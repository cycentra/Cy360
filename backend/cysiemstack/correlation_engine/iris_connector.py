"""
iris_connector.py
=================
DFIR IRIS (CyIRIS) integration for the CySIEM Correlation Engine.

Responsibilities
----------------
1. create_iris_case()   — POST a new case to IRIS for a correlated incident.
2. get_iris_case_status() — GET a case status from IRIS (for sync polling).
3. sync_closed_cases()  — Batch-poll all open IRIS-linked incidents and close
                          any whose IRIS case has been closed by an analyst.
4. auto_close_fp()      — Mark an incident as false positive / auto-closed when
                          its confidence_score >= iris_fp_threshold.

Configuration is read from Settings (cysiemstack.env):
  IRIS_MODE         disabled | cloud | local
  IRIS_ENABLED      true | false
  IRIS_URL          https://cyiris.cycentra.com  (or local IP/hostname)
  IRIS_API_KEY      <bearer token from IRIS user settings>
  IRIS_CUSTOMER_ID  1  (integer — IRIS customer record ID)
  IRIS_FP_THRESHOLD 90.0  (incidents at/above this confidence score auto-close)

The module reads the resolved config from ai_settings.json via
_load_iris_config() — same approach as ai_router.py reads LLM settings —
so portal Save actions take effect immediately without a restart.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from models import Incident
from config import get_settings

log = structlog.get_logger()
settings = get_settings()

_AI_SETTINGS_FILE = Path("/opt/cycentra/ai_settings.json")
_CYCENTRA_ENV_FILE = Path("/opt/cycentra/.env")   # loaded by Flask; not by engine's systemd unit
_CLOUD_IRIS_URL_DEFAULT = "https://cyiris.cycentra.com"


# ── .env reader ────────────────────────────────────────────────────────────────

def _read_cycentra_env() -> dict:
    """
    Parse /opt/cycentra/.env and return a key→value dict.
    The engine's systemd unit uses cysiemstack.env, so CLOUD_IRIS_* vars are
    not injected into os.environ.  We read the file directly as a fallback.
    Only called when os.environ is missing the needed key — low overhead.
    """
    env: dict = {}
    if not _CYCENTRA_ENV_FILE.exists():
        return env
    try:
        for line in _CYCENTRA_ENV_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return env

# IRIS severity ID mapping (matches IRIS built-in severity table)
_SEV_MAP = {
    "critical": 1,  # Critical
    "high":     2,  # High
    "medium":   3,  # Medium
    "low":      4,  # Low
}


# ── Config loader ─────────────────────────────────────────────────────────────

def _load_iris_config() -> dict | None:
    """
    Resolve effective CyIRIS connection config from ai_settings.json.

    Returns dict with keys: url, api_key, customer_id, fp_threshold, mode
    Returns None if iris is disabled or credentials are missing.

    NOTE: The engine's systemd unit loads cysiemstack.env, NOT /opt/cycentra/.env,
    so CLOUD_IRIS_* vars are absent from os.environ inside the engine process.
    We fall back to _read_cycentra_env() which reads .env directly.
    """
    try:
        raw = _AI_SETTINGS_FILE.read_text() if _AI_SETTINGS_FILE.exists() else "{}"
        stored = json.loads(raw)
    except Exception:
        stored = {}

    iris = stored.get("iris", {})
    mode = iris.get("mode", "disabled")

    if mode == "cloud":
        # Fall back to .env file when env vars are missing (engine process doesn't get .env)
        _dotenv = None
        url_env = os.environ.get("CLOUD_IRIS_URL", "")
        key_env = os.environ.get("CLOUD_IRIS_API_KEY", "")
        cid_env = os.environ.get("CLOUD_IRIS_CUSTOMER_ID", "")
        if not url_env or not key_env:
            _dotenv = _read_cycentra_env()
            url_env = url_env or _dotenv.get("CLOUD_IRIS_URL", "")
            key_env = key_env or _dotenv.get("CLOUD_IRIS_API_KEY", "")
            cid_env = cid_env or _dotenv.get("CLOUD_IRIS_CUSTOMER_ID", "")

        url = (url_env or _CLOUD_IRIS_URL_DEFAULT).rstrip("/")
        key = key_env.strip() or iris.get("apiKey", "").strip()
        if not key:
            return None
        return {
            "url":          url,
            "api_key":      key,
            "customer_id":  int(cid_env or iris.get("customerId", settings.iris_customer_id)),
            "fp_threshold": float(iris.get("fpThreshold", settings.iris_fp_threshold)),
            "mode":         "cloud",
        }

    if mode == "local":
        url = iris.get("url", "").strip().rstrip("/")
        key = iris.get("apiKey", "").strip()
        if not url or not key:
            return None
        return {
            "url":          url,
            "api_key":      key,
            "customer_id":  int(iris.get("customerId", settings.iris_customer_id)),
            "fp_threshold": float(iris.get("fpThreshold", settings.iris_fp_threshold)),
            "mode":         "local",
        }

    # disabled
    return None


def _iris_headers(api_key: str) -> dict:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }


# ── Case creation ─────────────────────────────────────────────────────────────

async def create_iris_case(db: AsyncSession, incident: Incident) -> dict:
    """
    Create a DFIR IRIS case for the given incident.

    Returns a dict with: iris_case_id, iris_case_url, iris_case_status
    Returns {} if IRIS is disabled, already has a ticket, or an error occurs.
    """
    if incident.iris_case_id:
        return {}  # already ticketed

    cfg = _load_iris_config()
    if not cfg:
        return {}

    misp = incident.misp_enrichment or {}
    ioc_summary = ""
    if misp.get("ioc_hits"):
        ioc_summary = "\n\nMISP IOC Matches:\n" + "\n".join(
            f"  • {h['ioc']} ({h['type']}) — {h['threat_level']} threat"
            for h in misp["ioc_hits"][:5]
        )

    mitre_str = ", ".join(incident.mitre_ids or []) or "None"
    tactics_str = ", ".join(incident.mitre_tactics or []) or "None"
    agents_str = ", ".join(incident.affected_agents or []) or "unknown"
    users_str = ", ".join(incident.affected_users or []) or "none"

    description = (
        f"**Incident:** {incident.id}\n"
        f"**Severity:** {(incident.severity or 'unknown').upper()}\n"
        f"**First Seen:** {incident.first_seen.strftime('%Y-%m-%d %H:%M UTC') if incident.first_seen else 'N/A'}\n"
        f"**Last Seen:** {incident.last_seen.strftime('%Y-%m-%d %H:%M UTC') if incident.last_seen else 'N/A'}\n"
        f"**Alert Count:** {incident.alert_count}\n\n"
        f"**Affected Hosts:** {agents_str}\n"
        f"**Affected Users:** {users_str}\n"
        f"**Source IPs:** {', '.join(str(ip) for ip in (incident.src_ips or [])) or 'none'}\n\n"
        f"**MITRE ATT&CK:** {mitre_str}\n"
        f"**Tactics:** {tactics_str}\n"
        f"{ioc_summary}"
    )

    if incident.llm_summary:
        description += f"\n\n**AI Analyst Summary:**\n{incident.llm_summary}"
    if incident.llm_remediation:
        description += f"\n\n**Recommended Remediation:**\n{incident.llm_remediation}"

    payload = {
        "case_name":        f"{incident.id} — {(incident.severity or 'unknown').capitalize()} "
                            f"Incident ({', '.join((incident.categories or [])[:2]) or 'alert'})",
        "case_description": description,
        "case_customer":    cfg["customer_id"],
        "case_severity_id": _SEV_MAP.get(incident.severity, 4),
        "case_soc_id":      incident.id,  # our internal ID — key link for reverse sync
    }

    try:
        async with httpx.AsyncClient(
            base_url=cfg["url"],
            headers=_iris_headers(cfg["api_key"]),
            timeout=10.0,
            verify=False,   # IRIS commonly runs with a self-signed cert on-premise
        ) as client:
            resp = await client.post("/api/v2/cases", json=payload)

        if resp.status_code in (200, 201):
            data = resp.json()
            case = data if "case_id" in data else data.get("data", data)
            case_id  = case.get("case_id")
            case_url = f"{cfg['url']}/case?cid={case_id}" if case_id else None

            incident.iris_case_id     = case_id
            incident.iris_case_status = "open"
            incident.iris_case_url    = case_url
            incident.updated_at       = datetime.now(timezone.utc)
            await db.flush()

            log.info("iris_case_created",
                     incident_id=incident.id, iris_case_id=case_id)
            return {
                "iris_case_id":     case_id,
                "iris_case_url":    case_url,
                "iris_case_status": "open",
            }

        log.warning("iris_case_create_failed",
                    incident_id=incident.id, status=resp.status_code,
                    body=resp.text[:300])
        return {}

    except Exception as e:
        log.error("iris_case_create_error", incident_id=incident.id, error=str(e))
        return {}


# ── Status sync ───────────────────────────────────────────────────────────────

async def get_iris_case_status(cfg: dict, case_id: int) -> str | None:
    """
    Fetch a single IRIS case status.
    Returns "open", "closed", or None on error.
    """
    try:
        async with httpx.AsyncClient(
            base_url=cfg["url"],
            headers=_iris_headers(cfg["api_key"]),
            timeout=8.0,
            verify=False,
        ) as client:
            resp = await client.get(f"/api/v2/cases/{case_id}")

        if resp.status_code == 200:
            data = resp.json()
            case = data if "is_open" in data else data.get("data", data)
            is_open = case.get("is_open", True)
            return "open" if is_open else "closed"

        return None
    except Exception as e:
        log.warning("iris_status_fetch_error", case_id=case_id, error=str(e))
        return None


async def sync_closed_cases(db: AsyncSession) -> int:
    """
    Poll IRIS for all open-linked incidents and close any whose IRIS case is
    now closed by an analyst.  Returns the count of incidents auto-closed.

    Called by the scheduler in main.py every 5 minutes.
    """
    cfg = _load_iris_config()
    if not cfg:
        return 0

    result = await db.execute(
        select(Incident).where(
            and_(
                Incident.iris_case_id != None,       # noqa: E711
                Incident.iris_case_status == "open",
                Incident.status != "closed",
            )
        )
    )
    incidents = result.scalars().all()

    closed_count = 0
    for inc in incidents:
        remote_status = await get_iris_case_status(cfg, inc.iris_case_id)
        if remote_status == "closed":
            inc.iris_case_status = "closed"
            inc.status           = "closed"
            inc.closed_at        = datetime.now(timezone.utc)
            inc.updated_at       = datetime.now(timezone.utc)
            closed_count += 1
            log.info("incident_closed_via_iris",
                     incident_id=inc.id, iris_case_id=inc.iris_case_id)

    if closed_count:
        await db.flush()

    return closed_count


# ── False-positive auto-close ─────────────────────────────────────────────────

async def auto_close_fp(db: AsyncSession, incident: Incident,
                        confidence_score: float) -> bool:
    """
    Close an incident as a false positive if confidence_score >= threshold.

    Returns True if auto-closed, False otherwise.
    """
    cfg = _load_iris_config()
    threshold = cfg["fp_threshold"] if cfg else settings.iris_fp_threshold

    incident.confidence_score = confidence_score

    if confidence_score >= threshold:
        incident.status               = "closed"
        incident.closed_at            = datetime.now(timezone.utc)
        incident.updated_at           = datetime.now(timezone.utc)
        incident.false_positive_reason = (
            f"Auto-closed: AI confidence score {confidence_score:.1f} >= "
            f"threshold {threshold:.1f}"
        )
        await db.flush()
        log.info("incident_auto_closed_fp",
                 incident_id=incident.id, score=confidence_score,
                 threshold=threshold)
        return True

    return False
