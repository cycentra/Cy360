"""
evidence_collector.py
Autonomous Evidence Collection — Phase 3 of the AI Investigation Engine.

Wraps Wazuh API calls and a local alert query to collect 5 types of
forensic evidence for open incidents. Called from the fire-and-forget
background task in llm_enricher.py after gap analysis completes.

Collectors:
  ProcessTreeCollector   — Wazuh /agents/{id}/processes
  FileHashCollector      — Wazuh /agents/{id}/fim/files
  DNSHistoryCollector    — Local alerts table (rule_desc ILIKE '%dns%')
  UserPrivilegeCollector — Wazuh /agents/{id}/sca (SCA check results)
  VulnerabilityCollector — Wazuh /vulnerability/{id}

Every collector returns an EvidenceItem dict. On Wazuh API failure, item
status is FAILED with the error message stored. Never raises.

Collection timeout per item: 8 s. Total task timeout: 30 s (enforced by caller).
"""

import asyncio
from datetime import datetime, timezone
import structlog
import httpx
from config import get_settings

log = structlog.get_logger()
settings = get_settings()

_ITEM_TIMEOUT = 8.0  # seconds per individual Wazuh API call


# ── Wazuh API helpers ─────────────────────────────────────────────────────────

async def _wazuh_token() -> str:
    """Obtain a short-lived Wazuh JWT — same pattern as MCP toolset in main.py."""
    import base64
    creds = base64.b64encode(
        f"{settings.wazuh_api_user}:{settings.wazuh_api_password}".encode()
    ).decode()
    async with httpx.AsyncClient(verify=False, timeout=_ITEM_TIMEOUT) as client:
        r = await client.post(
            f"{settings.wazuh_api_url}/security/user/authenticate",
            headers={"Authorization": f"Basic {creds}"},
        )
        r.raise_for_status()
        return r.json()["data"]["token"]


async def _wazuh_get(path: str, token: str, params: dict | None = None) -> dict:
    """GET wrapper for Wazuh Manager API."""
    async with httpx.AsyncClient(verify=False, timeout=_ITEM_TIMEOUT) as client:
        r = await client.get(
            f"{settings.wazuh_api_url}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params or {},
        )
        r.raise_for_status()
        return r.json()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_item(
    hypothesis_id: str,
    evidence_type: str,
    collector: str,
    agent_id: str | None,
    status: str,
    summary: str,
    data: dict | None = None,
    error: str | None = None,
) -> dict:
    return {
        "timestamp":     _now_iso(),
        "hypothesis_id": hypothesis_id,
        "evidence_type": evidence_type,
        "collector":     collector,
        "agent_id":      agent_id,
        "status":        status,   # COLLECTED | MISSING | FAILED | PENDING
        "summary":       summary,
        "data":          data,
        "error":         error,
    }


# ── Individual collectors ─────────────────────────────────────────────────────

async def _collect_process_tree(
    hypothesis_id: str, agent_id: str, token: str
) -> dict:
    try:
        r = await _wazuh_get(f"/agents/{agent_id}/processes", token, {"limit": 50})
        procs = r.get("data", {}).get("affected_items", [])
        if procs:
            return _make_item(
                hypothesis_id, "process_tree", "ProcessTreeCollector", agent_id,
                "COLLECTED",
                f"{len(procs)} processes on agent {agent_id}",
                data={"processes": procs[:20]},  # cap stored data to 20
            )
        return _make_item(
            hypothesis_id, "process_tree", "ProcessTreeCollector", agent_id,
            "MISSING", "No processes returned by Wazuh agent",
        )
    except Exception as exc:
        return _make_item(
            hypothesis_id, "process_tree", "ProcessTreeCollector", agent_id,
            "FAILED", "Process tree unavailable",
            error=str(exc)[:200],
        )


async def _collect_file_hash(
    hypothesis_id: str, agent_id: str, token: str
) -> dict:
    try:
        r = await _wazuh_get(
            f"/agents/{agent_id}/fim/files", token,
            {"limit": 30, "sort": "-date"},
        )
        files = r.get("data", {}).get("affected_items", [])
        if files:
            return _make_item(
                hypothesis_id, "file_hash", "FileHashCollector", agent_id,
                "COLLECTED",
                f"{len(files)} recently modified files with hashes on {agent_id}",
                data={"files": files[:15]},
            )
        return _make_item(
            hypothesis_id, "file_hash", "FileHashCollector", agent_id,
            "MISSING", "No recent FIM file events found",
        )
    except Exception as exc:
        return _make_item(
            hypothesis_id, "file_hash", "FileHashCollector", agent_id,
            "FAILED", "File hash collection unavailable",
            error=str(exc)[:200],
        )


async def _collect_dns_history(
    hypothesis_id: str, agent_id: str, db
) -> dict:
    """Query local alerts table for DNS-related events — no Wazuh API needed."""
    try:
        from sqlalchemy import select, text as sa_text
        from models import Alert
        result = await db.execute(
            select(Alert.timestamp, Alert.rule_desc, Alert.src_ip, Alert.agent_id)
            .where(
                Alert.agent_id == agent_id,
                Alert.rule_desc.ilike("%dns%"),
            )
            .order_by(Alert.timestamp.desc())
            .limit(20)
        )
        rows = result.all()
        if rows:
            items = [
                {
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "rule_desc": r.rule_desc,
                    "src_ip":    r.src_ip,
                    "agent_id":  r.agent_id,
                }
                for r in rows
            ]
            return _make_item(
                hypothesis_id, "dns_history", "DNSHistoryCollector", agent_id,
                "COLLECTED",
                f"{len(items)} DNS-related alerts found for agent {agent_id}",
                data={"dns_events": items},
            )
        return _make_item(
            hypothesis_id, "dns_history", "DNSHistoryCollector", agent_id,
            "MISSING", "No DNS-related alerts in local alert store",
        )
    except Exception as exc:
        return _make_item(
            hypothesis_id, "dns_history", "DNSHistoryCollector", agent_id,
            "FAILED", "DNS history query failed",
            error=str(exc)[:200],
        )


async def _collect_user_privilege(
    hypothesis_id: str, agent_id: str, token: str
) -> dict:
    try:
        r = await _wazuh_get(
            f"/agents/{agent_id}/sca", token, {"limit": 10, "sort": "-score"}
        )
        checks = r.get("data", {}).get("affected_items", [])
        if checks:
            return _make_item(
                hypothesis_id, "user_privilege", "UserPrivilegeCollector", agent_id,
                "COLLECTED",
                f"{len(checks)} SCA policy checks retrieved for {agent_id}",
                data={"sca_checks": checks},
            )
        return _make_item(
            hypothesis_id, "user_privilege", "UserPrivilegeCollector", agent_id,
            "MISSING", "No SCA policy data available for this agent",
        )
    except Exception as exc:
        return _make_item(
            hypothesis_id, "user_privilege", "UserPrivilegeCollector", agent_id,
            "FAILED", "SCA/privilege data unavailable",
            error=str(exc)[:200],
        )


async def _collect_vulnerability(
    hypothesis_id: str, agent_id: str, token: str
) -> dict:
    try:
        r = await _wazuh_get(
            f"/vulnerability/{agent_id}", token,
            {"limit": 10, "sort": "-severity"},
        )
        vulns = r.get("data", {}).get("affected_items", [])
        if vulns:
            return _make_item(
                hypothesis_id, "vulnerability", "VulnerabilityCollector", agent_id,
                "COLLECTED",
                f"{len(vulns)} vulnerabilities found on {agent_id}",
                data={"vulnerabilities": vulns},
            )
        return _make_item(
            hypothesis_id, "vulnerability", "VulnerabilityCollector", agent_id,
            "MISSING", "No vulnerabilities found or scan not available",
        )
    except Exception as exc:
        return _make_item(
            hypothesis_id, "vulnerability", "VulnerabilityCollector", agent_id,
            "FAILED", "Vulnerability data unavailable",
            error=str(exc)[:200],
        )


# ── Dispatcher map ────────────────────────────────────────────────────────────

_COLLECTORS_NEEDING_TOKEN = {"process_tree", "file_hash", "user_privilege", "vulnerability"}
_COLLECTORS_LOCAL         = {"dns_history"}


async def collect_all(incident, gaps: list[dict], db) -> list[dict]:
    """Collect evidence for all gaps concurrently.

    Args:
        incident: Incident ORM instance (used for affected_agents and ID).
        gaps:     Output from gap_analyser.analyse_gaps().
        db:       AsyncSession for local queries (DNS history collector).

    Returns a list of EvidenceItem dicts — one per (hypothesis, evidence_type, agent).
    Returns [] when no Wazuh credentials are configured or no gaps exist.
    """
    if not gaps:
        return []

    # Determine primary agent to collect from (first affected agent, if any)
    agents: list[str] = (incident.affected_agents or [])
    primary_agent = agents[0] if agents else None

    # Check if Wazuh credentials are configured
    needs_wazuh = any(
        m["evidence_type"] in _COLLECTORS_NEEDING_TOKEN
        for g in gaps for m in g["missing"]
    )

    token: str | None = None
    if needs_wazuh and settings.wazuh_api_password:
        try:
            token = await asyncio.wait_for(_wazuh_token(), timeout=_ITEM_TIMEOUT)
        except Exception as exc:
            log.warning("wazuh_token_failed_in_collector", error=str(exc))

    tasks: list[asyncio.Task] = []

    for gap in gaps:
        hyp_id = gap["hypothesis_id"]
        for missing in gap["missing"]:
            ev_type  = missing["evidence_type"]
            agent_id = primary_agent  # collect from primary host

            coro = None
            if ev_type == "process_tree":
                if token and agent_id:
                    coro = _collect_process_tree(hyp_id, agent_id, token)
                else:
                    tasks.append(_immediate(
                        _make_item(hyp_id, ev_type, "ProcessTreeCollector", agent_id,
                                   "FAILED", "Wazuh credentials not configured or no agent")
                    ))
            elif ev_type == "file_hash":
                if token and agent_id:
                    coro = _collect_file_hash(hyp_id, agent_id, token)
                else:
                    tasks.append(_immediate(
                        _make_item(hyp_id, ev_type, "FileHashCollector", agent_id,
                                   "FAILED", "Wazuh credentials not configured or no agent")
                    ))
            elif ev_type == "dns_history":
                if agent_id:
                    coro = _collect_dns_history(hyp_id, agent_id, db)
                else:
                    tasks.append(_immediate(
                        _make_item(hyp_id, ev_type, "DNSHistoryCollector", agent_id,
                                   "MISSING", "No agent ID available")
                    ))
            elif ev_type == "user_privilege":
                if token and agent_id:
                    coro = _collect_user_privilege(hyp_id, agent_id, token)
                else:
                    tasks.append(_immediate(
                        _make_item(hyp_id, ev_type, "UserPrivilegeCollector", agent_id,
                                   "FAILED", "Wazuh credentials not configured or no agent")
                    ))
            elif ev_type == "vulnerability":
                if token and agent_id:
                    coro = _collect_vulnerability(hyp_id, agent_id, token)
                else:
                    tasks.append(_immediate(
                        _make_item(hyp_id, ev_type, "VulnerabilityCollector", agent_id,
                                   "FAILED", "Wazuh credentials not configured or no agent")
                    ))

            if coro is not None:
                tasks.append(asyncio.create_task(coro))

    if not tasks:
        return []

    results = await asyncio.gather(*tasks, return_exceptions=True)

    evidence_items: list[dict] = []
    for r in results:
        if isinstance(r, dict):
            evidence_items.append(r)
        elif isinstance(r, Exception):
            log.debug("evidence_collector_task_exc", error=str(r))

    log.info(
        "evidence_collected",
        incident_id=getattr(incident, "id", "?"),
        total=len(evidence_items),
        collected=sum(1 for e in evidence_items if e["status"] == "COLLECTED"),
    )
    return evidence_items


async def _immediate(value: dict) -> dict:
    """Wrap a pre-computed result as a coroutine so it can be used with asyncio.gather."""
    return value
