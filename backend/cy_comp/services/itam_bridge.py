"""
cy_comp/services/itam_bridge.py
================================
Compliance auto-feed bridge for the ITAM module.

Reads ITAM metrics (network_assets, iot_devices, shadow_ai_findings) and
auto-populates questionnaire responses for controls that require asset
inventory evidence.

Mirrors the siem_bridge.py pattern: no data duplication; writes directly
into cy_comp_questionnaire_responses with evidence_refs.

Mapped controls:
  nist_csf   / nist-id-01   — ID.AM-01/02 (asset inventory + automated discovery)
  iso27001   / iso-org-06   — A.5.9–A.5.12 (asset inventory, classification, owners)
  dora       / dora-asset-01 — Art.8(1) (complete ICT asset inventory)
  nis2       / nis2-asset-01 — Art.21(2)(i) (CMDB + automated discovery tool)
  eu_ai_act  / euai-ai-inv-01 — Art.9 (AI system inventory and risk classification)
  iso27001   / iso-ai-mgmt   — A.8.19 (management of AI/shadow IT)

Scoring logic:
  EDR/SIEM coverage ≥ 80% → full credit (score 2)
  50–79%                  → partial (score 1)
  < 50%                   → insufficient (score 0), generates a finding
  Shadow AI open findings → reduces eu_ai_act score; generates findings
"""
from __future__ import annotations
import json
import logging
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

from core.config import CYCENTRA_DB_URL

_log = logging.getLogger(__name__)

# ── Control mapping ───────────────────────────────────────────────────────────
# (framework, question_id, description)
ASSET_INVENTORY_CONTROLS = [
    ("nist_csf",  "nist-id-01",    "NIST CSF ID.AM-01/02 — Asset inventory via automated discovery"),
    ("iso27001",  "iso-org-06",    "ISO 27001 A.5.9–A.5.12 — Asset inventory with classification"),
    ("dora",      "dora-asset-01", "DORA Art.8(1) — Complete ICT asset inventory with criticality"),
    ("nis2",      "nis2-asset-01", "NIS2 Art.21(2)(i) — CMDB + automated discovery tool in place"),
]

AI_INVENTORY_CONTROLS = [
    ("eu_ai_act", "euai-ai-inv-01", "EU AI Act Art.9 — AI system inventory and risk classification"),
    ("iso27001",  "iso-ai-mgmt",    "ISO 27001 A.8.19 — Management of AI tools (shadow IT control)"),
]


def _db():
    return psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def _coverage_score(pct: float) -> int:
    """Convert coverage percentage to 0-2 compliance score."""
    if pct >= 80: return 2
    if pct >= 50: return 1
    return 0


def _save_response(conn, framework: str, question_id: str, response: str,
                   score: int, notes: str, evidence_refs: list[str]) -> None:
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO cy_comp_questionnaire_responses
                (framework, question_id, response, score, notes, evidence_refs, responded_by)
            VALUES (%s, %s, %s, %s, %s, %s, 'itam_bridge')
            ON CONFLICT (framework, question_id) DO UPDATE SET
                response     = EXCLUDED.response,
                score        = EXCLUDED.score,
                notes        = EXCLUDED.notes,
                evidence_refs= EXCLUDED.evidence_refs,
                responded_by = EXCLUDED.responded_by,
                responded_at = NOW()
        """, [framework, question_id, response, score,
              notes, json.dumps(evidence_refs)])


def _save_finding(conn, framework: str, control_id: str, title: str,
                  description: str, severity: str) -> None:
    """Insert a compliance finding if one doesn't already exist for this control."""
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO cy_comp_findings
                (framework, control_id, title, description, severity,
                 status, source, created_at)
            VALUES (%s, %s, %s, %s, %s, 'open', 'itam_bridge', NOW())
            ON CONFLICT (framework, control_id) DO UPDATE SET
                title       = EXCLUDED.title,
                description = EXCLUDED.description,
                severity    = EXCLUDED.severity,
                updated_at  = NOW()
        """, [framework, control_id, title, description, severity])


def sync() -> dict:
    """
    Main sync function. Reads ITAM tables and writes compliance evidence.
    Returns summary dict with counts.
    Called by APScheduler every 6 hours and on CMDB import.
    """
    summary = {"responses_updated": 0, "findings_raised": 0, "errors": []}

    try:
        conn = _db()
    except Exception as exc:
        _log.error("itam_bridge: DB connect failed: %s", exc)
        summary["errors"].append(str(exc))
        return summary

    try:
        with conn.cursor() as cur:
            # ── Gather metrics ────────────────────────────────────────────────
            # Check if network_assets table exists
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name='network_assets'
                ) AS exists
            """)
            if not cur.fetchone()["exists"]:
                _log.info("itam_bridge: network_assets table not yet created, skipping sync")
                conn.close()
                return summary

            cur.execute("SELECT COUNT(*) AS n FROM network_assets")
            total_assets = cur.fetchone()["n"]

            cur.execute("SELECT COUNT(*) AS n FROM network_assets WHERE edr_agent_id IS NOT NULL")
            edr_covered = cur.fetchone()["n"]

            cur.execute("SELECT COUNT(*) AS n FROM network_assets WHERE siem_agent_id IS NOT NULL")
            siem_covered = cur.fetchone()["n"]

            cur.execute("SELECT COUNT(*) AS n FROM iot_devices WHERE status='active'")
            iot_count = cur.fetchone()["n"]

            cur.execute("SELECT COUNT(*) AS n FROM shadow_ai_findings WHERE status='open'")
            shadow_ai_open = cur.fetchone()["n"]

            cur.execute("SELECT COUNT(DISTINCT ai_tool) AS n FROM shadow_ai_findings")
            unique_ai_tools = cur.fetchone()["n"]

            cur.execute("SELECT COUNT(*) AS n FROM ai_tool_whitelist")
            whitelisted_tools = cur.fetchone()["n"]

            cur.execute("SELECT COUNT(*) AS n FROM network_assets WHERE source='manual'")
            cmdb_entries = cur.fetchone()["n"]

            cur.execute("SELECT COUNT(*) AS n FROM network_assets WHERE source='nmap'")
            nmap_entries = cur.fetchone()["n"]

            cur.execute("SELECT COUNT(*) AS n FROM network_assets WHERE source='arp_report'")
            arp_entries = cur.fetchone()["n"]

        has_automated_discovery = (nmap_entries + arp_entries) > 0
        max_covered = max(edr_covered, siem_covered)
        coverage_pct = round((max_covered / total_assets * 100), 1) if total_assets else 0.0

        # ── Build evidence strings ────────────────────────────────────────────
        inv_evidence = [
            f"ITAM: {total_assets} total network assets tracked",
            f"ITAM: EDR coverage {coverage_pct}% ({edr_covered}/{total_assets} assets)",
            f"ITAM: SIEM coverage ({siem_covered}/{total_assets} assets)",
            f"ITAM: {iot_count} IoT/unmanaged devices catalogued",
        ]
        if cmdb_entries:
            inv_evidence.append(f"ITAM: {cmdb_entries} assets from CMDB import (manual ground truth)")
        if has_automated_discovery:
            inv_evidence.append(
                f"ITAM: Automated discovery active — {arp_entries} via ARP, {nmap_entries} via nmap"
            )

        # Response text
        if total_assets == 0:
            inv_response = "no"
            inv_score    = 0
            inv_notes    = "No assets in ITAM inventory. Import a CMDB or run a subnet scan."
        elif coverage_pct >= 80:
            inv_response = "yes"
            inv_score    = 2
            inv_notes    = (
                f"Asset inventory maintained with {total_assets} assets. "
                f"EDR coverage {coverage_pct}% meets ≥80% threshold."
            )
        elif coverage_pct >= 50:
            inv_response = "partial"
            inv_score    = 1
            inv_notes    = (
                f"Asset inventory present ({total_assets} assets) but EDR coverage "
                f"is {coverage_pct}% — below 80% target. Uncovered: "
                f"{total_assets - max_covered} endpoints."
            )
        else:
            inv_response = "partial"
            inv_score    = 0
            inv_notes    = (
                f"Asset inventory present ({total_assets} assets) but EDR coverage "
                f"is critically low at {coverage_pct}%. Immediate deployment recommended."
            )

        # ── Write asset inventory controls ────────────────────────────────────
        for framework, question_id, desc in ASSET_INVENTORY_CONTROLS:
            try:
                _save_response(conn, framework, question_id, inv_response,
                               inv_score, inv_notes, inv_evidence)
                summary["responses_updated"] += 1

                # Raise finding if coverage is insufficient
                if inv_score == 0 and total_assets > 0:
                    _save_finding(
                        conn, framework, question_id,
                        "EDR coverage below acceptable threshold",
                        f"Asset inventory shows {coverage_pct}% EDR coverage "
                        f"({edr_covered}/{total_assets} assets). Target: ≥80%.",
                        "high",
                    )
                    summary["findings_raised"] += 1
            except Exception as exc:
                _log.warning("itam_bridge: %s/%s write failed: %s", framework, question_id, exc)
                summary["errors"].append(f"{framework}/{question_id}: {exc}")

        # ── Build AI inventory evidence ───────────────────────────────────────
        ai_evidence = [
            f"ITAM Shadow AI: {unique_ai_tools} distinct AI tools detected in environment",
            f"ITAM Shadow AI: {shadow_ai_open} open (unapproved) findings",
            f"ITAM: {whitelisted_tools} AI tools formally approved in AI whitelist",
        ]

        if shadow_ai_open == 0 and whitelisted_tools > 0:
            ai_response = "yes"
            ai_score    = 2
            ai_notes    = (
                f"{whitelisted_tools} AI tools formally approved; "
                f"no unapproved Shadow AI findings currently open."
            )
        elif shadow_ai_open > 0:
            ai_response = "partial"
            ai_score    = 1 if shadow_ai_open < 5 else 0
            ai_notes    = (
                f"{shadow_ai_open} unapproved AI tool detections open. "
                f"Review and either approve or block these tools."
            )
        elif total_assets > 0 and unique_ai_tools == 0:
            ai_response = "partial"
            ai_score    = 1
            ai_notes    = (
                "No Shadow AI detections found. This may indicate detection gaps "
                "(Shadow AI process monitoring requires CyEDR agents). "
                "Consider enabling CyEDR on all endpoints."
            )
        else:
            ai_response = "no"
            ai_score    = 0
            ai_notes    = "No AI tool inventory established and no detection in place."

        for framework, question_id, desc in AI_INVENTORY_CONTROLS:
            try:
                _save_response(conn, framework, question_id, ai_response,
                               ai_score, ai_notes, ai_evidence)
                summary["responses_updated"] += 1

                if shadow_ai_open > 0:
                    _save_finding(
                        conn, framework, question_id,
                        f"Shadow AI: {shadow_ai_open} unapproved AI tools in use",
                        f"{shadow_ai_open} instances of unauthorized AI tool usage detected. "
                        f"Tools include: review Shadow AI Monitor for details.",
                        "high" if shadow_ai_open >= 5 else "medium",
                    )
                    summary["findings_raised"] += 1
            except Exception as exc:
                _log.warning("itam_bridge AI: %s/%s write failed: %s", framework, question_id, exc)
                summary["errors"].append(f"{framework}/{question_id}: {exc}")

        conn.commit()
        conn.close()
        _log.info("itam_bridge sync complete: %s", summary)
        return summary

    except Exception as exc:
        _log.error("itam_bridge sync error: %s", exc)
        summary["errors"].append(str(exc))
        try:
            conn.close()
        except Exception:
            pass
        return summary


def register_itam_scheduler(scheduler) -> None:
    """Register itam_bridge.sync() with the APScheduler — called from scheduler/routes.py."""
    def _job():
        try:
            sync()
        except Exception as exc:
            _log.error("itam_bridge scheduled sync failed: %s", exc)

    scheduler.add_job(
        _job,
        trigger="interval",
        hours=6,
        id="itam_compliance_sync",
        replace_existing=True,
    )
    _log.info("itam_bridge: compliance sync scheduled every 6 hours")
