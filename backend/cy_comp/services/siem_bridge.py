"""
cy_comp/services/siem_bridge.py
================================
Compliance enrichment engine (v2 — zero duplicate storage).

Architecture:
  enrich_alerts_pass()     — UPDATE alerts table with compliance columns in-place.
  enrich_incidents_pass()  — UPDATE incidents with aggregated compliance data.
  sync()                   — runs both passes, returns summary dict.

No data is copied or duplicated. The correlation engine's existing alerts and
incidents tables get four extra columns populated by this service:
  alerts:    is_compliance_relevant, compliance_frameworks, compliance_controls,
             compliance_confidence
  incidents: compliance_breach, compliance_frameworks, compliance_controls,
             compliance_confidence

cy_comp_alerts is kept only for FK compatibility — it is no longer written to.
"""

import json
import logging
from datetime import datetime, timezone

from cy_comp.models import db
from cy_comp.services.enrichment import (
    COMPLIANCE_MIN_LEVEL,
    CRITICAL_LEVEL,
    HIGH_LEVEL,
    MITRE_TO_CONTROLS,
    WAZUH_RULE_TO_CONTROLS,
    enrich_alert,
)

log = logging.getLogger("cycentra.cy_comp.siem_bridge")

BATCH_SIZE = 1000


def _mitre_parent(mitre_id: str) -> str:
    """Return parent technique ID: T1110.001 → T1110."""
    return mitre_id.split(".")[0] if mitre_id else ""


def _severity_from_level(level: int) -> str:
    if level >= CRITICAL_LEVEL: return "critical"
    if level >= HIGH_LEVEL:     return "high"
    if level >= COMPLIANCE_MIN_LEVEL: return "medium"
    return "low"


def _compute_controls(mitre_id: str, rule_id: int) -> dict:
    """Return compliance_controls JSONB dict by mapping MITRE + rule ID."""
    controls: dict[str, list[str]] = {}

    if mitre_id:
        for technique in [mitre_id, _mitre_parent(mitre_id)]:
            for fw, ctrl_list in MITRE_TO_CONTROLS.get(technique, {}).items():
                for c in ctrl_list:
                    controls.setdefault(fw, [])
                    if c not in controls[fw]:
                        controls[fw].append(c)

    rule_key = str(rule_id) if rule_id else ""
    for fw, ctrl_list in WAZUH_RULE_TO_CONTROLS.get(rule_key, {}).items():
        for c in ctrl_list:
            controls.setdefault(fw, [])
            if c not in controls[fw]:
                controls[fw].append(c)

    return controls


def _compute_confidence(rule_level: int, controls: dict) -> float:
    """
    Confidence score 0.00–1.00:
      - base from rule_level (0.3 at level 7 → 1.0 at level 15)
      - bonus for number of frameworks matched
    """
    base = min(1.0, max(0.0, (rule_level - COMPLIANCE_MIN_LEVEL + 1) / (15 - COMPLIANCE_MIN_LEVEL + 1)))
    fw_bonus = min(0.2, len(controls) * 0.05)
    return round(min(1.0, base + fw_bonus), 2)


# ── Alert enrichment pass ─────────────────────────────────────────────────────

def enrich_alerts_pass(batch_size: int = BATCH_SIZE) -> dict:
    """
    Process up to batch_size unprocessed alerts (is_compliance_relevant IS NULL)
    that have MITRE data or high rule_level.
    Updates alerts table in-place with compliance columns.
    """
    enriched = 0
    relevant = 0
    errors   = 0

    try:
        with db() as conn:
            cur = conn.cursor()

            # Fetch alerts that haven't been compliance-enriched yet
            cur.execute(
                """
                SELECT id, rule_id, rule_level, mitre_id, rule_desc, category
                FROM alerts
                WHERE is_compliance_relevant IS NULL
                  AND (mitre_id IS NOT NULL OR rule_level >= %s)
                ORDER BY id DESC
                LIMIT %s;
                """,
                (COMPLIANCE_MIN_LEVEL, batch_size)
            )
            rows = cur.fetchall()
            log.info("enrich_alerts_pass: found %d unprocessed alerts", len(rows))

            for (aid, rule_id, rule_level, mitre_id, rule_desc, category) in rows:
                try:
                    rule_level = int(rule_level or 0)
                    controls   = _compute_controls(mitre_id or "", rule_id)
                    frameworks = list(controls.keys()) if controls else []

                    # An alert is compliance-relevant if it meets the level threshold
                    # OR it has a known MITRE technique mapped to a framework.
                    # Fix: use OR logic to match the stated design intent.
                    # Previous (buggy) AND logic excluded MITRE-mapped alerts with
                    # rule_level < COMPLIANCE_MIN_LEVEL, leaving them as
                    # is_compliance_relevant=FALSE while compliance_frameworks was
                    # still populated — causing alerts=0 / breach_incidents=2 split.
                    is_relevant = bool(frameworks) or rule_level >= COMPLIANCE_MIN_LEVEL

                    confidence  = _compute_confidence(rule_level, controls) if is_relevant else 0.0

                    cur.execute(
                        """
                        UPDATE alerts
                        SET is_compliance_relevant = %s,
                            compliance_frameworks  = %s,
                            compliance_controls    = %s,
                            compliance_confidence  = %s
                        WHERE id = %s;
                        """,
                        (
                            is_relevant,
                            frameworks or None,
                            json.dumps(controls) if controls else None,
                            confidence,
                            aid,
                        )
                    )
                    enriched += 1
                    if is_relevant:
                        relevant += 1
                except Exception as row_exc:
                    log.warning("enrich_alerts_pass: alert %s failed: %s", aid, row_exc)
                    errors += 1

            # Mark high-level alerts without MITRE as not-relevant (so we don't re-scan)
            cur.execute(
                """
                UPDATE alerts
                SET is_compliance_relevant = FALSE
                WHERE is_compliance_relevant IS NULL
                  AND rule_level < %s
                  AND mitre_id IS NULL;
                """,
                (COMPLIANCE_MIN_LEVEL,)
            )

    except Exception as exc:
        log.error("enrich_alerts_pass failed: %s", exc)
        errors += 1

    log.info("enrich_alerts_pass: enriched=%d relevant=%d errors=%d", enriched, relevant, errors)
    return {"enriched": enriched, "relevant": relevant, "errors": errors}


# ── Incident enrichment pass ──────────────────────────────────────────────────

def enrich_incidents_pass() -> dict:
    """
    Propagate compliance data from alerts → incidents.
    An incident is a compliance_breach if any of its linked alerts are
    compliance_relevant OR it has MITRE techniques mapped to frameworks.
    """
    updated = 0
    errors  = 0

    try:
        with db() as conn:
            cur = conn.cursor()

            # Fetch incidents that need compliance update
            cur.execute(
                """
                SELECT i.id,
                       array_agg(DISTINCT a.mitre_id) FILTER (WHERE a.mitre_id IS NOT NULL) AS mitre_ids,
                       array_agg(DISTINCT a.compliance_controls) FILTER (WHERE a.compliance_controls IS NOT NULL AND a.compliance_controls != '{}') AS controls_arr,
                       MAX(a.rule_level) AS max_rule_level,
                       bool_or(a.is_compliance_relevant) AS any_relevant
                FROM incidents i
                LEFT JOIN alerts a ON a.incident_id = i.id
                WHERE i.compliance_breach IS NULL
                   OR i.compliance_breach = FALSE
                GROUP BY i.id;
                """
            )
            rows = cur.fetchall()

            for (inc_id, mitre_ids, controls_arr, max_level, any_relevant) in rows:
                try:
                    merged: dict[str, list[str]] = {}

                    # Merge controls from all linked alerts
                    for ctrl_json in (controls_arr or []):
                        if ctrl_json:
                            d = ctrl_json if isinstance(ctrl_json, dict) else json.loads(ctrl_json)
                            for fw, cids in d.items():
                                for c in cids:
                                    merged.setdefault(fw, [])
                                    if c not in merged[fw]:
                                        merged[fw].append(c)

                    # Also map from incident's own mitre_ids
                    for mid in (mitre_ids or []):
                        c2 = _compute_controls(mid or "", 0)
                        for fw, cids in c2.items():
                            for c in cids:
                                merged.setdefault(fw, [])
                                if c not in merged[fw]:
                                    merged[fw].append(c)

                    frameworks   = list(merged.keys())
                    max_level    = int(max_level or 0)
                    is_breach    = bool(any_relevant) or bool(frameworks) or max_level >= HIGH_LEVEL
                    confidence   = _compute_confidence(max_level, merged) if is_breach else 0.0

                    cur.execute(
                        """
                        UPDATE incidents
                        SET compliance_breach     = %s,
                            compliance_frameworks = %s,
                            compliance_controls   = %s,
                            compliance_confidence = %s
                        WHERE id = %s;
                        """,
                        (
                            is_breach,
                            frameworks or None,
                            json.dumps(merged) if merged else None,
                            confidence,
                            inc_id,
                        )
                    )
                    updated += 1
                except Exception as row_exc:
                    log.warning("enrich_incidents_pass: incident %s: %s", inc_id, row_exc)
                    errors += 1

    except Exception as exc:
        log.error("enrich_incidents_pass failed: %s", exc)
        errors += 1

    log.info("enrich_incidents_pass: updated=%d errors=%d", updated, errors)
    return {"updated": updated, "errors": errors}


# ── Public sync entry point ───────────────────────────────────────────────────

def sync(batch_size: int = BATCH_SIZE) -> dict:
    """
    Run compliance enrichment over existing alert and incident data.
    Returns a summary dict for the API response.
    """
    alert_result    = enrich_alerts_pass(batch_size)
    incident_result = enrich_incidents_pass()
    return {
        "alerts":    alert_result,
        "incidents": incident_result,
        "new":       alert_result["relevant"],
    }


def get_bridge():
    """Backward-compat shim — callers that do get_bridge().sync() still work."""
    class _Shim:
        def sync(self):
            return sync()
    return _Shim()


# ── APScheduler integration ───────────────────────────────────────────────────

def _compliance_sync_job() -> None:
    """Scheduled job wrapper — runs incremental enrichment, logs summary."""
    try:
        result = sync()
        log.info(
            "compliance_sync_job: alerts_enriched=%d relevant=%d incidents_updated=%d",
            result["alerts"]["enriched"],
            result["alerts"]["relevant"],
            result["incidents"]["updated"],
        )
    except Exception as exc:
        log.error("compliance_sync_job failed: %s", exc)


def register_compliance_scheduler(scheduler) -> None:
    """
    Register an hourly incremental compliance enrichment job into the platform
    APScheduler instance.  Called unconditionally from init_scheduler() —
    no env-var gate needed because the job is lightweight and idempotent
    (it only processes IS NULL rows, so it is a no-op once everything is caught up).

    Usage in blueprints/scheduler/routes.py init_scheduler():
        from cy_comp.services.siem_bridge import register_compliance_scheduler
        register_compliance_scheduler(_scheduler)
    """
    try:
        from apscheduler.triggers.interval import IntervalTrigger
        scheduler.add_job(
            _compliance_sync_job,
            trigger=IntervalTrigger(hours=1),
            id="compliance_enrichment_sync",
            replace_existing=True,
            misfire_grace_time=300,
        )
        log.info("[compliance] Hourly enrichment sync job registered")
    except Exception as exc:
        log.warning("[compliance] Could not register enrichment sync job: %s", exc)


# ── SIEM Autonomous Evidence → cy_comp_evidence bridge ────────────────────────

def sync_siem_evidence_to_comp(limit: int = 200) -> dict:
    """
    Bridge evidence items collected by the SIEM AI Investigation Engine
    (incidents.evidence_log JSONB) into cy_comp_evidence rows, linked to any
    associated compliance finding.

    Only processes COLLECTED items from compliance-breach incidents that have
    not already been imported (deduplicates on source_ref = 'siem:<incident_id>:<evidence_type>').

    Writes to cy_comp_evidence — never modifies the incidents table.
    Returns {imported, skipped, errors}.
    """
    imported = skipped = errors = 0
    try:
        with db() as conn:
            cur = conn.cursor()

            # Fetch compliance-breach incidents with non-empty evidence_log
            cur.execute(
                """
                SELECT id, evidence_log, compliance_frameworks
                FROM incidents
                WHERE compliance_breach = TRUE
                  AND evidence_log IS NOT NULL
                  AND jsonb_array_length(evidence_log) > 0
                ORDER BY last_seen DESC
                LIMIT %s;
                """,
                (limit,)
            )
            incidents = cur.fetchall()

            for inc_id, evidence_log, frameworks in incidents:
                if not isinstance(evidence_log, list):
                    continue
                for item in evidence_log:
                    if not isinstance(item, dict):
                        continue
                    if item.get("status") != "COLLECTED":
                        skipped += 1
                        continue

                    ev_type  = item.get("evidence_type", "unknown")
                    source_ref = f"siem:{inc_id}:{ev_type}"

                    # Check deduplication by source_ref
                    cur.execute(
                        "SELECT id FROM cy_comp_evidence WHERE source_ref = %s LIMIT 1;",
                        (source_ref,)
                    )
                    if cur.fetchone():
                        skipped += 1
                        continue

                    # Map evidence type → comp evidence type
                    ev_map = {
                        "process_tree":       "process_artifact",
                        "file_hash":          "file_artifact",
                        "dns_history":        "network_log",
                        "user_privilege":     "access_log",
                        "vulnerability_scan": "vuln_report",
                    }
                    comp_type = ev_map.get(ev_type, "siem_evidence")

                    # Find linked finding (if any) via alert_id FK
                    finding_id = None
                    try:
                        cur.execute(
                            """
                            SELECT id FROM cy_comp_findings
                            WHERE source_type = 'auto'
                              AND framework = ANY(%s::text[])
                              AND created_at > NOW() - INTERVAL '30 days'
                            ORDER BY created_at DESC LIMIT 1;
                            """,
                            (frameworks or [],)
                        )
                        row = cur.fetchone()
                        if row:
                            finding_id = row[0]
                    except Exception:
                        pass

                    try:
                        import uuid as _uuid, json as _json
                        summary = item.get("summary", f"SIEM evidence: {ev_type}")
                        data_snippet = _json.dumps(item.get("data") or {})[:500]
                        cur.execute(
                            """
                            INSERT INTO cy_comp_evidence
                                (id, title, type, description, finding_id,
                                 source_ref, uploaded_by, created_at)
                            VALUES (%s, %s, %s, %s, %s, %s, 'siem_bridge', NOW());
                            """,
                            (
                                str(_uuid.uuid4()),
                                f"SIEM: {ev_type.replace('_', ' ').title()} [{inc_id[:8]}]",
                                comp_type,
                                f"{summary}\n\nData: {data_snippet}",
                                finding_id,
                                source_ref,
                            )
                        )
                        imported += 1
                    except Exception as ins_exc:
                        log.warning("sync_siem_evidence: insert failed for %s: %s", source_ref, ins_exc)
                        errors += 1

    except Exception as exc:
        log.error("sync_siem_evidence_to_comp: %s", exc)
        errors += 1

    log.info("sync_siem_evidence: imported=%d skipped=%d errors=%d", imported, skipped, errors)
    return {"imported": imported, "skipped": skipped, "errors": errors}
