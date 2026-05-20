"""
cysiemstack/threat_hunter/hunter.py
=====================================
Proactive threat hunting engine.

Unlike the reactive correlator (which fires on individual alert patterns in
real-time), the hunter sweeps historical alert data looking for low-and-slow
patterns that individually fall below the correlation threshold.

Hunt rules are defined as YAML files in threat_hunter/rules/.
Each rule specifies a time window, minimum event counts, and optional
field grouping.  When a rule fires, the engine creates a new Incident
of type 'hunt_finding' so analysts can investigate through the standard
incident workflow.

Run schedule: every 6 hours via the APScheduler job registered in main.py.
On-demand: POST /api/siem/threat-hunting/run (admin only).
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import yaml
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("cysiemstack.threat_hunter")

RULES_DIR = Path(__file__).parent / "rules"


# ── Rule loader ───────────────────────────────────────────────────────────────

def load_hunt_rules() -> list[dict]:
    """Load all YAML hunt rule files from the rules/ directory."""
    rules = []
    if not RULES_DIR.exists():
        return rules
    for path in sorted(RULES_DIR.glob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text())
            if data and isinstance(data, dict) and data.get("id"):
                data["_file"] = str(path)
                rules.append(data)
        except Exception as exc:
            log.warning("[hunter] failed to load rule %s: %s", path, exc)
    return rules


# ── Individual rule evaluator ─────────────────────────────────────────────────

async def _evaluate_rule(rule: dict, session: AsyncSession) -> list[dict]:
    """Evaluate a single hunt rule against the alerts table.

    Returns a list of match dicts, each representing a distinct entity
    (agent_id or username) that triggered the rule.
    """
    window_hours = int(rule.get("window_hours", 24))
    min_count    = int(rule.get("conditions", [{}])[0].get("min_count", 5))
    category     = rule.get("conditions", [{}])[0].get("category", "")
    desc_contains= rule.get("conditions", [{}])[0].get("rule_desc_contains", "")
    same_field   = rule.get("conditions", [{}])[0].get("same_field", "agent_id")
    severity     = rule.get("severity", "medium")
    confidence   = float(rule.get("confidence", 0.65))

    # Build WHERE clause
    clauses = ["timestamp > NOW() - :window"]
    params: dict  = {"window": timedelta(hours=window_hours), "min_count": min_count}

    if category:
        clauses.append("category = :category")
        params["category"] = category
    if desc_contains:
        clauses.append("LOWER(rule_desc) LIKE :desc_pat")
        params["desc_pat"] = f"%{desc_contains.lower()}%"

    group_field = same_field if same_field in ("agent_id", "username", "src_ip") else "agent_id"

    sql = text(f"""
        SELECT {group_field} AS entity,
               COUNT(*)             AS event_count,
               MIN(timestamp)       AS first_seen,
               MAX(timestamp)       AS last_seen,
               ARRAY_AGG(DISTINCT agent_id) AS agents,
               ARRAY_AGG(DISTINCT agent_name) AS agent_names,
               ARRAY_AGG(DISTINCT mitre_id) FILTER (WHERE mitre_id IS NOT NULL) AS mitre_ids
        FROM alerts
        WHERE {' AND '.join(clauses)}
          AND {group_field} IS NOT NULL
        GROUP BY {group_field}
        HAVING COUNT(*) >= :min_count
    """)

    try:
        rows = await session.execute(sql, params)
        matches = []
        for row in rows.fetchall():
            matches.append({
                "entity":      row.entity,
                "event_count": int(row.event_count),
                "first_seen":  row.first_seen,
                "last_seen":   row.last_seen,
                "agents":      list(row.agents or []),
                "agent_names": list(row.agent_names or []),
                "mitre_ids":   list(row.mitre_ids or []) + (rule.get("mitre", []) or []),
                "severity":    severity,
                "confidence":  confidence,
            })
        return matches
    except Exception as exc:
        log.warning("[hunter] rule %s evaluation failed: %s", rule.get("id"), exc)
        return []


# ── Incident creation ─────────────────────────────────────────────────────────

async def _create_hunt_incident(
    rule: dict,
    match: dict,
    session: AsyncSession,
) -> Optional[str]:
    """Create a hunt_finding incident if one doesn't already exist for this rule+entity."""
    from cysiemstack.correlation_engine.models import Incident

    rule_id   = rule["id"]
    entity    = match["entity"]
    severity  = match["severity"]

    # Check for existing open hunt finding for this rule+entity
    existing = await session.execute(
        text("""
            SELECT id FROM incidents
            WHERE correlated_rules::text LIKE :rule_pat
              AND :entity = ANY(affected_agents || affected_users)
              AND status NOT IN ('closed','false_positive')
              AND categories @> ARRAY['hunt_finding']
            LIMIT 1
        """),
        {"rule_pat": f"%{rule_id}%", "entity": entity},
    )
    if existing.fetchone():
        return None  # already open

    incident_id = f"HUNT-{rule_id}-{uuid.uuid4().hex[:8].upper()}"
    mitre_ids   = list(set(match.get("mitre_ids", [])))

    inc = Incident(
        id                   = incident_id,
        first_seen           = match["first_seen"] or datetime.now(timezone.utc),
        last_seen            = match["last_seen"]  or datetime.now(timezone.utc),
        updated_at           = datetime.now(timezone.utc),
        status               = "open",
        severity             = severity,
        alert_count          = match["event_count"],
        affected_agents      = match["agents"],
        affected_agent_names = match["agent_names"],
        affected_users       = [entity] if rule.get("conditions", [{}])[0].get("same_field") == "username" else [],
        categories           = ["hunt_finding"],
        mitre_ids            = mitre_ids,
        correlated_rules     = [{
            "rule_id":     rule_id,
            "rule_name":   rule.get("name", rule_id),
            "confidence":  match["confidence"],
            "event_count": match["event_count"],
        }],
        llm_summary = (
            f"Threat hunt rule '{rule.get('name', rule_id)}' fired: "
            f"{match['event_count']} events matching pattern "
            f"'{rule.get('conditions', [{}])[0].get('rule_desc_contains', '')}' "
            f"for entity '{entity}' over the past {rule.get('window_hours', 24)} hours. "
            f"Frameworks: {', '.join(rule.get('frameworks', []))}."
        ),
        fp_probability = round((1 - match["confidence"]) * 100, 1),
    )
    session.add(inc)
    return incident_id


# ── Main run function ─────────────────────────────────────────────────────────

async def run_all_hunts(session: AsyncSession) -> dict:
    """
    Evaluate all hunt rules and create incidents for new matches.

    Returns summary dict: {rules_run, matches_found, incidents_created, errors}.
    """
    rules = load_hunt_rules()
    if not rules:
        log.info("[hunter] no hunt rules found in %s", RULES_DIR)
        return {"rules_run": 0, "matches_found": 0, "incidents_created": 0, "errors": 0}

    rules_run = matches_found = incidents_created = errors = 0

    for rule in rules:
        try:
            matches = await _evaluate_rule(rule, session)
            rules_run   += 1
            matches_found += len(matches)
            for match in matches:
                inc_id = await _create_hunt_incident(rule, match, session)
                if inc_id:
                    incidents_created += 1
                    log.info("[hunter] created %s for rule %s entity %s",
                             inc_id, rule["id"], match["entity"])
        except Exception as exc:
            log.error("[hunter] rule %s failed: %s", rule.get("id", "?"), exc)
            errors += 1

    await session.commit()
    log.info("[hunter] run complete — rules:%d matches:%d incidents_created:%d errors:%d",
             rules_run, matches_found, incidents_created, errors)
    return {
        "rules_run":          rules_run,
        "matches_found":      matches_found,
        "incidents_created":  incidents_created,
        "errors":             errors,
        "run_at":             datetime.now(timezone.utc).isoformat(),
    }


async def get_hunt_rules_status(session: AsyncSession) -> list[dict]:
    """Return all hunt rules with their last-run incident count."""
    rules  = load_hunt_rules()
    result = []
    for rule in rules:
        inc_row = await session.execute(
            text("""
                SELECT COUNT(*) FROM incidents
                WHERE correlated_rules::text LIKE :pat
                  AND categories @> ARRAY['hunt_finding']
            """),
            {"pat": f"%{rule['id']}%"},
        )
        total_findings = inc_row.scalar() or 0
        open_row = await session.execute(
            text("""
                SELECT COUNT(*) FROM incidents
                WHERE correlated_rules::text LIKE :pat
                  AND categories @> ARRAY['hunt_finding']
                  AND status NOT IN ('closed','false_positive')
            """),
            {"pat": f"%{rule['id']}%"},
        )
        open_findings = open_row.scalar() or 0
        result.append({
            "id":            rule["id"],
            "name":          rule.get("name", rule["id"]),
            "description":   rule.get("description", ""),
            "mitre":         rule.get("mitre", []),
            "window_hours":  rule.get("window_hours", 24),
            "severity":      rule.get("severity", "medium"),
            "frameworks":    rule.get("frameworks", []),
            "total_findings": int(total_findings),
            "open_findings":  int(open_findings),
        })
    return result
