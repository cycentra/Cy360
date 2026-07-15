"""
custom_rules_engine.py
Generic "N alerts matching these field conditions within a time window"
evaluator, shared by custom correlation rules (run alongside correlator.py's
CR-001..055) and custom UEBA rules (run alongside ueba.py's built-in
detectors). Both are simpler than the hand-written Python rules they sit
next to by design — they're meant to be authored through a UI condition
builder (a flat AND list of {field, op, value}), not hand-written code, so
there's no boolean expression grammar here the way sigma_engine.py has one
for hand-authored Sigma YAML.

Fields available for conditions are exactly normaliser.normalise()'s output
keys — rule_id, rule_desc, category, agent_id, agent_name, agent_ip,
username, src_ip, process_name, file_path, mitre_id, mitre_tactic,
base_score, rule_level.
"""
from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Any

import structlog
from models import Incident, CustomCorrelationRule, CustomUebaRule  # noqa: F401 (type reference in docstrings)

log = structlog.get_logger()

_SEV_ORDER = ["low", "medium", "high", "critical"]


def _match_one(op: str, actual: Any, expected: Any) -> bool:
    if actual is None:
        return expected is None
    a = str(actual).lower()
    e = str(expected).lower()
    if op == "eq":
        return a == e
    if op == "contains":
        return e in a
    if op == "startswith":
        return a.startswith(e)
    if op == "endswith":
        return a.endswith(e)
    if op == "re":
        return re.search(str(expected), str(actual)) is not None
    if op == "in":
        values = expected if isinstance(expected, list) else [expected]
        return a in {str(v).lower() for v in values}
    if op == "gte":
        try:
            return float(actual) >= float(expected)
        except (TypeError, ValueError):
            return False
    if op == "lte":
        try:
            return float(actual) <= float(expected)
        except (TypeError, ValueError):
            return False
    return False


def match_conditions(conditions: list[dict], record: dict) -> bool:
    """All conditions ANDed. `record` is a flat dict (a normalised alert)."""
    if not conditions:
        return False  # a rule with no conditions matches nothing, not everything
    for cond in conditions:
        field = cond.get("field")
        op = cond.get("op", "eq")
        expected = cond.get("value")
        if field is None:
            continue
        if not _match_one(op, record.get(field), expected):
            return False
    return True


def _escalate(incident: Incident, severity_override: str | None) -> None:
    if not severity_override or severity_override not in _SEV_ORDER:
        return
    if _SEV_ORDER.index(severity_override) > _SEV_ORDER.index(incident.severity or "low"):
        incident.severity = severity_override


async def run_custom_correlation_rules(
    incident: Incident,
    alerts: list[dict],
    new_alert: dict,
    rules: list[dict],
) -> list[dict]:
    """Mirrors correlator.run_correlation()'s built-in-rule loop: returns
    newly-fired rule entries and may escalate incident.severity. Does NOT
    write incident.correlated_rules itself — the caller (run_correlation)
    appends the combined built-in + custom list once, in one place, so
    there's a single source of truth for what's already fired. `alerts` is
    the full incident alert list run_correlation already fetched — reused
    here rather than re-querying the DB."""
    already_fired = {r["rule_id"] for r in (incident.correlated_rules or [])}
    newly_fired: list[dict] = []

    for rule in rules:
        rule_key = rule["rule_key"]
        if rule_key in already_fired:
            continue
        window_cutoff = new_alert["timestamp"] - _minutes(rule["window_minutes"])
        matching = [a for a in alerts if a["timestamp"] >= window_cutoff
                    and match_conditions(rule["conditions"], a)]
        if len(matching) < rule["min_count"]:
            continue
        entry = {
            "rule_id": rule_key,
            "name": rule["name"],
            "description": rule["description"] or "",
            "severity": rule["severity_override"] or incident.severity or "medium",
            "tactics": [],
            "detail": f"{len(matching)} matching alert(s) within {rule['window_minutes']}m (custom rule)",
            "key_alerts": [a.get("wazuh_id") for a in matching[:3]],
            "confidence": 0.6,
            "custom": True,
        }
        newly_fired.append(entry)
        _escalate(incident, rule["severity_override"])

    if newly_fired:
        log.info("custom_correlation_fired", incident_id=incident.id,
                 rules=[r["rule_id"] for r in newly_fired])
    return newly_fired


async def run_custom_ueba_rules(
    db,
    alert: dict,
    recent_alerts: list[dict],
    incident_id: str,
    entity_key: str,
    entity_type: str,
    rules: list[dict],
) -> list:
    """Mirrors ueba.py's _record_anomaly() shape — writes a UEBAAnomaly row
    and flags incident.ueba_flags, reusing ueba._record_anomaly directly so
    there's exactly one code path that persists an anomaly."""
    from ueba import _record_anomaly  # local import — avoids a circular import at module load

    created = []
    for rule in rules:
        if rule["entity_type"] != entity_type:
            continue
        window_cutoff = alert["timestamp"] - _minutes(rule["window_minutes"])
        candidates = [a for a in recent_alerts if a.get("timestamp") and a["timestamp"] >= window_cutoff]
        candidates.append(alert)
        matching = [a for a in candidates if match_conditions(rule["conditions"], a)]
        if len(matching) < rule["min_count"]:
            continue
        anomaly = await _record_anomaly(
            db, entity_key, rule["anomaly_type"],
            f"{rule['name']}: {len(matching)} matching alert(s) within {rule['window_minutes']}m (custom rule)",
            incident_id, [a.get("wazuh_id") for a in matching],
            risk_contribution=rule["risk_contribution"],
        )
        created.append(anomaly)
        log.info("custom_ueba_fired", entity=entity_key, rule_key=rule["rule_key"])
    return created


def _minutes(n: int):
    from datetime import timedelta
    return timedelta(minutes=n)
