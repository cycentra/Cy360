"""
blueprints/edr/confidence_matrix.py
=====================================
CyEDR Confidence & Risk Matrix Engine.

Translates behavioral heuristic triggers, threat intelligence hits, and
asset criticality into a unified 0-100 risk score aligned with the
existing SIEM risk_scorer.py scale.

Formula:
  raw = sum(triggered_weights) + ti_bonus
  final = min(100, round(raw * asset_modifier, 1))

MITRE ATT&CK mappings are assigned per trigger so the downstream
SIEM normalizer can populate mitre_id / mitre_tactic fields.
"""
from __future__ import annotations
from typing import Any

# ── Heuristic weight table ─────────────────────────────────────────────────────
# Each key is a trigger name emitted by the EDR agent.
# Base weight: contribution to the raw risk score before asset multiplier.
# mitre: (technique_id, tactic) pair for MITRE ATT&CK mapping.
HEURISTIC_TABLE: dict[str, dict[str, Any]] = {
    "unsigned_temp_exec": {
        "weight": 15,
        "mitre": ("T1059", "Execution"),
        "rule_id": 100302,
        "desc": "Unsigned binary executed from temporary directory",
    },
    "process_lineage_anomaly": {
        "weight": 35,
        "mitre": ("T1059.003", "Execution"),
        "rule_id": 100301,
        "desc": "Suspicious process parent-child relationship detected",
    },
    "memory_injection": {
        "weight": 40,
        "mitre": ("T1055", "Defense Evasion"),
        "rule_id": 100300,
        "desc": "Cross-process memory injection pattern observed",
    },
    "lsass_access": {
        "weight": 45,
        "mitre": ("T1003.001", "Credential Access"),
        "rule_id": 100304,
        "desc": "Unauthorized LSASS memory read attempt detected",
    },
    "credential_dump": {
        "weight": 40,
        "mitre": ("T1003", "Credential Access"),
        "rule_id": 100305,
        "desc": "Credential dumping tool or technique identified",
    },
    "ransomware_canary": {
        "weight": 50,
        "mitre": ("T1486", "Impact"),
        "rule_id": 100303,
        "desc": "Ransomware canary file modified — potential encryption event",
    },
    "lateral_movement": {
        "weight": 35,
        "mitre": ("T1021", "Lateral Movement"),
        "rule_id": 100306,
        "desc": "Lateral movement via remote execution service detected",
    },
    "c2_beacon": {
        "weight": 35,
        "mitre": ("T1071", "Command and Control"),
        "rule_id": 100307,
        "desc": "Periodic outbound connection matching C2 beacon pattern",
    },
    "defense_evasion": {
        "weight": 25,
        "mitre": ("T1562", "Defense Evasion"),
        "rule_id": 100308,
        "desc": "Security tool disabled or ETW patch attempted",
    },
    "persistence_mechanism": {
        "weight": 30,
        "mitre": ("T1053", "Persistence"),
        "rule_id": 100309,
        "desc": "Persistence mechanism installed (registry, scheduled task, service)",
    },
    "script_obfuscation": {
        "weight": 25,
        "mitre": ("T1027", "Defense Evasion"),
        "rule_id": 100310,
        "desc": "Heavily obfuscated script execution detected",
    },
    "living_off_land": {
        "weight": 20,
        "mitre": ("T1218", "Defense Evasion"),
        "rule_id": 100306,
        "desc": "LOLBin abuse — trusted system binary used maliciously",
    },
    "first_time_execution": {
        "weight": 20,
        "mitre": ("T1059", "Execution"),
        "rule_id": 100312,
        "desc": "First-time execution of unusual tool by this identity",
    },
    "network_ioc_match": {
        "weight": 35,
        "mitre": ("T1071", "Command and Control"),
        "rule_id": 100311,
        "desc": "Outbound connection to known malicious infrastructure",
    },
    "file_hash_ioc": {
        "weight": 50,
        "mitre": ("T1204", "Execution"),
        "rule_id": 100313,
        "desc": "File hash matches known malware indicator",
    },
    "registry_manipulation": {
        "weight": 25,
        "mitre": ("T1112", "Defense Evasion"),
        "rule_id": 100314,
        "desc": "Sensitive registry key modification detected",
    },
    "ransomware_extension": {
        "weight": 45,
        "mitre": ("T1486", "Impact"),
        "rule_id": 100315,
        "desc": "File renamed with ransomware-associated extension pattern",
    },
    "dll_sideloading": {
        "weight": 30,
        "mitre": ("T1574.002", "Persistence"),
        "rule_id": 100316,
        "desc": "DLL side-loading into legitimate signed process",
    },
    "token_impersonation": {
        "weight": 35,
        "mitre": ("T1134", "Privilege Escalation"),
        "rule_id": 100317,
        "desc": "Token impersonation or privilege escalation via token theft",
    },
}

# Threat intelligence hit bonus (MISP / TI cache confirmed match)
TI_MATCH_BONUS = 50

# ── Asset criticality multipliers ─────────────────────────────────────────────
ASSET_MODIFIERS: dict[str, float] = {
    "workstation":        1.0,
    "laptop":             1.0,
    "server":             1.4,
    "domain_controller":  2.0,
    "database":           1.7,
    "api_gateway":        1.5,
    "jump_server":        1.8,
    "ci_cd_node":         1.6,
    "iot_device":         1.2,
    "unknown":            1.0,
}

# Severity thresholds on the 0-100 scale (aligned with SIEM grouper thresholds)
SEVERITY_THRESHOLDS = {
    "critical": 75,
    "high":     50,
    "medium":   25,
    "low":      0,
}

# Synthetic rule level (1-15) mapped from final score — for SIEM normalizer compat
def score_to_rule_level(score: float) -> int:
    if score >= 75:
        return 14
    if score >= 50:
        return 11
    if score >= 25:
        return 7
    return 4


def compute_score(
    triggers: list[str],
    ti_match: bool = False,
    asset_type: str = "unknown",
) -> dict[str, Any]:
    """
    Compute EDR confidence score for a detection event.

    Args:
        triggers:   List of heuristic trigger keys (from HEURISTIC_TABLE).
        ti_match:   True if the event matched a MISP/TI cache indicator.
        asset_type: Asset classification string (from ASSET_MODIFIERS).

    Returns dict with:
        score, severity, rule_id, mitre_id, mitre_tactic,
        triggered_weights, asset_modifier
    """
    triggered = [HEURISTIC_TABLE[t] for t in triggers if t in HEURISTIC_TABLE]
    raw = sum(h["weight"] for h in triggered)
    if ti_match:
        raw += TI_MATCH_BONUS

    modifier = ASSET_MODIFIERS.get(asset_type, 1.0)
    final = min(100.0, round(raw * modifier, 1))

    severity = "low"
    for sev, threshold in SEVERITY_THRESHOLDS.items():
        if final >= threshold:
            severity = sev
            break

    # Primary rule_id and MITRE from the highest-weight trigger
    primary = max(triggered, key=lambda h: h["weight"]) if triggered else None
    rule_id    = primary["rule_id"]    if primary else 100399
    mitre_id   = primary["mitre"][0]  if primary else ""
    mitre_tactic = primary["mitre"][1] if primary else ""
    rule_desc  = primary["desc"]       if primary else "EDR behavioral detection"

    return {
        "score":        final,
        "severity":     severity,
        "rule_level":   score_to_rule_level(final),
        "rule_id":      rule_id,
        "rule_desc":    rule_desc,
        "mitre_id":     mitre_id,
        "mitre_tactic": mitre_tactic,
        "asset_modifier": modifier,
        "triggered_weights": {t: HEURISTIC_TABLE[t]["weight"] for t in triggers if t in HEURISTIC_TABLE},
        "ti_bonus":     TI_MATCH_BONUS if ti_match else 0,
    }
