"""
cy_comp/services/enrichment.py
===============================
Maps Wazuh rule IDs and MITRE ATT&CK techniques to compliance framework controls.
Ported and extended from CyComp standalone enrichment service.

Frameworks covered: NIS2, DORA, AVG (GDPR-NL), ISO 27001:2022, SOC 2
"""
from typing import Dict, List

# ── Severity thresholds (Wazuh rule level) ───────────────────────────────────
COMPLIANCE_MIN_LEVEL = 7   # below this → not compliance-relevant
CRITICAL_LEVEL       = 12
HIGH_LEVEL           = 10
MEDIUM_LEVEL         = 7


# ── MITRE ATT&CK → Framework Controls ───────────────────────────────────────
MITRE_TO_CONTROLS: Dict[str, Dict[str, List[str]]] = {
    # Credential access
    "T1110": {"nis2": ["NIS2-Art21-2i", "NIS2-Art21-2j"], "dora": ["DORA-Art9", "DORA-Art10"], "iso27001": ["ISO-A8.5", "ISO-A5.15"]},
    "T1078": {"nis2": ["NIS2-Art21-2i", "NIS2-Art21-2j"], "dora": ["DORA-Art9"],               "iso27001": ["ISO-A5.16", "ISO-A8.2"]},
    "T1555": {"nis2": ["NIS2-Art21-2i"],                   "dora": ["DORA-Art9"],               "iso27001": ["ISO-A5.17"]},
    # Privilege escalation
    "T1548": {"nis2": ["NIS2-Art21-2i"],                   "dora": ["DORA-Art9", "DORA-Art10"], "iso27001": ["ISO-A8.2", "ISO-A8.5"]},
    "T1068": {"nis2": ["NIS2-Art21-2e", "NIS2-Art21-2i"],  "dora": ["DORA-Art6", "DORA-Art9"],  "iso27001": ["ISO-A8.8", "ISO-A8.2"]},
    # Execution / malware
    "T1059": {"nis2": ["NIS2-Art21-2a"],                   "dora": ["DORA-Art9", "DORA-Art10"], "iso27001": ["ISO-A8.7"]},
    "T1204": {"nis2": ["NIS2-Art21-2g"],                   "dora": ["DORA-Art9"],               "iso27001": ["ISO-A8.7"]},
    # Lateral movement
    "T1021": {"nis2": ["NIS2-Art21-2i", "NIS2-Art21-2j"], "dora": ["DORA-Art9", "DORA-Art10"], "iso27001": ["ISO-A8.20", "ISO-A5.15"]},
    # Exfiltration
    "T1041": {"nis2": ["NIS2-Art21-2b", "NIS2-Art23"],    "dora": ["DORA-Art11", "DORA-Art13"], "iso27001": ["ISO-A8.20"], "avg": ["AVG-Art33"]},
    "T1048": {"nis2": ["NIS2-Art21-2h", "NIS2-Art23"],    "dora": ["DORA-Art13"],               "avg": ["AVG-Art33"]},
    # Defense evasion
    "T1562": {"nis2": ["NIS2-Art21-2a"],                   "dora": ["DORA-Art10"],              "iso27001": ["ISO-A8.15", "ISO-A8.16"]},
    # Persistence
    "T1053": {"nis2": ["NIS2-Art21-2a"],                   "dora": ["DORA-Art9"],               "iso27001": ["ISO-A8.16"]},
    # Discovery
    "T1046": {"nis2": ["NIS2-Art21-2a"],                   "dora": ["DORA-Art10"],              "iso27001": ["ISO-A8.20"]},
    # Vulnerability exploitation
    "T1190": {"nis2": ["NIS2-Art21-2e"],                   "dora": ["DORA-Art6", "DORA-Art9"],  "iso27001": ["ISO-A8.8"]},
    # Ransomware / encryption
    "T1486": {"nis2": ["NIS2-Art21-2b", "NIS2-Art21-2c", "NIS2-Art23"], "dora": ["DORA-Art11", "DORA-Art13"], "iso27001": ["ISO-A8.24"]},
}

# ── Wazuh Rule ID → Framework Controls ──────────────────────────────────────
WAZUH_RULE_TO_CONTROLS: Dict[str, Dict[str, List[str]]] = {
    # SSH failures
    "5710":  {"nis2": ["NIS2-Art21-2i", "NIS2-Art21-2j"], "dora": ["DORA-Art9", "DORA-Art10"], "iso27001": ["ISO-A8.5"]},
    "5763":  {"nis2": ["NIS2-Art21-2i"],                   "dora": ["DORA-Art9"],               "iso27001": ["ISO-A8.5"]},
    # File integrity
    "550":   {"nis2": ["NIS2-Art21-2e"],                   "dora": ["DORA-Art9"],               "iso27001": ["ISO-A8.15"]},
    "554":   {"nis2": ["NIS2-Art21-2e"],                   "dora": ["DORA-Art9"],               "iso27001": ["ISO-A8.15"]},
    # Vulnerability detection
    "23504": {"nis2": ["NIS2-Art21-2e"],                   "dora": ["DORA-Art6"],               "iso27001": ["ISO-A8.8"]},
    "23505": {"nis2": ["NIS2-Art21-2e"],                   "dora": ["DORA-Art6"],               "iso27001": ["ISO-A8.8"]},
    # Windows auth
    "18107": {"nis2": ["NIS2-Art21-2i"],                   "dora": ["DORA-Art9"],               "iso27001": ["ISO-A5.15"]},
    "18106": {"nis2": ["NIS2-Art21-2i"],                   "dora": ["DORA-Art9"],               "iso27001": ["ISO-A5.15"]},
    # Privilege escalation
    "5402":  {"nis2": ["NIS2-Art21-2i"],                   "dora": ["DORA-Art9"],               "iso27001": ["ISO-A8.2"]},
    # Rootkit / malware
    "510":   {"nis2": ["NIS2-Art21-2a", "NIS2-Art21-2b"],  "dora": ["DORA-Art10", "DORA-Art11"], "iso27001": ["ISO-A8.7"]},
}

# ── Framework tag from Wazuh rule groups ─────────────────────────────────────
_GROUP_TO_FRAMEWORK: Dict[str, str] = {
    "pci_dss":     "pci_dss",
    "gdpr":        "avg",
    "hipaa":       "hipaa",
    "nist_800_53": "nist_csf",
    "tsc":         "soc2",
}


def enrich_alert(alert: dict) -> dict:
    """
    Given a normalized alert dict, return it enriched with:
      - is_compliance_relevant: bool
      - controls: dict mapping framework → list of control IDs
      - severity: critical / high / medium / low (derived from rule_level)
      - primary_framework: best-guess framework label for the alert

    Rule levels below COMPLIANCE_MIN_LEVEL are dropped (is_compliance_relevant=False).
    """
    rule_level      = int(alert.get("rule_level") or alert.get("level") or 0)
    rule_id         = str(alert.get("rule_id") or alert.get("external_id") or "")
    mitre_field     = alert.get("mitre_technique") or alert.get("mitre") or ""
    rule_groups     = alert.get("rule_groups") or []

    if rule_level < COMPLIANCE_MIN_LEVEL:
        return {**alert, "is_compliance_relevant": False, "controls": {}}

    controls: Dict[str, List[str]] = {}

    # 1. MITRE technique mapping
    for technique in str(mitre_field).replace(",", " ").split():
        technique = technique.strip()
        if technique in MITRE_TO_CONTROLS:
            for fw, ctrl_list in MITRE_TO_CONTROLS[technique].items():
                for c in ctrl_list:
                    controls.setdefault(fw, [])
                    if c not in controls[fw]:
                        controls[fw].append(c)

    # 2. Wazuh rule ID mapping
    if rule_id in WAZUH_RULE_TO_CONTROLS:
        for fw, ctrl_list in WAZUH_RULE_TO_CONTROLS[rule_id].items():
            for c in ctrl_list:
                controls.setdefault(fw, [])
                if c not in controls[fw]:
                    controls[fw].append(c)

    # 3. Severity from rule level
    if rule_level >= CRITICAL_LEVEL:
        severity = "critical"
    elif rule_level >= HIGH_LEVEL:
        severity = "high"
    elif rule_level >= MEDIUM_LEVEL:
        severity = "medium"
    else:
        severity = "low"

    # 4. Primary framework guess from Wazuh groups (fallback)
    primary_framework = alert.get("framework")
    if not primary_framework and rule_groups:
        for grp in rule_groups:
            if grp in _GROUP_TO_FRAMEWORK:
                primary_framework = _GROUP_TO_FRAMEWORK[grp]
                break
    if not primary_framework and controls:
        primary_framework = next(iter(controls))

    return {
        **alert,
        "is_compliance_relevant": True,
        "controls":               controls,
        "severity":               severity,
        "framework":              primary_framework or alert.get("framework"),
    }
