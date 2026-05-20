"""
cy_comp/services/enrichment.py
===============================
Maps Wazuh rule IDs and MITRE ATT&CK techniques to compliance framework controls.
Ported and extended from CyComp standalone enrichment service.

Frameworks covered: NIS2, DORA, GDPR, ISO 27001:2022, SOC 2, NIST CSF 2.0, PCI DSS v4.0,
                    HIPAA Security Rule, TSC (Trust Services Criteria / SOC 2 CC/A/PI)
"""
from typing import Dict, List

# ── Severity thresholds (Wazuh rule level) ───────────────────────────────────
COMPLIANCE_MIN_LEVEL = 7   # below this → not compliance-relevant
CRITICAL_LEVEL       = 12
HIGH_LEVEL           = 10
MEDIUM_LEVEL         = 7


# ── MITRE ATT&CK → Framework Controls ───────────────────────────────────────
#
# Frameworks: nis2 | dora | gdpr | iso27001 | soc2 | nist_csf | pci_dss
#
# GDPR refs:         Art.5 | Art.25 | Art.32 | Art.33 | Art.34 | Art.35
# SOC 2 references:  CC1–CC9 Trust Services Criteria
# NIST CSF 2.0 refs: GV | ID.AM | PR.AA | PR.AT | PR.DS | PR.PS | DE.AE | DE.CM | RS.MA | RC.RP
# PCI DSS v4.0 refs: Req 1–Req 12
MITRE_TO_CONTROLS: Dict[str, Dict[str, List[str]]] = {
    # Credential access — brute force / password spraying
    "T1110": {
        "nis2":     ["NIS2-Art21-2i", "NIS2-Art21-2j"],
        "dora":     ["DORA-Art9", "DORA-Art10"],
        "gdpr":     ["GDPR-Art32"],
        "iso27001": ["ISO-A8.5", "ISO-A5.15"],
        "soc2":     ["CC6.1", "CC6.7"],
        "nist_csf": ["PR.AA-01", "PR.AA-02", "DE.CM-01"],
        "pci_dss":  ["Req 8.3", "Req 8.4"],
    },
    # Valid accounts — stolen credentials
    "T1078": {
        "nis2":     ["NIS2-Art21-2i", "NIS2-Art21-2j"],
        "dora":     ["DORA-Art9"],
        "gdpr":     ["GDPR-Art32", "GDPR-Art5-1f"],
        "iso27001": ["ISO-A5.16", "ISO-A8.2"],
        "soc2":     ["CC6.1", "CC6.2", "CC6.3"],
        "nist_csf": ["PR.AA-01", "PR.AA-05", "DE.CM-01"],
        "pci_dss":  ["Req 7.2", "Req 8.2"],
    },
    # Credentials from password stores
    "T1555": {
        "nis2":     ["NIS2-Art21-2i"],
        "dora":     ["DORA-Art9"],
        "gdpr":     ["GDPR-Art32"],
        "iso27001": ["ISO-A5.17"],
        "soc2":     ["CC6.1"],
        "nist_csf": ["PR.AA-02"],
        "pci_dss":  ["Req 8.3"],
    },
    # Abuse elevation / UAC bypass
    "T1548": {
        "nis2":     ["NIS2-Art21-2i"],
        "dora":     ["DORA-Art9", "DORA-Art10"],
        "gdpr":     ["GDPR-Art32"],
        "iso27001": ["ISO-A8.2", "ISO-A8.5"],
        "soc2":     ["CC6.3", "CC6.8"],
        "nist_csf": ["PR.AA-05", "DE.CM-03"],
        "pci_dss":  ["Req 7.3"],
    },
    # Exploit for privilege escalation
    "T1068": {
        "nis2":     ["NIS2-Art21-2e", "NIS2-Art21-2i"],
        "dora":     ["DORA-Art6", "DORA-Art9"],
        "gdpr":     ["GDPR-Art32", "GDPR-Art25"],
        "iso27001": ["ISO-A8.8", "ISO-A8.2"],
        "soc2":     ["CC7.1"],
        "nist_csf": ["PR.PS-01", "DE.CM-04"],
        "pci_dss":  ["Req 6.3", "Req 11.3"],
    },
    # Command and scripting interpreter / malware execution
    "T1059": {
        "nis2":     ["NIS2-Art21-2a"],
        "dora":     ["DORA-Art9", "DORA-Art10"],
        "gdpr":     ["GDPR-Art32"],
        "iso27001": ["ISO-A8.7"],
        "soc2":     ["CC6.8", "CC7.2"],
        "nist_csf": ["DE.CM-01", "PR.PS-01"],
        "pci_dss":  ["Req 5.2", "Req 6.2"],
    },
    # User execution (phishing payload)
    "T1204": {
        "nis2":     ["NIS2-Art21-2g"],
        "dora":     ["DORA-Art9"],
        "gdpr":     ["GDPR-Art32", "GDPR-Art5-1f"],
        "iso27001": ["ISO-A8.7"],
        "soc2":     ["CC9.2"],
        "nist_csf": ["PR.AT-01", "DE.AE-02"],
        "pci_dss":  ["Req 12.6"],
    },
    # Lateral movement via remote services
    "T1021": {
        "nis2":     ["NIS2-Art21-2i", "NIS2-Art21-2j"],
        "dora":     ["DORA-Art9", "DORA-Art10"],
        "gdpr":     ["GDPR-Art32"],
        "iso27001": ["ISO-A8.20", "ISO-A5.15"],
        "soc2":     ["CC6.6"],
        "nist_csf": ["PR.AA-05", "DE.CM-01"],
        "pci_dss":  ["Req 1.3", "Req 8.4"],
    },
    # Exfiltration over C2 channel
    "T1041": {
        "nis2":     ["NIS2-Art21-2b", "NIS2-Art23"],
        "dora":     ["DORA-Art11", "DORA-Art13"],
        "gdpr":     ["GDPR-Art33", "GDPR-Art5-1f"],
        "iso27001": ["ISO-A8.20"],
        "soc2":     ["CC6.7"],
        "nist_csf": ["DE.AE-02", "DE.CM-01"],
        "pci_dss":  ["Req 12.3"],
    },
    # Exfiltration over alternative protocol (DNS tunnelling, etc.)
    "T1048": {
        "nis2":     ["NIS2-Art21-2h", "NIS2-Art23"],
        "dora":     ["DORA-Art13"],
        "gdpr":     ["GDPR-Art33", "GDPR-Art34"],
        "iso27001": ["ISO-A8.20", "ISO-A8.22"],
        "soc2":     ["CC6.7"],
        "nist_csf": ["DE.AE-02", "PR.DS-01"],
        "pci_dss":  ["Req 4.2", "Req 12.3"],
    },
    # Defense evasion — impair defenses / disable AV
    "T1562": {
        "nis2":     ["NIS2-Art21-2a"],
        "dora":     ["DORA-Art10"],
        "gdpr":     ["GDPR-Art32"],
        "iso27001": ["ISO-A8.15", "ISO-A8.16"],
        "soc2":     ["CC7.2"],
        "nist_csf": ["DE.CM-09", "PR.PS-06"],
        "pci_dss":  ["Req 5.3", "Req 10.3"],
    },
    # Persistence via scheduled task / cron
    "T1053": {
        "nis2":     ["NIS2-Art21-2a"],
        "dora":     ["DORA-Art9"],
        "gdpr":     ["GDPR-Art32"],
        "iso27001": ["ISO-A8.16"],
        "soc2":     ["CC6.3"],
        "nist_csf": ["DE.CM-01", "PR.PS-01"],
        "pci_dss":  ["Req 6.3"],
    },
    # Discovery — network service scanning
    "T1046": {
        "nis2":     ["NIS2-Art21-2a"],
        "dora":     ["DORA-Art10"],
        "gdpr":     ["GDPR-Art25", "GDPR-Art32"],
        "iso27001": ["ISO-A8.20"],
        "soc2":     ["CC7.1"],
        "nist_csf": ["ID.AM-01", "DE.CM-01"],
        "pci_dss":  ["Req 11.4"],
    },
    # Exploit public-facing application
    "T1190": {
        "nis2":     ["NIS2-Art21-2e"],
        "dora":     ["DORA-Art6", "DORA-Art9"],
        "gdpr":     ["GDPR-Art32", "GDPR-Art25"],
        "iso27001": ["ISO-A8.8"],
        "soc2":     ["CC7.1", "CC6.6"],
        "nist_csf": ["PR.PS-01", "DE.CM-04"],
        "pci_dss":  ["Req 6.3", "Req 11.3"],
    },
    # Ransomware / data encryption for impact
    "T1486": {
        "nis2":     ["NIS2-Art21-2b", "NIS2-Art21-2c", "NIS2-Art23"],
        "dora":     ["DORA-Art11", "DORA-Art13"],
        "gdpr":     ["GDPR-Art33", "GDPR-Art34", "GDPR-Art32"],
        "iso27001": ["ISO-A8.24"],
        "soc2":     ["CC9.1", "CC7.5"],
        "nist_csf": ["RS.MA-01", "RC.RP-01"],
        "pci_dss":  ["Req 12.10"],
    },
}

# ── Wazuh Rule ID → Framework Controls ──────────────────────────────────────
WAZUH_RULE_TO_CONTROLS: Dict[str, Dict[str, List[str]]] = {
    # SSH authentication failures
    "5710": {
        "nis2":     ["NIS2-Art21-2i", "NIS2-Art21-2j"],
        "dora":     ["DORA-Art9", "DORA-Art10"],
        "gdpr":     ["GDPR-Art32"],
        "iso27001": ["ISO-A8.5"],
        "soc2":     ["CC6.1", "CC6.7"],
        "nist_csf": ["PR.AA-01", "DE.CM-01"],
        "pci_dss":  ["Req 8.3", "Req 10.2"],
    },
    "5763": {
        "nis2":     ["NIS2-Art21-2i"],
        "dora":     ["DORA-Art9"],
        "gdpr":     ["GDPR-Art32"],
        "iso27001": ["ISO-A8.5"],
        "soc2":     ["CC6.1"],
        "nist_csf": ["PR.AA-01", "DE.CM-01"],
        "pci_dss":  ["Req 8.3"],
    },
    # File integrity monitoring alerts
    "550": {
        "nis2":     ["NIS2-Art21-2e"],
        "dora":     ["DORA-Art9"],
        "gdpr":     ["GDPR-Art32", "GDPR-Art5-1f"],
        "iso27001": ["ISO-A8.15"],
        "soc2":     ["CC7.2"],
        "nist_csf": ["DE.CM-03", "PR.DS-01"],
        "pci_dss":  ["Req 10.3", "Req 11.5"],
    },
    "554": {
        "nis2":     ["NIS2-Art21-2e"],
        "dora":     ["DORA-Art9"],
        "gdpr":     ["GDPR-Art32", "GDPR-Art5-1f"],
        "iso27001": ["ISO-A8.15"],
        "soc2":     ["CC7.2"],
        "nist_csf": ["DE.CM-03", "PR.DS-01"],
        "pci_dss":  ["Req 10.3", "Req 11.5"],
    },
    # Vulnerability detection (Wazuh SCA / Vuls module)
    "23504": {
        "nis2":     ["NIS2-Art21-2e"],
        "dora":     ["DORA-Art6"],
        "gdpr":     ["GDPR-Art25", "GDPR-Art32"],
        "iso27001": ["ISO-A8.8"],
        "soc2":     ["CC7.1"],
        "nist_csf": ["ID.RA-01", "DE.CM-04"],
        "pci_dss":  ["Req 6.3", "Req 11.3"],
    },
    "23505": {
        "nis2":     ["NIS2-Art21-2e"],
        "dora":     ["DORA-Art6"],
        "gdpr":     ["GDPR-Art25", "GDPR-Art32"],
        "iso27001": ["ISO-A8.8"],
        "soc2":     ["CC7.1"],
        "nist_csf": ["ID.RA-01", "DE.CM-04"],
        "pci_dss":  ["Req 6.3", "Req 11.3"],
    },
    # Windows authentication events
    "18107": {
        "nis2":     ["NIS2-Art21-2i"],
        "dora":     ["DORA-Art9"],
        "gdpr":     ["GDPR-Art32"],
        "iso27001": ["ISO-A5.15"],
        "soc2":     ["CC6.2"],
        "nist_csf": ["PR.AA-01", "DE.CM-01"],
        "pci_dss":  ["Req 8.2", "Req 10.2"],
    },
    "18106": {
        "nis2":     ["NIS2-Art21-2i"],
        "dora":     ["DORA-Art9"],
        "gdpr":     ["GDPR-Art32"],
        "iso27001": ["ISO-A5.15"],
        "soc2":     ["CC6.2"],
        "nist_csf": ["PR.AA-01", "DE.CM-01"],
        "pci_dss":  ["Req 8.2", "Req 10.2"],
    },
    # Privilege escalation (sudo / su)
    "5402": {
        "nis2":     ["NIS2-Art21-2i"],
        "dora":     ["DORA-Art9"],
        "gdpr":     ["GDPR-Art32"],
        "iso27001": ["ISO-A8.2"],
        "soc2":     ["CC6.3"],
        "nist_csf": ["PR.AA-05", "DE.CM-03"],
        "pci_dss":  ["Req 7.3"],
    },
    # Rootkit / malware detection
    "510": {
        "nis2":     ["NIS2-Art21-2a", "NIS2-Art21-2b"],
        "dora":     ["DORA-Art10", "DORA-Art11"],
        "gdpr":     ["GDPR-Art32", "GDPR-Art33"],
        "iso27001": ["ISO-A8.7"],
        "soc2":     ["CC6.8", "CC7.2"],
        "nist_csf": ["DE.CM-04", "DE.AE-02"],
        "pci_dss":  ["Req 5.2", "Req 11.4"],
    },
}

# ── HIPAA Security Rule — MITRE ATT&CK technique → §164 controls ─────────────
# Refs: §164.312(a)(1) Access Control, §164.312(a)(2) Auto-logoff / Encryption,
#       §164.312(b) Audit Controls, §164.312(c)(1) Integrity,
#       §164.312(d) Person or Entity Auth, §164.312(e)(1)-(2) Transmission Security
HIPAA_TECHNIQUE_MAP: Dict[str, List[str]] = {
    "T1110": ["§164.312(a)(2)(i)", "§164.312(d)"],
    "T1078": ["§164.312(a)(1)", "§164.312(d)"],
    "T1556": ["§164.312(a)(2)(iii)", "§164.312(d)"],
    "T1548": ["§164.312(a)(1)", "§164.312(a)(2)(iv)"],
    "T1068": ["§164.312(a)(1)", "§164.308(a)(1)(ii)(D)"],
    "T1070": ["§164.312(b)"],
    "T1562": ["§164.312(b)", "§164.312(e)(2)(i)"],
    "T1040": ["§164.312(e)(1)", "§164.312(e)(2)(ii)"],
    "T1557": ["§164.312(e)(1)"],
    "T1485": ["§164.312(c)(1)"],
    "T1565": ["§164.312(c)(1)", "§164.312(c)(2)"],
    "T1530": ["§164.312(a)(1)", "§164.308(a)(3)"],
    "T1213": ["§164.312(a)(1)", "§164.308(a)(3)"],
    "T1021": ["§164.312(a)(1)", "§164.312(e)(1)"],
    "T1059": ["§164.312(b)", "§164.308(a)(1)(ii)(D)"],
    "T1053": ["§164.308(a)(5)(ii)(B)", "§164.312(b)"],
    "T1486": ["§164.312(c)(1)", "§164.308(a)(7)(ii)(A)"],
    "T1041": ["§164.312(e)(1)", "§164.308(a)(6)(ii)"],
    "T1566": ["§164.308(a)(5)(ii)(C)", "§164.308(a)(1)(ii)(D)"],
}

# ── TSC (Trust Services Criteria) — MITRE ATT&CK technique → CC/A/PI controls ─
# Refs: CC6 Logical Access, CC7 System Ops, CC8 Change Mgmt, CC9 Risk Mitigation,
#       A1 Availability, PI1 Processing Integrity
TSC_TECHNIQUE_MAP: Dict[str, List[str]] = {
    "T1110": ["CC6.1", "CC6.7"],
    "T1078": ["CC6.1", "CC6.2", "CC6.3"],
    "T1556": ["CC6.1", "CC6.8"],
    "T1548": ["CC6.3", "CC6.8"],
    "T1068": ["CC7.1", "CC6.8"],
    "T1070": ["CC7.2", "CC7.3"],
    "T1562": ["CC7.1", "CC7.2"],
    "T1021": ["CC6.6", "CC6.7"],
    "T1059": ["CC6.8", "CC7.2"],
    "T1053": ["CC6.3", "CC8.1"],
    "T1046": ["CC7.1", "CC6.6"],
    "T1190": ["CC7.1", "CC9.2"],
    "T1195": ["CC8.1", "CC9.1"],
    "T1499": ["A1.1", "A1.2"],
    "T1498": ["A1.1", "A1.2"],
    "T1485": ["A1.3", "PI1.1"],
    "T1565": ["PI1.1", "PI1.2"],
    "T1486": ["A1.3", "CC9.1"],
    "T1566": ["CC9.1", "CC9.2"],
    "T1041": ["CC6.7", "CC7.3"],
    "T1048": ["CC6.7", "CC7.3"],
}

# ── SCA rule ID range → compliance controls (hardening failures) ──────────────
# SCA policy check failures map to configuration management controls
_SCA_CONTROLS: Dict[str, List[str]] = {
    "nis2":     ["NIS2-Art21-2e", "NIS2-Art21-2h"],
    "dora":     ["DORA-Art9", "DORA-Art10"],
    "gdpr":     ["GDPR-Art25", "GDPR-Art32"],
    "iso27001": ["ISO-A8.8", "ISO-A8.9"],
    "soc2":     ["CC7.1", "CC8.1"],
    "nist_csf": ["PR.PS-01", "PR.PS-02", "ID.RA-01"],
    "pci_dss":  ["Req 2.2", "Req 6.3"],
    "hipaa":    ["§164.312(a)(2)(iv)", "§164.308(a)(1)(ii)(D)"],
    "tsc":      ["CC7.1", "CC8.1"],
}

# ── Framework tag from Wazuh rule groups ─────────────────────────────────────
_GROUP_TO_FRAMEWORK: Dict[str, str] = {
    "pci_dss":     "pci_dss",
    "gdpr":        "gdpr",
    "hipaa":       "hipaa",
    "nist_800_53": "nist_csf",
    "tsc":         "tsc",
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

    # 1. MITRE technique mapping (NIS2/DORA/GDPR/ISO/SOC2/NIST/PCI + HIPAA + TSC)
    for technique in str(mitre_field).replace(",", " ").split():
        technique = technique.strip()
        if technique in MITRE_TO_CONTROLS:
            for fw, ctrl_list in MITRE_TO_CONTROLS[technique].items():
                for c in ctrl_list:
                    controls.setdefault(fw, [])
                    if c not in controls[fw]:
                        controls[fw].append(c)
        if technique in HIPAA_TECHNIQUE_MAP:
            for c in HIPAA_TECHNIQUE_MAP[technique]:
                controls.setdefault("hipaa", [])
                if c not in controls["hipaa"]:
                    controls["hipaa"].append(c)
        if technique in TSC_TECHNIQUE_MAP:
            for c in TSC_TECHNIQUE_MAP[technique]:
                controls.setdefault("tsc", [])
                if c not in controls["tsc"]:
                    controls["tsc"].append(c)

    # 1b. SCA category — apply configuration management controls to all frameworks
    if alert.get("category") == "sca":
        for fw, ctrl_list in _SCA_CONTROLS.items():
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
