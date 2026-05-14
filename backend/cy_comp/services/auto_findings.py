"""
cy_comp/services/auto_findings.py
====================================
Auto-generate cy_comp_findings from compliance-relevant alerts.

Verdict logic:
  BREACH   — critical/high alert with high confidence (>=0.7)
  WARNING  — medium alert or lower confidence
  COMPLIANT— alert enriched but score below COMPLIANCE_MIN_LEVEL

Dedup: one finding per (framework, control_id, source_type='automated').
       Existing findings are updated (alert_count, last_seen_at, verdict).
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from cy_comp.models import db

log = logging.getLogger("cycentra.cy_comp.auto_findings")

COMPLIANCE_MIN_LEVEL = 5  # same as siem_bridge

# ── Remediation guidance ──────────────────────────────────────────────────────
# Maps MITRE ATT&CK technique ID → remediation actions + relevant frameworks

REMEDIATION_GUIDANCE: dict[str, dict] = {
    # Credential Access
    "T1110": {
        "title":      "Brute Force Attack",
        "actions":    [
            "Enable account lockout policies (3–5 failed attempts → 15 min lockout).",
            "Enforce MFA on all privileged and remote-access accounts.",
            "Restrict authentication endpoints to known IP ranges where feasible.",
            "Alert on >5 failed logins within 60 seconds per account.",
            "Review and rotate any accounts that received successful auth after multiple failures.",
        ],
        "frameworks": ["nis2", "iso27001", "soc2", "nist_csf", "pci_dss"],
        "controls":   {"nis2": ["Art.21(2)(i)"], "iso27001": ["A.8.5"], "pci_dss": ["Req 8.3"]},
    },
    "T1110.001": {
        "title":   "Password Guessing",
        "actions": [
            "Deploy password complexity policy: min 12 chars, mixed case, special characters.",
            "Block common password lists using HIBP or equivalent.",
            "Enable adaptive MFA triggered by failed-login velocity.",
        ],
        "frameworks": ["nis2", "iso27001", "pci_dss"],
        "controls":   {"iso27001": ["A.8.5"], "pci_dss": ["Req 8.3.6"]},
    },
    "T1078": {
        "title":   "Valid Accounts",
        "actions": [
            "Audit all privileged accounts quarterly; disable stale accounts within 30 days.",
            "Enforce principle of least privilege — remove admin rights from non-admin roles.",
            "Deploy PAM (Privileged Access Management) solution for all admin credentials.",
            "Alert on logins outside normal hours or from unusual geolocation.",
        ],
        "frameworks": ["nis2", "dora", "iso27001", "soc2", "pci_dss"],
        "controls":   {"nis2": ["Art.21(2)(i)"], "iso27001": ["A.5.15", "A.5.18"], "pci_dss": ["Req 7"]},
    },
    # Lateral Movement
    "T1021": {
        "title":   "Remote Services",
        "actions": [
            "Restrict RDP/SSH to jump hosts only; block direct access from internet.",
            "Require MFA for all remote service logins.",
            "Log all remote-session commands; store logs in tamper-evident SIEM.",
            "Segment network so lateral movement requires explicit firewall rules.",
        ],
        "frameworks": ["nis2", "iso27001", "soc2", "nist_csf"],
        "controls":   {"nis2": ["Art.21(2)(e)"], "iso27001": ["A.8.20"], "soc2": ["CC6.6"]},
    },
    # Privilege Escalation
    "T1068": {
        "title":   "Exploitation for Privilege Escalation",
        "actions": [
            "Apply security patches within 48 hours of critical CVE publication.",
            "Deploy EDR on all endpoints with exploit-protection rules enabled.",
            "Run vulnerability scans weekly on all internal systems.",
            "Restrict compiler/interpreter access on production systems.",
        ],
        "frameworks": ["nis2", "dora", "iso27001", "pci_dss"],
        "controls":   {"nis2": ["Art.21(2)(e)"], "iso27001": ["A.8.8"], "pci_dss": ["Req 6.3"]},
    },
    # Defense Evasion
    "T1562": {
        "title":   "Impair Defenses",
        "actions": [
            "Alert immediately on any security tool being stopped, uninstalled, or reconfigured.",
            "Protect agent/AV processes with tamper protection; require admin + MFA to disable.",
            "Correlate defense-evasion events with lateral movement to detect kill chains.",
        ],
        "frameworks": ["nis2", "soc2", "nist_csf"],
        "controls":   {"nis2": ["Art.21(2)(b)"], "soc2": ["CC7.2"]},
    },
    # Exfiltration
    "T1048": {
        "title":   "Exfiltration Over Alternative Protocol",
        "actions": [
            "Block unapproved protocols at perimeter (DNS over HTTPS, ICMP tunnelling, etc.).",
            "Deploy DLP (Data Loss Prevention) on endpoints and email gateway.",
            "Alert on large outbound transfers (>100 MB) to unknown destinations.",
            "Monitor and restrict USB / removable storage on sensitive workstations.",
        ],
        "frameworks": ["nis2", "dora", "iso27001", "pci_dss", "avg"],
        "controls":   {"nis2": ["Art.21(2)(f)"], "iso27001": ["A.8.24"], "pci_dss": ["Req 12.3"]},
    },
    # Command & Control
    "T1071": {
        "title":   "Application Layer Protocol C2",
        "actions": [
            "Block outbound connections to uncategorised / newly-registered domains.",
            "Deploy network-based IDS/IPS with C2 threat-intelligence feeds.",
            "Inspect TLS traffic at egress proxy for certificate anomalies.",
            "Sandbox all email attachments and URLs before delivery.",
        ],
        "frameworks": ["nis2", "iso27001", "nist_csf"],
        "controls":   {"nis2": ["Art.21(2)(e)"], "iso27001": ["A.8.22"]},
    },
    # Initial Access
    "T1566": {
        "title":   "Phishing",
        "actions": [
            "Deploy DMARC/DKIM/SPF and reject email that fails all three.",
            "Implement anti-phishing training with simulated phishing campaigns quarterly.",
            "Enable safe-links and safe-attachments in email security gateway.",
            "Report phishing metrics to management monthly.",
        ],
        "frameworks": ["nis2", "iso27001", "soc2", "nist_csf"],
        "controls":   {"nis2": ["Art.21(2)(g)"], "iso27001": ["A.6.3"], "soc2": ["CC9.2"]},
    },
    # Impact
    "T1486": {
        "title":   "Data Encrypted for Impact (Ransomware)",
        "actions": [
            "Maintain tested offline backups with 3-2-1 strategy; verify restores monthly.",
            "Segment backup storage from production network.",
            "Deploy honeypot files to detect mass encryption early.",
            "Develop and test ransomware-specific IR playbook at least annually.",
        ],
        "frameworks": ["nis2", "dora", "iso27001", "soc2"],
        "controls":   {"nis2": ["Art.21(2)(c)"], "dora": ["Art.12"], "iso27001": ["A.8.13"]},
    },
    # Discovery
    "T1046": {
        "title":   "Network Service Discovery",
        "actions": [
            "Disable unnecessary services and close unused ports — enforce least exposure.",
            "Alert on internal port scans from non-scanner IPs.",
            "Maintain an up-to-date asset inventory; flag unrecognised hosts automatically.",
        ],
        "frameworks": ["nis2", "iso27001", "nist_csf"],
        "controls":   {"nis2": ["Art.21(2)(a)"], "iso27001": ["A.8.8"]},
    },
    # Persistence
    "T1053": {
        "title":   "Scheduled Task/Job",
        "actions": [
            "Audit all scheduled tasks and cron jobs on servers weekly.",
            "Alert on creation of new scheduled tasks outside maintenance windows.",
            "Restrict who can create scheduled tasks using group policy / sudo rules.",
        ],
        "frameworks": ["iso27001", "soc2", "nist_csf"],
        "controls":   {"iso27001": ["A.8.5"], "soc2": ["CC6.3"]},
    },
    # Collection
    "T1005": {
        "title":   "Data from Local System",
        "actions": [
            "Classify sensitive data and apply access controls based on classification.",
            "Deploy file-integrity monitoring on directories containing sensitive data.",
            "Alert on mass file access or unusual copy-to-external operations.",
        ],
        "frameworks": ["iso27001", "pci_dss", "avg"],
        "controls":   {"iso27001": ["A.5.12", "A.5.13"], "avg": ["Art.25", "Art.32"]},
    },
}

DEFAULT_REMEDIATION = {
    "title":   "Security Finding",
    "actions": [
        "Investigate alert source and determine scope of impact.",
        "Isolate affected systems if active exploitation is suspected.",
        "Apply relevant security patches and configuration hardening.",
        "Review and update relevant security controls.",
        "Document findings and lessons learned in the incident register.",
    ],
    "frameworks": [],
    "controls":   {},
}


def _get_remediation(mitre_id: Optional[str]) -> dict:
    if not mitre_id:
        return DEFAULT_REMEDIATION
    # Try exact, then parent technique
    r = REMEDIATION_GUIDANCE.get(mitre_id)
    if r:
        return r
    parent = mitre_id.split(".")[0] if "." in mitre_id else None
    return REMEDIATION_GUIDANCE.get(parent, DEFAULT_REMEDIATION) if parent else DEFAULT_REMEDIATION


def _verdict(rule_level: int, confidence: float) -> str:
    if rule_level >= 12 and confidence >= 0.7:
        return "breach"
    if rule_level >= 10 or (rule_level >= 7 and confidence >= 0.6):
        return "warning"
    return "compliant"


def _severity_from_level(level: int) -> str:
    if level >= 12: return "critical"
    if level >= 10: return "high"
    if level >= 7:  return "medium"
    return "low"


# ── Main generator ────────────────────────────────────────────────────────────

def generate_findings_from_alerts(
    framework: Optional[str] = None,
    created_by: Optional[str] = None,
) -> dict:
    """
    Scan compliance-relevant alerts and create/update cy_comp_findings.

    One finding per (framework, control_id) pair — aggregated across alerts.
    Existing auto-generated findings are updated rather than duplicated.

    Returns {created, updated, skipped, frameworks_processed}.
    """
    created   = 0
    updated   = 0
    skipped   = 0
    fw_done: set[str] = set()

    try:
        with db() as conn:
            cur = conn.cursor()

            # Pull aggregated alert data per framework × MITRE technique
            fw_filter = "AND %s = ANY(compliance_frameworks)" if framework else ""
            params: list = [framework] if framework else []

            cur.execute(
                f"""
                SELECT
                    unnest(compliance_frameworks)   AS fw,
                    mitre_id,
                    rule_desc,
                    category,
                    MAX(rule_level)                 AS max_level,
                    MAX(compliance_confidence)       AS max_conf,
                    COUNT(*)                        AS alert_count,
                    MAX(timestamp)                  AS last_seen,
                    compliance_controls
                FROM alerts
                WHERE is_compliance_relevant = TRUE
                  {fw_filter}
                GROUP BY fw, mitre_id, rule_desc, category, compliance_controls
                ORDER BY fw, max_level DESC;
                """,
                params,
            )
            aggregated = cur.fetchall()

            for row in aggregated:
                fw_name      = row[0]
                mitre_id     = row[1]
                rule_desc    = row[2] or "Security Alert"
                category     = row[3]
                max_level    = int(row[4] or 5)
                max_conf     = float(row[5] or 0.5)
                alert_count  = int(row[6] or 1)
                last_seen    = row[7]
                controls_raw = row[8] or {}

                fw_done.add(fw_name)
                rem      = _get_remediation(mitre_id)
                verdict  = _verdict(max_level, max_conf)
                severity = _severity_from_level(max_level)

                # Control reference from enrichment or mitre
                control_id = (
                    ", ".join(controls_raw.get(fw_name, [])[:2])
                    if isinstance(controls_raw, dict) and controls_raw.get(fw_name)
                    else (mitre_id or "UNKNOWN")
                )

                title = f"{rem['title']} — {rule_desc[:80]}"
                desc  = (
                    f"Auto-generated from {alert_count} compliance-relevant alert(s).\n"
                    f"MITRE: {mitre_id or 'N/A'}  |  Category: {category or 'N/A'}\n"
                    f"Max rule level: {max_level}  |  Confidence: {round(max_conf * 100)}%"
                )
                remediation = "\n".join(f"• {a}" for a in rem["actions"])

                # Dedup check
                cur.execute(
                    """
                    SELECT id FROM cy_comp_findings
                    WHERE framework = %s AND control_id = %s
                      AND source_type = 'automated' AND auto_generated = TRUE
                    LIMIT 1;
                    """,
                    (fw_name, control_id)
                )
                existing = cur.fetchone()

                if existing:
                    cur.execute(
                        """
                        UPDATE cy_comp_findings SET
                            severity    = %s,
                            verdict     = %s,
                            alert_count = %s,
                            last_seen_at= %s,
                            title       = %s,
                            description = %s,
                            remediation = %s,
                            updated_at  = NOW()
                        WHERE id = %s;
                        """,
                        (severity, verdict, alert_count, last_seen,
                         title, desc, remediation, existing[0])
                    )
                    updated += 1
                else:
                    cur.execute(
                        """
                        INSERT INTO cy_comp_findings
                            (framework, control_id, control_name, severity, title,
                             description, remediation, status, source_type,
                             auto_generated, verdict, alert_count, last_seen_at, created_by)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,'open','automated',TRUE,%s,%s,%s,%s);
                        """,
                        (
                            fw_name, control_id, category or rem["title"],
                            severity, title, desc, remediation,
                            verdict, alert_count, last_seen, created_by,
                        )
                    )
                    created += 1

    except Exception as exc:
        log.error("generate_findings_from_alerts: %s", exc)
        raise

    return {
        "created":             created,
        "updated":             updated,
        "skipped":             skipped,
        "frameworks_processed": sorted(fw_done),
    }


def get_findings_summary() -> dict:
    """Counts of auto-generated findings by verdict, for the dashboard."""
    out = {"breach": 0, "warning": 0, "compliant": 0, "total": 0}
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT verdict, COUNT(*) FROM cy_comp_findings
                WHERE auto_generated = TRUE AND status = 'open'
                GROUP BY verdict;
                """
            )
            for verdict, cnt in cur.fetchall():
                k = verdict or "warning"
                out[k] = int(cnt)
                out["total"] += int(cnt)
    except Exception as exc:
        log.error("get_findings_summary: %s", exc)
    return out


def get_remediation_for_mitre(mitre_id: str) -> dict:
    """Public helper — return remediation dict for a MITRE technique."""
    return _get_remediation(mitre_id)
