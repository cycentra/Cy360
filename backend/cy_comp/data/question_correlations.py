"""
cy_comp/data/question_correlations.py
=======================================
Static cross-framework question correlation map.

Each CLUSTER groups question IDs from different frameworks that address the same
control theme. All pairs within a cluster are considered correlated, meaning that
if a user answers any one question, the engine can suggest propagating that answer
to the other questions in the same cluster.

similarity_type values:
  equivalent  — questions are substantively identical (same control, same requirement)
  overlapping — questions cover largely the same ground with minor scope differences
  related     — questions share the same theme but have different depth or scope

seed_correlations() is idempotent — safe to call at every startup.
"""

from itertools import combinations
from typing import Iterator

# ── Cluster definitions ───────────────────────────────────────────────────────
# Each cluster: (cluster_id, cluster_theme, similarity_type, [question_ids...])

CLUSTERS: list[tuple[str, str, str, list[str]]] = [

    # ── Governance & Board Accountability ─────────────────────────────────────
    (
        "GOV-01", "Governance & Board Accountability", "equivalent",
        [
            "iso-isms-02",    # ISO 27001 Cl.5.1-5.3 — top management sign-off, IS policy
            "nis2-gov-01",    # NIS2 Art.20(1) — management body formally approved policy
            "dora-gov-01",    # DORA Art.5(2) — management body approves ICT risk framework
            "soc2-cc1-02",   # SOC 2 CC1.3 — organisational structure, board oversight
            "nist-gv-01",    # NIST CSF GV.OC-01 — documented cybersecurity policy, leadership approval
            "pci-pol-01",    # PCI DSS Req.12.1 — comprehensive IS policy, all-staff acknowledgement
            "gdpr-gov-01",   # GDPR Art.5(2)/Art.24 — GDPR compliance programme, executive sponsorship
            "euaia-gov-04",  # EU AI Act Art.9 — board-level oversight of AI governance
        ],
    ),
    (
        "GOV-02", "Governance KPIs & Management Review", "equivalent",
        [
            "iso-isms-03",    # ISO 27001 Cl.6.2 — IS objectives, KPIs, management reporting
            "nis2-gov-03",    # NIS2 Art.20 — governance maturity score
            "dora-audit-01",  # DORA Art.6(5) — ICTRMF reviewed annually
            "soc2-cc4-01",   # SOC 2 CC4.1/CC4.2 — ongoing evaluations, deficiency tracking
            "nist-gv-05",    # NIST CSF GV.OV — management review of cybersecurity performance
        ],
    ),

    # ── Risk Assessment ───────────────────────────────────────────────────────
    (
        "RISK-01", "Formal Risk Assessment Process", "equivalent",
        [
            "iso-isms-04",   # ISO 27001 Cl.6.1.2 — documented risk assessment, risk register
            "nis2-risk-01",  # NIS2 Art.21(1) — formal annual cybersecurity risk assessment
            "dora-risk-02",  # DORA Art.6(2)(a) — ICT risks assessed annually
            "soc2-cc3-01",  # SOC 2 CC3.2 — risk assessment identifying TSC risks
            "nist-id-03",   # NIST CSF ID.RA-01/05 — risks identified and prioritised
            "pci-risk-01",  # PCI DSS Req.12.3 — formal risk assessment annually
            "euaia-risk-01", # EU AI Act Art.9(1) — AI risk management system, lifecycle
        ],
    ),
    (
        "RISK-02", "Risk Appetite & Tolerance", "equivalent",
        [
            "nis2-risk-02",  # NIS2 Art.21(1) — cyber risk appetite statement
            "dora-risk-01",  # DORA Art.6(1) — board-approved ICTRMF with risk tolerance
            "soc2-cc3-02",  # SOC 2 CC3.3/CC3.4 — fraud risk, change-triggered reviews
            "nist-gv-02",   # NIST CSF GV.RM-01/02 — cyber risk integrated into ERM, tolerance
        ],
    ),

    # ── Identity & Access Management ─────────────────────────────────────────
    (
        "IAM-01", "Access Control & Least Privilege", "equivalent",
        [
            "iso-org-08",   # ISO 27001 A.5.15/A.5.18 — access control policy, RBAC, access reviews
            "nis2-iam-01",  # NIS2 Art.21(2)(i) — least-privilege RBAC, accounts disabled on departure
            "dora-iam-01",  # DORA Art.9 — MFA for critical ICT, PAM, session recording
            "soc2-cc6-01",  # SOC 2 CC6.1-CC6.3 — least privilege, quarterly access reviews
            "nist-pr-01",   # NIST CSF PR.AA-01/06 — IAM, least privilege, periodic access reviews
            "pci-iam-01",   # PCI DSS Req.7.1/7.2 — access restricted to minimum necessary
            "gdpr-sec-02",  # GDPR Art.32(1)(b) — RBAC/least-privilege for personal data systems
        ],
    ),
    (
        "IAM-02", "Multi-Factor Authentication", "equivalent",
        [
            "iso-tech-02",  # ISO 27001 A.8.2 — PAM with MFA, enhanced monitoring
            "nis2-mfa-01",  # NIS2 Art.21(2)(j) — MFA for privileged accounts and remote access
            "soc2-cc6-02",  # SOC 2 CC6.1 — MFA enforced for all production/admin/remote access
            "nist-pr-01",   # NIST CSF PR.AA-06 — MFA for all users (shared with IAM-01)
            "pci-iam-02",   # PCI DSS Req.8.4.2/8.4.3 — MFA for non-console CDE admin access
            "gdpr-sec-02",  # GDPR Art.32(1)(b) — MFA for personal data systems
        ],
    ),

    # ── Incident Response ─────────────────────────────────────────────────────
    (
        "IR-01", "Incident Response Plan", "equivalent",
        [
            "iso-org-11",   # ISO 27001 A.5.24-A.5.28 — IRP covering all phases, evidence, post-IR review
            "nis2-ir-01",   # NIS2 Art.21(2)(b)/Art.23 — documented IRP for NIS2-significant incidents
            "dora-ir-01",   # DORA Art.17(1) — ICT IRP covering detection, classification, notification
            "soc2-cc7-02",  # SOC 2 CC7.3-CC7.5 — IRP with severity SLAs, customer notification
            "nist-rs-01",   # NIST CSF RS.MA-01/02 — documented IRP with scenario playbooks
            "pci-pol-03",   # PCI DSS Req.12.10 — IRP for cardholder data breaches
            "gdpr-breach-01", # GDPR Art.33 — breach response procedure, 72-hour notification
            "euaia-pmm-02",   # EU AI Act Art.73 — serious AI incident reporting procedure
        ],
    ),
    (
        "IR-02", "Incident Response Testing", "overlapping",
        [
            "iso-isms-07",  # ISO 27001 Cl.9.2 — internal audits with corrective action (proximate)
            "nis2-ir-02",   # NIS2 Art.21(2)(b) — IRP exercised in past 12 months
            "soc2-cc7-02",  # SOC 2 CC7.3 — IRP tested, tabletop exercise
            "nist-rs-01",   # NIST CSF RS.MA-01 — IRP tested at least annually
            "gdpr-breach-03", # GDPR Art.32/Art.5(2) — breach procedures tested, staff trained
        ],
    ),

    # ── Business Continuity & Backup ─────────────────────────────────────────
    (
        "BCP-01", "Business Continuity & Disaster Recovery", "equivalent",
        [
            "iso-org-12",   # ISO 27001 A.5.29/A.5.30 — BCP/DRP covering IS, ICT readiness tested
            "nis2-bcp-01",  # NIS2 Art.21(2)(c) — BCP/DRP covering essential services, RTO/RPO validated
            "dora-bcp-01",  # DORA Art.11(1) — BCP/DRP tested annually, RTO/RPO validated
            "soc2-av-01",   # SOC 2 A1.1/A1.2 — availability SLAs, DRP, RTO/RPO
            "nist-rc-01",   # NIST CSF RC.RP-01/02 — recovery plan with restoration priorities
            "gdpr-sec-04",  # GDPR Art.32(1)(c)(d) — tested process to restore availability of personal data
        ],
    ),
    (
        "BCP-02", "Backup & Recovery", "equivalent",
        [
            "iso-tech-07",  # ISO 27001 A.8.13/A.8.14 — backups tested, off-site, RPO/RTO compliant
            "nis2-bcp-02",  # NIS2 Art.21(2)(c) — backup tested, off-site/offline copies
            "dora-bcp-02",  # DORA Art.12(1) — 3-2-1 backup strategy, tested restorability
            "soc2-av-01",   # SOC 2 A1.2 — procedures to restore services within RTO/RPO
            "nist-rc-02",   # NIST CSF RC.RP-03 — offsite/offline backups, restoration validated
            "gdpr-sec-04",  # GDPR Art.32(1)(c)(d) — restore personal data availability after incident
        ],
    ),

    # ── Security Awareness & Training ─────────────────────────────────────────
    (
        "TRAIN-01", "Security Awareness Training", "equivalent",
        [
            "iso-ppl-03",         # ISO 27001 A.6.3 — mandatory annual IS awareness, role-specific training
            "nis2-train-01",      # NIS2 Art.21(2)(g) — mandatory annual cybersecurity training, >90%
            "soc2-cc1-03",        # SOC 2 CC1.4/CC1.5 — personnel competencies for security responsibilities
            "nist-pr-03",         # NIST CSF PR.AT-01/02 — security awareness and role-specific training
            "pci-pol-02",         # PCI DSS Req.12.6 — security awareness programme, phishing, annual
            "gdpr-gov-02",        # GDPR Art.39(1)(b) — GDPR awareness training for all staff handling PII
            "euaia-oversight-02", # EU AI Act Art.14(4) — human oversight training, automation-bias guidance
        ],
    ),

    # ── Cryptography & Encryption ─────────────────────────────────────────────
    (
        "CRYPTO-01", "Encryption & Key Management", "equivalent",
        [
            "iso-tech-11",  # ISO 27001 A.8.24 — cryptographic policy, AES-256/TLS 1.2+, key rotation
            "nis2-crypto-01", # NIS2 Art.21(2)(h) — data encrypted in transit and at rest
            "soc2-cc6-03",  # SOC 2 CC6.1/CC6.7 — encryption at rest and in transit, key management
            "nist-pr-02",   # NIST CSF PR.DS-01/02/10 — data classification, encryption, disposal
            "pci-tls-01",   # PCI DSS Req.4.2 — strong crypto (TLS 1.2+) for cardholder data in transit
            "gdpr-sec-01",  # GDPR Art.32(1)(a) — personal data encrypted at rest and in transit
            "euaia-sec-03", # EU AI Act Art.15(5) — cybersecurity controls for AI infrastructure, encryption
        ],
    ),

    # ── Vulnerability Management ──────────────────────────────────────────────
    (
        "VULN-01", "Vulnerability Management & Patching", "equivalent",
        [
            "iso-tech-04",  # ISO 27001 A.8.7/A.8.8 — malware protection, patch management SLAs
            "nis2-vuln-01", # NIS2 Art.21(2)(e) — vulnerability management programme, patching SLAs
            "dora-vuln-01", # DORA Art.6(2) — vulnerability scanning, severity-based patching SLAs
            "soc2-vuln-01", # SOC 2 CC7.1 — vulnerability management, severity-based remediation SLAs
            "nist-id-04",   # NIST CSF ID.RA-01 — vulnerabilities identified, used in risk assessment
            "pci-sdlc-01",  # PCI DSS Req.6.3 — patching within defined SLAs (critical ≤1 month)
        ],
    ),

    # ── Supply Chain / Third-Party Risk ──────────────────────────────────────
    (
        "SC-01", "Third-Party & Supply Chain Risk", "equivalent",
        [
            "iso-org-10",   # ISO 27001 A.5.19-A.5.23 — supplier security policy, contract clauses
            "nis2-sc-01",   # NIS2 Art.21(2)(d) — cybersecurity requirements in ICT supplier contracts
            "dora-tpr-01",  # DORA Art.28(2) — CTPP register, risk assessments before engagement
            "soc2-cc9-01",  # SOC 2 CC9.2 — vendor risk assessed, security in contracts, annual reviews
            "nist-sup-01",  # NIST CSF GV.SC-01/06 — supply chain risk programme, procurement requirements
            "pci-pol-04",   # PCI DSS Req.12.8 — vendor risk programme, annual PCI compliance attestation
            "gdpr-proc-01", # GDPR Art.28(3) — DPA with every processor, Art.28 mandatory clauses
        ],
    ),

    # ── Monitoring & Logging ──────────────────────────────────────────────────
    (
        "LOG-01", "Security Monitoring & SIEM", "equivalent",
        [
            "iso-tech-08",  # ISO 27001 A.8.15-A.8.17 — SIEM, log retention ≥12 months, NTP sync
            "nis2-mon-01",  # NIS2 Art.21(2)(b) — continuous SIEM/IDS monitoring, detection rules
            "dora-detect-01", # DORA Art.10(1) — continuous ICT risk monitoring, real-time dashboards
            "soc2-cc7-01",  # SOC 2 CC7.1/CC7.2 — production monitoring, SIEM, anomaly detection
            "nist-de-01",   # NIST CSF DE.CM-01/09 — continuous monitoring, SIEM/UEBA, detection rules
            "pci-log-01",   # PCI DSS Req.10.2/10.5 — audit logs for CDE systems, ≥12 months
            "euaia-doc-02", # EU AI Act Art.12(1) — automated logging for high-risk AI systems
        ],
    ),
    (
        "LOG-02", "Log Retention & Integrity", "equivalent",
        [
            "iso-tech-08",  # ISO 27001 A.8.15-A.8.17 — logs retained ≥12 months, protected from tampering
            "nis2-mon-02",  # NIS2 Art.21(2)(e) — logs retained ≥12 months, protected against modification
            "dora-log-01",  # DORA Art.10 — audit logs from critical ICT systems, sufficient retention
            "pci-log-01",   # PCI DSS Req.10.5 — logs ≥12 months, 3 months immediately accessible
            "euaia-doc-03", # EU AI Act Art.12(2) — AI logs retained ≥6 months, tamper-proof
        ],
    ),

    # ── Penetration Testing ───────────────────────────────────────────────────
    (
        "PENTEST-01", "Penetration Testing", "equivalent",
        [
            "nis2-audit-01",  # NIS2 Art.21(2)(f) — independent testing (pen tests) at least annually
            "dora-test-01",   # DORA Art.24(1) — annual ICT resilience tests, pen tests for critical systems
            "soc2-pen-01",    # SOC 2 CC4.1 — annual pen test, findings tracked, leadership briefed
            "nist-de-01",     # NIST CSF DE.CM — continuous monitoring (proximate)
            "pci-pentest-01", # PCI DSS Req.11.4 — annual pen test, CDE network and application layers
            "euaia-sec-02",   # EU AI Act Art.15(3)/(4) — adversarial testing / AI red-team exercises
        ],
    ),

    # ── Asset Management & Inventory ─────────────────────────────────────────
    (
        "ASSET-01", "Asset Inventory & Classification", "equivalent",
        [
            "iso-org-06",   # ISO 27001 A.5.9-A.5.12 — asset inventory, classifications, owners
            "nis2-iam-02",  # NIS2 Art.21(2)(i) — up-to-date inventory of all in-scope assets
            "dora-asset-01", # DORA Art.8(1) — complete ICT asset inventory, criticality classification
            "nist-id-01",   # NIST CSF ID.AM-01/02 — comprehensive inventory via automated discovery
            "gdpr-ropa-01", # GDPR Art.30 — RoPA covering all processing activities (data asset register)
            "euaia-gov-01", # EU AI Act Art.6/Annex III — AI system inventory with risk classification
        ],
    ),

    # ── Physical Security ────────────────────────────────────────────────────
    (
        "PHY-01", "Physical Access Controls", "equivalent",
        [
            "iso-phy-01",  # ISO 27001 A.7.1/A.7.2/A.7.4 — physical perimeters, entry controls, CCTV
            "soc2-cc6-04", # SOC 2 CC6.4 — physical access controls, visitor logs, badge access
            "pci-phy-01",  # PCI DSS Req.9.1/9.3 — physical access control, CDE badge readers, visitor logs
        ],
    ),

    # ── Secure Development Lifecycle ─────────────────────────────────────────
    (
        "SDLC-01", "Secure Development & Change Management", "equivalent",
        [
            "iso-tech-12",  # ISO 27001 A.8.25-A.8.29 — SDL: requirements, arch review, SAST/DAST
            "nis2-vuln-02", # NIS2 Art.21(2)(e) — security-by-design in acquisition and development
            "dora-protect-01", # DORA Art.9(1) — change management with security impact assessment
            "soc2-cc8-01",  # SOC 2 CC8.1 — formal change management, security review, rollback
            "pci-sdlc-02",  # PCI DSS Req.6.4 — web apps protected against OWASP Top 10 (WAF or DAST)
            "gdpr-pbd-01",  # GDPR Art.25(1) — privacy by design: pseudonymisation, encryption in arch
            "euaia-sec-03", # EU AI Act Art.15(5) — secure SDLC for AI systems
        ],
    ),

    # ── Threat Intelligence ───────────────────────────────────────────────────
    (
        "CTI-01", "Threat Intelligence", "equivalent",
        [
            "iso-org-04",   # ISO 27001 A.5.7 — threat intelligence programme
            "dora-cti-01",  # DORA Art.13(1) — threat intelligence feeds, ISAC membership
            "nist-de-03",   # NIST CSF DE.AE-02 — threat intelligence informs detection logic
        ],
    ),

    # ── Data Protection & Privacy ─────────────────────────────────────────────
    (
        "PRIV-01", "Data Privacy & PII Protection", "equivalent",
        [
            "iso-org-14",     # ISO 27001 A.5.34-A.5.36 — privacy / PII integration into ISMS
            "soc2-prv-01",    # SOC 2 P1.0 — privacy notice, DPIA register, data subject requests
            "gdpr-prin-01",   # GDPR Art.5(1)(a)/Art.6 — lawful basis for personal data processing
            "euaia-data-02",  # EU AI Act Art.10(5) — special-category data in AI training datasets
        ],
    ),

    # ── Incident Reporting to Authorities ────────────────────────────────────
    (
        "NOTIF-01", "Regulatory Incident Notification", "equivalent",
        [
            "nis2-report-01",  # NIS2 Art.23(1)(a) — early warning to CSIRT within 24 hours
            "nis2-report-02",  # NIS2 Art.23(1)(b-c) — detailed notification ≤72h, final report ≤1 month
            "dora-ir-03",      # DORA Art.19(4)(a) — initial notification to authority within 4 hours
            "dora-ir-04",      # DORA Art.19(4)(b-c) — intermediate ≤72h, final ≤1 month
            "gdpr-breach-01",  # GDPR Art.33 — supervisory authority notification within 72 hours
        ],
    ),
]


# ── Pair generator ────────────────────────────────────────────────────────────

def _generate_pairs() -> Iterator[tuple[str, str, str, str, str, str, str]]:
    """
    Yield (cluster_id, theme, sim_type, fw_a, qid_a, fw_b, qid_b) for every unique
    pair within each cluster. Framework key is derived from qid prefix.
    Pairs are emitted in both directions (A→B and B→A) for O(1) lookup by qid_a.
    """
    def _fw(qid: str) -> str:
        prefixes = {
            "iso-": "iso27001",
            "nis2-": "nis2",
            "dora-": "dora",
            "soc2-": "soc2",
            "nist-": "nist_csf",
            "pci-": "pci_dss",
            "gdpr-": "gdpr",
            "euaia-": "eu_ai_act",
        }
        for pfx, fw in prefixes.items():
            if qid.startswith(pfx):
                return fw
        return "unknown"

    seen: set[tuple[str, str]] = set()
    for cluster_id, theme, sim_type, qids in CLUSTERS:
        for qid_a, qid_b in combinations(qids, 2):
            pair = (qid_a, qid_b)
            rev  = (qid_b, qid_a)
            if pair not in seen and rev not in seen:
                seen.add(pair)
                fw_a = _fw(qid_a)
                fw_b = _fw(qid_b)
                yield (cluster_id, theme, sim_type, fw_a, qid_a, fw_b, qid_b)
                yield (cluster_id, theme, sim_type, fw_b, qid_b, fw_a, qid_a)


# ── Seed function ─────────────────────────────────────────────────────────────

def seed_correlations(conn) -> dict:
    """
    Populate cy_comp_question_correlations from CLUSTERS.
    Idempotent — uses ON CONFLICT DO NOTHING.
    conn: open psycopg2 connection (caller commits).
    Returns {inserted, skipped}.
    """
    inserted = 0
    skipped  = 0
    cur = conn.cursor()
    for (cluster_id, theme, sim_type, fw_a, qid_a, fw_b, qid_b) in _generate_pairs():
        cur.execute(
            """
            INSERT INTO cy_comp_question_correlations
                (cluster_id, cluster_theme, framework_a, question_id_a,
                 framework_b, question_id_b, similarity_type, confidence)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 1.0)
            ON CONFLICT (question_id_a, question_id_b) DO NOTHING;
            """,
            (cluster_id, theme, fw_a, qid_a, fw_b, qid_b, sim_type),
        )
        if cur.rowcount:
            inserted += 1
        else:
            skipped += 1
    return {"inserted": inserted, "skipped": skipped}
