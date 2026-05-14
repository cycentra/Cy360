"""
cy_comp/data/questionnaires.py
================================
Comprehensive compliance questionnaire templates for all six supported frameworks.

Each question dict:
  qid          — globally unique, stable ID (used as foreign key in responses)
  section      — readable section name within the framework
  question     — the assessment question (plain language)
  guidance     — what evidence or implementation to look for
  control_ref  — specific article / control / clause reference
  weight       — 1=informational, 2=standard, 3=critical
  question_type— yes_no | score_1_5 | multi_choice | text
  options      — list of choices for multi_choice type
  order_idx    — display order within section

Scoring logic (applied by questionnaire service):
  yes_no:     YES → score=2 (pass), NO → score=0 (gap/finding)
  score_1_5:  1-2 → gap, 3 → partial, 4-5 → pass
  multi_choice: each option has an implicit score; evaluated by caller
  text:       no automatic score — analyst reviews manually
"""

# ── NIS2 (Network and Information Security Directive 2) ───────────────────────
NIS2 = [
    # Section 1: Governance & Accountability
    {
        "qid": "nis2-gov-01", "section": "Governance & Accountability",
        "question": "Has the organisation's management body formally approved and endorsed the NIS2 cybersecurity risk management policy?",
        "guidance": "NIS2 Art.20 requires top management to take direct accountability. Evidence: signed policy, board minutes, CISO appointment letter.",
        "control_ref": "NIS2 Art.20(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 1,
    },
    {
        "qid": "nis2-gov-02", "section": "Governance & Accountability",
        "question": "Are management members required to complete NIS2 cybersecurity training, and is completion tracked?",
        "guidance": "Art.20(2) mandates that management undertake training. Evidence: training records, certificates, LMS logs.",
        "control_ref": "NIS2 Art.20(2)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 2,
    },
    {
        "qid": "nis2-gov-03", "section": "Governance & Accountability",
        "question": "Does the organisation maintain an up-to-date inventory of all in-scope essential/important services and their supporting assets?",
        "guidance": "Evidence: CMDB, asset register covering network, systems, applications, and data classified as in-scope for NIS2.",
        "control_ref": "NIS2 Art.21(2)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 3,
    },
    {
        "qid": "nis2-gov-04", "section": "Governance & Accountability",
        "question": "How mature is the organisation's cybersecurity governance structure? (1=ad-hoc, 5=fully defined with KPIs and board reporting)",
        "guidance": "Look for: CISO role, cybersecurity committee, defined roles/responsibilities, regular board reporting.",
        "control_ref": "NIS2 Art.20", "weight": 3, "question_type": "score_1_5", "options": [], "order_idx": 4,
    },
    # Section 2: Risk Management
    {
        "qid": "nis2-risk-01", "section": "Risk Management",
        "question": "Does the organisation conduct a formal cybersecurity risk assessment at least annually covering all in-scope systems?",
        "guidance": "Art.21(1) requires proportionate risk management. Evidence: risk register, assessment reports dated within 12 months.",
        "control_ref": "NIS2 Art.21(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 5,
    },
    {
        "qid": "nis2-risk-02", "section": "Risk Management",
        "question": "Are risk treatment plans documented with owners and target remediation dates for each identified risk?",
        "guidance": "Evidence: risk register with owner, risk appetite statement, treatment plan with due dates tracked to closure.",
        "control_ref": "NIS2 Art.21(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 6,
    },
    {
        "qid": "nis2-risk-03", "section": "Risk Management",
        "question": "Has the organisation defined and documented its cyber risk appetite, and is it reviewed at least annually?",
        "guidance": "Evidence: board-approved risk appetite statement, risk tolerance thresholds per category.",
        "control_ref": "NIS2 Art.21(1)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 7,
    },
    # Section 3: Technical & Operational Security
    {
        "qid": "nis2-tech-01", "section": "Technical Security Measures",
        "question": "Are all privileged accounts protected with Multi-Factor Authentication (MFA) and are remote access connections MFA-enforced?",
        "guidance": "Art.21(2)(j) explicitly requires MFA. Evidence: IAM configuration, PAM tool reports, VPN access policy.",
        "control_ref": "NIS2 Art.21(2)(j)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 8,
    },
    {
        "qid": "nis2-tech-02", "section": "Technical Security Measures",
        "question": "Is data classified and encrypted in transit and at rest using current cryptographic standards?",
        "guidance": "Art.21(2)(j) requires encryption. Evidence: TLS 1.2+ for transit, AES-256 for rest; key management procedure.",
        "control_ref": "NIS2 Art.21(2)(j)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 9,
    },
    {
        "qid": "nis2-tech-03", "section": "Technical Security Measures",
        "question": "Is a vulnerability management programme in place with defined SLAs for patching critical vulnerabilities (e.g., within 7-30 days)?",
        "guidance": "Art.21(2)(e) covers vulnerability handling. Evidence: scanner reports, patch SLA policy, exception process.",
        "control_ref": "NIS2 Art.21(2)(e)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 10,
    },
    {
        "qid": "nis2-tech-04", "section": "Technical Security Measures",
        "question": "How effective is the organisation's network segmentation and access control implementation? (1=flat network, 5=micro-segmented with zero-trust)",
        "guidance": "Evidence: network diagrams, firewall rule reviews, VLAN configuration, zero-trust architecture documentation.",
        "control_ref": "NIS2 Art.21(2)(i)", "weight": 3, "question_type": "score_1_5", "options": [], "order_idx": 11,
    },
    {
        "qid": "nis2-tech-05", "section": "Technical Security Measures",
        "question": "Are backup procedures tested regularly, and can the organisation restore critical systems within its Recovery Time Objective (RTO)?",
        "guidance": "Art.21(2)(c) covers backup and business continuity. Evidence: backup test reports, RTO/RPO definition, DR test results.",
        "control_ref": "NIS2 Art.21(2)(c)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 12,
    },
    # Section 4: Incident Response & Reporting
    {
        "qid": "nis2-ir-01", "section": "Incident Response & Reporting",
        "question": "Does the organisation have a documented Incident Response Plan (IRP) specific to NIS2-significant incidents, with defined roles and escalation paths?",
        "guidance": "Art.21(2)(b) and Art.23 require IR capability. Evidence: IRP document, incident severity classification, contact list.",
        "control_ref": "NIS2 Art.21(2)(b)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 13,
    },
    {
        "qid": "nis2-ir-02", "section": "Incident Response & Reporting",
        "question": "Is the organisation able to detect, assess, and submit an early warning to the national CSIRT within 24 hours of a significant incident?",
        "guidance": "Art.23(1) mandates early warning within 24h, detailed report within 72h. Evidence: IRP with notification template, CSIRT contacts.",
        "control_ref": "NIS2 Art.23(1)(a)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 14,
    },
    {
        "qid": "nis2-ir-03", "section": "Incident Response & Reporting",
        "question": "Has the incident response plan been exercised (tabletop or live drill) in the past 12 months?",
        "guidance": "Evidence: exercise report, lessons-learned document, plan updated post-exercise.",
        "control_ref": "NIS2 Art.21(2)(b)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 15,
    },
    # Section 5: Supply Chain & Third Parties
    {
        "qid": "nis2-sc-01", "section": "Supply Chain Security",
        "question": "Are cybersecurity requirements formally embedded in contracts with all critical third-party ICT suppliers and service providers?",
        "guidance": "Art.21(2)(d) requires supply chain security. Evidence: standard contract clauses, supplier questionnaires, security addenda.",
        "control_ref": "NIS2 Art.21(2)(d)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 16,
    },
    {
        "qid": "nis2-sc-02", "section": "Supply Chain Security",
        "question": "Is a third-party risk register maintained with periodic security assessments of critical suppliers?",
        "guidance": "Evidence: vendor register, risk ratings, assessment schedule, evidence of follow-up on identified gaps.",
        "control_ref": "NIS2 Art.21(2)(d)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 17,
    },
    {
        "qid": "nis2-sc-03", "section": "Supply Chain Security",
        "question": "How comprehensively does the organisation assess cybersecurity risks arising from its software supply chain (open-source, COTS, cloud services)?",
        "guidance": "Evidence: SBOM practices, OSS vulnerability scanning, SaaS/IaaS risk assessments.",
        "control_ref": "NIS2 Art.21(2)(d)", "weight": 2, "question_type": "score_1_5", "options": [], "order_idx": 18,
    },
    # Section 6: Training & Awareness
    {
        "qid": "nis2-train-01", "section": "Training & Awareness",
        "question": "Is mandatory annual cybersecurity awareness training provided to all staff, with completion tracked and non-completions followed up?",
        "guidance": "Art.21(2)(g) covers training. Evidence: LMS records, completion rate >90%, phishing simulation results.",
        "control_ref": "NIS2 Art.21(2)(g)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 19,
    },
    {
        "qid": "nis2-train-02", "section": "Training & Awareness",
        "question": "Do technical roles (developers, admins, SOC analysts) receive role-specific security training in addition to general awareness?",
        "guidance": "Evidence: training matrix, secure coding training records, SOC certification tracking.",
        "control_ref": "NIS2 Art.21(2)(g)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 20,
    },
]

# ── DORA (Digital Operational Resilience Act) ─────────────────────────────────
DORA = [
    # Section 1: ICT Governance
    {
        "qid": "dora-gov-01", "section": "ICT Governance & Strategy",
        "question": "Does the management body approve and oversee the ICT risk management framework and take ultimate accountability for ICT risk?",
        "guidance": "Art.5 DORA: management body must define and approve the ICT strategy and regularly review it. Evidence: board decision, CISO reporting line.",
        "control_ref": "DORA Art.5(2)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 1,
    },
    {
        "qid": "dora-gov-02", "section": "ICT Governance & Strategy",
        "question": "Is there a documented, board-approved ICT Risk Management Framework (ICTRMF) that covers strategy, risk tolerance, and control objectives?",
        "guidance": "Art.6 requires a comprehensive ICTRMF. Evidence: framework document, version history, management sign-off, review cycle.",
        "control_ref": "DORA Art.6(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 2,
    },
    {
        "qid": "dora-gov-03", "section": "ICT Governance & Strategy",
        "question": "Does the organisation maintain a complete and current ICT asset inventory including hardware, software, data, and cloud services?",
        "guidance": "Art.8 requires asset identification. Evidence: CMDB, cloud asset inventory, software licence register, data classification map.",
        "control_ref": "DORA Art.8(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 3,
    },
    # Section 2: ICT Risk Management
    {
        "qid": "dora-risk-01", "section": "ICT Risk Management",
        "question": "Are ICT risks formally identified, assessed, and categorised using a consistent risk assessment methodology at least annually?",
        "guidance": "Art.6(2) requires systematic risk identification. Evidence: risk register, methodology document, latest risk assessment report.",
        "control_ref": "DORA Art.6(2)(a)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 4,
    },
    {
        "qid": "dora-risk-02", "section": "ICT Risk Management",
        "question": "Are ICT risk treatment plans implemented with defined owners, timelines, and residual risk acceptance by appropriate authority?",
        "guidance": "Art.6(2)(c) requires risk treatment and monitoring. Evidence: treatment plan, residual risk sign-off, progress tracking.",
        "control_ref": "DORA Art.6(2)(c)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 5,
    },
    {
        "qid": "dora-risk-03", "section": "ICT Risk Management",
        "question": "How mature is the organisation's continuous ICT risk monitoring capability? (1=manual/ad-hoc, 5=automated with real-time dashboards and alerting)",
        "guidance": "Art.10 requires detection and monitoring. Evidence: SIEM, vulnerability scanner, configuration monitoring tools, SOC.",
        "control_ref": "DORA Art.10(1)", "weight": 3, "question_type": "score_1_5", "options": [], "order_idx": 6,
    },
    {
        "qid": "dora-risk-04", "section": "ICT Risk Management",
        "question": "Are all critical ICT systems protected with documented change management procedures including security impact assessment?",
        "guidance": "Art.9 covers ICT system protection. Evidence: change management policy, CAB process, security sign-off in change tickets.",
        "control_ref": "DORA Art.9(1)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 7,
    },
    # Section 3: ICT Incident Management & Reporting
    {
        "qid": "dora-ir-01", "section": "ICT Incident Management",
        "question": "Is there a documented ICT-related incident management process that includes detection, classification, notification, and post-incident review?",
        "guidance": "Art.17 requires ICT incident management. Evidence: IRP covering all phases, escalation matrix, post-incident review template.",
        "control_ref": "DORA Art.17(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 8,
    },
    {
        "qid": "dora-ir-02", "section": "ICT Incident Management",
        "question": "Are ICT incidents classified against DORA criteria (significant vs. non-significant) with defined thresholds for regulatory notification?",
        "guidance": "Art.18 defines classification criteria (number of clients affected, transaction impact, reputation, data loss). Evidence: classification matrix.",
        "control_ref": "DORA Art.18(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 9,
    },
    {
        "qid": "dora-ir-03", "section": "ICT Incident Management",
        "question": "Is the organisation able to submit an initial notification to the competent authority within 4 hours of classifying an incident as major?",
        "guidance": "Art.19 requires initial report within 4 hours of major incident classification. Evidence: notification procedure, authority contacts, SLA tracking.",
        "control_ref": "DORA Art.19(4)(a)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 10,
    },
    {
        "qid": "dora-ir-04", "section": "ICT Incident Management",
        "question": "Are threat intelligence feeds actively consumed and integrated into the organisation's security monitoring and incident response process?",
        "guidance": "Art.13 requires threat intelligence. Evidence: CTI platform, ISAC membership, threat intel integration in SIEM.",
        "control_ref": "DORA Art.13(1)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 11,
    },
    # Section 4: Digital Operational Resilience Testing
    {
        "qid": "dora-test-01", "section": "Resilience Testing",
        "question": "Does the organisation conduct annual ICT resilience tests (vulnerability assessments, penetration tests) covering critical systems?",
        "guidance": "Art.24-25 require testing programme. Evidence: annual pentest schedule, scope, findings tracker, remediation evidence.",
        "control_ref": "DORA Art.24(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 12,
    },
    {
        "qid": "dora-test-02", "section": "Resilience Testing",
        "question": "If the organisation qualifies as significant under DORA, has Threat-Led Penetration Testing (TLPT) been conducted or planned in the past 3 years?",
        "guidance": "Art.26 requires TLPT for significant entities. Evidence: TLPT scope approval, red-team engagement, regulator-notified results.",
        "control_ref": "DORA Art.26(1)", "weight": 2, "question_type": "multi_choice",
        "options": ["Completed TLPT", "Planned (within 12 months)", "Not required (not significant entity)", "Not yet assessed"],
        "order_idx": 13,
    },
    {
        "qid": "dora-test-03", "section": "Resilience Testing",
        "question": "Are penetration test findings tracked to closure, and is there a defined SLA for remediation based on finding severity?",
        "guidance": "Evidence: findings register linked to pentest, remediation SLAs (e.g., critical=14d, high=30d), sign-off process.",
        "control_ref": "DORA Art.24(6)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 14,
    },
    # Section 5: Third-Party ICT Risk
    {
        "qid": "dora-tpr-01", "section": "Third-Party ICT Risk",
        "question": "Is a register of all critical ICT third-party providers (CTPPs) maintained, with formal risk assessments conducted before and during the relationship?",
        "guidance": "Art.28 requires CTPP register. Evidence: CTPP list, risk assessment per provider, annual review schedule.",
        "control_ref": "DORA Art.28(2)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 15,
    },
    {
        "qid": "dora-tpr-02", "section": "Third-Party ICT Risk",
        "question": "Do contracts with critical ICT third parties include DORA-mandated clauses (audit rights, sub-contracting controls, termination, data portability)?",
        "guidance": "Art.30 defines required contractual provisions. Evidence: contract template review, legal sign-off on DORA clauses.",
        "control_ref": "DORA Art.30(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 16,
    },
    {
        "qid": "dora-tpr-03", "section": "Third-Party ICT Risk",
        "question": "Are exit strategies and substitutability plans documented for all critical ICT third-party dependencies?",
        "guidance": "Art.28(8) requires exit plans. Evidence: exit strategy documents, data portability assessment, alternative provider analysis.",
        "control_ref": "DORA Art.28(8)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 17,
    },
    # Section 6: Business Continuity
    {
        "qid": "dora-bcp-01", "section": "Business Continuity",
        "question": "Are Business Continuity Plans (BCPs) and Disaster Recovery Plans (DRPs) documented, tested annually, and covering all critical ICT systems?",
        "guidance": "Art.11 requires BCP/DRP. Evidence: plans covering critical systems, annual test results, RTO/RPO defined and validated.",
        "control_ref": "DORA Art.11(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 18,
    },
    {
        "qid": "dora-bcp-02", "section": "Business Continuity",
        "question": "How well does the organisation's backup strategy satisfy the 4-2-1 or equivalent principle (multiple copies, offline/offsite, tested regularly)?",
        "guidance": "Evidence: backup policy, test restoration logs, off-site storage confirmation, RPO compliance evidence.",
        "control_ref": "DORA Art.12(1)", "weight": 3, "question_type": "score_1_5", "options": [], "order_idx": 19,
    },
]

# ── ISO 27001:2022 ────────────────────────────────────────────────────────────
ISO27001 = [
    # Section 1: ISMS Context & Leadership
    {
        "qid": "iso-ctx-01", "section": "ISMS Context & Leadership",
        "question": "Is the scope of the ISMS formally defined, documented, and approved, including all applicable boundaries and interfaces?",
        "guidance": "Clause 4.3. Evidence: ISMS scope statement, organisational chart showing in-scope entities, site/system list.",
        "control_ref": "ISO 27001 Cl.4.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 1,
    },
    {
        "qid": "iso-ctx-02", "section": "ISMS Context & Leadership",
        "question": "Has top management demonstrated leadership commitment by establishing an information security policy and communicating it to all personnel?",
        "guidance": "Clause 5.1/5.2. Evidence: signed IS policy, all-staff communication records, policy available on intranet.",
        "control_ref": "ISO 27001 Cl.5.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 2,
    },
    {
        "qid": "iso-ctx-03", "section": "ISMS Context & Leadership",
        "question": "Are information security objectives defined, measurable, and communicated, with progress tracked and reported to management?",
        "guidance": "Clause 6.2. Evidence: IS objectives document, KPIs/metrics, management review records showing objective progress.",
        "control_ref": "ISO 27001 Cl.6.2", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 3,
    },
    # Section 2: Risk Assessment & Treatment
    {
        "qid": "iso-risk-01", "section": "Risk Assessment & Treatment",
        "question": "Is a documented risk assessment process in place that identifies information security risks against defined criteria, conducted at planned intervals and on significant change?",
        "guidance": "Clause 6.1.2. Evidence: risk assessment methodology, risk register, evidence of reviews triggered by change.",
        "control_ref": "ISO 27001 Cl.6.1.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 4,
    },
    {
        "qid": "iso-risk-02", "section": "Risk Assessment & Treatment",
        "question": "Is a risk treatment plan maintained with selected controls, risk owners, implementation status, and residual risk?",
        "guidance": "Clause 6.1.3. Evidence: risk treatment plan, Statement of Applicability (SoA), risk owner assignments.",
        "control_ref": "ISO 27001 Cl.6.1.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 5,
    },
    {
        "qid": "iso-risk-03", "section": "Risk Assessment & Treatment",
        "question": "Has a Statement of Applicability (SoA) been produced listing all Annex A controls with inclusion/exclusion justifications?",
        "guidance": "Clause 6.1.3(d). Evidence: SoA document covering all 93 Annex A controls (2022 version), signed off by management.",
        "control_ref": "ISO 27001 Cl.6.1.3(d)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 6,
    },
    # Section 3: Access Control & Identity
    {
        "qid": "iso-iam-01", "section": "Access Control & Identity",
        "question": "Is a formal access control policy implemented with role-based access, least privilege, and periodic access reviews?",
        "guidance": "Annex A 5.15/5.18. Evidence: access policy, IAM system configuration, quarterly access reviews, privilege escalation process.",
        "control_ref": "ISO 27001 A.5.15 / A.5.18", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 7,
    },
    {
        "qid": "iso-iam-02", "section": "Access Control & Identity",
        "question": "Are privileged accounts managed separately with enhanced monitoring, MFA, and time-limited elevation where applicable?",
        "guidance": "Annex A 8.2. Evidence: PAM tool, privileged access policy, session recording, MFA enforcement for admins.",
        "control_ref": "ISO 27001 A.8.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 8,
    },
    {
        "qid": "iso-iam-03", "section": "Access Control & Identity",
        "question": "Are user accounts disabled/removed within one business day of employee departure, and is an off-boarding checklist enforced?",
        "guidance": "Annex A 5.18. Evidence: HR-IT integration process, account disablement SLA, periodic orphan account reviews.",
        "control_ref": "ISO 27001 A.5.18", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 9,
    },
    # Section 4: Asset & Vulnerability Management
    {
        "qid": "iso-asset-01", "section": "Asset & Vulnerability Management",
        "question": "Is an information asset inventory maintained, with assets classified by sensitivity, and ownership assigned for each asset?",
        "guidance": "Annex A 5.9/5.10. Evidence: asset register with owner, classification (e.g., Public/Internal/Confidential/Restricted).",
        "control_ref": "ISO 27001 A.5.9 / A.5.10", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 10,
    },
    {
        "qid": "iso-asset-02", "section": "Asset & Vulnerability Management",
        "question": "Are technical vulnerabilities identified, assessed, and remediated within defined SLAs (e.g., critical ≤7 days, high ≤30 days)?",
        "guidance": "Annex A 8.8. Evidence: vulnerability scanner reports, patch management policy, SLA tracking, exception process.",
        "control_ref": "ISO 27001 A.8.8", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 11,
    },
    {
        "qid": "iso-asset-03", "section": "Asset & Vulnerability Management",
        "question": "Rate the organisation's secure configuration management maturity (1=no baselines, 5=automated CIS Benchmark enforcement with drift detection)",
        "guidance": "Annex A 8.9. Evidence: hardening standards, CIS Benchmark compliance reports, configuration management tooling.",
        "control_ref": "ISO 27001 A.8.9", "weight": 2, "question_type": "score_1_5", "options": [], "order_idx": 12,
    },
    # Section 5: Cryptography
    {
        "qid": "iso-crypto-01", "section": "Cryptography",
        "question": "Is a cryptographic policy in place specifying approved algorithms, key lengths, and key management procedures?",
        "guidance": "Annex A 8.24. Evidence: cryptographic policy, algorithm list (TLS 1.2+, AES-256, RSA-2048+), key rotation schedule.",
        "control_ref": "ISO 27001 A.8.24", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 13,
    },
    # Section 6: Incident Management & Logging
    {
        "qid": "iso-ir-01", "section": "Incident Management",
        "question": "Is an information security incident management procedure documented, tested, and covering detection, reporting, escalation, and post-incident review?",
        "guidance": "Annex A 5.24-5.28. Evidence: IRP, severity classification scheme, RACI, lessons-learned log.",
        "control_ref": "ISO 27001 A.5.24", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 14,
    },
    {
        "qid": "iso-ir-02", "section": "Incident Management",
        "question": "Are security event logs collected from all critical systems, retained for the required period, and actively monitored for anomalies?",
        "guidance": "Annex A 8.15/8.16. Evidence: SIEM coverage map, log retention policy (≥12 months), SOC monitoring procedures.",
        "control_ref": "ISO 27001 A.8.15 / A.8.16", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 15,
    },
    # Section 7: Supplier Relationships
    {
        "qid": "iso-sup-01", "section": "Supplier Relationships",
        "question": "Are information security requirements defined and agreed with all suppliers that access, process, or store the organisation's information?",
        "guidance": "Annex A 5.19-5.22. Evidence: supplier security policy, contractual clauses, supplier assessment questionnaire, SLA.",
        "control_ref": "ISO 27001 A.5.19", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 16,
    },
    # Section 8: Business Continuity & Internal Audit
    {
        "qid": "iso-bcp-01", "section": "Business Continuity",
        "question": "Are information security requirements included in the organisation's BCP/DRP, and has the plan been tested within the past 12 months?",
        "guidance": "Annex A 5.29-5.30. Evidence: BCP/DRP documents, DR test report, IS-specific recovery procedures.",
        "control_ref": "ISO 27001 A.5.29", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 17,
    },
    {
        "qid": "iso-audit-01", "section": "Internal Audit & Review",
        "question": "Are ISMS internal audits conducted at planned intervals by competent, objective auditors, with findings tracked and closed?",
        "guidance": "Clause 9.2. Evidence: audit programme, audit reports, finding tracker, management review records.",
        "control_ref": "ISO 27001 Cl.9.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 18,
    },
    {
        "qid": "iso-audit-02", "section": "Internal Audit & Review",
        "question": "Does management formally review the ISMS at least annually, covering performance, risks, opportunities, and resource needs?",
        "guidance": "Clause 9.3. Evidence: management review meeting minutes with all required agenda items addressed.",
        "control_ref": "ISO 27001 Cl.9.3", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 19,
    },
]

# ── SOC 2 ─────────────────────────────────────────────────────────────────────
SOC2 = [
    # CC1: Control Environment
    {
        "qid": "soc2-cc1-01", "section": "CC1 — Control Environment",
        "question": "Does the organisation demonstrate commitment to integrity and ethical values through a code of conduct that is communicated to all personnel?",
        "guidance": "CC1.1. Evidence: code of conduct, annual acknowledgement records, ethics reporting mechanism.",
        "control_ref": "SOC 2 CC1.1", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 1,
    },
    {
        "qid": "soc2-cc1-02", "section": "CC1 — Control Environment",
        "question": "Is there a defined organisational structure with assigned security responsibilities, reporting lines, and accountability for internal controls?",
        "guidance": "CC1.3. Evidence: org chart, security RACI, job descriptions with security responsibilities.",
        "control_ref": "SOC 2 CC1.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 2,
    },
    # CC2: Communication & Information
    {
        "qid": "soc2-cc2-01", "section": "CC2 — Communication & Information",
        "question": "Are security policies and information communicated to internal and external parties with a need to know, and updated when significant changes occur?",
        "guidance": "CC2.2/CC2.3. Evidence: policy distribution records, vendor communication, customer-facing security page, notification process for changes.",
        "control_ref": "SOC 2 CC2.2 / CC2.3", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 3,
    },
    # CC3: Risk Assessment
    {
        "qid": "soc2-cc3-01", "section": "CC3 — Risk Assessment",
        "question": "Is a risk assessment process in place to identify risks to the achievement of the service's trust service criteria, with results documented and acted upon?",
        "guidance": "CC3.2. Evidence: risk assessment methodology, SOC-2-specific risk register, risk owner assignments.",
        "control_ref": "SOC 2 CC3.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 4,
    },
    {
        "qid": "soc2-cc3-02", "section": "CC3 — Risk Assessment",
        "question": "Does the risk assessment process consider fraud risk and risks from significant changes to the organisation, its systems, or its environment?",
        "guidance": "CC3.3/CC3.4. Evidence: fraud risk assessment, change-triggered risk reviews, emerging threat process.",
        "control_ref": "SOC 2 CC3.3 / CC3.4", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 5,
    },
    # CC6: Logical & Physical Access
    {
        "qid": "soc2-cc6-01", "section": "CC6 — Logical & Physical Access",
        "question": "Are logical access controls implemented using a least-privilege model, with access provisioned based on role and revoked promptly on role change or termination?",
        "guidance": "CC6.1/CC6.2/CC6.3. Evidence: access control policy, IAM reports, joiner/mover/leaver process, periodic access reviews.",
        "control_ref": "SOC 2 CC6.1 – CC6.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 6,
    },
    {
        "qid": "soc2-cc6-02", "section": "CC6 — Logical & Physical Access",
        "question": "Is Multi-Factor Authentication (MFA) enforced for all access to the production environment, administrative interfaces, and remote access?",
        "guidance": "CC6.1. Evidence: MFA configuration screenshots, exception log, coverage percentage (target: 100% for privileged).",
        "control_ref": "SOC 2 CC6.1", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 7,
    },
    {
        "qid": "soc2-cc6-03", "section": "CC6 — Logical & Physical Access",
        "question": "Are encryption controls in place for data at rest and in transit, with key management procedures documented?",
        "guidance": "CC6.1/CC6.7. Evidence: encryption policy, TLS configuration, encryption coverage for data stores, KMS documentation.",
        "control_ref": "SOC 2 CC6.1 / CC6.7", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 8,
    },
    # CC7: System Operations
    {
        "qid": "soc2-cc7-01", "section": "CC7 — System Operations",
        "question": "Is the production environment continuously monitored for security events, with automated alerting for anomalous activity and defined response procedures?",
        "guidance": "CC7.1/CC7.2. Evidence: SIEM coverage, alert thresholds, on-call runbooks, mean-time-to-respond metrics.",
        "control_ref": "SOC 2 CC7.1 / CC7.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 9,
    },
    {
        "qid": "soc2-cc7-02", "section": "CC7 — System Operations",
        "question": "Is there a defined and tested incident response procedure, with incidents classified by severity and reported within defined SLAs?",
        "guidance": "CC7.3/CC7.4/CC7.5. Evidence: IRP, severity matrix, tabletop exercise results, customer notification SLAs.",
        "control_ref": "SOC 2 CC7.3 – CC7.5", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 10,
    },
    # CC8: Change Management
    {
        "qid": "soc2-cc8-01", "section": "CC8 — Change Management",
        "question": "Is a formal change management process in place that includes security review, testing, approval, and post-change validation before production deployment?",
        "guidance": "CC8.1. Evidence: change management policy, CAB approval records, pre-production testing evidence, rollback procedures.",
        "control_ref": "SOC 2 CC8.1", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 11,
    },
    {
        "qid": "soc2-cc8-02", "section": "CC8 — Change Management",
        "question": "Are development, test, and production environments fully separated, with no direct developer access to production systems?",
        "guidance": "CC8.1. Evidence: environment separation documentation, access control for prod, deployment pipeline with approvals.",
        "control_ref": "SOC 2 CC8.1", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 12,
    },
    # CC9: Risk Mitigation
    {
        "qid": "soc2-cc9-01", "section": "CC9 — Risk Mitigation",
        "question": "Are vendor and sub-service provider risks assessed prior to engagement, with security requirements embedded in contracts and annually reviewed?",
        "guidance": "CC9.2. Evidence: vendor assessment process, security questionnaires, contractual security clauses, annual reviews.",
        "control_ref": "SOC 2 CC9.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 13,
    },
    # Availability
    {
        "qid": "soc2-av-01", "section": "A — Availability",
        "question": "Are availability SLAs defined, monitored, and reported, with documented procedures to restore services within committed RTO/RPO?",
        "guidance": "A1.1/A1.2. Evidence: uptime SLAs, monitoring dashboards, DR plan with RTO/RPO, last DR test report.",
        "control_ref": "SOC 2 A1.1 / A1.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 14,
    },
    # Confidentiality
    {
        "qid": "soc2-cf-01", "section": "C — Confidentiality",
        "question": "Is confidential information identified, classified, protected, and securely disposed of at end of life in accordance with a data retention and destruction policy?",
        "guidance": "C1.1/C1.2. Evidence: data classification policy, encryption for confidential data, secure deletion procedures, disposal records.",
        "control_ref": "SOC 2 C1.1 / C1.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 15,
    },
    # Privacy (optional criterion)
    {
        "qid": "soc2-pi-01", "section": "PI — Processing Integrity",
        "question": "Are controls in place to ensure that system processing is complete, valid, accurate, timely, and authorised, with error detection and correction procedures?",
        "guidance": "PI1.1. Evidence: input/output validation controls, reconciliation procedures, error logging and alerting.",
        "control_ref": "SOC 2 PI1.1", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 16,
    },
]

# ── NIST CSF 2.0 ──────────────────────────────────────────────────────────────
NIST_CSF = [
    # GV: Govern
    {
        "qid": "nist-gv-01", "section": "GV — Govern",
        "question": "Is there a documented cybersecurity policy aligned to business objectives, approved by leadership, and reviewed annually?",
        "guidance": "GV.OC-01. Evidence: cybersecurity strategy, policy document, leadership approval, review history.",
        "control_ref": "NIST CSF GV.OC-01", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 1,
    },
    {
        "qid": "nist-gv-02", "section": "GV — Govern",
        "question": "Is cybersecurity integrated into enterprise risk management (ERM) with defined risk tolerance communicated across the organisation?",
        "guidance": "GV.RM-01/02. Evidence: ERM framework including cyber, risk appetite statement, board reporting on cyber risk.",
        "control_ref": "NIST CSF GV.RM-01 / GV.RM-02", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 2,
    },
    {
        "qid": "nist-gv-03", "section": "GV — Govern",
        "question": "Are cybersecurity roles and responsibilities formally defined, communicated, and coordinated across all relevant internal and external stakeholders?",
        "guidance": "GV.RR-01. Evidence: RACI matrix, job descriptions with security responsibilities, third-party security obligations.",
        "control_ref": "NIST CSF GV.RR-01", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 3,
    },
    # ID: Identify
    {
        "qid": "nist-id-01", "section": "ID — Identify",
        "question": "Is a comprehensive inventory of hardware, software, data, and services maintained and kept current through automated discovery tools?",
        "guidance": "ID.AM-01/02. Evidence: CMDB, asset discovery tool, software bill of materials (SBOM), cloud asset inventory.",
        "control_ref": "NIST CSF ID.AM-01 / ID.AM-02", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 4,
    },
    {
        "qid": "nist-id-02", "section": "ID — Identify",
        "question": "Are cybersecurity risks identified and prioritised using a risk assessment methodology that considers likelihood, impact, and organisational context?",
        "guidance": "ID.RA-01/02/05. Evidence: risk assessment reports, threat modelling artifacts, risk register with prioritisation.",
        "control_ref": "NIST CSF ID.RA-01 / ID.RA-05", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 5,
    },
    {
        "qid": "nist-id-03", "section": "ID — Identify",
        "question": "Has the organisation identified its critical assets and defined their cyber resilience requirements including availability, integrity, and confidentiality?",
        "guidance": "ID.AM-05/06. Evidence: criticality classification, BIA results, asset-specific protection requirements.",
        "control_ref": "NIST CSF ID.AM-05 / ID.AM-06", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 6,
    },
    # PR: Protect
    {
        "qid": "nist-pr-01", "section": "PR — Protect",
        "question": "Are identity and access management controls implemented with least privilege, MFA, and periodic access reviews for all user types?",
        "guidance": "PR.AA-01/03/05/06. Evidence: IAM system, MFA coverage report, access review records, privileged access controls.",
        "control_ref": "NIST CSF PR.AA-01 / PR.AA-06", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 7,
    },
    {
        "qid": "nist-pr-02", "section": "PR — Protect",
        "question": "Is data protected through classification, encryption, integrity controls, and secure disposal aligned to data sensitivity?",
        "guidance": "PR.DS-01/02/10. Evidence: data classification policy, encryption standards, DLP controls, disposal procedures.",
        "control_ref": "NIST CSF PR.DS-01 / PR.DS-02", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 8,
    },
    {
        "qid": "nist-pr-03", "section": "PR — Protect",
        "question": "Are security awareness and skills training programmes in place for all staff, with role-specific training for high-risk functions?",
        "guidance": "PR.AT-01/02. Evidence: security training programme, completion records, phishing simulation results, technical training for IT/DevSec roles.",
        "control_ref": "NIST CSF PR.AT-01 / PR.AT-02", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 9,
    },
    {
        "qid": "nist-pr-04", "section": "PR — Protect",
        "question": "Rate the maturity of platform security controls (patching, hardening, endpoint protection, network segmentation) (1=ad-hoc, 5=fully automated and monitored)",
        "guidance": "PR.PS-01/02/03. Evidence: patch management KPIs, CIS Benchmark compliance, EDR coverage, network segmentation diagrams.",
        "control_ref": "NIST CSF PR.PS-01 – PR.PS-03", "weight": 3, "question_type": "score_1_5", "options": [], "order_idx": 10,
    },
    # DE: Detect
    {
        "qid": "nist-de-01", "section": "DE — Detect",
        "question": "Is continuous monitoring of networks, systems, and users in place using a SIEM or equivalent, with defined detection rules for known attack patterns?",
        "guidance": "DE.CM-01/03/06/09. Evidence: SIEM coverage, detection rule library, UEBA, alert tuning documentation.",
        "control_ref": "NIST CSF DE.CM-01 / DE.CM-09", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 11,
    },
    {
        "qid": "nist-de-02", "section": "DE — Detect",
        "question": "Are detected events correlated and analysed in context to distinguish genuine incidents from false positives, with documented investigation procedures?",
        "guidance": "DE.AE-02/04/06. Evidence: alert triage runbooks, correlation rules, analyst investigation logs, false positive rate metrics.",
        "control_ref": "NIST CSF DE.AE-02 / DE.AE-06", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 12,
    },
    # RS: Respond
    {
        "qid": "nist-rs-01", "section": "RS — Respond",
        "question": "Is a documented Incident Response Plan in place with defined playbooks for top threat scenarios, and is it tested at least annually?",
        "guidance": "RS.MA-01/02. Evidence: IRP, scenario-specific playbooks (ransomware, phishing, insider threat), exercise reports.",
        "control_ref": "NIST CSF RS.MA-01 / RS.MA-02", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 13,
    },
    {
        "qid": "nist-rs-02", "section": "RS — Respond",
        "question": "Are incident communication procedures defined, including internal escalation, regulatory notification, and external communications (customers, media) where required?",
        "guidance": "RS.CO-02/03/04. Evidence: communication plan, authority notification templates, PR/legal involvement process.",
        "control_ref": "NIST CSF RS.CO-02 – RS.CO-04", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 14,
    },
    # RC: Recover
    {
        "qid": "nist-rc-01", "section": "RC — Recover",
        "question": "Is a recovery plan documented and tested, with defined restoration priorities based on system criticality and BIA results?",
        "guidance": "RC.RP-01/02. Evidence: DRP/BCP linked to BIA, restoration priority list, last successful recovery test report.",
        "control_ref": "NIST CSF RC.RP-01 / RC.RP-02", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 15,
    },
    {
        "qid": "nist-rc-02", "section": "RC — Recover",
        "question": "Are post-incident lessons learned formally documented, shared with relevant stakeholders, and used to update plans, procedures, and controls?",
        "guidance": "RC.IM-01/02. Evidence: PIR reports, lessons-learned register, evidence of plan/control updates following incidents.",
        "control_ref": "NIST CSF RC.IM-01 / RC.IM-02", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 16,
    },
    {
        "qid": "nist-rc-03", "section": "RC — Recover",
        "question": "Does the organisation maintain and test offsite/offline backups of all critical data with restoration tested against defined RPO and RTO?",
        "guidance": "RC.RP-03. Evidence: backup policy (3-2-1 rule), off-site backup confirmation, restoration test logs, RPO/RTO compliance.",
        "control_ref": "NIST CSF RC.RP-03", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 17,
    },
]

# ── PCI DSS v4.0 ──────────────────────────────────────────────────────────────
PCI_DSS = [
    # Req 1 & 2: Network Security
    {
        "qid": "pci-net-01", "section": "Network Security Controls",
        "question": "Is the Cardholder Data Environment (CDE) segmented from untrusted networks using firewalls or equivalent controls, with all firewall rules documented and reviewed at least every six months?",
        "guidance": "PCI DSS Req 1.1/1.2. Evidence: network diagram showing CDE segmentation, firewall rule set, bi-annual review records.",
        "control_ref": "PCI DSS v4 Req.1.1 / Req.1.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 1,
    },
    {
        "qid": "pci-net-02", "section": "Network Security Controls",
        "question": "Are all system components in the CDE configured according to a hardening baseline (e.g., CIS Benchmarks), with default credentials changed and unnecessary services disabled?",
        "guidance": "PCI DSS Req 2.2. Evidence: hardening standards, configuration compliance scans, baseline review schedule.",
        "control_ref": "PCI DSS v4 Req.2.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 2,
    },
    # Req 3 & 4: Data Protection
    {
        "qid": "pci-data-01", "section": "Cardholder Data Protection",
        "question": "Is primary account number (PAN) data stored only where necessary, rendered unreadable (e.g., tokenised, truncated, or encrypted with AES-256), and purged per the data retention policy?",
        "guidance": "PCI DSS Req 3.3/3.5. Evidence: data flow diagram, storage inventory, encryption configuration, retention policy with purge logs.",
        "control_ref": "PCI DSS v4 Req.3.3 / Req.3.5", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 3,
    },
    {
        "qid": "pci-data-02", "section": "Cardholder Data Protection",
        "question": "Is all transmission of cardholder data over open, public networks encrypted using strong cryptography (TLS 1.2 or higher)?",
        "guidance": "PCI DSS Req 4.2. Evidence: TLS configuration scan, cipher suite policy, certificate management, no deprecated protocols (SSL, TLS 1.0/1.1).",
        "control_ref": "PCI DSS v4 Req.4.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 4,
    },
    {
        "qid": "pci-data-03", "section": "Cardholder Data Protection",
        "question": "Has a Data Discovery scan been performed in the last 12 months to locate all locations where PAN data resides, including unstructured data stores?",
        "guidance": "PCI DSS Req 3.1 (customised approach). Evidence: data discovery tool output, remediation of unauthorised PAN storage.",
        "control_ref": "PCI DSS v4 Req.3.1", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 5,
    },
    # Req 5 & 6: Vulnerability Management
    {
        "qid": "pci-vuln-01", "section": "Vulnerability Management",
        "question": "Is anti-malware software deployed on all applicable systems in the CDE, kept current with definitions, and configured to perform periodic scans?",
        "guidance": "PCI DSS Req 5.2/5.3. Evidence: EDR/AV deployment report, definition update policy, scan schedule, detected/quarantined malware log.",
        "control_ref": "PCI DSS v4 Req.5.2 / Req.5.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 6,
    },
    {
        "qid": "pci-vuln-02", "section": "Vulnerability Management",
        "question": "Are all in-scope systems scanned for vulnerabilities at least quarterly using an Approved Scanning Vendor (ASV), with critical vulnerabilities remediated before re-scan?",
        "guidance": "PCI DSS Req 11.3.2. Evidence: quarterly ASV scan reports showing passing status, vulnerability remediation tracker.",
        "control_ref": "PCI DSS v4 Req.11.3.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 7,
    },
    {
        "qid": "pci-vuln-03", "section": "Vulnerability Management",
        "question": "Has an annual penetration test been conducted covering CDE network and application layers by a qualified internal or external tester?",
        "guidance": "PCI DSS Req 11.4. Evidence: pentest scope, methodology (OWASP/PTES), findings report, remediation evidence.",
        "control_ref": "PCI DSS v4 Req.11.4", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 8,
    },
    # Req 7 & 8: Access Control
    {
        "qid": "pci-iam-01", "section": "Access Control",
        "question": "Is access to CDE system components and cardholder data restricted on a need-to-know basis, with access requests formally approved and documented?",
        "guidance": "PCI DSS Req 7.1/7.2. Evidence: access policy, RBAC configuration, access request tickets, quarterly privilege reviews.",
        "control_ref": "PCI DSS v4 Req.7.1 / Req.7.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 9,
    },
    {
        "qid": "pci-iam-02", "section": "Access Control",
        "question": "Is MFA required for all non-console administrative access to the CDE, and for all remote access to the cardholder data environment?",
        "guidance": "PCI DSS Req 8.4.2/8.4.3. Evidence: MFA configuration for CDE admin accounts, VPN configuration, remote access policy.",
        "control_ref": "PCI DSS v4 Req.8.4.2 / Req.8.4.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 10,
    },
    {
        "qid": "pci-iam-03", "section": "Access Control",
        "question": "Are individual user IDs used for all personnel accessing CDE systems (no shared accounts), with passwords meeting PCI DSS complexity requirements?",
        "guidance": "PCI DSS Req 8.2/8.3. Evidence: IAM policy, no shared account evidence, password policy configuration.",
        "control_ref": "PCI DSS v4 Req.8.2 / Req.8.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 11,
    },
    # Req 10 & 11: Monitoring & Testing
    {
        "qid": "pci-mon-01", "section": "Monitoring & Testing",
        "question": "Are audit logs enabled for all CDE system components, capturing all access to cardholder data, admin actions, and security events, retained for at least 12 months (3 months immediately available)?",
        "guidance": "PCI DSS Req 10.2/10.5. Evidence: log configuration for all in-scope systems, SIEM coverage, retention policy, 3-month availability test.",
        "control_ref": "PCI DSS v4 Req.10.2 / Req.10.5", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 12,
    },
    {
        "qid": "pci-mon-02", "section": "Monitoring & Testing",
        "question": "Is a change detection mechanism (File Integrity Monitoring) deployed on CDE systems to alert on unauthorised modifications to critical files, configurations, and content?",
        "guidance": "PCI DSS Req 11.5. Evidence: FIM tool deployment, alert configuration, critical file baseline, alert response procedure.",
        "control_ref": "PCI DSS v4 Req.11.5", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 13,
    },
    # Req 12: Policy
    {
        "qid": "pci-pol-01", "section": "Security Policy & Awareness",
        "question": "Is a comprehensive information security policy in place, reviewed at least annually and after significant changes, and communicated to all personnel?",
        "guidance": "PCI DSS Req 12.1. Evidence: IS policy with review date, all-staff communication evidence, policy acknowledgement.",
        "control_ref": "PCI DSS v4 Req.12.1", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 14,
    },
    {
        "qid": "pci-pol-02", "section": "Security Policy & Awareness",
        "question": "Is a formal security awareness training programme in place for all personnel, with training covering phishing, social engineering, and PCI DSS requirements annually?",
        "guidance": "PCI DSS Req 12.6. Evidence: training programme content, completion records (>90%), phishing simulation results.",
        "control_ref": "PCI DSS v4 Req.12.6", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 15,
    },
    {
        "qid": "pci-pol-03", "section": "Security Policy & Awareness",
        "question": "Is an incident response plan in place that specifically addresses cardholder data breaches, with roles defined and tested at least annually?",
        "guidance": "PCI DSS Req 12.10. Evidence: PCI-specific IRP, contact list including card brands/acquirer, annual test evidence.",
        "control_ref": "PCI DSS v4 Req.12.10", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 16,
    },
    {
        "qid": "pci-pol-04", "section": "Security Policy & Awareness",
        "question": "Is a vendor/supplier risk management programme in place specifically for service providers that could impact CDE security, including annual attestation requirements?",
        "guidance": "PCI DSS Req 12.8. Evidence: service provider list, due diligence process, annual PCI compliance confirmation, contract security requirements.",
        "control_ref": "PCI DSS v4 Req.12.8", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 17,
    },
]

# ── Master registry ───────────────────────────────────────────────────────────
ALL_QUESTIONNAIRES: dict[str, list[dict]] = {
    "nis2":     NIS2,
    "dora":     DORA,
    "iso27001": ISO27001,
    "soc2":     SOC2,
    "nist_csf": NIST_CSF,
    "pci_dss":  PCI_DSS,
}

FRAMEWORK_META: dict[str, dict] = {
    "nis2":     {"label": "NIS2 Directive",            "color": "#6378ff", "total": len(NIS2)},
    "dora":     {"label": "DORA",                      "color": "#ffd166", "total": len(DORA)},
    "iso27001": {"label": "ISO 27001:2022",             "color": "#00e5c0", "total": len(ISO27001)},
    "soc2":     {"label": "SOC 2",                     "color": "#ff6b6b", "total": len(SOC2)},
    "nist_csf": {"label": "NIST CSF 2.0",              "color": "#38bdf8", "total": len(NIST_CSF)},
    "pci_dss":  {"label": "PCI DSS v4.0",              "color": "#f97316", "total": len(PCI_DSS)},
}
