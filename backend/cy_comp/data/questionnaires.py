"""
cy_comp/data/questionnaires.py
================================
Comprehensive compliance questionnaire templates covering all sections of each
supported framework so that assessors and auditors can identify exactly which
theme or clause is lagging.

ISO 27001:2022  — 45 questions mapping all 93 Annex A controls across the four
                  themes (Organisational 37, People 8, Physical 14, Technological 34)
                  plus ISMS clause requirements.
NIS2            — 28 questions covering all 10 Art.21 security measures.
DORA            — 28 questions covering governance, risk, incident, testing, TPR, BCP.
SOC 2           — 28 questions covering CC1-CC9 + A, C, PI, P criteria.
NIST CSF 2.0    — 26 questions covering all 6 functions (GV, ID, PR, DE, RS, RC).
PCI DSS v4.0    — 30 questions covering all 12 requirements.

Scoring:
  yes_no:     YES→2 (pass), NO→0 (gap)
  score_1_5:  ≥4→2 (pass), 3→1 (partial), ≤2→0 (gap)
  multi_choice / text: score=1, pending manual review
"""

# ── ISO 27001:2022 ────────────────────────────────────────────────────────────
# 4 Annex A themes — each section label includes the theme prefix so dashboards
# and gap reports immediately show which theme is underperforming.
ISO27001 = [

    # ── ISMS Clauses (4–10) ───────────────────────────────────────────────────
    {
        "qid": "iso-isms-01", "section": "ISMS — Context & Leadership",
        "question": "Is the ISMS scope formally defined and documented, covering all organisational units, locations, assets and interfaces within the boundary?",
        "guidance": "Cl.4.3. Evidence: ISMS scope document, system boundary diagrams, management sign-off.",
        "control_ref": "ISO 27001:2022 Cl.4.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 1,
    },
    {
        "qid": "iso-isms-02", "section": "ISMS — Context & Leadership",
        "question": "Has top management signed and communicated an information security policy, and are IS roles and responsibilities formally assigned?",
        "guidance": "Cl.5.1 / 5.2 / 5.3. Evidence: signed IS policy, CISO appointment, RACI for IS.",
        "control_ref": "ISO 27001:2022 Cl.5.1–5.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 2,
    },
    {
        "qid": "iso-isms-03", "section": "ISMS — Context & Leadership",
        "question": "Are measurable IS objectives defined, tracked against KPIs, and reported to management at planned intervals?",
        "guidance": "Cl.6.2. Evidence: IS objectives register, quarterly KPI reports to management or board.",
        "control_ref": "ISO 27001:2022 Cl.6.2", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 3,
    },
    {
        "qid": "iso-isms-04", "section": "ISMS — Risk Assessment & Treatment",
        "question": "Is a documented risk assessment process in place with defined criteria, conducted at planned intervals and triggered on significant change?",
        "guidance": "Cl.6.1.2. Evidence: methodology, risk register, evidence of change-triggered reassessment.",
        "control_ref": "ISO 27001:2022 Cl.6.1.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 4,
    },
    {
        "qid": "iso-isms-05", "section": "ISMS — Risk Assessment & Treatment",
        "question": "Has a Statement of Applicability (SoA) been produced covering all 93 Annex A controls with justified inclusions and exclusions, signed off by management?",
        "guidance": "Cl.6.1.3(d). Evidence: SoA document with all 93 controls listed, inclusion rationale, management approval.",
        "control_ref": "ISO 27001:2022 Cl.6.1.3(d)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 5,
    },
    {
        "qid": "iso-isms-06", "section": "ISMS — Support & Operation",
        "question": "Are competence requirements defined for IS roles, with training records maintained and gaps addressed through planned development?",
        "guidance": "Cl.7.2. Evidence: competence matrix, training plan, completion records, external certification tracking.",
        "control_ref": "ISO 27001:2022 Cl.7.2", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 6,
    },
    {
        "qid": "iso-isms-07", "section": "ISMS — Performance & Improvement",
        "question": "Are ISMS internal audits conducted at planned intervals by competent objective auditors, with a corrective action process for findings?",
        "guidance": "Cl.9.2. Evidence: audit programme, latest audit report, corrective action tracker.",
        "control_ref": "ISO 27001:2022 Cl.9.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 7,
    },
    {
        "qid": "iso-isms-08", "section": "ISMS — Performance & Improvement",
        "question": "Does management formally review the ISMS at least annually, covering all required inputs (performance, risks, audit results, objectives)?",
        "guidance": "Cl.9.3. Evidence: management review meeting minutes with all Cl.9.3 agenda items present.",
        "control_ref": "ISO 27001:2022 Cl.9.3", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 8,
    },

    # ── Annex A — Organisational Controls (A.5.1 – A.5.37) ───────────────────
    {
        "qid": "iso-org-01", "section": "Annex A — Organisational Controls",
        "question": "Are topic-specific information security policies in place (e.g. access control, mobile devices, remote work, encryption, change management) and reviewed on a defined schedule?",
        "guidance": "A.5.1. Evidence: policy library with review dates; policies covering at least the mandatory topics.",
        "control_ref": "ISO 27001:2022 A.5.1", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 9,
    },
    {
        "qid": "iso-org-02", "section": "Annex A — Organisational Controls",
        "question": "Are segregation of duties applied to conflicting IS functions, and are management responsibilities for IS enforcement clearly documented?",
        "guidance": "A.5.3 / A.5.4. Evidence: segregation matrix, evidence of separated roles in IAM system.",
        "control_ref": "ISO 27001:2022 A.5.3 / A.5.4", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 10,
    },
    {
        "qid": "iso-org-03", "section": "Annex A — Organisational Controls",
        "question": "Are contacts with regulatory authorities and relevant special interest groups (ISACs, CERTs) maintained and kept current?",
        "guidance": "A.5.5 / A.5.6. Evidence: contacts list, ISAC/CERT membership, records of interactions.",
        "control_ref": "ISO 27001:2022 A.5.5 / A.5.6", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 11,
    },
    {
        "qid": "iso-org-04", "section": "Annex A — Organisational Controls",
        "question": "Is a threat intelligence programme in place that collects, analyses, and distributes actionable intelligence on relevant threats to the organisation?",
        "guidance": "A.5.7. Evidence: CTI feed subscriptions, threat intel reports, integration into SIEM/SOC processes.",
        "control_ref": "ISO 27001:2022 A.5.7", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 12,
    },
    {
        "qid": "iso-org-05", "section": "Annex A — Organisational Controls",
        "question": "Is IS integrated into project management so that security requirements are addressed from initiation, and documented operating procedures are maintained for IT operations?",
        "guidance": "A.5.8 / A.5.37. Evidence: project security gate checklist, IT ops runbooks.",
        "control_ref": "ISO 27001:2022 A.5.8 / A.5.37", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 13,
    },
    {
        "qid": "iso-org-06", "section": "Annex A — Organisational Controls",
        "question": "Is an information and associated asset inventory maintained with classifications (e.g., Public/Internal/Confidential/Restricted) and assigned owners for each asset?",
        "guidance": "A.5.9 / A.5.10 / A.5.12. Evidence: asset register with owner, classification tag, acceptable use policy.",
        "control_ref": "ISO 27001:2022 A.5.9 / A.5.10 / A.5.12", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 14,
    },
    {
        "qid": "iso-org-07", "section": "Annex A — Organisational Controls",
        "question": "Are labelling standards applied to all classified information assets, and is a formal information transfer policy in place governing sharing via all channels (email, physical, cloud)?",
        "guidance": "A.5.13 / A.5.14. Evidence: labelling standard, DLP tool configuration, secure transfer agreements.",
        "control_ref": "ISO 27001:2022 A.5.13 / A.5.14", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 15,
    },
    {
        "qid": "iso-org-08", "section": "Annex A — Organisational Controls",
        "question": "Is a formal access control policy implemented with role-based access, least privilege enforcement, and periodic access reviews (at least annually)?",
        "guidance": "A.5.15 / A.5.18. Evidence: access policy, IAM system configuration, access review records.",
        "control_ref": "ISO 27001:2022 A.5.15 / A.5.18", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 16,
    },
    {
        "qid": "iso-org-09", "section": "Annex A — Organisational Controls",
        "question": "Are identity management processes in place covering provisioning, modification, and deprovisioning, and is authentication information (passwords, tokens) managed securely?",
        "guidance": "A.5.16 / A.5.17. Evidence: IAM lifecycle process, password policy, MFA rollout, credential reset procedures.",
        "control_ref": "ISO 27001:2022 A.5.16 / A.5.17", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 17,
    },
    {
        "qid": "iso-org-10", "section": "Annex A — Organisational Controls",
        "question": "Are information security requirements formally defined and agreed with all suppliers, covering ICT supply chain risk, cloud services, and monitoring of service delivery?",
        "guidance": "A.5.19–A.5.23. Evidence: supplier security policy, contract clauses, supplier assessment questionnaire, ICT supply chain risk register, cloud security addenda.",
        "control_ref": "ISO 27001:2022 A.5.19–A.5.23", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 18,
    },
    {
        "qid": "iso-org-11", "section": "Annex A — Organisational Controls",
        "question": "Is an IS incident management procedure in place covering planning, detection, assessment, response, evidence collection, and post-incident review?",
        "guidance": "A.5.24–A.5.28. Evidence: IRP with all phases, severity matrix, lessons-learned register, evidence handling procedures.",
        "control_ref": "ISO 27001:2022 A.5.24–A.5.28", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 19,
    },
    {
        "qid": "iso-org-12", "section": "Annex A — Organisational Controls",
        "question": "Are IS continuity requirements defined in the BCP/DRP, and has ICT readiness for business continuity been tested within the past 12 months?",
        "guidance": "A.5.29 / A.5.30. Evidence: BCP/DRP covering IS, ICT recovery procedures, test report dated within 12 months.",
        "control_ref": "ISO 27001:2022 A.5.29 / A.5.30", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 20,
    },
    {
        "qid": "iso-org-13", "section": "Annex A — Organisational Controls",
        "question": "Are legal, statutory, and regulatory requirements (data protection, IP rights, records retention) identified per system, and is compliance reviewed regularly?",
        "guidance": "A.5.31–A.5.33. Evidence: legal register, DPIA for personal data, records retention schedule, IP rights inventory.",
        "control_ref": "ISO 27001:2022 A.5.31–A.5.33", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 21,
    },
    {
        "qid": "iso-org-14", "section": "Annex A — Organisational Controls",
        "question": "Are privacy and PII protection requirements integrated into the ISMS, with IS independently reviewed against policies and compliance obligations?",
        "guidance": "A.5.34 / A.5.35 / A.5.36. Evidence: privacy policy, PII processing register, independent IS review (internal audit or external assessment).",
        "control_ref": "ISO 27001:2022 A.5.34–A.5.36", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 22,
    },

    # ── Annex A — People Controls (A.6.1 – A.6.8) ────────────────────────────
    {
        "qid": "iso-ppl-01", "section": "Annex A — People Controls",
        "question": "Are background screening checks (identity, criminal, employment history) conducted for all new employees and contractors before access is granted, in accordance with local law?",
        "guidance": "A.6.1. Evidence: HR screening policy, screening records (with consent), third-party vetting service.",
        "control_ref": "ISO 27001:2022 A.6.1", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 23,
    },
    {
        "qid": "iso-ppl-02", "section": "Annex A — People Controls",
        "question": "Do employment contracts and terms reference IS responsibilities, confidentiality obligations, and acceptable use of information assets?",
        "guidance": "A.6.2. Evidence: employment contract template, NDA/confidentiality agreement, acceptable use acknowledgement.",
        "control_ref": "ISO 27001:2022 A.6.2", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 24,
    },
    {
        "qid": "iso-ppl-03", "section": "Annex A — People Controls",
        "question": "Is mandatory annual IS awareness training provided to all personnel, with role-specific training for high-risk functions, and completion tracked?",
        "guidance": "A.6.3. Evidence: training programme, LMS completion records (>90% target), phishing simulation results.",
        "control_ref": "ISO 27001:2022 A.6.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 25,
    },
    {
        "qid": "iso-ppl-04", "section": "Annex A — People Controls",
        "question": "Is a disciplinary process defined and applied consistently for IS policy violations, and are IS responsibilities maintained after termination (e.g., NDA, return of assets)?",
        "guidance": "A.6.4 / A.6.5 / A.6.6. Evidence: disciplinary policy referencing IS, offboarding checklist with asset return, post-employment NDA.",
        "control_ref": "ISO 27001:2022 A.6.4–A.6.6", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 26,
    },
    {
        "qid": "iso-ppl-05", "section": "Annex A — People Controls",
        "question": "Are remote working security measures in place (endpoint protection, VPN, secure home network guidance) and is there a process for personnel to report IS events promptly?",
        "guidance": "A.6.7 / A.6.8. Evidence: remote working policy, VPN enforcement, IS event reporting procedure, known reporting channels.",
        "control_ref": "ISO 27001:2022 A.6.7 / A.6.8", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 27,
    },

    # ── Annex A — Physical Controls (A.7.1 – A.7.14) ─────────────────────────
    {
        "qid": "iso-phy-01", "section": "Annex A — Physical Controls",
        "question": "Are physical security perimeters defined and enforced with appropriate entry controls (badge readers, CCTV, security staff) for all areas hosting sensitive systems or information?",
        "guidance": "A.7.1 / A.7.2 / A.7.4. Evidence: site access policy, visitor log, CCTV coverage map, entry control system records.",
        "control_ref": "ISO 27001:2022 A.7.1 / A.7.2 / A.7.4", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 28,
    },
    {
        "qid": "iso-phy-02", "section": "Annex A — Physical Controls",
        "question": "Are offices, rooms, and facilities secured appropriately, and are measures in place against physical and environmental threats (fire, flood, power failure)?",
        "guidance": "A.7.3 / A.7.5. Evidence: facility risk assessment, fire suppression, UPS, flood barriers, environmental monitoring.",
        "control_ref": "ISO 27001:2022 A.7.3 / A.7.5", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 29,
    },
    {
        "qid": "iso-phy-03", "section": "Annex A — Physical Controls",
        "question": "Are clear desk and clear screen policies enforced, and are procedures defined for working in secure areas (clean-desk audits, restricted access)?",
        "guidance": "A.7.6 / A.7.7. Evidence: clean desk policy, clean-desk audit results, secure area access logs.",
        "control_ref": "ISO 27001:2022 A.7.6 / A.7.7", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 30,
    },
    {
        "qid": "iso-phy-04", "section": "Annex A — Physical Controls",
        "question": "Are equipment siting, cabling security, maintenance, and supporting utilities managed to protect availability and integrity of information processing systems?",
        "guidance": "A.7.8 / A.7.11 / A.7.12 / A.7.13. Evidence: data centre siting standards, labelled structured cabling, maintenance schedule, UPS/generator records.",
        "control_ref": "ISO 27001:2022 A.7.8 / A.7.11–A.7.13", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 31,
    },
    {
        "qid": "iso-phy-05", "section": "Annex A — Physical Controls",
        "question": "Are assets used off-premises (laptops, mobile devices, removable media) protected, tracked, and authorised, and is storage media securely disposed of at end of life?",
        "guidance": "A.7.9 / A.7.10 / A.7.14. Evidence: mobile device policy, off-site asset log, removable media register, NIST 800-88 or equivalent disposal records.",
        "control_ref": "ISO 27001:2022 A.7.9 / A.7.10 / A.7.14", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 32,
    },

    # ── Annex A — Technological Controls (A.8.1 – A.8.34) ────────────────────
    {
        "qid": "iso-tech-01", "section": "Annex A — Technological Controls",
        "question": "Are all user endpoint devices (laptops, mobile, BYOD) managed with endpoint protection, MDM enrolment, disk encryption, and remote wipe capability?",
        "guidance": "A.8.1. Evidence: MDM coverage report, disk encryption policy, EDR deployment, BYOD policy.",
        "control_ref": "ISO 27001:2022 A.8.1", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 33,
    },
    {
        "qid": "iso-tech-02", "section": "Annex A — Technological Controls",
        "question": "Are privileged access rights managed through a PAM solution with enhanced monitoring, MFA, time-limited elevation, and session recording where applicable?",
        "guidance": "A.8.2. Evidence: PAM tool, privileged account register, session recording, MFA enforcement for all admin accounts.",
        "control_ref": "ISO 27001:2022 A.8.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 34,
    },
    {
        "qid": "iso-tech-03", "section": "Annex A — Technological Controls",
        "question": "Is access to source code restricted to authorised developers, and are secure authentication mechanisms (MFA, SSO with strong IdP) implemented across all systems?",
        "guidance": "A.8.3 / A.8.4 / A.8.5. Evidence: source control RBAC, branch protection rules, MFA enforcement reports.",
        "control_ref": "ISO 27001:2022 A.8.3–A.8.5", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 35,
    },
    {
        "qid": "iso-tech-04", "section": "Annex A — Technological Controls",
        "question": "Are capacity and performance requirements monitored, malware protection deployed on all applicable systems with current definitions, and patch management SLAs enforced?",
        "guidance": "A.8.6 / A.8.7 / A.8.8 / A.8.19. Evidence: capacity dashboards, AV/EDR deployment report, vulnerability scanner reports with SLA tracking, patch compliance metrics.",
        "control_ref": "ISO 27001:2022 A.8.6–A.8.8 / A.8.19", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 36,
    },
    {
        "qid": "iso-tech-05", "section": "Annex A — Technological Controls",
        "question": "Rate the organisation's secure configuration management maturity (1=no baselines, 5=automated CIS Benchmark enforcement with continuous drift detection and remediation).",
        "guidance": "A.8.9. Evidence: hardening standards, CIS Benchmark compliance scan results, IaC templates, drift alerting.",
        "control_ref": "ISO 27001:2022 A.8.9", "weight": 3, "question_type": "score_1_5", "options": [], "order_idx": 37,
    },
    {
        "qid": "iso-tech-06", "section": "Annex A — Technological Controls",
        "question": "Are data masking, DLP controls, and information deletion procedures in place to prevent leakage and ensure secure data removal when no longer required?",
        "guidance": "A.8.10 / A.8.11 / A.8.12. Evidence: DLP policy and tool, data masking in non-prod environments, deletion/destruction certificates.",
        "control_ref": "ISO 27001:2022 A.8.10–A.8.12", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 38,
    },
    {
        "qid": "iso-tech-07", "section": "Annex A — Technological Controls",
        "question": "Are backups of critical information taken regularly, tested for restorability, and stored off-site or offline with redundant processing facility capability?",
        "guidance": "A.8.13 / A.8.14. Evidence: backup policy (3-2-1 principle), restoration test logs, RPO/RTO compliance evidence, off-site storage confirmation.",
        "control_ref": "ISO 27001:2022 A.8.13 / A.8.14", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 39,
    },
    {
        "qid": "iso-tech-08", "section": "Annex A — Technological Controls",
        "question": "Are security event logs collected from all critical systems, protected from tampering, retained for ≥12 months, and actively monitored with clock synchronisation enforced?",
        "guidance": "A.8.15 / A.8.16 / A.8.17. Evidence: SIEM coverage map, log retention policy, NTP configuration, anomaly detection rules.",
        "control_ref": "ISO 27001:2022 A.8.15–A.8.17", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 40,
    },
    {
        "qid": "iso-tech-09", "section": "Annex A — Technological Controls",
        "question": "Are privileged utility programs restricted to authorised users, and is installation of software on operational systems controlled via an approved software list?",
        "guidance": "A.8.18 / A.8.19. Evidence: utility program access policy, software whitelist, application control tool (e.g. AppLocker, Jamf).",
        "control_ref": "ISO 27001:2022 A.8.18 / A.8.19", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 41,
    },
    {
        "qid": "iso-tech-10", "section": "Annex A — Technological Controls",
        "question": "Are network security controls in place (firewall policy, network service security, network segregation, web filtering) to protect information in transit?",
        "guidance": "A.8.20–A.8.23. Evidence: firewall policy review, network diagrams showing segmentation, DNS/web proxy filtering configuration.",
        "control_ref": "ISO 27001:2022 A.8.20–A.8.23", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 42,
    },
    {
        "qid": "iso-tech-11", "section": "Annex A — Technological Controls",
        "question": "Is a cryptographic policy in place specifying approved algorithms (AES-256, TLS 1.2+, RSA-2048+), key management procedures, and key rotation schedules?",
        "guidance": "A.8.24. Evidence: cryptographic policy, key management procedure, TLS scan results, key rotation log.",
        "control_ref": "ISO 27001:2022 A.8.24", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 43,
    },
    {
        "qid": "iso-tech-12", "section": "Annex A — Technological Controls",
        "question": "Is a secure development lifecycle (SDL) in place covering security requirements, architecture review, secure coding standards, and security testing before release?",
        "guidance": "A.8.25–A.8.29 / A.8.32. Evidence: SDL policy, threat modelling artifacts, SAST/DAST results, security test sign-off in release gates.",
        "control_ref": "ISO 27001:2022 A.8.25–A.8.29 / A.8.32", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 44,
    },
    {
        "qid": "iso-tech-13", "section": "Annex A — Technological Controls",
        "question": "Are development, test, and production environments separated, is outsourced development subject to security oversight, and is test data protected (masked/anonymised)?",
        "guidance": "A.8.30 / A.8.31 / A.8.33 / A.8.34. Evidence: environment separation policy, outsourced dev security clauses, test data masking evidence.",
        "control_ref": "ISO 27001:2022 A.8.30 / A.8.31 / A.8.33 / A.8.34", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 45,
    },
]

# ── NIS2 Directive (Network and Information Security Directive 2) ─────────────
# Covers all 10 Art.21(2) security measures + Art.20 governance + Art.23 reporting.
NIS2 = [
    # Art.20 — Governance & Management Accountability
    {
        "qid": "nis2-gov-01", "section": "Art.20 — Governance & Accountability",
        "question": "Has the organisation's management body formally approved and endorsed the NIS2 cybersecurity risk management policy and taken direct accountability?",
        "guidance": "Art.20(1). Evidence: board-approved policy, CISO appointment letter, board minutes referencing NIS2 accountability.",
        "control_ref": "NIS2 Art.20(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 1,
    },
    {
        "qid": "nis2-gov-02", "section": "Art.20 — Governance & Accountability",
        "question": "Are management members required to complete NIS2 cybersecurity training, and is completion tracked and evidenced?",
        "guidance": "Art.20(2). Evidence: training records, LMS completion logs, certificates.",
        "control_ref": "NIS2 Art.20(2)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 2,
    },
    {
        "qid": "nis2-gov-03", "section": "Art.20 — Governance & Accountability",
        "question": "How mature is the cybersecurity governance structure (CISO role, committee, board reporting, defined KPIs)? (1=ad-hoc, 5=fully defined with board-level metrics)",
        "guidance": "Art.20. Evidence: governance charter, CISO reporting line, quarterly board cyber report.",
        "control_ref": "NIS2 Art.20", "weight": 3, "question_type": "score_1_5", "options": [], "order_idx": 3,
    },
    # Art.21(2)(a) — Policies on risk analysis and IS
    {
        "qid": "nis2-risk-01", "section": "Art.21(2)(a) — Risk Analysis & IS Policies",
        "question": "Does the organisation conduct a formal annual cybersecurity risk assessment covering all in-scope systems with documented risk treatment plans and owners?",
        "guidance": "Art.21(1). Evidence: risk register, assessment methodology, treatment plans with due dates.",
        "control_ref": "NIS2 Art.21(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 4,
    },
    {
        "qid": "nis2-risk-02", "section": "Art.21(2)(a) — Risk Analysis & IS Policies",
        "question": "Has the organisation defined and documented a cyber risk appetite statement, reviewed at least annually and approved by management?",
        "guidance": "Art.21(1). Evidence: board-approved risk appetite statement, tolerance thresholds per risk category.",
        "control_ref": "NIS2 Art.21(1)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 5,
    },
    # Art.21(2)(b) — Incident handling
    {
        "qid": "nis2-ir-01", "section": "Art.21(2)(b) — Incident Handling",
        "question": "Is there a documented IRP specific to NIS2-significant incidents, with defined detection, classification, escalation, and response roles?",
        "guidance": "Art.21(2)(b) / Art.23. Evidence: IRP document, severity classification matrix, escalation contacts.",
        "control_ref": "NIS2 Art.21(2)(b)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 6,
    },
    {
        "qid": "nis2-ir-02", "section": "Art.21(2)(b) — Incident Handling",
        "question": "Has the incident response plan been exercised (tabletop or live drill) in the past 12 months, with lessons learned documented?",
        "guidance": "Art.21(2)(b). Evidence: exercise scenario, participant list, lessons-learned log, plan updated post-exercise.",
        "control_ref": "NIS2 Art.21(2)(b)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 7,
    },
    # Art.21(2)(c) — Business continuity, backup, disaster recovery, crisis management
    {
        "qid": "nis2-bcp-01", "section": "Art.21(2)(c) — Business Continuity & Backup",
        "question": "Are BCP and DRP documented, covering all essential services, with RTO/RPO defined and validated through testing in the past 12 months?",
        "guidance": "Art.21(2)(c). Evidence: BCP/DRP, last test report, RTO/RPO definitions, gap remediation actions.",
        "control_ref": "NIS2 Art.21(2)(c)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 8,
    },
    {
        "qid": "nis2-bcp-02", "section": "Art.21(2)(c) — Business Continuity & Backup",
        "question": "Are backup procedures tested regularly with off-site or offline copies, and can critical systems be restored within the RTO?",
        "guidance": "Art.21(2)(c). Evidence: backup test reports, off-site storage confirmation, restoration drill results.",
        "control_ref": "NIS2 Art.21(2)(c)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 9,
    },
    # Art.21(2)(d) — Supply chain security
    {
        "qid": "nis2-sc-01", "section": "Art.21(2)(d) — Supply Chain Security",
        "question": "Are cybersecurity requirements formally embedded in contracts with all critical ICT suppliers and service providers?",
        "guidance": "Art.21(2)(d). Evidence: standard contract security clauses, supplier security addenda.",
        "control_ref": "NIS2 Art.21(2)(d)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 10,
    },
    {
        "qid": "nis2-sc-02", "section": "Art.21(2)(d) — Supply Chain Security",
        "question": "Is a third-party risk register maintained with periodic security assessments and follow-up on identified gaps for critical suppliers?",
        "guidance": "Art.21(2)(d). Evidence: vendor register, risk ratings, assessment schedule, remediation tracking.",
        "control_ref": "NIS2 Art.21(2)(d)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 11,
    },
    {
        "qid": "nis2-sc-03", "section": "Art.21(2)(d) — Supply Chain Security",
        "question": "How comprehensively does the organisation assess software supply chain risks (SBOM, open-source scanning, SaaS/IaaS risk reviews)?",
        "guidance": "Art.21(2)(d). Evidence: SBOM practices, OSS vulnerability scanning, SaaS risk assessments.",
        "control_ref": "NIS2 Art.21(2)(d)", "weight": 2, "question_type": "score_1_5", "options": [], "order_idx": 12,
    },
    # Art.21(2)(e) — Security in network/system acquisition, development, maintenance
    {
        "qid": "nis2-vuln-01", "section": "Art.21(2)(e) — Vulnerability Handling",
        "question": "Is a vulnerability management programme in place with defined SLAs for patching critical vulnerabilities (e.g., ≤7 days for critical, ≤30 days for high)?",
        "guidance": "Art.21(2)(e). Evidence: scanner reports, patch SLA policy, exception process, patch compliance metrics.",
        "control_ref": "NIS2 Art.21(2)(e)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 13,
    },
    {
        "qid": "nis2-vuln-02", "section": "Art.21(2)(e) — Vulnerability Handling",
        "question": "Are security requirements integrated into the acquisition and development of network and information systems (security-by-design)?",
        "guidance": "Art.21(2)(e). Evidence: SDL process, procurement security requirements, security review gates in change management.",
        "control_ref": "NIS2 Art.21(2)(e)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 14,
    },
    # Art.21(2)(f) — Policies to assess effectiveness of cybersecurity measures
    {
        "qid": "nis2-audit-01", "section": "Art.21(2)(f) — Effectiveness Assessment",
        "question": "Are cybersecurity effectiveness metrics collected and reviewed, with independent testing (pen tests, audits) conducted at least annually?",
        "guidance": "Art.21(2)(f). Evidence: security KPIs, annual pentest report, audit programme, management review of results.",
        "control_ref": "NIS2 Art.21(2)(f)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 15,
    },
    # Art.21(2)(g) — Training & awareness
    {
        "qid": "nis2-train-01", "section": "Art.21(2)(g) — Training & Awareness",
        "question": "Is mandatory annual cybersecurity awareness training provided to all staff, with completion tracked and non-completions followed up?",
        "guidance": "Art.21(2)(g). Evidence: LMS completion rate (>90%), phishing simulation results, training content review.",
        "control_ref": "NIS2 Art.21(2)(g)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 16,
    },
    {
        "qid": "nis2-train-02", "section": "Art.21(2)(g) — Training & Awareness",
        "question": "Do technical roles (developers, admins, SOC analysts) receive role-specific security training in addition to general awareness?",
        "guidance": "Art.21(2)(g). Evidence: training matrix showing role-specific content, secure coding training records, SOC certification.",
        "control_ref": "NIS2 Art.21(2)(g)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 17,
    },
    # Art.21(2)(h) — Cryptography and encryption
    {
        "qid": "nis2-crypto-01", "section": "Art.21(2)(h) — Cryptography & Encryption",
        "question": "Is data classified and encrypted in transit (TLS 1.2+) and at rest (AES-256) with a documented key management procedure?",
        "guidance": "Art.21(2)(h). Evidence: cryptographic policy, TLS scan, encryption coverage assessment, key rotation schedule.",
        "control_ref": "NIS2 Art.21(2)(h)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 18,
    },
    # Art.21(2)(i) — Access control, asset management, HR security
    {
        "qid": "nis2-iam-01", "section": "Art.21(2)(i) — Access Control & Asset Management",
        "question": "Is a formal access control policy with least-privilege and RBAC implemented, with accounts disabled within one business day of departure?",
        "guidance": "Art.21(2)(i). Evidence: access policy, IAM reports, offboarding SLA compliance.",
        "control_ref": "NIS2 Art.21(2)(i)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 19,
    },
    {
        "qid": "nis2-iam-02", "section": "Art.21(2)(i) — Access Control & Asset Management",
        "question": "Is an up-to-date inventory of all in-scope assets (hardware, software, data) maintained with classification and ownership?",
        "guidance": "Art.21(2)(i). Evidence: CMDB, asset register with owner and classification, automated discovery tool.",
        "control_ref": "NIS2 Art.21(2)(i)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 20,
    },
    # Art.21(2)(j) — MFA / continuous authentication / secured communications
    {
        "qid": "nis2-mfa-01", "section": "Art.21(2)(j) — MFA & Secure Communications",
        "question": "Are all privileged accounts and remote access connections protected with Multi-Factor Authentication (MFA)?",
        "guidance": "Art.21(2)(j). Evidence: IAM MFA configuration, VPN access policy, MFA coverage report showing 100% for privileged.",
        "control_ref": "NIS2 Art.21(2)(j)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 21,
    },
    {
        "qid": "nis2-mfa-02", "section": "Art.21(2)(j) — MFA & Secure Communications",
        "question": "How effective is the organisation's network segmentation and zero-trust access control implementation? (1=flat network, 5=micro-segmented zero-trust)",
        "guidance": "Art.21(2)(j) / (i). Evidence: network diagrams, firewall rule review, VLAN configuration, zero-trust architecture docs.",
        "control_ref": "NIS2 Art.21(2)(j) / (i)", "weight": 3, "question_type": "score_1_5", "options": [], "order_idx": 22,
    },
    # Art.23 — Incident Reporting
    {
        "qid": "nis2-report-01", "section": "Art.23 — Incident Reporting",
        "question": "Is the organisation able to detect and submit an early warning to the national CSIRT within 24 hours of a significant incident?",
        "guidance": "Art.23(1)(a). Evidence: notification procedure with 24h SLA, CSIRT contact list, notification template.",
        "control_ref": "NIS2 Art.23(1)(a)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 23,
    },
    {
        "qid": "nis2-report-02", "section": "Art.23 — Incident Reporting",
        "question": "Is a detailed incident notification submitted to the CSIRT within 72 hours, and a final report submitted within one month?",
        "guidance": "Art.23(1)(b)(c). Evidence: notification templates, incident report log, regulatory correspondence.",
        "control_ref": "NIS2 Art.23(1)(b–c)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 24,
    },
    # Art.21 — Monitoring & Detection (overlapping measures)
    {
        "qid": "nis2-mon-01", "section": "Art.21 — Monitoring & Detection",
        "question": "Is continuous security monitoring (SIEM, IDS/IPS) in place for all in-scope networks and systems, with detection rules for relevant attack patterns?",
        "guidance": "Art.21(2)(b). Evidence: SIEM coverage map, detection rules, SOC monitoring SLAs.",
        "control_ref": "NIS2 Art.21(2)(b)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 25,
    },
    {
        "qid": "nis2-mon-02", "section": "Art.21 — Monitoring & Detection",
        "question": "Are security logs retained for an adequate period (≥12 months) and protected against unauthorised modification?",
        "guidance": "Art.21(2)(e). Evidence: log retention policy, SIEM log integrity controls, retention compliance check.",
        "control_ref": "NIS2 Art.21(2)(e)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 26,
    },
    {
        "qid": "nis2-coord-01", "section": "Art.21 — Coordinated Vulnerability Disclosure",
        "question": "Does the organisation have a coordinated vulnerability disclosure (CVD) policy enabling external researchers to report security vulnerabilities?",
        "guidance": "Art.21(2)(e) + ENISA guidance. Evidence: published CVD policy/security.txt, disclosure process, acknowledgement records.",
        "control_ref": "NIS2 Art.21(2)(e)", "weight": 1, "question_type": "yes_no", "options": [], "order_idx": 27,
    },
    {
        "qid": "nis2-gov-04", "section": "Art.20 — Governance & Accountability",
        "question": "Does the organisation maintain an up-to-date register of all in-scope essential/important services and the supporting ICT assets?",
        "guidance": "Art.21(2). Evidence: service register, CMDB, scope boundary documentation.",
        "control_ref": "NIS2 Art.21(2)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 28,
    },
]

# ── DORA (Digital Operational Resilience Act) ─────────────────────────────────
# Covers Art.5 (governance), Art.6–16 (ICT risk), Art.17–23 (incidents),
# Art.24–27 (testing), Art.28–44 (third-party risk), Art.11–12 (BCP/backup).
DORA = [
    # Art.5 — ICT Governance
    {
        "qid": "dora-gov-01", "section": "Art.5 — ICT Governance",
        "question": "Does the management body approve and oversee the ICT risk management framework and take ultimate accountability for ICT risk?",
        "guidance": "Art.5(2). Evidence: board decision, CISO reporting line, quarterly ICT risk report to board.",
        "control_ref": "DORA Art.5(2)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 1,
    },
    {
        "qid": "dora-gov-02", "section": "Art.5 — ICT Governance",
        "question": "Has the management body completed dedicated ICT risk training, and are members able to challenge and oversee ICT risk decisions?",
        "guidance": "Art.5(4). Evidence: training records, board skills assessment, training content.",
        "control_ref": "DORA Art.5(4)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 2,
    },
    # Art.6 — ICT Risk Management Framework
    {
        "qid": "dora-risk-01", "section": "Art.6 — ICT Risk Management Framework",
        "question": "Is there a documented, board-approved ICT Risk Management Framework (ICTRMF) covering strategy, risk tolerance, and control objectives?",
        "guidance": "Art.6(1). Evidence: ICTRMF document, version history, management sign-off, annual review cycle.",
        "control_ref": "DORA Art.6(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 3,
    },
    {
        "qid": "dora-risk-02", "section": "Art.6 — ICT Risk Management Framework",
        "question": "Are ICT risks formally identified, assessed, and categorised using a consistent methodology at least annually, with a current risk register maintained?",
        "guidance": "Art.6(2)(a). Evidence: methodology document, risk register, latest assessment report.",
        "control_ref": "DORA Art.6(2)(a)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 4,
    },
    {
        "qid": "dora-risk-03", "section": "Art.6 — ICT Risk Management Framework",
        "question": "Are ICT risk treatment plans implemented with defined owners, timelines, and residual risk acceptance by appropriate authority?",
        "guidance": "Art.6(2)(c). Evidence: treatment plan, residual risk sign-off, progress tracking.",
        "control_ref": "DORA Art.6(2)(c)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 5,
    },
    # Art.8 — Asset identification
    {
        "qid": "dora-asset-01", "section": "Art.8 — ICT Asset Management",
        "question": "Is a complete and current ICT asset inventory maintained, covering hardware, software, data, and cloud services, with criticality classification?",
        "guidance": "Art.8(1). Evidence: CMDB, cloud asset inventory, software licence register, data classification map.",
        "control_ref": "DORA Art.8(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 6,
    },
    # Art.9–10 — Protection & Detection
    {
        "qid": "dora-protect-01", "section": "Art.9 — ICT Protection",
        "question": "Are all critical ICT systems protected with documented change management procedures, including security impact assessment before any change?",
        "guidance": "Art.9(1). Evidence: change management policy, CAB process, security sign-off in change tickets.",
        "control_ref": "DORA Art.9(1)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 7,
    },
    {
        "qid": "dora-detect-01", "section": "Art.10 — Detection & Monitoring",
        "question": "How mature is the organisation's continuous ICT risk monitoring capability? (1=manual/ad-hoc, 5=automated with real-time dashboards and alerting)",
        "guidance": "Art.10(1). Evidence: SIEM, vulnerability scanner, configuration monitoring, SOC.",
        "control_ref": "DORA Art.10(1)", "weight": 3, "question_type": "score_1_5", "options": [], "order_idx": 8,
    },
    {
        "qid": "dora-detect-02", "section": "Art.10 — Detection & Monitoring",
        "question": "Are anomaly detection mechanisms in place to identify unusual patterns in ICT system behaviour, and are alerts triaged against defined runbooks?",
        "guidance": "Art.10(2). Evidence: UEBA/SIEM anomaly rules, alert triage procedures, runbook library.",
        "control_ref": "DORA Art.10(2)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 9,
    },
    # Art.11–12 — BCP and backup
    {
        "qid": "dora-bcp-01", "section": "Art.11 — Business Continuity",
        "question": "Are BCP and DRP documented, tested annually, and covering all critical ICT systems with defined RTO/RPO validated through test?",
        "guidance": "Art.11(1). Evidence: BCP/DRP, annual test results, RTO/RPO compliance evidence.",
        "control_ref": "DORA Art.11(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 10,
    },
    {
        "qid": "dora-bcp-02", "section": "Art.12 — Backup & Recovery",
        "question": "How well does the backup strategy satisfy 3-2-1 principles (multiple copies, offline/offsite, tested regularly for restorability)?",
        "guidance": "Art.12(1). Evidence: backup policy, test restoration logs, off-site storage confirmation, RPO compliance.",
        "control_ref": "DORA Art.12(1)", "weight": 3, "question_type": "score_1_5", "options": [], "order_idx": 11,
    },
    # Art.13 — Threat intelligence
    {
        "qid": "dora-cti-01", "section": "Art.13 — Threat Intelligence",
        "question": "Are threat intelligence feeds actively consumed and integrated into security monitoring and incident response?",
        "guidance": "Art.13(1). Evidence: CTI platform, ISAC membership, threat intel integration in SIEM.",
        "control_ref": "DORA Art.13(1)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 12,
    },
    # Art.17–19 — ICT Incident Management & Reporting
    {
        "qid": "dora-ir-01", "section": "Art.17 — ICT Incident Management",
        "question": "Is there a documented ICT incident management process covering detection, classification, notification, escalation, and post-incident review?",
        "guidance": "Art.17(1). Evidence: IRP covering all phases, escalation matrix, post-incident review template.",
        "control_ref": "DORA Art.17(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 13,
    },
    {
        "qid": "dora-ir-02", "section": "Art.18 — Incident Classification",
        "question": "Are ICT incidents classified against DORA major incident criteria (client impact, transaction impact, reputational damage, data loss) with defined thresholds?",
        "guidance": "Art.18(1). Evidence: classification matrix with DORA criteria, incident severity procedure.",
        "control_ref": "DORA Art.18(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 14,
    },
    {
        "qid": "dora-ir-03", "section": "Art.19 — Major Incident Reporting",
        "question": "Is the organisation able to submit an initial notification to the competent authority within 4 hours of classifying an incident as major?",
        "guidance": "Art.19(4)(a). Evidence: notification procedure with 4h SLA, authority contacts, notification template.",
        "control_ref": "DORA Art.19(4)(a)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 15,
    },
    {
        "qid": "dora-ir-04", "section": "Art.19 — Major Incident Reporting",
        "question": "Are intermediate and final reports on major ICT incidents submitted within the DORA-mandated timeframes (intermediate ≤72h, final ≤1 month)?",
        "guidance": "Art.19(4)(b)(c). Evidence: incident reporting SOP, example reports, regulatory submission log.",
        "control_ref": "DORA Art.19(4)(b–c)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 16,
    },
    # Art.24–26 — Digital Operational Resilience Testing
    {
        "qid": "dora-test-01", "section": "Art.24 — Resilience Testing",
        "question": "Does the organisation conduct annual ICT resilience tests (vulnerability assessments, penetration tests) covering critical systems?",
        "guidance": "Art.24(1). Evidence: annual pentest schedule, scope, findings tracker, remediation evidence.",
        "control_ref": "DORA Art.24(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 17,
    },
    {
        "qid": "dora-test-02", "section": "Art.24 — Resilience Testing",
        "question": "Are penetration test findings tracked to closure with severity-based remediation SLAs (e.g., critical ≤14 days, high ≤30 days)?",
        "guidance": "Art.24(6). Evidence: findings register, remediation SLAs, sign-off process.",
        "control_ref": "DORA Art.24(6)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 18,
    },
    {
        "qid": "dora-test-03", "section": "Art.26 — Threat-Led Penetration Testing",
        "question": "If the organisation qualifies as significant under DORA, has Threat-Led Penetration Testing (TLPT) been conducted or planned within the 3-year cycle?",
        "guidance": "Art.26(1). Evidence: TLPT scope approval, red-team engagement report, regulator notification.",
        "control_ref": "DORA Art.26(1)", "weight": 2, "question_type": "multi_choice",
        "options": ["Completed TLPT", "Planned within 12 months", "Not required (not significant entity)", "Not yet assessed"],
        "order_idx": 19,
    },
    # Art.28–30 — Third-party ICT risk
    {
        "qid": "dora-tpr-01", "section": "Art.28 — Third-Party ICT Risk",
        "question": "Is a register of all critical ICT third-party providers (CTPPs) maintained, with formal risk assessments conducted before engagement and annually thereafter?",
        "guidance": "Art.28(2). Evidence: CTPP list, risk assessment per provider, annual review schedule.",
        "control_ref": "DORA Art.28(2)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 20,
    },
    {
        "qid": "dora-tpr-02", "section": "Art.30 — Contractual Provisions",
        "question": "Do contracts with critical ICT third parties include all DORA-mandated clauses (audit rights, sub-contracting controls, termination rights, data portability)?",
        "guidance": "Art.30(1). Evidence: contract template review against Art.30 checklist, legal sign-off.",
        "control_ref": "DORA Art.30(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 21,
    },
    {
        "qid": "dora-tpr-03", "section": "Art.28 — Exit Strategies",
        "question": "Are exit strategies and substitutability plans documented for all critical ICT third-party dependencies?",
        "guidance": "Art.28(8). Evidence: exit strategy documents, data portability assessment, alternative provider analysis.",
        "control_ref": "DORA Art.28(8)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 22,
    },
    # Art.45–49 — Information sharing
    {
        "qid": "dora-share-01", "section": "Art.45 — Information Sharing",
        "question": "Does the organisation participate in cyber threat intelligence sharing arrangements with peers or sectoral authorities?",
        "guidance": "Art.45. Evidence: ISAC membership, information sharing agreement, TLP-marked intel exchange records.",
        "control_ref": "DORA Art.45", "weight": 1, "question_type": "yes_no", "options": [], "order_idx": 23,
    },
    # Additional operational controls
    {
        "qid": "dora-cfg-01", "section": "Art.9 — ICT Protection",
        "question": "Are secure configuration baselines (hardening standards) documented and enforced for all ICT systems in scope, with deviation alerts in place?",
        "guidance": "Art.9. Evidence: hardening standards per platform, CIS Benchmark scan results, drift detection alerts.",
        "control_ref": "DORA Art.9", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 24,
    },
    {
        "qid": "dora-iam-01", "section": "Art.9 — ICT Protection",
        "question": "Is MFA enforced for all access to critical ICT systems and remote access, with privileged accounts subject to enhanced controls (PAM, session recording)?",
        "guidance": "Art.9. Evidence: MFA configuration report, PAM tool deployment, privileged account register.",
        "control_ref": "DORA Art.9", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 25,
    },
    {
        "qid": "dora-vuln-01", "section": "Art.6 — ICT Risk Management Framework",
        "question": "Is a vulnerability management programme in place with regular scanning, severity-based patching SLAs, and an exception process for risk-accepted deviations?",
        "guidance": "Art.6(2). Evidence: scanner reports, patch SLA policy, exception log with risk acceptance.",
        "control_ref": "DORA Art.6(2)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 26,
    },
    {
        "qid": "dora-audit-01", "section": "Art.5 — ICT Governance",
        "question": "Is the ICTRMF reviewed at least annually and updated following major incidents, significant changes, or regulatory guidance?",
        "guidance": "Art.6(5). Evidence: ICTRMF version history, review minutes, post-incident update records.",
        "control_ref": "DORA Art.6(5)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 27,
    },
    {
        "qid": "dora-log-01", "section": "Art.10 — Detection & Monitoring",
        "question": "Are audit and security logs from all critical ICT systems retained for a sufficient period and protected against tampering?",
        "guidance": "Art.10. Evidence: log retention policy (≥12 months), SIEM log integrity controls.",
        "control_ref": "DORA Art.10", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 28,
    },
]

# ── SOC 2 Type II — Trust Service Criteria ───────────────────────────────────
# CC1-CC9 (Common Criteria) + A (Availability) + C (Confidentiality)
# + PI (Processing Integrity) + P (Privacy)
SOC2 = [
    # CC1 — Control Environment
    {
        "qid": "soc2-cc1-01", "section": "CC1 — Control Environment",
        "question": "Does the organisation demonstrate commitment to integrity and ethical values through a code of conduct communicated to and acknowledged by all personnel?",
        "guidance": "CC1.1. Evidence: code of conduct, annual acknowledgement records, ethics hotline.",
        "control_ref": "SOC 2 CC1.1", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 1,
    },
    {
        "qid": "soc2-cc1-02", "section": "CC1 — Control Environment",
        "question": "Is there a defined organisational structure with documented security responsibilities, reporting lines, and board-level oversight of internal controls?",
        "guidance": "CC1.3. Evidence: org chart, security RACI, board audit/risk committee charter.",
        "control_ref": "SOC 2 CC1.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 2,
    },
    {
        "qid": "soc2-cc1-03", "section": "CC1 — Control Environment",
        "question": "Are personnel recruited, developed, and retained with appropriate competencies for their security responsibilities, and is performance evaluated against security objectives?",
        "guidance": "CC1.4 / CC1.5. Evidence: job descriptions with security responsibilities, competency assessments, training records.",
        "control_ref": "SOC 2 CC1.4 / CC1.5", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 3,
    },
    # CC2 — Communication & Information
    {
        "qid": "soc2-cc2-01", "section": "CC2 — Communication & Information",
        "question": "Are security policies communicated to internal stakeholders and relevant external parties (customers, vendors) and updated when significant changes occur?",
        "guidance": "CC2.2 / CC2.3. Evidence: policy distribution records, vendor communication, customer-facing security page.",
        "control_ref": "SOC 2 CC2.2 / CC2.3", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 4,
    },
    # CC3 — Risk Assessment
    {
        "qid": "soc2-cc3-01", "section": "CC3 — Risk Assessment",
        "question": "Is a risk assessment process in place identifying risks to Trust Service Criteria achievement, with results documented and risk owners assigned?",
        "guidance": "CC3.2. Evidence: risk methodology, SOC 2 risk register, risk owner assignments, review cadence.",
        "control_ref": "SOC 2 CC3.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 5,
    },
    {
        "qid": "soc2-cc3-02", "section": "CC3 — Risk Assessment",
        "question": "Does the risk assessment consider fraud risks and risks from significant organisational, system, or environmental changes, with change-triggered reviews?",
        "guidance": "CC3.3 / CC3.4. Evidence: fraud risk assessment, change-triggered review process, emerging threat monitoring.",
        "control_ref": "SOC 2 CC3.3 / CC3.4", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 6,
    },
    # CC4 — Monitoring Activities
    {
        "qid": "soc2-cc4-01", "section": "CC4 — Monitoring Activities",
        "question": "Are ongoing and separate evaluations of internal controls performed, with deficiencies communicated to appropriate parties and remediated?",
        "guidance": "CC4.1 / CC4.2. Evidence: internal audit programme, control monitoring reports, deficiency tracker, management action plans.",
        "control_ref": "SOC 2 CC4.1 / CC4.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 7,
    },
    # CC5 — Control Activities
    {
        "qid": "soc2-cc5-01", "section": "CC5 — Control Activities",
        "question": "Are control activities (policies, procedures, automated controls) designed and implemented to mitigate identified risks to an acceptable level?",
        "guidance": "CC5.1 / CC5.2. Evidence: control matrix mapping risks to controls, evidence of control operation.",
        "control_ref": "SOC 2 CC5.1 / CC5.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 8,
    },
    {
        "qid": "soc2-cc5-02", "section": "CC5 — Control Activities",
        "question": "Are control responsibilities for vendor-provided services and complementary user entity controls (CUECs) documented and monitored?",
        "guidance": "CC5.3. Evidence: sub-service organisation monitoring, CUEC documentation, complementary controls matrix.",
        "control_ref": "SOC 2 CC5.3", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 9,
    },
    # CC6 — Logical & Physical Access
    {
        "qid": "soc2-cc6-01", "section": "CC6 — Logical & Physical Access",
        "question": "Are logical access controls implemented using a least-privilege model with role-based access provisioned, reviewed quarterly, and revoked promptly on role change or departure?",
        "guidance": "CC6.1–CC6.3. Evidence: access policy, IAM reports, joiner/mover/leaver process, quarterly access reviews.",
        "control_ref": "SOC 2 CC6.1–CC6.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 10,
    },
    {
        "qid": "soc2-cc6-02", "section": "CC6 — Logical & Physical Access",
        "question": "Is MFA enforced for all production environment access, administrative interfaces, and remote access?",
        "guidance": "CC6.1. Evidence: MFA configuration, coverage report (target 100% for privileged), exception log.",
        "control_ref": "SOC 2 CC6.1", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 11,
    },
    {
        "qid": "soc2-cc6-03", "section": "CC6 — Logical & Physical Access",
        "question": "Is encryption in place for data at rest and in transit, with key management procedures documented and key rotation enforced?",
        "guidance": "CC6.1 / CC6.7. Evidence: encryption policy, TLS configuration, data store encryption coverage, KMS documentation.",
        "control_ref": "SOC 2 CC6.1 / CC6.7", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 12,
    },
    {
        "qid": "soc2-cc6-04", "section": "CC6 — Logical & Physical Access",
        "question": "Are physical access controls in place for data centres and server rooms, with visitor logs, badge access systems, and CCTV monitoring?",
        "guidance": "CC6.4. Evidence: physical access policy, badge reader logs, visitor records, CCTV coverage.",
        "control_ref": "SOC 2 CC6.4", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 13,
    },
    {
        "qid": "soc2-cc6-05", "section": "CC6 — Logical & Physical Access",
        "question": "Are output protection controls in place to prevent authorised users from transmitting sensitive data to unauthorised parties (DLP)?",
        "guidance": "CC6.6 / CC6.8. Evidence: DLP policy, email DLP configuration, cloud DLP controls, data egress monitoring.",
        "control_ref": "SOC 2 CC6.6 / CC6.8", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 14,
    },
    # CC7 — System Operations
    {
        "qid": "soc2-cc7-01", "section": "CC7 — System Operations",
        "question": "Is the production environment continuously monitored for security events with automated alerting, anomaly detection, and defined response runbooks?",
        "guidance": "CC7.1 / CC7.2. Evidence: SIEM coverage, UEBA, on-call runbooks, MTTD/MTTR metrics.",
        "control_ref": "SOC 2 CC7.1 / CC7.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 15,
    },
    {
        "qid": "soc2-cc7-02", "section": "CC7 — System Operations",
        "question": "Is there a defined and tested IRP with severity-based SLAs, and are customer notification procedures defined for incidents impacting service?",
        "guidance": "CC7.3–CC7.5. Evidence: IRP, severity matrix, tabletop exercise, customer notification SLAs.",
        "control_ref": "SOC 2 CC7.3–CC7.5", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 16,
    },
    # CC8 — Change Management
    {
        "qid": "soc2-cc8-01", "section": "CC8 — Change Management",
        "question": "Is a formal change management process in place with security review, pre-production testing, approval, and rollback capability before production deployment?",
        "guidance": "CC8.1. Evidence: change management policy, CAB approval records, test evidence, rollback procedures.",
        "control_ref": "SOC 2 CC8.1", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 17,
    },
    {
        "qid": "soc2-cc8-02", "section": "CC8 — Change Management",
        "question": "Are development, test, and production environments fully separated, with no direct developer access to production?",
        "guidance": "CC8.1. Evidence: environment separation docs, access control for prod, deployment pipeline with approvals.",
        "control_ref": "SOC 2 CC8.1", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 18,
    },
    # CC9 — Risk Mitigation
    {
        "qid": "soc2-cc9-01", "section": "CC9 — Risk Mitigation",
        "question": "Are vendor/sub-service provider risks assessed before engagement and annually, with security requirements in contracts and monitoring of compliance?",
        "guidance": "CC9.2. Evidence: vendor assessment process, security questionnaires, contract clauses, annual reviews.",
        "control_ref": "SOC 2 CC9.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 19,
    },
    {
        "qid": "soc2-cc9-02", "section": "CC9 — Risk Mitigation",
        "question": "Are business disruption risks (natural disasters, infrastructure failure, cyber incidents) assessed and mitigated through insurance, redundancy, or operational controls?",
        "guidance": "CC9.1. Evidence: BIA, risk mitigation controls, cyber insurance policy, redundancy architecture.",
        "control_ref": "SOC 2 CC9.1", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 20,
    },
    # A — Availability
    {
        "qid": "soc2-av-01", "section": "A — Availability",
        "question": "Are availability SLAs defined, monitored against targets, and are procedures in place to restore services within committed RTO/RPO?",
        "guidance": "A1.1 / A1.2. Evidence: uptime SLAs, monitoring dashboards, DRP with RTO/RPO, last DR test.",
        "control_ref": "SOC 2 A1.1 / A1.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 21,
    },
    {
        "qid": "soc2-av-02", "section": "A — Availability",
        "question": "Are capacity management processes in place to ensure sufficient infrastructure capacity to meet current and projected demand?",
        "guidance": "A1.1. Evidence: capacity reports, auto-scaling configuration, capacity forecasting process.",
        "control_ref": "SOC 2 A1.1", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 22,
    },
    # C — Confidentiality
    {
        "qid": "soc2-cf-01", "section": "C — Confidentiality",
        "question": "Is confidential information identified, classified, protected, and securely disposed of per a data retention and destruction policy?",
        "guidance": "C1.1 / C1.2. Evidence: classification policy, encryption for confidential data, secure deletion records.",
        "control_ref": "SOC 2 C1.1 / C1.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 23,
    },
    # PI — Processing Integrity
    {
        "qid": "soc2-pi-01", "section": "PI — Processing Integrity",
        "question": "Are controls in place to ensure system processing is complete, valid, accurate, timely, and authorised, with error detection and reconciliation procedures?",
        "guidance": "PI1.1. Evidence: input/output validation controls, reconciliation procedures, error logging.",
        "control_ref": "SOC 2 PI1.1", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 24,
    },
    # P — Privacy
    {
        "qid": "soc2-prv-01", "section": "P — Privacy",
        "question": "Is a privacy notice in place describing how personal information is collected, used, retained, and disposed of, and is it reviewed to remain accurate?",
        "guidance": "P1.0. Evidence: privacy notice, DPIA register, data subject request process.",
        "control_ref": "SOC 2 P1.0", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 25,
    },
    {
        "qid": "soc2-prv-02", "section": "P — Privacy",
        "question": "Are procedures in place to respond to data subject access, correction, and deletion requests within regulatory timeframes?",
        "guidance": "P6.0 / P8.0. Evidence: DSAR process, response time tracking, deletion confirmation records.",
        "control_ref": "SOC 2 P6.0 / P8.0", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 26,
    },
    # Vulnerability management
    {
        "qid": "soc2-vuln-01", "section": "CC7 — System Operations",
        "question": "Is a vulnerability management programme in place with regular scanning of production systems and severity-based remediation SLAs?",
        "guidance": "CC7.1. Evidence: vulnerability scanner reports, patch SLA policy, remediation tracking.",
        "control_ref": "SOC 2 CC7.1", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 27,
    },
    {
        "qid": "soc2-pen-01", "section": "CC4 — Monitoring Activities",
        "question": "Is an annual penetration test conducted against production systems, with findings tracked to closure and test results communicated to leadership?",
        "guidance": "CC4.1. Evidence: pentest report, findings tracker, leadership briefing, remediation sign-off.",
        "control_ref": "SOC 2 CC4.1", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 28,
    },
]

# ── NIST CSF 2.0 ──────────────────────────────────────────────────────────────
# Covers all 6 functions: GV (Govern), ID (Identify), PR (Protect),
# DE (Detect), RS (Respond), RC (Recover)
NIST_CSF = [
    # GV — Govern (new in CSF 2.0)
    {
        "qid": "nist-gv-01", "section": "GV — Govern: Organisational Context",
        "question": "Is there a documented cybersecurity policy aligned to business objectives, approved by leadership, and reviewed annually?",
        "guidance": "GV.OC-01. Evidence: cybersecurity strategy, policy document, leadership approval, review history.",
        "control_ref": "NIST CSF GV.OC-01", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 1,
    },
    {
        "qid": "nist-gv-02", "section": "GV — Govern: Risk Strategy",
        "question": "Is cybersecurity integrated into enterprise risk management (ERM) with defined risk tolerance communicated across the organisation?",
        "guidance": "GV.RM-01/02. Evidence: ERM framework including cyber, risk appetite statement, board-level cyber risk reporting.",
        "control_ref": "NIST CSF GV.RM-01 / GV.RM-02", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 2,
    },
    {
        "qid": "nist-gv-03", "section": "GV — Govern: Roles & Responsibilities",
        "question": "Are cybersecurity roles and responsibilities formally defined, communicated, and coordinated across all relevant stakeholders (internal teams, suppliers, partners)?",
        "guidance": "GV.RR-01/02. Evidence: RACI matrix, job descriptions with security responsibilities, third-party security obligations.",
        "control_ref": "NIST CSF GV.RR-01 / GV.RR-02", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 3,
    },
    {
        "qid": "nist-gv-04", "section": "GV — Govern: Policy",
        "question": "Are cybersecurity policies reviewed and updated to reflect changes in legal/regulatory requirements, threat landscape, and organisational changes?",
        "guidance": "GV.PO-01/02. Evidence: policy review log, change-triggered review records, policy version history.",
        "control_ref": "NIST CSF GV.PO-01 / GV.PO-02", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 4,
    },
    {
        "qid": "nist-gv-05", "section": "GV — Govern: Oversight",
        "question": "Does management regularly review cybersecurity performance results against objectives and take corrective action where needed?",
        "guidance": "GV.OV-01/02/03. Evidence: management review records, KPI/metric dashboards, corrective action log.",
        "control_ref": "NIST CSF GV.OV-01–GV.OV-03", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 5,
    },
    # ID — Identify
    {
        "qid": "nist-id-01", "section": "ID — Identify: Asset Management",
        "question": "Is a comprehensive inventory of hardware, software, data, and services maintained and kept current through automated discovery tools?",
        "guidance": "ID.AM-01/02. Evidence: CMDB, asset discovery tool, SBOM, cloud asset inventory.",
        "control_ref": "NIST CSF ID.AM-01 / ID.AM-02", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 6,
    },
    {
        "qid": "nist-id-02", "section": "ID — Identify: Asset Management",
        "question": "Has the organisation identified its critical assets and defined protection requirements (availability, integrity, confidentiality) based on Business Impact Analysis?",
        "guidance": "ID.AM-05/06. Evidence: criticality classification, BIA results, asset-specific protection requirements.",
        "control_ref": "NIST CSF ID.AM-05 / ID.AM-06", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 7,
    },
    {
        "qid": "nist-id-03", "section": "ID — Identify: Risk Assessment",
        "question": "Are cybersecurity risks identified and prioritised using a risk assessment methodology that considers likelihood, impact, and organisational context?",
        "guidance": "ID.RA-01/02/05. Evidence: risk assessment reports, threat modelling artifacts, prioritised risk register.",
        "control_ref": "NIST CSF ID.RA-01 / ID.RA-05", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 8,
    },
    {
        "qid": "nist-id-04", "section": "ID — Identify: Risk Assessment",
        "question": "Are vulnerabilities in assets identified, documented, and used as inputs to the risk assessment and remediation process?",
        "guidance": "ID.RA-01. Evidence: vulnerability scanner integration with risk register, CVSS scoring, remediation prioritisation.",
        "control_ref": "NIST CSF ID.RA-01", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 9,
    },
    {
        "qid": "nist-id-05", "section": "ID — Identify: Improvement",
        "question": "Are lessons learned from cybersecurity events, external intelligence, and industry incidents incorporated into continuous improvement of the cybersecurity programme?",
        "guidance": "ID.IM-01/02. Evidence: lessons-learned register, post-incident updates to controls/processes, threat intel review process.",
        "control_ref": "NIST CSF ID.IM-01 / ID.IM-02", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 10,
    },
    # PR — Protect
    {
        "qid": "nist-pr-01", "section": "PR — Protect: Identity Management & Access Control",
        "question": "Are identity and access management controls implemented with least privilege, MFA for all users, and periodic access reviews?",
        "guidance": "PR.AA-01/03/05/06. Evidence: IAM system, MFA coverage report, access review records, PAM controls.",
        "control_ref": "NIST CSF PR.AA-01 / PR.AA-06", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 11,
    },
    {
        "qid": "nist-pr-02", "section": "PR — Protect: Data Security",
        "question": "Is data protected through classification, encryption (in transit and at rest), integrity controls, and secure disposal aligned to data sensitivity?",
        "guidance": "PR.DS-01/02/10. Evidence: data classification policy, encryption standards, DLP controls, disposal records.",
        "control_ref": "NIST CSF PR.DS-01 / PR.DS-02 / PR.DS-10", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 12,
    },
    {
        "qid": "nist-pr-03", "section": "PR — Protect: Awareness & Training",
        "question": "Are security awareness and skills training programmes in place for all staff, with role-specific training for high-risk functions (admins, developers, executives)?",
        "guidance": "PR.AT-01/02. Evidence: training programme, completion records, phishing simulation results, technical training records.",
        "control_ref": "NIST CSF PR.AT-01 / PR.AT-02", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 13,
    },
    {
        "qid": "nist-pr-04", "section": "PR — Protect: Platform Security",
        "question": "Rate the maturity of platform security controls (patching, hardening, endpoint protection, network segmentation): (1=ad-hoc, 5=fully automated with continuous monitoring)",
        "guidance": "PR.PS-01/02/03. Evidence: patch compliance metrics, CIS Benchmark scans, EDR coverage, network diagrams.",
        "control_ref": "NIST CSF PR.PS-01–PR.PS-03", "weight": 3, "question_type": "score_1_5", "options": [], "order_idx": 14,
    },
    {
        "qid": "nist-pr-05", "section": "PR — Protect: Technology Infrastructure",
        "question": "Are resilience requirements addressed in security architecture, including redundancy, network segmentation, and secure configuration of infrastructure?",
        "guidance": "PR.IR-01/02/03/04. Evidence: architecture diagrams, redundancy configuration, network segmentation, DR architecture.",
        "control_ref": "NIST CSF PR.IR-01–PR.IR-04", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 15,
    },
    # DE — Detect
    {
        "qid": "nist-de-01", "section": "DE — Detect: Continuous Monitoring",
        "question": "Is continuous monitoring of networks, systems, and user activity in place using SIEM/UEBA with defined detection rules for known attack patterns and anomalies?",
        "guidance": "DE.CM-01/03/06/09. Evidence: SIEM coverage, detection rule library, UEBA deployment, alert tuning.",
        "control_ref": "NIST CSF DE.CM-01 / DE.CM-09", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 16,
    },
    {
        "qid": "nist-de-02", "section": "DE — Detect: Adverse Event Analysis",
        "question": "Are detected events correlated and analysed in context using defined thresholds and investigation procedures to distinguish incidents from false positives?",
        "guidance": "DE.AE-02/04/06. Evidence: alert triage runbooks, correlation rules, analyst investigation logs, FP rate metrics.",
        "control_ref": "NIST CSF DE.AE-02 / DE.AE-06", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 17,
    },
    {
        "qid": "nist-de-03", "section": "DE — Detect: Adverse Event Analysis",
        "question": "Is threat intelligence used to inform detection logic and anomaly thresholds, with intelligence updated from multiple sources (commercial, government, ISAC)?",
        "guidance": "DE.AE-02. Evidence: CTI integration in SIEM, detection rule update process, intelligence source register.",
        "control_ref": "NIST CSF DE.AE-02", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 18,
    },
    # RS — Respond
    {
        "qid": "nist-rs-01", "section": "RS — Respond: Incident Management",
        "question": "Is a documented IRP in place with scenario-specific playbooks (ransomware, phishing, insider threat, DDoS), tested at least annually?",
        "guidance": "RS.MA-01/02. Evidence: IRP, playbook library, annual exercise report, plan updated post-exercise.",
        "control_ref": "NIST CSF RS.MA-01 / RS.MA-02", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 19,
    },
    {
        "qid": "nist-rs-02", "section": "RS — Respond: Incident Response Reporting & Communication",
        "question": "Are incident communication procedures defined, including internal escalation, regulatory notification, and external communications where required?",
        "guidance": "RS.CO-02/03/04. Evidence: comms plan, notification templates, PR/legal involvement process.",
        "control_ref": "NIST CSF RS.CO-02–RS.CO-04", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 20,
    },
    {
        "qid": "nist-rs-03", "section": "RS — Respond: Incident Analysis & Mitigation",
        "question": "Are incident root cause analysis and forensic preservation performed for significant incidents, with findings used to improve controls?",
        "guidance": "RS.AN-03/06. Evidence: RCA reports, forensic evidence procedures, control improvement actions.",
        "control_ref": "NIST CSF RS.AN-03 / RS.AN-06", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 21,
    },
    # RC — Recover
    {
        "qid": "nist-rc-01", "section": "RC — Recover: Incident Recovery Plan",
        "question": "Is a recovery plan documented and tested with defined restoration priorities based on BIA and asset criticality?",
        "guidance": "RC.RP-01/02. Evidence: DRP/BCP with restoration priorities, last recovery test report.",
        "control_ref": "NIST CSF RC.RP-01 / RC.RP-02", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 22,
    },
    {
        "qid": "nist-rc-02", "section": "RC — Recover: Backup & Restoration",
        "question": "Are offsite/offline backups of all critical data maintained, regularly tested for integrity, and restoration validated against defined RPO and RTO?",
        "guidance": "RC.RP-03. Evidence: backup policy (3-2-1 principle), off-site confirmation, restoration test logs, RPO/RTO compliance.",
        "control_ref": "NIST CSF RC.RP-03", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 23,
    },
    {
        "qid": "nist-rc-03", "section": "RC — Recover: Incident Recovery Communication",
        "question": "Are stakeholders informed during recovery operations, and is a communication plan in place for managing customer and media expectations during a significant cyber event?",
        "guidance": "RC.CO-03/04. Evidence: recovery comms plan, stakeholder notification templates, crisis communication records.",
        "control_ref": "NIST CSF RC.CO-03 / RC.CO-04", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 24,
    },
    {
        "qid": "nist-rc-04", "section": "RC — Recover: Improvements",
        "question": "Are post-incident lessons learned formally documented, shared with relevant stakeholders, and used to update plans, procedures, and security controls?",
        "guidance": "RC.IM-01/02. Evidence: PIR reports, lessons-learned register, evidence of plan/control updates after incidents.",
        "control_ref": "NIST CSF RC.IM-01 / RC.IM-02", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 25,
    },
    {
        "qid": "nist-sup-01", "section": "GV — Govern: Supply Chain Risk",
        "question": "Is cybersecurity risk in the supply chain assessed and managed, with security requirements in procurement and third-party risk monitored on an ongoing basis?",
        "guidance": "GV.SC-01/02/06. Evidence: supply chain risk programme, procurement security requirements, vendor assessment results.",
        "control_ref": "NIST CSF GV.SC-01 / GV.SC-06", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 26,
    },
]

# ── PCI DSS v4.0 ──────────────────────────────────────────────────────────────
# Covers all 12 Requirements
PCI_DSS = [
    # Req 1 — Network Security Controls
    {
        "qid": "pci-net-01", "section": "Req 1 — Network Security Controls",
        "question": "Is the CDE segmented from untrusted networks using firewalls or equivalent controls, with all rules documented, justified, and reviewed at least every six months?",
        "guidance": "Req 1.1 / 1.2. Evidence: network diagram showing CDE segmentation, firewall rule set, bi-annual review records.",
        "control_ref": "PCI DSS v4 Req.1.1 / Req.1.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 1,
    },
    {
        "qid": "pci-net-02", "section": "Req 1 — Network Security Controls",
        "question": "Are inbound and outbound traffic rules restricted to only what is necessary for each system's function, with a default-deny policy and all exceptions documented?",
        "guidance": "Req 1.3. Evidence: firewall policy with default-deny, exception register, quarterly rule review.",
        "control_ref": "PCI DSS v4 Req.1.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 2,
    },
    # Req 2 — Secure Configurations
    {
        "qid": "pci-cfg-01", "section": "Req 2 — Secure Configurations",
        "question": "Are all CDE system components configured according to a hardening baseline (e.g., CIS Benchmarks), with default credentials changed and unnecessary services disabled?",
        "guidance": "Req 2.2. Evidence: hardening standards, configuration compliance scans, baseline review schedule.",
        "control_ref": "PCI DSS v4 Req.2.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 3,
    },
    {
        "qid": "pci-cfg-02", "section": "Req 2 — Secure Configurations",
        "question": "Are wireless technologies in or connected to the CDE configured securely, with strong encryption and prohibited insecure protocols (WEP, TKIP) blocked?",
        "guidance": "Req 2.2 / 1.3. Evidence: wireless security policy, Wi-Fi configuration scan, rogue AP detection.",
        "control_ref": "PCI DSS v4 Req.2.2 / Req.1.3", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 4,
    },
    # Req 3 — Protect Stored Account Data
    {
        "qid": "pci-data-01", "section": "Req 3 — Protect Stored Account Data",
        "question": "Is PAN data stored only where necessary, rendered unreadable (tokenised, truncated, or AES-256 encrypted), and purged per a documented retention policy?",
        "guidance": "Req 3.3 / 3.5. Evidence: data flow diagram, storage inventory, encryption configuration, retention policy with purge logs.",
        "control_ref": "PCI DSS v4 Req.3.3 / Req.3.5", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 5,
    },
    {
        "qid": "pci-data-02", "section": "Req 3 — Protect Stored Account Data",
        "question": "Has a data discovery scan been performed in the past 12 months to locate all locations where PAN data resides (including unstructured stores)?",
        "guidance": "Req 3.1. Evidence: data discovery tool output, remediation of unauthorised PAN storage.",
        "control_ref": "PCI DSS v4 Req.3.1", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 6,
    },
    {
        "qid": "pci-data-03", "section": "Req 3 — Protect Stored Account Data",
        "question": "Is sensitive authentication data (CVV, PIN, full-track data) never stored after transaction authorisation, even in encrypted form?",
        "guidance": "Req 3.2. Evidence: data flow confirmation, code/DB review showing no SAD storage, vendor attestation.",
        "control_ref": "PCI DSS v4 Req.3.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 7,
    },
    # Req 4 — Protect in Transit
    {
        "qid": "pci-tls-01", "section": "Req 4 — Protect Cardholder Data in Transit",
        "question": "Is all transmission of cardholder data over open/public networks encrypted using strong cryptography (TLS 1.2 or higher, no deprecated protocols)?",
        "guidance": "Req 4.2. Evidence: TLS configuration scan, cipher suite policy, no SSL/TLS 1.0/1.1.",
        "control_ref": "PCI DSS v4 Req.4.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 8,
    },
    # Req 5 — Protect Against Malware
    {
        "qid": "pci-avm-01", "section": "Req 5 — Protect Against Malicious Software",
        "question": "Is anti-malware deployed on all applicable CDE systems, kept current, and configured for periodic scans with results reviewed?",
        "guidance": "Req 5.2 / 5.3. Evidence: EDR/AV deployment report, definition update policy, scan schedule.",
        "control_ref": "PCI DSS v4 Req.5.2 / Req.5.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 9,
    },
    {
        "qid": "pci-avm-02", "section": "Req 5 — Protect Against Malicious Software",
        "question": "Are phishing and social engineering awareness programmes in place, and is anti-phishing technology deployed to protect users from malicious emails?",
        "guidance": "Req 5.4. Evidence: phishing simulation results, email security gateway (DMARC/DKIM/SPF), user training records.",
        "control_ref": "PCI DSS v4 Req.5.4", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 10,
    },
    # Req 6 — Secure Systems & Software
    {
        "qid": "pci-sdlc-01", "section": "Req 6 — Develop & Maintain Secure Systems",
        "question": "Are security vulnerabilities in CDE systems patched within defined SLAs (critical ≤1 month; lower severity ≥quarterly), with a formal patch management process?",
        "guidance": "Req 6.3. Evidence: patch management policy, patch compliance reports, exception log.",
        "control_ref": "PCI DSS v4 Req.6.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 11,
    },
    {
        "qid": "pci-sdlc-02", "section": "Req 6 — Develop & Maintain Secure Systems",
        "question": "Are in-scope web applications protected against OWASP Top 10 vulnerabilities through either a WAF or a code review / penetration test process?",
        "guidance": "Req 6.4. Evidence: WAF deployment and configuration, or DAST/pentest results covering OWASP Top 10.",
        "control_ref": "PCI DSS v4 Req.6.4", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 12,
    },
    # Req 7 — Restrict Access by Need to Know
    {
        "qid": "pci-iam-01", "section": "Req 7 — Restrict Access to System Components",
        "question": "Is access to CDE system components and cardholder data restricted to the minimum necessary, with all access formally approved and documented?",
        "guidance": "Req 7.1 / 7.2. Evidence: access policy, RBAC configuration, access request tickets, quarterly privilege reviews.",
        "control_ref": "PCI DSS v4 Req.7.1 / Req.7.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 13,
    },
    # Req 8 — Identify Users & Authenticate
    {
        "qid": "pci-iam-02", "section": "Req 8 — Identify & Authenticate Access",
        "question": "Is MFA required for all non-console administrative access to the CDE and for all remote access into the CDE?",
        "guidance": "Req 8.4.2 / 8.4.3. Evidence: MFA configuration for CDE admin accounts, VPN/remote access policy.",
        "control_ref": "PCI DSS v4 Req.8.4.2 / Req.8.4.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 14,
    },
    {
        "qid": "pci-iam-03", "section": "Req 8 — Identify & Authenticate Access",
        "question": "Are individual user IDs enforced for all personnel accessing CDE systems (no shared accounts), with passwords meeting PCI DSS complexity and rotation requirements?",
        "guidance": "Req 8.2 / 8.3. Evidence: IAM policy, no shared account evidence, password policy configuration.",
        "control_ref": "PCI DSS v4 Req.8.2 / Req.8.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 15,
    },
    {
        "qid": "pci-iam-04", "section": "Req 8 — Identify & Authenticate Access",
        "question": "Are user accounts locked after a maximum of 6 failed authentication attempts, with automatic session timeout after no more than 15 minutes of inactivity?",
        "guidance": "Req 8.3.4 / 8.3.10. Evidence: account lockout policy, session timeout configuration.",
        "control_ref": "PCI DSS v4 Req.8.3.4 / Req.8.3.10", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 16,
    },
    # Req 9 — Restrict Physical Access
    {
        "qid": "pci-phy-01", "section": "Req 9 — Restrict Physical Access to Cardholder Data",
        "question": "Is physical access to areas housing CDE systems controlled with badge readers or equivalent, with visitor logs maintained and visitor access supervised?",
        "guidance": "Req 9.1 / 9.3. Evidence: physical access policy, badge reader logs, visitor register.",
        "control_ref": "PCI DSS v4 Req.9.1 / Req.9.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 17,
    },
    {
        "qid": "pci-phy-02", "section": "Req 9 — Restrict Physical Access to Cardholder Data",
        "question": "Are media containing cardholder data classified, securely stored, and destroyed or rendered unreadable when no longer needed?",
        "guidance": "Req 9.4 / 9.5. Evidence: media classification policy, secure storage records, destruction certificates.",
        "control_ref": "PCI DSS v4 Req.9.4 / Req.9.5", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 18,
    },
    {
        "qid": "pci-phy-03", "section": "Req 9 — Restrict Physical Access to Cardholder Data",
        "question": "Are POS terminals and payment devices inspected regularly for tampering and skimming devices, with staff trained to detect such attacks?",
        "guidance": "Req 9.5. Evidence: device inspection log, tamper-evident seals policy, staff training records.",
        "control_ref": "PCI DSS v4 Req.9.5", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 19,
    },
    # Req 10 — Log & Monitor
    {
        "qid": "pci-log-01", "section": "Req 10 — Log and Monitor All Access",
        "question": "Are audit logs enabled for all CDE systems capturing access to cardholder data, admin actions, and security events, retained for ≥12 months (3 months immediately accessible)?",
        "guidance": "Req 10.2 / 10.5. Evidence: log configuration for all in-scope systems, SIEM coverage, 3-month availability test.",
        "control_ref": "PCI DSS v4 Req.10.2 / Req.10.5", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 20,
    },
    {
        "qid": "pci-log-02", "section": "Req 10 — Log and Monitor All Access",
        "question": "Are security logs reviewed daily (automated alerting for anomalies) and are log integrity controls in place to detect tampering?",
        "guidance": "Req 10.4 / 10.7. Evidence: SIEM daily review procedure, alerting configuration, log integrity hash verification.",
        "control_ref": "PCI DSS v4 Req.10.4 / Req.10.7", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 21,
    },
    # Req 11 — Test Security Regularly
    {
        "qid": "pci-scan-01", "section": "Req 11 — Test Security of Systems & Networks",
        "question": "Are all in-scope systems scanned for vulnerabilities at least quarterly by an ASV, with critical vulnerabilities remediated before passing the scan?",
        "guidance": "Req 11.3.2. Evidence: quarterly ASV scan reports with passing status, remediation tracker.",
        "control_ref": "PCI DSS v4 Req.11.3.2", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 22,
    },
    {
        "qid": "pci-pentest-01", "section": "Req 11 — Test Security of Systems & Networks",
        "question": "Has an annual penetration test been conducted covering CDE network and application layers by a qualified tester using an industry-accepted methodology?",
        "guidance": "Req 11.4. Evidence: pentest scope, methodology (OWASP/PTES/NIST), findings report, remediation evidence.",
        "control_ref": "PCI DSS v4 Req.11.4", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 23,
    },
    {
        "qid": "pci-fim-01", "section": "Req 11 — Test Security of Systems & Networks",
        "question": "Is File Integrity Monitoring (FIM) deployed on CDE systems to alert on unauthorised modification of critical files and configurations?",
        "guidance": "Req 11.5. Evidence: FIM tool deployment, alert configuration, critical file baseline, alert response procedure.",
        "control_ref": "PCI DSS v4 Req.11.5", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 24,
    },
    # Req 12 — Security Policy
    {
        "qid": "pci-pol-01", "section": "Req 12 — Support Information Security with Policies",
        "question": "Is a comprehensive IS policy in place, reviewed at least annually and after significant changes, communicated to and acknowledged by all personnel?",
        "guidance": "Req 12.1. Evidence: IS policy with review date, all-staff acknowledgement records.",
        "control_ref": "PCI DSS v4 Req.12.1", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 25,
    },
    {
        "qid": "pci-pol-02", "section": "Req 12 — Support Information Security with Policies",
        "question": "Is a formal security awareness programme in place covering phishing, social engineering, and PCI DSS responsibilities, with annual completion tracked?",
        "guidance": "Req 12.6. Evidence: training content, completion records (>90%), phishing simulation results.",
        "control_ref": "PCI DSS v4 Req.12.6", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 26,
    },
    {
        "qid": "pci-pol-03", "section": "Req 12 — Support Information Security with Policies",
        "question": "Is an IRP in place that specifically addresses cardholder data breaches, with roles defined, card brand/acquirer contacts listed, and plan tested annually?",
        "guidance": "Req 12.10. Evidence: PCI-specific IRP, contact list, annual test evidence.",
        "control_ref": "PCI DSS v4 Req.12.10", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 27,
    },
    {
        "qid": "pci-pol-04", "section": "Req 12 — Support Information Security with Policies",
        "question": "Is a vendor/service provider risk management programme in place with annual PCI compliance attestation requirements and documented responsibilities?",
        "guidance": "Req 12.8. Evidence: service provider list, due diligence process, annual PCI compliance confirmation.",
        "control_ref": "PCI DSS v4 Req.12.8", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 28,
    },
    {
        "qid": "pci-pol-05", "section": "Req 12 — Support Information Security with Policies",
        "question": "Is a formal cryptographic key management policy in place covering key generation, distribution, storage, retirement, and destruction for all keys protecting cardholder data?",
        "guidance": "Req 3.7. Evidence: key management policy, KMS configuration, key rotation log, split-knowledge procedures.",
        "control_ref": "PCI DSS v4 Req.3.7", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 29,
    },
    {
        "qid": "pci-risk-01", "section": "Req 12 — Support Information Security with Policies",
        "question": "Is a formal risk assessment process conducted at least annually and after significant environmental changes, with results driving control selection and resource allocation?",
        "guidance": "Req 12.3. Evidence: annual risk assessment report, risk register, risk-to-control mapping.",
        "control_ref": "PCI DSS v4 Req.12.3", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 30,
    },
]

# ── GDPR (EU General Data Protection Regulation) ─────────────────────────────
# 30 questions covering key obligations across the GDPR's 99 articles.
# Sections map directly to the chapter/article structure so gap reports
# pinpoint which legal obligation is exposed.
GDPR = [
    # ── Art.5 — Principles of Processing ─────────────────────────────────────
    {
        "qid": "gdpr-prin-01", "section": "Art.5 — Principles of Processing",
        "question": "Has the organisation documented the legal basis for every category of personal data it processes, ensuring processing is lawful, fair, and transparent to data subjects?",
        "guidance": "Art.5(1)(a) & Art.6. Evidence: data inventory / RoPA with legal basis column, privacy notice, consent records.",
        "control_ref": "GDPR Art.5(1)(a) / Art.6", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 1,
    },
    {
        "qid": "gdpr-prin-02", "section": "Art.5 — Principles of Processing",
        "question": "Does the organisation apply data minimisation, purpose limitation, and storage limitation — collecting only what is necessary, using it only for stated purposes, and deleting it when no longer needed?",
        "guidance": "Art.5(1)(b)(c)(e). Evidence: data retention schedule, automated deletion processes, privacy impact assessments showing minimisation.",
        "control_ref": "GDPR Art.5(1)(b)(c)(e)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 2,
    },
    {
        "qid": "gdpr-prin-03", "section": "Art.5 — Principles of Processing",
        "question": "Are appropriate technical and organisational measures in place to ensure accuracy and integrity/confidentiality of personal data, and can the organisation demonstrate accountability for compliance (Art.5(2))?",
        "guidance": "Art.5(1)(d)(f) & Art.5(2). Evidence: data quality controls, encryption/access controls, compliance programme documentation.",
        "control_ref": "GDPR Art.5(1)(d)(f) / Art.5(2)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 3,
    },
    # ── Art.6/7 — Lawful Basis & Consent ─────────────────────────────────────
    {
        "qid": "gdpr-consent-01", "section": "Art.6/7 — Lawful Basis & Consent",
        "question": "Where consent is the legal basis for processing, is it obtained freely, specifically, informedly, and unambiguously (opt-in), with withdrawal as easy as giving it and full records maintained?",
        "guidance": "Art.7. Evidence: consent management platform records, opt-in UI screenshots, withdrawal mechanism, consent audit log.",
        "control_ref": "GDPR Art.7", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 4,
    },
    {
        "qid": "gdpr-consent-02", "section": "Art.6/7 — Lawful Basis & Consent",
        "question": "Are special-category data (Art.9) and criminal-offence data (Art.10) only processed under an explicit exception, with a separate documented justification for each processing activity?",
        "guidance": "Art.9-10. Evidence: RoPA with special-category flags, legal opinion or DPA guidance, explicit consent records or statutory basis citations.",
        "control_ref": "GDPR Art.9 / Art.10", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 5,
    },
    # ── Art.12-23 — Data Subject Rights ──────────────────────────────────────
    {
        "qid": "gdpr-dsr-01", "section": "Art.12-23 — Data Subject Rights",
        "question": "Are privacy notices provided to data subjects at the time of collection, covering all required Art.13/14 information in a concise, intelligible, and easily accessible format?",
        "guidance": "Art.13-14. Evidence: published privacy policy, layered notice design, version-controlled notice history.",
        "control_ref": "GDPR Art.13 / Art.14", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 6,
    },
    {
        "qid": "gdpr-dsr-02", "section": "Art.12-23 — Data Subject Rights",
        "question": "Does the organisation have a documented process to identify, validate, and respond to data subject access requests (SARs) within one calendar month, with a tracker and escalation path?",
        "guidance": "Art.15 & Art.12(3). Evidence: SAR procedure, ticketing system records, response-time SLA evidence.",
        "control_ref": "GDPR Art.15 / Art.12(3)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 7,
    },
    {
        "qid": "gdpr-dsr-03", "section": "Art.12-23 — Data Subject Rights",
        "question": "Are erasure (Art.17), rectification (Art.16), restriction (Art.18), portability (Art.20), and objection (Art.21) rights operationalised with defined workflows and tested regularly?",
        "guidance": "Art.16-21. Evidence: rights fulfilment procedure, system capability to export/delete data, test exercise records.",
        "control_ref": "GDPR Art.16-21", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 8,
    },
    {
        "qid": "gdpr-dsr-04", "section": "Art.12-23 — Data Subject Rights",
        "question": "Where automated decision-making or profiling with significant effects is used (Art.22), is a human review mechanism available and disclosed to data subjects?",
        "guidance": "Art.22. Evidence: profiling register, human-review SLA, disclosure in privacy notice.",
        "control_ref": "GDPR Art.22", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 9,
    },
    # ── Art.25 — Privacy by Design & Default ─────────────────────────────────
    {
        "qid": "gdpr-pbd-01", "section": "Art.25 — Privacy by Design & Default",
        "question": "Is privacy by design and default embedded in product/system development — including pseudonymisation, encryption, access minimisation, and retention limits built into architecture from the outset?",
        "guidance": "Art.25(1). Evidence: SDLC privacy gates, design review checklists, security architecture diagrams showing PbD controls.",
        "control_ref": "GDPR Art.25(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 10,
    },
    {
        "qid": "gdpr-pbd-02", "section": "Art.25 — Privacy by Design & Default",
        "question": "Are only personal data necessary for each specific purpose processed by default (data minimisation by design), with no opt-in required to achieve the minimal disclosure level?",
        "guidance": "Art.25(2). Evidence: default settings review, UX screenshots, data flow diagrams showing minimal fields collected.",
        "control_ref": "GDPR Art.25(2)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 11,
    },
    # ── Art.28 — Processors & Contracts ──────────────────────────────────────
    {
        "qid": "gdpr-proc-01", "section": "Art.28 — Processors & Data Processing Agreements",
        "question": "Is a written Data Processing Agreement (DPA) in place with every processor that handles personal data on behalf of the organisation, covering all Art.28(3) mandatory clauses?",
        "guidance": "Art.28(3). Evidence: signed DPA register, template DPA, supplier audit results.",
        "control_ref": "GDPR Art.28(3)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 12,
    },
    {
        "qid": "gdpr-proc-02", "section": "Art.28 — Processors & Data Processing Agreements",
        "question": "Does the organisation maintain an up-to-date register of all processors and sub-processors, and does it conduct or review periodic audits or certifications of key processors?",
        "guidance": "Art.28(2)(3)(h). Evidence: processor register, sub-processor notification log, audit reports or ISO 27001/SOC 2 certs.",
        "control_ref": "GDPR Art.28(2)(3)(h)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 13,
    },
    # ── Art.30 — Records of Processing Activities ─────────────────────────────
    {
        "qid": "gdpr-ropa-01", "section": "Art.30 — Records of Processing Activities (RoPA)",
        "question": "Does the organisation maintain a complete and current Record of Processing Activities (RoPA) covering all required Art.30 fields (controller/processor details, purposes, categories, transfers, retention, security)?",
        "guidance": "Art.30(1)(2). Evidence: RoPA document, last-reviewed date, process for updating on new processing activities.",
        "control_ref": "GDPR Art.30", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 14,
    },
    {
        "qid": "gdpr-ropa-02", "section": "Art.30 — Records of Processing Activities (RoPA)",
        "question": "Is the RoPA reviewed at least annually and updated within a defined SLA whenever a new processing activity is introduced or an existing one changes materially?",
        "guidance": "Art.30 & Art.5(2) accountability. Evidence: RoPA change log, annual review sign-off, change management procedure.",
        "control_ref": "GDPR Art.30 / Art.5(2)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 15,
    },
    # ── Art.32 — Security of Processing ──────────────────────────────────────
    {
        "qid": "gdpr-sec-01", "section": "Art.32 — Security of Processing",
        "question": "Are personal data encrypted at rest and in transit using appropriate algorithms, with key management procedures documented and tested?",
        "guidance": "Art.32(1)(a). Evidence: encryption standards policy, TLS configuration scan, KMS documentation, penetration test report.",
        "control_ref": "GDPR Art.32(1)(a)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 16,
    },
    {
        "qid": "gdpr-sec-02", "section": "Art.32 — Security of Processing",
        "question": "Are access controls (RBAC/least-privilege), MFA, and privileged access management implemented and reviewed for all systems processing personal data?",
        "guidance": "Art.32(1)(b). Evidence: IAM policy, MFA enforcement evidence, quarterly access review records.",
        "control_ref": "GDPR Art.32(1)(b)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 17,
    },
    {
        "qid": "gdpr-sec-03", "section": "Art.32 — Security of Processing",
        "question": "Is pseudonymisation applied where feasible to reduce the risk to data subjects, and are personal data separated from identifying attributes in analytics and test environments?",
        "guidance": "Art.32(1)(a) & Recital 78. Evidence: pseudonymisation design docs, test data masking evidence, data flow diagrams.",
        "control_ref": "GDPR Art.32(1)(a) / Recital 78", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 18,
    },
    {
        "qid": "gdpr-sec-04", "section": "Art.32 — Security of Processing",
        "question": "Is there a tested process to restore availability and access to personal data in a timely manner after a physical or technical incident (resilience and recovery capability)?",
        "guidance": "Art.32(1)(c)(d). Evidence: BCP/DR policy, last recovery test date and RTO/RPO achieved, backup audit.",
        "control_ref": "GDPR Art.32(1)(c)(d)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 19,
    },
    # ── Art.33-34 — Breach Notification ──────────────────────────────────────
    {
        "qid": "gdpr-breach-01", "section": "Art.33-34 — Breach Notification",
        "question": "Does the organisation have a documented personal data breach response procedure that ensures notification to the supervisory authority within 72 hours of becoming aware, with a defined breach register?",
        "guidance": "Art.33(1)(2). Evidence: breach response runbook, breach register, DPA notification template.",
        "control_ref": "GDPR Art.33", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 20,
    },
    {
        "qid": "gdpr-breach-02", "section": "Art.33-34 — Breach Notification",
        "question": "Is there a clear decision process to assess whether a breach is likely to result in a risk (notifiable) or high risk (also requires data-subject communication) to data subjects' rights and freedoms?",
        "guidance": "Art.33-34 & EDPB Breach Notification Guidelines. Evidence: breach risk assessment template, severity classification matrix.",
        "control_ref": "GDPR Art.33-34", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 21,
    },
    {
        "qid": "gdpr-breach-03", "section": "Art.33-34 — Breach Notification",
        "question": "Have breach response procedures been tested (tabletop or simulated exercise) within the last 12 months, and are employees trained to recognise and escalate potential breaches promptly?",
        "guidance": "Art.32 & Art.5(2). Evidence: breach simulation exercise report, training records, escalation procedure.",
        "control_ref": "GDPR Art.32 / Art.5(2)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 22,
    },
    # ── Art.35 — Data Protection Impact Assessment ────────────────────────────
    {
        "qid": "gdpr-dpia-01", "section": "Art.35 — Data Protection Impact Assessment (DPIA)",
        "question": "Is a DPIA conducted prior to processing that is likely to result in high risk (e.g. large-scale profiling, systematic monitoring, sensitive data processing), and are results documented with risk mitigations?",
        "guidance": "Art.35(1)(3). Evidence: DPIA register, completed DPIA reports, DPO consultation records.",
        "control_ref": "GDPR Art.35", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 23,
    },
    # ── Art.37-39 — Data Protection Officer ──────────────────────────────────
    {
        "qid": "gdpr-dpo-01", "section": "Art.37-39 — Data Protection Officer (DPO)",
        "question": "Has the organisation determined whether a DPO is required (Art.37), and if so, has a qualified DPO been designated, registered with the supervisory authority, and given sufficient resources and independence?",
        "guidance": "Art.37-39. Evidence: DPO appointment letter, DPA registration, DPO resource allocation, independence statement.",
        "control_ref": "GDPR Art.37-39", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 24,
    },
    {
        "qid": "gdpr-dpo-02", "section": "Art.37-39 — Data Protection Officer (DPO)",
        "question": "Is the DPO (or privacy function) involved in all material decisions involving personal data, and is there a documented process for data subjects to contact the DPO directly?",
        "guidance": "Art.38-39. Evidence: DPO engagement log, RACI matrix showing DPO in privacy decisions, contact details published in privacy notice.",
        "control_ref": "GDPR Art.38-39", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 25,
    },
    # ── Art.44-49 — International Transfers ──────────────────────────────────
    {
        "qid": "gdpr-xfer-01", "section": "Art.44-49 — International Data Transfers",
        "question": "Are all transfers of personal data to third countries documented, and is each transfer covered by an adequate transfer mechanism (adequacy decision, SCCs, BCRs, or Art.49 derogation)?",
        "guidance": "Art.44-46. Evidence: transfer impact assessment, SCCs signed by both parties, BCR approval, adequacy decision citation per destination.",
        "control_ref": "GDPR Art.44-46", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 26,
    },
    {
        "qid": "gdpr-xfer-02", "section": "Art.44-49 — International Data Transfers",
        "question": "Has a Transfer Impact Assessment (TIA) been conducted for transfers to countries without adequacy decisions to assess whether the legal framework of the destination undermines the SCCs' effectiveness?",
        "guidance": "CJEU Schrems II & EDPB Recommendations 01/2020. Evidence: TIA register, supplementary measures documentation, legal assessment per destination country.",
        "control_ref": "GDPR Art.46 / EDPB Rec. 01/2020", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 27,
    },
    # ── Art.5(2) / Art.83 — Accountability & Governance ─────────────────────
    {
        "qid": "gdpr-gov-01", "section": "Art.5(2) / Art.83 — Accountability & Governance",
        "question": "Is there a GDPR compliance programme with named ownership, executive sponsorship, documented policies and procedures, and a regular review cycle (at least annually)?",
        "guidance": "Art.5(2) & Art.24. Evidence: GDPR programme charter, policy register, board-level privacy report.",
        "control_ref": "GDPR Art.5(2) / Art.24", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 28,
    },
    {
        "qid": "gdpr-gov-02", "section": "Art.5(2) / Art.83 — Accountability & Governance",
        "question": "Does the organisation conduct regular GDPR awareness training for all staff handling personal data, with completion tracked and records maintained for at least 3 years?",
        "guidance": "Art.39(1)(b) & Art.5(2). Evidence: training platform completion reports, training content version history.",
        "control_ref": "GDPR Art.39(1)(b)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 29,
    },
    {
        "qid": "gdpr-gov-03", "section": "Art.5(2) / Art.83 — Accountability & Governance",
        "question": "Is there a third-party privacy audit or assessment (internal or external) conducted at least annually, with findings tracked to remediation and reported to leadership?",
        "guidance": "Art.5(2) & Art.32(1)(d). Evidence: last audit report date, finding-remediation tracker, board or DPO update.",
        "control_ref": "GDPR Art.5(2) / Art.32(1)(d)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 30,
    },
]

# ── Master registry ───────────────────────────────────────────────────────────
# ── EU AI Act (Regulation (EU) 2024/1689) ────────────────────────────────────
# 30 questions across 9 sections covering all key obligations for providers and
# deployers of high-risk AI systems, GPAI models, and general governance.
EU_AI_ACT = [

    # ── Section 1: Governance & Classification (Arts. 1-6, 8) ─────────────────
    {
        "qid": "euaia-gov-01", "section": "Governance — AI Inventory & Classification",
        "question": "Has the organisation produced and maintained a comprehensive inventory of all AI systems in use, with each system classified by risk category (prohibited, high-risk, limited-risk, minimal-risk) per EU AI Act Annexes I and III?",
        "guidance": "Art. 6 / Annex III. Evidence: AI system register with risk classification per Annex III, classification methodology, review cycle.",
        "control_ref": "EU AI Act Art.6 / Annex III", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 1,
    },
    {
        "qid": "euaia-gov-02", "section": "Governance — Prohibited Practices",
        "question": "Has the organisation assessed all AI systems against the list of prohibited AI practices (Art. 5) and confirmed that none are deployed — including social scoring by public authorities, real-time biometric identification in public spaces without derogation, and subliminal manipulation?",
        "guidance": "Art. 5. Evidence: prohibited-practices assessment report, legal sign-off, documented exclusions with rationale.",
        "control_ref": "EU AI Act Art.5", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 2,
    },
    {
        "qid": "euaia-gov-03", "section": "Governance — Roles & Accountability",
        "question": "Have formal roles been assigned for AI governance, including a designated AI compliance officer or equivalent, and are provider vs. deployer obligations clearly delineated for each AI system in scope?",
        "guidance": "Art. 16, 26. Evidence: RACI matrix for AI governance, role descriptions, appointment documentation.",
        "control_ref": "EU AI Act Art.16 / Art.26", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 3,
    },
    {
        "qid": "euaia-gov-04", "section": "Governance — Executive Oversight",
        "question": "Is there a board-level or executive oversight mechanism for AI governance, with regular reporting on AI risk posture, compliance status, and serious incidents?",
        "guidance": "Art. 9 (risk management system). Evidence: board/AI governance committee charter, meeting minutes, periodic AI risk reporting.",
        "control_ref": "EU AI Act Art.9", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 4,
    },

    # ── Section 2: Risk Management System (Art. 9) ──────────────────────────
    {
        "qid": "euaia-risk-01", "section": "Risk Management — Lifecycle Integration",
        "question": "Is a documented AI risk management system in place that covers the entire lifecycle of each high-risk AI system (design, development, deployment, decommissioning) and is continuously updated?",
        "guidance": "Art. 9(1). Evidence: AI risk management framework document with lifecycle coverage evidence.",
        "control_ref": "EU AI Act Art.9(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 5,
    },
    {
        "qid": "euaia-risk-02", "section": "Risk Management — Residual Risk & Testing",
        "question": "Are residual risks for each high-risk AI system evaluated against an acceptable risk threshold, and is testing performed in realistic operational conditions before deployment and throughout the system's lifetime?",
        "guidance": "Art. 9(2)(d) / Art. 9(7). Evidence: residual risk assessment reports, pre-deployment test records, acceptable risk criteria.",
        "control_ref": "EU AI Act Art.9(2)(d) / Art.9(7)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 6,
    },
    {
        "qid": "euaia-risk-03", "section": "Risk Management — Bias & Discrimination",
        "question": "Has a bias risk assessment been conducted for each high-risk AI system, identifying potential discriminatory outcomes against protected groups (sex, race, religion, disability, etc.), with documented mitigation measures?",
        "guidance": "Art. 9(7) / Art. 10(2)(f). Evidence: bias assessment reports, protected-attribute analysis, mitigation implementation evidence.",
        "control_ref": "EU AI Act Art.9(7) / Art.10(2)(f)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 7,
    },

    # ── Section 3: Data Governance (Art. 10) ────────────────────────────────
    {
        "qid": "euaia-data-01", "section": "Data Governance — Training Data Quality",
        "question": "Are training, validation, and testing datasets for high-risk AI systems subject to documented data governance practices, including relevance, representativeness, freedom from errors, and completeness criteria?",
        "guidance": "Art. 10(2). Evidence: data governance policy for AI, dataset documentation with quality metrics.",
        "control_ref": "EU AI Act Art.10(2)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 8,
    },
    {
        "qid": "euaia-data-02", "section": "Data Governance — Special Categories",
        "question": "Where high-risk AI training datasets include special categories of personal data (health, biometric, racial/ethnic origin), are appropriate safeguards applied and processing justified under GDPR Art. 9 or equivalent national law?",
        "guidance": "Art. 10(5). Evidence: DPIA, data processing records, GDPR Art. 9 legal basis, data minimisation evidence.",
        "control_ref": "EU AI Act Art.10(5)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 9,
    },
    {
        "qid": "euaia-data-03", "section": "Data Governance — Lineage & Provenance",
        "question": "Is data lineage documented for AI training datasets, covering origin, collection method, processing steps, and any third-party sources with applicable licences?",
        "guidance": "Art. 10(2)(b) / Art. 53(1)(c). Evidence: data lineage records, provenance documentation, third-party data agreements.",
        "control_ref": "EU AI Act Art.10(2)(b)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 10,
    },

    # ── Section 4: Technical Documentation & Record-Keeping (Arts. 11-12) ────
    {
        "qid": "euaia-doc-01", "section": "Technical Documentation — Completeness (Annex IV)",
        "question": "Is technical documentation prepared and maintained for each high-risk AI system covering all Annex IV elements: general description, intended purpose, design logic, training data, validation results, performance metrics, known limitations, and cybersecurity measures?",
        "guidance": "Art. 11 / Annex IV. Evidence: technical documentation per Annex IV checklist, version control records.",
        "control_ref": "EU AI Act Art.11 / Annex IV", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 11,
    },
    {
        "qid": "euaia-doc-02", "section": "Technical Documentation — Automated Logging",
        "question": "Are automated logging capabilities enabled for all high-risk AI systems, capturing sufficient system activity to identify risks and assess conformity throughout the system's operational lifetime?",
        "guidance": "Art. 12(1). Evidence: logging configuration documentation, log retention policy, sample log outputs.",
        "control_ref": "EU AI Act Art.12(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 12,
    },
    {
        "qid": "euaia-doc-03", "section": "Technical Documentation — Log Retention & Integrity",
        "question": "Are AI system log records retained for a minimum of 6 months (or longer per sector regulation), protected against tampering, and accessible to competent authorities on request?",
        "guidance": "Art. 12(2). Evidence: log retention policy, immutability controls, access procedures for market surveillance authorities.",
        "control_ref": "EU AI Act Art.12(2)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 13,
    },

    # ── Section 5: Transparency & Human Oversight (Arts. 13-14, 50) ──────────
    {
        "qid": "euaia-trans-01", "section": "Transparency — Instructions for Use",
        "question": "Are instructions for use provided to deployers of each high-risk AI system covering: intended purpose, performance characteristics, known limitations, human oversight measures, maintenance requirements, and expected system lifetime?",
        "guidance": "Art. 13(1) / Art. 13(3). Evidence: instructions-for-use document, deployer onboarding and acknowledgement records.",
        "control_ref": "EU AI Act Art.13(1) / Art.13(3)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 14,
    },
    {
        "qid": "euaia-trans-02", "section": "Transparency — AI Interaction & Synthetic Content Disclosure",
        "question": "Where AI systems interact with natural persons (chatbots, virtual assistants) or generate synthetic content (deepfakes, AI-generated text/images), are disclosure mechanisms in place informing users they are interacting with an AI or that content is AI-generated?",
        "guidance": "Art. 50. Evidence: chatbot disclosure UI, watermarking/metadata for synthetic content, user-facing disclosure records.",
        "control_ref": "EU AI Act Art.50", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 15,
    },
    {
        "qid": "euaia-oversight-01", "section": "Human Oversight — Design & Capability",
        "question": "Are human oversight measures built into each high-risk AI system, enabling designated natural persons to understand capabilities and limitations, monitor operation in real time, intervene or override outputs, and stop the system safely?",
        "guidance": "Art. 14(1)–(3). Evidence: oversight interface documentation, override mechanism test records, stop/pause capability.",
        "control_ref": "EU AI Act Art.14(1)–(3)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 16,
    },
    {
        "qid": "euaia-oversight-02", "section": "Human Oversight — Competence & Automation Bias",
        "question": "Are human overseers of high-risk AI systems assigned with appropriate authority, given adequate training on system capabilities and limitations, and supported with tools to minimise automation bias in decision-making?",
        "guidance": "Art. 14(4). Evidence: oversight training programme, competence assessments, training completion records, automation-bias guidance.",
        "control_ref": "EU AI Act Art.14(4)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 17,
    },

    # ── Section 6: Accuracy, Robustness & Cybersecurity (Art. 15) ─────────────
    {
        "qid": "euaia-sec-01", "section": "Accuracy, Robustness & Cybersecurity — Performance Benchmarking",
        "question": "Are accuracy, robustness, and cybersecurity metrics defined for each high-risk AI system, benchmarked against declared performance in technical documentation, and monitored continuously throughout the operational lifecycle?",
        "guidance": "Art. 15(1). Evidence: performance benchmarks, continuous monitoring dashboards, model drift detection alerts.",
        "control_ref": "EU AI Act Art.15(1)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 18,
    },
    {
        "qid": "euaia-sec-02", "section": "Accuracy, Robustness & Cybersecurity — Adversarial Resilience",
        "question": "Have AI-specific adversarial threats been assessed for each high-risk AI system — including data poisoning, model inversion, model evasion, and prompt injection — with technical controls implemented to maintain robustness under attack?",
        "guidance": "Art. 15(3)/(4). Evidence: adversarial testing reports, AI red-team exercise records, model robustness metrics.",
        "control_ref": "EU AI Act Art.15(3)/(4)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 19,
    },
    {
        "qid": "euaia-sec-03", "section": "Accuracy, Robustness & Cybersecurity — Secure SDLC",
        "question": "Are cybersecurity controls applied to AI system infrastructure and model artefacts throughout the development and deployment lifecycle, including access control, encryption, vulnerability management, and secure SDLC practices?",
        "guidance": "Art. 15(5). Evidence: AI security architecture, secure SDLC artefacts, penetration test reports for AI systems.",
        "control_ref": "EU AI Act Art.15(5)", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 20,
    },

    # ── Section 7: Provider & Deployer Obligations (Arts. 16-27, 43, 47, 49) ─
    {
        "qid": "euaia-qms-01", "section": "Provider Obligations — Quality Management System",
        "question": "Is a quality management system (QMS) in place covering AI system development, verification, validation, deployment, and post-market monitoring, with documented procedures and records retained for at least 10 years after last market placement?",
        "guidance": "Art. 17. Evidence: QMS documentation, 10-year retention policy, version-controlled procedures.",
        "control_ref": "EU AI Act Art.17", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 21,
    },
    {
        "qid": "euaia-qms-02", "section": "Provider Obligations — Conformity Assessment",
        "question": "Has a conformity assessment been completed for each high-risk AI system before market placement, using the appropriate procedure (internal assessment per Annex VI, or third-party notified body per Annex VII where mandated)?",
        "guidance": "Art. 43. Evidence: conformity assessment report, notified body certificate (where required), Annex VI/VII checklist.",
        "control_ref": "EU AI Act Art.43", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 22,
    },
    {
        "qid": "euaia-qms-03", "section": "Provider Obligations — EU Declaration of Conformity & Registration",
        "question": "Has an EU declaration of conformity been issued and CE marking affixed for each high-risk AI system placed on the EU market, and has the system been registered in the EU AI database (Art. 71) where required?",
        "guidance": "Art. 47 / Art. 49 / Art. 71. Evidence: EU DoC documents, CE marking records, EU database registration confirmation.",
        "control_ref": "EU AI Act Art.47 / Art.49 / Art.71", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 23,
    },
    {
        "qid": "euaia-depl-01", "section": "Deployer Obligations — Fundamental Rights Impact Assessment",
        "question": "Where the organisation deploys high-risk AI systems listed in Annex III as a public body or regulated private entity, has a Fundamental Rights Impact Assessment (FRIA) been conducted and documented prior to deployment?",
        "guidance": "Art. 27. Evidence: FRIA report, stakeholder consultation records, identified risks and mitigation measures.",
        "control_ref": "EU AI Act Art.27", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 24,
    },

    # ── Section 8: General-Purpose AI (GPAI) Models (Arts. 51-55) ─────────────
    {
        "qid": "euaia-gpai-01", "section": "GPAI Models — Transparency & Copyright",
        "question": "If the organisation provides a general-purpose AI (GPAI) model, has it prepared and maintained technical documentation, a copyright compliance policy (Art. 53(1)(c)), and published sufficient information to enable downstream providers to meet their obligations?",
        "guidance": "Art. 53(1). Evidence: GPAI technical documentation, copyright policy, model card or equivalent transparency publication.",
        "control_ref": "EU AI Act Art.53(1)", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 25,
    },
    {
        "qid": "euaia-gpai-02", "section": "GPAI Models — Systemic Risk Assessment",
        "question": "If the organisation provides a GPAI model at or above the systemic risk threshold (>10²⁵ FLOPs or Commission-designated), have systemic risk assessments, adversarial testing (red-teaming), incident reporting procedures, and enhanced cybersecurity measures been implemented per Art. 55?",
        "guidance": "Art. 51 / Art. 55. Evidence: systemic risk assessment report, red-team test results, GPAI incident log, cybersecurity measures for the model.",
        "control_ref": "EU AI Act Art.51 / Art.55", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 26,
    },

    # ── Section 9: Post-Market Monitoring & Incident Reporting (Arts. 72-75) ──
    {
        "qid": "euaia-pmm-01", "section": "Post-Market Monitoring — Plan & Execution",
        "question": "Is a post-market monitoring plan in place for all high-risk AI systems that proactively collects and reviews data on system performance, adverse events, and near-misses throughout the system's operational lifetime?",
        "guidance": "Art. 72. Evidence: post-market monitoring plan, data collection procedures, review cycle documentation.",
        "control_ref": "EU AI Act Art.72", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 27,
    },
    {
        "qid": "euaia-pmm-02", "section": "Post-Market Monitoring — Serious Incident Reporting",
        "question": "Is there a documented procedure for reporting serious incidents (as defined in Art. 3(49)) involving high-risk AI systems to the relevant national market surveillance authority within required timeframes, with a tested escalation path?",
        "guidance": "Art. 73. Evidence: serious incident reporting procedure, incident classification criteria, authority contact list, drill/exercise records.",
        "control_ref": "EU AI Act Art.73", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 28,
    },
    {
        "qid": "euaia-pmm-03", "section": "Post-Market Monitoring — Corrective Actions",
        "question": "When non-conformities, serious incidents, or performance degradations are identified in high-risk AI systems, are corrective actions implemented without undue delay, documented, and reported to competent authorities where required?",
        "guidance": "Art. 20 / Art. 21. Evidence: corrective action register, root cause analysis reports, regulatory notification records.",
        "control_ref": "EU AI Act Art.20 / Art.21", "weight": 3, "question_type": "yes_no", "options": [], "order_idx": 29,
    },
    {
        "qid": "euaia-pmm-04", "section": "Post-Market Monitoring — Complaints & Whistleblower Mechanism",
        "question": "Is there an accessible mechanism for staff, deployers, and affected persons to report concerns about AI system performance, ethical issues, or potential non-conformities, with whistleblower protections in place per Art. 85?",
        "guidance": "Art. 85 / Art. 86. Evidence: complaint/reporting mechanism documentation, whistleblower policy, accessibility evidence for affected persons.",
        "control_ref": "EU AI Act Art.85 / Art.86", "weight": 2, "question_type": "yes_no", "options": [], "order_idx": 30,
    },
]

ALL_QUESTIONNAIRES: dict[str, list[dict]] = {
    "nis2":       NIS2,
    "dora":       DORA,
    "iso27001":   ISO27001,
    "soc2":       SOC2,
    "nist_csf":   NIST_CSF,
    "pci_dss":    PCI_DSS,
    "gdpr":       GDPR,
    "eu_ai_act":  EU_AI_ACT,
}

FRAMEWORK_META: dict[str, dict] = {
    "nis2":      {"label": "NIS2 Directive",      "color": "#6378ff", "total": len(NIS2)},
    "dora":      {"label": "DORA",                "color": "#ffd166", "total": len(DORA)},
    "iso27001":  {"label": "ISO 27001:2022",      "color": "#00e5c0", "total": len(ISO27001)},
    "soc2":      {"label": "SOC 2",               "color": "#ff6b6b", "total": len(SOC2)},
    "nist_csf":  {"label": "NIST CSF 2.0",        "color": "#38bdf8", "total": len(NIST_CSF)},
    "pci_dss":   {"label": "PCI DSS v4.0",        "color": "#f97316", "total": len(PCI_DSS)},
    "gdpr":      {"label": "GDPR",                "color": "#8b5cf6", "total": len(GDPR)},
    "eu_ai_act": {"label": "EU AI Act",            "color": "#06b6d4", "total": len(EU_AI_ACT)},
}
