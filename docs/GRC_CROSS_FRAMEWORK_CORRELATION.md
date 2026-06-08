# GRC Cross-Framework Correlation — Inventory, Gap Analysis & Design

**Status:** Feature NOT yet implemented (as of v1.0.14)  
**Authored by:** g-cyra-mgr  
**Target agent:** g-cyra-comp (implementation) + g-cyra-360 (portal UI) + g-cyra-ai (CyMind multi-collection query)

---

## 1. Full Questionnaire Inventory (Current State)

All 8 frameworks are seeded from `backend/cy_comp/data/questionnaires.py` via `seed_templates(force=True)` at every startup. The master registry lives in `ALL_QUESTIONNAIRES` at line 1639.

### 1.1 Framework Summary Table

| Framework Key | Label | Questions | Sections | File Constant |
|---|---|---|---|---|
| `iso27001` | ISO 27001:2022 | 45 | 7 | `ISO27001` |
| `nis2` | NIS2 Directive | 28 | 10 | `NIS2` |
| `dora` | DORA | 28 | 12 | `DORA` |
| `soc2` | SOC 2 Type II | 28 | 12 | `SOC2` |
| `nist_csf` | NIST CSF 2.0 | 26 | 6 | `NIST_CSF` |
| `pci_dss` | PCI DSS v4.0 | 30 | 12 | `PCI_DSS` |
| `gdpr` | GDPR | 30 | 11 | `GDPR` |
| `eu_ai_act` | EU AI Act | 30 | 9 | `EU_AI_ACT` |
| **Total** | | **245** | | |

---

### 1.2 ISO 27001:2022 — 45 Questions

| QID | Section | Control Ref | Type | Weight |
|---|---|---|---|---|
| iso-isms-01 | ISMS — Context & Leadership | Cl.4.3 | yes_no | 3 |
| iso-isms-02 | ISMS — Context & Leadership | Cl.5.1–5.3 | yes_no | 3 |
| iso-isms-03 | ISMS — Context & Leadership | Cl.6.2 | yes_no | 2 |
| iso-isms-04 | ISMS — Risk Assessment & Treatment | Cl.6.1.2 | yes_no | 3 |
| iso-isms-05 | ISMS — Risk Assessment & Treatment | Cl.6.1.3(d) | yes_no | 3 |
| iso-isms-06 | ISMS — Support & Operation | Cl.7.2 | yes_no | 2 |
| iso-isms-07 | ISMS — Performance & Improvement | Cl.9.2 | yes_no | 3 |
| iso-isms-08 | ISMS — Performance & Improvement | Cl.9.3 | yes_no | 2 |
| iso-org-01..14 | Annex A — Organisational Controls | A.5.1–A.5.37 | yes_no | 2–3 |
| iso-ppl-01..05 | Annex A — People Controls | A.6.1–A.6.8 | yes_no | 2–3 |
| iso-phy-01..05 | Annex A — Physical Controls | A.7.1–A.7.14 | yes_no | 2–3 |
| iso-tech-01..13 | Annex A — Technological Controls | A.8.1–A.8.34 | yes_no / score_1_5 | 2–3 |

---

### 1.3 NIS2 Directive — 28 Questions

| QID | Section | Control Ref | Type | Weight |
|---|---|---|---|---|
| nis2-gov-01..04 | Art.20 — Governance & Accountability | Art.20(1)(2) | yes_no / score_1_5 | 2–3 |
| nis2-risk-01..02 | Art.21(2)(a) — Risk Analysis & IS Policies | Art.21(1) | yes_no | 2–3 |
| nis2-ir-01..02 | Art.21(2)(b) — Incident Handling | Art.21(2)(b) | yes_no | 2–3 |
| nis2-bcp-01..02 | Art.21(2)(c) — Business Continuity & Backup | Art.21(2)(c) | yes_no | 3 |
| nis2-sc-01..03 | Art.21(2)(d) — Supply Chain Security | Art.21(2)(d) | yes_no / score_1_5 | 2–3 |
| nis2-vuln-01..02 | Art.21(2)(e) — Vulnerability Handling | Art.21(2)(e) | yes_no | 2–3 |
| nis2-audit-01 | Art.21(2)(f) — Effectiveness Assessment | Art.21(2)(f) | yes_no | 3 |
| nis2-train-01..02 | Art.21(2)(g) — Training & Awareness | Art.21(2)(g) | yes_no | 2 |
| nis2-crypto-01 | Art.21(2)(h) — Cryptography & Encryption | Art.21(2)(h) | yes_no | 3 |
| nis2-iam-01..02 | Art.21(2)(i) — Access Control & Asset Management | Art.21(2)(i) | yes_no | 3 |
| nis2-mfa-01..02 | Art.21(2)(j) — MFA & Secure Communications | Art.21(2)(j) | yes_no / score_1_5 | 3 |
| nis2-report-01..02 | Art.23 — Incident Reporting | Art.23(1) | yes_no | 3 |
| nis2-mon-01..02 | Art.21 — Monitoring & Detection | Art.21(2)(b)(e) | yes_no | 2–3 |
| nis2-coord-01 | Art.21 — Coordinated Vulnerability Disclosure | Art.21(2)(e) | yes_no | 1 |

---

### 1.4 DORA — 28 Questions

| QID | Section | Control Ref | Type | Weight |
|---|---|---|---|---|
| dora-gov-01..02 | Art.5 — ICT Governance | Art.5(2)(4) | yes_no | 2–3 |
| dora-risk-01..03 | Art.6 — ICT Risk Management Framework | Art.6(1)(2)(c) | yes_no | 3 |
| dora-asset-01 | Art.8 — ICT Asset Management | Art.8(1) | yes_no | 3 |
| dora-protect-01 | Art.9 — ICT Protection | Art.9(1) | yes_no | 2 |
| dora-detect-01..02 | Art.10 — Detection & Monitoring | Art.10(1)(2) | score_1_5 / yes_no | 3 |
| dora-bcp-01..02 | Art.11–12 — BCP & Backup | Art.11(1) / Art.12(1) | yes_no / score_1_5 | 3 |
| dora-cti-01 | Art.13 — Threat Intelligence | Art.13(1) | yes_no | 2 |
| dora-ir-01..04 | Art.17–19 — Incident Management & Reporting | Art.17–19 | yes_no | 3 |
| dora-test-01..03 | Art.24–26 — Resilience Testing | Art.24(1)(6) / Art.26(1) | yes_no / multi_choice | 2–3 |
| dora-tpr-01..03 | Art.28–30 — Third-Party ICT Risk | Art.28(2)(8) / Art.30(1) | yes_no | 2–3 |
| dora-share-01 | Art.45 — Information Sharing | Art.45 | yes_no | 1 |
| dora-cfg-01 | Art.9 — ICT Protection | Art.9 | yes_no | 3 |
| dora-iam-01 | Art.9 — ICT Protection (MFA/PAM) | Art.9 | yes_no | 3 |
| dora-vuln-01 | Art.6 — ICT Risk (Vulnerability Mgmt) | Art.6(2) | yes_no | 3 |
| dora-audit-01 | Art.5 — ICT Governance (ICTRMF review) | Art.6(5) | yes_no | 2 |
| dora-log-01 | Art.10 — Detection (Log retention) | Art.10 | yes_no | 2 |

---

### 1.5 SOC 2 Type II — 28 Questions

| QID | Section | Control Ref | Type | Weight |
|---|---|---|---|---|
| soc2-cc1-01..03 | CC1 — Control Environment | CC1.1/CC1.3–CC1.5 | yes_no | 2–3 |
| soc2-cc2-01 | CC2 — Communication & Information | CC2.2/CC2.3 | yes_no | 2 |
| soc2-cc3-01..02 | CC3 — Risk Assessment | CC3.2–CC3.4 | yes_no | 2–3 |
| soc2-cc4-01 | CC4 — Monitoring Activities | CC4.1/CC4.2 | yes_no | 3 |
| soc2-cc5-01..02 | CC5 — Control Activities | CC5.1–CC5.3 | yes_no | 2–3 |
| soc2-cc6-01..05 | CC6 — Logical & Physical Access | CC6.1–CC6.8 | yes_no | 2–3 |
| soc2-cc7-01..02 | CC7 — System Operations | CC7.1–CC7.5 | yes_no | 3 |
| soc2-cc8-01..02 | CC8 — Change Management | CC8.1 | yes_no | 3 |
| soc2-cc9-01..02 | CC9 — Risk Mitigation | CC9.1/CC9.2 | yes_no | 2–3 |
| soc2-av-01..02 | A — Availability | A1.1/A1.2 | yes_no | 2–3 |
| soc2-cf-01 | C — Confidentiality | C1.1/C1.2 | yes_no | 3 |
| soc2-pi-01 | PI — Processing Integrity | PI1.1 | yes_no | 2 |
| soc2-prv-01..02 | P — Privacy | P1.0/P6.0/P8.0 | yes_no | 2 |
| soc2-vuln-01 | CC7 — System Operations (Vuln Mgmt) | CC7.1 | yes_no | 3 |
| soc2-pen-01 | CC4 — Monitoring (Pen Test) | CC4.1 | yes_no | 3 |

---

### 1.6 NIST CSF 2.0 — 26 Questions

| QID | Section | Control Ref | Type | Weight |
|---|---|---|---|---|
| nist-gv-01..05 | GV — Govern | GV.OC/GV.RM/GV.RR/GV.PO/GV.OV | yes_no | 2–3 |
| nist-id-01..05 | ID — Identify | ID.AM/ID.RA/ID.IM | yes_no | 2–3 |
| nist-pr-01..05 | PR — Protect | PR.AA/PR.DS/PR.AT/PR.PS/PR.IR | yes_no / score_1_5 | 2–3 |
| nist-de-01..03 | DE — Detect | DE.CM/DE.AE | yes_no | 2–3 |
| nist-rs-01..03 | RS — Respond | RS.MA/RS.CO/RS.AN | yes_no | 2–3 |
| nist-rc-01..04 | RC — Recover | RC.RP/RC.CO/RC.IM | yes_no | 2–3 |
| nist-sup-01 | GV — Supply Chain Risk | GV.SC | yes_no | 2 |

---

### 1.7 PCI DSS v4.0 — 30 Questions

| QID | Section | Control Ref | Type | Weight |
|---|---|---|---|---|
| pci-net-01..02 | Req 1 — Network Security Controls | Req.1.1–1.3 | yes_no | 3 |
| pci-cfg-01..02 | Req 2 — Secure Configurations | Req.2.2 | yes_no | 2–3 |
| pci-data-01..03 | Req 3 — Protect Stored Account Data | Req.3.1–3.5 | yes_no | 3 |
| pci-tls-01 | Req 4 — Protect in Transit | Req.4.2 | yes_no | 3 |
| pci-avm-01..02 | Req 5 — Protect Against Malware | Req.5.2–5.4 | yes_no | 2–3 |
| pci-sdlc-01..02 | Req 6 — Develop & Maintain Secure Systems | Req.6.3–6.4 | yes_no | 3 |
| pci-iam-01..04 | Req 7–8 — Access Control & Authentication | Req.7.1–8.3 | yes_no | 2–3 |
| pci-phy-01..03 | Req 9 — Physical Access | Req.9.1–9.5 | yes_no | 2–3 |
| pci-log-01..02 | Req 10 — Log and Monitor | Req.10.2–10.7 | yes_no | 3 |
| pci-scan-01 | Req 11 — Test Security | Req.11.3.2 | yes_no | 3 |
| pci-pentest-01 | Req 11 — Penetration Test | Req.11.4 | yes_no | 3 |
| pci-fim-01 | Req 11 — FIM | Req.11.5 | yes_no | 3 |
| pci-pol-01..05 | Req 12 — Policy | Req.12.1–12.10 | yes_no | 2–3 |
| pci-risk-01 | Req 12 — Risk Assessment | Req.12.3 | yes_no | 3 |

---

### 1.8 GDPR — 30 Questions

| QID | Section | Control Ref | Type | Weight |
|---|---|---|---|---|
| gdpr-prin-01..03 | Art.5 — Principles of Processing | Art.5(1)(2) | yes_no | 3 |
| gdpr-consent-01..02 | Art.6/7 — Lawful Basis & Consent | Art.7/9/10 | yes_no | 3 |
| gdpr-dsr-01..04 | Art.12-23 — Data Subject Rights | Art.12–22 | yes_no | 2 |
| gdpr-pbd-01..02 | Art.25 — Privacy by Design | Art.25(1)(2) | yes_no | 2–3 |
| gdpr-proc-01..02 | Art.28 — Processors | Art.28(2)(3) | yes_no | 2–3 |
| gdpr-ropa-01..02 | Art.30 — RoPA | Art.30 | yes_no | 2–3 |
| gdpr-sec-01..04 | Art.32 — Security of Processing | Art.32(1) | yes_no | 2–3 |
| gdpr-breach-01..03 | Art.33-34 — Breach Notification | Art.33–34 | yes_no | 2–3 |
| gdpr-dpia-01 | Art.35 — DPIA | Art.35 | yes_no | 3 |
| gdpr-dpo-01..02 | Art.37-39 — DPO | Art.37–39 | yes_no | 2–3 |
| gdpr-xfer-01..02 | Art.44-49 — International Transfers | Art.44–46 | yes_no | 3 |
| gdpr-gov-01..03 | Art.5(2)/83 — Accountability | Art.5(2)/Art.24 | yes_no | 2–3 |

---

### 1.9 EU AI Act — 30 Questions

| QID | Section | Control Ref | Type | Weight |
|---|---|---|---|---|
| euaia-gov-01..04 | Governance — AI Inventory, Prohibited Practices, Roles, Oversight | Art.6/5/16/9 | yes_no | 2–3 |
| euaia-risk-01..03 | Risk Management — Lifecycle, Residual Risk, Bias | Art.9(1)(2)(7) | yes_no | 3 |
| euaia-data-01..03 | Data Governance — Training Data Quality, Special Categories, Lineage | Art.10(2)(5) | yes_no | 2–3 |
| euaia-doc-01..03 | Technical Documentation & Logging | Art.11/12 | yes_no | 2–3 |
| euaia-trans-01..02 | Transparency — Instructions, AI Disclosure | Art.13/50 | yes_no | 2–3 |
| euaia-oversight-01..02 | Human Oversight — Design & Competence | Art.14(1)(4) | yes_no | 3 |
| euaia-sec-01..03 | Accuracy, Robustness & Cybersecurity | Art.15(1)(3)(5) | yes_no | 3 |
| euaia-qms-01..03 | Provider Obligations — QMS, Conformity, CE Marking | Art.17/43/47 | yes_no | 2–3 |
| euaia-depl-01 | Deployer Obligations — FRIA | Art.27 | yes_no | 2 |
| euaia-gpai-01..02 | GPAI Models | Art.53/51/55 | yes_no | 2 |
| euaia-pmm-01..04 | Post-Market Monitoring — Plan, Serious Incidents, Corrective Actions, Complaints | Art.72/73/20/85 | yes_no | 2–3 |

---

## 2. Cross-Framework Similarity Map

The following table maps equivalent or strongly overlapping questions across all 8 frameworks. This is the authoritative source for the correlation engine to be built.

**Theme: Governance & Board Accountability**

| Cluster ID | ISO 27001 | NIS2 | DORA | SOC 2 | NIST CSF | PCI DSS | GDPR | EU AI Act |
|---|---|---|---|---|---|---|---|---|
| GOV-01 | iso-isms-02 (Cl.5.1) | nis2-gov-01 (Art.20) | dora-gov-01 (Art.5.2) | soc2-cc1-02 (CC1.3) | nist-gv-01 (GV.OC-01) | pci-pol-01 (Req.12.1) | gdpr-gov-01 (Art.5.2) | euaia-gov-04 (Art.9) |
| GOV-02 | iso-isms-03 (KPIs) | nis2-gov-03 (score) | dora-audit-01 | soc2-cc4-01 | nist-gv-05 (GV.OV) | — | — | — |

**Theme: Risk Assessment**

| Cluster ID | ISO 27001 | NIS2 | DORA | SOC 2 | NIST CSF | PCI DSS | GDPR | EU AI Act |
|---|---|---|---|---|---|---|---|---|
| RISK-01 | iso-isms-04 (Cl.6.1.2) | nis2-risk-01 (Art.21.1) | dora-risk-02 (Art.6.2a) | soc2-cc3-01 (CC3.2) | nist-id-03 (ID.RA-01) | pci-risk-01 (Req.12.3) | — | euaia-risk-01 (Art.9.1) |
| RISK-02 | — | nis2-risk-02 (risk appetite) | dora-risk-01 (ICTRMF) | soc2-cc3-02 (CC3.3) | nist-gv-02 (GV.RM) | — | — | — |

**Theme: Access Control & Identity Management**

| Cluster ID | ISO 27001 | NIS2 | DORA | SOC 2 | NIST CSF | PCI DSS | GDPR | EU AI Act |
|---|---|---|---|---|---|---|---|---|
| IAM-01 | iso-org-08 (A.5.15/18) | nis2-iam-01 (Art.21.2.i) | dora-iam-01 (Art.9) | soc2-cc6-01 (CC6.1-3) | nist-pr-01 (PR.AA) | pci-iam-01 (Req.7) | gdpr-sec-02 (Art.32.1.b) | — |
| IAM-02 (MFA) | iso-tech-02 (A.8.2) | nis2-mfa-01 (Art.21.2.j) | dora-iam-01 (Art.9) | soc2-cc6-02 (CC6.1) | nist-pr-01 (PR.AA) | pci-iam-02 (Req.8.4.2) | gdpr-sec-02 | — |

**Theme: Incident Response Plan (IRP)**

| Cluster ID | ISO 27001 | NIS2 | DORA | SOC 2 | NIST CSF | PCI DSS | GDPR | EU AI Act |
|---|---|---|---|---|---|---|---|---|
| IR-01 | iso-org-11 (A.5.24-28) | nis2-ir-01 (Art.21.2.b) | dora-ir-01 (Art.17) | soc2-cc7-02 (CC7.3-5) | nist-rs-01 (RS.MA) | pci-pol-03 (Req.12.10) | gdpr-breach-01 (Art.33) | euaia-pmm-02 (Art.73) |
| IR-02 (exercises) | iso-org-11 | nis2-ir-02 (tabletop) | — | soc2-cc7-02 | nist-rs-01 | — | gdpr-breach-03 | — |

**Theme: Business Continuity & Backup**

| Cluster ID | ISO 27001 | NIS2 | DORA | SOC 2 | NIST CSF | PCI DSS | GDPR | EU AI Act |
|---|---|---|---|---|---|---|---|---|
| BCP-01 | iso-org-12 (A.5.29-30) | nis2-bcp-01 (Art.21.2.c) | dora-bcp-01 (Art.11) | soc2-av-01 (A1.1-2) | nist-rc-01 (RC.RP) | — | gdpr-sec-04 (Art.32.1.c) | — |
| BCP-02 (backup) | iso-tech-07 (A.8.13-14) | nis2-bcp-02 | dora-bcp-02 (Art.12) | soc2-av-01 | nist-rc-02 (RC.RP-03) | — | gdpr-sec-04 | — |

**Theme: Security Awareness & Training**

| Cluster ID | ISO 27001 | NIS2 | DORA | SOC 2 | NIST CSF | PCI DSS | GDPR | EU AI Act |
|---|---|---|---|---|---|---|---|---|
| TRAIN-01 | iso-ppl-03 (A.6.3) | nis2-train-01 (Art.21.2.g) | — | soc2-cc1-03 (CC1.4) | nist-pr-03 (PR.AT) | pci-pol-02 (Req.12.6) | gdpr-gov-02 (Art.39.1.b) | euaia-oversight-02 (Art.14.4) |

**Theme: Encryption / Cryptography**

| Cluster ID | ISO 27001 | NIS2 | DORA | SOC 2 | NIST CSF | PCI DSS | GDPR | EU AI Act |
|---|---|---|---|---|---|---|---|---|
| CRYPTO-01 | iso-tech-11 (A.8.24) | nis2-crypto-01 (Art.21.2.h) | — | soc2-cc6-03 (CC6.1/6.7) | nist-pr-02 (PR.DS) | pci-tls-01 (Req.4.2) | gdpr-sec-01 (Art.32.1.a) | euaia-sec-03 (Art.15.5) |

**Theme: Vulnerability Management & Patching**

| Cluster ID | ISO 27001 | NIS2 | DORA | SOC 2 | NIST CSF | PCI DSS | GDPR | EU AI Act |
|---|---|---|---|---|---|---|---|---|
| VULN-01 | iso-tech-04 (A.8.7-8) | nis2-vuln-01 (Art.21.2.e) | dora-vuln-01 (Art.6.2) | soc2-vuln-01 (CC7.1) | nist-id-04 (ID.RA-01) | pci-sdlc-01 (Req.6.3) | — | — |

**Theme: Supply Chain / Third-Party Risk**

| Cluster ID | ISO 27001 | NIS2 | DORA | SOC 2 | NIST CSF | PCI DSS | GDPR | EU AI Act |
|---|---|---|---|---|---|---|---|---|
| SC-01 | iso-org-10 (A.5.19-23) | nis2-sc-01 (Art.21.2.d) | dora-tpr-01 (Art.28) | soc2-cc9-01 (CC9.2) | nist-sup-01 (GV.SC) | pci-pol-04 (Req.12.8) | gdpr-proc-01 (Art.28) | — |

**Theme: Logging & Monitoring (SIEM)**

| Cluster ID | ISO 27001 | NIS2 | DORA | SOC 2 | NIST CSF | PCI DSS | GDPR | EU AI Act |
|---|---|---|---|---|---|---|---|---|
| LOG-01 | iso-tech-08 (A.8.15-17) | nis2-mon-01 (Art.21.2.b) | dora-detect-01 (Art.10) | soc2-cc7-01 (CC7.1-2) | nist-de-01 (DE.CM) | pci-log-01 (Req.10.2) | — | euaia-doc-02 (Art.12.1) |
| LOG-02 (retention) | iso-tech-08 | nis2-mon-02 | dora-log-01 | — | — | pci-log-01 | — | euaia-doc-03 (Art.12.2) |

**Theme: Penetration Testing**

| Cluster ID | ISO 27001 | NIS2 | DORA | SOC 2 | NIST CSF | PCI DSS | GDPR | EU AI Act |
|---|---|---|---|---|---|---|---|---|
| PENTEST-01 | iso-org-11 (audits) | nis2-audit-01 (Art.21.2.f) | dora-test-01 (Art.24) | soc2-pen-01 (CC4.1) | — | pci-pentest-01 (Req.11.4) | — | euaia-sec-02 (Art.15.3) |

**Theme: Asset Inventory**

| Cluster ID | ISO 27001 | NIS2 | DORA | SOC 2 | NIST CSF | PCI DSS | GDPR | EU AI Act |
|---|---|---|---|---|---|---|---|---|
| ASSET-01 | iso-org-06 (A.5.9-12) | nis2-iam-02 (Art.21.2.i) | dora-asset-01 (Art.8) | — | nist-id-01 (ID.AM-01) | — | gdpr-ropa-01 (Art.30) | euaia-gov-01 (Art.6) |

**Theme: Physical Security**

| Cluster ID | ISO 27001 | NIS2 | DORA | SOC 2 | NIST CSF | PCI DSS | GDPR | EU AI Act |
|---|---|---|---|---|---|---|---|---|
| PHY-01 | iso-phy-01..05 | — | — | soc2-cc6-04 (CC6.4) | — | pci-phy-01 (Req.9.1) | — | — |

**Theme: Change Management / Secure Development**

| Cluster ID | ISO 27001 | NIS2 | DORA | SOC 2 | NIST CSF | PCI DSS | GDPR | EU AI Act |
|---|---|---|---|---|---|---|---|---|
| SDLC-01 | iso-tech-12 (A.8.25-29) | nis2-vuln-02 (security-by-design) | dora-protect-01 (Art.9) | soc2-cc8-01 (CC8.1) | — | pci-sdlc-02 (Req.6.4) | gdpr-pbd-01 (Art.25) | euaia-sec-03 (Art.15.5) |

---

## 3. Current Implementation State (What Exists)

### 3.1 Backend Layer

**Questionnaire Engine** — `backend/cy_comp/services/questionnaire.py`
- `seed_templates(force)` — seeds all questions to `cy_comp_questionnaire_templates` at startup
- `get_templates(framework)` — returns ordered questions for ONE framework
- `get_responses(framework)` — returns saved answers keyed by `question_id` for ONE framework
- `save_response(framework, question_id, response, ...)` — upserts ONE answer for ONE framework
- `save_bulk_responses(framework, answers)` — batch upsert for ONE framework
- `score_framework(framework)` — computes weighted 0–100 score from saved answers
- `generate_gap_findings(framework)` — creates `cy_comp_findings` rows for unanswered questions

**Key architectural constraint:** The `cy_comp_questionnaire_responses` table has a `UNIQUE (framework, question_id)` constraint. Each question is siloed to its framework. There is NO cross-framework link.

**Policy Analysis Engine** — `backend/cy_comp/services/policy_analysis.py`
- `start_analysis_job(framework, overwrite, user_email)` — starts a background thread
- The worker calls `query_for_question(question_text, top_k=5)` which queries ONLY `policy-orgpolicies` collection
- LLM scores the question (0/1/2) via `score_question_from_policy()`
- Results are saved via `save_response()` — still per-framework
- **Triggered separately per framework** — user must run it once for ISO 27001, once for NIS2, etc.

**Policy RAG** — `backend/cy_comp/services/policy_rag.py`
- `upload_document(collection_id, file, metadata)` — uploads to ONE named collection
- `query_for_question(question_text, top_k)` — queries ONLY `policy-orgpolicies`
- No mechanism to upload once and map to multiple frameworks
- `cy_comp_policy_docs.framework` is a single text column (not an array)

**Controls Library** — `cy_comp_controls` table
- Has `framework_mappings JSONB DEFAULT '{}'` column at schema level
- This column is **never populated or read** anywhere in the codebase
- A full scan of `backend/` confirms no code touches `framework_mappings`

### 3.2 What Is NOT Implemented

| Feature | Status | Code gap |
|---|---|---|
| Cross-framework question similarity lookup | ❌ Missing | No mapping table, no similarity algorithm |
| Answer propagation: "You answered X in ISO 27001 — apply to NIS2?" | ❌ Missing | `save_response()` is per-framework only |
| "Apply same answer to all matching questions" API | ❌ Missing | No `/propagate` endpoint |
| "Reject mapping, answer individually" flow | ❌ Missing | No UI contract or backend state |
| Document → multi-framework mapping at upload | ❌ Missing | Single `collection_id`, single `framework` |
| Document reuse: upload once, satisfy multiple frameworks | ❌ Missing | No `framework[]` column, no multi-collection upload |
| Automatic framework detection from document content | ❌ Missing | No LLM call at upload time for framework detection |

---

## 4. Implementation Design

### 4.1 Database Schema Changes

**New table: `cy_comp_question_correlations`**
```sql
CREATE TABLE IF NOT EXISTS cy_comp_question_correlations (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    cluster_id      TEXT NOT NULL,          -- e.g. "IAM-01", "BCP-01"
    cluster_theme   TEXT NOT NULL,          -- e.g. "Access Control"
    framework_a     TEXT NOT NULL,
    question_id_a   TEXT NOT NULL,
    framework_b     TEXT NOT NULL,
    question_id_b   TEXT NOT NULL,
    similarity_type TEXT NOT NULL DEFAULT 'equivalent',  -- equivalent | overlapping | related
    confidence      NUMERIC(4,2) NOT NULL DEFAULT 1.0,
    UNIQUE (question_id_a, question_id_b)
);
CREATE INDEX IF NOT EXISTS idx_qcorr_cluster ON cy_comp_question_correlations (cluster_id);
CREATE INDEX IF NOT EXISTS idx_qcorr_qid_a ON cy_comp_question_correlations (question_id_a);
CREATE INDEX IF NOT EXISTS idx_qcorr_qid_b ON cy_comp_question_correlations (question_id_b);
```

This table is seeded statically from the Section 2 map above. Pairs are bidirectional — both (A→B) and (B→A) rows are inserted.

**New column on `cy_comp_questionnaire_responses`:**
```sql
ALTER TABLE cy_comp_questionnaire_responses
    ADD COLUMN IF NOT EXISTS propagated_from TEXT;   -- question_id that sourced this answer
ALTER TABLE cy_comp_questionnaire_responses
    ADD COLUMN IF NOT EXISTS propagation_accepted BOOLEAN DEFAULT NULL;  -- NULL=manual, TRUE=accepted, FALSE=rejected
```

**Schema change on `cy_comp_policy_docs`:**
```sql
ALTER TABLE cy_comp_policy_docs
    ADD COLUMN IF NOT EXISTS mapped_frameworks TEXT[] DEFAULT '{}';  -- replaces single framework text
```

### 4.2 New Service Functions (g-cyra-comp to implement)

**File:** `backend/cy_comp/services/questionnaire.py`

```python
def get_correlated_questions(question_id: str) -> list[dict]:
    """
    Return all questions correlated with question_id across other frameworks.
    Each entry: {question_id, framework, section, question, cluster_id, similarity_type, confidence}
    """

def propagate_response(
    source_question_id: str,
    source_framework: str,
    response: str,
    target_question_ids: list[str],
    responded_by: str,
) -> dict:
    """
    Write the same response to each target_question_id (in their respective frameworks).
    Marks each saved row with propagated_from=source_question_id, propagation_accepted=True.
    Returns {propagated: N, skipped: N}
    """

def get_propagation_suggestions(framework: str) -> list[dict]:
    """
    After a user answers a question in `framework`, find all correlated questions
    in OTHER frameworks that are still unanswered and return them as suggestions.
    Returns list of {cluster_id, answered_question_id, answered_response,
                     suggestions: [{framework, question_id, section, question}]}
    """
```

**File:** `backend/cy_comp/services/policy_rag.py`

```python
def upload_document_multi_framework(
    file_storage,
    metadata: dict,
    uploaded_by: str,
) -> dict:
    """
    Upload to org-policies collection (one copy), then use CyMind LLM to detect
    which frameworks the document satisfies. Store mapped_frameworks[] in DB.
    Returns doc record with detected_frameworks list.
    """

def detect_frameworks_from_document(cymind_doc_id: str, filename: str) -> list[str]:
    """
    Call CyMind chat API with a classification prompt listing all 8 frameworks.
    Returns list of framework keys the document is assessed to cover.
    """
```

### 4.3 New API Endpoints (g-cyra-comp to implement)

All under the existing `comp_bp` blueprint in `blueprints/comp/routes.py`:

```
GET  /api/comp/questionnaire/<framework>/correlations
     → Returns all propagation suggestions for answered questions in the framework.
     → Calls get_propagation_suggestions(framework)

POST /api/comp/questionnaire/propagate
     Body: {source_question_id, source_framework, response, accepted_targets: [question_id, ...]}
     → Calls propagate_response() for accepted_targets only
     → Returns {propagated, skipped}

POST /api/comp/questionnaire/reject-propagation
     Body: {source_question_id, target_question_id}
     → Writes a response row with propagation_accepted=FALSE so the suggestion is not shown again
     → User must answer the question manually

POST /api/comp/policy-docs/upload-multi
     Multipart: file + framework[] hint
     → Calls upload_document_multi_framework()
     → Returns doc with detected_frameworks[]

GET  /api/comp/question-correlations
     ?cluster_id= or ?question_id=
     → Returns the correlation table entries (read-only, admin/analyst)
```

### 4.4 Seed Data Function (one-time, idempotent)

**File:** `backend/cy_comp/data/question_correlations.py`

This file must contain the full static mapping derived from Section 2 above — all `(cluster_id, cluster_theme, framework_a, question_id_a, framework_b, question_id_b, similarity_type)` tuples and a `seed_correlations()` function called from `ensure_tables()` in `models.py`.

The static seed covers **~95 correlation pairs** across 15 themes. After seeding, the LLM can optionally augment by computing cosine similarity between question embeddings (if CyMind provides an embedding endpoint).

### 4.5 Frontend Changes (g-cyra-360 to implement)

**File:** `portal/src/pages/compliance/` (questionnaire view)

After a user saves an answer to any question, the frontend should:

1. Call `GET /api/comp/questionnaire/<framework>/correlations` to fetch current suggestions
2. If suggestions exist, display a non-blocking **suggestion panel**:
   ```
   ┌─────────────────────────────────────────────────────────────────────┐
   │ ✦ Your answer applies to 3 similar questions in other frameworks    │
   │                                                                      │
   │ • NIS2 Art.21(2)(b) — Incident Handling (nis2-ir-01)               │
   │ • SOC 2 CC7.3 — Incident Response (soc2-cc7-02)                   │
   │ • PCI DSS Req.12.10 — IRP (pci-pol-03)                            │
   │                                                                      │
   │  [Apply to all 3]    [Review individually]    [Skip]               │
   └─────────────────────────────────────────────────────────────────────┘
   ```
3. "Apply to all" → `POST /api/comp/questionnaire/propagate` with all targets
4. "Review individually" → opens each question in order, pre-filled with the answer
5. "Skip" → no action; suggestion reappears next session

**File:** `portal/src/pages/compliance/` (document upload view)

After upload, display detected frameworks as chips:
```
  ✓ Uploaded: Information Security Policy.pdf
  ─────────────────────────────────────────────
  Detected framework coverage:
  [ISO 27001]  [NIS2]  [SOC 2]  [NIST CSF]
  
  This document has been mapped to 4 frameworks automatically.
  All policy analysis jobs for these frameworks will use it.
```

### 4.6 Document Multi-Framework Flow (Full)

```
User uploads document
        │
        ▼
upload_document_multi_framework()
  │  ─ upload file bytes to CyMind collection: policy-orgpolicies (single copy)
  │  ─ get cymind_doc_id
  │  ─ call detect_frameworks_from_document(cymind_doc_id, filename)
  │      ─ POST /api/v1/chat with prompt:
  │          "This document is named '{filename}'. Based on the filename and
  │           your knowledge, which of these compliance frameworks does it
  │           most likely address? [iso27001, nis2, dora, soc2, nist_csf,
  │           pci_dss, gdpr, eu_ai_act]. Return a JSON list."
  │      ─ returns ["iso27001", "nis2", "soc2"]
  │  ─ INSERT into cy_comp_policy_docs with mapped_frameworks = detected list
  │
  ▼
Frontend shows coverage chips
        │
        ▼
When user runs policy analysis job (POST /api/comp/policy-docs/analyze-framework):
  - The job queries policy-orgpolicies (which contains the document)
  - Runs for each framework in mapped_frameworks automatically
  - OR: user can still run per-framework manually
```

---

## 5. Implementation Checklist

### Phase 1 — Backend Data Layer (g-cyra-comp)
- [ ] Add `cy_comp_question_correlations` table to `ensure_tables()` in `models.py`
- [ ] Add `propagated_from` and `propagation_accepted` columns to `cy_comp_questionnaire_responses` via `_MIGRATE_COLUMNS`
- [ ] Add `mapped_frameworks TEXT[]` column to `cy_comp_policy_docs` via `_MIGRATE_COLUMNS`
- [ ] Create `backend/cy_comp/data/question_correlations.py` with all static pairs from Section 2
- [ ] Implement `seed_correlations()` — idempotent, called from `ensure_tables()`
- [ ] Implement `get_correlated_questions(question_id)` in `questionnaire.py`
- [ ] Implement `propagate_response(...)` in `questionnaire.py`
- [ ] Implement `get_propagation_suggestions(framework)` in `questionnaire.py`

### Phase 2 — Document Multi-Framework (g-cyra-comp + g-cyra-ai)
- [ ] Implement `detect_frameworks_from_document(cymind_doc_id, filename)` in `policy_rag.py`
- [ ] Implement `upload_document_multi_framework(...)` in `policy_rag.py`
- [ ] Update `upload_document()` to populate `mapped_frameworks`

### Phase 3 — New API Endpoints (g-cyra-comp)
- [ ] `GET /api/comp/questionnaire/<framework>/correlations`
- [ ] `POST /api/comp/questionnaire/propagate`
- [ ] `POST /api/comp/questionnaire/reject-propagation`
- [ ] `POST /api/comp/policy-docs/upload-multi`
- [ ] `GET /api/comp/question-correlations`

### Phase 4 — Frontend UI (g-cyra-360)
- [ ] Suggestion panel after answering a question
- [ ] "Apply to all" / "Review individually" / "Skip" flow
- [ ] Document upload shows framework coverage chips
- [ ] Questionnaire hub shows propagation counts per framework

### Phase 5 — Testing (g-cyra-test)
- [ ] Unit: `seed_correlations()` idempotency
- [ ] Unit: `propagate_response()` writes correct `propagated_from` value
- [ ] Unit: `get_propagation_suggestions()` returns empty list when no correlations answered
- [ ] Integration: full round-trip — answer ISO 27001 question → propagate to NIS2 → verify score update
- [ ] Integration: upload document → detect frameworks → run analysis for all detected frameworks

---

## 6. Key File References

| File | Relevance |
|---|---|
| [backend/cy_comp/data/questionnaires.py](../backend/cy_comp/data/questionnaires.py) | All 245 question definitions — source of truth |
| [backend/cy_comp/services/questionnaire.py](../backend/cy_comp/services/questionnaire.py) | CRUD + scoring engine — all new service functions go here |
| [backend/cy_comp/services/policy_analysis.py](../backend/cy_comp/services/policy_analysis.py) | Per-framework RAG scoring job — must be extended for multi-framework |
| [backend/cy_comp/services/policy_rag.py](../backend/cy_comp/services/policy_rag.py) | CyMind RAG client — multi-framework upload + detection goes here |
| [backend/cy_comp/models.py](../backend/cy_comp/models.py) | DDL — new table + migration columns go here |
| [backend/blueprints/comp/routes.py](../backend/blueprints/comp/routes.py) | All new API endpoints go here |
| [backend/cy_comp/data/question_correlations.py](../backend/cy_comp/data/question_correlations.py) | **New file** — static correlation pairs seed data |
