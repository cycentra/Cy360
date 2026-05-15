# GRC Scoring Model — CyCentra 360

## Overview

The CyCentra 360 GRC engine computes a posture score (0–100) for each compliance framework. The score combines two independent signals: a **questionnaire baseline** derived from your assessment answers, and an **alert penalty** derived from live SIEM telemetry. The formula is intentionally simple and transparent.

---

## Supported Frameworks

| ID | Name | Questions | Region |
|---|---|---|---|
| `nis2` | NIS2 Directive | 28 | EU |
| `dora` | DORA | 28 | EU |
| `iso27001` | ISO 27001:2022 | 45 | Global |
| `soc2` | SOC 2 Type II | 28 | US |
| `nist_csf` | NIST CSF 2.0 | 26 | US |
| `pci_dss` | PCI DSS v4 | 30 | Global |
| `gdpr` | GDPR | 30 | EU |

---

## Scoring Formula

### Step 1 — Questionnaire Baseline (q_score)

Each questionnaire question carries a **weight** (default 2; critical controls = 3). Each answered question receives a **score**:

| Score | Meaning |
|---|---|
| 0 | Fail — control is not implemented |
| 1 | Partial — control is partially implemented |
| 2+ | Pass — control is fully implemented |

The baseline is computed as:

```
earned       = pass_weight + (partial_weight × 0.5)
q_score      = (earned / total_weight) × 100
```

- `pass_weight` = sum of weights for all questions scored ≥ 2
- `partial_weight` = sum of weights for all questions scored = 1
- `total_weight` = sum of weights for all questions in the framework
- Partial credit counts as 50% of the question's weight

**Important:** The control count used in the denominator is the questionnaire question count, not the alert count. This prevents alert volume from distorting the completeness percentage.

### Step 2 — Alert Penalty

Every compliance-relevant alert from the correlation engine carries a severity level. Alerts from the **last 30 days** are counted per framework (only alerts tagged with that framework's control mappings contribute):

| Severity | Rule Level | Penalty per Alert |
|---|---|---|
| Critical | ≥ 12 | 8 pts |
| High | 10–11 | 4 pts |
| Medium | 7–9 | 1 pt |
| Low | < 7 | 0 pts |

```
alert_penalty = min(40, Σ(critical × 8) + Σ(high × 4) + Σ(medium × 1))
```

**Hard cap:** The penalty is capped at **40 points**. Alerts alone can never zero a score — even a system with 1000 critical alerts deducts at most 40 points. This prevents noisy environments from making compliance tracking unusable.

### Step 3 — Final Score

```
if (questions have been answered):
    final_score = max(0, q_score − alert_penalty)
else:
    final_score = max(0, 100 − alert_penalty)   ← clean-start baseline
```

**Zero-questions baseline:** When no assessment questions have been answered, the system assumes a 100% questionnaire baseline. This represents a "clean start" — the framework posture is unknown, so only the live alert signal penalizes the score. This is intentional: a framework with no assessment data and no relevant alerts shows 100%, prompting you to complete the assessment rather than hiding behind a false 0%.

---

## Why Different Frameworks Show Different Scores

### With 0 questions answered

Every framework starts at 100%. The only thing that differentiates scores is the **alert penalty**, which depends entirely on:

1. How many compliance-relevant alerts exist in the last 30 days
2. How many of those alerts are tagged with each framework's control mappings

**Example scenario:**
- NIS2 has 450 tagged alerts (300 medium + 100 high + 50 critical) → penalty = min(40, 300 + 400 + 400) = 40 → score = 60%
- SOC 2 has 0 tagged alerts → penalty = 0 → score = 100%

This is not a bug. It means your SIEM enrichment mappings have associated more historical alerts with NIS2/DORA/ISO 27001 controls (because those frameworks were enriched first) and fewer with SOC 2/NIST/PCI (because they were added later and require re-enrichment of historical alerts).

**To normalize:** Run the compliance enrichment sync (`Run Compliance Enrichment` button on the Live Alerts page). This re-scans existing alerts and tags them with all framework control mappings.

### With questions answered

Scores diverge based on:
- Which controls you've marked as compliant, partial, or gap
- The weight assigned to those controls (critical controls weight 3, standard controls weight 2)
- The alert volume tagged to that framework's controls

---

## Weighting Model

The weighting system ensures that critical controls (e.g., multi-factor authentication, incident response) have more impact on the score than baseline hygiene items.

| Weight | Meaning | Examples |
|---|---|---|
| 3 | Critical control | MFA, encryption at rest, incident detection |
| 2 | Standard control (default) | Policy documentation, access review, logging |

The questionnaire templates define the weight for each question. When the backend computes the score, it sums weights — not question counts — so two questions with weight 3 count as much as three questions with weight 2.

---

## Normalization

Each framework is scored independently on a 0–100 scale. There is no cross-framework normalization. The Overall Posture score shown on the dashboard is a simple arithmetic mean of all selected framework scores:

```
overall = average(score_nis2, score_dora, score_iso27001, ...)
```

This means:
- A framework with many alerts drags down the overall score
- A framework with all questions passed and no alerts raises the overall score
- The overall score is only computed for the frameworks currently selected in the framework filter

---

## Alert-to-Framework Mapping

Alerts are tagged with frameworks through two mechanisms:

### 1. MITRE ATT&CK Technique Mapping

Each MITRE technique (e.g., T1078 — Valid Accounts) is mapped to one or more framework controls. When a correlation rule fires with a MITRE technique ID, the resulting alert is tagged with all frameworks that have a control for that technique.

### 2. Wazuh Rule ID Mapping

Specific Wazuh rule groups (e.g., `authentication_failed`, `web-attack`) are directly mapped to framework controls. Alerts matching these rule groups are tagged accordingly.

The enrichment is stored in the `alerts` table as:
- `is_compliance_relevant` (boolean) — true if the alert maps to any framework
- `compliance_frameworks` (text[]) — array of framework IDs (e.g., `["nis2","gdpr","iso27001"]`)
- `compliance_controls` (jsonb) — per-framework control IDs (e.g., `{"nis2": ["NIS2-Art21-2a"], "gdpr": ["GDPR-Art32"]}`)
- `compliance_confidence` (float) — mapping confidence score (0–1)

---

## Framework Score Persistence

Scores are stored in the `cy_comp_framework_scores` table as append-only snapshots. Each time you click **↻ Refresh Scores**, a new row is inserted per framework. This builds the score history used by the trend chart.

The displayed score is always the **most recent** snapshot, with two live fields merged in at read time:
- `alert_penalty` — always recomputed live from the last 30 days of alerts
- `q_answered` — always recomputed live from the current questionnaire responses

This means the score you see is always accurate even if you haven't clicked Refresh.

---

## GDPR Status Notes

GDPR was added in v1.2.10. Historical alerts enriched before this version are not tagged with GDPR framework mappings. To apply GDPR tags to existing alerts:

1. Navigate to **Live Compliance Alerts**
2. Click **Run Compliance Enrichment**

This re-scans all compliance-relevant alerts and applies the current enrichment mappings, including GDPR.

---

## Framework Selector

The **Framework Selector** on the GRC Posture Dashboard controls which frameworks appear across all compliance pages. Your selection is saved to `localStorage` under the key `cy_fw_filter` and persists across page navigation.

The filter affects:
- Framework Posture Scores bars
- Score Trend Line chart
- Overall Posture score (donut — averages only selected frameworks)
- Active Alerts count (only alerts tagged to selected frameworks)
- Findings by Severity chart
- Findings by Verdict chart
- Risk Register summary (only risks linked to selected frameworks)
- Questionnaire Hub (only shows selected frameworks)
- Framework dropdowns on Findings, Live Alerts, and Reports pages

---

## Score Interpretation

| Score | Status | Meaning |
|---|---|---|
| 80–100% | Good | Controls are largely in place; maintain and improve |
| 60–79% | Caution | Notable gaps or active alerts; prioritize remediation |
| < 60% | At Risk | Significant control failures or heavy alert volume; immediate action needed |

A score of exactly 60% with 0 questions answered and −40pt penalty means: no assessment has been done, AND the framework has hit the maximum alert penalty. Complete the questionnaire to get an accurate picture of your actual control implementation.
