# CySIEM Severity Pipeline — Tuning Reference

_Created: 2026-06-17 | Owner: SIEM Engineering_

---

## 1. Overview

Every Wazuh alert that enters CyCentra 360 passes through a four-stage severity pipeline:

```
Wazuh alert (rule_level 1–15)
    ↓
normaliser.py  → base_score (4.1–8.2)
    ↓
grouper.py     → incident severity (low / medium / high / critical)
    ↓
correlator.py  → severity escalation only (never downgrades)
    ↓
ingestor.py    → FP-based severity soft cap (downgrades if fp_probability ≥ 75)
```

Each stage is described below with the exact thresholds, the math behind them, and how to tune them.

---

## 2. Stage 1 — Normaliser: Wazuh Level → Base Score

**File:** `normaliser.py` → `_level_to_score(level: int) -> float`

**Formula:** `min(15.0, log(level + 1, base=1.4))`

### Score Table

| Wazuh Level | Computed Score | Wazuh Severity Category |
|---|---|---|
| 3 | 4.1 | Informational |
| 4 | 4.8 | Informational |
| 5 | 5.4 | Informational |
| 6 | 5.9 | Low |
| 7 | 6.2 | Low |
| 8 | 6.6 | Medium |
| 9 | 6.8 | Medium |
| 10 | 7.1 | High |
| 11 | 7.4 | High |
| 12 | 7.6 | High |
| 13 | 7.8 | High |
| 14 | 8.0 | Critical |
| 15 | 8.2 | Critical |

**Key constraint:** the logarithmic formula compresses all Wazuh levels into the range **4.1–8.2**. Any downstream threshold above 8.2 is unreachable and permanently dead code.

---

## 3. Stage 2 — Grouper: Base Score → Incident Severity

**File:** `grouper.py` → `_score_to_severity(alerts: list) -> str`

Takes the **maximum** `base_score` across all alerts in the incident.

### Current Thresholds (as of v1.0.55)

| Score Range | Incident Severity | Wazuh Levels |
|---|---|---|
| ≥ 8.2 | **critical** | 15 only |
| ≥ 7.6 and < 8.2 | **high** | 12, 13, 14 |
| ≥ 6.0 and < 7.6 | **medium** | 7, 8, 9, 10, 11 |
| < 6.0 | **low** | 3, 4, 5, 6 |

### Previous (Broken) Thresholds

Prior to v1.0.55 the thresholds were `>= 10 / 7 / 4`. Because the maximum reachable score is 8.2:
- `>= 10` (critical) **never fired** — zero critical incidents were created by the grouper
- `>= 7` (high) fired for **all level 10+ alerts** — every custom rule and most Wazuh built-in alerts landed as High
- Result: ~95% of active incidents were High severity with zero critical

### How to Tune

To adjust where the severity bands fall, edit the thresholds in `grouper.py._score_to_severity()`. Use the score table in Section 2 to map your desired level boundaries to scores.

**Example:** to promote level 14 alerts to critical (alongside level 15), lower the critical threshold from `>= 8.2` to `>= 8.0`.

---

## 4. Stage 3 — Correlator: Severity Escalation

**File:** `correlator.py` → `run_correlation()` (line ~1844)

Correlation rules can **only escalate** severity, never downgrade. When a rule fires, its declared `severity` is compared against the current incident severity using the order `[low, medium, high, critical]`. If the rule's severity is higher, the incident severity is updated.

### Rule Severity Distribution (55 rules)

| Declared Severity | Rule Count |
|---|---|
| critical | 17 |
| high | 33 |
| medium | 5 |

This is by design — correlation rules fire on confirmed attack patterns (kill-chain chains, LOLBin combinations, credential dump sequences) which warrant escalation. The raw alert grouper creates at the appropriate initial band; correlation lifts confirmed threats above it.

---

## 5. Stage 4 — Ingestor: FP-Based Severity Cap

**File:** `ingestor.py`, after `_fp_score_for()` is called (post-MISP / post-LLM enrichment)

When `fp_probability >= 75.0`, the incident severity is downgraded by **one band**:

```
critical → high
high     → medium
medium   → low
low      → (unchanged)
```

This is a soft cap — it does not close the incident. The purpose is to prevent incidents that the enrichment pipeline has already determined are likely noise from consuming high-priority analyst attention.

The FP probability is computed from:
1. Low rule confidence (below 0.5 average)
2. No UEBA anomalies — anomalies reduce FP probability
3. MISP miss — no IOC matches
4. Kill-chain stage: early stages (Recon) have higher FP floor; late stages (Exfiltration, C2) have FP cap at 30
5. Asset tier: Tier 1 (crown jewel) caps FP at 20; Tier 3 floors at 40

### Threshold

`75.0` is a conservative default. Lowering it (e.g. to `60.0`) will cap more incidents; raising it (e.g. to `90.0`) reduces the cap's effect. The value is hardcoded — change it in `ingestor.py` if needed (or expose it via `ai_settings.json` for operator control).

---

## 6. Custom Rules — Level Guidelines

**File:** `CYSIEM-Config/rules/cy_cust_rules.xml`

| Rule Purpose | Recommended Level | Score | Initial Severity |
|---|---|---|---|
| Credential dump / DCSync / Shadow copy delete | 15 | 8.2 | critical |
| LOLBAS, Pass-the-Hash, encoded PS, AV disabled | 12–14 | 7.6–8.0 | high |
| WMI execution, password spray, macro exec, recon w/ context | 10–11 | 7.1–7.4 | medium |
| Pure reconnaissance (nmap, BloodHound, net view) | 9 | 6.8 | medium |
| Tool noise, scanning detection | 7–8 | 6.2–6.6 | medium |
| Informational / audit | 3–6 | 4.1–5.9 | low |

**Rules 100900 and 100901** (SMB enumeration, network scanning) were lowered from level 10 to level 9 in v1.0.55. At level 9 they score 6.84 → medium severity. At level 10 they scored 7.1 → high, flooding analyst queues with pure reconnaissance detections before any exploitation was confirmed.

---

## 7. Alert Drop Filters

**File:** `normaliser.py`

Events below `MIN_RULE_LEVEL = 3` are silently dropped before any DB write. Additionally, specific rule IDs are suppressed:

| Rule ID | Description | Reason |
|---|---|---|
| 5710 | SSH login attempt with non-existent user | Scanner background noise |
| 5711 | SSH login attempt (scanner variant) | Scanner background noise |
| 5702 | SSH reverse lookup error | DNS configuration noise |
| 5703 | PAM shadow lookup error | PAM configuration noise |

To add suppression, append to `SUPPRESSED_RULE_IDS` or `SUPPRESSED_DESC_FRAGMENTS` in `normaliser.py`.

---

## 8. Severity Ratchet

Once an incident is created, its severity can only move **up**, never down — except for the FP soft cap in Stage 4.

- `grouper.py:merge_alert_into_incident()` — only escalates via `_score_to_severity()`
- `correlator.py:run_correlation()` — only escalates via `sev_order.index()` comparison
- `ingestor.py` FP cap — the only mechanism that can reduce severity, and only when `fp_probability >= 75`

This means a single high-severity alert at incident creation sets the floor for the entire incident's lifetime (unless FP cap applies). Analysts can manually change severity in the portal; this only governs automated pipeline behavior.

---

## 9. Environment Variables

All values tunable via `/opt/cycentra/cysiemstack.env`:

| Variable | Default | Effect |
|---|---|---|
| `UEBA_ML_SHADOW_MODE` | `true` | ML anomalies logged only; set `false` to enable risk score impact |
| `UEBA_ML_CONTAMINATION` | `0.05` | IsolationForest expected anomaly rate (0.01–0.10) |
| `UEBA_ML_MIN_TRAIN_DAYS` | `7` | Minimum alert history before training a user model |
| `CORRELATION_WINDOW_MINUTES` | `15` | Idle-gap guard for incident grouping |
| `INCIDENT_MAX_AGE_MINUTES` | `1440` | Hard ceiling for incident age (24 h default) |

FP threshold slider and LLM trigger severity live in `/opt/cycentra/ai_settings.json`.
