# CyCentra 360 — Benchmark Intelligence Engine: Score Calculations Reference

**Version:** v2 — Gap Patch (June 2026)  
**Applies to:** `backend/blueprints/benchmark/routes.py`

| Revision | Date | Changes |
|----------|------|---------|
| v1 Post-Accuracy-Fix | May 2026 | Data isolation fix; ext_benchmark overlap guard |
| **v2 Gap Patch** | **June 2026** | **Dimension 2 (SIEM) extended: UEBA anomalies, kill chain depth, no-agents coverage penalty** |

---

## Overview

The **Cyber Security Posture Index (CSPI)** is a composite score (0–100) that represents an organisation's overall security posture. It is computed from up to six independent data dimensions. Each dimension is scored separately from its own dedicated data source — no two active dimensions share the same underlying dataset.

---

## CSPI Composite Formula

$$\text{CSPI} = \frac{\sum_{i} \left( \text{score}_i \times w_i \times f_i \right)}{\sum_{i} \left( w_i \times f_i \right)}$$

Where for each enabled dimension $i$:
- $\text{score}_i$ = raw score (0–100) from that dimension's collector
- $w_i$ = configured weight (default values in the table below)
- $f_i$ = freshness factor: **1.0** if data ≤ 48 h old, **0.8** if stale
- Dimensions where `score = null` are excluded from both numerator and denominator

### Default Weights

| # | Dimension | Default Weight | Data Source | Status |
|---|-----------|---------------|-------------|--------|
| 1 | External Attack Surface (ASM) | 20% | ASM scan JSON | Always available after first scan |
| 2 | Internal Detection Posture (SIEM) | 20% | Correlation engine `/stats`, `/risk-scores`, `/ueba/users` + correlation DB (kill chain) | Available when CySIEM is running |
| 3 | Compliance Coverage | 20% | `cy_compliance_controls` PostgreSQL table | Requires CyComp module |
| 4 | Vulnerability Management | 20% | Wazuh API (vuln detector + SCA + CyIRIS MTTR) | Requires Wazuh + WAZUH_API_PASSWORD |
| 5 | Threat Intelligence | 15% | MISP API (feeds + IOC count + actionable ratio) | Requires MISP configured in System Settings |
| 6 | CIS / NIST Alignment | 5% (disabled by default) | Weighted proxy of Compliance + ASM | Only scores when one source dimension is disabled |

Weights are configurable per-tenant via `PUT /api/benchmark/config`. The composite automatically re-normalises when dimensions are disabled or return null scores.

---

## Dimension 1: External Attack Surface (ASM)

**Source:** Most recent scan JSON under `SCANS_DIR/<user>/<tenant>/scan_*.json`  
**Data age threshold:** 48 hours (older = STALE, contributes at 80% weight)

### Algorithm

```
score = 80  (starting baseline)

deduct per severity:
  critical finding : -12 each   cap -48
  high finding     : -6 each    cap -30
  medium finding   : -2 each    cap -16
  low finding      : -0.5 each  cap -5

SSL/TLS:
  TLS not present  : -10
  TLS present      : +5

Email security:
  status = elite | robust : +3
  status = basic | none   : -5

final = clamp(score, 0, 100)
```

**Grades:** A+ ≥ 90 · A ≥ 80 · B ≥ 70 · C ≥ 55 · D ≥ 35 · F < 35

**What is counted:** All findings in the latest scan file. ASM findings do not have an open/closed lifecycle — they reflect the external surface state at the time of the last scan.

**What this dimension does NOT count:** Internal vulnerabilities, SIEM alerts, compliance controls, or threat intelligence. It is strictly external attack surface exposure.

---

## Dimension 2: Internal Detection Posture (SIEM)

**Source:** Correlation engine HTTP API at `http://127.0.0.1:8100` + Correlation DB  
**Endpoints used:** `GET /stats`, `GET /risk-scores`, `GET /ueba/users`, direct DB query

### Algorithm (v2 — Gap Patch)

```
score = 100  (start from perfect)

── Signal group 1: Threat load (from /stats + /risk-scores) ──────────────────
  critical_alerts (24 h window)   : -3 each   cap -30
  open_incidents                  : -2 each   cap -20
  critical risk entities          : -5 each   cap -25
  high risk entities              : -2 each   cap -10

── Signal group 2: UEBA behavioral anomalies (NEW — from /ueba/users) ────────
  active UEBA anomalies (summed   : -3 each   cap -12
  across all users with unresolved
  anomalies)

── Signal group 3: Kill chain depth (NEW — from correlation DB) ──────────────
  open incidents at MITRE stage   : -6 each   cap -18
  >= 10 (Lateral Movement,
  Collection, Exfiltration, Impact)

  open incidents at MITRE stage   : -2 each   cap  -8
  7–9 (Defense Evasion,
  Credential Access, Discovery)

── Signal group 4: Coverage baseline (NEW) ───────────────────────────────────
  active_agents == 0              : -10 flat  (no endpoint visibility)

final = clamp(score, 0, 100)
```

**Maximum total deduction breakdown:**

| Signal | Max deduction |
|--------|--------------|
| Critical alerts | −30 |
| Open incidents | −20 |
| Critical entities | −25 |
| High entities | −10 |
| UEBA anomalies (new) | −12 |
| Deep kill chain incidents (new) | −18 |
| Mid kill chain incidents (new) | −8 |
| No agents coverage penalty (new) | −10 |
| **Total theoretical max** | **−133 → clamped to 0** |

### UEBA Signal Detail (new in v2)

- **Endpoint:** `GET /ueba/users?has_anomaly=true`
- **Field used:** `active_anomalies` (count of unresolved anomalies per user, injected by the `list_ueba_users` route)
- **Aggregation:** sum of `active_anomalies` across all returned users
- **Penalty:** −3 per anomaly, cap −12 (4+ anomalies = full deduction)
- **Degradation:** if endpoint unreachable, `ueba_active_anomalies = 0` — score not affected (graceful)

### Kill Chain Depth Signal Detail (new in v2)

- **Source:** Direct psycopg2 query to `CORRELATION_DB_URL` — `incidents` table  
- **Filter:** `status IN ('open', 'investigating', 'in_review') AND kill_chain_stage >= 7`
- **MITRE ATT&CK stage map (from correlator.py):**

| Stage # | MITRE Tactic | Group |
|---------|-------------|-------|
| 7 | Defense Evasion | Mid |
| 8 | Credential Access | Mid |
| 9 | Discovery | Mid |
| 10 | Lateral Movement | **Deep** |
| 11 | Collection | **Deep** |
| 12 | Exfiltration | **Deep** |
| 13 | Impact | **Deep** |

- **Rationale:** An open incident reaching stage 10+ means the threat actor progressed past initial access and is actively moving laterally or exfiltrating — a severe detection failure that warrants a significant score penalty beyond the baseline "open incident" deduction already applied.

### Coverage Baseline (new in v2)

- **Field:** `active_agents` from `/stats`
- **Condition:** if `active_agents == 0` → −10 flat penalty
- **Rationale:** Zero active agents means the SIEM has no telemetry source — any score above 0 would be misleading. The penalty ensures the dimension reflects the absence of monitoring visibility.

### What is counted vs. not counted

| Counted | Not counted |
|---------|-------------|
| Active critical alerts (24 h window) | Historical resolved alerts |
| Open / in-progress incidents | Closed/resolved incidents (those are in Vuln MTTR) |
| Current entity risk levels | Static host metadata |
| Unresolved UEBA anomalies | Resolved UEBA anomalies |
| Open incidents at advanced kill chain stages | Kill chain stage of closed incidents |
| Endpoint coverage (agent count baseline) | ASM findings, CVEs, MISP IOCs |

This dimension is **strictly independent** from all others — no shared data sources.

---

## Dimension 3: Compliance Coverage

**Source:** `cy_compliance_controls` PostgreSQL table (CyComp module)  
**Availability:** Requires CyComp to be installed and controls populated

### Algorithm (CyComp installed)

```
score = round( (compliant_count + partial_count * 0.5) / total_count * 100 )
```

- `compliant` controls count as full (1.0)
- `partial` controls count as half (0.5)
- `non_compliant` controls count as zero

**What is counted:** Framework control status for NIS2 / ISO 27001 / DORA / GDPR as tracked in CyComp.

### When CyComp is NOT installed

Score returns `null`. This dimension is **excluded from the CSPI composite** rather than falling back to ASM data. This prevents double-counting — ASM findings are already captured in Dimension 1.

---

## Dimension 4: Vulnerability Management

**Source:** Wazuh API (primary) → CyIRIS database (MTTR sub-score)  
**Credential:** `WAZUH_API_PASSWORD` resolved from `/opt/cycentra/.env` then `/opt/cycentra/cysiemstack.env`

### Sub-scores and weights

| Sub-score | Source | Weight within Vuln |
|-----------|--------|--------------------|
| Wazuh vuln detector | `/vulnerability/{agent_id}?status=Active` | 40% |
| Wazuh SCA policy pass rate | `/sca/{agent_id}` | 35% |
| CyIRIS MTTR (remediation speed) | `incidents` table — closed_at, first_seen | 25% |

The sub-scores are blended with re-normalisation when some are unavailable (e.g. IRIS not configured).

### Wazuh Vulnerability Sub-score (40%)

```
Counts severity of Active CVEs only (status=Active excludes Solved and Inactive)
across up to 50 active agents.

score = 100
score -= min(60, critical_CVEs * 12)
score -= min(36, high_CVEs     *  6)
score -= min(20, medium_CVEs   *  2)
final = clamp(score, 0, 100)
```

**Active-only filter:** `status=Active` is passed to the Wazuh API. Patched/resolved CVEs (status=`Solved` or `Inactive`) are **not counted**.

### Wazuh SCA Sub-score (35%)

```
Averaged across up to 30 active agents:
score = (total_pass_checks / (pass + fail + error)) * 100
```

Point-in-time configuration compliance — always reflects current agent state.

### CyIRIS MTTR Sub-score (25%)

```
Queries incidents closed in the last 90 days.
Calculates average hours to resolve per severity.

Band scoring (lower MTTR = higher score):
  critical MTTR < 24 h   → 100 pts
  critical MTTR < 72 h   → 80 pts
  critical MTTR < 168 h  → 60 pts
  critical MTTR < 336 h  → 40 pts
  critical MTTR ≥ 336 h  → 20 pts

Weighted blend: critical × 3, high × 2, medium × 1
```

**What is counted:** Only **resolved/closed** incidents (`closed_at IS NOT NULL`). This measures remediation velocity — not current exposure. It is complementary to the SIEM dimension, which measures open/active incidents only.

**When Wazuh is unavailable:** Score returns `null` — this dimension is excluded from the CSPI composite. ASM findings are NOT used as a fallback (they are already in Dimension 1).

---

## Dimension 5: Threat Intelligence

**Source:** MISP API (direct — not via the correlation engine)  
**Credential resolution (first match wins):**
1. `/opt/cycentra/ai_settings.json` → `misp.url` / `misp.apiKey`
2. Environment `CLOUD_MISP_URL` / `CLOUD_MISP_API_KEY` (from `/opt/cycentra/.env`)
3. `/opt/cycentra/cysiemstack.env` → `MISP_URL` / `MISP_API_KEY`
4. Environment `MISP_URL` / `MISP_API_KEY`

### Sub-signals and weights

| Sub-signal | Endpoint | Max pts | Full pts at |
|------------|----------|---------|-------------|
| Enabled feed count | `GET /feeds/index` | 40 | 3+ feeds enabled |
| Total IOC attribute count | `POST /attributes/statistics/type` | 30 | 10,000+ attributes |
| Actionable ratio (`to_ids=1`) | `POST /attributes/restSearch` | 30 | 100% actionable |

```
composite = min(100, feed_score + attr_score + active_score)
```

**What is counted:** MISP feed configuration and IOC database richness. Fully independent from all other dimensions — no shared data source.

---

## Dimension 6: CIS / NIST Alignment (ext_benchmark)

**Default state:** Disabled (`enabled: false`). Weight 5% when enabled.

### Source-overlap guard (post-fix behaviour)

This dimension is a **Phase 1 proxy estimate** derived from Compliance + ASM scores. Because it re-weights data already contributing to Dimensions 1 and 3, the following guard is enforced:

> **If both ASM (Dimension 1) and Compliance (Dimension 3) are enabled and have non-null scores, `ext_benchmark` returns `null` and is excluded from the CSPI composite.**

`ext_benchmark` only produces a score when one or both of its source dimensions are disabled or unavailable (e.g. CyComp not installed → Compliance is null). In that case:

```
if only asm available:   score = asm_score
if only comp available:  score = compliance_score
if both available:       score = compliance * 0.6 + asm * 0.4
if both null:            score = null
```

Phase 2 will replace this with a bundled CIS Controls v8 JSON dataset and nightly NVD/MITRE sync.

---

## Data Isolation Guarantee (v2)

Each active, scored dimension reads from a strictly separate data source:

| Dimension | Unique data source | Shares data with |
|-----------|-------------------|-----------------|
| ASM | ASM scan JSON (external surface) | None |
| SIEM | Correlation engine `/stats`, `/risk-scores`, `/ueba/users` + correlation DB (kill chain) | None |
| Compliance | `cy_compliance_controls` DB table | None |
| Vuln | Wazuh API + CyIRIS incidents DB (MTTR only — closed incidents) | None |
| Threat Intel | MISP API | None |
| ext_benchmark | Suppressed when ASM + Compliance both active | Would share with ASM + Compliance |

> **Note:** The SIEM dimension uses the correlation DB for kill chain depth queries, and the Vuln dimension uses the same DB for MTTR (closed incidents). There is no data overlap because the kill chain query filters `status IN ('open', 'investigating', 'in_review')` while MTTR filters `closed_at IS NOT NULL`. These are disjoint sets.

---

## Grading Scale

| Grade | CSPI Range |
|-------|-----------|
| A+ | ≥ 85 |
| A | 75 – 84 |
| B | 65 – 74 |
| C | 50 – 64 |
| D | 35 – 49 |
| F | < 35 |

---

## Industry Percentile Bands

Scores are placed against sector-specific P10/P25/P50/P75/P90 cohort bands:

| Band | Percentile label |
|------|-----------------|
| Below P10 | Bottom 10% |
| P10 – P25 | 10th–25th percentile |
| P25 – P50 | 25th–50th percentile |
| P50 – P75 | 50th–75th percentile |
| P75 – P90 | 75th–90th percentile |
| Above P90 | Top 10% |

Eight sectors available: Finance, Healthcare, Manufacturing, Logistics, Technology, Public Sector, Energy, Retail, plus a General (all-sector) baseline. Bands are derived from ENISA Threat Landscape 2024, CIS Benchmark SecureSuite, NCSC-NL reports, BSI Lagebericht, and Verizon DBIR 2024. Updated annually each Q1.

---

## Stale Data Handling

Any dimension whose underlying data is older than **48 hours** contributes at **80% of its configured weight** (freshness factor $f_i = 0.8$) and displays a `STALE` badge in the UI. This avoids silently inflating the CSPI with outdated scan results.

---

## Credential and Environment Requirements

| Variable | Required for | Written to |
|----------|-------------|-----------|
| `WAZUH_API_PASSWORD` | Vulnerability Management | `/opt/cycentra/cysiemstack.env` **and** `/opt/cycentra/.env` (since setup v7.1+) |
| `WAZUH_API_URL` | Vulnerability Management | Both env files |
| `MISP_URL` / `MISP_API_KEY` | Threat Intelligence | `ai_settings.json` or `cysiemstack.env` |
| `CYCENTRA_DB_URL` | Compliance (CyComp) | `/opt/cycentra/.env` |
| `CORRELATION_DB_URL` | Vuln MTTR (CyIRIS) | `/opt/cycentra/.env` |
| `SIEM_ENGINE_URL` | SIEM Posture | `/opt/cycentra/.env` (default: `http://127.0.0.1:8100`) |

---

## Gap Analysis & Resolution History

### Identified Gaps in Dimension 2 (addressed in v2)

Prior to v2, the Internal Detection Posture score used only four signals derived from two HTTP endpoints (`/stats` + `/risk-scores`). The following gaps were identified and addressed:

| Gap | Impact | Resolution |
|-----|--------|------------|
| **UEBA behavioral anomalies ignored** | Users with unusual behaviour patterns (off-hours logins, anomalous event volumes, impossible travel) were not reflected in the score even when the UEBA engine had active unresolved anomalies | Added `GET /ueba/users?has_anomaly=true` fetch; sum of `active_anomalies` across all users penalises −3/anomaly, cap −12 |
| **Kill chain depth invisible** | An incident where a threat actor had reached Lateral Movement or Exfiltration stages received the same score deduction as a Reconnaissance-stage incident. The `kill_chain_stage` field was set by `correlator.py` on all incidents but never read by the benchmark | Added direct DB query for `kill_chain_stage >= 7` on open incidents; deep-stage (≥10) incidents penalise −6 each, mid-stage (7–9) penalise −2 each |
| **No monitoring coverage baseline** | A score of 90+ was possible when `active_agents == 0` (no endpoint telemetry) — effectively a perfect score with no data to support it | Added flat −10 penalty when `active_agents == 0` |
| **`/incidents/distribution` data fetched but unused** | Distribution data (by severity / status / category) was fetched from the engine but only returned in the API response — not used in the formula | Still returned for UI display; kill chain gap addressed separately via DB query (more granular) |

### Remaining Known Gaps (Phase 3 candidates)

| Dimension | Gap | Planned fix |
|-----------|-----|-------------|
| SIEM | AI auto-close effectiveness (FP auto-close rate = healthy detection; not reflected) | Add `GET /feedback/accuracy` or `GET /fp-patterns` query; bonus points for high FP suppression rate |
| SIEM | No differentiation between "engine running but no alerts" vs. "engine offline" | Distinguish using `/health` endpoint: engine healthy + no alerts = stronger positive signal |
| Threat Intel | Feed freshness not measured — stale feeds count same as active | Add last-sync timestamp check from `/feeds/index` → `last_fetched_timestamp`; penalise feeds inactive > 7 days |
| Threat Intel | Only MISP used; no OpenCTI, TAXII, or in-house IOC sources | Phase 3: multi-source TI aggregation |
| Vuln | `host_posture_cache` staleness window (2 h) may miss recent scan updates | Reduce cache TTL or add invalidation on scan completion event |
| All | Industry percentile bands are static (updated annually) | Phase 3: live anonymised cohort pool with monthly refresh |

---

## Phase Roadmap

| Phase | Planned improvement |
|-------|-------------------|
| **v1 (May 2026)** | Wazuh API (active CVEs only) + CyIRIS MTTR + MISP direct + CyComp DB; data isolation fix |
| **v2 (June 2026)** | SIEM gap patch: UEBA anomalies + kill chain depth + coverage baseline |
| **Phase 3** | FP auto-close rate; TI feed freshness; multi-source TI; live cohort pool |
| **Phase 4** | Bundle CIS Controls v8 JSON; nightly NVD/MITRE sync for ext_benchmark |
| **Phase 5** | CSPI export to executive PDF report (extend `executive_report.py`) |

