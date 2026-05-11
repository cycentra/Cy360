# CyCentra 360 — Benchmark Intelligence Engine: Score Calculations Reference

**Version:** Post-Accuracy-Fix (May 2026)  
**Applies to:** `backend/blueprints/benchmark/routes.py`

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
| 2 | Internal Detection Posture (SIEM) | 20% | Correlation engine `/stats` + `/risk-scores` | Available when CySIEM is running |
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

**Source:** Correlation engine HTTP API at `http://127.0.0.1:8100`  
**Endpoints used:** `GET /stats`, `GET /risk-scores`

### Algorithm

```
score = 100  (start from perfect)

from /stats:
  critical_alerts (24 h window) : -3 each   cap -30
  open_incidents                : -2 each   cap -20

from /risk-scores (entity list):
  critical risk entities        : -5 each   cap -25
  high risk entities            : -2 each   cap -10

final = clamp(score, 0, 100)
```

**What is counted:** Only **currently open/active** incidents and **current 24-hour** alert counts. Closed or resolved incidents do not appear in `open_incidents`. Risk entity scores reflect current entity state.

**What this dimension does NOT count:** Historical resolved incidents, ASM findings, vulnerability CVEs, or MISP IOCs. Fully independent from all other dimensions.

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

## Data Isolation Guarantee (post-fix)

Each active, scored dimension reads from a strictly separate data source:

| Dimension | Unique data source | Shares data with |
|-----------|-------------------|-----------------|
| ASM | ASM scan JSON (external surface) | None |
| SIEM | Correlation engine `/stats`, `/risk-scores` | None |
| Compliance | `cy_compliance_controls` DB table | None |
| Vuln | Wazuh API + CyIRIS incidents DB | None |
| Threat Intel | MISP API | None |
| ext_benchmark | Suppressed when ASM + Compliance both active | Would share with ASM + Compliance |

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

## Phase Roadmap

| Phase | Planned improvement |
|-------|-------------------|
| **Current** | Wazuh API (active CVEs only) + CyIRIS MTTR + MISP direct + CyComp DB |
| **Phase 2** | Bundle CIS Controls v8 JSON; nightly NVD/MITRE sync for ext_benchmark |
| **Phase 3** | Live anonymised cohort pool in PostgreSQL; opt-in contributor data pipeline |
| **Phase 4** | CSPI export to executive PDF report (extend `executive_report.py`) |
