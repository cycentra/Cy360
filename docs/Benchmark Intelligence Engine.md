# CyCentra 360 — Benchmark Intelligence Engine — Patch Set

## What this adds

A new **Security Posture Benchmark** section to the CyCentra 360 portal —
sidebar item "Posture Benchmark" under a new "SECURITY POSTURE" nav group.

The page shows (in the order the calculation is performed):

| # | Section | Data source |
|---|---------|-------------|
| 1 | **CSPI gauge + grade + percentile** | Composite of all enabled sources |
| 2 | **Industry benchmark chart** | Customer score placed on cohort band chart |
| 3 | **Per-dimension score cards** | ASM → SIEM → Compliance → Vuln → Threat Intel → CIS/NIST |
| 4 | **Source weight configurator** | Toggle sources on/off, adjust weights |
| 5 | **Cohort selector** | Industry sector, organisation size, opt-in toggle |

---

## Patch files

| File | What it creates/patches |
|------|-------------------------|
| `PATCH_1_backend_benchmark.py` | Creates `backend/blueprints/benchmark/routes.py` — 4 API endpoints |
| `PATCH_2_frontend_BenchmarkPage.jsx` | Creates `portal/src/pages/benchmark/BenchmarkPage.jsx` |
| `PATCH_3_wiring.py` | 6 targeted str_replace patches across `app.py`, `App.jsx`, `navConfig.jsx` |
| `deploy_benchmark.sh` | End-to-end deployment script (calls all three patches) |

---

## Deployment options

### Option A — one-shot script (recommended)

```bash
# From repo root:
chmod +x benchmark-patch/deploy_benchmark.sh
./benchmark-patch/deploy_benchmark.sh
```

### Option B — manual, step by step

```bash
# 1. Create backend blueprint
mkdir -p backend/blueprints/benchmark
touch    backend/blueprints/benchmark/__init__.py
python3  benchmark-patch/PATCH_1_backend_benchmark.py

# 2. Create frontend page
mkdir -p portal/src/pages/benchmark
cp benchmark-patch/PATCH_2_frontend_BenchmarkPage.jsx \
   portal/src/pages/benchmark/BenchmarkPage.jsx

# 3. Apply wiring patches (auto str_replace)
python3 benchmark-patch/PATCH_3_wiring.py .

# 4. Restart + rebuild
sudo systemctl restart cycentra-backend
cd portal && npm run build
```

---

## What PATCH_3 changes (the wiring)

### `backend/app.py` — 2 lines added

```python
# After existing imports:
from blueprints.benchmark.routes   import benchmark_bp

# In create_app() blueprint registration:
# benchmark_bp added to the tuple
```

### `portal/src/App.jsx` — 2 changes

```jsx
// Import added:
import { BenchmarkPage } from './pages/benchmark/BenchmarkPage.jsx';

// Route added in page-render block:
{activeTab==="benchmark" && <BenchmarkPage />}
```

### `portal/src/sidebar/navConfig.jsx` — 2 changes

```jsx
// New icon constant:
const SvgBench = <svg .../>

// New nav section inserted before ACTIONS:
{
  section: "SECURITY POSTURE",
  items: [
    { id: "benchmark", label: "Posture Benchmark", icon: SvgBench, accent: "#00e5a0" },
  ],
},
```

---

## API endpoints (new, all require auth session)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/benchmark/score` | CSPI composite + per-dimension breakdown + cohort percentile |
| `GET` | `/api/benchmark/config` | Tenant's current source weights and enabled flags |
| `PUT` | `/api/benchmark/config` | Save tenant config (partial update, JSON body) |
| `GET` | `/api/benchmark/industries` | All industry cohort band data for the chart |

---

## Score sources and data paths

| Dimension | Data pulled from |
|-----------|-----------------|
| ASM | `/var/log/cycentra/cy-asm/scans/<tenant>/scan_*.json` |
| SIEM | `http://127.0.0.1:8100/risk/summary` (correlation engine) |
| Compliance | `cy_compliance_controls` PostgreSQL table (falls back to ASM estimate) |
| Vuln Mgmt | ASM scan JSON — CVSS+EPSS weighted open findings |
| Threat Intel | `http://127.0.0.1:8100/misp/stats` (correlation engine) |
| CIS/NIST | Weighted average of Compliance + ASM (Phase 1 estimate) |

All collectors are wrapped in try/except — a missing data source returns
`score: null` and the dimension is shown with a "—" placeholder.
Stale data (>48 h old) contributes at 80% weight with a STALE badge.

---

## Config storage

Tenant config is stored at:
```
/opt/cycentra/benchmark_config_<tenant_domain>.json
```

Same pattern as `schedules.json` — no DB migration required.

---

## Industry cohort data

Bundled static JSON in `routes.py` (`_INDUSTRY_COHORTS` dict).
Eight sectors: Finance, Healthcare, Manufacturing, Logistics, Technology,
Public Sector, Energy, Retail — plus a General (all-sector) baseline.

Bands represent P10/P25/P50/P75/P90 CSPI scores derived from:
- ENISA Threat Landscape 2024
- CIS Benchmark SecureSuite (anonymised)
- NCSC-NL annual reports
- BSI Lagebericht
- Verizon DBIR 2024

Update the `bands` arrays in `_INDUSTRY_COHORTS` each Q1 as new annual
reports are published.

---

## Phase roadmap

| Phase | What to add next |
|-------|-----------------|
| **Phase 2** | Bundle CIS Controls v8 JSON; nightly scheduler job for NVD/MITRE sync |
| **Phase 3** | Live anonymised cohort pool in PostgreSQL; opt-in data pipeline |
| **Phase 4** | Export CSPI to executive PDF report (extend `executive_report.py`) |
