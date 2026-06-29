# M05 — CySIEM Correlation Engine
**Files:** `backend/cysiemstack/correlation_engine/correlator.py`, `siem_proxy.py`
**Run Date:** 2026-06-29

---

## Module Scope

The core SIEM engine. Ingests Wazuh alerts, normalises them, correlates across 56 rules (CR-001→CR-056), runs UEBA detectors, scores risk, enriches with TI (MISP, VirusTotal, AbuseIPDB, GreyNoise), and raises incidents. Proxied through `siem_proxy.py` (13 endpoints).

**Components:**
- `normaliser.py` — Wazuh alert normalisation
- `correlator.py` + 56 correlation rules in `ALL_RULES`
- `ueba.py` — 17 user UEBA detectors + 3 host detectors
- `risk_scorer.py` — Composite risk score computation
- `ti_enricher.py` — Threat intelligence enrichment (MISP/VT/AbuseIPDB/GreyNoise)
- `ingestor.py` — Alert ingestion pipeline
- `grouper.py` — Alert clustering/grouping
- `fp_pattern_store.py` — False positive pattern suppression
- `campaign_correlator.py` — Multi-incident campaign correlation
- `gap_analyser.py` — MITRE ATT&CK coverage gap analysis

**SIEM Proxy Endpoints:**
- `GET /api/siem/health` — Engine health
- `GET /api/siem/stats` — Dashboard KPIs
- `GET /api/siem/incidents` — List incidents
- `DELETE /api/siem/incidents` — Purge
- `POST /api/siem/incidents/batch-close` — Bulk close
- `GET /api/siem/incidents/<id>` — Incident detail
- `PATCH /api/siem/incidents/<id>` — Update incident
- `GET /api/siem/incidents/<id>/audit` — Incident audit log
- `POST /api/siem/incidents/<id>/transition` — State machine transition
- `POST /api/siem/incidents/<id>/escalate` — Escalate to CySOAR
- `GET /api/siem/ueba` — UEBA risk scores
- `GET /api/siem/rules` — Correlation rule catalog
- `GET /api/siem/feed` — Alert feed

---

## AI-Executable Tests (Automated)

### A1 — Correlation Rule Registry

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `ALL_RULES` count == 56 | ✅ PASS | Exactly 56 rules |
| A1.02 | All IDs unique | ✅ PASS | No duplicates |
| A1.03 | All IDs sequential CR-001→CR-056 | ✅ PASS | No gaps |
| A1.04 | All IDs start with `CR-` | ✅ PASS | Naming convention enforced |
| A1.05 | All severities valid | ✅ PASS | low/medium/high/critical only |
| A1.06 | All tactics non-empty | ✅ PASS | MITRE ATT&CK alignment |
| A1.07 | All windows > 0 | ✅ PASS | Positive correlation window |
| A1.08 | Names and descriptions present | ✅ PASS | Human-readable metadata |

### A2 — Safety Tests (165 parametrized)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A2.01 | `match([])` → None for all 56 rules | ✅ PASS | Empty list safety |
| A2.02 | `match([null_alert])` → None or dict, never raises | ✅ PASS | Null-field robustness |
| A2.03 | Non-None result has `key_alert_ids, detail, confidence` | ✅ PASS | Contract enforced |

### A3 — Individual Rule Validation (446 tests — all PASSED)

| Rule Range | Tests | Result |
|------------|-------|--------|
| CR-001 to CR-010 | 38 | ✅ ALL PASS |
| CR-011 to CR-020 | 37 | ✅ ALL PASS |
| CR-021 to CR-030 | 32 | ✅ ALL PASS |
| CR-031 to CR-040 | 34 | ✅ ALL PASS |
| CR-041 to CR-050 | 42 | ✅ ALL PASS |
| CR-051 to CR-056 | 27 | ✅ ALL PASS |

**Notable accuracy checks:**
- CR-001: 5 failures → fires; 4 → None ✅
- CR-011: confidence == 0.95 ✅
- CR-041: confidence == 0.97 (Shadow Copy Deletion) ✅
- CR-055: confidence == 0.95 (DCSync) ✅
- CR-056: 2+ resource alerts → fires; 1 → None; confidence == 0.80 ✅

### A4 — Accuracy Checks

| # | Test | Result | Detail |
|---|------|--------|--------|
| A4.01 | CR-001 threshold 5 fires, 4 doesn't | ✅ PASS | |
| A4.02 | CR-011 confidence == 0.95 | ✅ PASS | Event log cleared |
| A4.03 | CR-041 confidence == 0.97 | ✅ PASS | Shadow copy deletion |
| A4.04 | CR-055 confidence == 0.95 | ✅ PASS | DCSync attack |
| A4.05 | CR-056 fires on 2+ resource alerts | ✅ PASS | High resource utilization |
| A4.06 | FP auto-close: 95.0 ≥ 90.0 → closed | ✅ PASS | FP formula correct |
| A4.07 | FP keep-open: 5.0 < 90.0 → open | ✅ PASS | |

### A5 — SIEM Proxy

| # | Test | Result | Detail |
|---|------|--------|--------|
| A5.01 | No `from app import` in `siem_proxy.py` | ✅ PASS | Comment on line 7, not import |
| A5.02 | `siem_bp` importable | ✅ PASS | |
| A5.03 | POST `/api/siem/incidents/<id>/escalate` → 401 unauth | ✅ PASS | |
| A5.04 | POST `/api/siem/incidents/<id>/escalate` → 403 viewer | ✅ PASS | |

---

## Manual Test Suite

### M-SIEM-01: Alert Ingestion
**Steps:**
1. Trigger a test Wazuh alert (e.g., failed SSH login spike)
2. Verify alert appears in CySIEM feed within 30 seconds
3. Verify alert is normalised (agent_name, rule_id, severity, timestamp preserved)

### M-SIEM-02: Correlation Rule Fire
**Steps:**
1. Generate 5 SSH auth failures followed by 1 success from same source
2. Verify CR-001 (SSH Brute Force) fires — incident created
3. Check incident detail: `confidence ≥ 0.25`, `tactics: ["Credential Access"]`

### M-SIEM-03: Incident Lifecycle
**Steps:**
1. Open a SIEM incident
2. Transition: `new → in_review → held → closed`
3. Verify each transition recorded in audit log
4. Verify `POST /api/siem/incidents/<id>/transition` returns 200 at each step

### M-SIEM-04: SOAR Escalation
**Steps:**
1. Open a high-severity incident
2. Click "Escalate to SOAR"
3. Verify `/api/siem/incidents/<id>/escalate` creates CySOAR ticket
4. Verify incident status updates to `escalated`

### M-SIEM-05: Batch Close
**Steps:**
1. Select 10+ incidents with "false positive" reason
2. Submit batch close
3. Verify all selected incidents closed; FP pattern store updated
4. Verify similar future alerts are auto-suppressed

### M-SIEM-06: Campaign Correlation
**Steps:**
1. Generate alerts across multiple hosts that match a campaign pattern
2. Verify `campaign_correlator.py` links incidents into a campaign
3. Verify campaign view shows unified timeline
