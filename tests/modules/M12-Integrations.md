# M12 — Integration Health Monitor
**Files:** `backend/blueprints/integrations/routes.py`, `health.py`
**Run Date:** 2026-06-29

---

## Module Scope

Monitors health of all platform integrations (Wazuh, SIEM Engine, CyMind, CySOAR, CyMISP, and marketplace integrations). Auto-raises SIEM incidents on integration failures. Runs on APScheduler with configurable interval.

**Check Functions:**
- `check_wazuh()` — Auth probe + ingest gap check
- `check_siem_engine()` — HTTP health endpoint probe
- `check_cymind()` — CyMind health probe
- `check_misp()` — MISP version endpoint probe
- `check_cysoar()` — CySOAR Node-RED probe
- `check_marketplace_integrations()` — Per-installed-integration health

**Endpoints:**
- `GET /api/integrations/health` — All integration statuses
- `GET /api/integrations/health/<name>` — Single integration status
- `POST /api/integrations/health/check` — Trigger manual check (analyst+)
- `GET /api/integrations/health/config` — Scheduler config (admin)
- `POST /api/integrations/health/config` — Update interval (admin)

---

## AI-Executable Tests (Automated)

### A1 — Check Functions (`test_integration_health.py`)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `check_wazuh()` ok when auth succeeds + recent alerts | ✅ PASS | |
| A1.02 | `check_wazuh()` down when non-200 response | ✅ PASS | |
| A1.03 | `check_wazuh()` down when connection refused | ✅ PASS | |
| A1.04 | `check_wazuh()` degraded when ingest gap exceeds window | ✅ PASS | |
| A1.05 | `check_wazuh()` ok when gap within window | ✅ PASS | |
| A1.06 | `check_wazuh()` result has required keys | ✅ PASS | |
| A1.07 | `check_siem_engine()` ok when 200 | ✅ PASS | |
| A1.08 | `check_siem_engine()` degraded when non-200 | ✅ PASS | |
| A1.09 | `check_siem_engine()` down when connection error | ❌ FAIL | `get_misp_config` API changed — function signature mismatch |
| A1.10 | `check_cymind()` skipped when not enabled | ✅ PASS | |
| A1.11 | `check_cymind()` ok when health 200 | ✅ PASS | |
| A1.12 | `check_cymind()` down when health fails | ✅ PASS | |
| A1.13 | `check_misp()` skipped when config None | ❌ FAIL | `get_misp_config` renamed/moved |
| A1.14 | `check_misp()` skipped when mode disabled | ❌ FAIL | Same root cause |
| A1.15 | `check_misp()` ok when version 200 | ❌ FAIL | Same |
| A1.16 | `check_cysoar()` down when connection refused | ❌ FAIL | Import path changed |

**Root cause for A1.09/A1.13-A1.16:** `get_misp_config()` was refactored and its import path changed. `test_integration_health.py` patches the old location. Tests need `mock.patch` target updated to new location.

### A2 — Incident Schema

| # | Test | Result | Detail |
|---|------|--------|--------|
| A2.01 | `raise_integration_incident()` executes INSERT | ❌ FAIL | Same import/mock path issue |
| A2.02 | Incident ID has `integ-` prefix | ✅ PASS | |
| A2.03 | ID is 8 hex chars after prefix | ✅ PASS | |
| A2.04 | Same name → same deterministic ID | ✅ PASS | |

### A3 — Marketplace Health Map

| # | Test | Result | Detail |
|---|------|--------|--------|
| A3.01 | Returns builtin map when no custom catalog | ✅ PASS | |
| A3.02 | Custom ingest_gap item added | ✅ PASS | |
| A3.03 | Custom http item added | ✅ PASS | |
| A3.04 | Builtin takes precedence over custom (same ID) | ✅ PASS | |
| A3.05 | Items without health_config ignored | ✅ PASS | |
| A3.06 | Corrupt catalog returns builtin only | ✅ PASS | |

---

## Manual Test Suite

### M-INT-01: Integration Dashboard
**Steps:**
1. Navigate to Integrations → Health Monitor
2. Verify all integrations listed with status badges (ok/degraded/down/skipped)
3. Verify last-checked timestamp for each

### M-INT-02: Manual Health Check Trigger
**Steps:**
1. Click "Check Now" (analyst role)
2. Verify status updates within 10 seconds
3. Verify "last checked" timestamp updates

### M-INT-03: Auto-Incident on Failure
**Steps:**
1. Stop Wazuh manager service temporarily
2. Wait for next scheduled health check
3. Verify SIEM incident created: "wazuh health check failed"
4. Restart Wazuh — verify incident auto-closed on next check (if configured)

### M-INT-04: Scheduler Interval Config
**Steps:**
1. Navigate to Integrations → Health → Config (admin)
2. Change check interval from 5 minutes to 1 minute
3. Verify checks run at new interval
4. Verify minimum interval floor is enforced (tests verify 1-min minimum)
