# M10 — Platform Management
**Files:** `backend/blueprints/platform/routes.py`, `compose.py`, `docker_utils.py`, `state.py`
**Run Date:** 2026-06-29

---

## Module Scope

Manages Docker-based platform module lifecycle (install, uninstall, start, stop, status, logs). Valid modules: `cysoar`, `cymisp`. Provides platform status dashboard with health of each module.

**Endpoints:**
- `GET /api/platform/status` — Status of all modules (`{cymisp, cysoar}`)
- `POST /api/platform/install/<module>` — Pull and start module
- `POST /api/platform/uninstall/<module>` — Stop and remove module
- `GET /api/platform/logs/<module>` — Streaming logs
- `GET /api/platform/extensions` — Platform extensions list

---

## AI-Executable Tests (Automated)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `platform_bp` imports cleanly | ✅ PASS | Blueprint importable |
| A1.02 | `VALID_MODULES = {cysoar, cymisp}` | ✅ PASS | CyCases is built-in; not in VALID_MODULES |
| A1.03 | Platform status returns `{cymisp, cysoar}` | ✅ PASS | E2E schema check |
| A1.04 | Platform status does NOT include `cyiris` | ✅ PASS | Deprecated module removed |
| A1.05 | Unauthenticated → 401 | ✅ PASS | Auth guard active |
| A1.06 | Viewer cannot install modules → 403 | ✅ PASS | Admin-only enforced |

---

## Manual Test Suite

### M-PLATFORM-01: CySOAR Install
**Steps:**
1. Log in as admin
2. Navigate to Platform → Modules → CySOAR
3. Click Install
4. Verify Docker container pulls and starts
5. Verify status changes to "running"
6. Navigate to CySOAR → verify Node-RED dashboard loads

### M-PLATFORM-02: CyMISP Install
**Steps:**
1. Navigate to Platform → Modules → CyMISP
2. Click Install
3. Verify MISP container pulls and starts
4. Verify `/api/platform/status` shows `cymisp: "running"`
5. Test MISP connection via Integrations → MISP → Test

### M-PLATFORM-03: Module Uninstall
**Steps:**
1. Uninstall CySOAR
2. Verify container stops and is removed
3. Verify status shows `cysoar: "not_installed"`
4. Verify CySOAR-dependent features (SOAR escalation) gracefully degrade

### M-PLATFORM-04: Streaming Logs
**Steps:**
1. With CySOAR running, click "View Logs"
2. Verify logs stream in real-time (Server-Sent Events or WebSocket)
3. Verify log entries are from correct container
