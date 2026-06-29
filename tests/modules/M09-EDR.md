# M09 — Endpoint Detection & Response (EDR / CyEDR)
**Files:** `backend/blueprints/edr/`, `backend/agent/cyedr_agent.py`
**Run Date:** 2026-06-29

---

## Module Scope

CyEDR provides host-based telemetry collection, threat detection via YARA rules, endpoint policy enforcement, and automated response. Integrates with the SIEM correlation engine via `cysiemstack/edr_bridge.py`.

**Components:**
- `routes.py` — EDR API endpoints
- `normalizer.py` — Alert normalisation from agent telemetry
- `policy_engine.py` — Endpoint policy evaluation
- `response_orchestrator.py` — Automated response actions
- `confidence_matrix.py` — Detection confidence scoring
- `cyedr_agent.py` — Agent-side collection script

**Agent:**
- Packages: `.deb`, `.rpm`, `.pkg`, `.msi`
- Current version: `1.0.103`
- Platforms: Linux (amd64/arm64/x86_64/aarch64), macOS (intel64/arm64), Windows

**Key Endpoints:**
- `GET /api/edr/endpoints` — List enrolled endpoints
- `GET /api/edr/endpoints/<id>` — Endpoint detail
- `GET /api/edr/detections` — Detection feed
- `GET /api/edr/policies` — Policy list
- `POST /api/edr/policies` — Create policy
- `GET /api/edr/yara` — YARA rule management
- `POST /api/edr/yara` — Deploy YARA rule
- `POST /api/edr/response` — Trigger response action

---

## AI-Executable Tests (Automated)

### A1 — Static Analysis

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `edr_bp` imports cleanly | ✅ PASS | Blueprint importable |
| A1.02 | AST syntax all `edr/*.py` | ✅ PASS | All files compile |
| A1.03 | `normalizer.py` defines `normalise()` | ✅ PASS | Core function present |
| A1.04 | `policy_engine.py` defines `evaluate_policy()` | ✅ PASS | |
| A1.05 | `confidence_matrix.py` defines scoring weights | ✅ PASS | Confidence matrix present |
| A1.06 | Unauthenticated → 401 | ✅ PASS | Auth guard active |
| A1.07 | Viewer cannot POST policies/YARA | ✅ PASS | Min analyst enforced |

### A2 — Normalizer Tests

| # | Test | Result | Detail |
|---|------|--------|--------|
| A2.01 | `normalise()` preserves `rule_id` as string | ✅ PASS | Verified in test_resource_monitor.py context |
| A2.02 | `normalise()` preserves `agent_name` | ✅ PASS | |
| A2.03 | Level-7 alerts not dropped | ✅ PASS | Resource monitor alerts pass through |
| A2.04 | Level-10 alerts not dropped | ✅ PASS | Sustained breach escalation passes |

---

## Manual Test Suite

### M-EDR-01: Agent Enrollment
**Steps:**
1. Navigate to EDR → Agent Installer
2. Download installer for target platform (Linux/macOS/Windows)
3. Run installer on test endpoint
4. Verify endpoint appears in EDR → Endpoints within 2 minutes
5. Verify endpoint status: online, agent version, platform

### M-EDR-02: Threat Detection (YARA)
**Steps:**
1. Navigate to EDR → YARA Rules → Add Rule
2. Upload a YARA rule targeting a known test file signature
3. Create test file matching the YARA signature on enrolled endpoint
4. Verify detection appears in EDR → Detections within 5 minutes
5. Verify detection confidence score populated

### M-EDR-03: Endpoint Policy
**Steps:**
1. Navigate to EDR → Policies → Create Policy
2. Define policy: block USB storage, alert on powershell -enc
3. Apply policy to test endpoint group
4. Plug in USB device on test endpoint
5. Verify block action triggered and detection logged

### M-EDR-04: Automated Response
**Steps:**
1. Navigate to EDR → Response → Configure Action
2. Set: if detection severity = critical AND confidence > 0.8 → isolate host
3. Trigger a critical detection on test endpoint
4. Verify host isolation occurs (network adapter disabled except for management)
5. Verify SOC alerted to isolation

### M-EDR-05: Endpoint Detail Page
**Steps:**
1. Click an enrolled endpoint
2. Verify endpoint detail panel shows: OS, agent version, last seen, policies applied
3. Verify process list, open ports, and installed packages visible
4. Verify detection history timeline renders

### M-EDR-06: Agent Groups
**Steps:**
1. Navigate to EDR → Agent Groups
2. Create group "Linux Servers"
3. Assign 5 test endpoints to the group
4. Verify group policy applies to all members
