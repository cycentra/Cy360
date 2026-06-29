# M20 — Frontend Portal (React)
**Files:** `portal/src/`, `portal/vite.config.js`, `portal/package.json`
**Run Date:** 2026-06-29

---

## Module Scope

React 19 + Vite single-page application. 55+ pages/components across all platform modules. No TypeScript (plain JSX). Deployed as Docker container with Express static server.

**Key Files:**
- `App.jsx` (101 lines ✅ — was 471 lines; decomposed 2026-06-29)
- `core/constants.js` — `API_BASE`, `CYSCAN_URL`, `BASE_API_URL`
- `core/adapter.js` — `adaptCyCentraJSON()`
- `core/auth.js` — Auth state management
- `registry/aiProviders.js` — `AI_PROVIDERS`, `DEFAULT_PROMPTS`
- `registry/platformModules.js` — Module registry
- `sidebar/navConfig.jsx` — Navigation configuration
- `hooks/useAppState.js` — Global app state hook

**Pages (55+):**
Dashboard, SIEM Feed, SIEM Incidents, UEBA, Threat Hunting, ASM Scan, Scan History, Cases, Case Detail, Compliance Dashboard/Assessment/Findings/Reports/Live Alerts/Risk Register/Policy Documents, EDR Endpoints/Detections/Policies/YARA/Response/Installer, Assets, Hosts/Host Detail, Audit Trail, Benchmark, Marketplace, Integrations, Platform, AI Settings, System Settings/SSO, Login, Vulnerability, Use Cases, Guest Scan, Host Intelligence, Internal Exposure Dashboard

---

## AI-Executable Tests (Automated)

### A1 — Build Checks

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `App.jsx` ≤ 120 lines | ✅ PASS | Actual: 101 lines (fixed 2026-06-29; 4 components extracted) |
| A1.02 | `BASE_API_URL` or `API_BASE` exported in constants.js | ✅ PASS | `API_BASE = ""` (same-origin) |
| A1.03 | `CYSCAN_URL` exported | ✅ PASS | `https://cyasm.${_BASE_DOMAIN}` |
| A1.04 | `adaptCyCentraJSON` exported from adapter.js | ✅ PASS | Line 130 |
| A1.05 | `AI_PROVIDERS` exported from aiProviders.js | ✅ PASS | Line 8 |
| A1.06 | `DEFAULT_PROMPTS` exported from aiProviders.js | ✅ PASS | Line 62 |
| A1.07 | No hardcoded secrets in frontend source | ✅ PASS | Static scan clean |
| A1.08 | npm build (needs Docker/Node) | MANUAL | Cannot verify without Node.js in this env |
| A1.09 | No circular imports | MANUAL | Build required |
| A1.10 | dist/index.html exists | MANUAL | Build required |

**RESOLVED 2026-06-29:** `App.jsx` reduced from 471 → 101 lines. Four components extracted: `PageErrorBoundary.jsx`, `ScanHistoryDropdown.jsx`, `AppTopBar.jsx`, `AppRouter.jsx`. Suite 01 (1.12) and Suite 08 (8.06) now pass.

---

## Manual Test Suite

### M-FE-01: Login Flow
**Steps:**
1. Navigate to portal URL
2. Verify login page renders: CyCentra logo, Google/Microsoft login buttons
3. Click Google login — verify OAuth flow works
4. Verify dashboard loads after auth

### M-FE-02: Navigation
**Steps:**
1. Verify sidebar loads all modules based on user role
2. Click each sidebar item — verify correct page loads
3. Viewer: verify write-action buttons hidden or disabled
4. Analyst: verify scan trigger, case creation available
5. Admin: verify Settings accessible

### M-FE-03: SIEM Dashboard
**Steps:**
1. Navigate to SIEM → Dashboard
2. Verify KPI widgets: total incidents, open, closed, high-severity
3. Verify severity distribution chart renders
4. Verify incident feed updates without full page reload

### M-FE-04: SIEM Incident Management
**Steps:**
1. Navigate to SIEM → Incidents
2. Filter by severity=high — verify filter works
3. Click an incident — verify detail panel slides in
4. Update status in detail panel — verify change saves
5. Click Escalate — verify confirmation dialog appears

### M-FE-05: ASM Scan Page
**Steps:**
1. Navigate to ASM/Scan
2. Enter domain; select profile; click Scan
3. Verify progress indicator updates
4. Verify results render when scan completes
5. Verify "Download Report" button produces PDF

### M-FE-06: Compliance Assessment UI
**Steps:**
1. Navigate to Compliance → Assessment
2. Select ISO 27001; start questionnaire
3. Answer 5 questions; verify auto-save
4. Verify score updates in real-time as questions answered
5. Complete all questions; verify final score and gap analysis displayed

### M-FE-07: EDR Endpoint List
**Steps:**
1. Navigate to EDR → Endpoints
2. Verify endpoint table: hostname, OS, status, agent version, last seen
3. Click endpoint — verify detail panel opens
4. Verify process list, detections, and policies tabs work

### M-FE-08: CyMind Chat Overlay
**Steps:**
1. Click CyMind chat button (bottom-right)
2. Verify overlay opens
3. Type query: "What was the last critical incident?"
4. Verify CyMind responds with relevant context
5. Verify overlay can be minimized/closed

### M-FE-09: License Banner
**Steps:**
1. With a valid license: verify no banner, all features enabled
2. With expired license: verify LicenseBanner.jsx shows warning
3. With no license: verify portal restricts feature access

### M-FE-10: Responsive Layout
**Steps:**
1. Resize browser window to tablet width (768px)
2. Verify sidebar collapses to hamburger menu
3. Verify all page content reflows correctly
4. Resize to mobile (375px) — verify minimum viable layout

### M-FE-11: World Map Widget (Assets)
**Steps:**
1. Navigate to Assets
2. Verify WorldMapWidget renders with asset locations plotted
3. Click a location marker — verify asset detail appears
4. Verify filters (country, asset type) update map

### M-FE-12: Guest Scan Page
**Steps:**
1. Navigate to public guest scan URL (unauthenticated)
2. Verify GuestScanPage renders without auth
3. Enter domain and scan — verify limited results returned
4. Verify no internal data exposed to guest
