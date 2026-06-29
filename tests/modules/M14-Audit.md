# M14 — Audit Trail
**File:** `backend/blueprints/audit/routes.py`
**Run Date:** 2026-06-29

---

## Module Scope

Immutable audit trail for all significant platform actions (login, logout, role changes, case state changes, scan triggers, config changes). Used for compliance evidence (SOC 2, ISO 27001 A.8.15 — Logging).

**Endpoints:**
- `GET /api/audit` — Query audit events (with filters: user, action, date range)
- `GET /api/audit/export` — Export audit log as CSV/JSON
- `GET /api/audit/stats` — Audit statistics

---

## AI-Executable Tests (Automated)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `audit_bp` imports cleanly | ✅ PASS | Blueprint importable |
| A1.02 | AST syntax `audit/routes.py` | ✅ PASS | Compiles cleanly |
| A1.03 | Unauthenticated → 401 | ✅ PASS | Auth guard active |
| A1.04 | Viewer can GET audit log | ✅ PASS | Read access allowed |
| A1.05 | Auth events logged (from auth/oauth.py) | ✅ PASS | `auth_event()` writes JSON |
| A1.06 | Auth log schema: timestamp, email, result | ✅ PASS | Required fields present |

---

## Manual Test Suite

### M-AUDIT-01: Login Event Logging
**Steps:**
1. Log in and log out
2. Navigate to Audit Trail
3. Verify login event: `{action: "login", email, timestamp, provider, result: "success"}`
4. Verify logout event present

### M-AUDIT-02: Role Change Audit
**Steps:**
1. Change a user's role from viewer to analyst
2. Navigate to Audit Trail
3. Verify event: `{action: "role_change", target_email, old_role, new_role, performed_by, timestamp}`

### M-AUDIT-03: Case Action Audit
**Steps:**
1. Create, comment, and close a case
2. Navigate to Audit Trail → filter by case ID
3. Verify all 3 events logged with correct action types

### M-AUDIT-04: Audit Export
**Steps:**
1. Navigate to Audit Trail → Export
2. Export last 30 days as CSV
3. Open in spreadsheet — verify all columns correct
4. Export as JSON — verify valid JSON array

### M-AUDIT-05: Tamper Detection
**Steps:**
1. Attempt to DELETE an audit record directly via API
2. Verify 405 Method Not Allowed
3. Verify no audit records can be modified via API
