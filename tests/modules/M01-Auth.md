# M01 — Authentication Module
**File:** `backend/blueprints/auth/oauth.py`
**Run Date:** 2026-06-29

---

## Module Scope

Handles Google OAuth2 and Microsoft OAuth2 login flows, session creation, session validation, and authentication event logging. Provides `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/verify` endpoints plus a `get_user_role()` helper used across all blueprints.

Key components:
- Google OAuth flow (`/auth/login?provider=google`, `/auth/callback`)
- Microsoft OAuth flow (`/auth/login?provider=microsoft`, `/auth/callback`)
- Session management (Flask session, `user_email`, `user_name`)
- Auth event logging (`auth_event()` writes JSON to `AUTH_LOG_FILE`)
- `get_user_role(email)` → queries RBAC JSON; defaults to `"viewer"`

---

## AI-Executable Tests (Automated)

### A1 — Static/Code Analysis

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | AST syntax check `auth/oauth.py` | ✅ PASS | `python3 -m py_compile` exits 0 |
| A1.02 | `auth_bp` import cleanly | ✅ PASS | `from blueprints.auth.oauth import auth_bp` succeeds |
| A1.03 | No `from app import` (circular guard) | ✅ PASS | 0 occurrences |
| A1.04 | `get_user_role()` defined | ✅ PASS | Function present in module |
| A1.05 | `auth_event()` defined | ✅ PASS | Writes JSON with timestamp/email/result |
| A1.06 | `AUTH_LOG_FILE` configured | ✅ PASS | Env/config key present |
| A1.07 | No hardcoded OAuth secrets | ✅ PASS | Static scan — 0 matches |

### A2 — RBAC Behavior (pytest `test_correlation_rules.py` setup)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A2.01 | `get_user_role("admin@x.com")` → `"admin"` | ✅ PASS | RBAC resolves known admin |
| A2.02 | `get_user_role("viewer@x.com")` → `"viewer"` | ✅ PASS | RBAC resolves known viewer |
| A2.03 | `get_user_role("unknown@x.com")` → `"viewer"` | ✅ PASS | Defaults to viewer for unknown |

### A3 — Session Guards

| # | Test | Result | Detail |
|---|------|--------|--------|
| A3.01 | `session["user_email"] = ""` → 401 | ✅ PASS | Empty email rejected by `require_login` |
| A3.02 | `session["user_email"] = None` → 401 | ✅ PASS | None email rejected |
| A3.03 | No session → 401/302 on all `/api/` | ✅ PASS | Auth guard covers all routes |

---

## Manual Test Suite

### M-Auth-01: Google OAuth End-to-End
**Steps:**
1. Navigate to portal login page; click "Login with Google"
2. Complete Google OAuth consent flow with valid credentials
3. Verify redirect back to portal with active session
4. Confirm user appears in RBAC with correct role
5. Check `AUTH_LOG_FILE` for JSON entry: `{timestamp, email, provider, result:"success"}`

**Expected:** Session established; dashboard loads; audit log entry written.

### M-Auth-02: Microsoft OAuth End-to-End
**Steps:**
1. Navigate to portal login page; click "Login with Microsoft"
2. Complete Microsoft OAuth consent flow
3. Verify session and redirect
4. Confirm auth log has `"provider":"microsoft"` entry

### M-Auth-03: Invalid OAuth Callback
**Steps:**
1. Tamper with OAuth callback `state` or `code` parameter
2. Verify portal rejects with error page (not 500)
3. Confirm no session created

### M-Auth-04: Session Expiry
**Steps:**
1. Log in successfully
2. Wait for session timeout (or manually expire session cookie)
3. Attempt to access protected route
4. Verify redirect to login or 401 response

### M-Auth-05: Concurrent Sessions
**Steps:**
1. Log in with User A in Browser 1
2. Log in with same User A in Browser 2
3. Verify both sessions are valid (or that prior session is invalidated if single-session policy is enforced)
