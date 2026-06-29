# M03 — Role-Based Access Control (RBAC)
**File:** `backend/blueprints/rbac/manager.py`
**Run Date:** 2026-06-29

---

## Module Scope

Manages user-role mappings stored in `rbac.json`. Provides `get_user_role(email)`, `list_users()`, `set_user_role()`, `remove_user()`. Exposes `/api/rbac/users` (GET/POST/DELETE) with role-level enforcement. Three roles: `admin`, `analyst`, `viewer`.

---

## AI-Executable Tests (Automated)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `rbac_bp` imports cleanly | ✅ PASS | No import error |
| A1.02 | `get_user_role("admin")` → `"admin"` | ✅ PASS | Correct role returned |
| A1.03 | `get_user_role("viewer")` → `"viewer"` | ✅ PASS | |
| A1.04 | `get_user_role("unknown")` → `"viewer"` | ✅ PASS | Safe default |
| A1.05 | Viewer cannot POST `/api/rbac/users` → 403 | ✅ PASS | (OWASP A01 verified) |
| A1.06 | Admin can POST `/api/rbac/users` | ✅ PASS | |
| A1.07 | Missing email → 400 | ✅ PASS | Input validation enforced |
| A1.08 | Invalid role → 400 | ✅ PASS | Enum enforcement |
| A1.09 | `X-Role: admin` header bypass blocked | ✅ PASS | RBAC reads session, not headers |
| A1.10 | No hardcoded secrets in `manager.py` | ✅ PASS | Static scan clean |

---

## Manual Test Suite

### M-RBAC-01: Role Assignment Lifecycle
**Steps:**
1. Log in as admin
2. Navigate to Settings → Users
3. Create new user with `analyst` role
4. Log out; log in as new user
5. Verify analyst access: can trigger scans, cannot manage users
6. As admin, promote user to `admin`
7. Verify elevated access immediately reflected

### M-RBAC-02: Role Demotion
**Steps:**
1. Demote admin to `viewer`
2. Verify next request reflects viewer permissions
3. Verify viewer cannot access write endpoints

### M-RBAC-03: User Deletion
**Steps:**
1. Delete user from RBAC
2. Verify deleted user's session is invalidated on next request
3. Verify user no longer appears in `/api/rbac/users`
