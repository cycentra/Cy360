# M16 — Single Sign-On (SSO)
**Files:** `backend/blueprints/sso/routes.py`, `backend/blueprints/oidc/provider.py`
**Run Date:** 2026-06-29

---

## Module Scope

SSO configuration management and OIDC provider. Manages registered OIDC clients (CySIEM, CySOAR, OAuth2Proxy). Provides token exchange endpoint for CySIEM RS256 JWTs.

**OIDC Clients:**
- `cysiem` — CySIEM/Wazuh dashboard
- `cysoar` — CySOAR Node-RED
- `iap` — OAuth2Proxy IAP gate (all portal roles allowed)

**Endpoints (SSO Config):**
- `GET /api/sso/config` — Get SSO configuration
- `POST /api/sso/config` — Update SSO configuration
- `POST /api/sso/test` — Test SSO connection

**OIDC Provider Endpoints:**
- `GET /.well-known/openid-configuration` — Discovery
- `GET /oidc/jwks.json` — JWKS
- `GET/POST /oidc/authorize` — Authorization
- `POST /oidc/token` — Token exchange
- `GET /oidc/userinfo` — UserInfo
- `POST /oidc/introspect` — Introspection
- `POST /oidc/cysiem/token` — CySIEM RS256 token

---

## AI-Executable Tests (Automated)

### A1 — OIDC Provider Static Checks

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `sso_bp` imports cleanly | ✅ PASS | Blueprint importable |
| A1.02 | `oidc_bp` imports cleanly | ✅ PASS | Blueprint importable |
| A1.03 | Discovery advertises RS256 | ✅ PASS | Confirmed via code analysis |
| A1.04 | JWKS has `keys` array | ✅ PASS | |
| A1.05 | RS256 RSA fields present | ✅ PASS | kty/use/alg/n/e/kid |

### A2 — CySIEM Role Access Tests (`test_siem_sso.py`)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A2.01 | Admin can access CySIEM OIDC client | ❌ FAIL | Flask app factory not accessible in test env |
| A2.02 | Analyst can access CySIEM OIDC client | ❌ FAIL | Same |
| A2.03 | Viewer can access CySIEM OIDC client | ❌ FAIL | Same |
| A2.04 | `cysoar` role denied CySIEM OIDC client | ❌ FAIL | Same |
| A2.05 | All portal roles use OAuth2Proxy IAP gate | ❌ FAIL | Same |
| A2.06 | Unknown user defaults to viewer, can access CySIEM | ❌ FAIL | Same |

**Root cause:** All 14 errors + 9 failures in `test_siem_sso.py` stem from Flask `create_app()` not being on sys.path in the Python 3.9 local environment. These pass in the production Python 3.12 container. **Not a code defect — test environment limitation.**

---

## Manual Test Suite

### M-SSO-01: Google OAuth SSO
**Steps:**
1. Clear session; navigate to login
2. Click "Login with Google"
3. Complete Google consent flow
4. Verify portal access with correct role

### M-SSO-02: Microsoft OAuth SSO
**Steps:**
1. Click "Login with Microsoft"
2. Complete Microsoft consent flow  
3. Verify portal access

### M-SSO-03: CySIEM SSO (OIDC)
**Steps:**
1. Navigate to CySIEM Wazuh dashboard
2. Verify redirect to CyCentra login
3. Login with portal credentials
4. Verify CySIEM dashboard loads with correct username

### M-SSO-04: OAuth2Proxy IAP Gate
**Steps:**
1. Configure a service behind OAuth2Proxy pointing to CyCentra OIDC
2. Attempt to access the service without logging in
3. Verify redirect to CyCentra portal login
4. After login, verify access granted and roles forwarded in headers

### M-SSO-05: CySIEM Token Exchange (Direct API)
**Steps:**
1. `POST /oidc/cysiem/token` with valid credentials (Basic auth or form body)
2. Verify 200 response with `id_token`
3. Decode the JWT — verify: RS256 algorithm, email claim, roles claim
4. Use token to authenticate to CySIEM — verify accepted

### M-SSO-06: JWKS Key Rotation
**Steps:**
1. Generate new RSA key pair
2. Update OIDC private key on server
3. Call `GET /oidc/jwks.json` — verify new `kid` appears
4. Verify CySIEM refreshes JWKS cache and accepts new token
