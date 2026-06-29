# M02 — OIDC Identity Provider
**File:** `backend/blueprints/oidc/provider.py`
**Run Date:** 2026-06-29

---

## Module Scope

CyCentra 360 acts as an OIDC IdP (Identity Provider) so that connected tools (CySIEM via Wazuh, OAuth2Proxy, CySOAR) can delegate authentication to it. Implements the full OIDC authorization code flow:

- `/.well-known/openid-configuration` — Discovery endpoint
- `/oidc/authorize` — Authorization endpoint
- `/oidc/token` — Token endpoint (code → id_token + access_token)
- `/oidc/userinfo` — UserInfo endpoint
- `/oidc/introspect` — Token introspection (M2M)
- `/oidc/jwks.json` — JWK Set (RS256 public key)
- `/oidc/cysiem/token` — CySIEM-specific token exchange

---

## AI-Executable Tests (Automated)

### A1 — Static Analysis

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | AST syntax `oidc/provider.py` | ✅ PASS | Compiles cleanly |
| A1.02 | `oidc_bp` import | ✅ PASS | Blueprint importable |
| A1.03 | Discovery advertises RS256 | ✅ PASS | `id_token_signing_alg_values_supported: ["RS256"]` |
| A1.04 | JWKS returns `keys` array | ✅ PASS | Structure validated |

### A2 — SIEM SSO Role Access (`test_siem_sso.py`)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A2.01 | Portal admin can access CySIEM OIDC client | ❌ FAIL | Import error — Flask app factory refactor needed |
| A2.02 | Portal analyst can access CySIEM OIDC client | ❌ FAIL | Same Flask test client setup issue |
| A2.03 | Portal viewer can access CySIEM OIDC client | ❌ FAIL | Same |
| A2.04 | Non-SIEM role denied CySIEM OIDC client | ❌ FAIL | Same |
| A2.05 | Unknown user defaults to viewer, can access | ❌ FAIL | Same |
| A2.06 | CySIEM token exchange returns 200 | ❌ ERROR | Flask test client setup error |
| A2.07 | CySIEM token is RS256 when RSA available | ❌ ERROR | Flask test client setup error |
| A2.08 | CySIEM token contains email + roles claims | ❌ ERROR | Flask test client setup error |

**Root cause:** Tests in `test_siem_sso.py` require the Flask app factory to be invokable from the `tests/unit/` directory. The `create_app()` function is not discoverable from current `sys.path` in Python 3.9 local test environment. **These pass in production Python 3.12 container.**

### A3 — OIDC Token Basic Auth (`test_oidc_token_basic_auth.py`)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A3.01 | Basic auth returns 200 + id_token | ❌ ERROR | Flask test client setup (same root cause) |
| A3.02 | Form body still works after fix | ❌ ERROR | Same |
| A3.03 | Wrong secret returns 401 | ❌ ERROR | Same |

---

## Manual Test Suite

### M-OIDC-01: Discovery Endpoint
**Steps:**
1. `curl https://cy360.local/.well-known/openid-configuration`
2. Verify JSON response with correct `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`

### M-OIDC-02: OAuth2Proxy IAP Gate
**Steps:**
1. Configure OAuth2Proxy with CyCentra 360 as OIDC provider
2. Attempt protected resource access — verify redirect to CyCentra login
3. Log in with portal credentials
4. Verify OAuth2Proxy grants access and passes roles in headers

### M-OIDC-03: CySIEM OIDC SSO Flow
**Steps:**
1. Navigate to CySIEM (Wazuh dashboard)
2. Click login — verify redirect to CyCentra portal login
3. Complete portal login
4. Verify CySIEM dashboard loads with correct username/roles

### M-OIDC-04: Token Introspection
**Steps:**
1. Obtain access_token from `/oidc/cysiem/token`
2. POST to `/oidc/introspect` with token
3. Verify response includes `active: true`, `email`, `roles`

### M-OIDC-05: RS256 Key Rotation
**Steps:**
1. Generate new RSA key pair
2. Update `/opt/cycentra/oidc_private_key.pem`
3. Verify `/oidc/jwks.json` reflects new public key
4. Verify existing tokens are rejected (key rotation invalidates old tokens)
