# CyCentra 360 — SSO Troubleshooting Guide

This document records all SSO integration issues discovered and resolved during the
April 2026 integration sprint (cycentra360 v1.0.220–v1.0.225, CyIRIS v1.0.8–v1.0.15).

---

## Architecture Overview

```
Browser → nginx (cysiem/cyiris/cysoc/cyasm) 
        → auth_request /oauth2/auth 
        → cy-proxy (oauth2-proxy, 127.0.0.1:4180)
        → validates session cookie (domain: .BASE_DOMAIN)
        → returns 200 + X-Auth-Request-Email header

nginx sets:
  X-Proxy-User: $upstream_http_x_auth_request_email
  X-Proxy-Roles: all_access           ← for Wazuh
  X-Forwarded-Email: ...              ← for CyIRIS (oidc_proxy mode)

Wazuh Dashboard (proxy auth) → OpenSearch (proxy_auth_domain)
CyIRIS (oidc_proxy)          → internal Flask user creation/lookup
CySOAR (Node-RED)            → oauth2-proxy header pass-through
```

---

## CyIRIS SSO Issues (all resolved — CyIRIS v1.0.8–v1.0.15)

### Issue 1: ruff CI failure — spurious f-string prefix
- **Symptom**: CI (ruff F541) fails on push
- **File**: `source/app/blueprints/rest/dashboard_routes.py`
- **Cause**: `f"/oauth2/sign_out?rd=/dashboard"` — f-prefix with no placeholder
- **Fix**: Remove `f` prefix → `"/oauth2/sign_out?rd=/dashboard"`
- **Version**: CyIRIS v1.0.8

### Issue 2: Logout `KeyError: 'current_case'`
- **Symptom**: 500 error on logout when no case was open in session
- **File**: `source/app/blueprints/rest/dashboard_routes.py`
- **Cause**: `session['current_case']` raises `KeyError` if key absent
- **Fix**: `session.get('current_case')` — safe lookup
- **Version**: CyIRIS v1.0.10

### Issue 3: Logout re-logs user in (oidc_proxy mode)
- **Symptom**: Clicking logout redirects back to CyIRIS logged in
- **File**: `source/app/blueprints/rest/dashboard_routes.py`
- **Cause**: `is_authentication_oidc()` returns `False` for `oidc_proxy` mode → OIDC
  logout block skipped → no sign-out call to oauth2-proxy
- **Fix**: Added explicit check for `AUTHENTICATION_PROXY_LOGOUT_URL` config and
  redirect to it when set (covers `oidc_proxy` mode)
- **Version**: CyIRIS v1.0.10

### Issue 4: Logout URL relative — 404 on wrong domain
- **Symptom**: Logout sends browser to `cyiris.DOMAIN/oauth2/sign_out` — 404
- **File**: `source/app/configuration.py`
- **Cause**: Relative URL `/oauth2/sign_out` resolved against `cyiris.DOMAIN` by browser;
  oauth2-proxy runs on `cysoc.DOMAIN`
- **Fix**: Absolute URL `https://cysoc.{BASE_DOMAIN}/oauth2/sign_out?rd=https://cysoc.{BASE_DOMAIN}/`
  using `BASE_DOMAIN` env var
- **Version**: CyIRIS v1.0.14

### Issue 5: New SSO users get no permissions
- **Symptom**: SSO user can log in but sees empty dashboard / permission denied
- **File**: `source/app/blueprints/access_controls.py`
- **Cause**: `_authenticate_with_email` called `create_user()` but never called
  `add_user_to_group()` — user was created with no group assignment
- **Fix**: After `create_user()`, call `add_user_to_group(user.id, initial_group.group_id)`
  using `IRIS_NEW_USERS_DEFAULT_GROUP` config (set to `Administrators` in compose)
- **Version**: CyIRIS v1.0.13 / cycentra360 v1.0.222

### Issue 6: CyIRIS crash-loop — `BASE_DOMAIN` blank in container
- **Symptom**: CyIRIS container starts and immediately exits; `docker logs` shows DNS failure
  on OIDC discovery URL (e.g. `https://cyasm./oidc/.well-known/openid-configuration`)
- **Files**: 
  - `backend/blueprints/platform/routes.py` (cycentra360)
  - `backend/blueprints/platform/compose.py` (cycentra360)
- **Cause**: `cyiris_env` dict in `routes.py` didn't include `BASE_DOMAIN` → Docker Compose
  substituted `${BASE_DOMAIN}` as empty string → OIDC discovery URL malformed → DNS fail
- **Fix**: Added `"BASE_DOMAIN": base_domain` to `cyiris_env` dict
- **Version**: cycentra360 v1.0.224

### Issue 7: CyIRIS crash-loop — `exit(0)` on OIDC discovery failure
- **Symptom**: Even after BASE_DOMAIN fix, container still crash-loops; logs show OIDC
  discovery failed but then `exit(0)` immediately
- **File**: `source/app/configuration.py` (CyIRIS)
- **Cause**: Any failure in OIDC discovery during startup in `oidc_proxy` mode called
  `exit(0)` at module import time — fatal for container
- **Fix**: Made OIDC discovery fully optional in `oidc_proxy` mode; wrapped in
  `if oidc_discovery_url:` guard with `log.warning` on failure — no `exit()`
- **Version**: CyIRIS v1.0.15

---

## Wazuh (CySIEM) SSO Issues (partially resolved — as of v1.0.225)

### Background
Wazuh Dashboard uses OpenSearch Security plugin's **proxy auth** mode:
- Dashboard reads `X-Proxy-User` / `X-Proxy-Roles` headers from nginx
- Dashboard makes all OpenSearch API calls using the `kibanaserver` service account
- OpenSearch Security plugin validates proxy headers via `proxy_auth_domain`
- OpenSearch rolesmapping maps the `all_access` backend_role to the `all_access` security role

### Issue 1: kibanaserver credentials commented out in opensearch_dashboards.yml
- **Symptom**: All browser requests to Wazuh return 401 in 2–5ms; Dashboard logs show
  `[security_exception]: no permissions for [cluster:monitor/nodes/info]` for `kibanaserver`
- **File**: `/etc/wazuh-dashboard/opensearch_dashboards.yml`
- **Cause**: Wazuh installer generates a random `kibanaserver` password but leaves
  `opensearch.username` and `opensearch.password` commented out. Dashboard cannot
  authenticate to OpenSearch at all → every request returns 401 before proxy headers
  are even evaluated
- **Manual fix**:
  ```bash
  # Reset kibanaserver password
  NEW_KS_PASS="CyKibana2026!"
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh \
    -u kibanaserver -p "${NEW_KS_PASS}"

  # Verify
  curl -sk -u "kibanaserver:${NEW_KS_PASS}" https://127.0.0.1:9200/_cluster/health \
    -w "\nHTTP: %{http_code}\n"

  # Inject into Dashboard config
  sed -i '/^#\?\s*opensearch\.username:/d; /^#\?\s*opensearch\.password:/d' \
    /etc/wazuh-dashboard/opensearch_dashboards.yml
  printf 'opensearch.username: kibanaserver\nopensearch.password: "%s"\n' \
    "${NEW_KS_PASS}" >> /etc/wazuh-dashboard/opensearch_dashboards.yml

  systemctl restart wazuh-dashboard
  ```
- **OOB fix in setup.sh**: Step 4.1 now detects and uncomments/injects kibanaserver
  credentials automatically from the installer tar or via wazuh-passwords-tool fallback
- **Version**: cycentra360 v1.0.225

### Issue 2: OpenSearch rolesmapping missing `_meta` header — securityadmin rejects patch
- **Symptom**: `securityadmin.sh` exits with
  `A version of 2 must have a _meta key for ROLESMAPPING`
- **Cause**: rolesmapping patch YAML missing required `_meta` block
- **Fix**: Always include `_meta:` section:
  ```yaml
  _meta:
    type: "rolesmapping"
    config_version: 2
  ```
- **Version**: cycentra360 v1.0.225

### Issue 3: Partial rolesmapping wipes kibana_server user mapping → 403 cascade
- **Symptom**: After applying a patch rolesmapping, Dashboard starts logging
  `no permissions for [cluster:monitor/nodes/info]` for `kibanaserver` continuously
- **Cause**: `securityadmin.sh -f <file> -t rolesmapping` REPLACES the entire
  rolesmapping. If `kibana_server → kibanaserver` entry is omitted, the service
  account loses its role and every Dashboard→OpenSearch call fails with 403
- **Fix**: Always include full rolesmapping with `kibana_server`, `kibana_user`,
  `wazuh_ui_user`, `wazuh_ui_admin`, `own_index` AND `all_access` entries together
- **Version**: cycentra360 v1.0.225

### Issue 4: `auth.type: proxycache` not supported by this Wazuh build
- **Symptom**: Dashboard crashes on startup with
  `FATAL  Error: Unsupported authentication type: proxycache`
- **Cause**: This Wazuh build's `auth_handler_factory.ts` implements `proxy` type;
  `proxycache` is listed in the JSON schema but not in the runtime handler switch
- **Fix**: Use `opensearch_security.auth.type: proxy` (NOT `proxycache`)
  The `proxycache` sub-keys (`user_header`, `roles_header`) are still used for
  header name configuration regardless of which type is set
- **Version**: cycentra360 v1.0.225

### Issue 5: `all_access` backend_role not mapped in OpenSearch (ongoing on existing servers)
- **Symptom**: Even after all config is correct, Dashboard returns 401 for proxy-authed requests
- **Cause**: Vanilla Wazuh OpenSearch does not pre-map the `all_access` backend_role.
  `X-Proxy-Roles: all_access` is passed correctly but OpenSearch has no rolesmapping
  entry for it → user has no permissions
- **Fix**: Apply rolesmapping via securityadmin (see Issue 3 fix — same yml covers this)
- **Status**: ⏳ Still returning 401 on the dev server after all fixes above.
  Suspected remaining cause: the `proxy` auth type in this Wazuh Dashboard build may
  not forward the proxy headers to OpenSearch's security plugin the same way `proxycache`
  does. Fresh install via new setup.sh should resolve — start new investigation if issue
  persists post-reinstall.

---

## Quick Diagnostic Checklist — Wazuh 401

Run in order, stop when you find a failure:

```bash
# 1. Is kibanaserver working?
KS_PASS=$(grep "^opensearch.password" /etc/wazuh-dashboard/opensearch_dashboards.yml \
  | awk '{print $2}' | tr -d '"')
curl -sk -u "kibanaserver:${KS_PASS}" https://127.0.0.1:9200/_cluster/health \
  -w "\nHTTP: %{http_code}\n"
# Expect: HTTP 200. If 401 → reset password with wazuh-passwords-tool.sh

# 2. Is auth.type correct?
grep "auth.type" /etc/wazuh-dashboard/opensearch_dashboards.yml
# Expect: opensearch_security.auth.type: proxy  (NOT proxycache — crashes this build)

# 3. Is proxy_auth_domain enabled in live OpenSearch config?
cd /
export JAVA_HOME=/usr/share/wazuh-indexer/jdk
S="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh"
C="/etc/wazuh-indexer/certs"
"$S" -backup /tmp/sec-dump -icl -nhnv \
  -cacert "$C/root-ca.pem" -cert "$C/admin.pem" -key "$C/admin-key.pem" -h 127.0.0.1
grep -A5 "proxy_auth_domain" /tmp/sec-dump/config.yml
# Expect: http_enabled: true

# 4. Is all_access rolesmapping present?
grep -A5 "all_access:" /tmp/sec-dump/rolesmapping.yml
# Expect: backend_roles: [admin, all_access]

# 5. Is kibana_server rolesmapping present?
grep -A5 "kibana_server:" /tmp/sec-dump/rolesmapping.yml
# Expect: users: [kibanaserver]
```

---

## Files Changed Per Version

| Version | File | Change |
|---------|------|--------|
| CyIRIS v1.0.8 | `blueprints/rest/dashboard_routes.py` | Remove spurious f-prefix |
| CyIRIS v1.0.10 | `blueprints/rest/dashboard_routes.py` | `session.get()` + oidc_proxy logout redirect |
| CyIRIS v1.0.13 | `blueprints/access_controls.py` | `add_user_to_group()` after `create_user()` |
| CyIRIS v1.0.14 | `configuration.py` | Absolute logout URL using BASE_DOMAIN |
| CyIRIS v1.0.15 | `configuration.py` | Remove fatal `exit(0)` from OIDC discovery |
| cy360 v1.0.221 | `blueprints/platform/routes.py` | BASE_DOMAIN in cyiris nginx block + logout location |
| cy360 v1.0.222 | `blueprints/platform/compose.py` | BASE_DOMAIN + IRIS_NEW_USERS_DEFAULT_GROUP: Administrators |
| cy360 v1.0.223 | `blueprints/platform/routes.py` | Absolute logout URL + nginx /logout location |
| cy360 v1.0.224 | `blueprints/platform/routes.py` | BASE_DOMAIN in cyiris_env dict |
| cy360 v1.0.225 | `cycentra-setup.sh` | kibanaserver credential inject + rolesmapping with `_meta` + `cd /` before securityadmin |
