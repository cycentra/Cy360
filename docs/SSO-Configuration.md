# CyCentra 360 — SSO Configuration Guide

## Overview

CyCentra 360 supports two layers of SSO:

| Layer | What it covers | How users reach it |
|---|---|---|
| **Legacy OAuth** (Google / Microsoft) | Direct login at `cy360.<domain>` via platform-native OAuth apps | `/auth/google`, `/auth/microsoft` |
| **Generic OIDC SSO** (any OIDC provider) | Any OIDC 2.0 compliant IdP — Google Workspace, Microsoft / Azure AD, Okta, Keycloak, or custom | `/api/sso/redirect` → `/api/sso/callback` |

Both layers share the same `cy_users` PostgreSQL table and session model. The Generic OIDC layer adds an **approval workflow**: new users can be held pending admin review before they gain portal access. SMTP email notifications are sent to both the admin and the user.

---

## Architecture at a Glance

```
Browser
  │
  ├─ /auth/google          (Legacy — platform OAuth app, no approval gate)
  ├─ /auth/microsoft        (Legacy — platform OAuth app, no approval gate)
  │
  └─ /api/sso/redirect     (Generic OIDC — any provider, approval gate)
          │
          │  1. generate state/nonce, store in _STATE_STORE (10-min TTL)
          │  2. redirect → IdP authorization endpoint
          │
          ▼
     Identity Provider (Google / Microsoft / Okta / Keycloak / …)
          │
          │  3. user authenticates at IdP
          │  4. IdP redirects back with ?code=…&state=…
          │
          ▼
     /api/sso/callback
          │
          │  5. validate state; exchange code for tokens
          │  6. fetch userinfo claims
          │  7. check allowed_domains (if configured)
          │  8. provision user in cy_users (if auto_provision=true)
          │  9. if require_approval=true AND new user → status=pending
          │         → notify admin via SMTP
          │         → redirect browser to /?sso_error=pending_approval
          │ 10. if status=approved → set Flask session → redirect to portal
          │
          ▼
     Portal (cy360.<domain>)
```

---

## Config Storage

SSO and SMTP settings are stored in two places (in priority order):

1. **`cy_sso_config` table** (PostgreSQL, key-value rows) — set via the Settings UI or `/api/sso/configure` API. Wins over env vars at runtime.
2. **`/opt/cycentra/.env`** — env var fallbacks. Used on first boot before the UI has been configured.

> Rule: always configure via the **Settings → SSO & Auth** tab. The env vars below are only needed if you want to pre-seed the config before the first boot (e.g. via Ansible/Terraform) or if the database is not yet available.

---

## Environment Variables

All are optional if you configure via the UI. Defined in `backend/core/config.py`.

### SSO

| Variable | Default | Description |
|---|---|---|
| `SSO_ENABLED` | `false` | Master switch. Set to `true` to activate the generic OIDC flow. |
| `SSO_PROVIDER` | _(empty)_ | Provider ID: `google` · `microsoft` · `okta` · `keycloak` · `cycentra360` · `custom` |
| `SSO_CLIENT_ID` | _(empty)_ | OAuth client ID issued by the IdP |
| `SSO_CLIENT_SECRET` | _(empty)_ | OAuth client secret issued by the IdP |
| `SSO_DISCOVERY_URL` | _(empty)_ | OIDC discovery endpoint URL (auto-populated for Google and Microsoft) |
| `SSO_REDIRECT_URI` | `https://cy360.<domain>/api/sso/callback` | Your callback URL — defaults to the portal vhost. Override only if you need a different hostname. |
| `SSO_DEFAULT_ROLE` | `viewer` | Role assigned to new SSO users: `viewer` · `analyst` · `admin` |
| `SSO_AUTO_PROVISION` | `true` | Create the user record automatically on first login |
| `SSO_REQUIRE_APPROVAL` | `false` | Hold new users in `pending` state until an admin approves |
| `SSO_ALLOWED_DOMAINS` | _(empty)_ | Comma-separated list of permitted email domains, e.g. `cycentra.com,partner.com`. Empty = all domains allowed. |

### SMTP

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | _(empty)_ | Mail server hostname, e.g. `smtp.gmail.com` |
| `SMTP_PORT` | `587` | Port: `465` (SMTP_SSL) · `587` (STARTTLS) · `25` (plain) |
| `SMTP_USER` | _(empty)_ | SMTP username / email address |
| `SMTP_PASSWORD` | _(empty)_ | SMTP password or app password |
| `SMTP_FROM` | _(empty)_ | Sender address shown to users, e.g. `CyCentra 360 <noreply@cycentra.com>` |
| `SMTP_ADMIN_EMAIL` | `CYCENTRA_ADMIN_EMAIL` | Where approval-request emails are sent |
| `SMTP_USE_TLS` | `true` | Enable STARTTLS on port 587. Set `false` for port 25 (not recommended). |

---

## Settings UI Walkthrough

Navigate to **Settings → SSO & Auth** tab inside the portal.

### 1 — SSO Provider card

| Field | Notes |
|---|---|
| **Provider** | Select from the dropdown. Google and Microsoft auto-fill the Discovery URL. |
| **Client ID** | Paste the OAuth client/application ID from your IdP. |
| **Client Secret** | Paste the secret. Leave blank on subsequent saves to keep the existing value. |
| **OIDC Discovery URL** | Auto-filled for Google / Microsoft. For Okta and Keycloak, paste the full URL (see provider sections below). |
| **Redirect URI** | Must match exactly what you register in the IdP. Default: `https://cy360.<domain>/api/sso/callback` |
| **Default Role** | `viewer` is safest. Promote users individually after approval. |
| **Auto-provision** | Leave enabled unless you want to pre-create user records manually. |
| **Require Approval** | Enable if you want every new SSO user to be held pending admin review. SMTP must be configured for email notifications, but approval also works manually via this tab without email. |
| **Allowed Domains** | Optional domain allowlist. Prevents users from other organisations logging in if the IdP is shared (e.g. personal Google accounts). |

Click **Save & Enable SSO**. Then click **Test Connection** — it probes the discovery URL and reports the issuer.

### 2 — SMTP card

| Field | Notes |
|---|---|
| **SMTP Host** | Your mail relay hostname. |
| **Port** | `587` for STARTTLS (recommended), `465` for SSL, `25` for legacy plain (only for internal relays on a trusted network). |
| **Username / Password** | Credentials for the sending account. For Gmail, use an **App Password** (not your account password). |
| **From Address** | Display name + address. Must be authorised to send by your mail provider. |
| **Admin Email** | The address that receives "new user pending approval" emails with one-click approve/reject links. |

Click **Save SMTP Settings**, then **Send Test Email** to verify delivery.

### 3 — Pending Approvals table

When `Require Approval` is on, new SSO users appear here. The table refreshes on demand via the **Refresh** button.

- **Approve** — sets `approval_status = approved`, sends the user an email, allows their next login to succeed.
- **Reject** — opens a reason prompt, sets `approval_status = rejected`, sends the user an email with the reason. The rejection reason is also shown on next login.

---

## Provider-Specific Setup

### Google Workspace (recommended for Google-hosted orgs)

**In Google Cloud Console → APIs & Services → Credentials:**

1. Create project (or use an existing one).
2. **OAuth consent screen** → set user type to **Internal** (Workspace org) or **External** (all Google users).
   - Add scopes: `openid`, `email`, `profile`.
   - Add your domain to **Authorised domains**.
3. **Create Credentials → OAuth client ID** → Application type: **Web application**.
4. **Authorised redirect URIs** → add:
   ```
   https://cy360.<your-domain>/api/sso/callback
   ```
5. Copy **Client ID** and **Client Secret**.

**In CyCentra 360 Settings:**

| Field | Value |
|---|---|
| Provider | `Google Workspace` |
| Client ID | Paste from Cloud Console |
| Client Secret | Paste from Cloud Console |
| Discovery URL | Auto-filled: `https://accounts.google.com/.well-known/openid-configuration` |
| Redirect URI | `https://cy360.<your-domain>/api/sso/callback` |
| Allowed Domains | `yourcompany.com` (restrict to Workspace domain) |

> **Note on scopes:** Google sends `email`, `name`, and `picture` in the userinfo response by default. No additional scope configuration is needed in CyCentra 360.

> **Note on the legacy Google OAuth buttons on the login page:** These use a separate Google OAuth app registered under `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` env vars. They do **not** go through the approval workflow. If you want the approval workflow for Google users, use the generic OIDC SSO button (enabled automatically when SSO is configured) and leave `GOOGLE_CLIENT_ID` unset.

---

### Microsoft / Azure AD

**In Azure Portal → Azure Active Directory → App registrations:**

1. **New registration**.
   - Name: `CyCentra 360`
   - Supported account types: choose **Single tenant** (your org only) or **Multitenant** as appropriate.
   - Redirect URI: Platform = **Web**, value:
     ```
     https://cy360.<your-domain>/api/sso/callback
     ```
2. After creation, note the **Application (client) ID** and **Directory (tenant) ID**.
3. **Certificates & secrets → New client secret** → set expiry → copy the **Value** immediately (only shown once).
4. **API permissions → Add a permission → Microsoft Graph → Delegated**:
   - `openid`
   - `email`
   - `profile`
   - `User.Read`
   
   Click **Grant admin consent**.

**Discovery URL options:**

| Scenario | Discovery URL |
|---|---|
| Single-tenant (your org only) | `https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration` |
| Multi-tenant | `https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration` |
| Microsoft accounts only | `https://login.microsoftonline.com/consumers/v2.0/.well-known/openid-configuration` |

**In CyCentra 360 Settings:**

| Field | Value |
|---|---|
| Provider | `Microsoft / Azure AD` |
| Client ID | Application (client) ID from Azure |
| Client Secret | Client secret value from Azure |
| Discovery URL | See table above (auto-filled for `common`) |
| Redirect URI | `https://cy360.<your-domain>/api/sso/callback` |
| Allowed Domains | `yourcompany.com` |

> **Token claims:** Azure sends the `email` claim only if the user has an email address set in their profile and the `email` scope is granted. If users appear without an email, go to **Token configuration → Add optional claim → ID token → `email`**.

---

### Okta

**In Okta Admin Console → Applications → Create App Integration:**

1. Sign-in method: **OIDC – OpenID Connect**. Application type: **Web Application**.
2. Name it `CyCentra 360`.
3. **Grant type**: Authorization Code.
4. **Sign-in redirect URIs**:
   ```
   https://cy360.<your-domain>/api/sso/callback
   ```
5. **Sign-out redirect URIs**: `https://cy360.<your-domain>` (optional).
6. Assignments: set who can access the app (everyone, or specific groups).
7. Copy **Client ID** and **Client Secret** from the General tab.

**Discovery URL** format (replace `<okta-domain>` with your Okta domain, e.g. `yourorg.okta.com`):
```
https://<okta-domain>/.well-known/openid-configuration
```

Or if using a custom authorisation server:
```
https://<okta-domain>/oauth2/<auth-server-id>/.well-known/openid-configuration
```

**In CyCentra 360 Settings:**

| Field | Value |
|---|---|
| Provider | `Okta` |
| Client ID | From Okta app |
| Client Secret | From Okta app |
| Discovery URL | `https://<okta-domain>/.well-known/openid-configuration` |
| Redirect URI | `https://cy360.<your-domain>/api/sso/callback` |

> **Group-to-role mapping:** Okta can pass group memberships in the `groups` claim. In the Okta application's **Sign On** tab, edit the ID token claim and add a `groups` claim (regex `.*`). CyCentra 360's `_parse_role()` function maps claim values to portal roles: if any claim value matches `admin`, `analyst`, or `viewer` exactly, that role is used; otherwise the Default Role applies.

---

### Keycloak

**In Keycloak Admin Console → your Realm → Clients:**

1. **Create client**.
   - Client ID: `cycentra360`
   - Client Protocol: `openid-connect`
   - Root URL: `https://cy360.<your-domain>`
2. Under **Settings**:
   - Access Type: `confidential`
   - Valid Redirect URIs: `https://cy360.<your-domain>/api/sso/callback`
   - Web Origins: `https://cy360.<your-domain>`
3. Under **Credentials** tab: copy **Client Secret**.

**Discovery URL** format (replace `<keycloak-url>` and `<realm-name>`):
```
https://<keycloak-url>/realms/<realm-name>/.well-known/openid-configuration
```
Example:
```
https://auth.cycentra.com/realms/cycentra/.well-known/openid-configuration
```

**In CyCentra 360 Settings:**

| Field | Value |
|---|---|
| Provider | `Keycloak` |
| Client ID | `cycentra360` (as registered) |
| Client Secret | From Credentials tab |
| Discovery URL | `https://<keycloak-url>/realms/<realm>/.well-known/openid-configuration` |
| Redirect URI | `https://cy360.<your-domain>/api/sso/callback` |

> **Role mapper:** In Keycloak, add a **Protocol Mapper** of type `User Realm Role` to the `cycentra360` client, Token Claim Name: `roles`, included in ID token and userinfo. `_parse_role()` checks this claim to derive the CyCentra portal role.

---

### CyCentra 360 IdP (OIDC for internal tools)

CyCentra 360 itself acts as an OIDC identity provider (via `blueprints/oidc/provider.py`). This is used so that CyIRIS, CySOAR, and CySIEM can trust the portal's sessions without their own OAuth apps.

To configure another CyCentra 360 instance (or another tool) to log in via a CyCentra OIDC provider:

1. Register the client in the source instance's `/opt/cycentra/.env`:
   ```
   OIDC_CLIENT_<name>_SECRET=<generated-secret>
   OIDC_CLIENT_<name>_REDIRECT_URI=https://cy360.<target-domain>/api/sso/callback
   ```
2. Discovery URL:
   ```
   https://cyasm.<source-domain>/.well-known/openid-configuration
   ```   (This is the IdP's own OIDC issuer URL — `cyasm` stays here because it is the OIDC provider host, not the callback target.)3. Client ID: the `<name>` registered in the source instance.
4. Client Secret: as set above.

---

## Approval Workflow Detail

```
New user authenticates at IdP → /api/sso/callback
        │
        ├─ allowed_domains check fails → 403 (redirect to error page)
        │
        ├─ user already exists in cy_users
        │       ├─ approval_status = approved → login succeeds
        │       ├─ approval_status = pending  → redirect to /?sso_error=pending_approval&email=…
        │       └─ approval_status = rejected → redirect to /?auth=error&message=…
        │
        └─ user does NOT exist (new user)
                ├─ auto_provision = false → error (user must be pre-created by admin)
                └─ auto_provision = true
                        ├─ require_approval = false
                        │       → INSERT cy_users with approval_status=approved
                        │       → login succeeds immediately
                        └─ require_approval = true
                                → INSERT cy_users with approval_status=pending
                                → fire-and-forget SMTP to SMTP_ADMIN_EMAIL
                                   subject: "New user pending approval: <email>"
                                   body: one-click approve + reject links
                                → redirect to /?sso_error=pending_approval&email=…
```

**Approve/Reject links in admin email** point to:
```
POST https://cy360.<domain>/api/sso/approve/<email>
POST https://cy360.<domain>/api/sso/reject/<email>
```
These require an active admin session. If the admin is not already logged in, the link will redirect to the login page first and then fulfil the action on next visit. Alternatively, use the **Pending Approvals** table in Settings → SSO & Auth.

**Email templates** (generated by `backend/smtp_service.py`):

| Trigger | Recipient | Subject |
|---|---|---|
| New user pending approval | Admin (`SMTP_ADMIN_EMAIL`) | `[CyCentra 360] New user access request: <email>` |
| Admin approves user | User | `[CyCentra 360] Your access has been approved` |
| Admin rejects user | User | `[CyCentra 360] Your access request was not approved` |
| Test email | Configurable | `[CyCentra 360] SMTP Test` |

---

## SMTP Port Reference

| Port | Mode | When to use |
|---|---|---|
| `465` | SMTP_SSL (TLS from first byte) | Gmail, some hosted providers |
| `587` | STARTTLS (upgrades to TLS after EHLO) | Most modern SMTP relays — **recommended** |
| `25` | Plain (no encryption) | Internal relay on a trusted private network only |

> Google Workspace SMTP relay requires **App Passwords** when 2FA is enabled on the sending account. Go to Google Account → Security → App passwords.

> Microsoft 365 SMTP requires `SMTP AUTH` to be enabled in the Exchange admin centre for the sending account under **Settings → Mail flow → SMTP AUTH clients submission**.

---

## API Reference

All `/api/sso/*` routes are served by `blueprints/sso/routes.py`. They are accessible at both `cy360.<domain>/api/sso/...` and `cyasm.<domain>/api/sso/...` because both nginx vhosts proxy `/api/` to the same Flask backend. The canonical base URL is `cy360.<domain>`.

| Method | Path | Auth required | Description |
|---|---|---|---|
| `GET` | `/api/sso/providers` | None (public) | Returns `{sso_enabled, provider_id, provider_name, discovery_url}` |
| `GET` | `/api/sso/status` | None (public) | Probes the IdP discovery URL; returns `{ok, issuer}` or `{ok: false, error}` |
| `GET` | `/api/sso/redirect` | None (public) | Starts the OIDC flow; redirects the browser to the IdP |
| `GET` | `/api/sso/callback` | None (IdP redirect) | Exchanges code, provisions user, sets session |
| `GET` | `/api/sso/config` | Admin | Returns non-secret SSO config (provider, client_id, redirect_uri, discovery_url, etc.) — client secret is redacted |
| `POST` | `/api/sso/configure` | Admin | Save provider settings; body: SSO config fields |
| `POST` | `/api/sso/disable` | Admin | Disable SSO (does not delete config) |
| `GET` | `/api/sso/pending` | Admin | List users with `approval_status = pending` |
| `GET` or `POST` | `/api/sso/approve/<email>` | Admin | Approve a pending user; GET used for email one-click links, POST used by the Settings UI |
| `GET` or `POST` | `/api/sso/reject/<email>` | Admin | Reject a pending user; GET used for email one-click links, POST used by the Settings UI; body (POST): `{"reason": "…"}` |
| `POST` | `/api/sso/revoke/<email>` | Admin | Revoke an approved user back to `pending` state (re-triggers the approval workflow) |
| `GET` | `/api/sso/smtp/config` | Admin | Get current SMTP settings (password redacted) |
| `POST` | `/api/sso/smtp/config` | Admin | Save SMTP settings |
| `POST` | `/api/sso/smtp/test` | Admin | Send a test email; body: `{"email": "…"}` |

---

## Database Schema

Two tables are involved:

**`cy_users`** (also used by RBAC):

| Column | Type | Notes |
|---|---|---|
| `email` | `TEXT PRIMARY KEY` | User's email address from IdP |
| `role` | `TEXT` | `admin` · `analyst` · `viewer` |
| `auth_type` | `TEXT` | `local` · `google` · `microsoft` · `sso` |
| `sso_provider` | `TEXT` | Provider ID that created this user, e.g. `okta` |
| `sso_id` | `TEXT` | Subject (`sub`) claim from the IdP token |
| `approval_status` | `TEXT` | `approved` (default) · `pending` · `rejected` |
| `approval_requested_at` | `TIMESTAMPTZ` | When the pending record was created |
| `approval_resolved_at` | `TIMESTAMPTZ` | When it was approved or rejected |
| `rejection_reason` | `TEXT` | Admin-supplied reason shown to user |

**`cy_sso_config`** (key-value store for SSO + SMTP settings):

| `key` | Stores |
|---|---|
| `sso_enabled` | `"true"` / `"false"` |
| `sso_provider` | Provider ID |
| `sso_client_id` | OAuth client ID |
| `sso_client_secret` | OAuth client secret (stored in DB, not logged) |
| `sso_discovery_url` | Full discovery URL |
| `sso_redirect_uri` | Callback URI |
| `sso_default_role` | `viewer` / `analyst` / `admin` |
| `sso_auto_provision` | `"true"` / `"false"` |
| `sso_require_approval` | `"true"` / `"false"` |
| `sso_allowed_domains` | Comma-separated domain list |
| `smtp_host` | SMTP hostname |
| `smtp_port` | Port number as string |
| `smtp_user` | SMTP username |
| `smtp_password` | SMTP password |
| `smtp_from` | Sender address |
| `smtp_admin_email` | Approval notification recipient |
| `smtp_use_tls` | `"true"` / `"false"` |

---

## Security Notes

- **Client secrets** are stored in `cy_sso_config` (PostgreSQL on `127.0.0.1:5433`). The table is not externally accessible. Treat the database as a secret store.
- **OIDC state and nonce** are stored in-memory (`_STATE_STORE` dict in `blueprints/sso/routes.py`) with a 10-minute TTL. On Flask worker restart, in-flight OIDC flows will fail cleanly (user is redirected back to login). This is acceptable for single-worker deployments; for multi-worker setups, move state to Redis.
- **`SSO_REQUIRE_APPROVAL = true`** is strongly recommended for providers configured with broad access (e.g. `microsoft common` endpoint which allows any Microsoft account). Combined with `SSO_ALLOWED_DOMAINS`, this prevents unwanted sign-ups.
- The approval one-click links in admin emails require an active admin session — they are not bearer-token links. An attacker who intercepts the email cannot approve access without also having valid admin credentials.
- SMTP passwords are never returned by `GET /api/sso/smtp/config` (the response omits the `smtp_password` key). Saving SMTP config with a blank password field leaves the existing password unchanged.
- All SSO-related auth events (`login`, `pending`, `denied`) are written to `AUTH_LOG_FILE` (default `/var/log/cycentra/auth.log`) via `auth_event()` and tailed by the Wazuh agent.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| "Test Connection" returns `UNREACHABLE` | Wrong or unreachable discovery URL | Verify the URL returns JSON in your browser; check network connectivity from the CyCentra server |
| Redirect loop after IdP authentication | `redirect_uri` mismatch | Ensure the URI in CyCentra Settings matches exactly what is registered in the IdP (scheme, hostname, path, no trailing slash) |
| User gets `Access denied — not registered` after IdP login | `auto_provision = false` | Enable auto-provision, or pre-create the user via **Settings → User Management** |
| User lands on pending-approval screen on every login | Approval was never actioned | Go to **Settings → SSO & Auth → Pending Approvals** and approve the user |
| No approval email received | SMTP not configured or port blocked | Use **Send Test Email** to verify delivery; check outbound port 587/465 is not firewalled |
| `invalid_grant` or `code expired` from IdP | Clock skew between CyCentra server and IdP | Run `ntpdate -u pool.ntp.org` on the server; OIDC tokens have very short lifetimes |
| Google: `redirect_uri_mismatch` | URI in Google Cloud Console doesn't match | Must be an exact string match including `https://` |
| Microsoft: missing `email` claim | Optional claims not enabled in Azure | Add the `email` optional claim in **App registrations → Token configuration** |
| Okta: empty role after login | `groups` claim not mapped | Add a groups claim mapper in the Okta app's Sign On policy |
| Keycloak: 401 on callback | `confidential` client secret not matching | Re-copy the secret from Keycloak Credentials tab |

For deeper diagnostics, check the Flask logs (`docker logs cycentra-backend`) and the auth event log:
```bash
tail -f /var/log/cycentra/auth.log | grep sso
```
