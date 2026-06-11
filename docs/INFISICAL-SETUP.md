# Infisical Secrets Integration — Setup, Architecture & Operations

This document covers everything an operator needs to know to set up, troubleshoot, and
extend Infisical as the secrets backend for CyCentra 360. It reflects hard-won lessons
from the initial CY360-DEV deployment and is the authoritative reference for all future
server installations.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Auth Method Decision Guide](#2-auth-method-decision-guide)
3. [First-Time Setup — Azure Arc OIDC (Recommended for Azure Servers)](#3-first-time-setup--azure-arc-oidc)
4. [First-Time Setup — Universal Auth (Recommended for Non-Azure / Multi-Server)](#4-first-time-setup--universal-auth)
5. [New Server Installation Checklist](#5-new-server-installation-checklist)
6. [Uploading Secrets to Infisical](#6-uploading-secrets-to-infisical)
7. [Verifying the Integration](#7-verifying-the-integration)
8. [Troubleshooting Reference](#8-troubleshooting-reference)
9. [Multi-Server Strategy — Critical Reading](#9-multi-server-strategy--critical-reading)
10. [Secret Rotation](#10-secret-rotation)

---

## 1. Architecture Overview

CyCentra 360 uses `backend/core/kv_secrets.py` as a provider-agnostic secrets bootstrap.
It runs at Flask startup (before any config is read) and injects secrets into `os.environ`.
Three backends are supported; select via `SECRETS_BACKEND` in `/opt/cycentra/.env`:

| Backend | Env var | Best for |
|---------|---------|----------|
| `infisical` | `SECRETS_BACKEND=infisical` | All deployments (recommended) |
| `azure` | `SECRETS_BACKEND=azure` | Azure Key Vault (legacy) |
| `hashicorp` | `SECRETS_BACKEND=hashicorp` | Self-hosted Vault |

**What goes into Infisical vs stays in `.env`:**

Infisical holds only **company-wide secrets** — values that are identical across every
CyCentra 360 deployment (OAuth app credentials, shared API keys). Install-specific values
(database passwords, OIDC inter-service secrets, per-install `SECRET_KEY`) stay in `.env`
and are never pushed to or pulled from the vault. See `FLASK_KV_MAP` in `kv_secrets.py`
for the exact list.

**Idempotency rule:** if a key is already present in `os.environ` (set via systemd
`EnvironmentFile` or `.env`), the vault is NOT consulted for that key — `.env` always wins.
This lets you override any secret locally during development.

---

## 2. Auth Method Decision Guide

Set `INFISICAL_AUTH_METHOD` in `/opt/cycentra/.env`:

```
INFISICAL_AUTH_METHOD=azure      # Azure Arc enrolled — no secret needed
INFISICAL_AUTH_METHOD=universal  # Any server — client ID + secret required
```

### Azure Arc OIDC (`azure` / `oidc`)
- **Requires:** Azure Arc agent (`azcmagent`) installed and enrolled on the server
- **How it works:** Flask calls the local HIMDS endpoint (`localhost:40342`) to get a
  short-lived JWT, then trades it for an Infisical session via OIDC auth
- **No client secret needed** — the Arc MSI is the credential
- **Critical limitation:** Each Arc-enrolled server has a unique `sub` (OID) in its JWT.
  See [Section 9](#9-multi-server-strategy--critical-reading) for how to handle this

### Universal Auth (`universal`)
- **Requires:** `INFISICAL_CLIENT_ID` + `INFISICAL_CLIENT_SECRET` in `.env`
- **Works on any server** — no Azure Arc required
- **One identity, all servers** — the same client secret is used everywhere
- **Trade-off:** The secret must be stored in `.env`; rotate it in Infisical and update
  `.env` on each server if compromised

---

## 3. First-Time Setup — Azure Arc OIDC

### Step 1 — Find this server's Arc subject (OID)

Run this on the server to decode the live HIMDS JWT and read the `sub` claim:

```bash
python3 << 'EOF'
import urllib.request, json, re, base64

url = "http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https://management.azure.com/"
req0 = urllib.request.Request(url, headers={"Metadata": "true"})
try:
    urllib.request.urlopen(req0, timeout=5)
except urllib.request.HTTPError as e:
    m = re.search(r"realm=(\S+)", e.headers.get("Www-Authenticate",""))
    key_path = m.group(1)
with open(key_path) as f:
    raw_key = f.read().strip()
req1 = urllib.request.Request(url, headers={"Metadata": "true", "Authorization": "Basic " + raw_key})
with urllib.request.urlopen(req1, timeout=10) as r:
    token = json.loads(r.read().decode())["access_token"]

parts = token.split(".")
pad = parts[1] + "=="*((4 - len(parts[1])%4)%4)
claims = json.loads(base64.urlsafe_b64decode(pad))
for k in ["iss","sub","oid","aud","appid","tid"]:
    print(k + ": " + str(claims.get(k,"(missing)")))
EOF
```

Note the `sub`/`oid` value — you need it for the Infisical machine identity.

### Step 2 — Create an OIDC machine identity in Infisical

1. Log in to Infisical → **Organization Settings** → **Machine Identities** → **Create**
2. Choose auth method: **OIDC Auth**
3. Fill in the fields:

| Field | Value |
|-------|-------|
| OIDC Discovery URL | `https://sts.windows.net/<TENANT-ID>/` |
| Bound Issuer | `https://sts.windows.net/<TENANT-ID>/` |
| Bound Subject | `<sub value from Step 1>` |
| Bound Audiences | `https://management.azure.com` |

> **Why `sts.windows.net`?** Azure Arc issues v1.0 tokens. The issuer is `sts.windows.net`,
> NOT `login.microsoftonline.com/v2.0` (which is for v2.0 tokens). Using the wrong issuer
> URL is the most common misconfiguration and results in a 403 at login.

4. Assign the identity **reader** role on your Infisical project
5. Copy the **Machine Identity ID** (UUID) — this is your `INFISICAL_CLIENT_ID`

### Step 3 — Configure `/opt/cycentra/.env`

```bash
SECRETS_BACKEND=infisical
INFISICAL_AUTH_METHOD=azure
INFISICAL_URL=https://eu.infisical.com/
INFISICAL_CLIENT_ID=<machine-identity-UUID-from-step-2>
INFISICAL_PROJECT_ID=<your-project-id>
INFISICAL_ENVIRONMENT=prod
```

No `INFISICAL_CLIENT_SECRET` needed for Arc OIDC.

### Step 4 — Restart the backend

```bash
systemctl restart cycentra-backend.service
```

---

## 4. First-Time Setup — Universal Auth

### Step 1 — Create a Universal Auth machine identity in Infisical

1. Log in to Infisical → **Organization Settings** → **Machine Identities** → **Create**
2. Choose auth method: **Universal Auth**
3. Generate a **Client Secret** and copy both the Client ID and Client Secret
4. Assign the identity **reader** role on your Infisical project

### Step 2 — Configure `/opt/cycentra/.env`

```bash
SECRETS_BACKEND=infisical
INFISICAL_AUTH_METHOD=universal
INFISICAL_URL=https://eu.infisical.com/
INFISICAL_CLIENT_ID=<machine-identity-UUID>
INFISICAL_CLIENT_SECRET=<client-secret>
INFISICAL_PROJECT_ID=<your-project-id>
INFISICAL_ENVIRONMENT=prod
```

### Step 3 — Restart the backend

```bash
systemctl restart cycentra-backend.service
```

---

## 5. New Server Installation Checklist

Follow this every time you install CyCentra 360 on a new server.

### Option A — Azure Arc OIDC (per-server identity)

- [ ] Verify Azure Arc agent is running: `systemctl status azcmagent`
- [ ] Run the JWT decode script (Section 3, Step 1) — note the `sub` value
- [ ] In Infisical UI: create a new OIDC machine identity for this server with its `sub`
- [ ] Copy the new Machine Identity ID
- [ ] Add to `/opt/cycentra/.env`: `INFISICAL_AUTH_METHOD=azure` + `INFISICAL_CLIENT_ID=<new-id>`
- [ ] Add shared vars: `SECRETS_BACKEND`, `INFISICAL_URL`, `INFISICAL_PROJECT_ID`, `INFISICAL_ENVIRONMENT`
- [ ] Run the verification test (Section 7)
- [ ] Restart the backend: `systemctl restart cycentra-backend.service`

### Option B — Universal Auth (same identity, all servers)

- [ ] Add to `/opt/cycentra/.env`: `INFISICAL_AUTH_METHOD=universal` + `INFISICAL_CLIENT_ID` + `INFISICAL_CLIENT_SECRET`
- [ ] Add shared vars: `SECRETS_BACKEND`, `INFISICAL_URL`, `INFISICAL_PROJECT_ID`, `INFISICAL_ENVIRONMENT`
- [ ] Run the verification test (Section 7)
- [ ] Restart the backend: `systemctl restart cycentra-backend.service`

> **Option B has no per-server steps in Infisical.** The same client secret works on every
> server. If the secret is ever compromised, rotate it once in Infisical and update `.env`
> on all servers.

---

## 6. Uploading Secrets to Infisical

Secrets only need to be uploaded **once** to the project — all servers share the same vault.

### Via Infisical UI (recommended for Azure OIDC installs)

Go to your project → **Secrets** → select `prod` environment → add each key/value pair.

The keys expected by CyCentra 360 (from `FLASK_KV_MAP` in `kv_secrets.py`):

```
MARKETPLACE_CATALOG_TOKEN
SSO_CLIENT_ID / SSO_CLIENT_SECRET
GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
MICROSOFT_CLIENT_ID / MICROSOFT_CLIENT_SECRET
GH_TOKEN
MAXMIND_KEY
CLOUD_MISP_URL / CLOUD_MISP_API_KEY
CYMIND_API_URL / CYMIND_API_KEY
```

> **Naming convention:** Upload secrets with underscores (`CYMIND_API_URL`). The code
> automatically tries both the hyphenated and underscore form, so either works — but
> underscores are simpler.

### Via Infisical CLI (for Universal Auth installs only)

```bash
infisical secrets set GOOGLE_CLIENT_ID="..." \
  --clientId=<id> --clientSecret=<secret> \
  --projectId=<project-id> --env=prod
```

The `azure` / `oidc` auth methods cannot authenticate the CLI non-interactively for writes
(the CLI's `--native-azure` flag requires an interactive session). Use the UI for those.

---

## 7. Verifying the Integration

Run this on the server to test the full fetch path with debug output:

```bash
python3 << 'EOF'
import logging, os
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
for line in open("/opt/cycentra/.env"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())
from core.kv_secrets import _infisical_fetch, FLASK_KV_MAP
result = _infisical_fetch(FLASK_KV_MAP)
print("\n--- " + str(result) + " secret(s) loaded from Infisical ---")
for k in FLASK_KV_MAP:
    status = "OK     " if os.environ.get(k) else "MISSING"
    print(status + "  " + k)
EOF
```

**What to look for:**

| Log line | Meaning |
|----------|---------|
| `HIMDS JWT obtained successfully` | Arc MSI is healthy |
| `POST /api/v1/auth/oidc-auth/login HTTP/1.1" 200` | OIDC auth succeeded |
| `POST /api/v1/auth/oidc-auth/login HTTP/1.1" 403` | Bound Subject mismatch — recheck `sub` |
| `ImportError: No module named 'infisical_sdk'` | Run `pip install infisical-sdk` |
| `INFISICAL_PROJECT_ID not set` | Missing env var in `.env` |
| Secret lines showing `404` | Secret not uploaded to Infisical yet |
| Secret lines showing `200` | Secret found and loaded |

---

## 8. Troubleshooting Reference

### Troubleshooting log — CY360-DEV initial deployment (2026-05-28)

This section documents the full chain of failures encountered during the first Infisical
deployment, in the order they were discovered. Each issue was identified via live testing
on the server.

---

**Issue 1 — `requirements.txt` package name typo**

- **Symptom:** No secrets loaded; no error in Flask logs beyond a WARNING
- **Root cause:** `requirements.txt` listed `infisicalsdk>=1.0.0`. The correct PyPI package
  name is `infisical-sdk` (with a hyphen). `infisicalsdk` does not exist on PyPI, so
  `pip install` on a fresh server installs nothing. The `except ImportError` block in
  `kv_secrets.py` silently returns 0 — the entire backend is skipped with only a WARNING.
- **Why it wasn't caught earlier:** The SDK had been manually installed on CY360-DEV before
  the requirements.txt was written, masking the typo at runtime.
- **Fix:** `backend/requirements.txt` — `infisicalsdk` → `infisical-sdk` (v1.2.68)

---

**Issue 2 — Wrong HIMDS path in `infisical-refresh.sh`**

- **Symptom:** Daily secret refresh timer always logged "Arc MSI endpoint unreachable"
  and exited with code 1, so the backend was never reloaded after secret rotation
- **Root cause:** The connectivity check in the generated `infisical-refresh.sh` used
  path `/identity/oauth2/token`. Azure Arc HIMDS returns 404 on that path. The correct
  path is `/metadata/identity/oauth2/token`
- **Fix:** `cycentra-setup.sh` refresh script block — path corrected (v1.2.68)

---

**Issue 3 — `curl -sf` rejects the valid HIMDS 401 challenge**

- **Symptom:** Same as Issue 2 — refresh timer always fails even after path was corrected
- **Root cause:** HIMDS always returns HTTP 401 on the first request (the challenge-response
  mechanism). The `-f` flag in `curl -sf` exits non-zero on any 4xx/5xx, so a 401 from a
  healthy Arc agent is indistinguishable from a real failure.
- **Fix:** Replaced `curl -sf` with `curl -s -w "%{http_code}"` and checked for `401`
  specifically as the healthy signal (v1.2.68)

---

**Issue 4 — Wrong `sub` value in Infisical OIDC Bound Subject**

- **Symptom:** HIMDS JWT fetched successfully; Infisical login returned `403 OIDC subject
  not allowed`
- **Root cause:** The machine identity was configured with Bound Subject
  `054ce2b3-5181-4843-b07b-377907694700`, taken from the Azure Portal App Registration
  page — which shows the App's Object ID, not the Arc Managed Identity's Object ID.
  The actual `sub` claim in the HIMDS JWT for CY360-DEV is
  `9bca8989-879a-4566-826a-1acb578c5f0d`.
- **How to get the right value:** Run the JWT decode script in Section 3, Step 1 and read
  the `sub` field. Do NOT rely on the Azure Portal "Object ID" shown on the App
  Registration page — it refers to a different identity.
- **Fix:** Updated Bound Subject in the Infisical UI to match the live JWT `sub` value

---

**Verified OIDC claims for CY360-DEV:**

| Claim | Value |
|-------|-------|
| `iss` | `https://sts.windows.net/00864d66-c8a8-443f-8d0a-3df93346e266/` |
| `sub` / `oid` | `9bca8989-879a-4566-826a-1acb578c5f0d` |
| `aud` | `https://management.azure.com` |
| `appid` (Arc MSI) | `bd494fef-83ea-453a-abf1-59a66674f1eb` |
| `tid` | `00864d66-c8a8-443f-8d0a-3df93346e266` |

---

## 9. Multi-Server Strategy — Critical Reading

### The per-server `sub` problem

**Each Azure Arc-enrolled server has a unique `sub` (OID)** assigned by Azure at Arc
enrollment time. The `sub` claim in the HIMDS JWT is that machine's Managed Identity
Object ID — it is unique, permanent, and different for every server.

This means a single OIDC machine identity with a hardcoded Bound Subject can only
authenticate from one specific server. For a second server, you have three options:

---

### Option A — One OIDC machine identity per server (most secure)

Create a separate machine identity in Infisical for each server. Each identity has
the specific `sub` for that server hardcoded as Bound Subject.

**Pros:**
- Per-server access control — you can revoke one server's access without affecting others
- Audit logs in Infisical show which server accessed secrets
- Principle of least privilege

**Cons:**
- One Infisical machine identity to create and manage per install
- Operator must run the JWT decode script on each new server and configure Infisical

**Use when:** You have a small number of production servers and strong audit requirements.

---

### Option B — Wildcard Bound Subject (one identity, all servers)

Infisical supports glob patterns in the Bound Subject field. Set Bound Subject to `*`
to match any subject — this allows all Arc-enrolled servers in your tenant to authenticate
with a single machine identity.

**Pros:**
- Zero Infisical config per new server install
- One identity to manage

**Cons:**
- Any Azure Arc server enrolled in your tenant can authenticate — not just CyCentra servers
- Relies entirely on Bound Issuer + Bound Audience being restrictive enough
- Less granular audit trail

**Security posture:** Acceptable if all Arc servers in your tenant are company-controlled.
Still grant the identity read-only ("reader") access to limit blast radius.

**How to configure:**
- Set Bound Subject to `*` in the Infisical machine identity OIDC settings
- Leave a single shared `INFISICAL_CLIENT_ID` in your `.env` template

**Use when:** You have many servers and all Arc-enrolled machines in your tenant are
CyCentra hosts (or you accept the broader trust boundary).

---

### Option C — Universal Auth (recommended for multi-server deployments)

Use `INFISICAL_AUTH_METHOD=universal` with a single client ID + secret shared across
all servers. No Azure Arc required; no per-server Infisical setup.

**Pros:**
- Simplest to operate — same `.env` template for every server
- No per-server Infisical config at all
- Works on any cloud, on-prem, or VM without Arc

**Cons:**
- The client secret lives in `.env` on every server — must be rotated if compromised
- Rotation requires updating `.env` on all servers and restarting the backend

**Use when:** You are deploying to many servers, or servers without Azure Arc, and
operational simplicity outweighs the per-server identity granularity of Option A.

---

### Recommendation for CyCentra 360

| Deployment size | Recommendation |
|-----------------|---------------|
| 1–3 servers, all Azure Arc | Option A (per-server OIDC identity) |
| 4+ servers, all Azure Arc, same tenant | Option B (wildcard subject) |
| Any servers without Arc, or mixed environments | Option C (universal auth) |

---

## 10. Secret Rotation

To rotate a secret (e.g. a compromised API key):

1. Update the value in the Infisical UI or CLI
2. Run the rotation helper to pull the new value into `.env` and restart:

```bash
cd /opt/cycentra
python3 -c "from core.kv_secrets import pull_to_env; pull_to_env()"
systemctl restart cycentra-backend.service
```

The `pull_to_env()` function force-fetches vault values and writes them back to `.env`,
then restarts the backend so the new value takes effect immediately. The daily
`cycentra-secret-refresh.timer` handles this automatically on a 24-hour cycle.
