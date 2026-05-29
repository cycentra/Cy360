"""
core/kv_secrets.py
==================
Provider-agnostic secrets bootstrap.  Fetches secrets at process startup and
injects them into os.environ before any config module reads them.

SELECTING A BACKEND
-------------------
Set SECRETS_BACKEND in /opt/cycentra/.env (or cysiemstack.env):

  SECRETS_BACKEND=azure       → Azure Key Vault  (default)
  SECRETS_BACKEND=hashicorp   → HashiCorp Vault
  SECRETS_BACKEND=infisical   → Infisical

For Infisical, also set INFISICAL_AUTH_METHOD — choose based on whether
your server has Azure Arc enrolled:

  INFISICAL_AUTH_METHOD=azure      → Azure Native Auth via Arc MSI
                                     Requires Azure Arc agent running on server
                                     Machine Identity type: "Azure Native Auth"
  INFISICAL_AUTH_METHOD=oidc       → Manual Arc JWT exchange (OIDC identity type)
                                     Requires Azure Arc agent running on server
                                     Machine Identity type: "OIDC"
  INFISICAL_AUTH_METHOD=universal  → Client ID + Secret
                                     Works on ANY server — Arc not required
                                     Machine Identity type: "Universal Auth"
                                     Use this when Arc is not enrolled (on-prem,
                                     non-Azure cloud, VMs without Arc)

Leave unset (or omit VAULT_ADDR / AZURE_KEYVAULT_URL) to skip entirely —
the app will rely on values already in .env or the process environment.

──────────────────────────────────────────────────────────────────────────────
AZURE KEY VAULT
──────────────────────────────────────────────────────────────────────────────
Required env var:
  AZURE_KEYVAULT_URL=https://my-vault.vault.azure.net/

Auth (tried in order by DefaultAzureCredential):
  1. Azure Arc / Managed Identity  ← recommended for Azure VMs and Arc servers
  2. AZURE_CLIENT_ID + AZURE_CLIENT_SECRET + AZURE_TENANT_ID  ← Service Principal
  3. `az login` CLI session  ← local dev

Secret naming:  env var FOO_BAR  →  KV secret name  FOO-BAR
  (Azure KV only allows alphanumeric + hyphens — underscores become hyphens)

Required packages:
  azure-identity>=1.15.0
  azure-keyvault-secrets>=4.7.0

──────────────────────────────────────────────────────────────────────────────
HASHICORP VAULT
──────────────────────────────────────────────────────────────────────────────
Required env vars:
  VAULT_ADDR=https://vault.internal:8200
  VAULT_MOUNT=secret                      (KV v2 mount point — default: secret)
  VAULT_PATH_PREFIX=cycentra              (folder inside the mount — default: cycentra)

Auth (tried in order):
  1. VAULT_TOKEN            ← direct token (dev / CI)
  2. VAULT_ROLE_ID + VAULT_SECRET_ID  ← AppRole (recommended for on-prem servers)

Secret naming:  env var FOO_BAR  →  Vault path  <mount>/<prefix>/FOO-BAR
  Example: secret/data/cycentra/GOOGLE-CLIENT-SECRET
  Each secret is stored as:  { "value": "actual_secret_here" }

Required package:
  hvac>=2.0.0

AppRole setup (run once on Vault server):
  vault secrets enable -path=secret kv-v2
  vault policy write cycentra-read - <<EOF
    path "secret/data/cycentra/*" { capabilities = ["read"] }
  EOF
  vault auth enable approle
  vault write auth/approle/role/cycentra \
      token_policies="cycentra-read" \
      token_ttl=1h token_max_ttl=4h \
      secret_id_ttl=0          # non-expiring secret_id; set a TTL for tighter security
  vault read auth/approle/role/cycentra/role-id   # → put in VAULT_ROLE_ID
  vault write -f auth/approle/role/cycentra/secret-id  # → put in VAULT_SECRET_ID

──────────────────────────────────────────────────────────────────────────────
IDEMPOTENCY
──────────────────────────────────────────────────────────────────────────────
If a variable is already present in the process environment (set via systemd
EnvironmentFile or shell export), the secrets backend is NOT consulted for
that variable — existing env values always win.  This allows local overrides
during dev without touching the vault.

──────────────────────────────────────────────────────────────────────────────
INFISICAL
──────────────────────────────────────────────────────────────────────────────
Set SECRETS_BACKEND=infisical plus:

  INFISICAL_URL=https://infisical.yourdomain.com   (self-hosted) or omit for cloud
  INFISICAL_CLIENT_ID=<machine-identity-client-id>
  INFISICAL_CLIENT_SECRET=<machine-identity-client-secret>
  INFISICAL_PROJECT_ID=<project-id>
  INFISICAL_ENVIRONMENT=prod   (dev | staging | prod)

Secret naming:  both FOO_BAR and FOO-BAR are accepted in Infisical.
  The lookup tries the hyphenated form first, then the underscore form,
  so secrets uploaded via the CSV template (underscores) resolve automatically.

Required package:
  infisical-python>=2.0.0

Infisical Machine Identity setup (run once in Infisical UI):
  1. Create a Machine Identity in your Infisical project
  2. Assign it the "developer" or "reader" role on the project
  3. Copy the Client ID and Client Secret into your .env as above

For production (Azure Arc):
  Use Infisical's "Native Azure Auth" machine identity — the machine identity
  authenticates with Azure Arc MSI instead of a client secret.
  Set INFISICAL_AZURE_RESOURCE=https://management.azure.com/ (or any resource URL).
  Remove INFISICAL_CLIENT_SECRET; Infisical SDK will call the Arc MSI endpoint.

──────────────────────────────────────────────────────────────────────────────
ADDING A NEW SECRET (any backend)
──────────────────────────────────────────────────────────────────────────────
1. Store it in the vault:
     Azure:      az keyvault secret set --vault-name ... --name MY-NEW-SECRET --value ...
     HashiCorp:  vault kv put secret/cycentra/MY-NEW-SECRET value=...
     Infisical:  infisical secrets set MY_NEW_SECRET=value --env prod

2. Add the mapping below in the correct map (FLASK_KV_MAP / ENGINE_KV_MAP / ASM_KV_MAP):
     Azure/HashiCorp:  "MY_NEW_SECRET": "MY-NEW-SECRET",
     Infisical:        "MY_NEW_SECRET": "MY_NEW_SECRET",

3. Read it in code as usual:
     MY_NEW_SECRET = os.environ.get("MY_NEW_SECRET", "")

No other files need changing.
"""

import logging
import os

log = logging.getLogger("cycentra.kv_secrets")

# ── Secret maps: env-var name → vault secret name ─────────────────────────────
# Split so each process only fetches secrets it actually needs.
# Secret names use hyphens (Azure KV requirement); HashiCorp uses the same names
# for consistency — one naming convention across both backends.

# Flask backend (/opt/cycentra/.env)
#
# Only secrets that are COMPANY-WIDE (same value across every deployment) live
# here.  Install-specific values — generated by setup.sh or set once per server
# (SECRET_KEY, POSTGRES_PASSWORD, OIDC inter-service secrets, DB URLs, CyMind
# API key, etc.) — are intentionally excluded; they stay in .env on the server
# and are never pushed to or pulled from the vault.
FLASK_KV_MAP: dict[str, str] = {
    # ── Marketplace ────────────────────────────────────────────────────────────
    "MARKETPLACE_CATALOG_TOKEN": "MARKETPLACE-CATALOG-TOKEN",
    # ── OAuth2 / SSO app credentials (company-registered apps, same everywhere)
    "SSO_CLIENT_ID":            "SSO-CLIENT-ID",
    "SSO_CLIENT_SECRET":        "SSO-CLIENT-SECRET",
    "GOOGLE_CLIENT_ID":         "GOOGLE-CLIENT-ID",
    "GOOGLE_CLIENT_SECRET":     "GOOGLE-CLIENT-SECRET",
    "MICROSOFT_CLIENT_ID":      "MICROSOFT-CLIENT-ID",
    "MICROSOFT_CLIENT_SECRET":  "MICROSOFT-CLIENT-SECRET",
    # ── External integrations (company-level credentials) ─────────────────────
    "GH_TOKEN":                 "GH-TOKEN",
    "MAXMIND_KEY":              "MAXMIND-KEY",
    "CLOUD_MISP_URL":           "CLOUD-MISP-URL",
    "CLOUD_MISP_API_KEY":       "CLOUD-MISP-API-KEY",
    "CYMIND_API_URL":           "CYMIND-API-URL",
    "CYMIND_API_KEY":           "CYMIND-API-KEY",
    #
    # ── NOT in vault — reason ─────────────────────────────────────────────────
    # SMTP_PASSWORD       — UI-managed (cy_sso_config DB); host/user/from are
    #                       also UI fields so vault can't bootstrap SMTP alone
    # CLOUD_IRIS_URL      — hardcoded default in helpers.py + setup.sh writes
    #                       https://cyiris.cycentra.com to .env at install time
    # SECRET_KEY, JWT_SECRET, ADMIN_API_KEY         — openssl rand per install
    # CYCENTRA_DB_URL, POSTGRES_PASSWORD             — per-install DB credentials
    # OAUTH2PROXY_SECRET, OAUTH2PROXY_COOKIE_SECRET  — openssl rand per install
    # CYIRIS_OIDC_SECRET, CYSIEM_OIDC_SECRET,
    #   CY360SSO_OIDC_SECRET                         — openssl rand per install
    # IRIS_SECRET_KEY, IRIS_DB_PASS, IRIS_ADM_PASSWORD — per-install CyIRIS
    # NODE_RED_CREDENTIAL_SECRET                     — openssl rand per install
    # IRIS_API_KEY, CLOUD_IRIS_API_KEY               — written by platform UI
    # CYSOAR_SESSION_SECRET                          — alias of NODE_RED_CREDENTIAL_SECRET
}

# Correlation engine (/opt/cycentra/cysiemstack.env) — separate process
#
# Only company-wide credentials here.  Install-specific values are excluded:
#   CORRELATION_DB_URL — per-install PostgreSQL connection string
#   WAZUH_API_*        — auto-detected by setup.sh from local Wazuh config
#   IRIS_API_KEY, CLOUD_IRIS_API_KEY — written by UI (_sync_iris_to_siem_env)
ENGINE_KV_MAP: dict[str, str] = {
    "CLOUD_MISP_URL":     "CLOUD-MISP-URL",
    "CLOUD_MISP_API_KEY": "CLOUD-MISP-API-KEY",
    "CYMIND_API_URL":     "CYMIND-API-URL",
    "CYMIND_API_KEY":     "CYMIND-API-KEY",
}

# CyASM scanning modules
ASM_KV_MAP: dict[str, str] = {
    "IPINFO_API_KEY":         "IPINFO-API-KEY",
    "SECURITYTRAILS_API_KEY": "SECURITYTRAILS-API-KEY",
    "VIRUSTOTAL_API_KEY":     "VIRUSTOTAL-API-KEY",
    "NVD_API_KEY":            "NVD-API-KEY",
    "SHODAN_API_KEY":         "SHODAN-API-KEY",
    "GOOGLE_GEMINI_KEY":      "GOOGLE-GEMINI-KEY",
    "HUNTER_API_KEY":         "HUNTER-API-KEY",
    "HIBP_API_KEY":           "HIBP-API-KEY",
    "GVM_PASSWORD":           "GVM-PASSWORD",
    "GVM_USER":               "GVM-USER",
}


# ── Azure Key Vault backend ────────────────────────────────────────────────────

def _azure_fetch(kv_map: dict[str, str], force: bool = False) -> int:
    vault_url = os.environ.get("AZURE_KEYVAULT_URL", "").strip()
    if not vault_url:
        log.debug("AZURE_KEYVAULT_URL not set — Azure backend skipped")
        return 0

    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
    except ImportError:
        log.warning(
            "azure-identity / azure-keyvault-secrets not installed — "
            "run: pip install azure-identity azure-keyvault-secrets"
        )
        return 0

    try:
        client = SecretClient(
            vault_url=vault_url.rstrip("/"),
            credential=DefaultAzureCredential(),
        )
    except Exception as exc:
        log.error("Azure Key Vault client init failed: %s", exc)
        return 0

    fetched = 0
    for env_key, secret_name in kv_map.items():
        if not force and os.environ.get(env_key):
            continue
        try:
            secret = client.get_secret(secret_name)
            if secret.value:
                os.environ[env_key] = secret.value
                fetched += 1
                log.debug("Azure KV → loaded %s", env_key)
        except Exception as exc:
            log.warning("Azure KV: could not fetch '%s': %s", secret_name, exc)

    log.info("Azure Key Vault: %d/%d secret(s) loaded", fetched, len(kv_map))
    return fetched


# ── HashiCorp Vault backend ────────────────────────────────────────────────────

def _hashicorp_fetch(kv_map: dict[str, str], force: bool = False) -> int:
    vault_addr = os.environ.get("VAULT_ADDR", "").strip()
    if not vault_addr:
        log.debug("VAULT_ADDR not set — HashiCorp backend skipped")
        return 0

    try:
        import hvac
    except ImportError:
        log.warning(
            "hvac not installed — run: pip install hvac>=2.0.0"
        )
        return 0

    mount   = os.environ.get("VAULT_MOUNT", "secret")
    prefix  = os.environ.get("VAULT_PATH_PREFIX", "cycentra").strip("/")

    # ── Authenticate ──────────────────────────────────────────────────────────
    client = hvac.Client(url=vault_addr)

    token = os.environ.get("VAULT_TOKEN", "").strip()
    if token:
        client.token = token
        log.debug("HashiCorp Vault: using VAULT_TOKEN auth")
    else:
        role_id   = os.environ.get("VAULT_ROLE_ID", "").strip()
        secret_id = os.environ.get("VAULT_SECRET_ID", "").strip()
        if not role_id or not secret_id:
            log.error(
                "HashiCorp Vault: set VAULT_TOKEN or both VAULT_ROLE_ID + VAULT_SECRET_ID"
            )
            return 0
        try:
            client.auth.approle.login(role_id=role_id, secret_id=secret_id)
            log.debug("HashiCorp Vault: AppRole login successful")
        except Exception as exc:
            log.error("HashiCorp Vault: AppRole login failed: %s", exc)
            return 0

    if not client.is_authenticated():
        log.error("HashiCorp Vault: client is not authenticated")
        return 0

    # ── Fetch secrets ─────────────────────────────────────────────────────────
    fetched = 0
    for env_key, secret_name in kv_map.items():
        if not force and os.environ.get(env_key):
            continue
        path = f"{prefix}/{secret_name}"
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=mount,
                raise_on_deleted_version=True,
            )
            value = response["data"]["data"].get("value", "")
            if value:
                os.environ[env_key] = value
                fetched += 1
                log.debug("HashiCorp Vault → loaded %s from %s", env_key, path)
            else:
                log.warning(
                    "HashiCorp Vault: secret at '%s' exists but has no 'value' key — "
                    "store secrets as: vault kv put %s/%s value=YOUR_SECRET",
                    path, mount, path,
                )
        except Exception as exc:
            log.warning("HashiCorp Vault: could not fetch '%s': %s", path, exc)

    log.info("HashiCorp Vault: %d/%d secret(s) loaded", fetched, len(kv_map))
    return fetched


# ── Infisical backend ──────────────────────────────────────────────────────────

def _fetch_arc_jwt(resource: str = "https://management.azure.com/") -> str:
    """
    Fetch a managed-identity JWT from the Azure Arc HIMDS endpoint.

    HIMDS uses a filesystem-based challenge-response to prove the caller
    is a local process (not an SSRF):
      1. GET /metadata/identity/oauth2/token → 401 + Www-Authenticate header
         with realm=<path-to-key-file>
      2. Read that key file — its content IS the Basic auth password (the key
         file is already base64, so no further encoding is needed).
      3. Re-send with Authorization: Basic <raw-key-content> → 200 + JWT.

    Returns the access_token string, or "" on any failure.
    """
    import json as _json
    import re as _re
    import urllib.request as _urlrequest

    _arc_url = (
        "http://localhost:40342/metadata/identity/oauth2/token"
        f"?api-version=2020-06-01&resource={resource}"
    )
    try:
        # Step 1 — get challenge
        _req0 = _urlrequest.Request(_arc_url, headers={"Metadata": "true"})
        try:
            _urlrequest.urlopen(_req0, timeout=5)
            log.error("Infisical Arc: HIMDS returned 200 without challenge — unexpected")
            return ""
        except _urlrequest.HTTPError as _e0:
            if _e0.code != 401:
                log.error("Infisical Arc: HIMDS returned %s (expected 401 challenge)", _e0.code)
                return ""
            _auth_hdr = _e0.headers.get("Www-Authenticate", "")
            _m = _re.search(r"realm=(\S+)", _auth_hdr)
            if not _m:
                log.error("Infisical Arc: no realm path in HIMDS Www-Authenticate header")
                return ""
            _key_path = _m.group(1)

        # Step 2 — read challenge key (its content is the raw Basic auth value)
        with open(_key_path) as _f:
            _raw_key = _f.read().strip()

        # Step 3 — authenticate
        _req1 = _urlrequest.Request(
            _arc_url,
            headers={"Metadata": "true", "Authorization": f"Basic {_raw_key}"},
        )
        with _urlrequest.urlopen(_req1, timeout=10) as _resp:
            _token = _json.loads(_resp.read().decode()).get("access_token", "")
            if _token:
                log.debug("Infisical Arc: HIMDS JWT obtained successfully")
            return _token

    except Exception as _exc:
        log.error(
            "Infisical Arc: could not fetch JWT from Azure Arc HIMDS "
            "(localhost:40342) — is azcmagent/himdsd running? %s", _exc
        )
        return ""


def _infisical_fetch(kv_map: dict[str, str], force: bool = False) -> int:
    """
    Fetches secrets from Infisical using one of three auth methods.
    Select via INFISICAL_AUTH_METHOD in .env:

      azure     — Fetches an Azure Arc JWT from localhost:40342 and authenticates
                  via Infisical OIDC REST endpoint (infisical-python v2 has no native oidc_auth method).
                  REQUIRES: Azure Arc agent enrolled and running on this server.
                  Machine Identity type in Infisical UI: MUST be "OIDC" (not
                  "Azure Native Auth" — that type requires SDK v2.x which is not
                  yet available on PyPI).  Configure the OIDC identity with:
                    OIDC Discovery URL:  https://sts.windows.net/<tenant>/
                    Bound Issuer:        https://sts.windows.net/<tenant>/
                    Bound Subject:       <managed-identity Object ID from Azure Portal>
                    Bound Audiences:     https://management.azure.com
                  Note: Arc issues v1.0 tokens — issuer is STS URL, not login.microsoft
                  Required env var: INFISICAL_CLIENT_ID (Infisical Machine Identity ID)
                  If you previously created an "Azure Native Auth" identity, delete
                  it and create a new one of type "OIDC" with the settings above.

      oidc      — Alias for "azure" — same behaviour (Arc JWT → OIDC login).
                  Use this explicitly to be clear about the identity type.
                  Machine Identity type in Infisical UI: "OIDC"
                  Required env var: INFISICAL_CLIENT_ID (Machine Identity ID)

      universal — Client ID + Client Secret authentication.
                  Works on ANY server — no Azure Arc required.
                  Use this for on-prem servers, non-Azure VMs, or any host
                  not enrolled in Azure Arc.  This is the correct choice for
                  most CyCentra 360 deployments.
                  Machine Identity type in Infisical UI: "Universal Auth"
                  Required env vars: INFISICAL_CLIENT_ID + INFISICAL_CLIENT_SECRET
    """
    project_id = os.environ.get("INFISICAL_PROJECT_ID", "").strip()
    environment = os.environ.get("INFISICAL_ENVIRONMENT", "prod").strip()
    if not project_id:
        log.debug("INFISICAL_PROJECT_ID not set — Infisical backend skipped")
        return 0

    try:
        from infisical_client import (
            InfisicalClient, ClientSettings, AuthenticationOptions,
            UniversalAuthMethod, GetSecretOptions,
        )
    except ImportError:
        log.warning(
            "infisical-python not installed — run: pip install infisical-python>=2.0.0"
        )
        return 0

    client_id = os.environ.get("INFISICAL_CLIENT_ID", "").strip()
    if not client_id:
        log.error("Infisical: INFISICAL_CLIENT_ID is required")
        return 0

    client_secret = os.environ.get("INFISICAL_CLIENT_SECRET", "").strip()
    auth_method = os.environ.get("INFISICAL_AUTH_METHOD", "azure").strip().lower()
    # Infer method from presence of client secret if not explicitly set
    if os.environ.get("INFISICAL_AUTH_METHOD", "").strip() == "" and client_secret:
        auth_method = "universal"

    infisical_url = os.environ.get("INFISICAL_URL", "https://app.infisical.com").rstrip("/")

    try:
        if auth_method == "universal":
            # Any server without Azure Arc — client ID + secret from Infisical Universal Auth identity
            if not client_secret:
                log.error("Infisical universal auth: INFISICAL_CLIENT_SECRET is required")
                return 0
            auth = AuthenticationOptions(
                universal_auth=UniversalAuthMethod(
                    client_id=client_id,
                    client_secret=client_secret,
                )
            )
            log.debug("Infisical: authenticated via Universal Auth")

        elif auth_method in ("oidc", "azure"):
            # Fetch Arc JWT via HIMDS challenge-response, then exchange for an
            # Infisical access token via the OIDC REST endpoint.
            # Machine Identity type in Infisical UI must be "OIDC".
            arc_jwt = _fetch_arc_jwt()
            if not arc_jwt:
                return 0
            import requests as _req
            resp = _req.post(
                f"{infisical_url}/api/v1/auth/oidc-auth/login",
                json={"identityId": client_id, "jwt": arc_jwt},
                timeout=10,
            )
            resp.raise_for_status()
            access_token = resp.json().get("accessToken", "")
            if not access_token:
                log.error("Infisical OIDC: no accessToken in login response")
                return 0
            auth = AuthenticationOptions(access_token=access_token)
            log.debug("Infisical: authenticated via Arc OIDC (JWT exchange)")

        else:
            log.error("Infisical: unknown INFISICAL_AUTH_METHOD=%s", auth_method)
            return 0

        client = InfisicalClient(
            settings=ClientSettings(site_url=infisical_url, auth=auth)
        )

    except Exception as exc:
        log.error("Infisical: authentication failed: %s", exc)
        return 0

    fetched = 0
    for env_key, secret_name in kv_map.items():
        if not force and os.environ.get(env_key):
            continue
        # Infisical allows any naming convention.  Try the canonical name first
        # (which uses hyphens to match Azure KV), then fall back to the underscore
        # form so secrets uploaded via the CSV template (FOO_BAR) also resolve.
        underscore_name = secret_name.replace("-", "_")
        candidates = [secret_name] if secret_name == underscore_name else [secret_name, underscore_name]
        loaded = False
        for name in candidates:
            try:
                secret = client.getSecret(GetSecretOptions(
                    secret_name=name,
                    project_id=project_id,
                    environment=environment,
                    path="/",
                ))
                value = getattr(secret, "secret_value", None)
                if value:
                    os.environ[env_key] = value
                    fetched += 1
                    log.debug("Infisical → loaded %s (key=%s)", env_key, name)
                    loaded = True
                    break
            except Exception:
                continue
        if not loaded:
            log.debug("Infisical: secret not found for %s (tried: %s)", env_key, ", ".join(candidates))

    log.info("Infisical: %d/%d secret(s) loaded", fetched, len(kv_map))
    return fetched


# ── Public entry point ─────────────────────────────────────────────────────────

def load_kv_secrets(kv_map: dict[str, str] | None = None, force: bool = False) -> None:
    """
    Fetch secrets from the configured backend and inject into os.environ.

    Called at import time by:
      core/config.py                              → FLASK_KV_MAP
      cysiemstack/correlation_engine/config.py    → ENGINE_KV_MAP
      cy_asm/config.py                            → ASM_KV_MAP

    Parameters
    ----------
    force : bool
        When False (default), keys already present in os.environ are skipped
        (systemd EnvironmentFile wins over vault — safe fallback mode).
        When True, vault values overwrite existing os.environ values.
        Use force=True only in the rotation sync path (pull_to_env).

    Switch backends by setting SECRETS_BACKEND in .env:
      SECRETS_BACKEND=azure       (default)
      SECRETS_BACKEND=hashicorp
      SECRETS_BACKEND=infisical
    """
    if kv_map is None:
        kv_map = FLASK_KV_MAP

    backend = os.environ.get("SECRETS_BACKEND", "azure").strip().lower()

    if backend == "hashicorp":
        _hashicorp_fetch(kv_map, force=force)
    elif backend == "infisical":
        _infisical_fetch(kv_map, force=force)
    else:
        _azure_fetch(kv_map, force=force)


def pull_to_env(
    env_path: str = "/opt/cycentra/.env",
    kv_map: dict[str, str] | None = None,
) -> int:
    """
    Pull the latest values from the vault and write them back to the .env file.

    Use this for **secret rotation**:
      1. Update the secret in your vault (Infisical / Azure KV / HashiCorp)
      2. Run:  python3 -c "from core.kv_secrets import pull_to_env; pull_to_env()"
      3. Restart the service: systemctl restart cycentra

    This is the correct way to rotate secrets without a full reinstall.
    The .env file is updated in-place — only keys present in kv_map are touched.
    Returns the number of keys written.
    """
    import pathlib
    import re as _re

    if kv_map is None:
        kv_map = FLASK_KV_MAP

    # Force-fetch vault values into a scratch copy of os.environ
    saved = {k: os.environ.get(k) for k in kv_map}
    load_kv_secrets(kv_map, force=True)

    env_file = pathlib.Path(env_path)
    lines = env_file.read_text().splitlines() if env_file.exists() else []

    updated, seen = [], set()
    for line in lines:
        key = line.split("=", 1)[0].strip()
        if key in kv_map and os.environ.get(key):
            updated.append(f"{key}={os.environ[key]}")
            seen.add(key)
        else:
            updated.append(line)

    # Append any keys that were not already in the file
    for key in kv_map:
        if key not in seen and os.environ.get(key):
            updated.append(f"{key}={os.environ[key]}")

    env_file.write_text("\n".join(updated) + "\n")
    written = sum(1 for k in kv_map if os.environ.get(k))
    log.info("pull_to_env: %d/%d secrets written to %s", written, len(kv_map), env_path)

    # Restore os.environ so this call is side-effect-free for the running process
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v

    return written
