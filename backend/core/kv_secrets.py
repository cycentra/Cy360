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

For Infisical, also set INFISICAL_AUTH_METHOD:
  INFISICAL_AUTH_METHOD=azure      → Azure Native Auth via Arc MSI (default)
  INFISICAL_AUTH_METHOD=oidc       → Manual Arc JWT exchange (OIDC identity type)
  INFISICAL_AUTH_METHOD=universal  → Client ID + Secret (dev/staging)

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

Secret naming:  env var FOO_BAR  →  Infisical secret name  FOO_BAR  (underscores kept)

Required package:
  infisicalsdk>=2.0.0

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
FLASK_KV_MAP: dict[str, str] = {
    # ── Core platform ──────────────────────────────────────────────────────────
    "SECRET_KEY":               "SECRET-KEY",
    "JWT_SECRET":               "JWT-SECRET",
    "ADMIN_API_KEY":            "ADMIN-API-KEY",
    "CYCENTRA_DB_URL":          "CYCENTRA-DB-URL",
    "POSTGRES_PASSWORD":        "POSTGRES-PASSWORD",
    "MARKETPLACE_CATALOG_TOKEN": "MARKETPLACE-CATALOG-TOKEN",
    # ── OIDC / OAuth2 ──────────────────────────────────────────────────────────
    "OAUTH2PROXY_SECRET":        "OAUTH2PROXY-SECRET",
    "OAUTH2PROXY_COOKIE_SECRET": "OAUTH2PROXY-COOKIE-SECRET",
    "CYIRIS_OIDC_SECRET":       "CYIRIS-OIDC-SECRET",
    "CYSIEM_OIDC_SECRET":       "CYSIEM-OIDC-SECRET",
    "CY360SSO_OIDC_SECRET":     "CY360SSO-OIDC-SECRET",
    "SSO_CLIENT_ID":            "SSO-CLIENT-ID",
    "SSO_CLIENT_SECRET":        "SSO-CLIENT-SECRET",
    "GOOGLE_CLIENT_ID":         "GOOGLE-CLIENT-ID",
    "GOOGLE_CLIENT_SECRET":     "GOOGLE-CLIENT-SECRET",
    "MICROSOFT_CLIENT_ID":      "MICROSOFT-CLIENT-ID",
    "MICROSOFT_CLIENT_SECRET":  "MICROSOFT-CLIENT-SECRET",
    # ── Sub-service credentials ────────────────────────────────────────────────
    "IRIS_API_KEY":             "IRIS-API-KEY",
    "IRIS_SECRET_KEY":          "IRIS-SECRET-KEY",
    "IRIS_DB_PASS":             "IRIS-DB-PASS",
    "IRIS_ADM_PASSWORD":        "IRIS-ADM-PASSWORD",
    "NODE_RED_CREDENTIAL_SECRET": "NODE-RED-CREDENTIAL-SECRET",
    "CYSOAR_SESSION_SECRET":    "CYSOAR-SESSION-SECRET",
    # ── Email ──────────────────────────────────────────────────────────────────
    "SMTP_PASSWORD":            "SMTP-PASSWORD",
    # ── External integrations ──────────────────────────────────────────────────
    "GH_TOKEN":                 "GH-TOKEN",
    "MAXMIND_KEY":              "MAXMIND-KEY",
    "CLOUD_MISP_URL":           "CLOUD-MISP-URL",
    "CLOUD_MISP_API_KEY":       "CLOUD-MISP-API-KEY",
    "CLOUD_IRIS_URL":           "CLOUD-IRIS-URL",
    "CLOUD_IRIS_API_KEY":       "CLOUD-IRIS-API-KEY",
}

# Correlation engine (/opt/cycentra/cysiemstack.env) — separate process
ENGINE_KV_MAP: dict[str, str] = {
    "WAZUH_API_URL":      "WAZUH-API-URL",
    "WAZUH_API_USER":     "WAZUH-API-USER",
    "WAZUH_API_PASSWORD": "WAZUH-API-PASSWORD",
    "CORRELATION_DB_URL": "CORRELATION-DB-URL",
    "CLOUD_IRIS_URL":     "CLOUD-IRIS-URL",
    "CLOUD_IRIS_API_KEY": "CLOUD-IRIS-API-KEY",
    "CLOUD_MISP_URL":     "CLOUD-MISP-URL",
    "CLOUD_MISP_API_KEY": "CLOUD-MISP-API-KEY",
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
}


# ── Azure Key Vault backend ────────────────────────────────────────────────────

def _azure_fetch(kv_map: dict[str, str]) -> int:
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
        if os.environ.get(env_key):
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

def _hashicorp_fetch(kv_map: dict[str, str]) -> int:
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
        if os.environ.get(env_key):
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

def _infisical_fetch(kv_map: dict[str, str]) -> int:
    """
    Fetches secrets from Infisical using one of three auth methods.
    Select via INFISICAL_AUTH_METHOD in .env:

      azure     (default) — Azure Native Auth via Arc Managed Identity.
                            SDK calls the local Arc MSI endpoint internally.
                            Machine Identity must be configured as "Azure Auth"
                            type in Infisical UI.
                            Required: INFISICAL_CLIENT_ID (Machine Identity ID)

      oidc      — Manually fetches the Arc JWT from localhost:40342 and trades
                  it for an Infisical session via OIDC login.  Equivalent to
                  the JS pattern: fetch Arc token → client.auth.oidc.login().
                  Machine Identity must be configured as "OIDC" type in Infisical UI.
                  Required: INFISICAL_CLIENT_ID (Machine Identity ID)

      universal — Client ID + Secret (for dev machines and staging environments
                  that are not Arc-enrolled).
                  Required: INFISICAL_CLIENT_ID + INFISICAL_CLIENT_SECRET
    """
    project_id = os.environ.get("INFISICAL_PROJECT_ID", "").strip()
    environment = os.environ.get("INFISICAL_ENVIRONMENT", "prod").strip()
    if not project_id:
        log.debug("INFISICAL_PROJECT_ID not set — Infisical backend skipped")
        return 0

    try:
        from infisicalsdk import InfisicalSDKClient
    except ImportError:
        log.warning(
            "infisicalsdk not installed — run: pip install infisicalsdk>=2.0.0"
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
        client = InfisicalSDKClient(host=infisical_url)

        if auth_method == "universal":
            # Developer machines and staging — client ID + secret
            if not client_secret:
                log.error("Infisical universal auth: INFISICAL_CLIENT_SECRET is required")
                return 0
            client.auth.universal_auth.login(
                client_id=client_id,
                client_secret=client_secret,
            )
            log.debug("Infisical: authenticated via Universal Auth")

        elif auth_method == "oidc":
            # OIDC path — manually fetch Arc JWT from localhost:40342 and trade
            # for an Infisical session.  Mirrors the JS SDK pattern:
            #   fetch(arcIdentityUrl) → arcData.access_token → client.auth.oidc.login()
            # Machine Identity must be "OIDC" type in Infisical UI.
            import json
            import urllib.request
            arc_url = (
                "http://localhost:40342/identity/oauth2/token"
                "?api-version=2020-06-01"
                "&resource=https://management.azure.com/"
            )
            try:
                req = urllib.request.Request(arc_url, headers={"Metadata": "true"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    arc_jwt = json.loads(resp.read().decode())["access_token"]
            except Exception as exc:
                log.error(
                    "Infisical OIDC: could not reach Azure Arc MSI endpoint "
                    "(localhost:40342) — is azcmagent running? %s", exc
                )
                return 0
            client.auth.oidc.login(identity_id=client_id, jwt=arc_jwt)
            log.debug("Infisical: authenticated via Arc OIDC (manual JWT exchange)")

        else:
            # azure (default) — SDK calls Arc MSI endpoint internally.
            # Machine Identity must be "Azure Auth" type in Infisical UI.
            client.auth.azure_auth.login(client_id=client_id)
            log.debug("Infisical: authenticated via Azure Native Auth (Arc MSI)")

    except Exception as exc:
        log.error("Infisical: authentication failed: %s", exc)
        return 0

    fetched = 0
    for env_key, secret_name in kv_map.items():
        if os.environ.get(env_key):
            continue
        try:
            secret = client.secrets.get_secret_by_name(
                secret_name=secret_name,
                project_id=project_id,
                environment_slug=environment,
                secret_path="/",
            )
            value = secret.secret_value
            if value:
                os.environ[env_key] = value
                fetched += 1
                log.debug("Infisical → loaded %s", env_key)
            else:
                log.warning("Infisical: secret '%s' exists but is empty", secret_name)
        except Exception as exc:
            log.warning("Infisical: could not fetch '%s': %s", secret_name, exc)

    log.info("Infisical: %d/%d secret(s) loaded", fetched, len(kv_map))
    return fetched


# ── Public entry point ─────────────────────────────────────────────────────────

def load_kv_secrets(kv_map: dict[str, str] | None = None) -> None:
    """
    Fetch secrets from the configured backend and inject into os.environ.

    Called at import time by:
      core/config.py                              → FLASK_KV_MAP
      cysiemstack/correlation_engine/config.py    → ENGINE_KV_MAP
      cy_asm/config.py                            → ASM_KV_MAP

    Switch backends by setting SECRETS_BACKEND in .env:
      SECRETS_BACKEND=azure       (default)
      SECRETS_BACKEND=hashicorp
      SECRETS_BACKEND=infisical
    """
    if kv_map is None:
        kv_map = FLASK_KV_MAP

    backend = os.environ.get("SECRETS_BACKEND", "azure").strip().lower()

    if backend == "hashicorp":
        _hashicorp_fetch(kv_map)
    elif backend == "infisical":
        _infisical_fetch(kv_map)
    else:
        _azure_fetch(kv_map)
