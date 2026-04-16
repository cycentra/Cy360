"""
core/kv_secrets.py
==================
Fetches secrets from Azure Key Vault at process startup and injects them
into os.environ before core/config.py reads them.

Activation:   Set AZURE_KEYVAULT_URL=/opt/cycentra/.env (or cysiemstack.env)
              Example: AZURE_KEYVAULT_URL=https://my-vault.vault.azure.net/

Auth strategy (tried in order by DefaultAzureCredential):
  1. Managed Identity          — recommended for Azure VMs (zero credentials needed)
  2. Service Principal env vars — AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
  3. Azure CLI session         — useful for local dev (`az login`)

Secret naming convention in Key Vault:
  env var  FOO_BAR  →  KV secret name  FOO-BAR  (underscores replaced with hyphens,
  because Azure KV secret names only allow alphanumeric characters and hyphens)

Idempotency: if a variable is already present in the process environment (e.g. set
  via the systemd EnvironmentFile or shell export), KV is NOT consulted for that
  variable — existing env values always win.  This allows local overrides during dev
  and staged rollouts without touching Key Vault.

Required packages (add to requirements.txt / wheel dependencies):
  azure-identity>=1.15.0
  azure-keyvault-secrets>=4.7.0
"""

import logging
import os

log = logging.getLogger("cycentra.kv_secrets")

# ── Secrets map: env-var name → Key Vault secret name ─────────────────────────
# Only variables that were previously hardcoded in cycentra-setup.sh are listed.
# Add or remove entries here as secrets are rotated in/out of Key Vault.
#
# Split into two maps so each service only fetches the secrets it actually needs.

# Flask backend (.env) secrets
FLASK_KV_MAP: dict[str, str] = {
    "GOOGLE_CLIENT_ID":        "GOOGLE-CLIENT-ID",
    "GOOGLE_CLIENT_SECRET":    "GOOGLE-CLIENT-SECRET",
    "MICROSOFT_CLIENT_ID":     "MICROSOFT-CLIENT-ID",
    "MICROSOFT_CLIENT_SECRET": "MICROSOFT-CLIENT-SECRET",
    "IRIS_ADM_PASSWORD":       "IRIS-ADM-PASSWORD",
    "GH_TOKEN":                "GH-TOKEN",
    "MAXMIND_KEY":             "MAXMIND-KEY",
    "CLOUD_MISP_URL":          "CLOUD-MISP-URL",
    "CLOUD_MISP_API_KEY":      "CLOUD-MISP-API-KEY",
    "CLOUD_IRIS_URL":          "CLOUD-IRIS-URL",
    "CLOUD_IRIS_API_KEY":      "CLOUD-IRIS-API-KEY",
}

# Engine (cysiemstack.env) secrets — subset relevant to the correlation engine.
# Includes CLOUD_IRIS/MISP because iris_connector.py and misp_enricher.py read
# these from os.environ in the engine process (separate from the Flask process).
ENGINE_KV_MAP: dict[str, str] = {
    "WAZUH_API_PASSWORD": "WAZUH-API-PASSWORD",
    "CLOUD_IRIS_URL":     "CLOUD-IRIS-URL",
    "CLOUD_IRIS_API_KEY": "CLOUD-IRIS-API-KEY",
    "CLOUD_MISP_URL":     "CLOUD-MISP-URL",
    "CLOUD_MISP_API_KEY": "CLOUD-MISP-API-KEY",
}

# CyASM module secrets — API keys used by cy_asm scanning modules.
# These were previously hardcoded in config.py patch files.
ASM_KV_MAP: dict[str, str] = {
    "IPINFO_API_KEY":         "IPINFO-API-KEY",
    "SECURITYTRAILS_API_KEY": "SECURITYTRAILS-API-KEY",
    "VIRUSTOTAL_API_KEY":     "VIRUSTOTAL-API-KEY",
    "NVD_API_KEY":            "NVD-API-KEY",
    "SHODAN_API_KEY":         "SHODAN-API-KEY",
    "GOOGLE_GEMINI_KEY":      "GOOGLE-GEMINI-KEY",
    "HUNTER_API_KEY":         "HUNTER-API-KEY",
    "HIBP_API_KEY":           "HIBP-API-KEY",
}


def _get_client(vault_url: str):
    """Return an authenticated SecretClient, or None if packages are missing."""
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
    except ImportError:
        log.warning(
            "azure-identity or azure-keyvault-secrets not installed — "
            "install: pip install azure-identity azure-keyvault-secrets"
        )
        return None

    try:
        return SecretClient(
            vault_url=vault_url.rstrip("/"),
            credential=DefaultAzureCredential(),
        )
    except Exception as exc:
        log.error("Key Vault client init failed: %s", exc)
        return None


def _fetch(client, kv_map: dict[str, str]) -> int:
    """Inject secrets from kv_map into os.environ. Returns count of secrets loaded."""
    fetched = 0
    for env_key, kv_name in kv_map.items():
        if os.environ.get(env_key):
            log.debug("Skipping %s — already set in environment", env_key)
            continue
        try:
            secret = client.get_secret(kv_name)
            if secret.value:
                os.environ[env_key] = secret.value
                fetched += 1
                log.debug("Loaded %s from Key Vault secret '%s'", env_key, kv_name)
        except Exception as exc:
            log.warning("Could not fetch KV secret '%s': %s", kv_name, exc)
    return fetched


def load_kv_secrets(kv_map: dict[str, str] | None = None) -> None:
    """
    Fetch Key Vault secrets and inject into os.environ.

    Called automatically by core/config.py (Flask) and
    cysiemstack/correlation_engine/config.py (engine) at import time.

    Args:
        kv_map: override the default secret map. Pass ENGINE_KV_MAP from the
                engine's config to fetch only engine-relevant secrets.
                Defaults to FLASK_KV_MAP.
    """
    vault_url = os.environ.get("AZURE_KEYVAULT_URL", "").strip()
    if not vault_url:
        log.debug("AZURE_KEYVAULT_URL not set — Key Vault bootstrap skipped")
        return

    if kv_map is None:
        kv_map = FLASK_KV_MAP

    client = _get_client(vault_url)
    if client is None:
        return

    fetched = _fetch(client, kv_map)
    log.info(
        "Key Vault bootstrap complete: %d/%d secret(s) loaded from %s",
        fetched, len(kv_map), vault_url,
    )
