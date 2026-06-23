import os
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

# ── Azure Key Vault bootstrap ──────────────────────────────────────────────────
# Must run before Settings() is instantiated so pydantic-settings sees the
# injected values.  AZURE_KEYVAULT_URL must be present in cysiemstack.env
# (or the process environment) for this to activate.
try:
    from core.kv_secrets import load_kv_secrets, ENGINE_KV_MAP
    load_kv_secrets(ENGINE_KV_MAP)
except Exception:
    pass  # never block engine startup if KV is unreachable


class Settings(BaseSettings):
    # Database — native PostgreSQL on localhost
    # Port 5433 used to avoid conflict with CyIRIS postgres on :5432
    database_url: str = "postgresql+asyncpg://corruser:@127.0.0.1:5433/correlation"

    # Redis — native Redis on localhost
    redis_url: str = "redis://127.0.0.1:6379/0"
    redis_alert_key: str = "cysiemstack:alerts:raw"

    # Wazuh Manager API (native install — localhost)
    wazuh_api_url: str = "https://127.0.0.1:55000"
    wazuh_api_user: str = "wazuh-wui"
    wazuh_api_password: str = ""

    # MISP
    # misp_mode is written by _sync_misp_to_siem_env() in system/routes.py whenever
    # the portal saves MISP settings.  Values: "disabled" | "cloud" | "local"
    misp_mode: str = "disabled"
    misp_url: str = "http://127.0.0.1:8200"
    misp_api_key: str = ""
    misp_enabled: bool = False

    # LLM — provider and credentials are read from /opt/cycentra/ai_settings.json
    # (written by the AI Settings page in the portal — no separate config needed).
    # Set LLM_ENABLED=false to disable LLM enrichment entirely.
    llm_enabled: bool = True

    # Correlation engine tuning
    # CORRELATION_WINDOW_MINUTES — idle gap: no activity for N min → next alert
    #   opens a new incident. Effective for spaced attacks.
    # INCIDENT_MAX_AGE_MINUTES   — hard ceiling: an incident stops absorbing
    #   alerts unconditionally after this age, regardless of activity.
    #   This guard is what prevents continuous brute-force from growing one
    #   incident forever.  Set both values in /opt/cycentra/cysiemstack.env.
    correlation_window_minutes: int = 15
    incident_max_age_minutes:   int = 30
    ueba_baseline_days: int = 30
    risk_decay_hours: int = 24
    incident_id_prefix: str = "INC"
    log_level: str = "INFO"

    # UEBA ML
    ueba_ml_shadow_mode: bool = True
    ueba_ml_min_train_days: int = 7
    ueba_ml_model_dir: str = "/opt/cycentra/ml_models"
    ueba_ml_contamination: float = 0.05

    # ── DFIR IRIS (CyIRIS) Integration ───────────────────────────────────────
    # Written by _sync_iris_to_siem_env() in system/routes.py whenever the
    # portal saves CyIRIS settings.  Values: "disabled" | "cloud" | "local"
    iris_mode: str = "disabled"
    iris_url: str = "https://cyiris.cycentra.com"
    iris_api_key: str = ""
    iris_enabled: bool = False
    iris_customer_id: int = 1
    # False-positive auto-close threshold (0–100).  Incidents with a
    # fp_probability >= this value are closed automatically without a ticket.
    iris_fp_threshold: float = 90.0

    # Watch-zone upper bound (0–100).  Incidents between iris_fp_threshold and
    # this value are placed in "held" status for re-enrichment after hold_window_minutes.
    fp_watch_zone_upper: float = 65.0

    # Hold window duration (minutes) — how long a "held" incident waits before re-enrichment.
    hold_window_minutes: int = 30

    # CySOAR (Node-RED) webhook URL — empty string means SOAR is not configured.
    soar_webhook_url: str = ""

    # FP Pattern Auto-Close Threshold
    # Number of times an analyst must manually close a matching incident
    # before the system starts auto-closing future matches automatically.
    # Increase for stricter control; decrease for faster learning.
    fp_pattern_close_threshold: int = 5

    # CyMind integration — API key that CyMind must present to access /mcp/*
    # Generated and stored via POST /api/system/cymind in the portal.
    # Empty string disables key enforcement (MCP is still reachable internally).
    cymind_api_key: str = ""

    # TLS CA bundle path for outbound httpx calls (MISP, IRIS).
    # Set to the path of a CA certificate bundle to verify self-signed certs.
    # Leave empty to use the system default CA store.
    tls_ca_bundle: str = ""

    # ── External Threat Intelligence APIs (Phase 1) ───────────────────────────
    # Written by _sync_ti_to_siem_env() in system/routes.py when the portal
    # saves TI settings.  Leave empty to disable the respective source.
    vt_api_key:        str = ""   # VirusTotal v3
    abuseipdb_api_key: str = ""   # AbuseIPDB v2
    greynoise_api_key: str = ""   # GreyNoise Community/Enterprise

    @model_validator(mode='after')
    def _bridge_cloud_misp_creds(self) -> 'Settings':
        """Bridge CLOUD_MISP_URL / CLOUD_MISP_API_KEY (injected by ENGINE_KV_MAP
        vault bootstrap) into the engine MISP settings.  This ensures MISP
        enrichment works without the removed UI widget or a manual MISP_ENABLED
        flag in cysiemstack.env."""
        cloud_url = os.environ.get("CLOUD_MISP_URL", "").strip().rstrip("/")
        cloud_key = os.environ.get("CLOUD_MISP_API_KEY", "").strip()
        # Fill url from CLOUD_MISP_URL if the local setting is still the default
        if cloud_url and self.misp_url in ("", "http://127.0.0.1:8200"):
            self.misp_url = cloud_url
        # Fill api key from CLOUD_MISP_API_KEY if not already set in cysiemstack.env
        if cloud_key and not self.misp_api_key:
            self.misp_api_key = cloud_key
        # Auto-enable when credentials are now present
        if self.misp_api_key and not self.misp_enabled:
            self.misp_enabled = True
            if self.misp_mode == "disabled":
                self.misp_mode = "cloud"
        return self

    @model_validator(mode='after')
    def _bridge_ti_keys(self) -> 'Settings':
        """Bridge VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY / GREYNOISE_API_KEY from
        os.environ (injected by ENGINE_KV_MAP vault bootstrap) into the TI fields.
        UI-set values in cysiemstack.env (written by _sync_ti_to_siem_env) take
        priority — this only fills the field when the UI has not configured it."""
        if not self.vt_api_key:
            self.vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
        if not self.abuseipdb_api_key:
            self.abuseipdb_api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
        if not self.greynoise_api_key:
            self.greynoise_api_key = os.environ.get("GREYNOISE_API_KEY", "").strip()
        return self

    model_config = SettingsConfigDict(
        env_file="/opt/cycentra/cysiemstack.env",
        case_sensitive=False,
        # Ignore unrecognised keys (e.g. POSTGRES_PASSWORD stored for --update convenience)
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    return Settings()
