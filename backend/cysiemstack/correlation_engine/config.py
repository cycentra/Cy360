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
    # Port 5433 to avoid conflict with any other postgres instance on :5432
    database_url: str = "postgresql+asyncpg://corruser:@127.0.0.1:5433/correlation"

    # Redis — native Redis on localhost
    redis_url: str = "redis://127.0.0.1:6379/0"
    redis_alert_key: str = "cysiemstack:alerts:raw"

    # Wazuh Manager API (native install — localhost)
    wazuh_api_url: str = "https://127.0.0.1:55000"
    wazuh_api_user: str = "wazuh-wui"
    wazuh_api_password: str = ""

    # CyTIM — Threat Intelligence Manager (single broker for MISP, VT, AbuseIPDB, GreyNoise)
    # Set CYTIM_URL and CYTIM_API_KEY in /opt/cycentra/cysiemstack.env to enable enrichment.
    cytim_url:     str = ""
    cytim_api_key: str = ""

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

    # ── CyCases / DFIR IRIS Integration ──────────────────────────────────────
    # Written by _sync_iris_to_siem_env() in system/routes.py whenever the
    # portal saves CyCases settings.  Values: "disabled" | "cloud" | "local"
    iris_mode: str = "disabled"
    iris_url: str = ""
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

    # TLS CA bundle path for outbound httpx calls (IRIS).
    # Set to the path of a CA certificate bundle to verify self-signed certs.
    # Leave empty to use the system default CA store.
    tls_ca_bundle: str = ""

    @model_validator(mode='after')
    def _bridge_cytim_env(self) -> 'Settings':
        """Pick up CYTIM_URL / CYTIM_API_KEY from os.environ (vault-injected)
        or ai_settings.json (UI-configured) when not set in cysiemstack.env."""
        if not self.cytim_url:
            self.cytim_url = os.environ.get("CYTIM_URL", "").strip().rstrip("/")
        if not self.cytim_api_key:
            self.cytim_api_key = os.environ.get("CYTIM_API_KEY", "").strip()
        # Final fallback: read from ai_settings.json (written by the portal UI).
        # This means no env file entry is needed when CyTIM is configured via the UI.
        if not self.cytim_url or not self.cytim_api_key:
            try:
                import json as _json
                _p = "/opt/cycentra/ai_settings.json"
                if os.path.exists(_p):
                    _d = _json.loads(open(_p).read())
                    _cytim = _d.get("cytim", {})
                    if not self.cytim_url:
                        self.cytim_url = (_cytim.get("url") or "").strip().rstrip("/")
                    if not self.cytim_api_key:
                        self.cytim_api_key = (_cytim.get("apiKey") or "").strip()
            except Exception:
                pass
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
