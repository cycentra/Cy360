from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    # Database — native PostgreSQL on localhost
    # Port 5433 used to avoid conflict with CyIRIS postgres on :5432
    database_url: str = "postgresql+asyncpg://corruser:changeme@127.0.0.1:5433/correlation"

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
    correlation_window_minutes: int = 15
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
    # this value are placed in "held" status for re-enrichment after 30 min.
    fp_watch_zone_upper: float = 65.0

    # CySOAR (Node-RED) webhook URL — empty string means SOAR is not configured.
    soar_webhook_url: str = ""

    # TLS CA bundle path for outbound httpx calls (MISP, IRIS).
    # Set to the path of a CA certificate bundle to verify self-signed certs.
    # Leave empty to use the system default CA store.
    tls_ca_bundle: str = ""

    model_config = SettingsConfigDict(
        env_file="/opt/cycentra/cysiemstack.env",
        case_sensitive=False,
        # Ignore unrecognised keys (e.g. POSTGRES_PASSWORD stored for --update convenience)
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    return Settings()
