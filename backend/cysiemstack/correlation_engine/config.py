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

    model_config = SettingsConfigDict(
        env_file="/opt/cycentra/cysiemstack.env",
        case_sensitive=False,
        # Ignore unrecognised keys (e.g. POSTGRES_PASSWORD stored for --update convenience)
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    return Settings()
