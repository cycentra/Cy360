from pydantic_settings import BaseSettings
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

    # Ollama (native install — localhost)
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.1:8b"
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

    class Config:
        env_file = "/opt/cycentra/cysiemstack.env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()
