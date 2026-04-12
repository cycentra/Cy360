"""
mcp_server/config.py

Reads Wazuh API credentials and MCP bind settings from
/opt/cycentra/cysiemstack.env (the same file used by the correlation engine).
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class MCPSettings(BaseSettings):
    # Wazuh Manager API — same values as the correlation engine
    wazuh_api_url: str = "https://127.0.0.1:55000"
    wazuh_api_user: str = "wazuh-wui"
    wazuh_api_password: str = ""

    # Correlation engine internal address
    engine_url: str = "http://127.0.0.1:8100"

    # MCP server bind address
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8101

    model_config = SettingsConfigDict(
        env_file="/opt/cycentra/cysiemstack.env",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache()
def get_settings() -> MCPSettings:
    return MCPSettings()
