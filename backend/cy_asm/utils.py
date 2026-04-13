import json
import logging
import aiohttp
import re
import os
from pathlib import Path
from config import HTTP_TIMEOUT
from aiohttp_socks import ProxyConnector

def setup_logging():
    logger = logging.getLogger("CyCentra")
    
    # Prevent duplicate handlers if setup_logging is called multiple times
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        
        # 1. Terminal Output (StreamHandler)
        sh = logging.StreamHandler()
        sh.setFormatter(formatter)
        logger.addHandler(sh)

        # 2. File Output (Troubleshooting Log)
        # We ensure the log directory exists before writing
        log_dir = Path("/var/log/cycentra/cy-asm/logs")
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_dir / "cycentra_engine.log")
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception as e:
            # Fallback if permissions to /var/log/ are denied
            print(f"⚠️ Warning: Could not create log file at {log_dir}: {e}")

    return logger

async def create_async_session(proxy_url=None) -> aiohttp.ClientSession:
    if proxy_url:
        connector = ProxyConnector.from_url(proxy_url)
    else:
        connector = aiohttp.TCPConnector(ssl=False)
    
    return aiohttp.ClientSession(connector=connector)

def validate_domain(domain: str) -> bool:
    if not domain: 
        return False
    return bool(re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain))


_CLOUD_MISP_URL_DEFAULT = "https://cymisp.cycentra.com"
_AI_SETTINGS_PATH = Path("/opt/cycentra/ai_settings.json")


def get_misp_config() -> dict | None:
    """
    Return the active MISP connection config {url, apiKey, mode} or None if
    disabled / credentials are missing.

    Delegates to core.helpers.get_misp_config() when running inside the full
    CyCentra stack (preferred — single source of truth).  Falls back to reading
    ai_settings.json directly so the ASM modules work in standalone / test runs
    without the Flask app being present.
    """
    try:
        from core.helpers import get_misp_config as _core_get_misp_config
        return _core_get_misp_config()
    except (ImportError, ModuleNotFoundError):
        # Running outside the full Flask stack (e.g. standalone scan or tests).
        pass
    except Exception as e:
        logging.getLogger("CyCentra").warning(f"[MISP] core.helpers.get_misp_config failed: {e}")

    # Standalone fallback: read ai_settings.json directly
    try:
        raw = _AI_SETTINGS_PATH.read_text() if _AI_SETTINGS_PATH.exists() else "{}"
        settings = json.loads(raw)
    except (OSError, json.JSONDecodeError) as e:
        logging.getLogger("CyCentra").warning(f"[MISP] Could not read ai_settings.json: {e}")
        return None

    misp = settings.get("misp", {})
    mode = misp.get("mode", "")

    if not mode:
        stored_key = misp.get("apiKey", "").strip()
        if stored_key and not misp.get("url", "").strip():
            mode = "cloud"
        else:
            mode = "disabled"

    if mode == "cloud":
        url = os.environ.get("CLOUD_MISP_URL", _CLOUD_MISP_URL_DEFAULT).rstrip("/")
        key = os.environ.get("CLOUD_MISP_API_KEY", "").strip() or misp.get("apiKey", "").strip()
        if not key:
            return None
        return {"url": url, "apiKey": key, "mode": "cloud"}

    if mode == "local":
        url = misp.get("url", "").strip().rstrip("/")
        key = misp.get("apiKey", "").strip()
        if not url or not key:
            return None
        return {"url": url, "apiKey": key, "mode": "local"}

    return None
