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
