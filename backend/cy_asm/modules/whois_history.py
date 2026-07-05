import sys
import json
import whois
import aiohttp
import asyncio

from typing import Dict, Any, List
import asyncio
from utils import setup_logging, create_async_session
from datetime import datetime
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))


logger = setup_logging()

def get_whois(domain: str) -> Dict[str, Any]:
    try:
        w = whois.whois(domain)
        exp = w.expiration_date
        if isinstance(exp, list):
            exp = exp[0] if exp else None
        elif not isinstance(exp, datetime):
            exp = None
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(exp.date()) if exp else "Unknown",
            "name_servers": w.name_servers or [],
            "status": w.status or []
        }
    except Exception as e:
        logger.error(f"WHOIS failed for {domain}: {e}")
        return {"error": str(e)}

def _cytim_whois_history(domain: str) -> List[str]:
    """Reverse WHOIS history via CyTIM /api/cytim/recon (whois_history module / ViewDNS)."""
    try:
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), '..', '..'))
        from core.helpers import cytim_recon
        results = cytim_recon(domain, ["whois_history"])
        return results.get("whois_history") or []
    except Exception as e:
        logger.debug(f"[WHOIS] CyTIM whois_history recon failed: {e}")
        return []


async def get_domain_history(domain: str, session: aiohttp.ClientSession) -> List[str]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _cytim_whois_history, domain)


async def gather_whois_history(domain: str) -> Dict[str, Any]:
    # 1. Entry Log
    logger.info(f"🔎 [WHOIS] Starting analysis for: {domain}")

    # 2. Track Local WHOIS lookup
    whois_data = get_whois(domain)
    if whois_data.get("registrar"):
        logger.info(f"✅ [WHOIS] Current Registrar identified: {whois_data.get('registrar')}")
    else:
        logger.warning(f"⚠️ [WHOIS] Could not identify registrar for {domain}")

    # 3. Track Async History lookup (The part getting blocked)
    async with await create_async_session() as session:
        logger.info(f"🌐 [WHOIS] Querying external history for {domain}...")
        history = await get_domain_history(domain, session)
        
        # This provides immediate feedback on the result of the web query
        if history:
            logger.info(f"📈 [WHOIS] Successfully found {len(history)} historical records.")
        else:
            logger.warning(f"📉 [WHOIS] No historical records found (or request blocked).")

    # Safe expiration check
    issues = []
    exp_str = whois_data.get("expiration_date", "Unknown")
    if exp_str != "Unknown":
        try:
            exp_date = datetime.strptime(exp_str.split()[0], "%Y-%m-%d").date()
            days_left = (exp_date - datetime.now().date()).days
            if days_left < 30:
                logger.warning(f"🚨 [WHOIS] URGENT: Domain expires in {days_left} days!")
                issues.append("Domain expires soon")
        except Exception as e:
            logger.error(f"❌ [WHOIS] Date parsing error: {e}")

    summary = f"Registrar: {whois_data.get('registrar', 'Unknown')}, History: {len(history)} domains"
    
    # 4. Exit Log
    logger.info(f"🏁 [WHOIS] Finished for {domain}.")
    
    return {
        "results": {"whois": whois_data, "history": history},
        "issues": issues,
        "summary": summary
    }

    run_standalone(gather_whois_history)

if __name__ == "__main__":
    from . import run_standalone
    run_standalone(gather_whois_history)
