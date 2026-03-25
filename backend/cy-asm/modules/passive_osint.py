# CyCentra Passive OSINT Module
import json
import aiohttp
import asyncio
from typing import Dict, Any, List
import asyncio
from config import SHODAN_API_KEY  # Add to config
from utils import setup_logging, create_async_session


logger = setup_logging()

async def search_shodan(domain: str, session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
    if not SHODAN_API_KEY:
        return []
    url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query=hostname:{domain}"
    try:
        async with session.get(url) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get("matches", [])
    except Exception as e:
        logger.error(f"Shodan failed for {domain}: {e}")
    return []

async def gather_passive_osint(domain: str) -> Dict[str, Any]:
    async with await create_async_session() as session:
        shodan_results = await search_shodan(domain, session)
    issues = [f"Exposed service: {m['port']}" for m in shodan_results if 'vulns' in m]
    summary = f"Found {len(shodan_results)} OSINT items from Shodan"
    return {"results": shodan_results, "issues": issues, "summary": summary}

    if len(sys.argv) != 2:
        print(f"Usage: python modules/{__file__.split('/')[-1]} <domain>")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()
    logger = setup_logging()
    logger.info(f"Running standalone {__file__.split('/')[-1]} on {domain}")
    result = asyncio.run(gather_passive_osint(domain))  # ← use your actual function name
    print(json.dumps(result, indent=2, default=str))

    run_standalone(gather_passive_osint)

if __name__ == "__main__":
    from . import run_standalone
    run_standalone(gather_passive_osint)
