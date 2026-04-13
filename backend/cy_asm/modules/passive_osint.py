"""
modules/passive_osint.py
CyCentra ASM — Passive OSINT / Threat Intelligence
Probe type: Passive
Typical runtime: ~5s per domain

Queries the configured MISP instance for existing threat-intelligence
attributes (hostnames, domains, IPs, URLs) associated with the target
domain.  No direct calls to Shodan or other external APIs — all intel is
routed through MISP as a centralised TIP.
"""
import json
import aiohttp
import asyncio
from typing import Any, Dict, List

from utils import setup_logging, create_async_session, get_misp_config

logger = setup_logging()

_MISP_ATTRIBUTE_TYPES = ["hostname", "domain", "ip-dst", "ip-src", "url", "domain|ip"]


async def search_misp_domain(
    domain: str,
    session: aiohttp.ClientSession,
    misp_cfg: dict,
) -> List[Dict[str, Any]]:
    """
    Search MISP for attributes associated with *domain*.

    Uses ``/attributes/restSearch`` with a wildcard value (``%.domain``) so
    that both the apex domain and any recorded subdomains / IPs are returned.
    Returns the raw MISP ``Attribute`` list (may be empty).
    """
    url = f"{misp_cfg['url']}/attributes/restSearch"
    headers = {
        "Authorization": misp_cfg["apiKey"],
        "Accept":        "application/json",
        "Content-Type":  "application/json",
    }
    payload = {
        "returnFormat": "json",
        "value":        f"%.{domain}",
        "type":         _MISP_ATTRIBUTE_TYPES,
        "limit":        200,
    }
    try:
        async with session.post(
            url,
            headers=headers,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=10),
            ssl=False,
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                attrs = data.get("response", {}).get("Attribute", [])
                logger.info(f"[OSINT] MISP returned {len(attrs)} attribute(s) for {domain}.")
                return attrs
            logger.warning(f"[OSINT] MISP returned HTTP {resp.status} for {domain}.")
    except asyncio.TimeoutError:
        logger.warning(f"[OSINT] MISP query timed out for {domain}.")
    except Exception as e:
        logger.error(f"[OSINT] MISP search failed for {domain}: {e}")
    return []


def _attr_to_issue(attr: dict, domain: str) -> str | None:
    """
    Convert a MISP attribute into a human-readable issue string.
    Returns None for benign / low-value attributes.
    """
    value    = attr.get("value", "")
    atype    = attr.get("type", "")
    to_ids   = attr.get("to_ids", False)
    category = attr.get("category", "")
    comment  = attr.get("comment", "")

    if to_ids:
        return f"IOC hit [{atype}] {value} — category: {category}" + (f" | {comment}" if comment else "")
    if atype in ("ip-src", "ip-dst"):
        return f"Recorded IP [{atype}] {value}" + (f" | {comment}" if comment else "")
    return None


async def gather_passive_osint(domain: str) -> Dict[str, Any]:
    """
    Run MISP-backed passive OSINT for *domain*.

    Returns::

        {
            "results": [<misp_attribute_dict>, ...],
            "issues":  ["IOC hit ...", ...],
            "summary": "Found N OSINT attributes from MISP",
        }
    """
    misp_cfg = get_misp_config()
    if not misp_cfg:
        logger.info("[OSINT] MISP not configured — passive OSINT skipped.")
        return {
            "results": [],
            "issues":  [],
            "summary": "MISP not configured — passive OSINT skipped",
        }

    async with await create_async_session() as session:
        attrs = await search_misp_domain(domain, session, misp_cfg)

    issues = [i for attr in attrs for i in [_attr_to_issue(attr, domain)] if i]
    summary = f"Found {len(attrs)} OSINT attribute(s) from MISP"

    return {"results": attrs, "issues": issues, "summary": summary}


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: python modules/passive_osint.py <domain>")
        sys.exit(1)
    domain = sys.argv[1].strip().lower()
    result = asyncio.run(gather_passive_osint(domain))
    print(json.dumps(result, indent=2, default=str))
