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
import os

logger = setup_logging()

_MISP_ATTRIBUTE_TYPES = ["hostname", "domain", "ip-dst", "ip-src", "url", "domain|ip"]

from config import SHODAN_API_KEY


async def search_shodan(domain: str, session: aiohttp.ClientSession) -> list[dict]:
    """
    Query Shodan for exposed services for the given domain.
    Returns a list of service dicts (may be empty).
    """
    if not SHODAN_API_KEY:
        logger.info("[OSINT] Shodan API key not set — skipping Shodan lookup.")
        return []
    url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query=hostname:{domain}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                matches = data.get("matches", [])
                logger.info(f"[OSINT] Shodan returned {len(matches)} result(s) for {domain}.")
                return matches
            else:
                logger.warning(f"[OSINT] Shodan returned HTTP {resp.status} for {domain}.")
    except asyncio.TimeoutError:
        logger.warning(f"[OSINT] Shodan query timed out for {domain}.")
    except Exception as e:
        logger.error(f"[OSINT] Shodan search failed for {domain}: {e}")
    return []


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
    async with await create_async_session() as session:
        # MISP
        attrs = []
        misp_issues = []
        misp_summary = ""
        if misp_cfg:
            attrs = await search_misp_domain(domain, session, misp_cfg)
            misp_issues = [i for attr in attrs for i in [_attr_to_issue(attr, domain)] if i]
            misp_summary = f"Found {len(attrs)} OSINT attribute(s) from MISP"
        else:
            logger.info("[OSINT] MISP not configured — passive OSINT skipped.")
            misp_summary = "MISP not configured — passive OSINT skipped"

        # Shodan
        shodan_results = await search_shodan(domain, session)
        shodan_issues: List[str] = []
        shodan_cve_findings: List[Dict[str, Any]] = []

        for m in shodan_results:
            port  = m.get("port")
            ip    = m.get("ip_str", "")
            vulns = m.get("vulns") or {}  # dict: {CVE-ID: {cvss, summary, ...}}

            if port and ip:
                shodan_issues.append(f"Exposed service: {ip}:{port} (Shodan)")

            for cve_id, vuln_meta in vulns.items():
                if isinstance(vuln_meta, dict):
                    cvss    = float(vuln_meta.get("cvss", 5.0))
                    summary = vuln_meta.get("summary", "")[:200]
                else:
                    cvss, summary = 5.0, ""

                severity = (
                    "Critical" if cvss >= 9.0 else
                    "High"     if cvss >= 7.0 else
                    "Medium"   if cvss >= 4.0 else "Low"
                )
                from datetime import datetime, timezone as _tz
                shodan_cve_findings.append({
                    "vulnerability": cve_id.upper(),
                    "module":        "passive_osint",
                    "source":        "shodan",
                    "ip":            ip,
                    "port":          port,
                    "cvss":          cvss,
                    "severity":      severity,
                    "risk_score":    max(1, min(10, round(cvss))),
                    "description":   (
                        summary or f"Shodan-confirmed {cve_id} on {ip}:{port}"
                    ),
                    "recommendation": (
                        f"Patch {cve_id} on {ip}:{port}. "
                        f"Verify with vendor advisory and apply available fix."
                    ),
                    "domain":        domain,
                    "discovered_at": datetime.now(_tz.utc).isoformat(),
                })
                shodan_issues.append(
                    f"{severity} — {cve_id} on {ip}:{port} "
                    f"(Shodan-confirmed, CVSS {cvss})"
                )

        # Merge results
        results = {
            "misp":                attrs,
            "shodan":              shodan_results,
            "shodan_cve_findings": shodan_cve_findings,
        }
        issues = misp_issues + shodan_issues
        summary = f"MISP: {misp_summary} | Shodan: {len(shodan_results)} result(s)"

        return {"results": results, "issues": issues, "summary": summary}


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: python modules/passive_osint.py <domain>")
        sys.exit(1)
    domain = sys.argv[1].strip().lower()
    result = asyncio.run(gather_passive_osint(domain))
    print(json.dumps(result, indent=2, default=str))
