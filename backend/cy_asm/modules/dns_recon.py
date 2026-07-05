import json
# CyCentra DNS Recon Module
from functools import lru_cache
import dns.resolver
import socket
import aiohttp
import asyncio
from typing import Dict, List, Any
import asyncio
from config import DNS_RECORD_TYPES, SAAS_PROVIDERS_FOR_TAKEOVER, HTTP_TIMEOUT
from utils import setup_logging, validate_domain, create_async_session

logger = setup_logging()

@lru_cache(maxsize=100)
def get_dns_records(domain: str) -> Dict[str, List[str]]:
    if not validate_domain(domain):
        logger.error(f"Invalid domain: {domain}")
        return {}
    records = {record_type: [] for record_type in DNS_RECORD_TYPES}
    resolver = dns.resolver.Resolver()
    #resolver.nameservers = ["8.8.8.8"]
    resolver.timeout = 5
    resolver.lifetime = 10
    try:
        resolver.resolve(domain, "A")
    except Exception as e:
        logger.error(f"Failed to verify resolution for {domain}: {e}")
        return records
    for record_type in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type)
            records[record_type] = [str(r).rstrip(".") for r in answers]
        except Exception as e:
            logger.debug(f"Failed to fetch {record_type} records for {domain}: {e}")
    # Added depth: Attempt zone transfer (AXFR) ethically (only if NS allows)
    try:
        for ns in records.get('NS', []):
            resolver.nameservers = [socket.gethostbyname(ns)]
            axfr = resolver.zone_transfer(domain)
            if axfr:
                logger.warning(f"Zone transfer succeeded from {ns} - Potential security issue")
    except:
        pass
    return records

def generate_typosquats(domain: str) -> List[str]:
    base, tld = domain.rsplit(".", 1)
    typos = [
        base[:-1] + "." + tld, base + base[-1] + "." + tld,
        base.replace("u", "v") + "." + tld, base.replace("u", "y") + "." + tld,
        base.replace("p", "o") + "." + tld, base + "s" + "." + tld,
        "www" + base + "." + tld, base + "-" + base + "." + tld,
        base.replace("e", "3") + "." + tld,
        # Added more variations (homoglyphs, e.g., 'l' -> '1')
        base.replace("l", "1") + "." + tld, base.replace("o", "0") + "." + tld
    ]
    return list(set(typos) - {domain})

def check_typosquatting(domain: str) -> Dict[str, List[str]]:
    results = {"registered": [], "unregistered": []}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    typos = generate_typosquats(domain)
    for typo in typos:
        try:
            resolver.resolve(typo, "A")
            results["registered"].append(typo)
        except Exception:
            results["unregistered"].append(typo)
    return results

async def check_takeover_risk(cname: str, subdomain: str) -> bool:
    if not cname:
        return False
    cname_lower = cname.lower()
    async with await create_async_session() as session:
        for provider in SAAS_PROVIDERS_FOR_TAKEOVER:
            if cname_lower.endswith(provider):
                try:
                    async with session.get(f"http://{subdomain}", timeout=HTTP_TIMEOUT) as resp:
                        text = await resp.text()
                        if resp.status == 404 or any(term in text.lower() for term in ["no such", "not found", "invalid", "does not exist"]):
                            return True
                except Exception as e:
                    logger.error(f"Takeover check failed for {subdomain}: {e}")
    return False

def _cytim_geoip(domain: str, ips: List[str]) -> Dict[str, Any]:
    """Batch GeoIP lookup via CyTIM /api/cytim/recon. Returns {ip: {country, city, org, asn, hostname}}."""
    try:
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), '..', '..'))
        from core.helpers import cytim_recon
        results = cytim_recon(domain, ["geoip"], ips=ips)
        return results.get("geoip") or {}
    except Exception as e:
        logger.debug(f"[DNS] CyTIM geoip failed: {e}")
        return {}


async def get_ip_addresses(domain: str, dns_records: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    # Collect all IPs and reverse DNS first
    raw_ips: List[Dict[str, Any]] = []
    for record_type in ["A", "AAAA"]:
        for ip in dns_records.get(record_type, []):
            ip_info: Dict[str, Any] = {"ip": ip, "reverse_dns": "None"}
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                ip_info["reverse_dns"] = hostname
            except Exception:
                pass
            raw_ips.append(ip_info)

    if not raw_ips:
        return []

    # Single batch CyTIM geoip call for all collected IPs
    ip_list = [entry["ip"] for entry in raw_ips]
    loop = asyncio.get_running_loop()
    geo_map: Dict[str, Any] = await loop.run_in_executor(None, _cytim_geoip, domain, ip_list)

    for ip_info in raw_ips:
        geo = geo_map.get(ip_info["ip"])
        if geo:
            org = geo.get("org", "Unknown")
            ip_info.update({
                "asn":            geo.get("asn", "Unknown"),
                "org":            org,
                "country":        geo.get("country", "Unknown"),
                "city":           geo.get("city", "Unknown"),
                "hostname":       geo.get("hostname") or ip_info["reverse_dns"],
                "cloud_provider": org.split()[0] if org and org != "Unknown" else "Unknown",
            })

    return raw_ips

async def gather_dns_intel(domain: str) -> Dict[str, Any]:
    records = get_dns_records(domain)
    ips = await get_ip_addresses(domain, records)
    typos = check_typosquatting(domain)
    # Stub for takeovers (needs subdomains; integrate with subdomain_enum)
    takeovers = []  # e.g., await check_takeover_risk(cname, sub) for subs
    issues = [] if records else ["No DNS records"]
    summary = f"Gathered {len(records)} record types, {len(ips)} IPs, {len(typos['registered'])} typosquats"
    return {"results": {"records": records, "ips": ips, "typos": typos, "takeovers": takeovers}, "issues": issues, "summary": summary}

    if len(sys.argv) != 2:
        print(f"Usage: python modules/{__file__.split('/')[-1]} <domain>")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()
    logger = setup_logging()
    logger.info(f"Running standalone {__file__.split('/')[-1]} on {domain}")
    result = asyncio.run(gather_dns_intel(domain))  # ← use your actual function name
    print(json.dumps(result, indent=2, default=str))

    run_standalone(gather_dns_intel)

if __name__ == "__main__":
    from . import run_standalone
    run_standalone(gather_dns_intel)
