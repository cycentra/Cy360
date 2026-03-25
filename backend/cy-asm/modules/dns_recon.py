import json
# CyCentra DNS Recon Module
from functools import lru_cache
import dns.resolver
import socket
import aiohttp
import asyncio
from typing import Dict, List, Any
import asyncio
from config import DNS_RECORD_TYPES, IPINFO_API_KEY, SAAS_PROVIDERS_FOR_TAKEOVER, HTTP_TIMEOUT
from utils import setup_logging, validate_domain, create_async_session

logger = setup_logging()

@lru_cache(maxsize=100)
def get_dns_records(domain: str) -> Dict[str, List[str]]:
    if not validate_domain(domain):
        logger.error(f"Invalid domain: {domain}")
        return {}
    records = {record_type: [] for record_type in DNS_RECORD_TYPES}
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8"]
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

async def get_ip_addresses(domain: str, dns_records: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    ip_addresses = []
    async with await create_async_session() as session:
        for record_type in ["A", "AAAA"]:
            for ip in dns_records.get(record_type, []):
                ip_info = {"ip": ip, "reverse_dns": "None"}
                try:
                    hostname, _, _ = socket.gethostbyaddr(ip)
                    ip_info["reverse_dns"] = hostname
                except:
                    pass
                if IPINFO_API_KEY:
                    try:
                        async with session.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}", timeout=5) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                ip_info.update({
                                    "asn": data.get("asn", "Unknown"),
                                    "org": data.get("org", "Unknown"),
                                    "country": data.get("country", "Unknown"),
                                    "city": data.get("city", "Unknown"),
                                    "hostname": data.get("hostname", ip_info["reverse_dns"]),
                                    "cloud_provider": data.get("org", "").split()[0] if data.get("org") else "Unknown",
                                })
                    except Exception as e:
                        logger.debug(f"ipinfo enrichment failed for {ip}: {e}")
                ip_addresses.append(ip_info)
    return ip_addresses

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
