# CyCentra Subdomain Enumeration Module
import aiohttp
import asyncio
import re
import json

from typing import List, Set
import asyncio
from urllib.parse import urlparse
from bs4 import BeautifulSoup

import dns.asyncresolver
import asyncio

from config import HTTP_TIMEOUT, BRUTE_FORCE_WORDLIST, SECURITYTRAILS_API_KEY, VIRUSTOTAL_API_KEY
from utils import setup_logging, create_async_session
from typing import List, Set, Dict, Any
import asyncio


logger = setup_logging()


async def get_subdomains_crtsh(domain: str, session: aiohttp.ClientSession) -> List[str]:
    subdomains: Set[str] = set()
    # Use exact match + wildcard exclusion of known test domains
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with session.get(url, timeout=HTTP_TIMEOUT + 15) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
            target = f".{domain}"
            for entry in data:
                name = entry.get("name_value", "").strip()
                # Strict filter: must end exactly with .domain or be domain itself
                # AND must NOT contain "example." or other known test domains
                if name.lower().endswith(target) or name.lower() == domain:
                    if "example." not in name.lower() and "test." not in name.lower():
                        clean = name.lstrip("*.").split("@")[0]  # remove wildcard & email
                        if clean.endswith(f".{domain}"):
                            subdomains.add(clean)
                        elif clean == domain:
                            subdomains.add(domain)
    except Exception as e:
        logger.debug(f"crt.sh failed for {domain}: {e}")
    return sorted(subdomains)

async def get_subdomains_securitytrails(domain: str, session: aiohttp.ClientSession) -> List[str]:
    if not SECURITYTRAILS_API_KEY:
        return []
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": SECURITYTRAILS_API_KEY}
    try:
        async with session.get(url, headers=headers, timeout=15) as resp:
            if resp.status == 200:
                data = await resp.json()
                subs = data.get("subdomains", [])
                return [f"{sub}.{domain}".lower() for sub in subs]
    except Exception as e:
        logger.debug(f"SecurityTrails failed: {e}")
    return []

async def brute_force_subdomains_async(domain: str) -> List[str]:
    import os
    subdomains: Set[str] = set()
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2  # Aggressive timeout for large lists
    resolver.lifetime = 5
    
    # 1. SEMAPHORE: Prevents the "7, 8, 11" fluctuation by limiting 
    # concurrent DNS queries. Adjust to 100 if your server is powerful.
    sem = asyncio.Semaphore(50) 

    wordlist_path = "/opt/cycentra/backend/cy-asm/modules/wordlists/subdomains.txt" 
    
    async def check(prefix: str):
        async with sem:
            target = f"{prefix.strip()}.{domain}"
            try:
                # Try A record first
                await resolver.resolve(target, "A")
                return target
            except:
                try:
                    # Fallback to CNAME (common for CDNs/Cloud)
                    await resolver.resolve(target, "CNAME")
                    return target
                except:
                    return None

    # 2. MEMORY-SAFE LOADING: We stream the file line by line 
    tasks = []
    if os.path.exists(wordlist_path):
        logger.info(f"🚀 Starting brute force with refreshed list: {wordlist_path}")
        with open(wordlist_path, "r") as f:
            for line in f:
                word = line.strip()
                if word:
                    tasks.append(check(word))
    else:
        from config import BRUTE_FORCE_WORDLIST
        logger.warning("⚠️ Refreshed wordlist not found, using config fallback.")
        tasks = [check(word) for word in BRUTE_FORCE_WORDLIST]

    # 3. BATCH PROCESSING: Executes the queries
    if tasks:
        logger.info(f"🔍 Checking {len(tasks)} potential subdomains...")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for r in results:
            if isinstance(r, str):
                subdomains.add(r.lower())

    logger.info(f"✅ Brute force complete. Found {len(subdomains)} live subdomains.")
    return sorted(list(subdomains))

async def crawl_for_subdomains(domain: str, session: aiohttp.ClientSession) -> List[str]:
    subdomains: Set[str] = set()
    url = f"https://{domain}"
    try:
        async with session.get(url, timeout=15) as resp:
            if resp.status == 200:
                text = await resp.text()
                soup = BeautifulSoup(text, "html.parser")
                for tag in soup.find_all(["a", "link", "script", "img", "source"]):
                    link = tag.get("href") or tag.get("src") or ""
                    if not link:
                        continue
                    host = urlparse(link).netloc.lower()
                    if host and host.endswith(f".{domain}") and host != domain:
                        subdomains.add(host)
    except Exception as e:
        logger.debug(f"Crawl failed for {domain}: {e}")
    return sorted(subdomains)

async def get_subdomains_virustotal(domain: str, session: aiohttp.ClientSession) -> List[str]:
    if not VIRUSTOTAL_API_KEY:
        return []
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        async with session.get(url, headers=headers, timeout=10) as resp:
            if resp.status == 200:
                data = await resp.json()
                subs = [item["id"] for item in data.get("data", []) if item["id"].endswith(domain)]
                return subs
    except Exception as e:
        logger.error(f"VirusTotal error for {domain}: {e}")
    return []

# Added depth: More sources (e.g., AlienVault OTX API - stub, add key if available)
async def get_subdomains_alienvault(domain: str, session: aiohttp.ClientSession) -> List[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        async with session.get(url, timeout=10) as resp:
            if resp.status == 200:
                data = await resp.json()
                subs = [entry['hostname'] for entry in data.get('passive_dns', []) if entry['hostname'].endswith(domain) and entry['hostname'] != domain]
                return list(set(subs))
    except:
        return []

async def gather_subdomains(domain: str, sources: List[str] = ['crtsh', 'securitytrails', 'bruteforce', 'crawl', 'virustotal', 'alienvault']) -> Dict[str, Any]:
    async with await create_async_session() as session:
        tasks = []
        if 'crtsh' in sources: tasks.append(get_subdomains_crtsh(domain, session))
        if 'securitytrails' in sources: tasks.append(get_subdomains_securitytrails(domain, session))
        if 'bruteforce' in sources: tasks.append(brute_force_subdomains_async(domain))
        if 'crawl' in sources: tasks.append(crawl_for_subdomains(domain, session))
        if 'virustotal' in sources: tasks.append(get_subdomains_virustotal(domain, session))
        if 'alienvault' in sources: tasks.append(get_subdomains_alienvault(domain, session))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_subs = set()
        for r in results:
            if isinstance(r, list):
                all_subs.update(r)
        all_subs = sorted(all_subs)
        issues = [] if all_subs else ["No subdomains found"]
        summary = f"Found {len(all_subs)} unique subdomains from {len(tasks)} sources"
        return {"results": all_subs, "issues": issues, "summary": summary}

    if len(sys.argv) != 2:
        print(f"Usage: python modules/{__file__.split('/')[-1]} <domain>")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()
    logger = setup_logging()
    logger.info(f"Running standalone {__file__.split('/')[-1]} on {domain}")
    result = asyncio.run(gather_subdomains(domain))  # ← use your actual function name
    print(json.dumps(result, indent=2, default=str))


    run_standalone(gather_subdomains)

if __name__ == "__main__":
    from . import run_standalone
    run_standalone(gather_subdomains)
