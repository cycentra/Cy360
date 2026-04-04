# CyCentra Subdomain Enumeration Module
import aiohttp
import asyncio
import re
import json
import os
from typing import List, Set, Dict, Any
from urllib.parse import urlparse
from bs4 import BeautifulSoup

import dns.asyncresolver

from config import HTTP_TIMEOUT, BRUTE_FORCE_WORDLIST, SECURITYTRAILS_API_KEY, VIRUSTOTAL_API_KEY
from utils import setup_logging, create_async_session


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

    # Wordlist path: resolve relative to this module file so it works whether
    # cy_asm is installed as a site-package or run directly from source.
    wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", "subdomains.txt")
    
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


# ── Live DNS validation ───────────────────────────────────────────────────────

async def _check_live(subdomain: str, sem: asyncio.Semaphore) -> Dict[str, Any]:
    """Resolve a subdomain via DNS and return live status with IP/CNAME details."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout  = 3
    resolver.lifetime = 5

    resolved_ips: List[str] = []
    cname: str | None       = None
    live                    = False

    async with sem:
        # A record
        try:
            ans = await resolver.resolve(subdomain, "A")
            resolved_ips = [r.address for r in ans]
            live = True
        except Exception:
            pass

        # CNAME (common for CDN/cloud-hosted subdomains)
        if not live:
            try:
                ans = await resolver.resolve(subdomain, "CNAME")
                cname = str(ans[0].target).rstrip(".")
                live  = True
            except Exception:
                pass

        # AAAA (IPv6)
        if not live:
            try:
                ans = await resolver.resolve(subdomain, "AAAA")
                resolved_ips = [r.address for r in ans]
                live = True
            except Exception:
                pass

    return {
        "subdomain":    subdomain,
        "live":         live,
        "resolved_ips": resolved_ips,
        "cname":        cname,
    }


async def gather_subdomains(
    domain: str,
    sources: List[str] = ['crtsh', 'securitytrails', 'bruteforce', 'crawl', 'virustotal', 'alienvault'],
) -> Dict[str, Any]:
    """
    Collect subdomains from all passive + active sources, then validate each
    one with a live DNS check.

    Returns a list of enriched dicts:
        {subdomain, live, resolved_ips, cname, sources}
    sorted live-first, then alphabetically.
    """
    async with await create_async_session() as session:
        # ── 1. Collect from all passive / active sources ─────────────────────
        task_specs: List[tuple[str, any]] = []
        if 'crtsh'          in sources: task_specs.append(('crtsh',          get_subdomains_crtsh(domain, session)))
        if 'securitytrails' in sources: task_specs.append(('securitytrails', get_subdomains_securitytrails(domain, session)))
        if 'bruteforce'     in sources: task_specs.append(('bruteforce',     brute_force_subdomains_async(domain)))
        if 'crawl'          in sources: task_specs.append(('crawl',          crawl_for_subdomains(domain, session)))
        if 'virustotal'     in sources: task_specs.append(('virustotal',     get_subdomains_virustotal(domain, session)))
        if 'alienvault'     in sources: task_specs.append(('alienvault',     get_subdomains_alienvault(domain, session)))

        source_names  = [s for s, _ in task_specs]
        source_tasks  = [t for _, t in task_specs]
        source_results = await asyncio.gather(*source_tasks, return_exceptions=True)

        # Build {subdomain -> set(sources)} map
        seen: Dict[str, Set[str]] = {}
        for src_name, result in zip(source_names, source_results):
            if not isinstance(result, list):
                continue
            for sub in result:
                sub = sub.lower().strip()
                if not sub:
                    continue
                if sub not in seen:
                    seen[sub] = set()
                seen[sub].add(src_name)

        if not seen:
            return {"results": [], "issues": ["No subdomains found"], "summary": "No subdomains found"}

        # ── 2. Live DNS validation (concurrent, capped at 50 parallel) ───────
        logger.info(f"🔍 [Subdomains] Validating {len(seen)} subdomains via live DNS...")
        sem = asyncio.Semaphore(50)
        live_checks = await asyncio.gather(
            *[_check_live(sub, sem) for sub in seen],
            return_exceptions=True,
        )

        # ── 3. Build enriched result list ────────────────────────────────────
        enriched: List[Dict[str, Any]] = []
        for check in live_checks:
            if isinstance(check, Exception):
                continue
            sub = check["subdomain"]
            enriched.append({
                **check,
                "sources": sorted(seen.get(sub, set())),
                # is_new / change are injected later by cycentra_scan.py state compare
                "is_new":  None,
                "change":  None,
            })

        # Sort: live first, then alphabetically
        enriched.sort(key=lambda x: (not x["live"], x["subdomain"]))

        live_count = sum(1 for e in enriched if e["live"])
        hist_count = len(enriched) - live_count
        summary = (
            f"Found {len(enriched)} subdomains "
            f"({live_count} LIVE, {hist_count} historical/not-resolving) "
            f"from {len(task_specs)} sources"
        )
        logger.info(f"✅ [Subdomains] {summary}")

        return {
            "results": enriched,
            "issues":  [] if enriched else ["No subdomains found"],
            "summary": summary,
        }


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: python modules/subdomain_enum.py <domain>")
        sys.exit(1)
    domain = sys.argv[1].strip().lower()
    logger = setup_logging()
    result = asyncio.run(gather_subdomains(domain))
    print(json.dumps(result, indent=2, default=str))
