# CyCentra Subdomain Enumeration Module
import aiohttp
import asyncio
import re
import json
import os
import time
from pathlib import Path
from typing import List, Set, Dict, Any
from urllib.parse import urlparse
from bs4 import BeautifulSoup

import dns.asyncresolver

from config import HTTP_TIMEOUT, BRUTE_FORCE_WORDLIST

_CRTSH_CACHE_DIR = Path("/var/log/cycentra/cy-asm/state/crtsh_cache")
_CRTSH_CACHE_TTL = 21600  # 6 hours in seconds

def get_subdomains_cytim_recon(domain: str) -> List[str]:
    """
    Query CyTIM /api/cytim/recon for subdomain discovery (VT, OTX, SecurityTrails).
    Returns a deduplicated list of subdomain strings. Falls back to [] if CyTIM unavailable.
    """
    try:
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), '..', '..'))
        from core.helpers import cytim_recon
        results = cytim_recon(domain, ["subdomains"])
        subs = results.get("subdomains") or []
        return [s.lower().strip() for s in subs if s and s.lower().strip().endswith(f".{domain}")]
    except Exception as e:
        return []
from utils import setup_logging, create_async_session, get_misp_config


logger = setup_logging()


async def get_subdomains_crtsh(domain: str, session: aiohttp.ClientSession) -> List[str]:
    """Query crt.sh with 3-attempt retry + 6h on-disk cache."""
    # Check cache first
    _CRTSH_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = _CRTSH_CACHE_DIR / f"{domain}.json"
    if cache_file.exists():
        try:
            cached = json.loads(cache_file.read_text())
            if time.time() - cached.get("ts", 0) < _CRTSH_CACHE_TTL:
                logger.info(f"[crtsh] Cache hit for {domain} — {len(cached['subs'])} subdomains")
                return cached["subs"]
        except Exception:
            pass

    subdomains: Set[str] = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    for attempt in range(3):
        try:
            timeout = aiohttp.ClientTimeout(total=30 + attempt * 15)  # 30s, 45s, 60s
            async with session.get(url, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.debug(f"[crtsh] HTTP {resp.status} for {domain} (attempt {attempt+1})")
                    await asyncio.sleep(2 ** attempt)
                    continue
                text = await resp.text()
                data = json.loads(text)
                target = f".{domain}"
                for entry in data:
                    # crt.sh name_value can contain multiple SANs separated by \n
                    # (one certificate can cover many subdomains — must split each line)
                    raw_names = entry.get("name_value", "").strip().splitlines()
                    for name in raw_names:
                        name = name.strip()
                        if not name:
                            continue
                        if name.lower().endswith(target) or name.lower() == domain:
                            if "example." not in name.lower() and "test." not in name.lower():
                                clean = name.lstrip("*.").split("@")[0]
                                if clean.endswith(f".{domain}"):
                                    subdomains.add(clean)
                                elif clean == domain:
                                    subdomains.add(domain)
                logger.info(f"[crtsh] {len(subdomains)} subdomains for {domain} (attempt {attempt+1})")
                break  # success — stop retrying
        except asyncio.TimeoutError:
            logger.warning(f"[crtsh] Timeout for {domain} (attempt {attempt+1}/3)")
            if attempt < 2:
                await asyncio.sleep(2 ** attempt)
        except Exception as e:
            logger.debug(f"[crtsh] Failed for {domain} (attempt {attempt+1}): {e}")
            if attempt < 2:
                await asyncio.sleep(2 ** attempt)

    result = sorted(subdomains)

    # Write cache only if we got results
    if result:
        try:
            cache_file.write_text(json.dumps({"ts": time.time(), "subs": result}))
        except Exception:
            pass

    return result

async def get_subdomains_misp(domain: str, session: aiohttp.ClientSession) -> List[str]:
    """
    Query the configured MISP instance for hostname/domain attributes that
    belong to *domain*, returning them as a list of subdomain strings.

    Uses ``/attributes/restSearch`` with a wildcard prefix (``%.domain``) so
    all historically-recorded subdomains in MISP events are surfaced without
    any direct call to SecurityTrails, VirusTotal, or AlienVault OTX.
    Returns an empty list when MISP is not configured or the query fails.
    """
    misp_cfg = get_misp_config()
    if not misp_cfg:
        return []

    url = f"{misp_cfg['url']}/attributes/restSearch"
    headers = {
        "Authorization": misp_cfg["apiKey"],
        "Accept":        "application/json",
        "Content-Type":  "application/json",
    }
    payload = {
        "returnFormat": "json",
        "value":        f"%.{domain}",
        "type":         ["hostname", "domain"],
        "limit":        500,
    }
    subdomains: Set[str] = set()
    try:
        async with session.post(
            url,
            headers=headers,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=10),
            ssl=False,
        ) as resp:
            if resp.status == 200:
                data  = await resp.json()
                attrs = data.get("response", {}).get("Attribute", [])
                for attr in attrs:
                    value = attr.get("value", "").lower().strip()
                    if value.endswith(f".{domain}") and value != domain:
                        subdomains.add(value)
                logger.info(f"[Subdomains/MISP] Found {len(subdomains)} subdomain(s) for {domain}.")
            else:
                logger.warning(f"[Subdomains/MISP] HTTP {resp.status} for {domain}.")
    except asyncio.TimeoutError:
        logger.warning(f"[Subdomains/MISP] Query timed out for {domain}.")
    except Exception as e:
        logger.debug(f"[Subdomains/MISP] Search failed for {domain}: {e}")
    return sorted(subdomains)

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
    sources: List[str] = ['crtsh', 'misp', 'bruteforce', 'crawl', 'cytim'],
) -> Dict[str, Any]:
    """
    Collect subdomains from all passive + active sources, then validate each
    one with a live DNS check.

    Sources
    -------
    - ``crtsh``     — certificate transparency logs (no API key needed, 6h cache)
    - ``misp``      — passive DNS / hostname attributes from local MISP
    - ``bruteforce`` — DNS brute-force using the local wordlist
    - ``crawl``     — crawl the apex domain for linked subdomains
    - ``cytim``     — CyTIM recon (VT subdomains + OTX passive DNS + SecurityTrails)

    Returns a list of enriched dicts:
        {subdomain, live, resolved_ips, cname, sources}
    sorted live-first, then alphabetically.
    """
    async with await create_async_session() as session:
        task_specs: List[tuple[str, any]] = []
        if 'crtsh'     in sources: task_specs.append(('crtsh',     get_subdomains_crtsh(domain, session)))
        if 'misp'      in sources: task_specs.append(('misp',      get_subdomains_misp(domain, session)))
        if 'bruteforce' in sources: task_specs.append(('bruteforce', brute_force_subdomains_async(domain)))
        if 'crawl'     in sources: task_specs.append(('crawl',     crawl_for_subdomains(domain, session)))

        # CyTIM recon (VT + OTX + SecurityTrails) — blocking call in executor so it
        # doesn't hold the event loop; merged into seen map before async sources finish.
        cytim_subs: List[str] = []
        if 'cytim' in sources:
            loop = asyncio.get_running_loop()
            cytim_subs = await loop.run_in_executor(None, get_subdomains_cytim_recon, domain)
            logger.info(f"[Subdomains] CyTIM recon returned {len(cytim_subs)} subdomain(s) for {domain}.")

        source_names  = [s for s, _ in task_specs]
        source_tasks  = [t for _, t in task_specs]
        source_results = await asyncio.gather(*source_tasks, return_exceptions=True)

        # Build {subdomain -> set(sources)} map
        seen: Dict[str, Set[str]] = {}

        # Seed with CyTIM results first
        for sub in cytim_subs:
            sub = sub.lower().strip()
            if sub:
                seen.setdefault(sub, set()).add("cytim")

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
