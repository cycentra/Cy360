# CyCentra Supply Chain Module
import aiohttp
import asyncio
from typing import Dict, Any, List
from bs4 import BeautifulSoup
from utils import setup_logging, create_async_session

logger = setup_logging()


async def scan_third_party_scripts(domain: str, session: aiohttp.ClientSession) -> List[str]:
    url = f"https://{domain}"
    try:
        async with session.get(url, timeout=15) as resp:
            if resp.status == 200:
                soup = BeautifulSoup(await resp.text(), "html.parser")
                scripts = [
                    script["src"]
                    for script in soup.find_all("script", src=True)
                    if "://" in script["src"]
                ]
                return scripts
    except Exception as e:
        logger.debug(f"Supply chain script scan failed for {domain}: {e}")
    return []


async def check_vuln_deps(scripts: List[str]) -> List[Dict[str, str]]:
    """
    Checks third-party scripts for known vulnerable versions.
    Returns a list of dicts with keys: url, library, severity, reason.
    Extend this with retire.js / OSV API integration as needed.
    """
    findings = []
    for s in scripts:
        sl = s.lower()
        # jQuery < 1.9 — known XSS vectors
        if "jquery" in sl:
            for old_ver in ["1.4.", "1.5.", "1.6.", "1.7.", "1.8."]:
                if old_ver in sl:
                    findings.append({
                        "url": s,
                        "library": f"jQuery {old_ver[:-1]}.x",
                        "severity": "High",
                        "reason": "Outdated jQuery version with known XSS vulnerabilities"
                    })
        # Angular 1.x — EOL, multiple CVEs
        if "angular.js" in sl or "angular.min.js" in sl:
            if "/1." in sl:
                findings.append({
                    "url": s,
                    "library": "AngularJS 1.x",
                    "severity": "Medium",
                    "reason": "AngularJS 1.x is EOL and has known prototype pollution CVEs"
                })
        # Lodash < 4.17.21
        if "lodash" in sl:
            for old_ver in ["lodash/3.", "lodash/4.17.1", "lodash/4.17.20"]:
                if old_ver in sl:
                    findings.append({
                        "url": s,
                        "library": "Lodash (outdated)",
                        "severity": "High",
                        "reason": "Old Lodash version — prototype pollution (CVE-2020-8203)"
                    })
        # Moment.js — ReDoS
        if "moment.js" in sl or "moment.min.js" in sl:
            findings.append({
                "url": s,
                "library": "Moment.js",
                "severity": "Low",
                "reason": "Moment.js is deprecated; ReDoS risk in some versions"
            })
    return findings


async def gather_supply_chain(domain: str) -> Dict[str, Any]:
    async with await create_async_session() as session:
        scripts = await scan_third_party_scripts(domain, session)

    vuln_deps = await check_vuln_deps(scripts)

    # Count by severity so App.jsx widget can display meaningful numbers
    high_count = sum(1 for v in vuln_deps if v.get("severity") in ("High", "Critical"))

    issues = [f"Vulnerable dependency: {v['library']} — {v['reason']}" for v in vuln_deps]
    summary = f"Found {len(scripts)} third-party scripts, {len(vuln_deps)} potentially vulnerable"

    logger.info(f"📦 [SUPPLY_CHAIN] {summary}")

    return {
        "results": {
            "scripts":    scripts,       # full list of external script URLs found
            "risks":      vuln_deps,     # list of {url, library, severity, reason}
            "count":      len(scripts),  # total third-party scripts
            "high":       high_count,    # high/critical risk count — read by App.jsx widget
        },
        "issues":  issues,
        "summary": summary
    }


if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(gather_supply_chain(domain))
    import json
    print(json.dumps(result, indent=2, default=str))