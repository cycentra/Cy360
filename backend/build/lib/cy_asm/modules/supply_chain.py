# CyCentra Supply Chain Module
import re
import aiohttp
import asyncio
from typing import Any, Dict, List, Optional, Tuple
from bs4 import BeautifulSoup
from utils import setup_logging, create_async_session

logger = setup_logging()

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# (url_regex_pattern, package_name_for_osv, ecosystem)
_LIB_PATTERNS = [
    (r"jquery[-/@v](\d+\.\d+(?:\.\d+)?)",           "jquery",     "npm"),
    (r"angular(?:\.js)?[-/@v](\d+\.\d+(?:\.\d+)?)", "angularjs",  "npm"),
    (r"lodash[-/@v](\d+\.\d+(?:\.\d+)?)",            "lodash",     "npm"),
    (r"moment[-/@v](\d+\.\d+(?:\.\d+)?)",            "moment",     "npm"),
    (r"bootstrap[-/@v](\d+\.\d+(?:\.\d+)?)",         "bootstrap",  "npm"),
    (r"underscore[-/@v](\d+\.\d+(?:\.\d+)?)",        "underscore", "npm"),
    (r"vue[-/@v](\d+\.\d+(?:\.\d+)?)",               "vue",        "npm"),
    (r"react[-/@v](\d+\.\d+(?:\.\d+)?)",             "react",      "npm"),
    (r"backbone[-/@v](\d+\.\d+(?:\.\d+)?)",          "backbone",   "npm"),
    (r"d3[-/@v](\d+\.\d+(?:\.\d+)?)",                "d3",         "npm"),
]


def _detect_library(url: str) -> Optional[Tuple[str, str, str]]:
    """
    Extract (package_name, version, ecosystem) from a CDN script URL.
    Returns None if no known library / version is detected.
    """
    url_lower = url.lower()
    for pattern, pkg_name, ecosystem in _LIB_PATTERNS:
        m = re.search(pattern, url_lower)
        if m:
            return pkg_name, m.group(1), ecosystem
    return None


def _parse_osv_severity(vuln: dict) -> Tuple[str, float]:
    """
    Extract the highest severity label and approximate CVSS from an OSV record.
    Falls back to Medium/5.0 when no severity metadata is present.
    """
    db_sev = (
        vuln.get("database_specific", {}).get("severity")
        or vuln.get("ecosystem_specific", {}).get("severity", "")
    )
    if isinstance(db_sev, str):
        mapping = {
            "CRITICAL": ("Critical", 9.5),
            "HIGH":     ("High",     7.5),
            "MODERATE": ("Medium",   5.0),
            "MEDIUM":   ("Medium",   5.0),
            "LOW":      ("Low",      2.5),
        }
        result = mapping.get(db_sev.upper())
        if result:
            return result
    return "Medium", 5.0


async def _osv_lookup(
    package: str,
    version: str,
    ecosystem: str,
    session: aiohttp.ClientSession,
) -> List[Dict[str, Any]]:
    """
    Query OSV.dev for vulnerabilities affecting package@version.
    No API key required. Returns raw OSV vuln records (may be empty).
    """
    payload = {
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version,
    }
    try:
        async with session.post(
            _OSV_QUERY_URL,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get("vulns", [])
    except Exception as e:
        logger.debug(f"[SupplyChain] OSV lookup failed for {package}@{version}: {e}")
    return []


async def scan_third_party_scripts(domain: str, session: aiohttp.ClientSession) -> List[str]:
    url = f"https://{domain}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                soup = BeautifulSoup(await resp.text(), "html.parser")
                return [
                    script["src"]
                    for script in soup.find_all("script", src=True)
                    if "://" in script["src"]
                ]
    except Exception as e:
        logger.debug(f"Supply chain script scan failed for {domain}: {e}")
    return []


async def check_vuln_deps(
    scripts: List[str],
    session: aiohttp.ClientSession,
) -> List[Dict[str, Any]]:
    """
    Check third-party scripts for known vulnerabilities using OSV.dev.

    For each script URL where a library + version can be parsed, queries the
    OSV.dev API for real CVE/GHSA data with CVSS scores. Falls back to static
    heuristics for unversioned or unrecognised URLs.

    Returns list of dicts: {url, library, osv_id, cve_ids, severity, cvss, reason}.
    """
    findings: List[Dict[str, Any]] = []
    osv_checked: set = set()  # avoid duplicate (pkg, version) lookups

    for script_url in scripts:
        detected = _detect_library(script_url)
        if detected:
            pkg, version, ecosystem = detected
            key = (pkg, version)
            if key not in osv_checked:
                osv_checked.add(key)
                osv_vulns = await _osv_lookup(pkg, version, ecosystem, session)
                for osv_vuln in osv_vulns[:5]:
                    cve_ids = [
                        a for a in osv_vuln.get("aliases", [])
                        if a.startswith("CVE-")
                    ]
                    severity, cvss = _parse_osv_severity(osv_vuln)
                    summary = (
                        osv_vuln.get("summary")
                        or f"Known vulnerability in {pkg}@{version}"
                    )
                    findings.append({
                        "url":      script_url,
                        "library":  f"{pkg} {version}",
                        "osv_id":   osv_vuln.get("id", ""),
                        "cve_ids":  cve_ids,
                        "severity": severity,
                        "cvss":     cvss,
                        "reason": (
                            (cve_ids[0] + ": " if cve_ids else "")
                            + summary[:200]
                        ),
                    })
            continue  # skip static fallback for versioned+recognised URLs

        # ── Static fallback for unversioned / unrecognised script URLs ────────
        sl = script_url.lower()

        if "jquery" in sl:
            for old_ver in ["1.4.", "1.5.", "1.6.", "1.7.", "1.8."]:
                if old_ver in sl:
                    findings.append({
                        "url": script_url, "library": f"jQuery {old_ver[:-1]}.x",
                        "osv_id": "", "cve_ids": [], "severity": "High", "cvss": 7.5,
                        "reason": "Outdated jQuery version with known XSS vulnerabilities",
                    })
        if "angular.js" in sl or "angular.min.js" in sl:
            if "/1." in sl:
                findings.append({
                    "url": script_url, "library": "AngularJS 1.x",
                    "osv_id": "", "cve_ids": [], "severity": "Medium", "cvss": 5.0,
                    "reason": "AngularJS 1.x is EOL and has known prototype pollution CVEs",
                })
        if "lodash" in sl:
            for old_ver in ["lodash/3.", "lodash/4.17.1", "lodash/4.17.20"]:
                if old_ver in sl:
                    findings.append({
                        "url": script_url, "library": "Lodash (outdated)",
                        "osv_id": "", "cve_ids": ["CVE-2020-8203"], "severity": "High", "cvss": 7.4,
                        "reason": "Old Lodash version — prototype pollution (CVE-2020-8203)",
                    })
        if "moment.js" in sl or "moment.min.js" in sl:
            findings.append({
                "url": script_url, "library": "Moment.js",
                "osv_id": "", "cve_ids": [], "severity": "Low", "cvss": 2.5,
                "reason": "Moment.js is deprecated; ReDoS risk in some versions",
            })

    return findings


async def gather_supply_chain(domain: str) -> Dict[str, Any]:
    async with await create_async_session() as session:
        scripts   = await scan_third_party_scripts(domain, session)
        vuln_deps = await check_vuln_deps(scripts, session)

    high_count = sum(1 for v in vuln_deps if v.get("severity") in ("High", "Critical"))

    issues = [
        "Vulnerable dependency: {lib} [{ids}] — {reason}".format(
            lib=v["library"],
            ids=", ".join(v.get("cve_ids", [])) or v.get("osv_id", ""),
            reason=v["reason"],
        )
        for v in vuln_deps
    ]
    summary = f"Found {len(scripts)} third-party scripts, {len(vuln_deps)} potentially vulnerable"
    logger.info(f"📦 [SUPPLY_CHAIN] {summary}")

    return {
        "results": {
            "scripts": scripts,
            "risks":   vuln_deps,
            "count":   len(scripts),
            "high":    high_count,
        },
        "issues":  issues,
        "summary": summary,
    }


if __name__ == "__main__":
    import sys, json
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(gather_supply_chain(domain))
    print(json.dumps(result, indent=2, default=str))
