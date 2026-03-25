# modules/web_analysis.py
# CyCentra Web/HTTP Analysis — FINAL ELITE VERSION (Dec 2025)
# FULL DEPTH + all fixes applied

import nmap
import aiohttp
import asyncio
import re
import socket
import dns.resolver
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Set
from bs4 import BeautifulSoup
from config import (
    HTTP_TIMEOUT, EXPOSED_PATHS, QUICK_SCAN_PORTS,
    EXTENDED_PORT_RANGE, ENABLE_EXTENDED_PORT_SCAN,
    ENABLE_UDP_SCAN, NVD_API_KEY
)
from utils import setup_logging, create_async_session

# FIXED: correct import path
try:
    from modules.crypto_checks import check_ssl_status
except ImportError:
    async def check_ssl_status(domain):
        return {"ssl_enabled": False, "issues": ["SSL check unavailable"]}

logger = setup_logging()

def scan_ports_with_nmap(domain: str) -> List[int]:
    open_ports = []
    nm = nmap.PortScanner()
    if ENABLE_EXTENDED_PORT_SCAN:
        ports_arg = EXTENDED_PORT_RANGE
        nmap_args = "-p {ports} -T4 -sV --open"
        if ENABLE_UDP_SCAN:
            ports_arg = f"{EXTENDED_PORT_RANGE},U:{EXTENDED_PORT_RANGE}"
            nmap_args += " -sU"
    else:
        ports_arg = QUICK_SCAN_PORTS
        nmap_args = f"-p {ports_arg} -T4 --top-ports 100 --open"
    logger.info(f"Port scanning {domain}")
    try:
        nm.scan(domain, arguments=nmap_args.format(ports=ports_arg))
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    if nm[host][proto][port]["state"] == "open":
                        open_ports.append(port)
        open_ports.sort()
    except Exception as e:
        logger.error(f"Port scan failed: {e}")
    return open_ports

async def fingerprint_services(host: str, ports: List[int]) -> Dict[int, Dict[str, Any]]:
    results = {}
    async with await create_async_session() as session:
        for port in ports:
            try:
                with socket.create_connection((host, port), timeout=5) as s:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode(errors="ignore").strip()
                vulns = []
                if NVD_API_KEY and banner:
                    try:
                        async with session.get(
                            "https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params={"keywordSearch": banner[:100], "resultsPerPage": 10},
                            headers={"apiKey": NVD_API_KEY},
                            timeout=10
                        ) as r:
                            if r.status == 200:
                                data = await r.json()
                                vulns = [v["id"] for v in data.get("vulnerabilities", [])[:5]]
                    except: pass
                results[port] = {"banner": banner or "Unknown", "vulns": vulns}
            except:
                results[port] = {"banner": "Error", "vulns": []}
    return results

async def find_secrets_in_js(url: str, session: aiohttp.ClientSession) -> List[Dict[str, str]]:
    patterns = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r"(?i)aws[_-]?secret[_-]?access[_-]?key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9/+=]{40})",
        "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
        "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24}",
        "GitHub PAT": r"ghp_[0-9a-zA-Z]{36}",
        "GitHub OAuth": r"gho_[0-9a-zA-Z]{36}",
        "Firebase URL": r"[a-z0-9-]+\.firebaseio\.com",
        "Firebase Key": r"AAAA[A-Za-z0-9_-]{35}:",
        "Private Key": r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})?",
        "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        "Twilio SID": r"SK[0-9a-fA-F]{32}",
        "Twilio Auth Token": r"[0-9a-fA-F]{32}",
        "JWT Token": r"eyJ[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}",
    }
    try:
        async with session.get(url, timeout=15) as resp:
            if resp.status != 200: return []
            soup = BeautifulSoup(await resp.text(), "html.parser")
            js_urls = []
            for script in soup.find_all("script", src=True):
                src = script["src"]
                if not src.endswith(".js"): continue
                full = src if src.startswith("http") else url.rstrip("/") + "/" + src.lstrip("/")
                js_urls.append(full)
            js_urls = js_urls[:15]
        found = []
        for js_url in js_urls:
            try:
                async with session.get(js_url, timeout=12) as resp:
                    if resp.status != 200: continue
                    text = await resp.text()
                    for name, regex in patterns.items():
                        for match in re.findall(regex, text):
                            value = match[0] if isinstance(match, tuple) else match
                            found.append({"type": name, "value": value.strip(), "source": js_url.split("/")[-1]})
                    await asyncio.sleep(0.3)
            except: pass
        return [dict(t) for t in {tuple(d.items()) for d in found}]
    except: return []

async def analyze_exposed_paths(domain: str, session: aiohttp.ClientSession, schemes: List[str]) -> List[Dict[str, Any]]:
    paths = set(EXPOSED_PATHS)
    for scheme in schemes:
        for file in ["/robots.txt", "/sitemap.xml"]:
            try:
                async with session.get(f"{scheme}://{domain}{file}", timeout=10) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if "robots" in file:
                            paths.update(re.findall(r"Disallow:\s*([^\s#]+)", text))
                        elif "sitemap" in file:
                            paths.update(re.findall(r"<loc>[^<]*" + re.escape(domain) + r"([^<]+)</loc>", text))
            except: pass

    results = []
    async def check(p):
        p = p.rstrip("/") + "/"
        for s in schemes:
            url = f"{s}://{domain}{p}"
            try:
                async with session.head(url, timeout=8) as resp:
                    if resp.status in [200, 301, 401, 403]:
                        sev = "Critical" if any(x in p for x in [".env", ".git", "backup", "admin", "config"]) else "High"
                        results.append({"path": p, "url": url, "status": resp.status, "severity": sev})
            except: pass
    await asyncio.gather(*[check(p) for p in paths])
    return sorted(results, key=lambda x: (x["severity"] == "Critical", x["severity"] == "High", x["path"]), reverse=True)[:50]

async def discover_api_endpoints(domain: str, session: aiohttp.ClientSession, schemes: List[str]) -> List[str]:
    found = []
    for scheme in schemes:
        for endpoint in ["/api", "/graphql", "/v1", "/api/v1", "/rest", "/jsonapi"]:
            url = f"{scheme}://{domain}{endpoint}"
            try:
                async with session.get(url, timeout=HTTP_TIMEOUT) as resp:
                    if resp.status == 200 and any(t in resp.headers.get("content-type", "").lower() for t in ["json", "text"]):
                        found.append(url)
            except: pass
    return found

async def web_analyzer(domain: str, dns_records: Dict, session) -> Dict[str, Any]:
    result = {
        "http_headers": [], "redirects_to_https": False,
        "cors_issues": [], "exposed_api_routes": []
    }
    try:
        async with session.get(f"http://{domain}", allow_redirects=True, timeout=HTTP_TIMEOUT) as resp:
            result["redirects_to_https"] = str(resp.url).startswith("https://")
            headers = resp.headers
            required = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
            missing = [h for h in required if h not in headers]
            if missing:
                result["http_headers"].extend([f"Missing {h}" for h in missing])
            acao = headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                result["cors_issues"].append("Permissive CORS")
    except: pass
    return result

async def gather_web_analysis(domain: str, dns_records: Dict[str, Any] = None) -> Dict[str, Any]:
    if dns_records is None:
        dns_records = {}
    ports = scan_ports_with_nmap(domain)
    fingerprints = await fingerprint_services(domain, ports)
    ssl_result = check_ssl_status(domain) if 443 in ports else {"ssl_enabled": False, "issues": []}
    async with await create_async_session() as session:
        js_secrets = await find_secrets_in_js(f"https://{domain}", session)
        schemes = ["https", "http"]
        exposed = await analyze_exposed_paths(domain, session, schemes)
        apis = await discover_api_endpoints(domain, session, schemes)
        http_analysis = await web_analyzer(domain, dns_records, session)

    issues = ssl_result.get("issues", [])
    issues += [f"Port {p}: CVE found" for p, fp in fingerprints.items() if fp["vulns"]]
    if js_secrets: issues.append(f"{len(js_secrets)} leaked secrets")
    if any(e["severity"] == "Critical" for e in exposed): issues.append("Critical exposures")

    summary = f"Web: {len(ports)} ports | {len(js_secrets)} secrets | {len(exposed)} paths | {len(apis)} APIs"

    return {
        "results": {
            "ports": ports,
            "fingerprints": fingerprints,
            "ssl": ssl_result,
            "js_secrets": js_secrets,
            "exposed_paths": exposed,
            "api_endpoints": apis,
            "http_analysis": http_analysis
        },
        "issues": issues,
        "summary": summary
    }

if __name__ == "__main__":
    from . import run_standalone
    run_standalone(gather_web_analysis)
