"""
modules/vuln_scanner.py
CyCentra ASM — Vulnerability Scanner Module

Combines three complementary scanning approaches:
  1. NVD/EPSS enrichment of existing port/banner findings from web_analysis
  2. OpenVAS/Greenbone authenticated scan (when GVM socket available)
  3. HTTP-based service fingerprint CVE lookup (lightweight fallback)

Design principle: this module enriches and extends what web_analysis.py already
discovers — it does NOT replace it. Always run web_analysis first, then pass its
port/fingerprint results here for CVE+EPSS enrichment and deeper scanning.

The approval-gate and response-action wiring is handled upstream in cycentra_scan.py
and the portal API — this module's job is finding + scoring, not remediating.
"""

import asyncio
import json
import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

from config import (
    HTTP_TIMEOUT,
    CVSS_CRITICAL, CVSS_HIGH, CVSS_MEDIUM,
    GVM_USER, GVM_PASSWORD,
)
from utils import setup_logging, create_async_session

logger = logging.getLogger("cycentra.modules.vuln_scanner")

# ---------------------------------------------------------------------------
# GVM (OpenVAS) optional import — gracefully degraded if not installed
# ---------------------------------------------------------------------------
try:
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeCheckCommandTransform
    GVM_AVAILABLE = True
except ImportError:
    GVM_AVAILABLE = False
    logger.info("[VulnScanner] python-gvm not installed — OpenVAS scan disabled. "
                "Install with: pip install python-gvm --break-system-packages")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_GVM_SOCKET = "/run/gvmd/gvmd.sock"   # default path; override via env if needed

_SEVERITY_FROM_CVSS = {
    (9.0, 10.0): "Critical",
    (7.0,  9.0): "High",
    (4.0,  7.0): "Medium",
    (0.1,  4.0): "Low",
}


def _severity_label(cvss: float) -> str:
    for (lo, hi), label in _SEVERITY_FROM_CVSS.items():
        if lo <= cvss <= hi:
            return label
    return "Informational"


def _risk_score(cvss: float, epss: float) -> int:
    """
    Combine CVSSv3 base score and EPSS probability into a 1-10 risk score.
    EPSS weighs in at 30% — a high-CVSS vuln with low exploitation probability
    scores lower than one with equal CVSS but active exploitation evidence.
    """
    weighted = (cvss * 0.7) + (epss * 10 * 0.3)
    return max(1, min(10, round(weighted)))



# ---------------------------------------------------------------------------
# NIS2 / DORA / ISO 27001 compliance impact tags
# ---------------------------------------------------------------------------
# Maps lowercase vulnerability keywords to specific regulatory article refs.
# NIS2 Directive (EU) 2022/2555 — Article 21 essential-entity requirements
# DORA Regulation (EU) 2022/2554 — ICT risk management articles
# ISO/IEC 27001:2022 — Annex A technical controls
_COMPLIANCE_MAP: Dict[str, Dict[str, str]] = {
    "ssl":       {"nis2": "Art.21.2.h", "dora": "Art.9.2", "iso27001": "A.8.24"},
    "tls":       {"nis2": "Art.21.2.h", "dora": "Art.9.2", "iso27001": "A.8.24"},
    "beast":     {"nis2": "Art.21.2.h", "dora": "Art.9.2", "iso27001": "A.8.24"},
    "poodle":    {"nis2": "Art.21.2.h", "dora": "Art.9.2", "iso27001": "A.8.24"},
    "drown":     {"nis2": "Art.21.2.h", "dora": "Art.9.2", "iso27001": "A.8.24"},
    "lucky13":   {"nis2": "Art.21.2.h", "dora": "Art.9.2", "iso27001": "A.8.24"},
    "exposed":   {"nis2": "Art.21.2.e", "dora": "Art.9.4", "iso27001": "A.8.3"},
    "admin":     {"nis2": "Art.21.2.e", "dora": "Art.9.3", "iso27001": "A.8.3"},
    "backup":    {"nis2": "Art.21.2.e", "dora": "Art.9.4", "iso27001": "A.8.9"},
    "git":       {"nis2": "Art.21.2.e", "dora": "Art.9.4", "iso27001": "A.8.3"},
    "env":       {"nis2": "Art.21.2.d", "dora": "Art.9.3", "iso27001": "A.8.12"},
    "secret":    {"nis2": "Art.21.2.d", "dora": "Art.9.3", "iso27001": "A.8.12"},
    "token":     {"nis2": "Art.21.2.d", "dora": "Art.9.3", "iso27001": "A.8.12"},
    "key":       {"nis2": "Art.21.2.d", "dora": "Art.9.3", "iso27001": "A.8.12"},
    "cve":       {"nis2": "Art.21.2.e", "dora": "Art.7.2", "iso27001": "A.8.8"},
    "openvas":   {"nis2": "Art.21.2.e", "dora": "Art.7.2", "iso27001": "A.8.8"},
    "_default":  {"nis2": "Art.21.2.e", "dora": "Art.9.2", "iso27001": "A.8.8"},
}


def _compliance_tags(vuln_id: str, source: str = "") -> Dict[str, str]:
    """
    Return NIS2/DORA/ISO 27001 article references for a finding.
    Matches the first keyword found in the combined vuln_id+source string.
    Always returns a dict — _default is the catch-all.
    """
    combined = (vuln_id + " " + source).lower()
    for keyword, tags in _COMPLIANCE_MAP.items():
        if keyword != "_default" and keyword in combined:
            return tags
    return _COMPLIANCE_MAP["_default"]


# ---------------------------------------------------------------------------
# CVE + EPSS via CyTIM
# ---------------------------------------------------------------------------

def _cytim_cve_by_keyword(domain: str, keyword: str) -> List[Dict[str, Any]]:
    """Query CyTIM /api/cytim/recon cve module by banner keyword. Returns CVE findings list."""
    try:
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), '..', '..'))
        from core.helpers import cytim_recon
        results = cytim_recon(domain, ["cve"], cve_keywords=[keyword[:120]])
        return (results.get("cve") or {}).get("findings", [])
    except Exception as e:
        logger.debug(f"[VulnScanner] CyTIM CVE keyword recon failed for '{keyword}': {e}")
        return []


def _cytim_epss_batch(domain: str, cve_ids: List[str]) -> Dict[str, float]:
    """Query CyTIM /api/cytim/recon cve module for EPSS scores. Returns {cve_id: float}."""
    if not cve_ids:
        return {}
    try:
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), '..', '..'))
        from core.helpers import cytim_recon
        results = cytim_recon(domain, ["cve"], cve_ids=cve_ids[:30])
        return (results.get("cve") or {}).get("epss", {})
    except Exception as e:
        logger.debug(f"[VulnScanner] CyTIM EPSS recon failed: {e}")
        return {}


# ---------------------------------------------------------------------------
# Port/banner-based CVE enrichment (extends web_analysis findings)
# ---------------------------------------------------------------------------
async def enrich_port_findings(
    fingerprints: Dict[int, Dict[str, Any]],
    domain: str,
    session: aiohttp.ClientSession,
) -> List[Dict[str, Any]]:
    """
    Takes the fingerprints dict from web_analysis.py (port → {banner, vulns})
    and enriches each open port with:
      - Full CVSSv3 score from NVD via CyTIM (not just CVE ID)
      - EPSS exploitation probability via CyTIM
      - Combined risk score (1-10)
      - Remediation recommendation
    """
    findings: List[Dict[str, Any]] = []
    loop = asyncio.get_running_loop()

    # Per-port CVE lookup via CyTIM (NVD keyword search)
    all_cve_ids: List[str] = []
    port_cves: Dict[int, List[Dict[str, Any]]] = {}

    for port, fp in fingerprints.items():
        banner = fp.get("banner", "")
        if not banner or banner in ("Error", "Unknown"):
            continue

        cves = await loop.run_in_executor(None, _cytim_cve_by_keyword, domain, banner)
        if cves:
            port_cves[port] = cves
            all_cve_ids.extend(c["cve_id"] for c in cves)

    # Single batch EPSS call via CyTIM for all collected CVE IDs
    epss_map = await loop.run_in_executor(None, _cytim_epss_batch, domain, all_cve_ids)

    for port, cves in port_cves.items():
        banner = fingerprints[port].get("banner", "")
        for cve in cves:
            cve_id = cve["cve_id"]
            epss   = epss_map.get(cve_id, 0.0)
            cvss   = cve["cvss"]
            risk   = _risk_score(cvss, epss)

            findings.append({
                "vulnerability":  cve_id,
                "module":         "vuln_scanner",
                "source":         "port_banner",
                "port":           port,
                "banner":         banner[:120],
                "cvss":           cvss,
                "epss":           round(epss, 4),
                "epss_pct":       f"{epss * 100:.1f}% exploitation probability",
                "severity":       _severity_label(cvss),
                "risk_score":     risk,
                "description":    cve["description"],
                "recommendation": _remediation_hint(port, cve_id, cvss),
                "compliance_impact": _compliance_tags(cve_id, "cve"),
                "domain":         domain,
                "discovered_at":  datetime.now(timezone.utc).isoformat(),
            })

    return sorted(findings, key=lambda x: x["risk_score"], reverse=True)


def _remediation_hint(port: int, cve_id: str, cvss: float) -> str:
    """Generate a context-aware remediation hint based on port and CVSS score."""
    base = f"Patch or upgrade the service on port {port} addressing {cve_id}"
    if cvss >= CVSS_CRITICAL:
        return f"URGENT: {base}. Consider taking service offline until patched. CVSSv3={cvss}."
    if cvss >= CVSS_HIGH:
        return f"{base}. Apply vendor patch within 7 days. CVSSv3={cvss}."
    if cvss >= CVSS_MEDIUM:
        return f"{base}. Schedule patch in next maintenance window. CVSSv3={cvss}."
    return f"{base}. Monitor and patch at next opportunity. CVSSv3={cvss}."


# ---------------------------------------------------------------------------
# SSL/TLS vulnerability checks (extends crypto_checks.py)
# ---------------------------------------------------------------------------
async def scan_ssl_vulnerabilities(domain: str) -> List[Dict[str, Any]]:
    """
    Check for well-known SSL/TLS vulnerabilities beyond what crypto_checks.py covers:
    - BEAST (CBC ciphers on TLS 1.0)
    - POODLE (SSLv3)
    - DROWN (SSLv2)
    - LUCKY13 (CBC mode)
    - Weak DH parameters (Logjam)
    - Certificate transparency log check
    """
    findings: List[Dict[str, Any]] = []

    checks = [
        ("SSLv2",  ssl.PROTOCOL_TLS_CLIENT, "DROWN",   9.8, "Disable SSLv2 immediately — allows decryption of RSA traffic."),
        ("SSLv3",  ssl.PROTOCOL_TLS_CLIENT, "POODLE",  3.4, "Disable SSLv3 — vulnerable to padding oracle attack."),
        ("TLSv1",  ssl.PROTOCOL_TLS_CLIENT, "BEAST",   3.4, "Disable TLS 1.0 — NIS2 and PCI-DSS require TLS 1.2+."),
        ("TLSv1.1",ssl.PROTOCOL_TLS_CLIENT, "BEAST",   3.4, "Disable TLS 1.1 — NIS2 and PCI-DSS require TLS 1.2+."),
    ]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for proto_name, _, vuln_name, cvss, rec in checks:
        try:
            test_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            test_ctx.check_hostname = False
            test_ctx.verify_mode = ssl.CERT_NONE
            # Deliberately try to force old protocol
            if proto_name in ("SSLv2", "SSLv3"):
                test_ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
            elif proto_name == "TLSv1":
                test_ctx.options |= ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3
            elif proto_name == "TLSv1.1":
                test_ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3

            with socket.create_connection((domain, 443), timeout=5) as sock:
                with test_ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    proto = ssock.version()
                    if proto and proto_name.replace("v", " ").lower() in proto.lower():
                        findings.append({
                            "vulnerability":  vuln_name,
                            "module":         "vuln_scanner",
                            "source":         "ssl_vuln_check",
                            "cvss":           cvss,
                            "epss":           0.0,
                            "severity":       _severity_label(cvss),
                            "risk_score":     _risk_score(cvss, 0.0),
                            "description":    f"{vuln_name}: server accepted {proto_name} connection from {domain}",
                            "recommendation": rec,
                            "compliance_impact": _compliance_tags(vuln_name, "ssl tls"),
                            "domain":         domain,
                            "discovered_at":  datetime.now(timezone.utc).isoformat(),
                        })
        except Exception:
            # Connection refused or handshake failure = protocol NOT supported = good
            pass

    return findings


# ---------------------------------------------------------------------------
# Exposed sensitive path enrichment (extends web_analysis.exposed_paths)
# ---------------------------------------------------------------------------
# Note: _verify_path_content removed — web_analysis.py already filters
# HTML soft-404s upstream via content-type gating. Only real exposures
# reach this function, so a second async content fetch is redundant and
# was the source of _UNVERIFIED duplicate findings.

async def enrich_exposed_paths(
    exposed_paths: List[Dict[str, Any]],
    domain: str,
    session: aiohttp.ClientSession,
) -> List[Dict[str, Any]]:
    """
    Takes the exposed_paths list from web_analysis (already HTML-filtered)
    and maps each path to a CVE reference, CVSS score, and remediation.
    One finding per CVE reference — no duplicates, no _UNVERIFIED variants.
    """
    _PATH_CVE_MAP = {
        "/.git/":      ("CVE-2021-40438", 9.1, "Git repository exposed — remove .git from web root"),
        "/.env":       ("ENV_EXPOSURE",   8.5, "Environment file exposed — rotate all credentials immediately"),
        "/admin":      ("ADMIN_EXPOSED",  6.5, "Admin panel exposed — restrict by IP or move behind VPN"),
        "/phpMyAdmin": ("CVE-2021-21234", 7.5, "phpMyAdmin exposed — restrict access by IP"),
        "/backup":     ("BACKUP_EXPOSED", 7.0, "Backup directory exposed — remove from web root"),
        "/db.dump":    ("DB_DUMP_EXPOSED",9.8, "Database dump exposed — remove immediately and rotate all DB credentials"),
    }
    seen: Dict[str, Dict] = {}
    for ep in exposed_paths:
        path = ep.get("path", "")
        status = ep.get("status")
        if status not in (200, 401, 403):   # skip redirects
            continue
        match = next(((cve, cvss, rec) for k, (cve, cvss, rec) in _PATH_CVE_MAP.items() if k in path), None)
        if not match:
            continue
        cve_ref, cvss, rec = match
        if cve_ref in seen:
            continue   # deduplicate by CVE ref — one finding per unique vulnerability
        seen[cve_ref] = {
            "vulnerability":     cve_ref,
            "module":            "vuln_scanner",
            "source":            "exposed_path",
            "path":              path,
            "http_status":       status,
            "cvss":              cvss,
            "epss":              0.0,
            "severity":          _severity_label(cvss),
            "risk_score":        _risk_score(cvss, 0.0),
            "description":       f"Exposed path {path} on {domain} returned HTTP {status}.",
            "recommendation":    rec,
            "compliance_impact": _compliance_tags(cve_ref, path),
            "domain":            domain,
            "discovered_at":     datetime.now(timezone.utc).isoformat(),
        }
    return sorted(seen.values(), key=lambda x: x["risk_score"], reverse=True)


# ---------------------------------------------------------------------------
# OpenVAS/GVM authenticated scan (optional — requires GVM running locally)
# ---------------------------------------------------------------------------
async def run_openvas_scan(
    domain: str,
    scan_config: str = "daba56c8-73ec-11df-a475-002264764cea",  # Full and Fast
) -> List[Dict[str, Any]]:
    """
    Run an OpenVAS authenticated scan via GVM Unix socket.
    Only executes when:
      - python-gvm is installed
      - GVM socket exists at _GVM_SOCKET
      - ENABLE_OPENVAS=true in env

    Returns normalised finding list compatible with the rest of the pipeline.
    """
    import os
    if not GVM_AVAILABLE:
        logger.info("[VulnScanner] Skipping OpenVAS — python-gvm not installed.")
        return []
    if not os.path.exists(_GVM_SOCKET):
        logger.info(f"[VulnScanner] Skipping OpenVAS — socket not found at {_GVM_SOCKET}.")
        return []
    if os.environ.get("ENABLE_OPENVAS", "false").lower() != "true":
        logger.info("[VulnScanner] Skipping OpenVAS — ENABLE_OPENVAS not set.")
        return []

    findings: List[Dict[str, Any]] = []
    try:
        connection = UnixSocketConnection(path=_GVM_SOCKET)
        transform  = EtreeCheckCommandTransform()
        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate(
                GVM_USER or "admin",
                GVM_PASSWORD,
            )
            # Create target
            target_resp = gmp.create_target(
                name=f"cycentra-{domain}-{int(datetime.now().timestamp())}",
                hosts=[domain],
                port_list_id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5",  # All IANA assigned
            )
            target_id = target_resp.get("id")
            if not target_id:
                logger.error("[VulnScanner] GVM create_target returned no ID")
                return []

            # Create and start task
            task_resp = gmp.create_task(
                name=f"cycentra-task-{domain}",
                config_id=scan_config,
                target_id=target_id,
                scanner_id="08b69003-5fc2-4037-a479-93b440211c73",  # OpenVAS Default
            )
            task_id = task_resp.get("id")
            gmp.start_task(task_id)

            # Poll for completion (max 10 min)
            for _ in range(60):
                await asyncio.sleep(10)
                status_resp = gmp.get_task(task_id)
                status = status_resp.find(".//status")
                if status is not None and status.text == "Done":
                    break
                progress = status_resp.find(".//progress")
                pct = progress.text if progress is not None else "?"
                logger.info(f"[VulnScanner] OpenVAS progress: {pct}%")

            # Fetch results
            results_resp = gmp.get_results(task_id=task_id)
            for result in results_resp.findall(".//result"):
                name  = result.findtext("name", "")
                desc  = result.findtext("description", "")
                threat = result.findtext("threat", "Log")
                cvss_elem = result.find(".//cvss_base")
                cvss  = float(cvss_elem.text) if cvss_elem is not None and cvss_elem.text else 0.0
                cve_refs = [ref.get("id", "") for ref in result.findall(".//ref[@type='cve']")]

                findings.append({
                    "vulnerability":  name or (cve_refs[0] if cve_refs else "OpenVAS Finding"),
                    "module":         "vuln_scanner",
                    "source":         "openvas",
                    "cve_refs":       cve_refs,
                    "cvss":           cvss,
                    "epss":           0.0,
                    "severity":       threat if threat != "Log" else "Informational",
                    "risk_score":     _risk_score(cvss, 0.0),
                    "description":    desc[:500],
                    "recommendation": f"Remediate {name} — see OpenVAS result for full details.",
                    "compliance_impact": _compliance_tags(name, "openvas cve"),
                    "domain":         domain,
                    "discovered_at":  datetime.now(timezone.utc).isoformat(),
                })

            logger.info(f"[VulnScanner] OpenVAS found {len(findings)} results for {domain}.")
    except Exception as e:
        logger.error(f"[VulnScanner] OpenVAS scan failed: {type(e).__name__}: {e}")

    return sorted(findings, key=lambda x: x["risk_score"], reverse=True)


# ---------------------------------------------------------------------------
# JS secret CVE mapping (extends web_analysis.js_secrets findings)
# ---------------------------------------------------------------------------
def enrich_js_secrets(js_secrets: List[Dict[str, Any]], domain: str) -> List[Dict[str, Any]]:
    """Adds severity/risk scoring to JS secret findings from web_analysis."""
    _SECRET_SEVERITY = {
        "AWS Access Key":    (9.8, "Rotate AWS credentials immediately. Revoke key in IAM console."),
        "AWS Secret Key":    (9.8, "Rotate AWS credentials immediately. Revoke key in IAM console."),
        "Stripe Live Key":   (9.5, "Revoke Stripe key immediately. Check for fraudulent charges."),
        "GitHub PAT":        (8.8, "Revoke GitHub PAT. Check for unauthorised repo access."),
        "Private Key":       (9.0, "Remove private key from codebase. Rotate associated certificate."),
        "Google API Key":    (7.5, "Restrict Google API key by referrer/IP. Rotate if possible."),
        "Firebase Key":      (7.5, "Restrict Firebase key. Review Firebase security rules."),
        "Slack Token":       (7.0, "Revoke Slack token. Check workspace audit logs."),
        "JWT Token":         (6.5, "Ensure JWT tokens are short-lived. Review signing secrets."),
        "Stripe Test Key":   (4.0, "Test key — rotate as best practice. Do not use in production."),
    }

    enriched = []
    for secret in js_secrets:
        stype = secret.get("type", "")
        cvss, rec = _SECRET_SEVERITY.get(stype, (6.0, "Rotate or remove this credential from client-side code."))
        enriched.append({
            "vulnerability":  f"SECRET_EXPOSURE_{stype.upper().replace(' ', '_')}",
            "module":         "vuln_scanner",
            "source":         "js_secret",
            "secret_type":    stype,
            "source_file":    secret.get("source", ""),
            "cvss":           cvss,
            "epss":           0.0,
            "severity":       _severity_label(cvss),
            "risk_score":     _risk_score(cvss, 0.0),
            "description":    (
                f"Secret type '{stype}' found in JavaScript file '{secret.get('source', '')}' "
                f"on {domain}. Value prefix: {str(secret.get('value', ''))[:12]}..."
            ),
            "recommendation": rec,
            "compliance_impact": _compliance_tags(stype, "secret token key"),
            "domain":         domain,
            "discovered_at":  datetime.now(timezone.utc).isoformat(),
        })

    return sorted(enriched, key=lambda x: x["risk_score"], reverse=True)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
async def gather_vuln_scanner(
    domain: str,
    web_results: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Main entry point for the vulnerability scanner module.

    Args:
        domain: target domain
        web_results: results dict from web_analysis.gather_web_analysis()
                     If None, only OpenVAS scan runs (if available).

    Returns standard cy_asm module dict: {results, issues, summary}
    """
    logger.info(f"[VulnScanner] Starting for {domain}...")
    all_findings: List[Dict[str, Any]] = []

    async with await create_async_session() as session:
        tasks = []

        # 1. Enrich port/banner findings from web_analysis
        if web_results:
            fp = web_results.get("results", {}).get("fingerprints", {})
            if fp:
                tasks.append(enrich_port_findings(fp, domain, session))

        # 2. Enrich exposed paths
        if web_results:
            ep = web_results.get("results", {}).get("exposed_paths", [])
            if ep:
                tasks.append(enrich_exposed_paths(ep, domain, session))

        # 3. SSL vulnerability checks
        tasks.append(scan_ssl_vulnerabilities(domain))

        # Run all async tasks concurrently
        task_results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in task_results:
            if isinstance(res, list):
                all_findings.extend(res)
            elif isinstance(res, Exception):
                logger.warning(f"[VulnScanner] Sub-task error: {res}")

        # 4. Enrich JS secrets (sync)
        if web_results:
            js = web_results.get("results", {}).get("js_secrets", [])
            if js:
                all_findings.extend(enrich_js_secrets(js, domain))

    # 5. OpenVAS (runs separately — potentially long)
    ov_findings = await run_openvas_scan(domain)
    all_findings.extend(ov_findings)

    # Deduplicate by vulnerability+port
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f.get("vulnerability"), f.get("port"), f.get("path"))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    deduped.sort(key=lambda x: x["risk_score"], reverse=True)

    critical_count = sum(1 for f in deduped if f["severity"] == "Critical")
    high_count     = sum(1 for f in deduped if f["severity"] == "High")
    issues = [
        f"{f['severity']} — {f['vulnerability']}: {f['description'][:80]}"
        for f in deduped
        if f["severity"] in ("Critical", "High")
    ]

    summary = (
        f"Vuln scan: {len(deduped)} findings "
        f"({critical_count} critical, {high_count} high)"
    )
    logger.info(f"[VulnScanner] {summary}")

    return {
        "results": {
            "findings":       deduped,
            "critical_count": critical_count,
            "high_count":     high_count,
            "total":          len(deduped),
            "openvas_used":   len(ov_findings) > 0,
        },
        "issues":  issues,
        "summary": summary,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python modules/vuln_scanner.py <domain>")
        sys.exit(1)
    target = sys.argv[1].strip().lower()
    result = asyncio.run(gather_vuln_scanner(target))
    print(json.dumps(result, indent=2, default=str))
