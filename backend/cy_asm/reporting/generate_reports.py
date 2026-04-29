#!/usr/bin/env python3
"""
reporting/generate_reports.py
CyCentra ASM — Report Generation Entry Point

Usage
-----
Standalone (from portal JSON file):
    python3 reporting/generate_reports.py /path/to/scan_domain.com_1234567.json

Called programmatically from cycentra_scan.py main():
    from reporting.generate_reports import generate_all_reports
    generate_all_reports(portal_payload, tenant_id, domain, timestamp)

Output
------
Both reports are saved to:
    /var/log/cycentra/cy-asm/reports/<tenant_id>/
        executive_<domain>_<timestamp>.pdf
        technical_<domain>_<timestamp>.pdf

The output directory can be overridden with the env var:
    CYCENTRA_REPORT_DIR=/custom/path
"""
from __future__ import annotations

import glob
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("CyCentra.Reports")

# Ensure the parent cy_asm directory is on sys.path when run standalone
_HERE = Path(__file__).resolve().parent
_CY_ASM = _HERE.parent
if str(_CY_ASM) not in sys.path:
    sys.path.insert(0, str(_CY_ASM))


_REPORTS_BASE = Path("/var/log/cycentra/cy-asm/reports")
_REPORT_LIMIT = 6


def _prune_old_reports() -> None:
    """Delete oldest PDFs so that no more than _REPORT_LIMIT files are retained."""
    base = os.environ.get("CYCENTRA_REPORT_DIR", "").strip()
    search_root = Path(base) if base else _REPORTS_BASE
    all_pdfs = sorted(
        glob.glob(str(search_root / "**" / "*.pdf"), recursive=True),
        key=os.path.getmtime,
        reverse=True,
    )
    for old_pdf in all_pdfs[_REPORT_LIMIT:]:
        try:
            os.remove(old_pdf)
            logger.info(f"[Reports] Pruned old report: {old_pdf}")
        except Exception as exc:
            logger.warning(f"[Reports] Failed to prune {old_pdf}: {exc}")


def _output_dir(tenant_id: str) -> Path:
    base = os.environ.get("CYCENTRA_REPORT_DIR", "").strip()
    if base:
        return Path(base)
    return Path("/var/log/cycentra/cy-asm/reports") / tenant_id


def generate_all_reports(
    portal_payload: Dict[str, Any],
    tenant_id: str,
    domain: str,
    timestamp: Optional[int] = None,
) -> Tuple[str, str]:
    """
    Generate both Executive and Technical PDF reports.

    Parameters
    ----------
    portal_payload : dict
        The portal JSON dict written by cycentra_scan.py main()
    tenant_id : str
        Tenant/organisation identifier (used for output folder)
    domain : str
        Target domain (used for filename)
    timestamp : int, optional
        Unix timestamp; defaults to now

    Returns
    -------
    (executive_path, technical_path) : Tuple[str, str]
    """
    ts = timestamp or int(time.time())
    out_dir = _output_dir(tenant_id)
    out_dir.mkdir(parents=True, exist_ok=True)

    safe_domain = domain.replace(".", "_").replace("/", "_")
    exec_path   = str(out_dir / f"executive_{safe_domain}_{ts}.pdf")
    tech_path   = str(out_dir / f"technical_{safe_domain}_{ts}.pdf")

    # Lazy imports — only load ReportLab when actually needed
    from reporting.executive_report import generate_executive_report
    from reporting.technical_report import generate_technical_report

    logger.info(f"[Reports] Generating Executive report → {exec_path}")
    try:
        generate_executive_report(portal_payload, exec_path)
        logger.info(f"[Reports] ✅ Executive report saved → {exec_path}")
    except Exception as e:
        logger.error(f"[Reports] ❌ Executive report failed: {type(e).__name__}: {e}")
        exec_path = ""

    logger.info(f"[Reports] Generating Technical report → {tech_path}")
    try:
        generate_technical_report(portal_payload, tech_path)
        logger.info(f"[Reports] ✅ Technical report saved → {tech_path}")
    except Exception as e:
        logger.error(f"[Reports] ❌ Technical report failed: {type(e).__name__}: {e}")
        tech_path = ""

    _prune_old_reports()

    return exec_path, tech_path


# ── Integration hook for cycentra_scan.py ────────────────────────────────────

def hook_into_scan(portal_payload: Dict[str, Any],
                   tenant_id: str,
                   domain: str,
                   timestamp: int) -> None:
    """
    Drop-in hook called from cycentra_scan.py main() after portal_file is saved.
    Never raises — report failure must never block scan output.
    """
    try:
        exec_p, tech_p = generate_all_reports(portal_payload, tenant_id, domain, timestamp)
        if exec_p:
            logger.info(f"[Reports] Executive → {exec_p}")
        if tech_p:
            logger.info(f"[Reports] Technical → {tech_p}")
    except Exception as e:
        logger.error(f"[Reports] Report generation hook failed (scan unaffected): {e}")


# ── Standalone CLI ────────────────────────────────────────────────────────────

def _demo_payload(domain: str) -> Dict[str, Any]:
    """Generate a realistic demo payload when no JSON file is provided."""
    import random
    ts = datetime.now().isoformat()
    findings = []
    vulns_data = [
        ("CVE-2024-1234", "Critical", 9.8, "SQL injection in login endpoint allows full DB dump.",
         "Apply patch >= 2.4.1 or disable the endpoint behind WAF.", "vuln_scanner"),
        ("ADMIN_EXPOSED", "Critical", 8.5, "Admin panel accessible without authentication at /admin.",
         "Restrict /admin by IP or move behind VPN.", "web"),
        ("ENV_EXPOSURE", "High", 8.5, ".env file exposed at /.env containing DB credentials.",
         "Remove .env from web root and rotate all credentials.", "web"),
        ("CVE-2023-44487", "High", 7.5, "HTTP/2 Rapid Reset vulnerability in nginx 1.24.",
         "Upgrade nginx to >= 1.25.3.", "vuln_scanner"),
        ("DMARC_WEAK", "High", 7.0, "DMARC policy set to 'none' — emails can be spoofed.",
         "Update DMARC to p=reject.", "email_sec"),
        ("EXPOSED_GIT", "High", 7.0, ".git directory accessible — source code leakage risk.",
         "Block .git access in web server config.", "web"),
        ("SSL_DEPRECATED_TLS", "Medium", 6.5, "TLS 1.0 accepted — deprecated protocol.",
         "Disable TLS 1.0 and 1.1 in server config.", "crypto"),
        ("JQUERY_CVE", "Medium", 5.0, "jQuery 1.7.2 loaded from CDN — XSS vulnerabilities known.",
         "Upgrade to jQuery >= 3.7.0.", "supply_chain"),
        ("BUCKET_PUBLIC", "Medium", 5.5, "S3 bucket company-assets publicly listable.",
         "Set bucket ACL to private and enable block public access.", "cloud"),
        ("SECRET_STRIPE_KEY", "Critical", 9.5, "Stripe live API key found in main.js.",
         "Revoke key immediately and move to server-side only.", "vuln_scanner"),
        ("TYPOSQUAT_REGISTERED", "Low", 3.0, "3 typosquatting domains are registered.",
         "Monitor and consider legal takedown.", "dns"),
        ("OCSP_MISSING", "Low", 2.5, "OCSP stapling not enabled on web server.",
         "Enable OCSP stapling in nginx/Apache config.", "crypto"),
    ]
    for vuln, sev, cvss, desc, rec, mod in vulns_data:
        findings.append({
            "vulnerability": vuln, "severity": sev, "cvss": cvss,
            "risk_score": min(10, round(cvss)),
            "description": desc, "recommendation": rec, "module": mod,
            "epss": round(random.uniform(0.01, 0.4), 3),
            "compliance_impact": {"nis2": "Art.21.2.e", "dora": "Art.9.2", "iso27001": "A.8.8"},
        })

    return {
        "meta": {
            "last_scan": ts, "org": "Demo Organisation Ltd",
            "scan_id": f"ASM-{int(time.time())}", "domain": domain,
            "scan_type": "deep", "include_subdomains": True,
        },
        "subdomain_summary": {"total": 42, "live": 18, "historical": 24, "new": 3},
        "assets": [{
            "id": f"{domain}-demo",
            "host": domain,
            "risk_score": 8,
            "summary": f"Demo scan of {domain}",
            "vulnerabilities": findings,
            "raw_results": {
                "dns": {"results": {
                    "records": {"A": ["185.220.101.1"], "MX": [f"mail.{domain}"],
                                "TXT": ["v=spf1 include:_spf.google.com ~all"],
                                "NS": [f"ns1.{domain}"], "AAAA": [], "CNAME": [],
                                "SOA": [], "DS": [], "CAA": []},
                    "ips": [{"ip": "185.220.101.1", "country": "DE", "org": "Hetzner",
                              "cloud_provider": "Hetzner", "reverse_dns": f"static.{domain}"}],
                    "typos": {"registered": [f"www{domain.split('.')[0]}.com",
                                              f"{domain.split('.')[0]}s.com"],
                               "unregistered": []},
                }, "issues": [], "summary": "DNS OK"},
                "subdomains": {"results": [
                    {"subdomain": f"www.{domain}",    "live": True,  "resolved_ips": ["185.220.101.1"], "sources": ["crtsh"], "is_new": False, "change": "persisted", "cname": None},
                    {"subdomain": f"mail.{domain}",   "live": True,  "resolved_ips": ["185.220.101.2"], "sources": ["crtsh","bruteforce"], "is_new": False, "change": "persisted", "cname": None},
                    {"subdomain": f"api.{domain}",    "live": True,  "resolved_ips": ["185.220.101.3"], "sources": ["crtsh"], "is_new": True,  "change": "new", "cname": None},
                    {"subdomain": f"dev.{domain}",    "live": False, "resolved_ips": [], "sources": ["crtsh"], "is_new": False, "change": "disappeared", "cname": None},
                    {"subdomain": f"staging.{domain}","live": True,  "resolved_ips": ["185.220.101.4"], "sources": ["bruteforce"], "is_new": True, "change": "new", "cname": None},
                ], "issues": [], "summary": "5 subdomains"},
                "crypto": {"results": {"ssl": {
                    "ssl_enabled": False,
                    "cert_info": {"issuer": "Let's Encrypt", "days_to_expiry": 12,
                                  "cipher": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.2",
                                  "chain_valid": True, "san_valid": True,
                                  "self_signed": False, "ocsp_stapling": False},
                    "issues": ["TLS 1.0 accepted", "OCSP stapling not enabled"],
                }, "pqc": {"server_pqc": False}}, "issues": ["TLS 1.0 accepted"]},
                "email_sec": {"results": {
                    "spf": {"present": True, "record": "v=spf1 include:_spf.google.com ~all"},
                    "dmarc": {"present": True, "record": "v=DMARC1; p=none; rua=mailto:dmarc@"+domain,
                               "policy": "none"},
                    "dkim": [{"selector": "google", "record": "v=DKIM1; k=rsa; p=MIIBIjAN...", "valid": True}],
                    "dnssec": {"enabled": False},
                    "elite_checks": {
                        "bimi": {"status": "fail"}, "mta_sts": {"status": "fail"},
                        "tls_rpt": {"status": "fail"},
                        "caa_ssl": {"caa_records": []},
                    },
                    "spoofing_risk": {"level": "medium", "note": "DMARC policy is 'none'"},
                    "elite_score": "2/8", "elite_status": "basic",
                }, "issues": ["Email spoofing risk: medium"]},
                "cloud": {"results": {
                    "providers": ["AWS", "Cloudflare"],
                    "buckets": [
                        {"url": f"https://{domain.split('.')[0]}-assets.s3.amazonaws.com",
                         "risk": "PUBLIC/LISTABLE", "status": 200, "details": "Bucket listing enabled"},
                        {"url": f"https://{domain.split('.')[0]}-backup.s3.amazonaws.com",
                         "risk": "EXISTS", "status": 403, "details": "Private but exists"},
                    ],
                    "k8s_exposed": False,
                }, "issues": ["1 public/listable cloud buckets detected"]},
                "web": {"results": {
                    "ports": [80, 443, 22, 8080],
                    "fingerprints": {
                        80:   {"banner": "nginx/1.24.0", "vulns": ["CVE-2023-44487"]},
                        443:  {"banner": "nginx/1.24.0 OpenSSL/1.1.1t", "vulns": ["CVE-2023-44487"]},
                        22:   {"banner": "OpenSSH_8.9p1", "vulns": []},
                        8080: {"banner": "Apache Tomcat/9.0.75", "vulns": ["CVE-2023-42795"]},
                    },
                    "js_secrets": [
                        {"type": "Stripe Live Key", "value": "sk_live_4xBc...truncated", "source": "main.bundle.js"},
                    ],
                    "exposed_paths": [
                        {"path": "/admin", "url": f"https://{domain}/admin", "status": 200, "severity": "Critical"},
                        {"path": "/.env",  "url": f"https://{domain}/.env",  "status": 200, "severity": "Critical"},
                        {"path": "/.git/", "url": f"https://{domain}/.git/", "status": 200, "severity": "High"},
                    ],
                    "api_endpoints": [f"https://{domain}/api/v1", f"https://{domain}/graphql"],
                    "http_analysis": {
                        "http_headers": ["Missing Content-Security-Policy", "Missing Strict-Transport-Security"],
                        "redirects_to_https": True, "cors_issues": [],
                    },
                }, "issues": ["Critical exposures"]},
                "supply_chain": {"results": {
                    "scripts": [f"https://code.jquery.com/jquery-1.7.2.min.js",
                                f"https://cdn.example.com/lodash/4.17.1/lodash.min.js"],
                    "risks": [
                        {"library": "jQuery 1.7", "severity": "High", "cvss": 7.5,
                         "cve_ids": ["CVE-2019-11358"], "reason": "Prototype pollution vulnerability"},
                        {"library": "Lodash (outdated)", "severity": "High", "cvss": 7.4,
                         "cve_ids": ["CVE-2020-8203"], "reason": "Prototype pollution"},
                    ], "count": 2, "high": 2,
                }, "issues": ["Vulnerable dependency: jQuery"]},
                "dark_web": {"results": {
                    "hibp": [
                        {"title": "Adobe", "breach_date": "2013-10-04",
                         "data_classes": ["Email addresses", "Passwords", "Credit cards"],
                         "url": "https://haveibeenpwned.com/Breaches#Adobe",
                         "risk": "Data breach (2013-10-04). Includes passwords."},
                    ],
                    "ahmia": [],
                    "summary": "1 data breach found.",
                }, "issues": []},
                "osint": {"results": {
                    "misp": [],
                    "shodan": [],
                    "shodan_cve_findings": [
                        {"vulnerability": "CVE-2023-44487", "cvss": 7.5, "severity": "High",
                         "ip": "185.220.101.1", "port": 443,
                         "description": "HTTP/2 Rapid Reset DoS vulnerability",
                         "recommendation": "Upgrade nginx to >= 1.25.3",
                         "module": "passive_osint", "source": "shodan",
                         "risk_score": 8, "domain": domain,
                         "discovered_at": ts},
                    ],
                }, "issues": []},
                "whois": {"results": {"whois": {"registrar": "Namecheap", "expiration_date": "2026-01-15"},
                                       "history": []}, "issues": [], "summary": "WHOIS OK"},
                "vuln_scanner": {"results": {"total": 4, "critical_count": 2, "high_count": 2,
                                              "findings": findings[:4]}, "issues": []},
            },
        }],
    }


if __name__ == "__main__":
    # Set up basic logging for standalone run
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)s  %(message)s",
    )

    if len(sys.argv) >= 2 and sys.argv[1].endswith(".json"):
        # Load real portal JSON
        json_path = sys.argv[1]
        with open(json_path) as f:
            payload = json.load(f)
        domain    = payload.get("meta", {}).get("domain", "unknown")
        tenant_id = payload.get("meta", {}).get("org", "demo")
        ts        = int(time.time())
    elif len(sys.argv) >= 2:
        # Use domain argument with demo data
        domain    = sys.argv[1].strip().lower()
        tenant_id = "demo"
        ts        = int(time.time())
        payload   = _demo_payload(domain)
    else:
        domain    = "example.com"
        tenant_id = "demo"
        ts        = int(time.time())
        payload   = _demo_payload(domain)

    exec_path, tech_path = generate_all_reports(payload, tenant_id, domain, ts)
    print(f"\n✅ Executive report : {exec_path}")
    print(f"✅ Technical report  : {tech_path}\n")
