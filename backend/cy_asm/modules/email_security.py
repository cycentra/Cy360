# modules/email_security.py
import dns.resolver
import socket
import ssl
import re
import requests
from typing import Dict, List, Any
from urllib3.util import Retry
from requests.adapters import HTTPAdapter
from config import COMMON_DKIM_SELECTORS, HTTP_TIMEOUT
from utils import setup_logging

logger = setup_logging()

def reconstruct_txt_record(rdata) -> str:
    try:
        return ''.join(s.decode('utf-8', errors='ignore').strip('"') for s in rdata.strings).strip()
    except Exception: return ""

def _http_get(url: str, timeout: int = 5) -> str:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    try:
        resp = session.get(url, timeout=timeout, verify=True)
        resp.raise_for_status()
        return resp.text
    except Exception: return ""

async def gather_email_security(domain: str) -> Dict[str, Any]:
    logger.info(f"📧 [EMAIL] Starting full security audit for {domain}")
    
    results = {
        "spf": {"present": False, "record": None, "note": None},
        "dmarc": {"present": False, "record": None, "policy": None, "note": None},
        "dkim": [],
        "dnssec": {"enabled": False, "note": None},
        "mx": [],
        "elite_checks": {
            "bimi": {"status": "fail", "record": None},
            "mta_sts": {"status": "fail", "mode": None, "policy": None},
            "tls_rpt": {"status": "fail", "record": None},
            "caa_ssl": {"caa_records": [], "ssl_grade": None}
        }
    }

    resolver = dns.resolver.Resolver()
    #resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
    resolver.timeout = 5

    # --- SPF & TXT ---
    try:
        txt_ans = resolver.resolve(domain, "TXT")
        for rdata in txt_ans:
            txt = reconstruct_txt_record(rdata)
            if txt.startswith("v=spf1"):
                results["spf"]["present"] = True
                results["spf"]["record"] = txt
                if " -all" in txt: results["spf"]["note"] = "Hard fail policy enforced"
                elif " ~all" in txt: results["spf"]["note"] = "Soft fail policy"
                elif " +all" in txt: results["spf"]["note"] = "WARNING: +all allows spoofing!"
    except: pass

    # --- DMARC ---
    try:
        d_ans = resolver.resolve("_dmarc." + domain, "TXT")
        txt = reconstruct_txt_record(d_ans[0])
        results["dmarc"]["present"] = True
        results["dmarc"]["record"] = txt
        pm = re.search(r"p=([a-z]+)", txt)
        if pm: 
            results["dmarc"]["policy"] = pm.group(1)
            results["dmarc"]["note"] = f"Policy: {pm.group(1)}"
    except: pass

    # --- DKIM ---
    for sel in COMMON_DKIM_SELECTORS:
        try:
            ans = resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            txt = reconstruct_txt_record(ans[0])
            results["dkim"].append({"selector": sel, "record": txt, "valid": "v=DKIM1" in txt})
        except: pass

    # --- MX & SMTP TLS ---
    mx_tls_issues = []
    try:
        ans = resolver.resolve(domain, "MX")
        results["mx"] = [str(r.exchange).rstrip(".") for r in ans]
        for mx in results["mx"]:
            try:
                s = socket.create_connection((mx, 25), timeout=5)
                # Note: original used wrap_socket directly on 25, usually requires STARTTLS
                ss = ssl.create_default_context().wrap_socket(s, server_hostname=mx)
                mx_tls_issues.append(f"{mx}: TLS supported")
            except: mx_tls_issues.append(f"{mx}: TLS check failed")
    except: pass
    results["mx_tls"] = mx_tls_issues

    # --- DNSSEC ---
    try:
        ans = resolver.resolve(domain, "DS")
        if ans: results["dnssec"] = {"enabled": True, "note": f"{len(ans)} DS records"}
    except: pass

    # --- BIMI, MTA-STS, TLS-RPT, CAA ---
    try:
        ans = resolver.resolve("default._bimi." + domain, "TXT")
        results["elite_checks"]["bimi"] = {"status": "pass", "record": reconstruct_txt_record(ans[0])}
    except: pass

    try:
        ans = resolver.resolve("_mta-sts." + domain, "TXT")
        txt = reconstruct_txt_record(ans[0])
        if txt.startswith("v=STSv1"):
            results["elite_checks"]["mta_sts"]["status"] = "pass"
            policy = _http_get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", HTTP_TIMEOUT)
            if policy: results["elite_checks"]["mta_sts"]["policy"] = policy
    except: pass

    try:
        ans = resolver.resolve("_smtp._tls." + domain, "TXT")
        results["elite_checks"]["tls_rpt"] = {"status": "pass", "record": reconstruct_txt_record(ans[0])}
    except: pass

    try:
        ans = resolver.resolve(domain, "CAA")
        results["elite_checks"]["caa_ssl"]["caa_records"] = [reconstruct_txt_record(r) for r in ans]
    except: pass

    # --- Spoofing Risk & Scoring ---
    accepts = bool(results["mx"])
    spf_v = results["spf"]["present"] and "-all" in (results["spf"]["record"] or "")
    dm_v = results["dmarc"]["present"] and results["dmarc"]["policy"] == "reject"
    
    risk = "none"
    note = []
    if accepts:
        if not results["spf"]["present"] or not results["dmarc"]["present"]: 
            risk = "high"
            note.append("Missing SPF/DMARC")
        elif not spf_v or results["dmarc"]["policy"] in ["none", "quarantine"]:
            risk = "medium"
            note.append("Policy not strict (reject)")
    results["spoofing_risk"] = {"level": risk, "note": "; ".join(note)}

    passes = sum([spf_v, bool(results["dkim"]), dm_v, results["dnssec"]["enabled"],
                  results["elite_checks"]["bimi"]["status"]=="pass", 
                  results["elite_checks"]["mta_sts"]["status"]=="pass",
                  results["elite_checks"]["tls_rpt"]["status"]=="pass",
                  bool(results["elite_checks"]["caa_ssl"]["caa_records"])])
    
    results["elite_score"] = f"{passes}/8"
    results["elite_status"] = "elite" if passes == 8 else "robust" if passes >= 6 else "basic"

    return {
        "results": results, 
        "issues": [f"Email spoofing risk: {risk}"] if risk != "none" else [],
        "summary": f"Email: {results['elite_status']} (Score: {results['elite_score']})"
    }
