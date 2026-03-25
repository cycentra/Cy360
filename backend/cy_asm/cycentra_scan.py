#!/opt/cycentra/backend/venv/bin/python3
import asyncio
import json
import sys
import time
import os
import httpx
import traceback
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

# Import all modules
from modules.dns_recon import gather_dns_intel
from modules.subdomain_enum import gather_subdomains
from modules.web_analysis import gather_web_analysis
from modules.cloud_infra import gather_cloud_infra
from modules.crypto_checks import audit_crypto
from modules.whois_history import gather_whois_history
from modules.passive_osint import gather_passive_osint
from modules.supply_chain import gather_supply_chain
from modules.social_eng import gather_social_eng
from modules.mobile_api import gather_mobile_api
from modules.email_security import gather_email_security
from modules.dark_web import gather_dark_web
from tenant_manager import validate_tenant
from utils import setup_logging

# --- ENRICHMENT IMPORTS ---
from config import GOOGLE_GEMINI_KEY
from google import genai
from google.genai import types

logger = setup_logging()

# --- OLLAMA CONFIG ---
OLLAMA_BASE_URL = "http://116.203.115.95:11434"
OLLAMA_MODEL = "mranv/siem-llama-3.1:v1"


def _trim_payload(context_payload: dict, max_chars: int = 3000) -> dict:
    """Truncates the payload to avoid overwhelming smaller local models."""
    raw = json.dumps(context_payload)
    if len(raw) > max_chars:
        logger.warning(f"⚠️ [AI] Payload trimmed from {len(raw)} to {max_chars} chars for Ollama.")
        return {"truncated_data": raw[:max_chars] + "... [truncated]"}
    return context_payload


async def get_available_ollama_models() -> List[str]:
    """Fetches the list of pulled models from Ollama on server B."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
            response.raise_for_status()
            models = response.json().get("models", [])
            return [m["name"] for m in models]
    except Exception as e:
        logger.warning(f"⚠️ [Ollama] Could not reach server B to check models: {e}")
        return []


async def resolve_ollama_model(desired: str) -> str | None:
    """Validates the desired model exists on server B, with fuzzy matching."""
    available = await get_available_ollama_models()

    if not available:
        logger.error("❌ [Ollama] No models found or server B unreachable.")
        return None

    # Exact match first
    if desired in available:
        logger.info(f"✅ [Ollama] Model '{desired}' confirmed on server B.")
        return desired

    # Fuzzy match: 'llama3' should match 'llama3:latest'
    for model in available:
        if model.startswith(desired.split(":")[0]):
            logger.warning(f"⚠️ [Ollama] '{desired}' not exact — using '{model}' instead.")
            return model

    logger.error(
        f"❌ [Ollama] Model '{desired}' not found on server B.\n"
        f"   Available models: {', '.join(available)}\n"
        f"   Run: ollama pull {desired}  (on server B)"
    )
    return None


async def enrich_findings_with_ai(full_results: Dict[str, Any], domain: str) -> List[Dict[str, Any]]:
    """Tries Google Gemini first, falls back to local Ollama on server B if it fails."""

    context_payload = {
        "dns": full_results.get('dns', {}).get('results', {}).get('records', {}),
        "email": full_results.get('email_sec', {}).get('results', {}),
        "web": {
            "headers": full_results.get('web', {}).get('results', {}).get('http_analysis', {}).get('http_headers', []),
            "tech": full_results.get('web', {}).get('results', {}).get('fingerprints', {}),
            "ssl": full_results.get('web', {}).get('results', {}).get('ssl', {}).get('cert_info', {})
        },
        "cloud": full_results.get('cloud', {}).get('results', {}),
        "supply_chain": full_results.get('supply_chain', {}).get('results', []),
        "crypto": full_results.get('crypto', {}).get('results', {})
    }

    prompt = f"""
    As a Senior Security Architect, analyze this ASM data for {domain}.

    CRITICAL ANALYSIS POINTS:
    1. SUPPLY CHAIN: Check if third-party scripts (JS) pose a 'Magecart' or 'Data Leak' risk.
    2. CLOUD: Identify if the infrastructure is split across providers (AWS/GCP/Azure) and if that increases the attack surface.
    3. CRYPTO: Evaluate SSL strength and Post-Quantum readiness.
    4. CORRELATION: Does a DNS record point to a Cloud provider that isn't properly configured?

    DATA:
    {json.dumps(context_payload)}

    Return a JSON LIST of objects. Each object MUST include:
    "vulnerability", "severity", "risk_score" (1-10), "description", "recommendation", and "module".

    Return ONLY the raw JSON list, no markdown, no explanation.
    """

    # ── ATTEMPT 1: Google Gemini ──────────────────────────────────────────────
    try:
        logger.info(f"🤖 [AI] Trying Google Gemini for {domain}...")
        client = genai.Client(api_key=GOOGLE_GEMINI_KEY)
        response = await asyncio.to_thread(
            client.models.generate_content,
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(response_mime_type="application/json")
        )
        result = response.parsed if response.parsed else json.loads(response.text)
        logger.info(f"✅ [AI] Gemini enrichment succeeded for {domain}.")
        return result

    except Exception as gemini_err:
        logger.warning(f"⚠️ [AI] Gemini failed: {type(gemini_err).__name__}: {gemini_err}")
        logger.info(f"🔄 [AI] Falling back to Ollama ({OLLAMA_MODEL}) for {domain}...")

    # ── ATTEMPT 2: Ollama (trimmed payload + extended timeout) ────────────────
    resolved_model = await resolve_ollama_model(OLLAMA_MODEL)

    if resolved_model is None:
        logger.error("❌ [AI] Ollama unavailable or model missing. Returning empty.")
        return []

    ollama_payload = _trim_payload(context_payload, max_chars=3000)

    prompt_ollama = f"""
    As a Senior Security Architect, analyze this ASM data for {domain}.

    CRITICAL ANALYSIS POINTS:
    1. SUPPLY CHAIN: Check if third-party scripts (JS) pose a 'Magecart' or 'Data Leak' risk.
    2. CLOUD: Identify if the infrastructure is split across providers and increases attack surface.
    3. CRYPTO: Evaluate SSL strength and Post-Quantum readiness.
    4. CORRELATION: Does a DNS record point to a misconfigured Cloud provider?

    DATA:
    {json.dumps(ollama_payload)}

    Return a JSON LIST of objects. Each MUST include:
    "vulnerability", "severity", "risk_score" (1-10), "description", "recommendation", "module".

    Return ONLY the raw JSON list, no markdown, no explanation.
    """

    try:
        # Use streaming=True so each token resets the read timeout,
        # avoiding ReadTimeout on large/slow responses from the 8B model.
        timeout_config = httpx.Timeout(connect=10.0, read=60.0, write=30.0, pool=10.0)
        full_response = ""
        chunk_count = 0

        async with httpx.AsyncClient(timeout=timeout_config) as http_client:
            logger.info(f"⏳ [AI] Sending to Ollama (streaming, may take a few mins)...")
            async with http_client.stream(
                "POST",
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": resolved_model,
                    "prompt": prompt_ollama,
                    "stream": True,   # ← streaming keeps read timeout alive per chunk
                    "format": "json"
                }
            ) as stream_response:
                stream_response.raise_for_status()
                async for line in stream_response.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                        full_response += chunk.get("response", "")
                        chunk_count += 1
                        # Log a heartbeat every 20 chunks so we know it's alive
                        if chunk_count % 20 == 0:
                            logger.info(f"⏳ [AI] Ollama still generating... ({len(full_response)} chars so far)")
                        if chunk.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue

        result = json.loads(full_response)
        logger.info(f"✅ [AI] Ollama ({resolved_model}) enrichment succeeded for {domain} ({chunk_count} chunks).")
        return result

    except json.JSONDecodeError as e:
        logger.error(f"❌ [AI] Ollama returned malformed JSON: {e}\nRaw: {full_response[:500]}")
    except Exception as ollama_err:
        logger.error(
            f"❌ [AI] Ollama fallback failed: {type(ollama_err).__name__}: {ollama_err}\n"
            f"{traceback.format_exc()}"
        )

    # ── BOTH FAILED ───────────────────────────────────────────────────────────
    logger.error(f"❌ [AI] All enrichment providers exhausted for {domain}. Returning empty.")
    return []


async def run_full_scan(domain: str, tenant_id: str) -> Dict[str, Any]:
    scan_start = datetime.now()
    logger.info(f"=== Starting CyCentra UNIVERSAL Scan for {domain} (Tenant: {tenant_id}) ===")

    # 1. Core Recon (DNS & Subs first as others depend on them)
    dns = await gather_dns_intel(domain)
    subs = await gather_subdomains(domain)
    subdomains_list = subs.get("results", [])

    # 2. Launch all other modules in parallel
    logger.info(f"⚡ Launching all security modules in parallel...")
    tasks = {
        "crypto": audit_crypto(domain),
        "whois": gather_whois_history(domain),
        "osint": gather_passive_osint(domain),
        "supply_chain": gather_supply_chain(domain),
        "social_eng": gather_social_eng(domain),
        "mobile_api": gather_mobile_api(domain),
        "email_sec": gather_email_security(domain),
        "dark_web": gather_dark_web(domain, subdomains_list),
        "web": gather_web_analysis(domain, dns.get("results", {}).get("records", {})),
        "cloud": gather_cloud_infra(domain, dns.get("results", {}).get("ips", []))
    }

    module_names = list(tasks.keys())
    raw_results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    results = {"dns": dns, "subdomains": subs}
    all_issues = []

    # Progress labels used by app.py /api/scan/status to track % completion.
    # Keys must match the task dict keys above exactly.
    _progress_labels = {
        "dns":          "DNS Reconnaissance",
        "subdomains":   "Subdomain Enumeration",
        "web":          "Web Analysis",
        "crypto":       "Crypto & SSL Audit",
        "email_sec":    "Email Security Check",
        "whois":        "WHOIS & History",
        "osint":        "OSINT Gathering",
        "cloud":        "Cloud Infrastructure",
        "dark_web":     "Dark Web Monitoring",
        "supply_chain": "Supply Chain Analysis",
        "social_eng":   "Social Engineering Intel",
        "mobile_api":   "Mobile & API Checks",
    }

    for name, res in zip(module_names, raw_results):
        if isinstance(res, Exception):
            logger.error(f"❌ Module '{name}' CRASHED: {res}")
            results[name] = {"error": str(res), "results": {}, "issues": []}
        else:
            results[name] = res
            if isinstance(res, dict) and "issues" in res:
                all_issues.extend(res["issues"])
            label = _progress_labels.get(name, name)
            logger.info(f"📥 Module '{name}' completed. [{label}]")

    summary_text = f"CyCentra scan complete | {len(subdomains_list)} subdomains | {len(all_issues)} issues"

    scan_end = datetime.now()
    duration = (scan_end - scan_start).seconds

    logger.info(
        f"\n{'='*60}\n"
        f"✅ SCAN COMPLETE: {domain}\n"
        f"   Tenant      : {tenant_id}\n"
        f"   Subdomains  : {len(subdomains_list)}\n"
        f"   Issues Found: {len(all_issues)}\n"
        f"   Duration    : {duration}s\n"
        f"   Finished At : {scan_end.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{'='*60}"
    )

    return {
        "domain": domain,
        "summary": summary_text,
        "total_subdomains": len(subdomains_list),
        "total_issues": len(all_issues),
        "tenant_id": tenant_id,
        "results": results,
        "all_issues": all_issues
    }


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 cycentra_scan.py <domain> <tenant_id>")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()
    raw_tenant = sys.argv[2].strip().lower()
    final_tenant_id = validate_tenant(raw_tenant)

    # Execute Scan
    result = asyncio.run(run_full_scan(domain, final_tenant_id))

    # AI Enrichment (single call — removed duplicate)
    logger.info(f"🤖 Starting AI enrichment for {domain}...")
    enriched_issues = asyncio.run(enrich_findings_with_ai(result['results'], domain))
    timestamp = int(time.time())

    # --- FOLDER SETUP ---
    # If app.py passed a per-user output dir via env var, use it for the portal JSON.
    # Falls back to the tenant-based path when run manually from CLI.
    output_dir_override = os.environ.get("CYCENTRA_OUTPUT_DIR", "").strip()

    reports_base = Path("/var/log/cycentra/cy-asm/reports") / final_tenant_id
    portal_base  = Path(output_dir_override) if output_dir_override else Path("/var/log/cycentra/cy-asm/scans") / final_tenant_id

    for p in [reports_base, portal_base]:
        p.mkdir(parents=True, exist_ok=True)

    report_file = reports_base / "asm_scan.json"
    portal_file = portal_base / f"scan_{domain}_{timestamp}.json"

    # --- 1. NDJSON REPORT (For Wazuh) ---
    logger.info("💾 Saving NDJSON report...")
    try:
        with open(report_file, "a") as f:
            # Scan summary line
            f.write(json.dumps({
                "type": "scan_summary", "tenant_id": final_tenant_id, "domain": domain,
                "total_issues": result['total_issues'], "summary": result['summary'],
                "timestamp": datetime.now().isoformat()
            }) + "\n")

            # Loop through every module
            for mod_name, mod_data in result['results'].items():
                if not isinstance(mod_data, dict):
                    continue

                findings = mod_data.get('results', {})
                if isinstance(findings, dict):
                    for key, val in findings.items():
                        if val:
                            f.write(json.dumps({
                                "type": f"{mod_name}_{key}", "tenant_id": final_tenant_id,
                                "domain": domain, "data": val
                            }) + "\n")
                elif isinstance(findings, list):
                    for item in findings:
                        f.write(json.dumps({
                            "type": f"{mod_name}_item", "tenant_id": final_tenant_id,
                            "domain": domain, "value": item
                        }) + "\n")

                for issue in mod_data.get('issues', []):
                    f.write(json.dumps({
                        "type": "vulnerability", "tenant_id": final_tenant_id,
                        "domain": domain, "module": mod_name, "finding": issue
                    }) + "\n")

        logger.info(f"✅ NDJSON report saved → {report_file}")

    except Exception as e:
        logger.error(f"❌ Failed to save NDJSON: {e}")

    # --- 2. PORTAL JSON ---
    logger.info("💾 Saving portal JSON...")
    try:
        all_findings = result.get('all_issues', [])
        severity_map = {"Critical": 10, "High": 8, "Medium": 5, "Low": 2, "Informational": 1}
        ai_score = max(
            [severity_map.get(i.get('severity'), 0) for i in enriched_issues] + [len(all_findings)]
        )

        summary_text = (
            enriched_issues[0]['description'][:100] + "..."
            if enriched_issues else result['summary']
        )

        portal_payload = {
            "meta": {
                "last_scan": datetime.now().isoformat(),
                "org": final_tenant_id,
                "scan_id": f"ASM-{timestamp}",
                "domain": domain
            },
            "assets": [{
                "id": f"{domain}-{timestamp}",
                "host": domain,
                "risk_score": ai_score,
                "summary": summary_text,
                "vulnerabilities": enriched_issues,
                "raw_results": result['results']
            }]
        }

        with open(portal_file, "w") as pf:
            json.dump(portal_payload, pf, indent=2)

        logger.info(f"✅ Portal JSON saved → {portal_file}")

    except Exception as e:
        logger.error(f"❌ Failed to save portal JSON: {e}")

    # --- FINAL SUMMARY ---
    ai_provider = "Gemini" if enriched_issues else "None (both providers failed)"
    logger.info(
        f"\n{'='*60}\n"
        f"🏁 ALL DONE: {domain}\n"
        f"   AI Provider : {ai_provider}\n"
        f"   AI Findings : {len(enriched_issues)} enriched issues\n"
        f"   Reports     : {report_file}\n"
        f"              : {portal_file}\n"
        f"{'='*60}"
    )
    logger.info("✅ Portal JSON saved — scan complete")


if __name__ == "__main__":
    main()