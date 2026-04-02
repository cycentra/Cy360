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

# --- AI SETTINGS: dynamic read from /opt/cycentra/ai_settings.json ---
_AI_SETTINGS_FILE = Path("/opt/cycentra/ai_settings.json")

# Hardcoded fallbacks (used when no settings file exists)
_FALLBACK_OLLAMA_URL   = "http://116.203.115.95:11434"
_FALLBACK_OLLAMA_MODEL = "mranv/siem-llama-3.1:v1"


def _load_ai_settings() -> dict:
    """Load AI settings persisted by the UI. Returns empty dict on any failure."""
    try:
        if _AI_SETTINGS_FILE.exists():
            return json.loads(_AI_SETTINGS_FILE.read_text())
    except Exception as e:
        logger.warning(f"⚠️ [AI] Could not load ai_settings.json: {e}")
    return {}


def _get_ollama_config() -> tuple[str, str]:
    """Return (base_url, model) from saved settings or fallback defaults."""
    settings = _load_ai_settings()
    fields   = settings.get("fields", {})
    url      = fields.get("baseUrl", "").strip() or _FALLBACK_OLLAMA_URL
    model    = fields.get("model",   "").strip() or _FALLBACK_OLLAMA_MODEL
    return url, model


def _get_gemini_key() -> str:
    """Return Gemini API key from saved settings or env/config fallback."""
    settings = _load_ai_settings()
    provider = settings.get("provider", "")
    if provider == "gemini":
        key = settings.get("fields", {}).get("apiKey", "").strip()
        if key:
            return key
    return GOOGLE_GEMINI_KEY


def _get_cymind_config() -> tuple[str, str, str] | None:
    """
    Return (base_url, api_key, model) if provider=cymind is configured.
    Returns None if CyMind is not the selected provider or config is incomplete.
    """
    settings = _load_ai_settings()
    if settings.get("provider") != "cymind":
        return None
    fields  = settings.get("fields", {})
    url     = fields.get("baseUrl", "").strip()
    api_key = fields.get("apiKey",  "").strip()
    model   = fields.get("model",   "").strip() or "mistral:7b"
    if not url or not api_key:
        logger.warning("⚠️ [CyMind] Provider set to cymind but baseUrl or apiKey is missing.")
        return None
    return url.rstrip("/"), api_key, model


async def enrich_with_cymind(
    context_payload: dict,
    domain: str,
    prompt: str,
) -> list | None:
    """
    Call CyMind's authenticated /api/v1/chat endpoint for ASM enrichment.
    Returns parsed JSON list on success, None on failure.

    CyMind API contract (from cymind/api/routers/chat.py):
      POST /api/v1/chat
      Authorization: Bearer <pak_...>
      Body: { messages, model, use_rag, system }
    """
    config = _get_cymind_config()
    if config is None:
        return None

    base_url, api_key, model = config
    logger.info(f"🧠 [CyMind] Sending ASM enrichment request for {domain} (model: {model})...")

    # Override CyMind's default system prompt (which uses markdown) with a strict
    # JSON-only instruction so the LLM never wraps output in markdown fences.
    _CYMIND_ASM_SYSTEM = (
        "You are a security analysis engine. "
        "You MUST respond with ONLY a valid raw JSON array — no markdown, no code fences, "
        "no explanation, no preamble, no trailing text. "
        "Output starts with '[' and ends with ']'. Nothing else."
    )

    payload = {
        "messages":     [{"role": "user", "content": prompt}],
        "system":       _CYMIND_ASM_SYSTEM,
        "model":        model,
        "use_rag":      False,   # ASM enrichment uses direct scan data, not RAG docs
        "use_external": False,   # Stay on-premise — do not relay to external AI
        "temperature":  0.2,     # Lowest practical temp for deterministic structured output
    }

    try:
        timeout_config = httpx.Timeout(connect=10.0, read=120.0, write=30.0, pool=10.0)
        async with httpx.AsyncClient(timeout=timeout_config) as client:
            resp = await client.post(
                f"{base_url}/api/v1/chat",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type":  "application/json",
                },
                json=payload,
            )
            resp.raise_for_status()
            data    = resp.json()
            content = data.get("content", "")
            # Robustly extract the first JSON array from the response.
            # Uses regex to find the outermost [...] block, handling cases where
            # the LLM wraps output in markdown fences or adds trailing commentary.
            import re as _re
            match = _re.search(r'\[.*\]', content, _re.DOTALL)
            if not match:
                logger.error(f"❌ [CyMind] No JSON array found in response. Raw: {content[:300]}")
                return None
            result = json.loads(match.group(0))
            if isinstance(result, list):
                logger.info(f"✅ [CyMind] Enrichment succeeded for {domain} — {len(result)} findings.")
                return result
            logger.warning(f"⚠️ [CyMind] Unexpected response shape (not a list): {str(result)[:200]}")
            return None
    except json.JSONDecodeError as e:
        logger.error(f"❌ [CyMind] Malformed JSON in response: {e}\nRaw snippet: {content[:300]}")
    except httpx.HTTPStatusError as e:
        logger.error(f"❌ [CyMind] HTTP {e.response.status_code}: {e.response.text[:300]}")
    except Exception as e:
        logger.error(f"❌ [CyMind] Request failed: {type(e).__name__}: {e}")
    return None


def _trim_payload(context_payload: dict, max_chars: int = 3000) -> dict:
    """Truncates the payload to avoid overwhelming smaller local models."""
    raw = json.dumps(context_payload)
    if len(raw) > max_chars:
        logger.warning(f"⚠️ [AI] Payload trimmed from {len(raw)} to {max_chars} chars for Ollama.")
        return {"truncated_data": raw[:max_chars] + "... [truncated]"}
    return context_payload


async def get_available_ollama_models() -> List[str]:
    """Fetches the list of pulled models from Ollama (URL read from ai_settings.json)."""
    ollama_url, _ = _get_ollama_config()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{ollama_url}/api/tags")
            response.raise_for_status()
            models = response.json().get("models", [])
            return [m["name"] for m in models]
    except Exception as e:
        logger.warning(f"⚠️ [Ollama] Could not reach Ollama at {ollama_url}: {e}")
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

    # ── ATTEMPT 1: CyMind (on-premise, authenticated, preferred) ─────────────
    cymind_result = await enrich_with_cymind(context_payload, domain, prompt)
    if cymind_result is not None:
        return cymind_result

    # ── ATTEMPT 2: Google Gemini ──────────────────────────────────────────────
    try:
        logger.info(f"🤖 [AI] Trying Google Gemini for {domain}...")
        gemini_key = _get_gemini_key()
        client = genai.Client(api_key=gemini_key)
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
        _, ollama_model = _get_ollama_config()
        logger.info(f"🔄 [AI] Falling back to Ollama ({ollama_model}) for {domain}...")

    # ── ATTEMPT 3: Ollama (trimmed payload + extended timeout) ────────────────
    ollama_url, ollama_model = _get_ollama_config()
    resolved_model = await resolve_ollama_model(ollama_model)

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
                f"{ollama_url}/api/generate",
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

    # ── ALL PROVIDERS EXHAUSTED (CyMind → Gemini → Ollama) ───────────────────
    logger.error(f"❌ [AI] All enrichment providers exhausted for {domain}. Returning empty.")
    return []


async def run_full_scan(domain: str, tenant_id: str) -> Dict[str, Any]:
    scan_start = datetime.now()
    logger.info(f"=== Starting CyCentra UNIVERSAL Scan for {domain} (Tenant: {tenant_id}) ===")

    # ── Progress labels must match app.py /api/scan/status module_keywords exactly ──
    # app.py matches on lowercase log lines like "[dns reconnaissance]"
    # So we log each module start in that format so progress % updates live.
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

    def _start(key: str):
        """Log module start in the format app.py /api/scan/status looks for."""
        label = _progress_labels.get(key, key)
        logger.info(f"[{label}] Starting...")

    def _done(key: str, res):
        label = _progress_labels.get(key, key)
        if isinstance(res, Exception):
            logger.error(f"❌ Module '{key}' CRASHED: {res}")
        else:
            logger.info(f"📥 [{label}] Complete.")

    results    = {}
    all_issues = []

    # ── Stage 1: DNS (everything else depends on it) ─────────────────────────
    _start("dns")
    dns = await gather_dns_intel(domain)
    _done("dns", dns)
    results["dns"] = dns

    # ── Stage 2: Subdomains (dark_web and web depend on subdomain list) ───────
    _start("subdomains")
    subs = await gather_subdomains(domain)
    _done("subdomains", subs)
    results["subdomains"] = subs
    subdomains_list = subs.get("results", []) if isinstance(subs, dict) else []

    dns_records = dns.get("results", {}).get("records", {}) if isinstance(dns, dict) else {}
    dns_ips     = dns.get("results", {}).get("ips", [])     if isinstance(dns, dict) else []

    # ── Stage 3: Sequential modules ──────────────────────────────────────────
    # Ordered by value/speed — fastest/highest-value first so the progress bar
    # moves steadily and the most important data arrives early.
    sequential_modules = [
        ("web",          lambda: gather_web_analysis(domain, dns_records)),
        ("crypto",       lambda: audit_crypto(domain)),
        ("email_sec",    lambda: gather_email_security(domain)),
        ("cloud",        lambda: gather_cloud_infra(domain, dns_ips)),
        ("whois",        lambda: gather_whois_history(domain)),
        ("osint",        lambda: gather_passive_osint(domain)),
        ("dark_web",     lambda: gather_dark_web(domain, subdomains_list)),
        ("supply_chain", lambda: gather_supply_chain(domain)),
        ("social_eng",   lambda: gather_social_eng(domain)),
        ("mobile_api",   lambda: gather_mobile_api(domain)),
    ]

    for key, coro_fn in sequential_modules:
        _start(key)
        try:
            res = await coro_fn()
        except Exception as exc:
            res = exc
        _done(key, res)

        if isinstance(res, Exception):
            results[key] = {"error": str(res), "results": {}, "issues": []}
        else:
            results[key] = res
            if isinstance(res, dict) and "issues" in res:
                all_issues.extend(res["issues"])

    # ── Summary ───────────────────────────────────────────────────────────────
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