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

# ── Subdomain state management ────────────────────────────────────────────────
# State files persist subdomain history across scans so new/disappeared
# subdomains can be highlighted. Location: /var/log/cycentra/cy-asm/state/
_STATE_BASE = Path("/var/log/cycentra/cy-asm/state")


def _load_subdomain_state(tenant_id: str, domain: str) -> dict:
    """Load previous subdomain state. Returns {} on first scan or any read error."""
    state_file = _STATE_BASE / tenant_id / f"{domain}_subdomains.json"
    try:
        if state_file.exists():
            return json.loads(state_file.read_text())
    except Exception as e:
        logger.warning(f"⚠️ [State] Could not load subdomain state: {e}")
    return {}


def _save_subdomain_state(tenant_id: str, domain: str, enriched_subs: list):
    """Persist current scan subdomain data for comparison on the next scan."""
    state_file = _STATE_BASE / tenant_id / f"{domain}_subdomains.json"
    state_file.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now().isoformat()

    # Preserve first_seen dates from previous state
    existing      = _load_subdomain_state(tenant_id, domain)
    existing_subs = existing.get("subdomains", {})

    updated: dict = {}
    for e in enriched_subs:
        sub  = e["subdomain"] if isinstance(e, dict) else e
        live = e.get("live", False) if isinstance(e, dict) else False
        ips  = e.get("resolved_ips", []) if isinstance(e, dict) else []
        prior = existing_subs.get(sub, {})
        updated[sub] = {
            "first_seen": prior.get("first_seen", now),
            "last_seen":  now,
            "last_live":  live,
            "last_ips":   ips,
        }

    state = {"domain": domain, "last_scan": now, "subdomains": updated}
    try:
        state_file.write_text(json.dumps(state, indent=2))
        logger.info(f"✅ [State] Subdomain state saved → {state_file}")
    except Exception as e:
        logger.error(f"❌ [State] Failed to save subdomain state: {e}")


def _annotate_subdomains(enriched_subs: list, prev_state: dict) -> list:
    """
    Compare current scan against previous state. Adds to each subdomain dict:
      is_new  (bool)  — True if this subdomain was never seen before
      change  (str)   — 'new' | 'appeared' | 'disappeared' | 'persisted' | 'first_scan'
    """
    prev_subs  = prev_state.get("subdomains", {})
    first_scan = not prev_subs  # no previous data at all

    annotated: list = []
    for e in enriched_subs:
        if not isinstance(e, dict):
            e = {"subdomain": e, "live": False, "resolved_ips": [], "cname": None, "sources": []}

        sub   = e["subdomain"]
        live  = e.get("live", False)
        prior = prev_subs.get(sub)

        if first_scan:
            change, is_new = "first_scan", False
        elif prior is None:
            change, is_new = "new", True
        elif live and not prior.get("last_live", False):
            change, is_new = "appeared", False
        elif not live and prior.get("last_live", False):
            change, is_new = "disappeared", False
        else:
            change, is_new = "persisted", False

        annotated.append({**e, "is_new": is_new, "change": change})
    return annotated
# ─────────────────────────────────────────────────────────────────────────────

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
    """Return (base_url, model) from saved settings or fallback defaults.
    Only reads fields when provider == 'local' — other providers (cymind,
    gemini, etc.) store different URLs/keys in the same fields dict and must
    never bleed into the Ollama fallback.
    """
    settings = _load_ai_settings()
    if settings.get("provider", "") == "local":
        fields = settings.get("fields", {})
        url    = fields.get("baseUrl", "").strip() or _FALLBACK_OLLAMA_URL
        model  = fields.get("model",   "").strip() or _FALLBACK_OLLAMA_MODEL
        return url, model
    # Non-local provider is active — always use the hardcoded Ollama fallback
    return _FALLBACK_OLLAMA_URL, _FALLBACK_OLLAMA_MODEL


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
    logger.info(f"[AI Enrichment] Starting...")
    cymind_result = await enrich_with_cymind(context_payload, domain, prompt)
    if cymind_result is not None:
        return cymind_result

    # ── ATTEMPT 2: Google Gemini ──────────────────────────────────────────────
    try:
        logger.info(f"🤖 [AI] Trying Google Gemini for {domain}...")
        gemini_key = _get_gemini_key()
        client = genai.Client(api_key=gemini_key)
        # 90-second hard timeout — prevents indefinite hang if the Gemini API
        # is slow or unresponsive, ensuring the portal JSON is always saved.
        response = await asyncio.wait_for(
            asyncio.to_thread(
                client.models.generate_content,
                model="gemini-2.0-flash",
                contents=prompt,
                config=types.GenerateContentConfig(response_mime_type="application/json"),
            ),
            timeout=90.0,
        )
        result = response.parsed if response.parsed else json.loads(response.text)
        if not isinstance(result, list):
            logger.warning(f"⚠️ [AI] Gemini returned non-list ({type(result).__name__}), discarding.")
            raise ValueError("Gemini response is not a JSON list")
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

    # Annotate with historical change status before storing in results
    subdomain_entries = subs.get("results", []) if isinstance(subs, dict) else []
    prev_state        = _load_subdomain_state(tenant_id, domain)
    subdomain_entries = _annotate_subdomains(subdomain_entries, prev_state)
    if isinstance(subs, dict):
        subs["results"] = subdomain_entries

    results["subdomains"] = subs

    # Extract plain strings for downstream modules (dark_web, etc.)
    # Use all subdomains (live + historical) so dark web check is exhaustive
    subdomains_list = [
        e["subdomain"] if isinstance(e, dict) else e
        for e in subdomain_entries
    ]

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
    live_count = sum(1 for e in subdomain_entries if isinstance(e, dict) and e.get("live"))
    new_count  = sum(1 for e in subdomain_entries if isinstance(e, dict) and e.get("is_new"))
    summary_text = (
        f"CyCentra scan complete | "
        f"{len(subdomains_list)} subdomains "
        f"({live_count} live, {len(subdomains_list) - live_count} historical"
        f"{f', {new_count} new' if new_count else ''}) | "
        f"{len(all_issues)} issues"
    )

    scan_end = datetime.now()
    duration = (scan_end - scan_start).seconds
    
    logger.info(
        f"\n{'='*60}\n"
        f"✅ SCAN COMPLETE: {domain}\n"
        f"   Tenant      : {tenant_id}\n"
        f"   Subdomains  : {len(subdomains_list)} total "
        f"({live_count} live, {len(subdomains_list) - live_count} historical, {new_count} new)\n"
        f"   Issues Found: {len(all_issues)}\n"
        f"   Duration    : {duration}s\n"
        f"   Finished At : {scan_end.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{'='*60}"
    )

    return {
        "domain":             domain,
        "summary":            summary_text,
        "total_subdomains":   len(subdomains_list),
        "live_subdomains":    live_count,
        "historical_subdomains": len(subdomains_list) - live_count,
        "new_subdomains":     new_count,
        "total_issues":       len(all_issues),
        "tenant_id":          tenant_id,
        "results":            results,
        "all_issues":         all_issues,
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

    # ── Persist subdomain state for next scan comparison ─────────────────────
    enriched_sub_entries = result["results"].get("subdomains", {}).get("results", [])
    _save_subdomain_state(final_tenant_id, domain, enriched_sub_entries)

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
    logger.info("[Portal JSON] Saving...")
    logger.info("💾 Saving portal JSON...")
    try:
        all_findings = result.get('all_issues', [])
        severity_map = {"Critical": 10, "High": 8, "Medium": 5, "Low": 2, "Informational": 1}

        # ── Normalise raw module issues into the same shape the UI adapter expects ──
        # Needed when AI enrichment fails (all providers exhausted) so the dashboard
        # still shows real findings rather than empty vulnerability widgets.
        def _normalise_issue(issue) -> dict:
            if isinstance(issue, dict):
                return {
                    "vulnerability":  issue.get("vulnerability", issue.get("type", "Unknown Finding")),
                    "severity":       issue.get("severity",      "Medium"),
                    "risk_score":     issue.get("risk_score",    5),
                    "description":    issue.get("description",   ""),
                    "recommendation": issue.get("recommendation",""),
                    "module":         issue.get("module",        "Scan"),
                }
            return {"vulnerability": str(issue), "severity": "Medium", "risk_score": 5,
                    "description": str(issue), "recommendation": "", "module": "Scan"}

        # Use AI findings when available; fall back to raw module issues
        final_vulns = enriched_issues if enriched_issues else [_normalise_issue(i) for i in all_findings]

        ai_score = max(
            [severity_map.get(i.get('severity'), 0) for i in final_vulns] + [len(all_findings)]
        )

        summary_text = (
            final_vulns[0]['description'][:100] + "..."
            if final_vulns else result['summary']
        )

        # Subdomain breakdown for portal display
        live_subs  = [e for e in enriched_sub_entries if isinstance(e, dict) and e.get("live")]
        hist_subs  = [e for e in enriched_sub_entries if isinstance(e, dict) and not e.get("live")]
        new_subs   = [e for e in enriched_sub_entries if isinstance(e, dict) and e.get("is_new")]

        portal_payload = {
            "meta": {
                "last_scan": datetime.now().isoformat(),
                "org":       final_tenant_id,
                "scan_id":   f"ASM-{timestamp}",
                "domain":    domain,
            },
            "subdomain_summary": {
                "total":      len(enriched_sub_entries),
                "live":       len(live_subs),
                "historical": len(hist_subs),
                "new":        len(new_subs),
            },
            "assets": [{
                "id":              f"{domain}-{timestamp}",
                "host":            domain,
                "risk_score":      ai_score,
                "summary":         summary_text,
                "vulnerabilities": final_vulns,
                "raw_results":     result['results'],
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