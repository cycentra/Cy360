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

from modules.vuln_scanner import gather_vuln_scanner
from modules.debug_crypto import audit_crypto_deep
from modules.nuclei_scanner import gather_nuclei_scanner

# --- ENRICHMENT IMPORTS ---
from google import genai
from google.genai import types

logger = setup_logging()

# ─────────────────────────────────────────────────────────────────────────────
# SCAN PROFILES
# Each profile controls which sequential modules run and whether AI enrichment
# is executed at the end. DNS Reconnaissance is always run as a baseline.
# ─────────────────────────────────────────────────────────────────────────────
SCAN_PROFILES = {
    "passive": {
        "run_subdomains":   False,
        "modules":          ["email_sec", "whois", "osint", "dark_web"],
        "run_vuln_scanner": False,
        "ai_enrichment":    False,
    },
    "standard": {
        "run_subdomains":   True,
        "modules":          ["web", "crypto", "email_sec", "cloud", "whois", "osint"],
        "run_vuln_scanner": True,
        "ai_enrichment":    False,
    },
    "deep": {
        "run_subdomains":   True,
        "modules":          [
            "web", "crypto", "email_sec", "cloud", "whois", "osint",
            "dark_web", "supply_chain", "social_eng", "mobile_api",
        ],
        "run_vuln_scanner": True,
        "ai_enrichment":    True,
    },
}

# Fallback when an unrecognised scan_type is supplied
_DEFAULT_SCAN_TYPE = "standard"


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
    return os.environ.get("GOOGLE_GEMINI_KEY", "")


def _get_misp_config() -> dict | None:
    """
    Return resolved MISP connection config based on the current mode
    (disabled / cloud / local).  Delegates to core.helpers.get_misp_config()
    which is the single source of truth for all modules.
    """
    try:
        from core.helpers import get_misp_config
        return get_misp_config()
    except Exception as e:
        logger.warning(f"⚠️ [MISP] Could not load MISP config: {e}")
        return None


async def lookup_misp_iocs(ips: list) -> dict:
    """
    Query MISP for each IP. Returns {ip: [attribute_dicts]} for hits only.
    Never raises — always returns a (possibly empty) dict so the scan is never blocked.
    """
    config = _get_misp_config()
    if not config:
        # _get_misp_config() already logs the reason — no duplicate warning here
        return {}
    if not ips:
        logger.debug("[MISP] No IPs to look up — skipping IOC query.")
        return {}

    unique_ips = list(dict.fromkeys(str(ip) for ip in ips if ip))
    results_map: dict = {}
    headers = {
        "Authorization": config["apiKey"],
        "Accept":        "application/json",
        "Content-Type":  "application/json",
    }
    try:
        timeout_cfg = httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)
        async with httpx.AsyncClient(timeout=timeout_cfg, verify=False) as client:
            for ip in unique_ips:
                try:
                    resp = await client.post(
                        f"{config['url']}/attributes/restSearch",
                        headers=headers,
                        json={"returnFormat": "json", "value": ip,
                              "type": "ip-src", "to_ids": 1, "limit": 5},
                    )
                    resp.raise_for_status()
                    attrs = resp.json().get("response", {}).get("Attribute", [])
                    if attrs:
                        results_map[ip] = attrs
                        logger.info(f"🔴 [MISP] IOC hit for {ip} — {len(attrs)} attribute(s).")
                    else:
                        logger.debug(f"[MISP] No hits for {ip}.")
                except Exception as ip_err:
                    logger.warning(f"⚠️ [MISP] Lookup failed for {ip}: {ip_err}")
    except Exception as e:
        logger.warning(f"⚠️ [MISP] Client setup failed: {e}")
    return results_map


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
        missing = []
        if not url:     missing.append("baseUrl (Server URL)")
        if not api_key: missing.append("apiKey")
        logger.warning(f"⚠️ [CyMind] Provider set to cymind but missing: {', '.join(missing)}. Configure these in System Settings → AI Config.")
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


def _get_cymind_memory_config() -> tuple[str, str] | None:
    """
    Return (base_url, api_key) for CyMind episodic memory storage,
    regardless of which LLM provider is currently active.
    Priority: dedicated 'cymind_memory' block → active cymind provider fields.
    """
    settings = _load_ai_settings()
    cm = settings.get("cymind_memory") or {}
    url = cm.get("baseUrl", "").strip()
    key = cm.get("apiKey",  "").strip()
    if url and key:
        return url.rstrip("/"), key
    # Fall back: only if CyMind is the active provider
    config = _get_cymind_config()
    if config:
        return config[0], config[1]
    return None


async def store_to_cymind_memory(findings: list, domain: str, provider: str) -> None:
    """
    Store completed ASM scan findings into CyMind's episodic memory
    so analysts can query them from the CyMind chat window.
    Each finding becomes a separate incident record in soc-episodic-memory.
    Fire-and-forget — never blocks the scan result from being saved.
    """
    config = _get_cymind_memory_config()
    if config is None:
        return   # CyMind memory not configured — skip silently

    base_url, api_key = config
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).isoformat()

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)) as client:
            for i, finding in enumerate(findings):
                severity_raw = str(finding.get("severity", "medium")).lower()
                severity = severity_raw if severity_raw in ("low", "medium", "high", "critical") else "medium"
                incident_id = f"ASM-{domain}-{finding.get('module', 'UNKNOWN')}-{i}".upper()[:60]

                payload = {
                    "incident_id":   incident_id,
                    "alert_type":    finding.get("vulnerability", finding.get("module", "ASM Finding")),
                    "severity":      severity,
                    "source_ip":     domain,
                    "description":   finding.get("description", ""),
                    "analyst_notes": finding.get("recommendation", ""),
                    "outcome":       "open",
                    "resolution":    None,
                    "tags":          ["asm", domain, finding.get("module", "").lower(), provider.lower()],
                    "ttps":          [],
                    "timestamp":     ts,
                }
                try:
                    resp = await client.post(
                        f"{base_url}/api/v1/rag/memory/incident",
                        headers=headers,
                        json=payload,
                    )
                    if resp.status_code in (200, 201):
                        body = resp.json()
                        if body.get("stored", True):
                            logger.info(f"🧠 [CyMind Memory] Stored: {incident_id}")
                        else:
                            # Embedding service unavailable on CyMind — run: ollama pull nomic-embed-text
                            logger.warning(
                                f"⚠️ [CyMind Memory] {incident_id} — embedding unavailable "
                                f"({body.get('reason','unknown')}). "
                                f"Fix: ollama pull nomic-embed-text on the CyMind server."
                            )
                    else:
                        logger.warning(f"⚠️ [CyMind Memory] {incident_id} → HTTP {resp.status_code}")
                except Exception as e:
                    logger.warning(f"⚠️ [CyMind Memory] Failed to store {incident_id}: {e}")
    except Exception as e:
        logger.warning(f"⚠️ [CyMind Memory] store_to_cymind_memory failed: {e}")


async def enrich_findings_with_ai(full_results: Dict[str, Any], domain: str) -> tuple[List[Dict[str, Any]], str]:
    """Tries CyMind first, then Google Gemini, then local Ollama. Returns (findings, provider_name)."""

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
        await store_to_cymind_memory(cymind_result, domain, "CyMind")
        return cymind_result, "CyMind"

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
        await store_to_cymind_memory(result, domain, "Gemini")
        return result, "Gemini (gemini-2.0-flash)"

    except Exception as gemini_err:
        logger.warning(f"⚠️ [AI] Gemini failed: {type(gemini_err).__name__}: {gemini_err}")
        _, ollama_model = _get_ollama_config()
        logger.info(f"🔄 [AI] Falling back to Ollama ({ollama_model}) for {domain}...")

    # ── ATTEMPT 3: Ollama (trimmed payload + extended timeout) ────────────────
    ollama_url, ollama_model = _get_ollama_config()
    resolved_model = await resolve_ollama_model(ollama_model)

    if resolved_model is None:
        logger.error("❌ [AI] Ollama unavailable or model missing. Returning empty.")
        return [], "None (all providers failed)"

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
        await store_to_cymind_memory(result, domain, f"Ollama ({resolved_model})")
        return result, f"Ollama ({resolved_model})"

    except json.JSONDecodeError as e:
        logger.error(f"❌ [AI] Ollama returned malformed JSON: {e}\nRaw: {full_response[:500]}")
    except Exception as ollama_err:
        logger.error(
            f"❌ [AI] Ollama fallback failed: {type(ollama_err).__name__}: {ollama_err}\n"
            f"{traceback.format_exc()}"
        )

    # ── ALL PROVIDERS EXHAUSTED (CyMind → Gemini → Ollama) ───────────────────
    logger.error(f"❌ [AI] All enrichment providers exhausted for {domain}. Returning empty.")
    return [], "None (all providers exhausted)"


async def run_full_scan(
    domain: str,
    tenant_id: str,
    scan_type: str = "standard",
    include_subdomains: bool = True,
) -> Dict[str, Any]:
    profile    = SCAN_PROFILES.get(scan_type, SCAN_PROFILES[_DEFAULT_SCAN_TYPE])
    scan_start = datetime.now()
    logger.info(
        f"=== Starting CyCentra {scan_type.upper()} Scan for {domain} "
        f"(Tenant: {tenant_id}, subdomains={'on' if include_subdomains else 'off'}) ==="
    )

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
        "nuclei":       "Nuclei Template Scan",
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

    results      = {}
    all_issues    = []   # complete issue list — used for counts, NDJSON, summary log
    portal_issues = []   # subset for portal JSON fallback: excludes vuln_scanner/nuclei
                         # (those modules surface via rich findings, not issue strings)

    # ── Stage 1: DNS (always runs — baseline for all scan types) ─────────────
    _start("dns")
    dns = await gather_dns_intel(domain)
    _done("dns", dns)
    results["dns"] = dns

    dns_records = dns.get("results", {}).get("records", {}) if isinstance(dns, dict) else {}
    dns_ips     = dns.get("results", {}).get("ips", [])     if isinstance(dns, dict) else []

    # ── Stage 2: Subdomains (skipped for passive scan) ────────────────────────
    subdomain_entries = []
    subdomains_list   = []

    if profile["run_subdomains"] and include_subdomains:
        _start("subdomains")
        subs = await gather_subdomains(domain)
        _done("subdomains", subs)

        subdomain_entries = subs.get("results", []) if isinstance(subs, dict) else []
        prev_state        = _load_subdomain_state(tenant_id, domain)
        subdomain_entries = _annotate_subdomains(subdomain_entries, prev_state)
        if isinstance(subs, dict):
            subs["results"] = subdomain_entries
        results["subdomains"] = subs
        subdomains_list = [
            e["subdomain"] if isinstance(e, dict) else e
            for e in subdomain_entries
        ]
    else:
        reason = "profile" if not profile["run_subdomains"] else "user preference"
        logger.info(f"⏭️  [Subdomain Enumeration] Skipped — {reason}.")
        results["subdomains"] = {"skipped": True, "results": [], "issues": []}

    # ── Stage 3: Profile-filtered sequential modules ──────────────────────────
    # Master registry — only modules listed in the active profile will run.
    _all_sequential = [
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
    active_keys        = set(profile["modules"])
    sequential_modules = [(k, fn) for k, fn in _all_sequential if k in active_keys]

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
                portal_issues.extend(res["issues"])  # sequential module issues feed portal fallback

    # ── Post-sequential enrichment ──────────────────────────────────────────
    # vuln_scanner needs web results so runs after the sequential loop
    if profile.get("run_vuln_scanner"):
        _start("vuln_scanner")
        try:
            vuln_res = await gather_vuln_scanner(
                domain,
                web_results=results.get("web"),
            )
        except Exception as exc:
            vuln_res = {"error": str(exc), "results": {}, "issues": []}
        _done("vuln_scanner", vuln_res)
        results["vuln_scanner"] = vuln_res
        if isinstance(vuln_res, dict) and "issues" in vuln_res:
            # Add to all_issues for count/NDJSON/log accuracy.
            # Do NOT add to portal_issues — these are string summaries of
            # vuln_scanner.results.findings; the rich findings are used directly
            # in the portal JSON fallback to avoid duplication.
            all_issues.extend(vuln_res["issues"])

    if profile.get("run_vuln_scanner"):
        _start("crypto_deep")
        try:
            crypto_deep_res = await audit_crypto_deep(domain)
        except Exception as exc:
            crypto_deep_res = {"error": str(exc), "results": {}, "issues": []}
        _done("crypto_deep", crypto_deep_res)
        results["crypto_deep"] = crypto_deep_res
        if isinstance(crypto_deep_res, dict) and "issues" in crypto_deep_res:
            all_issues.extend(crypto_deep_res["issues"])
            portal_issues.extend(crypto_deep_res["issues"])  # no rich findings — only issue strings

    if profile.get("run_vuln_scanner"):
        logger.info("[Nuclei Scanner] Starting...")
        try:
            nuclei_res = await gather_nuclei_scanner(domain)
        except Exception as exc:
            nuclei_res = {"error": str(exc), "results": {}, "issues": []}
        logger.info("📥 [Nuclei Scanner] Complete.")
        results["nuclei"] = nuclei_res
        if isinstance(nuclei_res, dict) and "issues" in nuclei_res:
            # Same as vuln_scanner: count/NDJSON only — rich findings handle portal JSON.
            all_issues.extend(nuclei_res["issues"])

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
        "scan_type":          scan_type,
        "summary":            summary_text,
        "total_subdomains":   len(subdomains_list),
        "live_subdomains":    live_count,
        "historical_subdomains": len(subdomains_list) - live_count,
        "new_subdomains":     new_count,
        "total_issues":       len(all_issues),     # full count inc. vuln_scanner/nuclei
        "tenant_id":          tenant_id,
        "results":            results,
        "all_issues":         all_issues,          # full list for NDJSON/Wazuh
        "portal_issues":      portal_issues,       # dedup-safe subset for portal JSON fallback
    }


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 cycentra_scan.py <domain> <tenant_id> [scan_type]")
        sys.exit(1)

    domain    = sys.argv[1].strip().lower()
    raw_tenant = sys.argv[2].strip().lower()
    scan_type = sys.argv[3].strip().lower() if len(sys.argv) >= 4 else _DEFAULT_SCAN_TYPE

    # Guard: reject unknown scan types so misconfigured callers fail loudly
    if scan_type not in SCAN_PROFILES:
        logger.warning(f"⚠️  Unknown scan_type '{scan_type}' — falling back to '{_DEFAULT_SCAN_TYPE}'.")
        scan_type = _DEFAULT_SCAN_TYPE

    final_tenant_id = validate_tenant(raw_tenant)

    # Read include_subdomains from env var (set by scanner.py) or default True
    include_subdomains = os.environ.get("CYCENTRA_INCLUDE_SUBDOMAINS", "true").strip().lower() != "false"

    # Execute Scan
    result = asyncio.run(run_full_scan(domain, final_tenant_id, scan_type, include_subdomains))

    # ── Persist subdomain state for next scan comparison ─────────────────────
    enriched_sub_entries = result["results"].get("subdomains", {}).get("results", [])
    _save_subdomain_state(final_tenant_id, domain, enriched_sub_entries)

    # ── MISP IOC Lookup (runs BEFORE AI enrichment, never blocks scan) ────────
    _all_scan_ips: list = []
    _all_scan_ips += result["results"].get("dns", {}).get("results", {}).get("ips", [])
    for _sub in enriched_sub_entries:
        if isinstance(_sub, dict):
            _all_scan_ips += _sub.get("resolved_ips", [])
    misp_hit_map: dict = {}
    if _all_scan_ips:
        try:
            misp_hit_map = asyncio.run(lookup_misp_iocs(_all_scan_ips))
            if misp_hit_map:
                logger.info(f"🔴 [MISP] {len(misp_hit_map)} IOC hit(s) across {len(_all_scan_ips)} IPs for {domain}.")
            else:
                logger.info(f"✅ [MISP] No IOC hits for {len(_all_scan_ips)} IPs for {domain}.")
        except Exception as _misp_err:
            logger.warning(f"⚠️ [MISP] Lookup block failed (scan continues): {_misp_err}")
    else:
        logger.debug(f"[MISP] No IPs collected from DNS/subdomains for {domain} — IOC lookup skipped.")
    # ─────────────────────────────────────────────────────────────────────────

    # AI Enrichment — only for Deep scan; skipped for Standard and Passive
    profile = SCAN_PROFILES[scan_type]
    if profile["ai_enrichment"]:
        logger.info(f"🤖 Starting AI enrichment for {domain}...")
        enriched_issues, ai_provider_used = asyncio.run(enrich_findings_with_ai(result['results'], domain))
    else:
        logger.info(f"⏭️  AI enrichment skipped — {scan_type} scan profile.")
        enriched_issues, ai_provider_used = [], f"Skipped ({scan_type} scan)"
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
        # portal_issues excludes vuln_scanner/nuclei issue strings (covered by rich findings).
        # Falls back to all_issues only when portal_issues is absent (shouldn't happen).
        all_findings = result.get('portal_issues') or result.get('all_issues', [])
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

        # Use AI findings when available; fall back to rich scanner findings +
        # deduplicated module issue strings.
        if enriched_issues:
            final_vulns = enriched_issues
        else:
            # 1. Rich findings from vuln_scanner and nuclei are the source of truth
            #    for those modules (proper CVSSv3 scores, compliance tags, etc.).
            vs_rich  = results.get("vuln_scanner", {}).get("results", {}).get("findings", [])
            nuc_rich = results.get("nuclei",       {}).get("results", {}).get("findings", [])

            # 2. Deduplicate remaining module issue strings (handles e.g. the
            #    "SAN mismatch" string emitted by both web and crypto modules).
            seen_issue_keys: set = set()
            deduped_module_issues: list = []
            for issue in all_findings:
                key = (
                    str(issue) if not isinstance(issue, dict)
                    else issue.get("description", str(issue))
                ).strip().lower()
                if key not in seen_issue_keys:
                    seen_issue_keys.add(key)
                    deduped_module_issues.append(_normalise_issue(issue))

            final_vulns = vs_rich + nuc_rich + deduped_module_issues

        # Attach MISP IOC hits to findings whose description contains a known hit IP
        if misp_hit_map:
            for _finding in final_vulns:
                _text = (_finding.get("description", "") + " " +
                         _finding.get("vulnerability", "") + " " +
                         _finding.get("recommendation", ""))
                _matched = [hit for ip, hits in misp_hit_map.items()
                            if ip in _text for hit in hits]
                if _matched:
                    _finding["misp_hits"] = _matched

            # For findings without a direct IP match, attach a summary threat intel note
            # so the AI narrative and portal always knows about MISP hits during the scan
            hit_summary = [{"ip": ip, "count": len(hits), "event_ids": [h.get("event_id") for h in hits]}
                           for ip, hits in misp_hit_map.items()]
            for _finding in final_vulns:
                if "misp_hits" not in _finding:
                    _finding["misp_threat_intel"] = hit_summary

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
                "scan_type":           scan_type,
                "include_subdomains":  include_subdomains,
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

        # ── Generate PDF Reports (Executive + Technical) ─────────────────────
        try:
            from reporting.generate_reports import hook_into_scan
            hook_into_scan(portal_payload, final_tenant_id, domain, timestamp)
        except Exception as _rpt_err:
            logger.warning(f"⚠️ [Reports] PDF generation failed (scan unaffected): {_rpt_err}")

    except Exception as e:
        logger.error(f"❌ Failed to save portal JSON: {e}")

    # --- FINAL SUMMARY ---
    logger.info(
        f"\n{'='*60}\n"
        f"🏁 ALL DONE: {domain}\n"
        f"   Scan Type   : {scan_type.upper()}\n"
        f"   AI Provider : {ai_provider_used}\n"
        f"   AI Findings : {len(enriched_issues)} enriched issues\n"
        f"   Reports     : {report_file}\n"
        f"              : {portal_file}\n"
        f"   PDF Reports : /var/log/cycentra/cy-asm/reports/{final_tenant_id}/\n"
        f"{'='*60}"
    )
    logger.info("✅ Portal JSON saved — scan complete")


if __name__ == "__main__":
    main()