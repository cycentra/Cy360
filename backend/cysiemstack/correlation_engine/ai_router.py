"""
ai_router.py
Universal LLM caller for the CySIEM correlation engine.

Reads provider/credentials from /opt/cycentra/ai_settings.json — the same
file written by the AI Settings page in the Cycentra portal.
No separate env vars needed: whichever provider is configured in the UI
is automatically used here.

Supported providers (matching portal aiProviders.js):
  cymind    — CyMind on-prem AI  (POST /api/v1/chat, Bearer pak_...)
  local     — Ollama             (POST /api/generate)
  anthropic — Claude             (POST api.anthropic.com/v1/messages)
  gemini    — Google Gemini      (POST generativelanguage.googleapis.com)
  deepseek  — DeepSeek           (OpenAI-compat POST api.deepseek.com)

Falls back to local Ollama on localhost:11434 if no settings file exists.
"""
import json
import os
from pathlib import Path
import httpx
import structlog

log = structlog.get_logger()

_AI_SETTINGS_FILE = Path("/opt/cycentra/ai_settings.json")

# Last-resort fallback when no settings file exists
_FALLBACK_OLLAMA_URL   = "http://127.0.0.1:11434"
_FALLBACK_OLLAMA_MODEL = "llama3.1:8b"


def _load() -> dict:
    """Read ai_settings.json. Returns {} on any failure — never raises."""
    try:
        if _AI_SETTINGS_FILE.exists():
            return json.loads(_AI_SETTINGS_FILE.read_text())
    except Exception as e:
        log.warning("ai_settings_load_error", path=str(_AI_SETTINGS_FILE), error=str(e))
    return {}


# ── Provider-specific callers ──────────────────────────────────────────────────

async def _cymind(fields: dict, system: str, prompt: str, timeout: float) -> str:
    base_url = fields.get("baseUrl", "").rstrip("/")
    api_key  = fields.get("apiKey", "")
    model    = fields.get("model", "").strip()

    if not base_url or not api_key:
        raise RuntimeError("CyMind: baseUrl and apiKey are required but not configured in AI Settings")

    # Place all incident/enrichment context in the system prompt.
    # CyMind's prompt-injection check (SEC-24) runs only on the user message
    # (req.messages[-1]["content"]).  Raw SIEM data — IP addresses, attack
    # commands, rule descriptions — can false-positive on patterns like
    # "jailbreak", "bypass content filter", or base64-decoded payloads (GAP-005).
    # Keeping the user message as a short, benign instruction avoids those
    # false positives while still giving the LLM all necessary context.
    combined_system = f"{system}\n\n---\nINCIDENT CONTEXT:\n{prompt}"
    user_instruction = (
        "Analyse the incident in the INCIDENT CONTEXT section above and "
        "return ANALYST_SUMMARY and REMEDIATION_STEPS."
    )

    body: dict = {
        "messages":         [{"role": "user", "content": user_instruction}],
        "system":           combined_system,
        "use_rag":          False,
        "use_external":     False,
        "use_mcp":          False,
        "use_integrations": False,
        "use_operational":  False,
        "temperature":      0.1,
    }
    if model:
        body["model"] = model

    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=timeout,
    ) as client:
        resp = await client.post(f"{base_url}/api/v1/chat", json=body)
        if not resp.is_success:
            # Surface the CyMind error detail for easier debugging
            try:
                detail = resp.json().get("detail", resp.text[:200])
            except Exception:
                detail = resp.text[:200]
            raise RuntimeError(
                f"CyMind returned HTTP {resp.status_code}: {detail}"
            )
        return resp.json().get("content", "")


async def _ollama(fields: dict, system: str, prompt: str, timeout: float) -> str:
    base_url = (fields.get("baseUrl") or _FALLBACK_OLLAMA_URL).rstrip("/")
    model    = (fields.get("model")   or _FALLBACK_OLLAMA_MODEL).strip()

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(f"{base_url}/api/generate", json={
            "model":   model,
            "prompt":  prompt,
            "system":  system,
            "stream":  False,
            "options": {"temperature": 0.1, "num_predict": 600},
        })
        resp.raise_for_status()
        return resp.json().get("response", "")


async def _anthropic(fields: dict, system: str, prompt: str, timeout: float) -> str:
    api_key = fields.get("apiKey", "")
    model   = fields.get("model") or "claude-haiku-4-5-20251001"

    if not api_key:
        raise RuntimeError("Anthropic: apiKey not configured in AI Settings")

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
            json={
                "model":      model,
                "max_tokens": 1024,
                "system":     system,
                "messages":   [{"role": "user", "content": prompt}],
            },
        )
        resp.raise_for_status()
        blocks = resp.json().get("content", [])
        return " ".join(b.get("text", "") for b in blocks if b.get("type") == "text")


async def _gemini(fields: dict, system: str, prompt: str, timeout: float) -> str:
    api_key = fields.get("apiKey", "")
    model   = fields.get("model") or "gemini-1.5-flash"

    if not api_key:
        raise RuntimeError("Gemini: apiKey not configured in AI Settings")

    full_prompt = f"{system}\n\n{prompt}"
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}",
            json={"contents": [{"parts": [{"text": full_prompt}]}]},
        )
        resp.raise_for_status()
        candidates = resp.json().get("candidates", [])
        if not candidates:
            return ""
        return candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")


async def _openai_compat(endpoint: str, fields: dict, system: str, prompt: str, timeout: float) -> str:
    api_key = fields.get("apiKey", "")
    model   = fields.get("model", "")

    if not api_key:
        raise RuntimeError(f"OpenAI-compat ({endpoint}): apiKey not configured in AI Settings")

    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        timeout=timeout,
    ) as client:
        body: dict = {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": prompt},
            ],
            "max_tokens": 1024,
            "temperature": 0.1,
        }
        if model:
            body["model"] = model
        resp = await client.post(endpoint, json=body)
        resp.raise_for_status()
        choices = resp.json().get("choices", [])
        if not choices:
            return ""
        return choices[0].get("message", {}).get("content", "")


# ── Public entry point ─────────────────────────────────────────────────────────

async def call_llm(system: str, user_prompt: str, timeout: float = 90.0) -> str:
    """
    Dispatch to the AI provider configured in the portal's AI Settings page.
    Reads /opt/cycentra/ai_settings.json at call time — no restart needed
    when the provider is changed in the UI.

    Returns the response text on success.
    Raises RuntimeError if the provider call fails.
    """
    cfg      = _load()
    provider = cfg.get("provider", "local")
    fields   = cfg.get("fields",   {})

    log.debug("ai_router_dispatch", provider=provider)

    if provider == "cymind":
        # Vault-injected env vars take precedence over ai_settings.json fields
        if os.environ.get("CYMIND_API_URL"):
            fields = {**fields, "baseUrl": os.environ["CYMIND_API_URL"]}
        if os.environ.get("CYMIND_API_KEY"):
            fields = {**fields, "apiKey": os.environ["CYMIND_API_KEY"]}
        return await _cymind(fields, system, user_prompt, timeout)
    elif provider == "local":
        return await _ollama(fields, system, user_prompt, timeout)
    elif provider == "anthropic":
        return await _anthropic(fields, system, user_prompt, timeout)
    elif provider == "gemini":
        return await _gemini(fields, system, user_prompt, timeout)
    elif provider == "deepseek":
        return await _openai_compat(
            "https://api.deepseek.com/v1/chat/completions",
            fields, system, user_prompt, timeout,
        )
    else:
        log.warning("ai_router_unrecognised_provider", provider=provider)
        return await _ollama({}, system, user_prompt, timeout)
