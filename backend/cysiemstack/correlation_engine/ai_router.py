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

    body: dict = {
        "messages":     [{"role": "user", "content": prompt}],
        "system":       system,
        "use_rag":      False,
        "use_external": False,
        "temperature":  0.1,
    }
    if model:
        body["model"] = model

    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=timeout,
    ) as client:
        resp = await client.post(f"{base_url}/api/v1/chat", json=body)
        resp.raise_for_status()
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
