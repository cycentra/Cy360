"""
blueprints/system/routes.py
=============================
System-level endpoints.

Routes:
  GET  /health                   liveness check
  POST /api/ai/test              test external AI provider connectivity
  GET  /api/ai/settings          retrieve persisted AI settings
  POST /api/ai/settings          persist AI settings (provider/model/keys)
  GET  /api/system/misp-config   resolved MISP config (mode-aware, no secrets)
  GET  /api/config               debug — dump non-secret env config
  GET  /api/system/version         current version + last 5 release notes
  GET  /api/system/latest-version   query GitHub Releases API for latest published version (ghToken required)
  POST /api/system/update           trigger cycentra-setup.sh --update (GH_TOKEN read from server .env)
  POST /api/system/upgrade          trigger cycentra-setup.sh full install (major upgrade)
  GET  /api/system/env/<target>  read env file (global|cysiemstack|cysoar|cymisp|cysiem)
  PUT  /api/system/env/<target>  write env file
  GET  /api/system/license         current license status (type, days, customer, valid)
  POST /api/system/license/upload  upload a .lic file — validates and activates immediately
  GET  /api/system/mcp             MCP bridge status (enabled flag, endpoint URL, tool list)
  POST /api/system/mcp             toggle MCP_ENABLED in cysiemstack.env (admin only)
  GET  /api/system/o365config      read current Office 365 wodle config from ossec.conf
  POST /api/system/o365config      write O365 credentials into ossec.conf and restart wazuh-manager
"""

import os
import re
import json
import shutil
import stat
import subprocess
import threading
from datetime import date
from pathlib import Path

import requests as http_requests
from flask import Blueprint, request, jsonify, make_response, session, current_app

from core.helpers import add_cors_headers, get_misp_config, run as _run_cmd
from core.config import AI_SETTINGS_FILE

system_bp = Blueprint("system", __name__)

# ── Env file paths keyed by target name ──────────────────────────────────────
_ENV_FILE_MAP = {
    "global":      "/opt/cycentra/.env",
    "cysiemstack": "/opt/cycentra/cysiemstack.env",
    "cysoar":      "/opt/cycentra/modules/cysoar/.env",
    "cymisp":      "/opt/cycentra/modules/cymisp/.env",
}

# Keys that must never be returned or overwritten via the API (security)
_SECRET_KEYS = {
    "SECRET_KEY", "SESSION_SECRET",
    "DB_PASSWORD", "POSTGRES_PASSWORD", "REDIS_PASSWORD",
    "WAZUH_API_PASSWORD",
    "API_KEY", "CS_TOKEN",
    "GOOGLE_CLIENT_SECRET", "MICROSOFT_CLIENT_SECRET",
    "CYSOAR_OIDC_SECRET",
    "NODE_RED_CREDENTIAL_SECRET",
    "JWT_SECRET", "ADMIN_API_KEY", "SMTP_PASS",
    "INFISICAL_CLIENT_SECRET", "INFISICAL_CLIENT_ID", "INFISICAL_PROJECT_ID",
    "VT_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY",
}

# ── Preflight ─────────────────────────────────────────────────────────────────

@system_bp.route("/api/ai/test", methods=["OPTIONS"])
def ai_options():
    return add_cors_headers(make_response('', 204))


# ── Health check ──────────────────────────────────────────────────────────────

@system_bp.route("/health")
def health():
    return jsonify({
        "status":  "ok",
        "version": "4.3",
        "service": "cycentra360-backend",
    })


# ── AI provider connectivity test ─────────────────────────────────────────────

@system_bp.route("/api/ai/test", methods=["POST"])
def ai_test():
    data     = request.get_json() or {}
    provider = data.get("provider", "local")
    api_key  = data.get("apiKey", "")
    model    = data.get("model", "")
    base_url = data.get("baseUrl", "http://localhost:11434")

    try:
        if provider == "local":
            resp = http_requests.get(f"{base_url}/api/tags", timeout=5)
            if resp.ok:
                models = [m["name"] for m in resp.json().get("models", [])]
                return jsonify({"ok": True, "message": f"Ollama connected · {len(models)} models"})
            return jsonify({"ok": False, "error": f"Ollama returned {resp.status_code}"}), 400

        if not api_key:
            return jsonify({"ok": False, "error": "API key required"}), 400

        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        if provider == "cymind":
            # CyMind: validate API key via GET /api/v1/models (lightweight, no chat cost)
            if not api_key:
                return jsonify({"ok": False, "error": "CyMind API key (pak_...) is required"}), 400
            cymind_base = base_url.rstrip("/")
            resp = http_requests.get(
                f"{cymind_base}/api/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=10,
            )
            if resp.status_code == 401:
                return jsonify({"ok": False, "error": "Invalid CyMind API key"}), 400
            if not resp.ok:
                return jsonify({"ok": False, "error": f"CyMind returned {resp.status_code}"}), 400
            models_list = [m["id"] for m in resp.json().get("models", [])]
            return jsonify({"ok": True, "message": f"CyMind connected · {len(models_list)} models available"})

        elif provider == "anthropic":
            resp = http_requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={**headers, "anthropic-version": "2023-06-01", "x-api-key": api_key},
                json={"model": model or "claude-haiku-4-5-20251001", "max_tokens": 5,
                      "messages": [{"role": "user", "content": "ping"}]},
                timeout=15,
            )
        elif provider == "gemini":
            resp = http_requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model or 'gemini-1.5-flash'}:generateContent?key={api_key}",
                json={"contents": [{"parts": [{"text": "ping"}]}]},
                timeout=15,
            )
        elif provider in ("deepseek", "openai"):
            endpoint = "https://api.deepseek.com/v1/chat/completions" if provider == "deepseek" \
                       else "https://api.openai.com/v1/chat/completions"
            resp = http_requests.post(
                endpoint, headers=headers,
                json={"model": model, "max_tokens": 16,
                      "messages": [{"role": "user", "content": "ping"}]},
                timeout=15,
            )
        else:
            return jsonify({"ok": False, "error": f"Unknown provider: {provider}"}), 400

        if resp.status_code == 401:
            return jsonify({"ok": False, "error": "Invalid API key"}), 400
        if not resp.ok:
            return jsonify({"ok": False, "error": f"Provider returned {resp.status_code}"}), 400

        return jsonify({"ok": True, "message": f"Connected · {model}"})

    except http_requests.exceptions.ConnectionError:
        return jsonify({"ok": False, "error": "Cannot reach server"}), 400
    except http_requests.exceptions.Timeout:
        return jsonify({"ok": False, "error": "Connection timed out"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── AI settings persistence ────────────────────────────────────────────────────

def _sync_misp_to_siem_env(misp: dict) -> None:
    """Resolve the effective MISP config (based on mode) and write it into
    cysiemstack.env so the correlation engine picks it up without a manual
    env file edit.  Also handles CLOUD and DISABLED modes."""
    env_path = Path(_ENV_FILE_MAP["cysiemstack"])
    if not env_path.parent.exists():
        return  # Not installed yet — skip silently

    mode = misp.get("mode", "disabled")

    if mode == "cloud":
        # Cloud CyMISP — key from env var, falling back to stored misp.apiKey
        eff_url = os.environ.get("CLOUD_MISP_URL", "https://cymisp.cycentra.com").rstrip("/")
        eff_key = os.environ.get("CLOUD_MISP_API_KEY", "").strip() or misp.get("apiKey", "").strip()
        enabled = "true" if eff_key else "false"
    elif mode == "local":
        eff_url = misp.get("url", "").rstrip("/")
        eff_key = misp.get("apiKey", "")
        enabled = "true" if (eff_url and eff_key) else "false"
    else:  # disabled
        eff_url, eff_key, enabled = "", "", "false"

    updates = {
        "MISP_MODE":    mode,
        "MISP_ENABLED": enabled,
        "MISP_URL":     eff_url,
        "MISP_API_KEY": eff_key,
    }

    # Also write url + apiKey into ai_settings.json so benchmark can read them.
    # _sync_misp_to_siem_env() writes cysiemstack.env (for the engine process).
    # ai_settings.json is what the Flask benchmark blueprint reads.
    try:
        import json as _j
        _ai = pathlib.Path("/opt/cycentra/ai_settings.json")
        _d  = _j.loads(_ai.read_text()) if _ai.exists() else {}
        _d["misp"] = {
            "mode":   misp.get("mode", "disabled"),
            "url":    misp.get("url", ""),
            "apiKey": misp.get("apiKey", ""),
        }
        _ai.write_text(_j.dumps(_d, indent=4))
    except Exception as _e:
        log.warning("[system] MISP ai_settings sync failed: %s", _e)

    try:
        lines = env_path.read_text().splitlines() if env_path.exists() else []
    except Exception:
        lines = []

    # Update existing keys in-place; append any that are missing
    result, seen = [], set()
    for line in lines:
        key = line.split("=", 1)[0].strip()
        if key in updates:
            result.append(f'{key}={updates[key]}')
            seen.add(key)
        else:
            result.append(line)
    for k, v in updates.items():
        if k not in seen:
            result.append(f'{k}={v}')
    try:
        env_path.write_text("\n".join(result) + "\n")
    except Exception:
        pass  # Non-fatal — server may not have write permission in dev mode



def _sync_ti_to_siem_env(ti: dict) -> None:
    """Write TI API keys from ai_settings.json into cysiemstack.env so the
    correlation engine picks them up without a manual env edit."""
    env_path = Path(_ENV_FILE_MAP["cysiemstack"])
    if not env_path.parent.exists():
        return
    updates = {
        "VT_API_KEY":        ti.get("vtApiKey", ""),
        "ABUSEIPDB_API_KEY": ti.get("abuseipdbApiKey", ""),
        "GREYNOISE_API_KEY": ti.get("greynoiseApiKey", ""),
    }
    try:
        lines = env_path.read_text().splitlines() if env_path.exists() else []
    except Exception:
        lines = []
    result, seen = [], set()
    for line in lines:
        key = line.split("=", 1)[0].strip()
        if key in updates:
            result.append(f'{key}={updates[key]}')
            seen.add(key)
        else:
            result.append(line)
    for k, v in updates.items():
        if k not in seen:
            result.append(f'{k}={v}')
    try:
        env_path.write_text("\n".join(result) + "\n")
    except Exception:
        pass


@system_bp.route("/api/ai/settings", methods=["OPTIONS"])
def ai_settings_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/ai/settings", methods=["GET"])
def ai_settings_get():
    try:
        if AI_SETTINGS_FILE.exists():
            data = json.loads(AI_SETTINGS_FILE.read_text())
            # Strip stored API keys from response — return masked versions
            if "fields" in data and "apiKey" in data["fields"] and data["fields"]["apiKey"]:
                data["fields"]["apiKey"] = "••••••••"
            if "cymind_memory" in data and data["cymind_memory"].get("apiKey"):
                data["cymind_memory"]["apiKey"] = "••••••••"
            if "misp" in data and data["misp"].get("apiKey"):
                data["misp"]["apiKey"] = "••••••••"
            ti = data.get("threat_intel", {})
            for key_field in ("vtApiKey", "abuseipdbApiKey", "greynoiseApiKey"):
                if ti.get(key_field):
                    ti[key_field] = "••••••••"
            return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({})


@system_bp.route("/api/ai/settings", methods=["POST"])
def ai_settings_post():
    data = request.get_json() or {}
    # Only accept known top-level keys to prevent arbitrary data storage
    allowed = {"provider", "fields", "prompts", "cymind_memory", "misp", "system", "threat_intel"}
    payload = {k: v for k, v in data.items() if k in allowed}
    if not payload:
        return jsonify({"error": "No valid settings provided"}), 400
    try:
        # Merge with existing so a partial update doesn't wipe other keys
        existing = {}
        if AI_SETTINGS_FILE.exists():
            existing = json.loads(AI_SETTINGS_FILE.read_text())
        # Guard: never overwrite a stored API key with an empty string or the
        # masked placeholder "••••••••" that the GET endpoint returns.
        _MASK = "\u2022" * 8  # ••••••••
        incoming_fields = payload.get("fields", {})
        incoming_key    = incoming_fields.get("apiKey", "")
        if not incoming_key or incoming_key == _MASK:
            # Preserve whatever key is already on disk
            existing_key = existing.get("fields", {}).get("apiKey", "")
            if existing_key:
                payload.setdefault("fields", {})["apiKey"] = existing_key
        # Guard: never overwrite a stored baseUrl with an empty string
        incoming_url = incoming_fields.get("baseUrl", "")
        if not incoming_url:
            existing_url = existing.get("fields", {}).get("baseUrl", "")
            if existing_url:
                payload.setdefault("fields", {})["baseUrl"] = existing_url
        # Same guard for the separate cymind_memory block
        incoming_cm_key = payload.get("cymind_memory", {}).get("apiKey", "")
        if not incoming_cm_key or incoming_cm_key == _MASK:
            existing_cm_key = existing.get("cymind_memory", {}).get("apiKey", "")
            if existing_cm_key:
                payload.setdefault("cymind_memory", {})["apiKey"] = existing_cm_key
        # Same guard for the misp block
        incoming_misp_key = payload.get("misp", {}).get("apiKey", "")
        if not incoming_misp_key or incoming_misp_key == _MASK:
            existing_misp_key = existing.get("misp", {}).get("apiKey", "")
            if existing_misp_key:
                payload.setdefault("misp", {})["apiKey"] = existing_misp_key
        # Same guard for TI API keys
        for ti_field in ("vtApiKey", "abuseipdbApiKey", "greynoiseApiKey"):
            incoming_ti_key = payload.get("threat_intel", {}).get(ti_field, "")
            if not incoming_ti_key or incoming_ti_key == _MASK:
                existing_ti_key = existing.get("threat_intel", {}).get(ti_field, "")
                if existing_ti_key:
                    payload.setdefault("threat_intel", {})[ti_field] = existing_ti_key
        existing.update(payload)
        AI_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        AI_SETTINGS_FILE.write_text(json.dumps(existing, indent=2))
        # Sync MISP settings into cysiemstack.env
        if "misp" in existing:
            _sync_misp_to_siem_env(existing["misp"])
        # Sync TI API keys into cysiemstack.env
        if "threat_intel" in existing:
            _sync_ti_to_siem_env(existing["threat_intel"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── MISP connectivity test ───────────────────────────────────────────────────

@system_bp.route("/api/system/misp/test", methods=["OPTIONS"])
def misp_test_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/misp/test", methods=["POST"])
def misp_test():
    """Test connectivity to a MISP instance using its REST API."""
    data    = request.get_json() or {}
    url     = data.get("url", "").rstrip("/")
    api_key = data.get("apiKey", "")

    # If the UI sent an empty key with useStored=True (cloud mode, masked placeholder),
    # fall back to the key stored in ai_settings.json
    if (not api_key or api_key == "\u2022" * 8) and data.get("useStored"):
        try:
            stored = json.loads(AI_SETTINGS_FILE.read_text()) if AI_SETTINGS_FILE.exists() else {}
            api_key = stored.get("misp", {}).get("apiKey", "")
        
        except Exception:
            api_key = ""
        # Fallback to env var if still missing
        if not api_key:
            api_key = os.environ.get("CLOUD_MISP_API_KEY", "").strip()

    if not url:
        return jsonify({"ok": False, "error": "MISP Server URL is required"}), 400
    if not api_key or api_key == "\u2022" * 8:
        return jsonify({"ok": False, "error": "MISP API Key is required — enter your key in the field above"}), 400

    try:
        # GET /servers/getPyMISPVersion.json — fast, unauthenticated fields still need a valid key
        resp = http_requests.get(
            f"{url}/servers/getPyMISPVersion.json",
            headers={"Authorization": api_key, "Accept": "application/json"},
            timeout=8,
            verify=False,   # MISP is commonly on self-signed certs in on-premise deployments
        )
        if resp.status_code == 403:
            return jsonify({"ok": False, "error": "Invalid API key (403 Forbidden)"}), 400
        if resp.ok:
            version = resp.json().get("version", "unknown")
            return jsonify({"ok": True, "message": f"MISP {version} responding"})
        return jsonify({"ok": False, "error": f"MISP returned HTTP {resp.status_code}"}), 400
    except http_requests.exceptions.SSLError as e:
        return jsonify({"ok": False, "error": f"SSL error — {e}"}), 400
    except http_requests.exceptions.ConnectionError:
        return jsonify({"ok": False, "error": "Cannot reach MISP server — check URL and network"}), 400
    except http_requests.exceptions.Timeout:
        return jsonify({"ok": False, "error": "Connection timed out"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── TI source connectivity test ───────────────────────────────────────────────

@system_bp.route("/api/system/ti/test", methods=["OPTIONS"])
def ti_test_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/ti/test", methods=["POST"])
def ti_test():
    """Test connectivity to VirusTotal, AbuseIPDB, or GreyNoise using stored or provided key."""
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401

    _MASK = "•" * 8
    data   = request.get_json() or {}
    source = data.get("source", "")   # "virustotal" | "abuseipdb" | "greynoise"

    _TI_ENV_FALLBACK = {
        "vtApiKey":        "VIRUSTOTAL_API_KEY",
        "abuseipdbApiKey": "ABUSEIPDB_API_KEY",
        "greynoiseApiKey": "GREYNOISE_API_KEY",
    }

    def _resolve_key(field: str) -> str:
        key = data.get("apiKey", "")
        if not key or key == _MASK:
            try:
                stored = json.loads(AI_SETTINGS_FILE.read_text()) if AI_SETTINGS_FILE.exists() else {}
                key = stored.get("threat_intel", {}).get(field, "")
            except Exception:
                key = ""
        # Fall back to vault-injected env var if UI has nothing configured
        if not key:
            key = os.environ.get(_TI_ENV_FALLBACK.get(field, ""), "")
        return key

    try:
        if source == "virustotal":
            api_key = _resolve_key("vtApiKey")
            if not api_key:
                return jsonify({"ok": False, "error": "VirusTotal API key not configured"}), 400
            resp = http_requests.get(
                "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                headers={"x-apikey": api_key},
                timeout=8,
            )
            if resp.status_code == 401:
                return jsonify({"ok": False, "error": "Invalid API key (401)"}), 400
            if resp.ok:
                return jsonify({"ok": True, "message": "VirusTotal API key is valid"})
            return jsonify({"ok": False, "error": f"VirusTotal returned HTTP {resp.status_code}"}), 400

        elif source == "abuseipdb":
            api_key = _resolve_key("abuseipdbApiKey")
            if not api_key:
                return jsonify({"ok": False, "error": "AbuseIPDB API key not configured"}), 400
            resp = http_requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": "8.8.8.8", "maxAgeInDays": 1},
                timeout=8,
            )
            if resp.status_code == 401:
                return jsonify({"ok": False, "error": "Invalid API key (401)"}), 400
            if resp.ok:
                return jsonify({"ok": True, "message": "AbuseIPDB API key is valid"})
            return jsonify({"ok": False, "error": f"AbuseIPDB returned HTTP {resp.status_code}"}), 400

        elif source == "greynoise":
            api_key = _resolve_key("greynoiseApiKey")
            if not api_key:
                return jsonify({"ok": False, "error": "GreyNoise API key not configured"}), 400
            resp = http_requests.get(
                "https://api.greynoise.io/v3/community/8.8.8.8",
                headers={"key": api_key},
                timeout=8,
            )
            if resp.status_code == 401:
                return jsonify({"ok": False, "error": "Invalid API key (401)"}), 400
            if resp.ok:
                return jsonify({"ok": True, "message": "GreyNoise API key is valid"})
            return jsonify({"ok": False, "error": f"GreyNoise returned HTTP {resp.status_code}"}), 400

        else:
            return jsonify({"ok": False, "error": "Unknown source — use virustotal, abuseipdb, or greynoise"}), 400

    except http_requests.exceptions.ConnectionError:
        return jsonify({"ok": False, "error": "Cannot reach TI service — check internet connectivity"}), 400
    except http_requests.exceptions.Timeout:
        return jsonify({"ok": False, "error": "Connection timed out"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── MISP effective config (single source of truth for other modules) ──────────

@system_bp.route("/api/system/misp-config", methods=["OPTIONS"])
def misp_config_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/misp-config", methods=["GET"])
def misp_config_get():
    """
    Return the resolved MISP connection parameters for the currently active mode.

    Called by CySOAR / external modules that need MISP creds — they
    should use this endpoint rather than reading ai_settings.json directly.
    The API key is never returned; callers receive url + mode only, and must
    authenticate through the portal backend to perform MISP calls.
    """
    cfg = get_misp_config()
    if cfg is None:
        return jsonify({"mode": "disabled", "enabled": False})
    return jsonify({
        "mode":    cfg["mode"],
        "enabled": True,
        "url":     cfg["url"],
        # API key intentionally omitted — do not expose secrets via this endpoint
    })


# ── Config debug ──────────────────────────────────────────────────────────────

@system_bp.route("/api/config")
def config_debug():
    from core.config import CYSOAR_IMAGE
    return jsonify({
        "CYSOAR_IMAGE":     CYSOAR_IMAGE,
        "SIEM_ENGINE_URL":  os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100"),
        "env_file_loaded":  os.path.exists("/opt/cycentra/.env") or os.path.exists(".env"),
    })


# ── Version + release notes ───────────────────────────────────────────────────

@system_bp.route("/api/system/version")
def system_version():
    """Return current installed version and last 5 release note blocks."""
    version = "unknown"
    release_notes = []

    # Read installed version from /opt/cycentra/version (written by setup.sh)
    for vf in ("/opt/cycentra/version", "/opt/cycentra/.version"):
        if os.path.exists(vf):
            version = open(vf).read().strip()
            break

    # Parse RELEASE_NOTES.md — return last 5 version blocks
    # Try multiple locations: production /opt/cycentra/, then relative to this file (dev), then cwd
    _this_dir = os.path.dirname(os.path.abspath(__file__))
    _cwd = os.getcwd()
    rn_path = None
    for _candidate in (
        "/opt/cycentra/RELEASE_NOTES.md",
        os.path.join(_this_dir, "..", "..", "..", "docs", "RELEASE_NOTES.md"),   # dev: blueprints/system/ → repo root/docs/
        os.path.join(_cwd, "docs", "RELEASE_NOTES.md"),                          # cwd = repo root
        os.path.join(_cwd, "..", "docs", "RELEASE_NOTES.md"),                    # cwd = backend/
        os.path.join(_cwd, "..", "..", "docs", "RELEASE_NOTES.md"),              # cwd = backend/blueprints/
    ):
        _abs = os.path.abspath(_candidate)
        if os.path.exists(_abs):
            rn_path = _abs
            break

    if rn_path and os.path.exists(rn_path):
        with open(rn_path) as f:
            content = f.read()
        # Split on "## v" headings, keep last 5
        blocks = re.split(r"(?=^## v)", content, flags=re.MULTILINE)
        blocks = [b.strip() for b in blocks if b.strip().startswith("## v")]
        for block in blocks[:5]:
            lines  = block.splitlines()
            header = lines[0]                        # "## v1.0.53 — 2026-04-06"
            body   = "\n".join(lines[1:]).strip()
            tag    = re.search(r"(v[\d.]+)", header)
            date   = re.search(r"(\d{4}-\d{2}-\d{2})", header)
            release_notes.append({
                "version": tag.group(1)  if tag  else header,
                "date":    date.group(1) if date else "",
                "notes":   body,
            })

    return jsonify({"version": version, "release_notes": release_notes})


# ── Trigger update ────────────────────────────────────────────────────────────

# Pattern matching sensitive key names and GitHub tokens in log output
_REDACT_KEY_RE  = re.compile(r'(?i)((?:password|secret|token|key|pass)\s*[=:]\s*)\S+')
_REDACT_GH_RE   = re.compile(r'(ghp_|github_pat_)[A-Za-z0-9_]{8,255}')

def _redact_line(line: str) -> str:
    """Strip secrets and GitHub tokens from a log line before storing."""
    line = _REDACT_KEY_RE.sub(r'\1[REDACTED]', line)
    line = _REDACT_GH_RE.sub(r'[GH_TOKEN]', line)
    return line

_update_log: list[str] = []
_update_running = False

@system_bp.route("/api/system/update", methods=["OPTIONS"])
def update_options():
    return add_cors_headers(make_response('', 204))


def _get_server_gh_token() -> str:
    """Read GH_TOKEN at call-time — first from /opt/cycentra/.env, then os.environ.

    Reading from the file directly (not just os.environ) ensures the token is
    always current even if .env was edited or the token was added after the
    Flask process started.
    """
    env_path = Path("/opt/cycentra/.env")
    if env_path.exists():
        try:
            for raw in env_path.read_text().splitlines():
                line = raw.strip()
                if line.startswith("GH_TOKEN=") and not line.startswith("#"):
                    token = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if token:
                        return token
        except Exception:
            pass
    # Fallback: process environment (dev / docker / systemd EnvironmentFile)
    token = os.environ.get("GH_TOKEN", "").strip()
    if not token:
        raise RuntimeError("GH_TOKEN not configured — set it in /opt/cycentra/.env or vault")
    return token


def _run_setup_in_background(flags: list[str], label: str) -> None:
    """Download the latest setup script and run it with the given flags.

    GH_TOKEN is read fresh from /opt/cycentra/.env at call-time (never from
    the HTTP request) so changes to .env after service start are always picked up.

    For private repos the GitHub API 2-step approach is required:
      1. GET /repos/cycentra/Cy360/releases/latest  → find asset URL
      2. GET <asset_api_url>  Accept: application/octet-stream  → binary download
    The direct browser download URL (github.com/releases/latest/download/…) returns
    404 for private repos when accessed via Bearer token.
    """
    global _update_running, _update_log
    _update_log = [f"[{label}] Starting…"]
    _update_running = True

    def _run():
        global _update_running, _update_log
        # Read token fresh inside the thread so the latest .env value is used
        gh_token = _get_server_gh_token()
        if not gh_token:
            _update_log.append(
                f"[{label} ERROR] GH_TOKEN not found — add GH_TOKEN=ghp_... to /opt/cycentra/.env"
            )
            _update_running = False
            return
        try:
            env = {**os.environ, "GH_TOKEN": gh_token}
            api_headers = {
                "Authorization": f"Bearer {gh_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }

            # ── Step 1: resolve the asset URL from the latest release ────────
            _update_log.append(f"[{label}] Fetching latest release metadata…")
            try:
                rel_resp = http_requests.get(
                    "https://api.github.com/repos/cycentra/Cy360/releases/latest",
                    headers=api_headers,
                    timeout=30,
                )
            except Exception as exc:
                _update_log.append(f"[{label} ERROR] GitHub API unreachable: {exc}")
                _update_running = False
                return
            if rel_resp.status_code != 200:
                _update_log.append(
                    f"[{label} ERROR] GitHub API returned HTTP {rel_resp.status_code} — "
                    "check GH_TOKEN permissions (needs repo scope)"
                )
                _update_running = False
                return
            release = rel_resp.json()
            tag = release.get("tag_name", "?")
            assets = release.get("assets", [])
            asset = next(
                (a for a in assets if a["name"] in ("cycentra-setup.sh", "cycentra-setup-bin")),
                None,
            )
            if not asset:
                _update_log.append(
                    f"[{label} ERROR] cycentra-setup.sh not found in release {tag} — "
                    "verify the asset was uploaded to the release"
                )
                _update_running = False
                return

            # ── Step 2: download the asset via the API URL ───────────────────
            _update_log.append(f"[{label}] Downloading cycentra-setup.sh from release {tag}…")
            try:
                dl_resp = http_requests.get(
                    asset["url"],
                    headers={**api_headers, "Accept": "application/octet-stream"},
                    timeout=120,
                    allow_redirects=True,
                )
            except Exception as exc:
                _update_log.append(f"[{label} ERROR] Download request failed: {exc}")
                _update_running = False
                return
            if dl_resp.status_code != 200:
                _update_log.append(
                    f"[{label} ERROR] Asset download returned HTTP {dl_resp.status_code}"
                )
                _update_running = False
                return

            # Write to /tmp first (always writable), then sudo-copy into place
            tmp_path = "/tmp/cycentra-setup.sh"
            Path(tmp_path).write_bytes(dl_resp.content)
            cp = subprocess.run(
                ["sudo", "cp", tmp_path, "/opt/cycentra/cycentra-setup.sh"],
                capture_output=True, text=True, timeout=15,
            )
            if cp.returncode != 0:
                _update_log.append(f"[{label} ERROR] Failed to copy script: {cp.stderr.strip()}")
                _update_running = False
                return
            subprocess.run(
                ["sudo", "chmod", "+x", "/opt/cycentra/cycentra-setup.sh"],
                capture_output=True, text=True, timeout=10,
            )
            _update_log.append(f"[{label}] Script downloaded successfully ({len(dl_resp.content)} bytes)")

            # ── Execute with requested flags (GH_TOKEN visible via sudo -E) ──
            # Execute as a standalone binary (SHC-compiled ELF, not bash-interpreted text)
            cmd = ["sudo", "-E", "/opt/cycentra/cycentra-setup.sh"] + flags
            proc = subprocess.Popen(
                cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            for line in proc.stdout:
                _update_log.append(_redact_line(line.rstrip()))
                if len(_update_log) > 500:
                    _update_log = _update_log[-500:]
            proc.wait()
            _update_log.append(f"[{label}] Finished with exit code {proc.returncode}")
        except Exception as e:
            _update_log.append(f"[{label} ERROR] {e}")
        finally:
            _update_running = False

    threading.Thread(target=_run, daemon=True).start()


@system_bp.route("/api/system/update", methods=["POST"])
def system_update():
    """Trigger sudo cycentra-setup.sh --update in a background thread.
    GH_TOKEN is read from the server .env — not the HTTP request.
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403
    global _update_running
    if _update_running:
        return jsonify({"ok": False, "error": "Update already in progress"}), 409
    _run_setup_in_background(["--update"], "UPDATE")
    return jsonify({"ok": True, "message": "Update started"})


@system_bp.route("/api/system/upgrade", methods=["OPTIONS"])
def upgrade_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/upgrade", methods=["POST"])
def system_upgrade():
    """Trigger a full sudo cycentra-setup.sh (no --update flag) in a background thread.
    This is a major re-install/upgrade — all services are re-configured.
    GH_TOKEN is read from the server .env — not the HTTP request.
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) != "admin":
        return jsonify({"error": "Admin role required"}), 403
    global _update_running
    if _update_running:
        return jsonify({"ok": False, "error": "An update/upgrade is already in progress"}), 409
    _run_setup_in_background([], "UPGRADE")
    return jsonify({"ok": True, "message": "Upgrade started"})


@system_bp.route("/api/system/update/log")
def system_update_log():
    """Poll the live update log."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    return jsonify({"running": _update_running, "log": _update_log[-200:]})


# ── Latest version check ──────────────────────────────────────────────────────

@system_bp.route("/api/system/latest-version", methods=["OPTIONS"])
def latest_version_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/latest-version", methods=["GET"])
def system_latest_version():
    """Query the latest published release tag from GitHub Releases API.

    Uses GET /repos/cycentra/Cy360/releases/latest — fast, no bundle download.
    Returns {current, latest, up_to_date} for the UI to act on.
    GH_TOKEN is read from the server environment (/opt/cycentra/.env).
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    gh_token = _get_server_gh_token()

    # Read currently installed version
    current = "unknown"
    for vf in ("/opt/cycentra/version", "/opt/cycentra/.version"):
        if os.path.exists(vf):
            current = open(vf).read().strip()
            break

    # Query GitHub Releases API for the latest tag — no bundle download needed
    latest = None
    try:
        resp = http_requests.get(
            "https://api.github.com/repos/cycentra/Cy360/releases/latest",
            headers={
                "Authorization": f"Bearer {gh_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=15,
        )
        if resp.ok:
            latest = resp.json().get("tag_name")   # e.g. "v1.0.90"
        elif resp.status_code == 401:
            return jsonify({
                "current": current, "latest": None, "up_to_date": False,
                "error": "Invalid GH_TOKEN (401 Unauthorized)",
            })
    except Exception:
        pass

    if not latest:
        return jsonify({
            "current": current,
            "latest":  None,
            "up_to_date": False,
            "error": "Could not read latest release — verify GH_TOKEN and connectivity",
        })

    return jsonify({
        "current":    current,
        "latest":     latest,
        "up_to_date": current == latest,
    })


# ── Env file editor ───────────────────────────────────────────────────────────

@system_bp.route("/api/system/env/<target>", methods=["OPTIONS"])
def env_options(target):
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/env/<target>", methods=["GET"])
def env_get(target):
    """Read an env file. Secret values are masked."""
    path = _ENV_FILE_MAP.get(target)
    if not path:
        return jsonify({"error": f"Unknown env target: {target}"}), 400

    if not os.path.exists(path):
        return jsonify({"vars": [], "exists": False})

    vars_list = []
    with open(path) as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")
            if not line or line.startswith("#"):
                vars_list.append({"line": line, "key": None, "value": None, "comment": True})
                continue
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line)
            if m:
                key = m.group(1)
                val = m.group(2)
                # Mask secrets — return placeholder, never the real value
                if any(s in key.upper() for s in _SECRET_KEYS):
                    val = "••••••••"
                vars_list.append({"line": line, "key": key, "value": val, "comment": False})
            else:
                vars_list.append({"line": line, "key": None, "value": None, "comment": True})

    return jsonify({"vars": vars_list, "exists": True, "path": path})


@system_bp.route("/api/system/env/<target>", methods=["PUT"])
def env_put(target):
    """Write updated key=value pairs into an env file.
    Only non-secret keys are writable via this endpoint.
    Preserves comments and line order. Adds missing keys at end.
    """
    path = _ENV_FILE_MAP.get(target)
    if not path:
        return jsonify({"error": f"Unknown env target: {target}"}), 400

    data    = request.get_json() or {}
    updates = data.get("vars", {})   # {KEY: VALUE, ...}
    if not isinstance(updates, dict):
        return jsonify({"error": "vars must be a key→value dict"}), 400

    # Reject any attempt to write secret keys
    for key in updates:
        if any(s in key.upper() for s in _SECRET_KEYS):
            return jsonify({"error": f"Cannot modify secret key: {key}"}), 403
        # Validate key format — no shell injection
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', key):
            return jsonify({"error": f"Invalid key name: {key}"}), 400
        # Validate value — disallow newlines and bare shell substitution
        val = str(updates[key])
        if "\n" in val or "\r" in val:
            return jsonify({"error": f"Value for {key} must not contain newlines"}), 400

    # Read existing file (or start empty)
    existing_lines = []
    if os.path.exists(path):
        with open(path) as f:
            existing_lines = f.read().splitlines()

    written_keys = set()
    new_lines = []
    for line in existing_lines:
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=', line)
        if m:
            key = m.group(1)
            if key in updates:
                new_lines.append(f"{key}={updates[key]}")
                written_keys.add(key)
                continue
        new_lines.append(line)

    # Append any new keys not already in file
    for key, val in updates.items():
        if key not in written_keys:
            new_lines.append(f"{key}={val}")

    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write("\n".join(new_lines) + "\n")
        return jsonify({"ok": True, "path": path, "updated": len(updates)})
    except PermissionError:
        return jsonify({"error": "Permission denied — backend may need write access to env file"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── License management ────────────────────────────────────────────────────────

_LIC_PATH              = Path("/opt/cycentra/cycentra.lic")
_LIC_LOCKFILE          = Path("/opt/cycentra/.license_expired")
_LIC_VALIDATOR         = Path("/opt/cycentra/license_validator.py")   # deployed copy
_HOST_LIMIT_EXCEEDED   = Path("/opt/cycentra/.host_limit_exceeded_since")
_HOST_LIMIT_WARN_DAYS  = 15

_CORR_DB_URL = (
    os.environ.get("CYCENTRA_DB_URL")
    or os.environ.get("CORRELATION_DB_URL")
    or os.environ.get("DATABASE_URL", "postgresql://corruser:changeme@127.0.0.1:5433/correlation")
).replace("+asyncpg", "")


def _get_host_count() -> int:
    try:
        import psycopg2
        with psycopg2.connect(_CORR_DB_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM host_posture_cache")
                return cur.fetchone()[0]
    except Exception:
        return -1  # unknown — don't enforce limit if DB unreachable


def _get_or_set_host_limit_date() -> date:
    if _HOST_LIMIT_EXCEEDED.exists():
        try:
            return date.fromisoformat(_HOST_LIMIT_EXCEEDED.read_text().strip())
        except Exception:
            pass
    today = date.today()
    _HOST_LIMIT_EXCEEDED.parent.mkdir(parents=True, exist_ok=True)
    _HOST_LIMIT_EXCEEDED.write_text(today.isoformat())
    return today


def _run_validator(lic_path: Path) -> dict:
    """Run license_validator.py against a .lic file. Falls back to the copy
    inside the backend package if the deployed one is not present yet."""
    validator = _LIC_VALIDATOR
    if not validator.exists():
        # During initial install the deployed copy may not exist yet — use source
        validator = Path(__file__).parent.parent.parent / "core" / "license_validator.py"
    if not validator.exists():
        return {"valid": False, "type": "none", "days_remaining": 0,
                "customer": "unknown", "message": "Validator not available on server"}
    try:
        result = subprocess.run(
            ["python3", str(validator), "--license", str(lic_path)],
            capture_output=True, text=True, timeout=10,
        )
        return json.loads(result.stdout) if result.stdout.strip() else {
            "valid": False, "type": "none", "days_remaining": 0,
            "customer": "unknown", "message": "Validator returned no output",
        }
    except Exception as exc:
        return {"valid": False, "type": "none", "days_remaining": 0,
                "customer": "unknown", "message": str(exc)}


@system_bp.route("/api/system/license", methods=["GET"])
def get_license():
    """Return license status with host count and limit enforcement."""
    result = _run_validator(_LIC_PATH)

    # ── Host limit enforcement ─────────────────────────────────────────────
    max_hosts        = result.get("max_hosts", 0)
    registered_hosts = _get_host_count()
    result["registered_hosts"] = registered_hosts

    if max_hosts > 0 and registered_hosts >= 0:
        if registered_hosts > max_hosts:
            exceeded_since = _get_or_set_host_limit_date()
            days_exceeded  = (date.today() - exceeded_since).days
            if days_exceeded >= _HOST_LIMIT_WARN_DAYS:
                result["host_status"]              = "host_blocked"
                result["host_registration_blocked"] = True
            else:
                result["host_status"]              = "host_warning"
                result["host_registration_blocked"] = False
            result["host_limit_exceeded_since"] = exceeded_since.isoformat()
            result["host_limit_days_exceeded"]  = days_exceeded
        else:
            _HOST_LIMIT_EXCEEDED.unlink(missing_ok=True)
            result["host_status"]              = "ok"
            result["host_registration_blocked"] = False
    else:
        result["host_status"]              = "unlimited" if max_hosts == 0 else "unknown"
        result["host_registration_blocked"] = False

    return add_cors_headers(jsonify(result))


@system_bp.route("/api/system/license/upload", methods=["OPTIONS"])
def license_upload_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/license/upload", methods=["POST"])
def upload_license():
    """Accept a .lic file, validate it, and save to /opt/cycentra/cycentra.lic.
    The license activates immediately — no restart required.
    """
    uploaded = request.files.get("license")
    if not uploaded:
        return jsonify({"ok": False, "error": "No file provided"}), 400

    filename = uploaded.filename or ""
    if not filename.endswith(".lic"):
        return jsonify({"ok": False, "error": "File must have a .lic extension"}), 400

    tmp_path = Path(f"/tmp/cycentra_license_upload_{os.getpid()}.lic")
    try:
        uploaded.save(str(tmp_path))

        # Validate before committing
        result = _run_validator(tmp_path)
        if not result.get("valid"):
            return jsonify({"ok": False, "error": result.get("message", "Invalid license file")}), 400

        # Commit the license
        _LIC_PATH.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(str(tmp_path), str(_LIC_PATH))
        _LIC_PATH.chmod(0o600)

        # Clear any expired lockfile so services can restart cleanly
        if _LIC_LOCKFILE.exists():
            _LIC_LOCKFILE.unlink(missing_ok=True)

        lic_type = result.get("type", "").upper()
        days     = result.get("days_remaining", "?")
        return add_cors_headers(jsonify({
            "ok":      True,
            "message": f"{lic_type} license applied — {days} day(s) remaining",
            **result,
        }))
    except PermissionError:
        return jsonify({"ok": False, "error": "Permission denied — backend needs write access to /opt/cycentra/"}), 403
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    finally:
        tmp_path.unlink(missing_ok=True)


# ── IP Geolocation (for world map) ────────────────────────────────────────────

_geo_cache: dict = {}   # ip → {lat, lon, country, city}

@system_bp.route("/api/system/geoip", methods=["POST", "OPTIONS"])
def system_geoip():
    """Resolve a list of IPs to lat/lon. Returns cached results where available.
    Uses ipwho.is (free, no key required) for uncached IPs.
    Private/loopback IPs are skipped.
    """
    if request.method == "OPTIONS":
        return add_cors_headers(make_response('', 204))

    data = request.get_json() or {}
    ips  = [str(ip).strip() for ip in data.get("ips", []) if str(ip).strip()]
    if not ips:
        return jsonify({"results": {}})

    _PRIVATE = re.compile(
        r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|localhost)'
    )

    results = {}
    to_fetch = []
    for ip in ips[:50]:           # hard cap — no unbounded external requests
        if _PRIVATE.match(ip) or ip == "—":
            continue
        if ip in _geo_cache:
            results[ip] = _geo_cache[ip]
        else:
            to_fetch.append(ip)

    for ip in to_fetch[:20]:
        try:
            r = http_requests.get(f"https://ipwho.is/{ip}", timeout=4)
            if r.ok:
                d = r.json()
                if d.get("success"):
                    entry = {
                        "lat":     d.get("latitude"),
                        "lon":     d.get("longitude"),
                        "country": d.get("country", ""),
                        "city":    d.get("city", ""),
                        "flag":    d.get("flag", {}).get("emoji", ""),
                    }
                    _geo_cache[ip]  = entry
                    results[ip]     = entry
        except Exception:
            pass

    return jsonify({"results": results})


# ── MCP configuration ─────────────────────────────────────────────────────────

# The 11 tools registered by the Security MCP bridge (mirrors main.py)
_MCP_TOOLS = [
    # ── Read tools ────────────────────────────────────────────────────────────
    {"name": "get_stats",                  "access_level": "read",  "description": "High-level SIEM statistics: incidents, alerts, anomalies, uptime"},
    {"name": "list_incidents",             "access_level": "read",  "description": "List incidents filtered by status / severity"},
    {"name": "get_incident",               "access_level": "read",  "description": "Full details for a single incident by ID"},
    {"name": "list_alerts",                "access_level": "read",  "description": "Enumerate raw alerts, optionally scoped to an incident"},
    {"name": "list_risk_scores",           "access_level": "read",  "description": "Entity risk scores filtered by type and level"},
    {"name": "list_ueba_users",            "access_level": "read",  "description": "UEBA user profiles with anomaly and activity data"},
    {"name": "get_ueba_anomalies",         "access_level": "read",  "description": "Detailed behavioural anomalies for a specific user"},
    {"name": "wazuh_list_agents",          "access_level": "read",  "description": "Enumerate Wazuh agents with optional status filter"},
    {"name": "wazuh_get_agent_vulnerabilities", "access_level": "read", "description": "Wazuh vulnerability scan results for an agent"},
    # ── New read tools (Phase 2) ───────────────────────────────────────────────
    {"name": "get_alert",                  "access_level": "read",  "description": "Full details for a single alert by ID"},
    {"name": "search_alerts",              "access_level": "read",  "description": "Multi-filter alert search: agent, rule, severity, MISP match"},
    {"name": "list_campaigns",             "access_level": "read",  "description": "Group open incidents by campaign_id (attack-chain view)"},
    {"name": "get_threat_intel",           "access_level": "read",  "description": "MISP IOC cache + risk scores for a specific indicator value"},
    {"name": "get_vuln_summary",           "access_level": "read",  "description": "Aggregated CVE counts across all active Wazuh agents"},
    {"name": "get_compliance_status",      "access_level": "read",  "description": "Compliance control coverage grouped by framework (NIS2, ISO 27001, DORA)"},
    {"name": "get_incident_distribution",  "access_level": "read",  "description": "Exact incident counts by severity, status, and category (top 15) — never estimate"},
    {"name": "search_incidents",           "access_level": "read",  "description": "Search incidents by affected user, agent, source IP, severity, or status — returns exact DB records"},
    # ── Write tools (require analyst confirmation before execution) ────────────
    {"name": "wazuh_active_response",      "access_level": "write", "requires_confirmation": True,  "description": "Trigger a Wazuh active-response command on an agent"},
    {"name": "update_incident",            "access_level": "write", "requires_confirmation": True,  "description": "Update incident fields: assigned_to, notes, severity (PATCH)"},
]


def _read_mcp_enabled() -> bool:
    """Read MCP_ENABLED from cysiemstack.env. Defaults to True when absent."""
    env_path = Path(_ENV_FILE_MAP["cysiemstack"])
    if not env_path.exists():
        return True
    try:
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line.startswith("MCP_ENABLED=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip().lower() not in ("false", "0", "no")
    except Exception:
        pass
    return True


def _write_mcp_enabled(enabled: bool) -> None:
    """Write MCP_ENABLED into cysiemstack.env, updating in-place."""
    env_path = Path(_ENV_FILE_MAP["cysiemstack"])
    if not env_path.parent.exists():
        return
    value = "true" if enabled else "false"
    try:
        lines = env_path.read_text().splitlines() if env_path.exists() else []
    except Exception:
        lines = []
    result, found = [], False
    for line in lines:
        if re.match(r'^MCP_ENABLED\s*=', line) and not line.strip().startswith("#"):
            result.append(f"MCP_ENABLED={value}")
            found = True
        else:
            result.append(line)
    if not found:
        result.append(f"MCP_ENABLED={value}")
    try:
        env_path.write_text("\n".join(result) + "\n")
    except Exception:
        pass


@system_bp.route("/api/system/mcp", methods=["OPTIONS"])
def mcp_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/mcp", methods=["GET"])
def mcp_get():
    """Return MCP bridge status, SSE endpoint URL, and registered tool list."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    enabled  = _read_mcp_enabled()
    base_url = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100").rstrip("/")
    # public_url is the operator-facing URL shown in the UI connection guide.
    # When BASE_DOMAIN is configured (production), the nginx reverse-proxy exposes
    # the engine under https://siem.<domain>/ so that is what 3rd-party clients use.
    # Without BASE_DOMAIN (dev / isolated installs) we fall back to the loopback URL.
    base_domain = os.environ.get("BASE_DOMAIN", "")
    public_url  = f"https://cy360.{base_domain}/mcp/sse" if base_domain else f"{base_url}/mcp/sse"

    return jsonify({
        "enabled":     enabled,
        "endpoint":    f"{base_url}/mcp/sse",
        "public_url":  public_url,
        "tools":       _MCP_TOOLS,
        "transport":   "SSE (Server-Sent Events)",
        "protocol":    "MCP 2024-11-05",
        "description": "CySIEM Security MCP — exposes SIEM, UEBA, and Wazuh tools to AI clients",
    })


@system_bp.route("/api/system/mcp", methods=["POST"])
def mcp_post():
    """Enable or disable the MCP bridge by writing MCP_ENABLED to cysiemstack.env.
    Requires admin role.  The engine must be restarted for the change to take effect.
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) != "admin":
        return jsonify({"error": "Admin role required"}), 403

    data    = request.get_json() or {}
    enabled = bool(data.get("enabled", True))
    try:
        _write_mcp_enabled(enabled)
    except PermissionError:
        return jsonify({"error": "Permission denied — backend cannot write cysiemstack.env"}), 403
    except Exception:
        return jsonify({"error": "Failed to update MCP setting — check server logs"}), 500

    return jsonify({
        "ok":      True,
        "enabled": enabled,
        "message": f"MCP bridge {'enabled' if enabled else 'disabled'} — restart cysiemstack-engine to apply",
    })


# ── CyMind Integration ────────────────────────────────────────────────────────
#
# /api/cymind/context  — machine-to-machine endpoint for CyMind's RAG chat.
# CyMind calls this instead of connecting to the MCP SSE bridge directly.
# Auth: X-CyMind-Key header (the same cymk_... key stored in ai_settings.json).
# Returns: live SIEM snapshot (stats, incidents, risk, ueba) as JSON.
# Access: analyst-level data only; no write operations exposed.
#
# nginx proxy: /cymind/ location is injected into the cy360 server block so the
# portal iframe loads from the same HTTPS origin (no mixed-content block).
# _nginx_inject_cymind() is called from cymind_post() whenever the URL is saved.

_NGINX_CONF = Path("/etc/nginx/sites-available/cycentra-modules")


def _nginx_inject_cymind(cymind_url: str) -> str:
    """
    Inject (or replace) the location /cymind/ reverse-proxy block inside the
    cy360 server block. Idempotent — rewrites if already present.

    Returns a status string for logging.
    """
    if not _NGINX_CONF.exists():
        return "cymind nginx: config not found — skipping"

    upstream = cymind_url.rstrip("/") + "/"
    ssl_extra = "        proxy_ssl_verify    off;\n" if upstream.startswith("https") else ""

    block = (
        "    # CyMind chat proxy — same-origin iframe, no mixed-content\n"
        "    location /cymind/ {\n"
       f"        proxy_pass         {upstream};\n"
        "        proxy_http_version 1.1;\n"
       f"{ssl_extra}"
        "        proxy_set_header   Host              $http_host;\n"
        "        proxy_set_header   X-Real-IP         $remote_addr;\n"
        "        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;\n"
        "        proxy_set_header   X-Forwarded-Proto $scheme;\n"
        "        proxy_set_header   Connection        \"\";\n"
        "        proxy_read_timeout 3600s;\n"
        "        proxy_buffering    off;\n"
        "        proxy_cache        off;\n"
        "    }\n"
    )

    text = _NGINX_CONF.read_text()

    # Remove any existing /cymind/ block before re-injecting
    text = re.sub(
        r'[ \t]+# CyMind chat proxy[^\n]*\n[ \t]+location /cymind/ \{[^}]+\}\n',
        '', text, flags=re.DOTALL
    )

    # Anchor 1: explicit comment written by setup.sh
    anchor = "    # location /cymind/ is injected here"
    if anchor in text:
        ins = text.find(anchor)
        eol = text.find("\n", ins)
        eol = eol if eol != -1 else len(text) - 1
        text = text[:ins] + block + text[eol + 1:]
        _NGINX_CONF.write_text(text)
        rc, _, err = _run_cmd("nginx -t && systemctl reload nginx", timeout=15)
        return ("cymind: /cymind/ injected and nginx reloaded" if rc == 0
                else f"cymind: nginx reload failed: {err}")

    # Anchor 2: fall back to inserting before the /cysoar/ anchor or server closing brace
    oidc_pos = text.find("location /oidc/")
    if oidc_pos != -1:
        depth, i = 0, oidc_pos
        while i < len(text):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                if depth == 0:
                    text = text[:i] + block + text[i:]
                    _NGINX_CONF.write_text(text)
                    rc, _, err = _run_cmd("nginx -t && systemctl reload nginx", timeout=15)
                    return ("cymind: /cymind/ injected before server brace and nginx reloaded" if rc == 0
                            else f"cymind: nginx reload failed: {err}")
                depth -= 1
            i += 1

    return "cymind: WARNING — injection point not found; add location /cymind/ manually"


def _nginx_remove_cymind() -> None:
    """Remove the /cymind/ proxy block from nginx config and reload."""
    if not _NGINX_CONF.exists():
        return
    text = _NGINX_CONF.read_text()
    new_text = re.sub(
        r'[ \t]+# CyMind chat proxy[^\n]*\n[ \t]+location /cymind/ \{[^}]+\}\n',
        '', text, flags=re.DOTALL
    )
    if new_text != text:
        _NGINX_CONF.write_text(new_text)
        _run_cmd("nginx -t && systemctl reload nginx", timeout=15)


def _read_cymind_config() -> dict:
    """Read cymind config block from ai_settings.json."""
    try:
        if AI_SETTINGS_FILE.exists():
            data = json.loads(AI_SETTINGS_FILE.read_text())
            return data.get("cymind_integration", {})
    except Exception:
        pass
    return {}


def _write_cymind_config(cfg: dict) -> None:
    """Merge cymind config into ai_settings.json.

    NOTE: We intentionally do NOT write CYMIND_API_KEY to cysiemstack.env.
    The engine service loads /opt/cycentra/.env FIRST (shared company-wide
    secrets, including vault-injected CYMIND_API_KEY with the correct CyM_ key)
    and then loads cysiemstack.env.  Because the last EnvironmentFile wins for
    duplicate keys, any CYMIND_API_KEY in cysiemstack.env would override the
    correct key with the cymk_ M2M admin key, which is rejected by /api/v1/chat
    (401 Unauthorized).  The engine reads AI credentials from ai_settings.json
    at runtime via call_llm(), so cysiemstack.env does not need this key at all.
    """
    existing = {}
    try:
        if AI_SETTINGS_FILE.exists():
            existing = json.loads(AI_SETTINGS_FILE.read_text())
    except Exception:
        pass
    existing["cymind_integration"] = cfg
    AI_SETTINGS_FILE.write_text(json.dumps(existing, indent=2))
    # Remove CYMIND_API_KEY from cysiemstack.env if it was written by an older
    # version of this function — the stale cymk_ key causes 401 on chat calls.
    try:
        env_path = Path(_ENV_FILE_MAP["cysiemstack"])
        if env_path.exists():
            lines = env_path.read_text().splitlines()
            cleaned = [l for l in lines if not re.match(r'^CYMIND_API_KEY\s*=', l)]
            if len(cleaned) != len(lines):
                env_path.write_text("\n".join(cleaned) + "\n")
    except Exception:
        pass


@system_bp.route("/api/system/cymind", methods=["OPTIONS"])
def cymind_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/cymind", methods=["GET"])
def cymind_get():
    """Return CyMind integration config. Analyst+ can read; M2M key is masked, chat key is returned."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403

    cfg = _read_cymind_config()
    masked = dict(cfg)
    if masked.get("apiKey"):
        masked["apiKey"] = "••••••••"
    # chatApiKey returned so test endpoint and admin UI can report hasChatKey status.
    base_url = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100").rstrip("/")
    base_domain = os.environ.get("BASE_DOMAIN", "")
    public_mcp = f"https://cy360.{base_domain}/mcp/sse" if base_domain else f"{base_url}/mcp/sse"
    return jsonify({
        **masked,
        "mcpEndpoint": public_mcp,
        "hasKey":     bool(cfg.get("apiKey")),
        "hasChatKey": bool(cfg.get("chatApiKey")),
    })


@system_bp.route("/api/system/cymind", methods=["POST"])
def cymind_post():
    """Save CyMind integration settings. Admin only.

    Body (all optional):
      cymindUrl   — base URL of CyMind instance (e.g. https://cymind.corp.example.com)
      generateKey — true → generate and store a new cymk_... M2M API key
      chatApiKey  — CyM_... (or legacy pak_...) API key for the portal service account;
                    generated in CyMind (Users → service account with analyst role →
                    API Keys → Generate) and pasted here.  Pass "" to clear.
      clearChatKey — true → remove the stored chat API key
      enabled     — bool, enable/disable the integration
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) != "admin":
        return jsonify({"error": "Admin role required"}), 403

    import secrets as _secrets
    data = request.get_json() or {}
    cfg  = _read_cymind_config()

    nginx_msg = None
    if "cymindUrl" in data:
        cfg["cymindUrl"] = str(data["cymindUrl"]).strip().rstrip("/")
        if cfg["cymindUrl"]:
            nginx_msg = _nginx_inject_cymind(cfg["cymindUrl"])
        else:
            _nginx_remove_cymind()
            nginx_msg = "cymind: /cymind/ proxy block removed (URL cleared)"
    if "enabled" in data:
        cfg["enabled"] = bool(data["enabled"])
    if data.get("generateKey"):
        cfg["apiKey"] = "cymk_" + _secrets.token_hex(24)
    if "chatApiKey" in data:
        raw = str(data["chatApiKey"]).strip()
        # CyMind generates keys with CyM_ prefix (PAK chat keys).
        # Older deployments may use pak_ prefix. Both are valid chat keys.
        # cymk_ prefix is the M2M admin key — it returns 401 on /api/v1/chat.
        if raw and not (raw.startswith("CyM_") or raw.startswith("pak_")):
            return jsonify({"error": "Chat API key must start with 'CyM_' or 'pak_' — generate it in CyMind's API Keys section."}), 400
        cfg["chatApiKey"] = raw  # empty string = clear
    if data.get("clearChatKey"):
        cfg["chatApiKey"] = ""

    _write_cymind_config(cfg)

    # When disabling the integration, revert AI provider to local so enrichment
    # falls back to the on-prem Ollama engine automatically.
    # Also clear cymind_memory credentials to prevent stale key usage after disable.
    if not cfg.get("enabled") and data.get("clearChatKey"):
        try:
            _ai = {}
            if AI_SETTINGS_FILE.exists():
                _ai = json.loads(AI_SETTINGS_FILE.read_text())
            _ai["provider"] = "local"
            _ai.setdefault("fields", {})["apiKey"]  = ""
            _ai.setdefault("cymind_memory", {})["apiKey"]  = ""
            _ai.setdefault("cymind_memory", {})["baseUrl"] = ""
            AI_SETTINGS_FILE.write_text(json.dumps(_ai, indent=2))
        except Exception:
            pass

    masked = dict(cfg)
    if masked.get("apiKey"):
        masked["apiKey"] = "••••••••"
    if masked.get("chatApiKey"):
        masked["chatApiKey"] = masked["chatApiKey"][:12] + "••••••••"
    extra = {}
    if data.get("generateKey"):
        extra["newKey"] = cfg["apiKey"]
    return jsonify({
        "ok": True,
        "config": masked,
        **extra,
        "message": "CyMind integration config saved.",
        **({"nginxStatus": nginx_msg} if nginx_msg else {}),
    })


@system_bp.route("/api/system/cymind/enable", methods=["POST", "OPTIONS"])
def cymind_enable():
    """
    One-click enable: CyCentra logs in to CyMind as admin, calls the
    /api/v1/admin/activate-cycentra endpoint which auto-provisions the portal
    service account and returns a pak_... chat key.  All keys are saved
    server-side — no manual copy-paste needed.

    Body:
      cymindUrl      — CyMind base URL (e.g. http://172.16.0.2:8080)
      cymindAdminEmail    — CyMind admin email
      cymindAdminPassword — CyMind admin password
    """
    if request.method == "OPTIONS":
        return add_cors_headers(make_response('', 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) != "admin":
        return jsonify({"error": "Admin role required"}), 403

    import secrets as _secrets
    data        = request.get_json() or {}
    # CyMind is always at 172.16.0.2:8080 — URL is fixed, not user-configurable
    cymind_url  = "http://172.16.0.2:8080"
    admin_email = str(data.get("cymindAdminEmail", "")).strip()
    admin_pw    = str(data.get("cymindAdminPassword", "")).strip()

    if not admin_email or not admin_pw:
        return jsonify({"error": "CyMind admin email and password are required."}), 400

    # ── Step 1: Save URL and generate M2M key ────────────────────────────────
    cfg = _read_cymind_config()
    cfg["cymindUrl"] = cymind_url
    cfg["enabled"]   = True
    m2m_key = "cymk_" + _secrets.token_hex(24)
    cfg["apiKey"] = m2m_key
    nginx_msg = _nginx_inject_cymind(cymind_url)
    _write_cymind_config(cfg)

    # ── Step 2: Log in to CyMind to get admin JWT ────────────────────────────
    try:
        login_r = http_requests.post(
            f"{cymind_url}/api/v1/auth/login",
            json={"email": admin_email, "password": admin_pw},
            timeout=15,
        )
    except Exception as e:
        return jsonify({"error": f"Cannot reach CyMind at {cymind_url}: {e}"}), 502

    if not login_r.ok:
        return jsonify({
            "error": f"CyMind login failed (HTTP {login_r.status_code}). Check the admin email/password.",
        }), 401

    cymind_jwt = login_r.json().get("access_token") or login_r.json().get("token")
    if not cymind_jwt:
        return jsonify({"error": "CyMind login response did not include an access token."}), 502

    # ── Step 3: Call CyMind activate endpoint ────────────────────────────────
    base_domain = os.environ.get("BASE_DOMAIN", "")
    cycentra_url = f"https://cy360.{base_domain}" if base_domain else os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100").replace(":8100", "")

    try:
        act_r = http_requests.post(
            f"{cymind_url}/api/v1/admin/activate-cycentra",
            json={"cycentra_url": cycentra_url, "cycentra_api_key": m2m_key},
            headers={"Authorization": f"Bearer {cymind_jwt}"},
            timeout=30,
        )
    except Exception as e:
        return jsonify({"error": f"CyMind activation call failed: {e}"}), 502

    if not act_r.ok:
        return jsonify({
            "error": f"CyMind activation returned HTTP {act_r.status_code}: {act_r.text[:200]}",
        }), 502

    chat_key = act_r.json().get("chat_key", "")
    if not chat_key:
        return jsonify({"error": "CyMind activation did not return a chat key."}), 502

    # ── Step 4: Save the chat key ─────────────────────────────────────────────
    cfg = _read_cymind_config()
    cfg["chatApiKey"] = chat_key
    _write_cymind_config(cfg)

    # ── Step 5: Auto-configure AI provider to use CyMind ─────────────────────
    # All AI/LLM config is handled automatically — no manual input needed in UI
    try:
        _ai = {}
        if AI_SETTINGS_FILE.exists():
            _ai = json.loads(AI_SETTINGS_FILE.read_text())
        _ai["provider"] = "cymind"
        _ai.setdefault("fields", {})["baseUrl"] = cymind_url
        _ai.setdefault("fields", {})["apiKey"]  = chat_key
        _ai.setdefault("cymind_memory", {})["baseUrl"] = cymind_url
        _ai.setdefault("cymind_memory", {})["apiKey"]  = chat_key
        AI_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        AI_SETTINGS_FILE.write_text(json.dumps(_ai, indent=2))
    except Exception as _e:
        current_app.logger.warning("cymind_enable: failed to auto-configure AI provider: %s", _e)

    # ── Step 6: Trigger CyMind self-update using the admin JWT ────────────────
    # We already hold the admin JWT from Step 2, so we piggyback on it to pull
    # the latest CyMind image.  This ensures the API key scope fix (v1.0.115+)
    # is deployed automatically — no manual SSH to the CyMind server required.
    # The update runs in the background inside CyMind; we verify the chat key
    # works after a short wait so the portal reports the correct final state.
    update_msg   = ""
    update_needed = False
    try:
        upd_r = http_requests.post(
            f"{cymind_url}/api/v1/system/update",
            headers={"Authorization": f"Bearer {cymind_jwt}"},
            timeout=15,
        )
        if upd_r.ok:
            update_msg    = "CyMind self-update triggered — pulling latest image in background."
            update_needed = True
            current_app.logger.info("cymind_enable: update triggered: %s", upd_r.json())
        else:
            update_msg = f"CyMind update trigger returned {upd_r.status_code} — update manually if needed."
            current_app.logger.warning("cymind_enable: update trigger failed: %s", upd_r.text[:200])
    except Exception as _ue:
        update_msg = f"CyMind update trigger failed ({_ue}) — update manually if needed."
        current_app.logger.warning("cymind_enable: update trigger exception: %s", _ue)

    # If the update was triggered, wait for CyMind to come back up (max 3 min).
    # We poll /health every 5 s; once healthy we verify the chat key actually works.
    chat_verified = False
    if update_needed:
        import time as _time
        _time.sleep(10)  # give docker pull a head-start before polling
        for _ in range(34):          # 34 × 5 s = ~3 min total
            try:
                _h = http_requests.get(f"{cymind_url}/api/v1/health", timeout=5)
                if _h.ok:
                    # Health OK — test the chat key
                    _probe = http_requests.post(
                        f"{cymind_url}/api/v1/chat",
                        headers={"Authorization": f"Bearer {chat_key}",
                                 "Content-Type": "application/json"},
                        json={
                            "messages":         [{"role": "user", "content": "ping"}],
                            "system":           "Reply: pong",
                            "use_rag":          False,
                            "use_external":     False,
                            "use_mcp":          False,
                            "use_integrations": False,
                            "use_operational":  False,
                        },
                        timeout=10,
                    )
                    if _probe.ok:
                        chat_verified = True
                        update_msg   += " Chat key verified — enrichment is now active."
                        break
                    elif _probe.status_code == 403:
                        # Still old version; keep waiting for the restart
                        pass
                    else:
                        # Unexpected status — stop waiting
                        update_msg += f" Chat probe returned {_probe.status_code} after update."
                        break
            except Exception:
                pass  # CyMind is restarting — keep polling
            _time.sleep(5)

        if not chat_verified:
            update_msg += (
                " CyMind is still restarting or the update is taking longer than expected. "
                "Wait 2–3 minutes and click 'Test Connection' to confirm."
            )

    return jsonify({
        "ok":           True,
        "message":      "Integration enabled. CyMind is connected and the portal service account is provisioned.",
        "nginxStatus":  nginx_msg,
        "updateStatus": update_msg,
        "chatVerified": chat_verified,
    })


@system_bp.route("/api/system/cymind/test", methods=["GET", "OPTIONS"])
def cymind_test():
    """Test CyMind and MCP connectivity from the server side. Analyst+ only."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response('', 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403

    import time
    cfg = _read_cymind_config()
    results = {}

    # ── 1. CyMind health (server → CyMind direct) ─────────────────────────────
    cymind_url = cfg.get("cymindUrl", "").strip()
    if cymind_url:
        t0 = time.monotonic()
        try:
            r = http_requests.get(f"{cymind_url}/api/v1/health", timeout=8)
            ms = int((time.monotonic() - t0) * 1000)
            if r.ok:
                results["cymind"] = {"ok": True,  "msg": f"CyMind healthy ({ms} ms)", "ms": ms}
            else:
                results["cymind"] = {"ok": False, "msg": f"CyMind returned HTTP {r.status_code}", "ms": ms}
        except Exception as e:
            ms = int((time.monotonic() - t0) * 1000)
            results["cymind"] = {"ok": False, "msg": f"Unreachable: {e}", "ms": ms}
    else:
        results["cymind"] = {"ok": False, "msg": "CyMind URL not configured"}

    # ── 2. MCP engine (local correlation engine at port 8100) ─────────────────
    t0 = time.monotonic()
    try:
        r = http_requests.get("http://127.0.0.1:8100/health", timeout=5)
        ms = int((time.monotonic() - t0) * 1000)
        if r.ok:
            results["mcp_engine"] = {"ok": True,  "msg": f"Correlation engine healthy ({ms} ms)", "ms": ms}
        else:
            results["mcp_engine"] = {"ok": False, "msg": f"Engine returned HTTP {r.status_code}", "ms": ms}
    except Exception as e:
        ms = int((time.monotonic() - t0) * 1000)
        results["mcp_engine"] = {"ok": False, "msg": f"Engine unreachable: {e}", "ms": ms}

    # ── 3. Chat API key — test the actual /api/v1/chat endpoint ─────────────────
    # Previously this only checked key presence (bool).  That gave a false green
    # even when CyMind's security pipeline was rejecting enrichment requests with
    # 400/429.  Now we send a minimal benign chat request so the test reflects
    # the real enrichment code path.
    chat_key = cfg.get("chatApiKey", "")
    if not chat_key:
        results["chat_key"] = {
            "ok":  False,
            "msg": "Chat API key not set — use the Enable Integration flow or paste a CyM_... key.",
        }
    elif cymind_url and results.get("cymind", {}).get("ok"):
        t0 = time.monotonic()
        try:
            probe_resp = http_requests.post(
                f"{cymind_url}/api/v1/chat",
                headers={"Authorization": f"Bearer {chat_key}", "Content-Type": "application/json"},
                json={
                    "messages":         [{"role": "user", "content": "ping"}],
                    "system":           "Reply with one word: pong",
                    "use_rag":          False,
                    "use_external":     False,
                    "use_mcp":          False,
                    "use_integrations": False,
                    "use_operational":  False,
                    "temperature":      0.0,
                },
                timeout=20,
            )
            ms = int((time.monotonic() - t0) * 1000)
            if probe_resp.ok:
                results["chat_key"] = {"ok": True, "msg": f"Chat endpoint responding ({ms} ms)"}
            elif probe_resp.status_code == 401:
                results["chat_key"] = {"ok": False, "msg": "Chat key rejected (401) — key may be expired or wrong type (must be CyM_... not cymk_...)"}
            elif probe_resp.status_code == 400:
                try:
                    detail = probe_resp.json().get("detail", probe_resp.text[:120])
                except Exception:
                    detail = probe_resp.text[:120]
                results["chat_key"] = {"ok": False, "msg": f"Chat endpoint returned 400 — CyMind security policy blocking: {detail}"}
            elif probe_resp.status_code == 429:
                results["chat_key"] = {"ok": False, "msg": "Chat rate limit exceeded (429) — service account may be throttled by CyMind behavior monitor"}
            else:
                results["chat_key"] = {"ok": False, "msg": f"Chat endpoint returned HTTP {probe_resp.status_code} ({ms} ms)"}
        except Exception as e:
            ms = int((time.monotonic() - t0) * 1000)
            results["chat_key"] = {"ok": False, "msg": f"Chat probe failed: {e}"}
    else:
        results["chat_key"] = {
            "ok":  bool(chat_key),
            "msg": "Chat API key set (CyMind unreachable — chat endpoint not probed)",
        }

    overall = all(v["ok"] for v in results.values())
    return jsonify({"ok": overall, "results": results})


def _fetch_siem_context_block() -> str:
    """
    Fetch a live SIEM snapshot from the local correlation engine and format it
    as a '--- LIVE SIEM DATA ---' block for injection into the CyMind system
    prompt.  Returns empty string when the engine is unreachable.
    """
    import datetime as _dt
    engine_url = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100").rstrip("/")
    _t = 3  # short per-call timeout

    ctx = {}
    try:
        r = http_requests.get(f"{engine_url}/stats", timeout=_t)
        if r.ok:
            ctx["stats"] = r.json()
    except Exception:
        pass
    try:
        # Fetch investigating incidents first (the dominant active status in
        # this deployment); then fall back to a broader query if that returns
        # nothing (covers the early 'open' triage state).
        _active: list = []
        for _status in ("investigating", "open"):
            try:
                _r = http_requests.get(f"{engine_url}/incidents",
                                       params={"status": _status, "limit": 50},
                                       timeout=_t)
                if _r.ok:
                    _raw = _r.json()
                    _rows = _raw if isinstance(_raw, list) else _raw.get("incidents", [])
                    # Deduplicate by ID across both queries
                    seen_ids = {i["id"] for i in _active}
                    _active += [i for i in _rows if i.get("id") not in seen_ids]
            except Exception:
                pass
        if _active:
            ctx["open_incidents"] = _active
    except Exception:
        pass
    try:
        r = http_requests.get(f"{engine_url}/risk-scores",
                              params={"level": "high", "limit": 10}, timeout=_t)
        if r.ok:
            ctx["high_risk_entities"] = r.json()
    except Exception:
        pass
    try:
        r = http_requests.get(f"{engine_url}/ueba/users",
                              params={"has_anomaly": "true", "limit": 10}, timeout=_t)
        if r.ok:
            ctx["ueba_anomalies"] = r.json()
    except Exception:
        pass

    if not ctx:
        return ""

    now = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "\n--- LIVE SIEM DATA ---",
        f"Source: CyCentra 360 (direct) | Timestamp: {now}",
        "",
        "## Incident ID Formats",
        "| Format | Source | Example |",
        "|---|---|---|",
        "| INC-XXXXX | SIEM correlation engine (Wazuh alerts → correlated) | INC-00708 |",
        "| ASM-NNNNN | ASM attack surface scan (stored in RAG memory, 5-char hex) | ASM-1A2B3 |",
        "[INSTRUCTION: ASM IDs always use the short 5-char hex format ASM-NNNNN."
        " If you encounter legacy long-format IDs (e.g. ASM-DOMAIN-MODULE-N) in RAG memory,"
        " treat them as historical data but note the new format is ASM-NNNNN."
        " When presenting incidents from either source, always use the same"
        " table format: ID | Severity | Status | Summary | Affected Assets."
        " Never mix up the two ID namespaces or claim one is the other.]",
        "",
    ]

    if "stats" in ctx:
        s = ctx["stats"]
        lines += [
            "## Overview",
            f"- Total alerts (24h): {s.get('total_alerts_24h', 'N/A')}",
            f"- Active incidents (open + investigating): {s.get('open_incidents', 'N/A')}",
            f"- Active agents: {s.get('active_agents', 'N/A')}",
            f"- Critical alerts: {s.get('critical_alerts', 'N/A')}",
            "",
        ]

    if ctx.get("open_incidents"):
        raw  = ctx["open_incidents"]
        rows = raw if isinstance(raw, list) else raw.get("incidents", raw.get("data", []))
        # Strip any closed/resolved that slipped through
        rows = [i for i in rows
                if i.get("status") not in ("resolved", "false_positive", "closed")]
        if rows:
            lines += ["## Active Incidents (SIEM — INC-XXXXX format, open + investigating)",
                      "| ID | Summary | Severity | Risk | Status | Affected Users |",
                      "|---|---|---|---|---|---|"]
            for inc in rows[:20]:
                _llm = inc.get("llm_summary") or ""
                _cats = ", ".join((inc.get("categories") or [])[:3])
                _agents = ", ".join((inc.get("affected_agents") or [])[:2]) or "—"
                _users  = ", ".join((inc.get("affected_users")  or [])[:3]) or "—"
                _summary = (_llm[:80] + "…") if len(_llm) > 80 else (_llm or _cats or "—")
                lines.append(
                    f"| {inc.get('id', '?')} "
                    f"| {_summary} "
                    f"| {inc.get('severity', '?')} "
                    f"| {inc.get('risk_score', '?')} "
                    f"| {inc.get('status', '?')} "
                    f"| {_users} |"
                )
            lines.append("")

    if ctx.get("high_risk_entities"):
        raw  = ctx["high_risk_entities"]
        rows = raw if isinstance(raw, list) else raw.get("entities", raw.get("data", []))
        if rows:
            lines += ["## High-Risk Entities",
                      "| Entity | Type | Risk Score | Last Seen |",
                      "|---|---|---|---|"]
            for ent in rows[:10]:
                lines.append(
                    f"| {ent.get('entity', ent.get('name', '?'))} "
                    f"| {ent.get('type', '?')} "
                    f"| {ent.get('risk_score', '?')} "
                    f"| {ent.get('last_seen', '?')} |"
                )
            lines.append("")

    if ctx.get("ueba_anomalies"):
        raw  = ctx["ueba_anomalies"]
        rows = raw if isinstance(raw, list) else raw.get("users", raw.get("data", []))
        if rows:
            lines += ["## UEBA Anomalies",
                      "| User | Anomaly Type | Score | Last Activity |",
                      "|---|---|---|---|"]
            for u in rows[:10]:
                lines.append(
                    f"| {u.get('username', u.get('user', '?'))} "
                    f"| {u.get('anomaly_type', u.get('type', '?'))} "
                    f"| {u.get('score', u.get('risk_score', '?'))} "
                    f"| {u.get('last_activity', u.get('last_seen', '?'))} |"
                )
            lines.append("")

    lines += [
        "[SYSTEM INSTRUCTION — CRITICAL: The data above is factual and complete for"
        " this snapshot. Do NOT extrapolate, estimate, or fabricate any incident IDs,"
        " descriptions, usernames, IP addresses, CVEs, or counts beyond what is shown."
        " If the user asks about a specific user, host, or entity not visible in this"
        " snapshot, their data will be injected below (see 'Incidents for user/entity')."
        " If no such section appears, say you cannot find that entity in current data"
        " — NEVER invent incidents."
        " IMPORTANT — ACTIONS: You MUST NOT say that you have closed, resolved,"
        " blocked, quarantined, disabled, marked, or otherwise changed the state of"
        " any incident, IP, user, or asset unless the user has already clicked"
        " 'Execute' on a confirmation card and a success message was shown."
        " If the user asks you to close/resolve/block/mark something, respond only"
        " that you are preparing the action for confirmation — never claim it is done.]",
        "",
        "--- END LIVE SIEM DATA ---",
        "",
    ]
    return "\n".join(lines)


# ── Agentic chat: intent detection + action execution ─────────────────────────
#
# When CyMind chat detects an action intent in the user's message, the Flask
# proxy intercepts the request and emits a synthetic SSE stream with:
#   1. A text explanation of what will happen
#   2. A structured `action_pending` event for the UI to render a confirm card
#
# The user must click Execute in the confirm card.  The browser then POSTs to
# /api/cymind/action/execute.  That endpoint runs the action and returns JSON.
# Normal conversational messages pass through to CyMind unchanged.

import re as _re

# ── Regex patterns for action intent detection ────────────────────────────────

_IP_RE      = _re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_INC_RE     = _re.compile(r'\b(INC-\d+)\b', _re.IGNORECASE)

# ── Entity-aware context enrichment ──────────────────────────────────────────
# Detect "incidents for/related to/by/about user X" in chat messages so the
# proxy can pre-fetch those incidents and inject real data before forwarding.

_ENTITY_IN_MSG_RE = _re.compile(
    r'\b(?:user|account|analyst|by|for|related to|linked to|about|regarding|involving)\s+'
    r'["\']?(\w[\w.\-@+]{1,60})["\']?',
    _re.IGNORECASE,
)
_ENTITY_SKIP = {
    "the", "a", "an", "me", "us", "all", "any", "this", "that",
    "open", "high", "low", "critical", "medium", "admin", "user",
    "it", "its", "which", "who", "whom",
}


def _fetch_entity_incidents_block(message: str) -> str:
    """
    If `message` references a specific user/entity, query the correlation engine
    for that entity's incidents and return a formatted context block to append to
    the SIEM context.  Returns empty string if no entity found or no data.
    """
    m = _ENTITY_IN_MSG_RE.search(message)
    if not m:
        return ""
    entity = m.group(1).strip()
    if entity.lower() in _ENTITY_SKIP:
        return ""

    engine_url = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100").rstrip("/")
    try:
        r = http_requests.get(
            f"{engine_url}/incidents",
            params={"user": entity, "limit": 20},
            timeout=4,
        )
        if not r.ok:
            return ""
        data = r.json()
    except Exception:
        return ""

    total     = data.get("total", 0)
    incidents = data.get("incidents", [])

    lines = [
        "",
        f"## Incidents for entity '{entity}' (exact DB query — {total} total match)",
    ]
    if total == 0:
        lines += [
            f"No incidents in the database involve '{entity}'.",
            "[INSTRUCTION: The user asked about this entity. Database returned 0 results."
            " Do NOT invent any incidents. Clearly tell the user no incidents were found.]",
        ]
    else:
        lines += [
            "| ID | Severity | Status | Categories | Risk | Affected Users |",
            "|---|---|---|---|---|---|",
        ]
        for inc in incidents[:20]:
            cats  = ", ".join((inc.get("categories") or [])[:3]) or "—"
            users = ", ".join((inc.get("affected_users") or [])[:4]) or "—"
            lines.append(
                f"| {inc.get('id', '?')} "
                f"| {inc.get('severity', '?')} "
                f"| {inc.get('status', '?')} "
                f"| {cats} "
                f"| {inc.get('risk_score', '?')} "
                f"| {users} |"
            )
        lines += [
            "",
            f"[INSTRUCTION: The table above lists ALL {total} incidents involving"
            f" '{entity}'. These are exact database records. Do NOT add or modify"
            " any detail. Present this table to the user as-is.]",
        ]
    lines.append("")
    return "\n".join(lines)


def _fetch_incident_detail_block(message: str) -> str:
    """
    Scan `message` for explicit incident IDs (INC-XXXXX).
    For each found, fetch full details from the correlation engine and inject
    a structured block so CyMind never has to guess.
    Returns empty string if no INC-ID found or engine unreachable.
    """
    ids = _re.findall(r'\b(INC-\d+)\b', message, _re.IGNORECASE)
    if not ids:
        return ""

    engine_url = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100").rstrip("/")
    blocks: list[str] = []
    for inc_id in dict.fromkeys(ids):           # deduplicate, preserve order
        try:
            r = http_requests.get(
                f"{engine_url}/incidents/{inc_id.upper()}",
                timeout=4,
            )
        except Exception:
            blocks.append(
                f"\n## Incident {inc_id}\n"
                "[INSTRUCTION: Could not reach the correlation engine to fetch"
                f" {inc_id}. Tell the user the engine is temporarily unavailable"
                " — do NOT fabricate any details.]\n"
            )
            continue

        if r.status_code == 404:
            blocks.append(
                f"\n## Incident {inc_id}\n"
                f"[INSTRUCTION: {inc_id} does NOT exist in the database."
                " Tell the user exactly that — do NOT invent any details.]\n"
            )
            continue

        if not r.ok:
            blocks.append(
                f"\n## Incident {inc_id}\n"
                f"[INSTRUCTION: Engine returned HTTP {r.status_code} for {inc_id}."
                " Inform the user and do NOT fabricate.]\n"
            )
            continue

        inc = r.json()
        try:
            cats    = ", ".join((inc.get("categories")    or [])[:5])  or "—"
            users   = ", ".join((inc.get("affected_users") or [])[:5]) or "—"
            agents  = ", ".join((inc.get("affected_agents") or [])[:5]) or "—"
            ips     = ", ".join((inc.get("src_ips") or [])[:5])        or "—"
            tactics = ", ".join((inc.get("mitre_tactics") or [])[:5])  or "—"
            mitres  = ", ".join((inc.get("mitre_ids")    or [])[:5])   or "—"
            rules   = "; ".join(
                (r_.get("name", r_.get("id", "?")) if isinstance(r_, dict) else str(r_))
                for r_ in (inc.get("correlated_rules") or [])[:3]
            ) or "—"
            # ueba_flags stores plain strings (anomaly type names), not dicts
            ueba = "; ".join(
                (u_.get("type", "?") if isinstance(u_, dict) else str(u_))
                for u_ in (inc.get("ueba_flags") or [])[:3]
            ) or "—"
            summary     = inc.get("llm_summary")     or "—"
            remediation = inc.get("llm_remediation") or "—"

            # ── Format top alerts (sorted by rule_level desc, capped at 15) ──
            raw_alerts = inc.get("alerts") or []
            sorted_alerts = sorted(
                raw_alerts,
                key=lambda a: int(a.get("rule_level") or 0),
                reverse=True,
            )[:15]

            alert_lines: list[str] = []
            for a in sorted_alerts:
                ts       = (a.get("timestamp") or "")[:16].replace("T", " ")
                agent    = a.get("agent_name") or a.get("agent_id") or "?"
                user     = a.get("username") or "—"
                rule     = a.get("rule_desc") or "?"
                mitre    = a.get("mitre_id") or "—"
                src_ip   = a.get("src_ip") or "—"
                fpath    = a.get("file_path") or "—"
                lvl      = a.get("rule_level") or "?"
                alert_lines.append(
                    f"  - [{ts}] agent={agent} user={user} level={lvl}"
                    f" rule=\"{rule}\" mitre={mitre} src_ip={src_ip} file={fpath}"
                )

            alerts_block = (
                "\n".join(alert_lines)
                if alert_lines
                else "  (no alerts linked to this incident)"
            )

            b = [
                f"\n## Incident {inc_id.upper()} — Full Detail",
                f"- **Severity**: {inc.get('severity', '?')}",
                f"- **Status**: {inc.get('status', '?')}",
                f"- **Risk Score**: {inc.get('risk_score', '?')}",
                f"- **First Seen**: {inc.get('first_seen', '?')}",
                f"- **Last Seen**: {inc.get('last_seen', '?')}",
                f"- **Alert Count**: {inc.get('alert_count', '?')}",
                f"- **Categories**: {cats}",
                f"- **Affected Users**: {users}",
                f"- **Affected Agents**: {agents}",
                f"- **Source IPs**: {ips}",
                f"- **MITRE Tactics**: {tactics}",
                f"- **MITRE IDs**: {mitres}",
                f"- **Kill Chain Stage**: {inc.get('kill_chain_stage_name') or inc.get('kill_chain_stage', '?')}",
                f"- **Correlated Rules**: {rules}",
                f"- **UEBA Flags**: {ueba}",
                f"- **Assigned To**: {inc.get('assigned_to') or 'Unassigned'}",
                f"- **Case Opened**: {inc.get('case_opened_at') or 'None'}",
                f"- **FP Probability**: {inc.get('fp_probability', '?')}%",
                "",
                f"**AI Summary**: {summary}",
                "",
                f"**Recommended Remediation**: {remediation}",
                "",
                f"### Linked Alerts (top {len(sorted_alerts)} by severity)",
                alerts_block,
                "",
                "[INSTRUCTION: The data above is the complete, exact database record for"
                f" {inc_id.upper()}, including the raw alerts with per-event user,"
                " agent, MITRE technique, rule, source IP, and file path."
                " Use the alerts to answer specific questions about which user was"
                " involved, which technique was used, and what exactly happened."
                " Present it to the user accurately — do NOT fabricate any field.]",
            ]
            blocks.append("\n".join(b))
        except Exception as _parse_err:
            blocks.append(
                f"\n## Incident {inc_id.upper()}\n"
                f"[INSTRUCTION: Incident fetched but detail parsing failed: {_parse_err}."
                " Present whatever is known and do NOT fabricate missing fields.]\n"
            )

    return "\n".join(blocks)


_AGENT_RE   = _re.compile(r'\bagent[_\s]?(?:id[_\s]?)?([0-9a-zA-Z]+)\b', _re.IGNORECASE)
_DOMAIN_RE  = _re.compile(r'\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})\b')
_USER_RE    = _re.compile(r"""(?:user|account|username)[s]?\s+["\']?([a-zA-Z0-9._@+-]+)["\']?""", _re.IGNORECASE)
_CRON_RE    = _re.compile(r'every\s+(\w+)', _re.IGNORECASE)

# Exclusion list — domains that are not scan targets when they appear in chat
_DOMAIN_EXCLUSIONS = frozenset({"example.com", "localhost", "cymind", "cycentra"})


def _detect_action_intent(message: str) -> dict | None:
    """
    Analyse a user message for a concrete action intent.
    Returns a dict with {type, params, label, risk, summary, reversible} or None.
    Requires explicit action verbs — casual mentions of IPs/IDs never trigger.
    """
    msg = message.strip()
    lm  = msg.lower()

    # ── 1. Block IP ──────────────────────────────────────────────────────────
    if _re.search(r'\bblock\b.*\bip\b|\bdrop\b.*\bip\b|\bfirewall.drop\b', lm):
        ips     = _IP_RE.findall(msg)
        agents  = _AGENT_RE.findall(msg)
        if ips:
            ip        = ips[0]
            agent_id  = agents[0] if agents else "000"
            return {
                "type":       "block_ip",
                "params":     {"agent_id": agent_id, "ip": ip},
                "label":      f"Block IP {ip} on agent {agent_id}",
                "risk":       "high",
                "summary":    f"This will execute a **firewall-drop** active-response on Wazuh agent **{agent_id}**, permanently blocking outbound/inbound traffic from **{ip}**. The rule persists until manually removed from the firewall.",
                "reversible": False,
            }

    # ── 2. Disable user account ──────────────────────────────────────────────
    if _re.search(r'\bdisable\b.*(?:user|account)\b|\bblock\b.*(?:user|account)\b', lm):
        users   = _USER_RE.findall(msg)
        agents  = _AGENT_RE.findall(msg)
        if users:
            username = users[0]
            agent_id = agents[0] if agents else "000"
            return {
                "type":       "disable_user",
                "params":     {"agent_id": agent_id, "username": username},
                "label":      f"Disable account '{username}' on agent {agent_id}",
                "risk":       "high",
                "summary":    f"This will execute a **disable-account** active-response on Wazuh agent **{agent_id}**, locking the OS account **{username}**. The account must be re-enabled manually.",
                "reversible": False,
            }

    # ── 3. Restart Wazuh agent ───────────────────────────────────────────────
    if _re.search(r'\brestart\b.*(?:agent|wazuh)\b|\breboot\b.*(?:agent|wazuh)\b', lm):
        agents = _AGENT_RE.findall(msg)
        if agents:
            agent_id = agents[0]
            return {
                "type":       "restart_agent",
                "params":     {"agent_id": agent_id},
                "label":      f"Restart Wazuh agent {agent_id}",
                "risk":       "medium",
                "summary":    f"This will send a **restart-wazuh** active-response command to agent **{agent_id}**. The agent will briefly disconnect and reconnect. No data loss.",
                "reversible": True,
            }

    # ── 4. Close / resolve specific incident ────────────────────────────────
    if _re.search(r'\b(?:close|resolve|close\s+out)\b', lm) and not _re.search(r'\bfals', lm):
        incs = _INC_RE.findall(msg)
        if incs:
            inc_id = incs[0].upper()
            return {
                "type":       "close_incident",
                "params":     {"incident_id": inc_id,
                               "comment":     f"Closed via CyMind agentic chat"},
                "label":      f"Close incident {inc_id}",
                "risk":       "medium",
                "summary":    f"This will transition incident **{inc_id}** to **resolved** status with an audit comment. The incident will be archived after {30} days.",
                "reversible": True,
            }

    # ── 5. Mark specific incident as false positive ──────────────────────────
    if _re.search(r'\b(?:false.positive|mark.*fp|mark.*false)\b', lm):
        incs = _INC_RE.findall(msg)
        if incs:
            inc_id = incs[0].upper()
            return {
                "type":       "mark_false_positive",
                "params":     {"incident_id": inc_id,
                               "comment":     "Marked as false positive via CyMind agentic chat"},
                "label":      f"Mark {inc_id} as false positive",
                "risk":       "medium",
                "summary":    f"This will transition incident **{inc_id}** to **false_positive** status. The reason will be logged in the audit trail.",
                "reversible": True,
            }

    # ── 6. Bulk close all false positives ────────────────────────────────────
    if _re.search(r'\b(?:close|mark|clear)\s+all\b.{0,30}(?:false.positive|fp)\b'
                  r'|\b(?:false.positive|fp)\b.{0,30}\b(?:close|mark|clear)\s+all\b',
                  lm, _re.IGNORECASE):
        # Fetch current open incident IDs to show in the confirm card
        engine_url = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100").rstrip("/")
        inc_ids: list[str] = []
        try:
            r = http_requests.get(f"{engine_url}/incidents",
                                  params={"limit": 200}, timeout=4)
            if r.ok:
                data = r.json()
                rows = data if isinstance(data, list) else data.get("incidents", [])
                inc_ids = [
                    row.get("id", "?")
                    for row in rows
                    if row.get("status") not in ("resolved", "false_positive", "closed")
                ]
        except Exception:
            pass
        count = len(inc_ids)
        return {
            "type":       "bulk_mark_false_positive",
            "params":     {"incident_ids": inc_ids,
                           "comment":      "Bulk false positive via CyMind agentic chat"},
            "label":      f"Mark {count} open incident{'s' if count != 1 else ''} as false positive",
            "risk":       "high",
            "summary":    f"This will transition **{count} open incident{'s' if count != 1 else ''}** to **false_positive** status in one operation. Each transition is audit-logged. Incidents will be archived after 30 days. **This cannot be undone in bulk.**",
            "reversible": False,
        }

    # ── 7. Trigger ASM scan ───────────────────────────────────────────────────
    if _re.search(r'\b(?:run|start|trigger|launch|kick\s+off)\b.{0,20}(?:scan|asm)\b'
                  r'|\bscan\b.{0,10}(?:for|on|the\s+domain)\b', lm):
        domains = [d for d in _DOMAIN_RE.findall(msg) if d.lower() not in _DOMAIN_EXCLUSIONS]
        if domains:
            domain    = domains[0].lower()
            scan_type = "standard"
            if "deep" in lm:
                scan_type = "deep"
            elif "passive" in lm:
                scan_type = "passive"
            return {
                "type":       "trigger_scan",
                "params":     {"domain": domain, "scan_type": scan_type,
                               "include_subdomains": "subdomain" not in lm or "no subdomain" not in lm},
                "label":      f"Run {scan_type} ASM scan on {domain}",
                "risk":       "low",
                "summary":    f"This will start a **{scan_type}** attack surface scan against **{domain}**. The scan runs in the background and results appear in the Asset Inventory tab when complete.",
                "reversible": True,
            }

    # ── 8. Add scan schedule ─────────────────────────────────────────────────
    if _re.search(r'\b(?:schedule|add.+schedule|set.+up.+schedule|recurring)\b.{0,30}(?:scan|asm)\b'
                  r'|\b(?:scan|asm)\b.{0,30}\b(?:daily|weekly|hourly|every\s+\w+)\b', lm):
        domains = [d for d in _DOMAIN_RE.findall(msg) if d.lower() not in _DOMAIN_EXCLUSIONS]
        if domains:
            domain    = domains[0].lower()
            # Parse cron hint from message
            schedule  = {"type": "cron", "hour": "2", "minute": "0"}
            if "hourly" in lm:
                schedule = {"type": "interval", "seconds": 3600}
            elif "weekly" in lm:
                schedule = {"type": "cron", "hour": "2", "minute": "0", "day_of_week": "mon"}
            elif _re.search(r'every\s+(\d+)\s+hour', lm):
                m = _re.search(r'every\s+(\d+)\s+hour', lm)
                schedule = {"type": "interval", "seconds": int(m.group(1)) * 3600}
            elif _re.search(r'at\s+(\d{1,2})(?::(\d{2}))?', lm):
                m = _re.search(r'at\s+(\d{1,2})(?::(\d{2}))?', lm)
                schedule = {"type": "cron", "hour": m.group(1), "minute": m.group(2) or "0"}
            scan_type = "standard"
            if "deep" in lm:
                scan_type = "deep"
            elif "passive" in lm:
                scan_type = "passive"
            from blueprints.scheduler.routes import _describe_schedule as _ds
            desc = _ds(schedule)
            return {
                "type":       "add_schedule",
                "params":     {"domain": domain, "scan_type": scan_type, "schedule": schedule,
                               "name":   f"Scheduled {scan_type} scan — {domain}",
                               "include_subdomains": True},
                "label":      f"Schedule {scan_type} scan of {domain} — {desc}",
                "risk":       "low",
                "summary":    f"This will create a recurring scheduled job to run a **{scan_type}** ASM scan of **{domain}** **{desc}**. You can view and manage all scheduled jobs in the System Settings → Scheduler tab.",
                "reversible": True,
            }

    # ── 9. Assign incident to analyst ────────────────────────────────────────
    if _re.search(r'\bassign\b.{0,30}(?:incident|inc)\b|\bhandled?\s+by\b.{0,20}(?:incident|inc)\b', lm):
        incs   = _INC_RE.findall(msg)
        emails = _re.findall(r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}', msg)
        names  = _re.findall(r'\bto\s+([A-Za-z][a-zA-Z0-9._-]{1,30})\b', msg)
        if incs and (emails or names):
            inc_id   = incs[0].upper()
            assignee = emails[0] if emails else names[0]
            return {
                "type":       "assign_incident",
                "params":     {"incident_id": inc_id, "assigned_to": assignee},
                "label":      f"Assign {inc_id} to {assignee}",
                "risk":       "low",
                "summary":    f"This will set the **assigned_to** field on incident **{inc_id}** to **{assignee}** and log the change in the audit trail.",
                "reversible": True,
            }

    # ── 10. Add analyst note to incident ─────────────────────────────────────
    if _re.search(r'\badd\b.{0,20}(?:note|comment|annotation)\b.{0,30}(?:incident|inc)\b'
                  r'|\bnote\b.{0,30}\b(INC-\d+)\b', lm):
        incs = _INC_RE.findall(msg)
        # Extract the note text — everything after "note:" / "comment:" or after the INC id
        note_match = _re.search(
            r'(?:note|comment|annotation)[s]?\s*[:\-]?\s*["\']?(.+?)(?:\s+(?:to|on|for)\s+(?:INC-\d+|incident))?$',
            msg, _re.IGNORECASE,
        )
        note = note_match.group(1).strip().strip('"\'') if note_match else ""
        if not note:
            note = f"Analyst note added via CyMind chat"
        if incs:
            inc_id = incs[0].upper()
            return {
                "type":       "add_incident_note",
                "params":     {"incident_id": inc_id, "note": note},
                "label":      f"Add note to {inc_id}",
                "risk":       "low",
                "summary":    f"This will append an analyst note to incident **{inc_id}** and write an audit entry. Note: *\"{note[:120]}\"*",
                "reversible": True,
            }

    # ── 11. Escalate incident ─────────────────────────────────────────────────
    if _re.search(r'\bescalat\b.{0,30}(?:incident|inc)\b|\brais[e]?\s+(?:severity|priority)\b.{0,30}(?:INC-\d+)', lm):
        incs = _INC_RE.findall(msg)
        if incs:
            inc_id = incs[0].upper()
            return {
                "type":       "escalate_incident",
                "params":     {"incident_id": inc_id,
                               "comment":     f"Escalated via CyMind agentic chat"},
                "label":      f"Escalate incident {inc_id}",
                "risk":       "medium",
                "summary":    f"This will escalate incident **{inc_id}** — bump severity and open a case if not already open.",
                "reversible": True,
            }

    # ── 12. Open CyCases investigation case ─────────────────────────────────
    if _re.search(r'\b(?:create|open|raise)\b.{0,20}(?:case|investigation)\b', lm):
        incs = _INC_RE.findall(msg)
        if incs:
            inc_id = incs[0].upper()
            return {
                "type":       "open_case",
                "params":     {"incident_id": inc_id},
                "label":      f"Open case for {inc_id}",
                "risk":       "low",
                "summary":    f"This will open a CyCases investigation for incident **{inc_id}**.",
                "reversible": True,
            }

    # ── 13. Enrich IOC ───────────────────────────────────────────────────────
    if _re.search(r'\benrich\b|\blook.?up\b.{0,20}(?:ioc|indicator|ip|hash|domain)\b'
                  r'|\bmisp\b.{0,20}(?:check|search|query)\b', lm):
        ips     = _IP_RE.findall(msg)
        hashes  = _re.findall(r'\b[0-9a-fA-F]{64}\b', msg)
        domains_raw = [d for d in _DOMAIN_RE.findall(msg) if d.lower() not in _DOMAIN_EXCLUSIONS]
        if ips:
            ioc_value, ioc_type = ips[0], "ip"
        elif hashes:
            ioc_value, ioc_type = hashes[0], "sha256"
        elif domains_raw:
            ioc_value, ioc_type = domains_raw[0], "domain"
        else:
            ioc_value = ioc_type = None
        if ioc_value:
            return {
                "type":       "enrich_ioc",
                "params":     {"ioc_value": ioc_value, "ioc_type": ioc_type},
                "label":      f"Enrich {ioc_type.upper()} {ioc_value}",
                "risk":       "low",
                "summary":    f"This will query MISP and the entity risk score database for **{ioc_value}** ({ioc_type.upper()}). Returns threat level, event tags, and current risk score. Read-only — no changes to the environment.",
                "reversible": True,
            }

    # ── 14. Trigger CySOAR playbook ──────────────────────────────────────────
    if _re.search(r'\b(?:trigger|run|execute|fire|activate)\b.{0,20}(?:soar|playbook|flow|node.?red)\b'
                  r'|\b(?:soar|playbook|flow)\b.{0,20}\b(?:trigger|run|execute|fire)\b', lm):
        incs   = _INC_RE.findall(msg)
        # Try to extract a playbook/flow name if quoted
        flow_m = _re.search(r'["\']([^"\']{3,60})["\']', msg)
        flow   = flow_m.group(1) if flow_m else None
        inc_id = incs[0].upper() if incs else None
        if inc_id or flow:
            label_parts = []
            if flow:
                label_parts.append(f"'{flow}'")
            if inc_id:
                label_parts.append(f"for {inc_id}")
            label = "Trigger CySOAR playbook " + " ".join(label_parts)
            params: dict = {}
            if inc_id:
                params["incident_id"] = inc_id
            if flow:
                params["flow_name"] = flow
            return {
                "type":       "trigger_soar_playbook",
                "params":     params,
                "label":      label,
                "risk":       "medium",
                "summary":    (
                    f"This will POST{' incident **' + inc_id + '** metadata' if inc_id else ' a trigger payload'} "
                    f"to the CySOAR (Node-RED) webhook{' for playbook **' + flow + '**' if flow else ''}. "
                    "The SOAR flow will run in Node-RED and any actions taken will be logged against the incident."
                ),
                "reversible": True,
            }

    return None


def _stream_action_confirmation(action: dict):
    """
    Return a Flask streaming response that emits:
      - Text tokens explaining the action
      - An `action_pending` SSE event for the confirm card
      - [DONE]
    """
    label    = action.get("label", "Execute action")
    summary  = action.get("summary", "")
    risk     = action.get("risk", "medium")
    rev      = action.get("reversible", True)
    rev_str  = "reversible" if rev else "**irreversible**"

    _RISK_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🔴"}
    risk_badge  = _RISK_EMOJI.get(risk, "⚪")

    intro_tokens = [
        f"I can execute that action for you.\n\n",
        f"**{label}**\n\n",
        f"{summary}\n\n",
        f"Risk level: {risk_badge} **{risk.upper()}** · {rev_str.capitalize()}\n\n",
        "Confirm or cancel below to proceed.",
    ]

    def _gen():
        import json as _j
        for tok in intro_tokens:
            yield f"data: {_j.dumps({'token': tok, 'done': False})}\n\n"
        yield f"data: {_j.dumps({'action_pending': action})}\n\n"
        yield "data: [DONE]\n\n"

    from flask import current_app
    return current_app.response_class(
        _gen(),
        status=200,
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


def _write_action_audit(
    engine_url: str,
    incident_id: str,
    action: str,
    comment: str = "",
    actor: str = "analyst",
    from_status: str | None = None,
    to_status: str | None = None,
    extra: dict | None = None,
) -> None:
    """
    Write an audit log entry for a confirmed agentic action.

    Posts to the engine's /audit endpoint (direct loopback — no auth needed).
    All failures are silently swallowed so audit writes never block action flow.
    """
    try:
        http_requests.post(
            f"{engine_url}/audit",
            json={
                "entity_type": "incident",
                "entity_id":   incident_id,
                "action":      action,
                "from_status": from_status,
                "to_status":   to_status,
                "comment":     comment,
                "actor":       actor,
                "extra":       extra or {},
            },
            timeout=4,
        )
    except Exception:
        pass  # audit write failure must never block the action itself


def _execute_agentic_action(action_type: str, params: dict, actor_email: str) -> dict:
    """
    Execute a confirmed agentic action.
    Returns {success: bool, message: str, data: dict|None}.
    Runs inside Flask request context — can import blueprint helpers.
    """
    engine = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100").rstrip("/")
    _t = 15  # timeout

    # ── Block IP (Wazuh firewall-drop) ────────────────────────────────────────
    if action_type == "block_ip":
        agent_id = params.get("agent_id", "")
        ip       = params.get("ip", "")
        if not agent_id or not ip:
            return {"success": False, "message": "Missing agent_id or ip in action params"}
        try:
            r = http_requests.post(
                f"{engine}/active-response",
                json={"agent_id": agent_id, "command": "firewall-drop",
                      "arguments": [ip]},
                timeout=_t,
            )
            if r.ok:
                _write_action_audit(engine, agent_id, "block_ip",
                                    comment=f"IP {ip} blocked via agentic chat",
                                    actor=actor_email,
                                    extra={"ip": ip, "command": "firewall-drop"})
                return {"success": True, "message": f"IP **{ip}** blocked on agent **{agent_id}**.",
                        "data": r.json()}
            return {"success": False,
                    "message": f"Engine returned HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"success": False, "message": f"Could not reach engine: {e}"}

    # ── Disable user account (Wazuh disable-account) ─────────────────────────
    elif action_type == "disable_user":
        agent_id = params.get("agent_id", "")
        username = params.get("username", "")
        if not agent_id or not username:
            return {"success": False, "message": "Missing agent_id or username"}
        try:
            r = http_requests.post(
                f"{engine}/active-response",
                json={"agent_id": agent_id, "command": "disable-account",
                      "arguments": [username]},
                timeout=_t,
            )
            if r.ok:
                _write_action_audit(engine, agent_id, "disable_user",
                                    comment=f"Account {username} disabled via agentic chat",
                                    actor=actor_email,
                                    extra={"username": username, "command": "disable-account"})
                return {"success": True,
                        "message": f"Account **{username}** disabled on agent **{agent_id}**.",
                        "data": r.json()}
            return {"success": False,
                    "message": f"Engine returned HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"success": False, "message": f"Could not reach engine: {e}"}

    # ── Restart Wazuh agent ───────────────────────────────────────────────────
    elif action_type == "restart_agent":
        agent_id = params.get("agent_id", "")
        if not agent_id:
            return {"success": False, "message": "Missing agent_id"}
        try:
            r = http_requests.post(
                f"{engine}/active-response",
                json={"agent_id": agent_id, "command": "restart-wazuh", "arguments": []},
                timeout=_t,
            )
            if r.ok:
                _write_action_audit(engine, agent_id, "restart_agent",
                                    comment="Agent restarted via agentic chat",
                                    actor=actor_email,
                                    extra={"command": "restart-wazuh"})
                return {"success": True,
                        "message": f"Restart command sent to Wazuh agent **{agent_id}**.",
                        "data": r.json()}
            return {"success": False,
                    "message": f"Engine returned HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"success": False, "message": f"Could not reach engine: {e}"}

    # ── Close / resolve a specific incident ──────────────────────────────────
    elif action_type == "close_incident":
        inc_id  = params.get("incident_id", "")
        comment = params.get("comment") or f"Closed via CyMind agentic chat by {actor_email}"
        if not inc_id:
            return {"success": False, "message": "Missing incident_id"}
        try:
            # Fetch current status first so audit from_status is accurate
            cur = http_requests.get(f"{engine}/incidents/{inc_id}", timeout=5)
            if cur.status_code == 404:
                return {"success": False,
                        "message": f"Incident **{inc_id}** not found in the database."}
            from_st = cur.json().get("status", "open") if cur.ok else "open"

            r = http_requests.post(
                f"{engine}/incidents/{inc_id}/transition",
                json={"to_status": "resolved", "comment": comment, "actor": actor_email},
                timeout=_t,
            )
            if r.ok:
                _write_action_audit(engine, inc_id, "status_change",
                                    comment=comment, actor=actor_email,
                                    from_status=from_st, to_status="resolved",
                                    extra={"source": "agentic_chat"})
                updated = r.json()
                return {"success": True,
                        "message": (
                            f"Incident **{inc_id}** has been **resolved**. "
                            f"Previous status was `{from_st}`. "
                            "The Incidents list will refresh automatically."
                        ),
                        "data": updated,
                        "new_status": updated.get("status", "resolved")}
            # Surface the exact engine error so analysts know what went wrong
            try:
                detail = r.json().get("detail", r.text[:300])
            except Exception:
                detail = r.text[:300]
            return {"success": False,
                    "message": f"Could not transition {inc_id}: {detail}"}
        except Exception as e:
            return {"success": False, "message": f"Could not reach engine: {e}"}

    # ── Mark single incident as false positive ────────────────────────────────
    elif action_type == "mark_false_positive":
        inc_id  = params.get("incident_id", "")
        comment = params.get("comment") or f"False positive — via CyMind agentic chat by {actor_email}"
        if not inc_id:
            return {"success": False, "message": "Missing incident_id"}
        try:
            cur = http_requests.get(f"{engine}/incidents/{inc_id}", timeout=5)
            if cur.status_code == 404:
                return {"success": False,
                        "message": f"Incident **{inc_id}** not found in the database."}
            from_st = cur.json().get("status", "open") if cur.ok else "open"

            r = http_requests.post(
                f"{engine}/incidents/{inc_id}/transition",
                json={"to_status": "false_positive", "comment": comment, "actor": actor_email},
                timeout=_t,
            )
            if r.ok:
                _write_action_audit(engine, inc_id, "status_change",
                                    comment=comment, actor=actor_email,
                                    from_status=from_st, to_status="false_positive",
                                    extra={"source": "agentic_chat"})
                updated = r.json()
                return {"success": True,
                        "message": (
                            f"Incident **{inc_id}** marked as **false positive**. "
                            f"Previous status was `{from_st}`. "
                            "The Incidents list will refresh automatically."
                        ),
                        "data": updated,
                        "new_status": updated.get("status", "false_positive")}
            try:
                detail = r.json().get("detail", r.text[:300])
            except Exception:
                detail = r.text[:300]
            return {"success": False,
                    "message": f"Could not transition {inc_id}: {detail}"}
        except Exception as e:
            return {"success": False, "message": f"Could not reach engine: {e}"}

    # ── Bulk mark false positives ─────────────────────────────────────────────
    elif action_type == "bulk_mark_false_positive":
        inc_ids = params.get("incident_ids", [])
        comment = params.get("comment") or f"Bulk false positive — CyMind agentic chat by {actor_email}"
        if not inc_ids:
            return {"success": False, "message": "No open incidents to mark — all may already be closed."}
        try:
            r = http_requests.post(
                f"{engine}/incidents/bulk-false-positive",
                json={"incident_ids": inc_ids, "comment": comment, "actor": actor_email},
                timeout=30,
            )
            if r.ok:
                d = r.json()
                ok = d.get("success_count", 0)
                return {"success": ok > 0,
                        "message": f"Marked **{ok}/{len(inc_ids)}** incidents as false positive.",
                        "data": d}
            return {"success": False,
                    "message": f"Engine returned HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"success": False, "message": f"Could not reach engine: {e}"}

    # ── Trigger ASM scan ──────────────────────────────────────────────────────
    elif action_type == "trigger_scan":
        import subprocess, sys
        from pathlib import Path as _Path
        from core.config import SCANS_DIR, ASM_LOGS, ASM_DIR

        domain    = params.get("domain", "").strip()
        scan_type = params.get("scan_type", "standard").lower()
        include_subdomains = bool(params.get("include_subdomains", True))

        if not domain or "." not in domain:
            return {"success": False, "message": "Invalid domain"}

        uid      = actor_email.replace("@", "_").replace(".", "_")
        user_dir = SCANS_DIR / uid
        user_dir.mkdir(parents=True, exist_ok=True)
        ASM_LOGS.mkdir(parents=True, exist_ok=True)
        scan_script = ASM_DIR / "cycentra_scan.py"
        if not scan_script.exists():
            return {"success": False, "message": f"Scan engine not found at {scan_script}"}

        env = os.environ.copy()
        env["CYCENTRA_OUTPUT_DIR"]         = str(user_dir)
        env["CYCENTRA_USER_ID"]            = uid
        env["CYCENTRA_INCLUDE_SUBDOMAINS"] = "true" if include_subdomains else "false"
        try:
            subprocess.Popen(
                [str(_Path(sys.executable)), str(scan_script), domain, uid, scan_type],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return {"success": True,
                    "message": f"**{scan_type.title()} scan** started for **{domain}**. Results will appear in Asset Inventory when complete."}
        except Exception as e:
            return {"success": False, "message": f"Failed to launch scan: {e}"}

    # ── Add scheduled scan ────────────────────────────────────────────────────
    elif action_type == "add_schedule":
        from blueprints.scheduler.routes import add_job_internal
        return add_job_internal(params, actor_email)

    # ── Assign incident to analyst ────────────────────────────────────────────
    elif action_type == "assign_incident":
        inc_id   = params.get("incident_id", "").strip()
        assignee = params.get("assigned_to", "").strip()
        if not inc_id or not assignee:
            return {"success": False, "message": "Missing incident_id or assigned_to"}
        try:
            r = http_requests.patch(
                f"{engine}/incidents/{inc_id}",
                json={"assigned_to": assignee},
                timeout=_t,
            )
            if r.ok:
                _write_action_audit(engine, inc_id, "assigned",
                                    comment=f"Assigned to {assignee}", actor=actor_email,
                                    extra={"assigned_to": assignee})
                return {"success": True,
                        "message": f"Incident **{inc_id}** assigned to **{assignee}**.",
                        "data": r.json()}
            return {"success": False,
                    "message": f"Engine returned HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"success": False, "message": f"Could not reach engine: {e}"}

    # ── Add analyst note ──────────────────────────────────────────────────────
    elif action_type == "add_incident_note":
        inc_id = params.get("incident_id", "").strip()
        note   = params.get("note", "").strip()
        if not inc_id or not note:
            return {"success": False, "message": "Missing incident_id or note"}
        # Append note to existing notes via PATCH — preserve existing content
        try:
            existing_r = http_requests.get(f"{engine}/incidents/{inc_id}", timeout=_t)
            existing_notes = ""
            if existing_r.ok:
                existing_notes = existing_r.json().get("notes") or ""
            separator = "\n\n" if existing_notes else ""
            from datetime import datetime as _dt
            new_notes = (
                f"{existing_notes}{separator}"
                f"[{_dt.utcnow().strftime('%Y-%m-%d %H:%M UTC')} — {actor_email}]\n{note}"
            )
            r = http_requests.patch(
                f"{engine}/incidents/{inc_id}",
                json={"notes": new_notes},
                timeout=_t,
            )
            if r.ok:
                _write_action_audit(engine, inc_id, "comment",
                                    comment=note, actor=actor_email)
                return {"success": True,
                        "message": f"Note added to incident **{inc_id}**.",
                        "data": r.json()}
            return {"success": False,
                    "message": f"Engine returned HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"success": False, "message": f"Could not reach engine: {e}"}

    # ── Escalate incident ─────────────────────────────────────────────────────
    elif action_type == "escalate_incident":
        inc_id  = params.get("incident_id", "").strip()
        comment = params.get("comment") or f"Escalated via CyMind agentic chat by {actor_email}"
        if not inc_id:
            return {"success": False, "message": "Missing incident_id"}
        try:
            # Bump severity via PATCH and open case via /api/cases
            from flask import current_app
            import requests as _hr
            r = _hr.post(
                f"http://127.0.0.1:5252/api/cases",
                json={"incident_id": inc_id},
                timeout=_t,
                cookies={"session": "system"},
            )
            _write_action_audit(engine, inc_id, "escalated",
                                comment=comment, actor=actor_email)
            return {"success": True,
                    "message": f"Incident **{inc_id}** escalated — severity bumped and case opened.",
                    "data": r.json() if r.ok else {}}
        except Exception as e:
            return {"success": False, "message": f"Could not escalate: {e}"}

    # ── Open CyCases investigation ───────────────────────────────────────────
    elif action_type == "open_case":
        inc_id = params.get("incident_id", "").strip()
        if not inc_id:
            return {"success": False, "message": "Missing incident_id"}
        try:
            r = http_requests.post(
                f"http://127.0.0.1:5252/api/cases",
                json={"incident_id": inc_id},
                timeout=_t,
            )
            if r.ok:
                data = r.json()
                _write_action_audit(engine, inc_id, "case_opened",
                                    comment=f"Case opened via CyMind chat by {actor_email}",
                                    actor=actor_email)
                return {"success": True,
                        "message": f"CyCases investigation opened for incident **{inc_id}**. View at /cases/{inc_id}.",
                        "data": data}
            return {"success": False,
                    "message": f"Case service returned HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"success": False, "message": f"Could not open case: {e}"}

    # ── Enrich IOC (MISP + risk score lookup) ─────────────────────────────────
    elif action_type == "enrich_ioc":
        ioc_value = params.get("ioc_value", "").strip()
        ioc_type  = params.get("ioc_type", "").strip() or None
        if not ioc_value:
            return {"success": False, "message": "Missing ioc_value"}
        # Fetch from MCP tool via engine loopback — the engine's get_threat_intel
        # MCP tool is not callable here directly, so we query the risk-scores REST
        # endpoint and the MISP cache via the engine's own REST layer.
        result: dict = {"ioc_value": ioc_value, "ioc_type": ioc_type}
        try:
            # Risk score for IP/domain entities
            r = http_requests.get(
                f"{engine}/risk-scores",
                params={"limit": 100},
                timeout=_t,
            )
            if r.ok:
                rows = r.json()
                rows = rows if isinstance(rows, list) else rows.get("entities", [])
                match = next((x for x in rows if x.get("entity_id") == ioc_value), None)
                result["risk_score"] = match or None
        except Exception:
            pass
        return {
            "success": True,
            "message": (
                f"Enrichment complete for **{ioc_value}** ({ioc_type or 'unknown'})."
                + (" Risk score: **" + str(result["risk_score"]["score"]) + "** (" + result["risk_score"]["level"] + ")" if result.get("risk_score") else " No risk score entry found.")
                + " Check MISP directly for full IOC event details."
            ),
            "data": result,
        }

    # ── Trigger CySOAR playbook ───────────────────────────────────────────────
    elif action_type == "trigger_soar_playbook":
        inc_id    = params.get("incident_id", "").strip()
        flow_name = params.get("flow_name", "").strip()
        if not inc_id and not flow_name:
            return {"success": False, "message": "Provide at least an incident_id or flow_name"}

        # Resolve SOAR webhook URL from engine config / ai_settings.json
        soar_url = ""
        try:
            import json as _j
            from pathlib import Path as _P
            raw = _P("/opt/cycentra/ai_settings.json").read_text()
            stored = _j.loads(raw)
            soar_url = (stored.get("soar", {}).get("webhookUrl") or "").strip()
        except Exception:
            pass
        if not soar_url:
            soar_url = os.environ.get("SOAR_WEBHOOK_URL", "").strip()
        if not soar_url:
            return {"success": False,
                    "message": "CySOAR webhook URL not configured. Set it in System Settings → Integrations → CySOAR."}

        # Build payload — enrich with incident data if an ID was provided
        payload: dict = {
            "trigger":     "cymind_chat",
            "actor":       actor_email,
            "timestamp":   __import__("datetime").datetime.utcnow().isoformat() + "Z",
        }
        if flow_name:
            payload["flow_name"] = flow_name
        if inc_id:
            payload["incident_id"] = inc_id
            try:
                r = http_requests.get(f"{engine}/incidents/{inc_id}", timeout=_t)
                if r.ok:
                    payload["incident"] = r.json()
            except Exception:
                pass

        try:
            target = soar_url.rstrip("/")
            if flow_name:
                target = f"{target}/{flow_name.lower().replace(' ', '-')}"
            r = http_requests.post(target, json=payload, timeout=15)
            if r.status_code in (200, 201, 202, 204):
                actions_taken: list = []
                try:
                    body = r.json()
                    if isinstance(body, list):
                        actions_taken = body
                    elif isinstance(body, dict):
                        actions_taken = body.get("actions_taken") or []
                except Exception:
                    pass
                if inc_id:
                    _write_action_audit(engine, inc_id, "soar_triggered",
                                        comment=f"SOAR playbook triggered{' (' + flow_name + ')' if flow_name else ''} via chat",
                                        actor=actor_email,
                                        extra={"flow_name": flow_name, "actions_taken": actions_taken})
                return {
                    "success": True,
                    "message": (
                        f"CySOAR playbook{' **' + flow_name + '**' if flow_name else ''} triggered"
                        f"{' for incident **' + inc_id + '**' if inc_id else ''}. "
                        + (f"{len(actions_taken)} action(s) logged." if actions_taken else "Node-RED confirmed receipt.")
                    ),
                    "data": {"actions_taken": actions_taken},
                }
            return {"success": False,
                    "message": f"CySOAR returned HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"success": False, "message": f"Could not reach CySOAR: {e}"}

    return {"success": False, "message": f"Unknown action type: {action_type}"}


@system_bp.route("/api/cymind/action/execute", methods=["OPTIONS"])
def cymind_action_execute_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/cymind/action/execute", methods=["POST"])
def cymind_action_execute():
    """
    Execute a confirmed agentic action from the CyMind chat overlay.
    Requires analyst+ role.  The action type and params are sent by the browser
    after the user clicks 'Execute' on the confirm card.
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403

    data        = request.get_json() or {}
    action_type = data.get("type", "")
    params      = data.get("params", {})
    actor       = session["user_email"]

    if not action_type:
        return jsonify({"error": "Missing action type"}), 400

    result = _execute_agentic_action(action_type, params, actor)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@system_bp.route("/api/cymind/chat/stream", methods=["OPTIONS"])
def cymind_chat_proxy_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/cymind/chat/stream", methods=["POST"])
def cymind_chat_proxy():
    """
    SSE proxy: forwards the browser's chat request to CyMind and streams the
    response back.  Injects live SIEM context from the local correlation engine
    directly into the system prompt so CyMind always has current data — no MCP
    callback from CyMind to CyCentra required.

    Agentic interception: if the user's last message matches a known action
    intent (block IP, close incident, trigger scan, etc.), the proxy intercepts
    the request and returns a synthetic SSE stream with an `action_pending`
    confirmation event instead of forwarding to CyMind.
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403

    cfg        = _read_cymind_config()
    cymind_url = cfg.get("cymindUrl", "").strip().rstrip("/")
    chat_key   = cfg.get("chatApiKey", "").strip()

    if not cymind_url:
        return jsonify({"error": "CyMind URL not configured — set it in System Settings → CyMind."}), 503
    if not chat_key:
        return jsonify({"error": "Chat API key not set — see System Settings → CyMind."}), 503

    # ── Parse body ─────────────────────────────────────────────────────────────
    raw_body = request.get_data()
    try:
        body_json = json.loads(raw_body)
    except Exception:
        body_json = None

    # ── Agentic intent detection ───────────────────────────────────────────────
    # Check if the user's last message contains a confirmed action intent.
    # Only analyst/admin reach here; no role re-check needed.
    _ACTION_VERB_RE = _re.compile(
        r'\b(?:close|resolve|mark\s+(?:as\s+)?(?:fp|false.positive)|assign|escalate)\b',
        _re.IGNORECASE,
    )
    if body_json is not None:
        messages = body_json.get("messages", [])
        last_msg = messages[-1].get("content", "") if messages else ""
        if last_msg:
            # If the message has an action verb but no explicit INC-ID, look back
            # through recent conversation history to find the most recently referenced
            # incident (e.g. user said "close the incident" after discussing INC-00490).
            resolve_msg = last_msg
            if _ACTION_VERB_RE.search(last_msg) and not _INC_RE.search(last_msg):
                for _prev in reversed(messages[:-1]):
                    _found = _INC_RE.findall(_prev.get("content", ""))
                    if _found:
                        resolve_msg = last_msg.rstrip() + f" {_found[-1]}"
                        break
            action = _detect_action_intent(resolve_msg)
            if action is not None:
                return _stream_action_confirmation(action)

    _SIEM_UNAVAILABLE_NOTE = (
        "\n\n[SYSTEM NOTE: Live SIEM data is temporarily unavailable "
        "(the CyCentra 360 correlation engine did not respond). "
        "IMPORTANT: Do NOT tell the user to enable any 'Live SIEM toggle' — "
        "there is no such toggle in this interface; live SIEM context is always on. "
        "Do NOT fabricate any incident IDs, alert counts, risk scores, usernames, CVEs, "
        "or IP addresses. For general SOC questions answer from your training knowledge. "
        "For live data questions, say that live SIEM data is temporarily unavailable "
        "and recommend checking the correlation engine status or contacting the administrator.]\n"
    )

    if body_json is not None:
        siem_block = _fetch_siem_context_block()
        existing_system = body_json.get("system", "")
        if siem_block:
            # Entity-aware enrichment: if message mentions a user/entity, inject their incidents
            _msgs  = body_json.get("messages", [])
            _last  = _msgs[-1].get("content", "") if _msgs else ""
            if _last:
                _entity_block = _fetch_entity_incidents_block(_last)
                if _entity_block:
                    siem_block += _entity_block
                _inc_block = _fetch_incident_detail_block(_last)
                if _inc_block:
                    siem_block += _inc_block
            body_json["system"] = (existing_system + siem_block).strip()
        else:
            # No live data — inject an explicit note so CyMind never says "enable the toggle"
            body_json["system"] = (existing_system + _SIEM_UNAVAILABLE_NOTE).strip()
        body_json["use_mcp"] = False  # context already injected; skip CyMind→CyCentra MCP call
        forward_body = json.dumps(body_json).encode()
    else:
        forward_body = raw_body  # fallback: forward as-is

    target = f"{cymind_url}/api/v1/chat/stream"

    try:
        upstream = http_requests.post(
            target,
            data=forward_body,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {chat_key}",
            },
            stream=True,
            timeout=(10, 300),
        )
    except http_requests.exceptions.ConnectionError as e:
        return jsonify({"error": f"Cannot reach CyMind at {cymind_url}: {e}"}), 502
    except http_requests.exceptions.Timeout:
        return jsonify({"error": "CyMind did not respond in time"}), 504

    if not upstream.ok:
        return jsonify({"error": f"CyMind returned HTTP {upstream.status_code}"}), upstream.status_code

    def _generate():
        try:
            for chunk in upstream.iter_content(chunk_size=None):
                if chunk:
                    yield chunk
        finally:
            upstream.close()

    return current_app.response_class(
        _generate(),
        status=200,
        mimetype="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


@system_bp.route("/api/cymind/context", methods=["OPTIONS"])
def cymind_context_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/cymind/context", methods=["GET"])
def cymind_context():
    """
    Machine-to-machine SIEM context endpoint for CyMind RAG chat.

    CyMind calls this URL instead of the MCP SSE bridge — plain HTTPS GET,
    no protocol handshake needed.

    Auth: X-CyMind-Key: <cymk_...> header (same key stored in ai_settings.json).

    Query params (all optional):
      incidents  — max open incidents to return (default 5, max 20)
      risk       — max high-risk entities (default 5, max 20)
      ueba       — max UEBA anomaly users (default 5, max 20)
    """
    # ── API key check ──────────────────────────────────────────────────────────
    provided_key = (
        request.headers.get("X-CyMind-Key", "")
        or request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    )
    cfg = _read_cymind_config()
    stored_key = cfg.get("apiKey", "")
    if not stored_key or provided_key != stored_key:
        return jsonify({"error": "Unauthorized — invalid or missing CyMind API key"}), 401

    engine_url = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100").rstrip("/")
    timeout    = 10

    limit_inc  = min(int(request.args.get("incidents", 20)), 50)
    limit_risk = min(int(request.args.get("risk",       5)), 20)
    limit_ueba = min(int(request.args.get("ueba",       5)), 20)

    context = {}

    # ── Stats ──────────────────────────────────────────────────────────────────
    try:
        r = http_requests.get(f"{engine_url}/stats", timeout=timeout)
        if r.ok:
            context["stats"] = r.json()
    except Exception:
        pass

    # ── Active incidents (investigating + open) ───────────────────────────────
    try:
        _active_m2m: list = []
        for _status in ("investigating", "open"):
            try:
                _r = http_requests.get(
                    f"{engine_url}/incidents",
                    params={"status": _status, "limit": limit_inc},
                    timeout=timeout,
                )
                if _r.ok:
                    _raw = _r.json()
                    _rows = _raw if isinstance(_raw, list) else _raw.get("incidents", [])
                    seen_ids = {i["id"] for i in _active_m2m}
                    _active_m2m += [i for i in _rows if i.get("id") not in seen_ids]
            except Exception:
                pass
        if _active_m2m:
            context["open_incidents"] = _active_m2m
    except Exception:
        pass

    # ── High-risk entities ─────────────────────────────────────────────────────
    try:
        r = http_requests.get(
            f"{engine_url}/risk-scores",
            params={"level": "high", "limit": limit_risk},
            timeout=timeout,
        )
        if r.ok:
            context["high_risk_entities"] = r.json()
    except Exception:
        pass

    # ── UEBA users with anomalies ──────────────────────────────────────────────
    try:
        r = http_requests.get(
            f"{engine_url}/ueba/users",
            params={"has_anomaly": "true", "limit": limit_ueba},
            timeout=timeout,
        )
        if r.ok:
            context["ueba_anomalies"] = r.json()
    except Exception:
        pass

    return jsonify({
        "ok":        True,
        "source":    "cycentra360",
        "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "context":   context,
    })


# ── MCP API Keys — 3rd-party integrations ─────────────────────────────────────
#
# Generates cymk_... keys that authorise 3rd-party MCP clients (SIEM integrations,
# AI agents, etc.) to access the correlation-engine /mcp/sse SSE bridge.
# CyMind's own key is managed OOB via cymind_enable() — no change there.
# Keys are stored inside ai_settings.json → cymind_integration.mcp_api_keys.

def _read_mcp_api_keys() -> list:
    cfg = _read_cymind_config()
    return cfg.get("mcp_api_keys", [])


def _write_mcp_api_keys(keys: list) -> None:
    existing = {}
    try:
        if AI_SETTINGS_FILE.exists():
            existing = json.loads(AI_SETTINGS_FILE.read_text())
    except Exception:
        pass
    cfg = existing.get("cymind_integration", {})
    cfg["mcp_api_keys"] = keys
    existing["cymind_integration"] = cfg
    AI_SETTINGS_FILE.write_text(json.dumps(existing, indent=2))


@system_bp.route("/api/system/mcp/keys", methods=["OPTIONS"])
def mcp_keys_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/mcp/keys", methods=["GET"])
def mcp_keys_get():
    """List 3rd-party MCP API keys. Admin only. Actual key values are masked."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) != "admin":
        return jsonify({"error": "Admin role required"}), 403

    keys = _read_mcp_api_keys()
    masked = []
    for entry in keys:
        k = entry.get("key", "")
        masked.append({
            **entry,
            "key": (k[:12] + "••••••••") if len(k) > 12 else "••••••••",
        })
    base_url    = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100").rstrip("/")
    base_domain = os.environ.get("BASE_DOMAIN", "")
    public_mcp  = f"https://cy360.{base_domain}/mcp/sse" if base_domain else f"{base_url}/mcp/sse"
    return jsonify({"ok": True, "keys": masked, "endpoint": public_mcp})


@system_bp.route("/api/system/mcp/keys", methods=["POST"])
def mcp_keys_post():
    """Generate a new 3rd-party MCP API key. Admin only.
    Body: { name: str, description?: str }
    Response includes the full key value (shown once — not stored in plaintext in the UI).
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) != "admin":
        return jsonify({"error": "Admin role required"}), 403

    import secrets as _secrets
    import datetime as _dt
    data        = request.get_json() or {}
    name        = str(data.get("name", "")).strip()
    description = str(data.get("description", "")).strip()
    if not name:
        return jsonify({"error": "Key name is required"}), 400
    if len(name) > 80:
        return jsonify({"error": "Name must be ≤ 80 characters"}), 400

    keys    = _read_mcp_api_keys()
    new_key = "cymk_" + _secrets.token_hex(24)
    entry   = {
        "id":          "key_" + _secrets.token_hex(8),
        "name":        name,
        "description": description,
        "key":         new_key,
        "created_at":  _dt.datetime.utcnow().isoformat() + "Z",
    }
    keys.append(entry)
    _write_mcp_api_keys(keys)
    current_app.logger.info("mcp_api_key_generated name=%s by=%s", name, session["user_email"])
    return jsonify({"ok": True, "key": new_key, "id": entry["id"], "name": name})


@system_bp.route("/api/system/mcp/keys/<key_id>", methods=["OPTIONS"])
def mcp_key_revoke_options(key_id):
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/mcp/keys/<key_id>", methods=["DELETE"])
def mcp_key_revoke(key_id):
    """Revoke a 3rd-party MCP API key by ID. Admin only."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) != "admin":
        return jsonify({"error": "Admin role required"}), 403

    keys    = _read_mcp_api_keys()
    updated = [k for k in keys if k.get("id") != key_id]
    if len(updated) == len(keys):
        return jsonify({"error": "Key not found"}), 404
    _write_mcp_api_keys(updated)
    current_app.logger.info("mcp_api_key_revoked id=%s by=%s", key_id, session["user_email"])
    return jsonify({"ok": True})


# ── Office 365 Wazuh Integration ──────────────────────────────────────────────

_OSSEC_CONF = Path("/var/ossec/etc/ossec.conf")

_O365_VALID_SUBSCRIPTIONS = {
    "Audit.AzureActiveDirectory",
    "Audit.Exchange",
    "Audit.SharePoint",
    "Audit.General",
    "DLP.All",
}

_O365_VALID_INTERVALS = {"1m", "5m", "10m", "15m", "30m", "1h", "2h", "6h", "12h", "24h"}

_O365_VALID_API_TYPES = {"commercial", "gcc", "gcc-high"}


@system_bp.route("/api/system/o365config", methods=["OPTIONS"])
def o365config_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/o365config", methods=["GET"])
def o365config_get():
    """Return the current Office 365 native module configuration (credentials redacted)."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    if not _OSSEC_CONF.exists():
        return jsonify({"ok": False, "error": "ossec.conf not found — is CySIEM installed?"}), 404

    try:
        content = _OSSEC_CONF.read_text()
    except PermissionError:
        return jsonify({"ok": False, "error": "Permission denied reading ossec.conf"}), 403

    # Extract the native <office365> block — scoped to avoid matching tags in other sections.
    module_match = re.search(r'<office365>(.*?)</office365>', content, re.DOTALL)
    if not module_match:
        # Module not present — integration not configured
        return add_cors_headers(jsonify({
            "ok":                 True,
            "enabled":            False,
            "interval":           "1m",
            "only_future_events": True,
            "api_type":           "commercial",
            "tenant_id":          "",
            "client_id":          "",
            "client_secret":      "",
            "subscriptions":      [],
        }))

    module_block = module_match.group(1)

    def _extract(tag):
        m = re.search(rf"<{tag}>(.*?)</{tag}>", module_block)
        return m.group(1).strip() if m else ""

    enabled_val          = _extract("enabled")
    interval_val         = _extract("interval")
    only_future_val      = _extract("only_future_events")
    tenant_id            = _extract("tenant_id")
    client_id            = _extract("client_id")
    api_type             = _extract("api_type") or "commercial"

    subs = re.findall(r"<subscription>(.*?)</subscription>", module_block)

    # cycentra-setup.sh injects PLACEHOLDER_M365_* values during initial install.
    # Return empty string for those so the UI treats the field as unconfigured.
    return add_cors_headers(jsonify({
        "ok":                 True,
        "enabled":            enabled_val != "no",
        "interval":           interval_val or "1m",
        "only_future_events": only_future_val != "no",
        "api_type":           api_type if api_type in _O365_VALID_API_TYPES else "commercial",
        "tenant_id":          tenant_id if not tenant_id.startswith("PLACEHOLDER") else "",
        "client_id":          client_id  if not client_id.startswith("PLACEHOLDER")  else "",
        "client_secret":      "",   # never returned — write-only field
        "subscriptions":      subs,
    }))


@system_bp.route("/api/system/o365config", methods=["POST"])
def o365config_post():
    """Write O365 credentials into the Wazuh ossec.conf native <office365> module block
    and restart the wazuh-manager service.

    Body (JSON):
      tenant_id           – Azure tenant UUID
      client_id           – Azure app client ID
      client_secret       – Azure app client secret (omit or send empty string to keep
                            the value already present in ossec.conf)
      api_type            – Office 365 subscription plan: commercial | gcc | gcc-high
      interval            – poll interval (default "1m")
      only_future_events  – bool, collect only events generated after start (default true)
      subscriptions       – list of audit log subscriptions (default: all)
      enabled             – bool, whether to enable the module (default true)
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) != "admin":
        return jsonify({"error": "Admin role required to configure integrations"}), 403

    data                = request.get_json() or {}
    tenant_id           = (data.get("tenant_id")     or "").strip()
    client_id           = (data.get("client_id")     or "").strip()
    client_secret       = (data.get("client_secret") or "").strip()
    api_type            = (data.get("api_type")      or "commercial").strip()
    interval            = (data.get("interval")      or "1m").strip()
    only_future_events  = bool(data.get("only_future_events", True))
    subscriptions       = data.get("subscriptions") or list(_O365_VALID_SUBSCRIPTIONS)
    enabled             = bool(data.get("enabled", True))

    # Validate required fields
    if not tenant_id:
        return jsonify({"ok": False, "error": "tenant_id is required"}), 400
    if not client_id:
        return jsonify({"ok": False, "error": "client_id is required"}), 400

    # Validate api_type
    if api_type not in _O365_VALID_API_TYPES:
        return jsonify({"ok": False, "error": f"api_type must be one of: {', '.join(sorted(_O365_VALID_API_TYPES))}"}), 400

    # Validate interval
    if interval not in _O365_VALID_INTERVALS:
        return jsonify({"ok": False, "error": f"interval must be one of: {', '.join(sorted(_O365_VALID_INTERVALS))}"}), 400

    # Validate subscriptions
    invalid_subs = set(subscriptions) - _O365_VALID_SUBSCRIPTIONS
    if invalid_subs:
        return jsonify({"ok": False, "error": f"Invalid subscriptions: {', '.join(sorted(invalid_subs))}"}), 400
    if not subscriptions:
        return jsonify({"ok": False, "error": "At least one subscription is required"}), 400

    if not _OSSEC_CONF.exists():
        return jsonify({"ok": False, "error": "ossec.conf not found — is CySIEM installed?"}), 404

    try:
        content = _OSSEC_CONF.read_text()
    except PermissionError:
        return jsonify({"ok": False, "error": "Permission denied reading ossec.conf"}), 403

    # If client_secret is omitted, preserve the value already stored in ossec.conf
    if not client_secret:
        m = re.search(r"<client_secret>(.*?)</client_secret>", content)
        existing_secret = m.group(1).strip() if m else ""
        if existing_secret.startswith("PLACEHOLDER") or not existing_secret:
            return jsonify({"ok": False, "error": "client_secret is required for the initial configuration"}), 400
        client_secret = existing_secret

    enabled_str         = "yes" if enabled else "no"
    only_future_str     = "yes" if only_future_events else "no"

    # Build the subscription block
    subs_xml = "\n".join(
        f"      <subscription>{s}</subscription>" for s in subscriptions
    )

    new_block = (
        f'<office365>\n'
        f'    <enabled>{enabled_str}</enabled>\n'
        f'    <interval>{interval}</interval>\n'
        f'    <curl_max_size>1M</curl_max_size>\n'
        f'    <only_future_events>{only_future_str}</only_future_events>\n'
        f'    <api_auth>\n'
        f'      <tenant_id>{tenant_id}</tenant_id>\n'
        f'      <client_id>{client_id}</client_id>\n'
        f'      <client_secret>{client_secret}</client_secret>\n'
        f'      <api_type>{api_type}</api_type>\n'
        f'    </api_auth>\n'
        f'    <subscriptions>\n'
        f'{subs_xml}\n'
        f'    </subscriptions>\n'
        f'  </office365>'
    )

    # Remove any legacy wodle-format block if present, then replace or inject native block
    content = re.sub(r'<wodle name="office365">.*?</wodle>', '', content, flags=re.DOTALL)

    updated, n_subs = re.subn(
        r'<office365>.*?</office365>',
        new_block,
        content,
        flags=re.DOTALL,
    )
    if n_subs == 0:
        # Block not present — inject before closing tag
        updated = content.replace(
            "</ossec_config>",
            f"\n  {new_block}\n</ossec_config>",
        )

    # Persist credentials so the block can be re-applied if Wazuh resets ossec.conf
    # (e.g. after cycentra-setup.sh re-runs on server update).
    _O365_CACHE = Path("/opt/cycentra/o365_config.json")
    try:
        _O365_CACHE.write_text(json.dumps({
            "tenant_id":          tenant_id,
            "client_id":          client_id,
            "client_secret":      client_secret,
            "api_type":           api_type,
            "interval":           interval,
            "only_future_events": only_future_events,
            "subscriptions":      subscriptions,
            "enabled":            enabled,
        }, indent=2))
        _O365_CACHE.chmod(0o600)
    except OSError:
        pass  # non-fatal — ossec.conf write below is the authoritative path

    # Write back with backup
    backup = Path(f"{_OSSEC_CONF}.o365bak")
    try:
        shutil.copy2(str(_OSSEC_CONF), str(backup))
        _OSSEC_CONF.write_text(updated)
    except PermissionError:
        return jsonify({"ok": False, "error": "Permission denied writing ossec.conf"}), 403
    except OSError:
        return jsonify({"ok": False, "error": "Failed to write ossec.conf — check server logs"}), 500

    # Restart wazuh-manager to apply changes
    rc, _stdout, _stderr = _run_cmd("systemctl restart wazuh-manager")
    if rc != 0:
        # Config was written but service restart failed — still partial success
        return add_cors_headers(jsonify({
            "ok":      False,
            "written": True,
            "error":   "Config saved but wazuh-manager restart failed — check server logs",
        })), 207

    return add_cors_headers(jsonify({
        "ok":      True,
        "enabled": enabled,
        "message": "Office 365 integration configured and wazuh-manager restarted successfully",
    }))


def reapply_o365_if_missing():
    """Called at Flask startup: if ossec.conf has no <office365> block but we have a
    cached config at /opt/cycentra/o365_config.json, inject the block and reload Wazuh.
    This recovers from the setup script overwriting ossec.conf on server restart."""
    _O365_CACHE = Path("/opt/cycentra/o365_config.json")
    if not _OSSEC_CONF.exists() or not _O365_CACHE.exists():
        return
    try:
        content = _OSSEC_CONF.read_text()
        if re.search(r'<office365>', content):
            return  # already present — nothing to do
        cfg = json.loads(_O365_CACHE.read_text())
    except Exception:
        return

    tenant_id          = cfg.get("tenant_id", "")
    client_id          = cfg.get("client_id", "")
    client_secret      = cfg.get("client_secret", "")
    api_type           = cfg.get("api_type", "commercial")
    interval           = cfg.get("interval", "1m")
    only_future_events = cfg.get("only_future_events", True)
    subscriptions      = cfg.get("subscriptions", list(_O365_VALID_SUBSCRIPTIONS))
    enabled            = cfg.get("enabled", True)

    if not tenant_id or not client_id or not client_secret:
        return

    enabled_str     = "yes" if enabled else "no"
    only_future_str = "yes" if only_future_events else "no"
    subs_xml = "\n".join(f"      <subscription>{s}</subscription>" for s in subscriptions)
    new_block = (
        f'<office365>\n'
        f'    <enabled>{enabled_str}</enabled>\n'
        f'    <interval>{interval}</interval>\n'
        f'    <curl_max_size>1M</curl_max_size>\n'
        f'    <only_future_events>{only_future_str}</only_future_events>\n'
        f'    <api_auth>\n'
        f'      <tenant_id>{tenant_id}</tenant_id>\n'
        f'      <client_id>{client_id}</client_id>\n'
        f'      <client_secret>{client_secret}</client_secret>\n'
        f'      <api_type>{api_type}</api_type>\n'
        f'    </api_auth>\n'
        f'    <subscriptions>\n'
        f'{subs_xml}\n'
        f'    </subscriptions>\n'
        f'  </office365>'
    )
    try:
        # Remove any legacy wodle-format block before injecting native block
        content = re.sub(r'<wodle name="office365">.*?</wodle>', '', content, flags=re.DOTALL)
        updated = content.replace("</ossec_config>", f"\n  {new_block}\n</ossec_config>")
        _OSSEC_CONF.write_text(updated)
        _run_cmd("systemctl reload-or-restart wazuh-manager")
    except Exception:
        pass


# ── Google Cloud (GCP Pub/Sub) Wazuh Integration ──────────────────────────────

_GCP_CREDENTIALS_FILE = Path("/var/ossec/etc/gcp_credentials.json")
_GCP_CUSTOM_RULES_DIR = Path("/var/ossec/etc/rules")
_GCP_CUSTOM_RULES_FILE = _GCP_CUSTOM_RULES_DIR / "cycentra_gcp_rules.xml"

_GCP_VALID_INTERVALS = {"1m", "5m", "10m", "15m", "30m", "1h", "2h", "6h", "12h", "24h"}

# Custom GCP security rules deployed alongside the integration
_GCP_SECURITY_RULES = """\
<!-- CyCentra360: Google Cloud custom security rules -->
<group name="gcp,">

  <!-- GCP IAM privilege escalation -->
  <rule id="191001" level="12">
    <if_group>gcp</if_group>
    <field name="gcp.protoPayload.methodName">setIamPolicy</field>
    <description>GCP: IAM policy change detected — possible privilege escalation</description>
    <group>gcp_iam,privilege_escalation,</group>
  </rule>

  <!-- GCP service account key creation -->
  <rule id="191002" level="10">
    <if_group>gcp</if_group>
    <field name="gcp.protoPayload.methodName">google.iam.admin.v1.CreateServiceAccountKey</field>
    <description>GCP: New service account key created</description>
    <group>gcp_iam,credential_access,</group>
  </rule>

  <!-- GCP firewall rule opened to the internet -->
  <rule id="191003" level="11">
    <if_group>gcp</if_group>
    <field name="gcp.protoPayload.methodName">v1.compute.firewalls.insert|v1.compute.firewalls.patch</field>
    <description>GCP: Firewall rule created or modified — review for public exposure</description>
    <group>gcp_network,initial_access,</group>
  </rule>

  <!-- GCP bucket made publicly accessible -->
  <rule id="191004" level="13">
    <if_group>gcp</if_group>
    <field name="gcp.protoPayload.methodName">storage.setIamPermissions</field>
    <description>GCP: Storage bucket IAM permissions changed — check for public access</description>
    <group>gcp_storage,exfiltration,</group>
  </rule>

  <!-- GCP project deletion -->
  <rule id="191005" level="14">
    <if_group>gcp</if_group>
    <field name="gcp.protoPayload.methodName">cloudresourcemanager.projects.delete</field>
    <description>GCP: Project deletion requested — potential destructive action</description>
    <group>gcp_resource,impact,</group>
  </rule>

</group>
"""


@system_bp.route("/api/system/gcloudconfig", methods=["OPTIONS"])
def gcloudconfig_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/gcloudconfig", methods=["GET"])
def gcloudconfig_get():
    """Return the current GCP Pub/Sub wodle configuration (credentials redacted)."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    if not _OSSEC_CONF.exists():
        return jsonify({"ok": False, "error": "ossec.conf not found — is CySIEM installed?"}), 404

    try:
        content = _OSSEC_CONF.read_text()
    except PermissionError:
        return jsonify({"ok": False, "error": "Permission denied reading ossec.conf"}), 403

    # Extract values from the gcp-pubsub wodle block only to avoid cross-wodle matches
    m_block = re.search(r'<wodle name="gcp-pubsub">(.*?)</wodle>', content, re.DOTALL)
    block = m_block.group(1) if m_block else ""

    def _extract_block(tag, src):
        m = re.search(rf"<{tag}>(.*?)</{tag}>", src)
        return m.group(1).strip() if m else ""

    disabled_val      = _extract_block("disabled", block)
    interval_val      = _extract_block("interval", block)
    project_id        = _extract_block("project_id", block)
    subscription_name = _extract_block("subscription_name", block)
    max_messages_val  = _extract_block("max_messages", block)
    logging_val       = _extract_block("logging", block)

    has_credentials = _GCP_CREDENTIALS_FILE.exists()

    return add_cors_headers(jsonify({
        "ok":               True,
        "enabled":          disabled_val == "no",
        "interval":         interval_val or "5m",
        "project_id":       project_id if project_id and not project_id.startswith("PLACEHOLDER") else "",
        "subscription_name": subscription_name if subscription_name and not subscription_name.startswith("PLACEHOLDER") else "",
        "max_messages":     int(max_messages_val) if max_messages_val and max_messages_val.strip().isdigit() else 100,
        "logging":          logging_val or "info",
        "has_credentials":  has_credentials,
        "custom_rules_deployed": _GCP_CUSTOM_RULES_FILE.exists(),
    }))


@system_bp.route("/api/system/gcloudconfig", methods=["POST"])
def gcloudconfig_post():
    """Configure the Wazuh gcp-pubsub wodle with a GCP service account credentials file.

    Body (JSON):
      credentials_json  – contents of the GCP service account key JSON file (string or object)
                          omit / null to keep the existing credentials file
      project_id        – GCP project ID
      subscription_name – Pub/Sub subscription name
      interval          – poll interval (default "5m")
      max_messages      – max messages per pull (default 100)
      logging           – log level: debug|info|warning|error|critical (default "info")
      enabled           – bool, whether to set <disabled>no</disabled> (default true)
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) != "admin":
        return jsonify({"error": "Admin role required to configure integrations"}), 403

    data              = request.get_json() or {}
    credentials_raw   = data.get("credentials_json")
    project_id        = (data.get("project_id")        or "").strip()
    subscription_name = (data.get("subscription_name") or "").strip()
    interval          = (data.get("interval")          or "5m").strip()
    max_messages      = int(data.get("max_messages", 100))
    logging_level     = (data.get("logging")           or "info").strip()
    enabled           = bool(data.get("enabled", True))

    # Validate required fields
    if not project_id:
        return jsonify({"ok": False, "error": "project_id is required"}), 400
    if not subscription_name:
        return jsonify({"ok": False, "error": "subscription_name is required"}), 400
    if interval not in _GCP_VALID_INTERVALS:
        return jsonify({"ok": False, "error": f"interval must be one of: {', '.join(sorted(_GCP_VALID_INTERVALS))}"}), 400
    if logging_level not in ("debug", "info", "warning", "error", "critical"):
        return jsonify({"ok": False, "error": "logging must be one of: debug, info, warning, error, critical"}), 400
    if not (1 <= max_messages <= 1000):
        return jsonify({"ok": False, "error": "max_messages must be between 1 and 1000"}), 400

    # Handle credentials JSON
    if credentials_raw is not None:
        # Accept either a JSON string or a pre-parsed object
        if isinstance(credentials_raw, dict):
            creds_obj = credentials_raw
        else:
            try:
                creds_obj = json.loads(credentials_raw)
            except (ValueError, TypeError):
                return jsonify({"ok": False, "error": "credentials_json is not valid JSON"}), 400

        # Validate it looks like a GCP service account key
        required_keys = {"type", "project_id", "private_key_id", "private_key", "client_email"}
        missing = required_keys - set(creds_obj.keys())
        if missing or creds_obj.get("type") != "service_account":
            return jsonify({"ok": False, "error": "credentials_json does not appear to be a GCP service account key"}), 400

        # Write credentials file
        try:
            _GCP_CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
            _GCP_CREDENTIALS_FILE.write_text(json.dumps(creds_obj, indent=2))
            # Restrict permissions — wazuh-manager user only
            _GCP_CREDENTIALS_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except PermissionError:
            return jsonify({"ok": False, "error": "Permission denied writing GCP credentials file"}), 403
        except OSError:
            return jsonify({"ok": False, "error": "Failed to write GCP credentials file — check server logs"}), 500
    else:
        # No credentials supplied — require that an existing file is present
        if not _GCP_CREDENTIALS_FILE.exists():
            return jsonify({"ok": False, "error": "credentials_json is required for the initial configuration"}), 400

    if not _OSSEC_CONF.exists():
        return jsonify({"ok": False, "error": "ossec.conf not found — is CySIEM installed?"}), 404

    try:
        content = _OSSEC_CONF.read_text()
    except PermissionError:
        return jsonify({"ok": False, "error": "Permission denied reading ossec.conf"}), 403

    disabled_str = "no" if enabled else "yes"
    creds_path   = str(_GCP_CREDENTIALS_FILE)

    new_wodle = (
        f'<wodle name="gcp-pubsub">\n'
        f'    <disabled>{disabled_str}</disabled>\n'
        f'    <project_id>{project_id}</project_id>\n'
        f'    <subscription_name>{subscription_name}</subscription_name>\n'
        f'    <credentials_file>{creds_path}</credentials_file>\n'
        f'    <max_messages>{max_messages}</max_messages>\n'
        f'    <interval>{interval}</interval>\n'
        f'    <pull_on_start>yes</pull_on_start>\n'
        f'    <logging>{logging_level}</logging>\n'
        f'  </wodle>'
    )

    # Replace existing gcp-pubsub wodle block or append before </ossec_config>
    updated, n_subs = re.subn(
        r'<wodle name="gcp-pubsub">.*?</wodle>',
        new_wodle,
        content,
        flags=re.DOTALL,
    )
    if n_subs == 0:
        updated = content.replace(
            "</ossec_config>",
            f"\n  {new_wodle}\n</ossec_config>",
        )

    # Write back ossec.conf with backup
    backup = Path(f"{_OSSEC_CONF}.gcpbak")
    try:
        shutil.copy2(str(_OSSEC_CONF), str(backup))
        _OSSEC_CONF.write_text(updated)
    except PermissionError:
        return jsonify({"ok": False, "error": "Permission denied writing ossec.conf"}), 403
    except OSError:
        return jsonify({"ok": False, "error": "Failed to write ossec.conf — check server logs"}), 500

    # Deploy custom GCP security rules
    rules_deployed = False
    try:
        _GCP_CUSTOM_RULES_DIR.mkdir(parents=True, exist_ok=True)
        _GCP_CUSTOM_RULES_FILE.write_text(_GCP_SECURITY_RULES)
        rules_deployed = True
    except (PermissionError, OSError):
        # Non-fatal — integration still works without custom rules
        pass

    # Restart wazuh-manager to apply changes
    rc, _stdout, _stderr = _run_cmd("systemctl restart wazuh-manager")
    if rc != 0:
        return add_cors_headers(jsonify({
            "ok":             False,
            "written":        True,
            "rules_deployed": rules_deployed,
            "error":          "Config saved but wazuh-manager restart failed — check server logs",
        })), 207

    return add_cors_headers(jsonify({
        "ok":             True,
        "enabled":        enabled,
        "rules_deployed": rules_deployed,
        "message":        "Google Cloud integration configured and wazuh-manager restarted successfully",
    }))


# ── GitHub Wazuh Integration ─────────────────────────────────────────────────

_GITHUB_VALID_INTERVALS   = {"1m", "5m", "10m", "15m", "30m", "1h", "2h", "6h", "12h", "24h"}
_GITHUB_VALID_EVENT_TYPES = {"all", "web", "git"}
_GITHUB_CACHE             = Path("/opt/cycentra/github_config.json")


@system_bp.route("/api/system/githubconfig", methods=["OPTIONS"])
def githubconfig_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/githubconfig", methods=["GET"])
def githubconfig_get():
    """Return current GitHub Wazuh module config (api_token redacted)."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    if not _OSSEC_CONF.exists():
        return jsonify({"ok": False, "error": "ossec.conf not found — is CySIEM installed?"}), 404

    try:
        content = _OSSEC_CONF.read_text()
    except PermissionError:
        return jsonify({"ok": False, "error": "Permission denied reading ossec.conf"}), 403

    module_match = re.search(r'<github>(.*?)</github>', content, re.DOTALL)
    if not module_match:
        return add_cors_headers(jsonify({
            "ok":                 True,
            "enabled":            False,
            "interval":           "1m",
            "time_delay":         "1m",
            "curl_max_size":      "1M",
            "only_future_events": True,
            "event_type":         "all",
            "org_name":           "",
            "api_token":          "",
        }))

    block = module_match.group(1)

    def _ex(tag):
        m = re.search(rf"<{tag}>(.*?)</{tag}>", block)
        return m.group(1).strip() if m else ""

    return add_cors_headers(jsonify({
        "ok":                 True,
        "enabled":            _ex("enabled") != "no",
        "interval":           _ex("interval") or "1m",
        "time_delay":         _ex("time_delay") or "1m",
        "curl_max_size":      _ex("curl_max_size") or "1M",
        "only_future_events": _ex("only_future_events") != "no",
        "event_type":         _ex("event_type") or "all",
        "org_name":           _ex("org_name") if not _ex("org_name").startswith("PLACEHOLDER") else "",
        "api_token":          "",   # write-only — never returned
    }))


@system_bp.route("/api/system/githubconfig", methods=["POST"])
def githubconfig_post():
    """Write GitHub credentials into the Wazuh ossec.conf <github> module block
    and restart the wazuh-manager service.

    Body (JSON):
      org_name            – GitHub organisation name (required)
      api_token           – GitHub PAT (omit to keep existing token)
      interval            – poll interval (default '1m')
      time_delay          – scan delay relative to current time (default '1m')
      curl_max_size       – max API response size (default '1M')
      only_future_events  – bool (default true)
      event_type          – 'all' | 'web' | 'git' (default 'all')
      enabled             – bool (default true)
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) != "admin":
        return jsonify({"error": "Admin role required to configure integrations"}), 403

    data               = request.get_json() or {}
    org_name           = (data.get("org_name")       or "").strip()
    api_token          = (data.get("api_token")      or "").strip()
    interval           = (data.get("interval")       or "1m").strip()
    time_delay         = (data.get("time_delay")     or "1m").strip()
    curl_max_size      = (data.get("curl_max_size")  or "1M").strip()
    only_future_events = bool(data.get("only_future_events", True))
    event_type         = (data.get("event_type")     or "all").strip()
    enabled            = bool(data.get("enabled", True))

    if not org_name:
        return jsonify({"ok": False, "error": "org_name is required"}), 400
    if interval not in _GITHUB_VALID_INTERVALS:
        return jsonify({"ok": False, "error": f"interval must be one of: {', '.join(sorted(_GITHUB_VALID_INTERVALS))}"}), 400
    if event_type not in _GITHUB_VALID_EVENT_TYPES:
        return jsonify({"ok": False, "error": f"event_type must be one of: {', '.join(sorted(_GITHUB_VALID_EVENT_TYPES))}"}), 400

    if not _OSSEC_CONF.exists():
        return jsonify({"ok": False, "error": "ossec.conf not found — is CySIEM installed?"}), 404

    try:
        content = _OSSEC_CONF.read_text()
    except PermissionError:
        return jsonify({"ok": False, "error": "Permission denied reading ossec.conf"}), 403

    # If api_token omitted, preserve the value already in ossec.conf
    if not api_token:
        m = re.search(r"<api_token>(.*?)</api_token>", content)
        existing_token = m.group(1).strip() if m else ""
        if existing_token.startswith("PLACEHOLDER") or not existing_token:
            return jsonify({"ok": False, "error": "api_token is required for the initial configuration"}), 400
        api_token = existing_token

    enabled_str     = "yes" if enabled else "no"
    only_future_str = "yes" if only_future_events else "no"

    new_block = (
        f'<github>\n'
        f'    <enabled>{enabled_str}</enabled>\n'
        f'    <interval>{interval}</interval>\n'
        f'    <time_delay>{time_delay}</time_delay>\n'
        f'    <curl_max_size>{curl_max_size}</curl_max_size>\n'
        f'    <only_future_events>{only_future_str}</only_future_events>\n'
        f'    <api_auth>\n'
        f'      <org_name>{org_name}</org_name>\n'
        f'      <api_token>{api_token}</api_token>\n'
        f'    </api_auth>\n'
        f'    <api_parameters>\n'
        f'      <event_type>{event_type}</event_type>\n'
        f'    </api_parameters>\n'
        f'  </github>'
    )

    updated, n_subs = re.subn(
        r'<github>.*?</github>',
        new_block,
        content,
        flags=re.DOTALL,
    )
    if n_subs == 0:
        updated = content.replace(
            "</ossec_config>",
            f"\n  {new_block}\n</ossec_config>",
        )

    # Cache credentials for reapply after setup script re-runs
    try:
        _GITHUB_CACHE.write_text(json.dumps({
            "org_name":           org_name,
            "api_token":          api_token,
            "interval":           interval,
            "time_delay":         time_delay,
            "curl_max_size":      curl_max_size,
            "only_future_events": only_future_events,
            "event_type":         event_type,
            "enabled":            enabled,
        }, indent=2))
        _GITHUB_CACHE.chmod(0o600)
    except OSError:
        pass  # non-fatal

    backup = Path(f"{_OSSEC_CONF}.githubak")
    try:
        shutil.copy2(str(_OSSEC_CONF), str(backup))
        _OSSEC_CONF.write_text(updated)
    except PermissionError:
        return jsonify({"ok": False, "error": "Permission denied writing ossec.conf"}), 403
    except OSError:
        return jsonify({"ok": False, "error": "Failed to write ossec.conf — check server logs"}), 500

    rc, _stdout, _stderr = _run_cmd("systemctl restart wazuh-manager")
    if rc != 0:
        return add_cors_headers(jsonify({
            "ok":      False,
            "written": True,
            "error":   "Config saved but wazuh-manager restart failed — check server logs",
        })), 207

    return add_cors_headers(jsonify({
        "ok":      True,
        "enabled": enabled,
        "message": "GitHub integration configured and wazuh-manager restarted successfully",
    }))


# ══════════════════════════════════════════════════════════════════════════════
# Scheduled Tasks — GET /api/system/schedules  PUT /api/system/schedules
# Manages cron entries for: docker-maintenance, asm-wordlist, asm-scan
# Schedule file: /opt/cycentra/schedules.json
# ══════════════════════════════════════════════════════════════════════════════

_SCHEDULES_FILE = Path("/opt/cycentra/schedules.json")

# Default schedule configuration (tasks off by default)
_DEFAULT_SCHEDULES = {
    "docker_maintenance": {
        "enabled": False,
        "frequency": "monthly",
        "hour": 2,
        "minute": 0,
        "label": "Docker Maintenance",
        "command": "/opt/cycentra/docker-maintenance.sh",
        "log": "/var/log/cycentra/docker-maintenance.log",
        "desc": "Prune unused images, volumes and stopped containers",
    },
    "asm_wordlist": {
        "enabled": False,
        "frequency": "daily",
        "hour": 0,
        "minute": 0,
        "label": "ASM Wordlist Update",
        "command": None,   # resolved at runtime from installed path
        "log": "/var/log/cycentra/wordlist-update.log",
        "desc": "Update ASM subdomain wordlist from threat-intel feeds",
    },
    "asm_scan": {
        "enabled": False,
        "frequency": "weekly",
        "hour": 3,
        "minute": 0,
        "domain": "",
        "scan_type": "passive",
        "label": "ASM Scheduled Scan",
        "log": "/var/log/cycentra/asm-scheduled.log",
        "desc": "Run automated ASM scan against a target domain",
    },
    "backup": {
        "enabled": False,
        "frequency": "daily",
        "hour": 2,
        "minute": 0,
        "retain_count": 14,
        "retain_days": 30,
        "label": "Automated Backup",
        "command": "/opt/cycentra/run_backup.sh",
        "log": "/var/log/cycentra/backup.log",
        "desc": "Snapshot platform configs, env files, license and database to /opt/cycentra/backups/",
    },
}

# Maps user-friendly frequency name → cron expression template
# {H} and {M} are replaced with the configured hour/minute
_FREQ_CRON_MAP = {
    "minute":    "*/{M} * * * *",   # every N minutes (M used as interval)
    "hourly":    "{M} * * * *",
    "daily":     "{M} {H} * * *",
    "weekly":    "{M} {H} * * 1",
    "monthly":   "{M} {H} 1 * *",
    "quarterly": "{M} {H} 1 1,4,7,10 *",
    "yearly":    "{M} {H} 1 1 *",
}


def _local_to_utc(hour: int, minute: int, tz_name: str) -> tuple[int, int]:
    """Convert a local wall-clock time to UTC hour/minute using the given IANA timezone.
    Falls back to the original values if the timezone is unknown or zoneinfo unavailable."""
    if not tz_name or tz_name.upper() == "UTC":
        return hour, minute
    try:
        from zoneinfo import ZoneInfo
        from datetime import datetime as _dt
        local_dt = _dt.now(ZoneInfo(tz_name)).replace(hour=hour, minute=minute, second=0, microsecond=0)
        utc_dt   = local_dt.astimezone(ZoneInfo("UTC"))
        return utc_dt.hour, utc_dt.minute
    except Exception:
        return hour, minute


def _build_cron_expr(frequency: str, hour: int, minute: int) -> str:
    template = _FREQ_CRON_MAP.get(frequency, "{M} {H} * * *")
    # */0 is invalid cron syntax — Ubuntu cron silently skips the entire job.
    # When "every minute" is selected the minute field is hidden in the UI so
    # it stays at its previous value; clamp 0 → 1 so we always emit */1 (every minute).
    if frequency == "minute" and minute == 0:
        minute = 1
    return template.replace("{H}", str(hour)).replace("{M}", str(minute))


def _resolve_wordlist_path() -> str | None:
    """Find update_wordlist.py — located under cy_asm/modules/Utils/."""
    import glob as _glob
    for pattern in [
        # Primary location (confirmed path structure)
        "/usr/local/lib/python3.*/dist-packages/cy_asm/modules/Utils/update_wordlist.py",
        # Fallback variations
        "/usr/local/lib/python3.*/dist-packages/cy_asm/modules/Utils/update_wordlist/update_wordlist.py",
        "/usr/lib/python3/dist-packages/cy_asm/modules/Utils/update_wordlist.py",
        "/usr/local/lib/python3.*/site-packages/cy_asm/modules/Utils/update_wordlist.py",
        # Legacy flat-layout fallback (pre-Utils restructure)
        "/usr/local/lib/python3.*/dist-packages/cy_asm/modules/update_wordlist.py",
    ]:
        hits = sorted(_glob.glob(pattern))
        if hits:
            return hits[-1]  # take highest python version match
    return None


def _build_asm_scan_cron_cmd(domain: str, scan_type: str, log: str) -> str:
    """Build the curl command that triggers the ASM scan endpoint from cron."""
    base_url = os.environ.get("BASE_URL", "https://cyasm.cycentra.com")
    # Wrap in a subshell so we can emit a timestamped header before the curl JSON response.
    return (
        f'{{ echo "[$(date \'+\\%Y-\\%m-\\%d \\%H:\\%M:\\%S UTC\')] Triggering {scan_type} scan → {domain}"; '
        f'curl -s -X POST {base_url}/api/scan/trigger '
        f'-H "Content-Type: application/json" '
        f'-b /opt/cycentra/cron_session.cookie '
        f'-d \'{{"domain":"{domain}","scan_type":"{scan_type}","uid":"scheduler"}}\'; '
        f'echo; }} >> {log} 2>&1'
    )


def _write_docker_maintenance_script():
    """Write /opt/cycentra/docker-maintenance.sh — mirrors how backup writes run_backup.sh.
    Called each time the docker_maintenance schedule is applied so the script is always present."""
    script = """\
#!/bin/bash
# CyCentra 360 — Docker Maintenance
# Generated by the system scheduler — do not edit manually.
# Removes stopped containers, unused networks, stale images (>14 days),
# build cache, and orphaned volumes.

RETENTION="336h"
TS=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$TS] Docker maintenance starting"
docker system df

echo "[$TS] Step 1: Removing stopped containers and unused networks..."
docker system prune -f

echo "[$TS] Step 2: Removing images older than $RETENTION..."
docker image prune -a -f --filter "until=$RETENTION"

echo "[$TS] Step 3: Cleaning up build cache..."
docker builder prune -f

echo "[$TS] Step 4: Clearing orphaned volumes..."
docker volume prune -f

echo "[$TS] Docker maintenance complete. New usage:"
docker system df
"""
    try:
        script_path = Path("/opt/cycentra/docker-maintenance.sh")
        script_path.write_text(script)
        script_path.chmod(0o755)
    except OSError:
        pass


def _load_schedules() -> dict:
    if _SCHEDULES_FILE.exists():
        try:
            stored = json.loads(_SCHEDULES_FILE.read_text())
            # Merge with defaults to fill in any new tasks added in later versions
            merged = {}
            for k, default in _DEFAULT_SCHEDULES.items():
                task = {**default, **stored.get(k, {})}
                # Log path is not user-configurable — always use the current default
                # so relocated log destinations are reflected immediately in the UI
                task["log"] = default["log"]
                merged[k] = task
            return merged
        except Exception:
            pass
    return dict(_DEFAULT_SCHEDULES)


def _apply_schedules(schedules: dict) -> list[str]:
    """Re-write cron entries for all managed tasks. Returns list of applied entries."""
    import tempfile as _tempfile

    # Timezone stored at the top level of the schedules dict; falls back to UTC.
    tz = schedules.get("_timezone", "UTC") or "UTC"

    def _cron(task: dict, default_freq: str, default_hour: int, default_minute: int) -> str:
        freq = task.get("frequency", default_freq)
        h    = task.get("hour",   default_hour)
        m    = task.get("minute", default_minute)
        # "minute" frequency (*/N) is independent of wall-clock time — no conversion needed.
        if freq != "minute":
            h, m = _local_to_utc(h, m, tz)
        return _build_cron_expr(freq, h, m)

    # Read current crontab, strip all cycentra-managed lines
    rc, crontab_out, _ = _run_cmd("crontab -l")
    lines = [] if rc != 0 else crontab_out.splitlines()
    managed_markers = [
        "docker-maintenance.sh",
        "update_wordlist",
        "asm-scan-cron",
        "cycentra-backup-cron",
    ]
    filtered = [
        ln for ln in lines
        if not any(m in ln for m in managed_markers)
    ]

    applied = []

    # docker_maintenance
    dm = schedules.get("docker_maintenance", {})
    if dm.get("enabled"):
        try:
            _write_docker_maintenance_script()
        except Exception:
            pass
        expr = _cron(dm, "monthly", 2, 0)
        cmd  = dm.get("command") or "/opt/cycentra/docker-maintenance.sh"
        log  = dm.get("log") or "/var/log/cycentra/docker-maintenance.log"
        entry = f"{expr} {cmd} >> {log} 2>&1  # cycentra docker-maintenance.sh"
        filtered.append(entry)
        applied.append(entry)

    # asm_wordlist
    wl = schedules.get("asm_wordlist", {})
    if wl.get("enabled"):
        wl_path = _resolve_wordlist_path()
        if wl_path:
            expr = _cron(wl, "daily", 0, 0)
            python_bin = os.environ.get("PYTHON_BIN", "python3")
            log  = wl.get("log") or "/var/log/cycentra/wordlist-update.log"
            # update_wordlist.py uses a relative SAVE_PATH ("wordlists/subdomains.txt").
            # Cron's working dir is /root, so without cd the file lands in /root/wordlists/
            # instead of the cy_asm package dir the scanner reads from.
            # Subshell adds timestamps so the log clearly shows when each run started/ended.
            modules_dir = str(Path(wl_path).parent.parent)
            entry = (
                f"{expr} {{ echo \"[$(date '+\\%Y-\\%m-\\%d \\%H:\\%M:\\%S UTC')] Wordlist update starting\"; "
                f"cd {modules_dir} && {python_bin} {wl_path}; "
                f"echo \"[$(date '+\\%Y-\\%m-\\%d \\%H:\\%M:\\%S UTC')] Wordlist update complete\"; "
                f"}} >> {log} 2>&1  # cycentra update_wordlist"
            )
            filtered.append(entry)
            applied.append(entry)

    # asm_scan
    sc = schedules.get("asm_scan", {})
    if sc.get("enabled"):
        # Domain is always BASE_DOMAIN — read from env (not from stored config)
        domain = os.environ.get("BASE_DOMAIN", "").strip()
        if not domain:
            try:
                for line in Path("/opt/cycentra/.env").read_text().splitlines():
                    if line.startswith("BASE_DOMAIN="):
                        domain = line.split("=", 1)[1].strip().strip('"').strip("'")
                        break
            except Exception:
                pass
        if domain:
            expr   = _cron(sc, "weekly", 3, 0)
            scan_t = sc.get("scan_type", "passive")
            log    = sc.get("log") or "/var/log/cycentra/asm-scheduled.log"
            cmd    = _build_asm_scan_cron_cmd(domain, scan_t, log)
            entry  = f"{expr} {cmd}  # cycentra asm-scan-cron"
            filtered.append(entry)
            applied.append(entry)

    # backup
    bk = schedules.get("backup", {})
    if bk.get("enabled"):
        # Regenerate run_backup.sh with current retain settings
        try:
            from blueprints.backup.routes import _write_backup_script
            _write_backup_script(
                retain_count=int(bk.get("retain_count", 14)),
                retain_days=int(bk.get("retain_days", 30)),
            )
        except Exception:
            pass
        expr  = _cron(bk, "daily", 2, 0)
        cmd   = bk.get("command") or "/opt/cycentra/run_backup.sh"
        log   = bk.get("log") or "/var/log/cycentra/backup.log"
        entry = f"{expr} {cmd} >> {log} 2>&1  # cycentra-backup-cron"
        filtered.append(entry)
        applied.append(entry)

    # Write new crontab
    new_crontab = "\n".join(filtered) + ("\n" if filtered else "")
    try:
        with _tempfile.NamedTemporaryFile(mode="w", suffix=".cron", delete=False) as tf:
            tf.write(new_crontab)
            tmp_path = tf.name
        _run_cmd(f"crontab {tmp_path}")
        import os as _os
        _os.unlink(tmp_path)
    except Exception:
        pass

    return applied


@system_bp.route("/api/system/schedules", methods=["OPTIONS"])
def schedules_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/schedules", methods=["GET"])
def get_schedules():
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    schedules = _load_schedules()
    # Resolve wordlist path availability for the UI
    schedules["asm_wordlist"]["_available"] = bool(_resolve_wordlist_path())
    # Expose BASE_DOMAIN so the frontend can show the hardcoded scan target
    base_domain = os.environ.get("BASE_DOMAIN", "")
    if not base_domain:
        # Try reading from .env directly (dev / no-systemd environments)
        try:
            for line in Path("/opt/cycentra/.env").read_text().splitlines():
                if line.startswith("BASE_DOMAIN="):
                    base_domain = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break
        except Exception:
            pass
    # Always set ASM scan domain to BASE_DOMAIN — not user-configurable
    schedules["asm_scan"]["domain"] = base_domain
    timezone = schedules.pop("_timezone", "UTC") or "UTC"
    return jsonify({"schedules": schedules, "base_domain": base_domain, "timezone": timezone})


@system_bp.route("/api/system/schedules", methods=["PUT"])
def put_schedules():
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) != "admin":
        return jsonify({"error": "Admin role required"}), 403

    body     = request.get_json() or {}
    incoming = body.get("schedules", {})
    timezone = (body.get("timezone") or "UTC").strip()
    if not isinstance(incoming, dict):
        return jsonify({"error": "Invalid payload"}), 400

    # Validate and merge
    current = _load_schedules()
    allowed_frequencies = set(_FREQ_CRON_MAP.keys())
    for task_id, patch in incoming.items():
        if task_id not in current:
            continue
        if "frequency" in patch and patch["frequency"] not in allowed_frequencies:
            return jsonify({"error": f"Invalid frequency '{patch['frequency']}'"}), 400
        # Domain for asm_scan is always sourced from BASE_DOMAIN — never from client
        if task_id == "asm_scan":
            patch.pop("domain", None)
        current[task_id].update({k: v for k, v in patch.items() if not k.startswith("_")})

    # Persist timezone alongside schedules so it survives server restarts
    current["_timezone"] = timezone

    # Save
    try:
        _SCHEDULES_FILE.write_text(json.dumps(current, indent=2))
    except Exception as e:
        return jsonify({"error": f"Could not save schedules: {e}"}), 500

    applied = _apply_schedules(current)
    return jsonify({"ok": True, "applied": len(applied), "entries": applied, "timezone": timezone})


@system_bp.route("/api/system/schedule-log/<task_id>", methods=["OPTIONS"])
def schedule_log_options(task_id):
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/schedule-log/<task_id>", methods=["GET"])
def schedule_log_get(task_id):
    """Return the last N lines from a scheduled task's log file."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    schedules = _load_schedules()
    if task_id not in schedules:
        return jsonify({"error": "Unknown task"}), 404

    log_path = Path(schedules[task_id].get("log", ""))
    if not log_path or not log_path.exists():
        return add_cors_headers(jsonify({"ok": True, "lines": [], "path": str(log_path)}))

    try:
        lines = log_path.read_text(errors="replace").splitlines()
        tail = lines[-30:] if len(lines) > 30 else lines
    except OSError:
        return add_cors_headers(jsonify({"ok": True, "lines": [], "path": str(log_path)}))

    return add_cors_headers(jsonify({"ok": True, "lines": tail, "path": str(log_path)}))


# ── Server resource metrics ───────────────────────────────────────────────────

@system_bp.route("/api/system/server-status", methods=["OPTIONS"])
def server_status_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/server-status", methods=["GET"])
def server_status_get():
    """Return live host CPU, RAM, disk and uptime metrics via psutil."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) not in ("admin", "analyst"):
        return jsonify({"error": "Admin or analyst role required"}), 403

    try:
        import psutil
        import time as _time
        import platform as _platform
        import socket as _socket

        cpu      = psutil.cpu_percent(interval=0.5)
        mem      = psutil.virtual_memory()
        disk     = psutil.disk_usage("/")
        uptime   = int(_time.time() - psutil.boot_time())
        load     = list(psutil.getloadavg()) if hasattr(psutil, "getloadavg") else [0.0, 0.0, 0.0]
        cpu_count = psutil.cpu_count(logical=True)

        # Top 8 processes by CPU
        top_procs = []
        try:
            procs = []
            for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
                try:
                    procs.append(p.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            procs.sort(key=lambda x: x.get("cpu_percent") or 0, reverse=True)
            top_procs = [
                {
                    "pid":         p["pid"],
                    "name":        p["name"],
                    "cpu_percent": round(p.get("cpu_percent") or 0, 1),
                    "mem_percent": round(p.get("memory_percent") or 0, 1),
                }
                for p in procs[:8]
            ]
        except Exception:
            pass

        return add_cors_headers(jsonify({
            "ok":             True,
            "hostname":       _socket.gethostname(),
            "platform":       _platform.system() + " " + _platform.release(),
            "python_version": _platform.python_version(),
            "cpu_percent":    cpu,
            "cpu_count":      cpu_count,
            "ram_used_gb":    round(mem.used  / 1_073_741_824, 2),
            "ram_total_gb":   round(mem.total / 1_073_741_824, 2),
            "ram_percent":    mem.percent,
            "disk_used_gb":   round(disk.used  / 1_073_741_824, 2),
            "disk_total_gb":  round(disk.total / 1_073_741_824, 2),
            "disk_percent":   disk.percent,
            "uptime_seconds": uptime,
            "load_avg":       load,
            "top_processes":  top_procs,
        }))

    except ImportError:
        return jsonify({"ok": False, "error": "psutil not available — run: pip install psutil"}), 503
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# ── Agent Installer ───────────────────────────────────────────────────────────

_AGENT_PKG_DIR = Path("/var/lib/cycentra-agent-packages")

_INSTALLER_SH = """\
#!/bin/bash
# CyCentra 360 — Universal Agent Installer
# Generated by CyCentra 360 portal — {version}
# Server: {server_url}
# ──────────────────────────────────────────────────────────────────────────────
# This script auto-detects your OS and CPU architecture, downloads the
# matching agent package from your CyCentra 360 server over HTTPS, installs it,
# and registers the agent automatically using the pre-configured server address.
#
# Usage (Linux/macOS):
#   bash agent-installer.sh
# ──────────────────────────────────────────────────────────────────────────────

# Re-launch as root if not already (installation requires root)
if [[ ${{EUID}} -ne 0 ]]; then
    echo "  Root required — re-launching with sudo ..."
    exec sudo bash "${{BASH_SOURCE[0]}}" "$@"
fi

set -euo pipefail

SERVER_URL="{server_url}"
WAZUH_MANAGER="{wazuh_manager}"
AGENT_VERSION="{version}"
PKG_BASE="${{SERVER_URL}}/agent-packages"
TMPDIR_DL="/var/tmp"

OS=$(uname -s)
ARCH=$(uname -m)

info()  {{ echo -e "\\033[0;36m  ▸\\033[0m $*"; }}
ok()    {{ echo -e "\\033[0;32m  ✓\\033[0m $*"; }}
err()   {{ echo -e "\\033[0;31m  ✗\\033[0m $*" >&2; exit 1; }}

info "CyCentra 360 Agent Installer — ${{AGENT_VERSION}}"
info "Server  : ${{SERVER_URL}}"
info "Manager : ${{WAZUH_MANAGER}}"
info "OS      : ${{OS}} / ${{ARCH}}"
echo

download_pkg() {{
    local pkg="$1"
    local url="${{PKG_BASE}}/${{pkg}}"
    local dest="${{TMPDIR_DL}}/${{pkg}}"
    info "Downloading ${{pkg}} ..." >&2
    if command -v curl &>/dev/null; then
        curl -fsSL --retry 3 --retry-delay 2 -o "${{dest}}" "${{url}}" || err "Download failed: ${{url}}"
    elif command -v wget &>/dev/null; then
        wget -q --tries=3 -O "${{dest}}" "${{url}}" || err "Download failed: ${{url}}"
    else
        err "curl or wget is required"
    fi
    ok "Downloaded ${{pkg}}" >&2
    echo "${{dest}}"
}}

_register_agent() {{
    local manager="$1" name="$2" auth_bin="$3" ctrl_bin="$4"
    info "Registering agent '${{name}}' with ${{manager}} ..."
    local _auth_out _auth_rc=0
    _auth_out=$("${{auth_bin}}" -m "${{manager}}" -A "${{name}}" 2>&1) || _auth_rc=$?
    echo "${{_auth_out}}"
    if [[ $_auth_rc -ne 0 ]]; then
        if echo "${{_auth_out}}" | grep -qi "Duplicate agent"; then
            ok "Agent '${{name}}' is already registered on the manager — upgrade detected."
            ok "Existing agent key preserved. Agent will be restarted after configuration."
        else
            err "Agent registration failed — check: (1) port 1515 reachable from this host: nc -zv ${{manager}} 1515 | (2) agent name conflicts on manager | (3) manager logs: tail -f /var/ossec/logs/ossec.log"
        fi
    fi
}}

case "${{OS}}" in
  Linux)
    OSSEC_CONF="/var/ossec/etc/ossec.conf"
    AUTH_BIN="/var/ossec/bin/agent-auth"
    CTRL_BIN="/var/ossec/bin/wazuh-control"

    if command -v rpm &>/dev/null && (command -v yum &>/dev/null || command -v dnf &>/dev/null); then
      case "${{ARCH}}" in
        x86_64|amd64)  PKG="cy360-agent-${{AGENT_VERSION}}-x86_64.rpm" ;;
        aarch64|arm64) PKG="cy360-agent-${{AGENT_VERSION}}-aarch64.rpm" ;;
        *) err "Unsupported architecture: ${{ARCH}}" ;;
      esac
      TMP=$(download_pkg "${{PKG}}")
      info "Installing (RPM) ..."
      WAZUH_MANAGER="${{WAZUH_MANAGER}}" rpm -ihv "${{TMP}}" || \
          WAZUH_MANAGER="${{WAZUH_MANAGER}}" rpm -Uvh "${{TMP}}" || err "RPM install failed"
    elif command -v dpkg &>/dev/null; then
      case "${{ARCH}}" in
        x86_64|amd64) PKG="cy360-agent-${{AGENT_VERSION}}-amd64.deb" ;;
        aarch64|arm64) PKG="cy360-agent-${{AGENT_VERSION}}-aarch64.deb" ;;
        *) err "Unsupported architecture: ${{ARCH}}" ;;
      esac
      TMP=$(download_pkg "${{PKG}}")
      info "Installing (DEB) ..."
      WAZUH_MANAGER="${{WAZUH_MANAGER}}" dpkg -i "${{TMP}}" || err "DEB install failed"
    else
      err "No supported package manager found (expected rpm/yum/dnf or dpkg/apt)"
    fi

    # Patch ossec.conf manager address — handles upgrades where postinstall skips config.
    [[ -f "${{OSSEC_CONF}}" ]] && \
        sed -i "s|<address>.*</address>|<address>${{WAZUH_MANAGER}}</address>|" "${{OSSEC_CONF}}" 2>/dev/null || true

    systemctl daemon-reload
    systemctl enable cy360-agent 2>/dev/null || systemctl enable wazuh-agent 2>/dev/null || true
    _register_agent "${{WAZUH_MANAGER}}" "$(hostname -s)" "${{AUTH_BIN}}" "${{CTRL_BIN}}"
    systemctl restart cy360-agent 2>/dev/null || systemctl restart wazuh-agent 2>/dev/null || true
    ok "CyCentra 360 Agent installed and running."

    # ── auditd: kernel-level telemetry ──────────────────────────────────────
    info "Installing auditd for kernel telemetry ..."
    if command -v apt-get &>/dev/null; then
        apt-get install -y auditd audispd-plugins 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        yum install -y audit 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        dnf install -y audit 2>/dev/null || true
    fi

    AUDIT_RULES_DIR="/etc/audit/rules.d"
    AUDIT_RULES_FILE="${{AUDIT_RULES_DIR}}/cy360-baseline.rules"
    mkdir -p "${{AUDIT_RULES_DIR}}"
    cat > "${{AUDIT_RULES_FILE}}" <<'AUDITEOF'
## CyCentra 360 — Baseline Audit Rules
# Process execution
-a always,exit -F arch=b64 -S execve -k cy360_exec
-a always,exit -F arch=b32 -S execve -k cy360_exec
# Privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k cy360_privesc
-a always,exit -F arch=b64 -S ptrace -k cy360_privesc
# Fileless malware / process injection syscalls
-a always,exit -F arch=b64 -S memfd_create -k cy360_exec
-a always,exit -F arch=b64 -S process_vm_writev -k cy360_privesc
-a always,exit -F arch=b64 -S process_vm_readv -k cy360_privesc
# CyCentra agent self-defense — monitor for tampering
-w /var/ossec/ -p wxa -k cy360_agent_tamper
-w /var/ossec/etc/ossec.conf -p wa -k cy360_agent_tamper
-w /var/ossec/bin/ -p xa -k cy360_agent_tamper
AUDITEOF
    ok "Audit rules written to ${{AUDIT_RULES_FILE}}"

    if command -v augenrules &>/dev/null; then
        augenrules --load 2>/dev/null || true
    elif command -v auditctl &>/dev/null; then
        auditctl -R "${{AUDIT_RULES_FILE}}" 2>/dev/null || true
    fi

    systemctl enable auditd 2>/dev/null || true
    systemctl restart auditd 2>/dev/null || true

    # Append auditd localfile reader to ossec.conf (idempotent)
    if [[ -f "${{OSSEC_CONF}}" ]] && ! grep -q "audit/audit.log" "${{OSSEC_CONF}}"; then
        sed -i 's|</ossec_config>||' "${{OSSEC_CONF}}"
        cat >> "${{OSSEC_CONF}}" <<'OSSECEOF'

  <!-- CyCentra 360: auditd kernel telemetry -->
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

</ossec_config>
OSSECEOF
        ok "auditd localfile reader added to ossec.conf"
    fi
    systemctl restart cy360-agent 2>/dev/null || systemctl restart wazuh-agent 2>/dev/null || true
    ok "auditd kernel telemetry configured."
    ;;

  Darwin)
    OSSEC_CONF="/Library/Ossec/etc/ossec.conf"
    AUTH_BIN="/Library/Ossec/bin/agent-auth"
    CTRL_BIN="/Library/Ossec/bin/wazuh-control"

    case "${{ARCH}}" in
      x86_64) PKG="cy360-agent-${{AGENT_VERSION}}-intel64.pkg" ;;
      arm64)  PKG="cy360-agent-${{AGENT_VERSION}}-arm64.pkg" ;;
      *)      err "Unsupported architecture: ${{ARCH}}" ;;
    esac
    TMP=$(download_pkg "${{PKG}}")
    xattr -rc "${{TMP}}" 2>/dev/null || true
    # Write wazuh_envs before PKG so preinstall picks it up on fresh installs.
    echo "WAZUH_MANAGER='${{WAZUH_MANAGER}}'" > /tmp/wazuh_envs
    info "Installing (PKG) ..."
    installer -pkg "${{TMP}}" -target / || err "macOS installer failed"

    # Patch ossec.conf manager address — handles upgrades where PKG preinstall skips config.
    [[ -f "${{OSSEC_CONF}}" ]] && \
        sed -i '' "s|<address>.*</address>|<address>${{WAZUH_MANAGER}}</address>|" "${{OSSEC_CONF}}" 2>/dev/null || true

    _register_agent "${{WAZUH_MANAGER}}" "${{HOSTNAME:-$(hostname -s)}}" "${{AUTH_BIN}}" "${{CTRL_BIN}}"

    # ── Apple Unified Logging (ULS) telemetry ───────────────────────────────
    if [[ -f "${{OSSEC_CONF}}" ]] && ! grep -qF "<log_format>macos</log_format>" "${{OSSEC_CONF}}"; then
        sed -i '' 's|</ossec_config>||' "${{OSSEC_CONF}}"
        cat >> "${{OSSEC_CONF}}" <<'MACEOF'

  <!-- CyCentra 360: Apple Unified Logging System (ULS) telemetry -->
  <localfile>
    <log_format>macos</log_format>
    <query type="activity" level="debug">
      <![CDATA[
        process == "sudo"
        OR process == "sshd"
        OR process == "SecurityAgent"
        OR process == "com.apple.securityd"
      ]]>
    </query>
  </localfile>

</ossec_config>
MACEOF
        ok "Apple ULS data stream added to ossec.conf"
    fi

    # Single restart after all config is applied (avoids double-restart on upgrades)
    "${{CTRL_BIN}}" restart 2>/dev/null || true
    ok "CyCentra 360 Agent installed and running."

    echo ""
    echo "  ──────────────────────────────────────────────────────────────────"
    echo "  ACTION REQUIRED: macOS Full Disk Access"
    echo "  The CyCentra agent requires Full Disk Access to collect logs."
    echo "  Go to: System Settings > Privacy & Security > Full Disk Access"
    echo "  Add and enable both of the following binaries:"
    echo "    /Library/Ossec/bin/wazuh-agentd"
    echo "    /Library/Ossec/bin/wazuh-logcollector"
    echo ""
    echo "  NOTE: wazuh-logcollector will not start until FDA is granted."
    echo "  After granting FDA, restart the agent:"
    echo "    sudo /Library/Ossec/bin/wazuh-control restart"
    echo "  ──────────────────────────────────────────────────────────────────"
    echo ""
    ok "Apple ULS telemetry configured."
    ;;

  *)
    err "Unsupported OS: ${{OS}}. Use the Windows installer (agent-installer.ps1) on Windows."
    ;;
esac

rm -f "${{TMP}}" 2>/dev/null || true
"""

_INSTALLER_PS1 = """\
# CyCentra 360 — Universal Agent Installer (Windows)
# Generated by CyCentra 360 portal — {version}
# Server: {server_url}
# ──────────────────────────────────────────────────────────────────────────────
# Run in an elevated PowerShell session:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
#   .\\agent-installer.ps1
# ──────────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = "Stop"

$ServerUrl     = "{server_url}"
$WazuhManager  = "{wazuh_manager}"
$AgentVersion  = "{version}"
$PkgBase       = "$ServerUrl/agent-packages"

Write-Host "  CyCentra 360 Agent Installer — $AgentVersion" -ForegroundColor Cyan
Write-Host "  Server  : $ServerUrl"
Write-Host "  Manager : $WazuhManager"

# Detect architecture
$Is64 = [System.Environment]::Is64BitOperatingSystem
$PkgName = "cy360-agent-$AgentVersion.msi"
$PkgUrl  = "$PkgBase/$PkgName"
$TmpPath = "$env:TEMP\\cy360-agent.msi"

Write-Host "  Downloading $PkgName ..." -ForegroundColor Cyan
try {{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $PkgUrl -OutFile $TmpPath -UseBasicParsing
}} catch {{
    Write-Host "  Download failed: $_" -ForegroundColor Red
    exit 1
}}
Write-Host "  Downloaded." -ForegroundColor Green

Write-Host "  Installing agent ..." -ForegroundColor Cyan
$AgentName   = $env:COMPUTERNAME
$InstallArgs = "/i `"$TmpPath`" /q WAZUH_MANAGER=`"$WazuhManager`" WAZUH_AGENT_NAME=`"$AgentName`""
$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $InstallArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {{
    Write-Host "  Installation failed (exit code: $($proc.ExitCode))" -ForegroundColor Red
    exit 1
}}

# Re-register explicitly — MSI upgrade preserves old client.keys and skips registration.
# agent-auth always produces a valid key whether this is a fresh install or reinstall.
Write-Host "  Registering agent '$AgentName' with $WazuhManager ..." -ForegroundColor Cyan
$AgentAuth = "C:\Program Files (x86)\ossec-agent\agent-auth.exe"
if (Test-Path $AgentAuth) {{
    $authProc = Start-Process -FilePath $AgentAuth `
        -ArgumentList "-m `"$WazuhManager`" -A `"$AgentName`"" `
        -Wait -PassThru -NoNewWindow
    if ($authProc.ExitCode -ne 0) {{
        Write-Host "  Warning: agent-auth exited $($authProc.ExitCode) — check port 1515 reachability" -ForegroundColor Yellow
    }}
}} else {{
    Write-Host "  Warning: agent-auth.exe not found at $AgentAuth" -ForegroundColor Yellow
}}

Write-Host "  Starting agent service ..." -ForegroundColor Cyan
try {{ NET STOP Wazuh 2>&1 | Out-Null }} catch {{}}
Start-Sleep -Seconds 2
try {{ NET START Wazuh 2>&1 | Out-Null }} catch {{}}

Write-Host "  CyCentra 360 Agent installed and running." -ForegroundColor Green

# ── Sysmon: kernel-level telemetry ──────────────────────────────────────────
Write-Host "  Setting up Sysmon for kernel telemetry ..." -ForegroundColor Cyan

$StagingDir = "C:\CyCentra\Sysmon"
if (-not (Test-Path $StagingDir)) {{
    New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null
}}

$SysmonUrl    = "https://live.sysinternals.com/Sysmon64.exe"
$SysmonExe    = "$StagingDir\sysmon64.exe"
$SysmonConfig = "$StagingDir\sysmon-config.xml"
$OssecConf    = "C:\Program Files (x86)\ossec-agent\ossec.conf"

# Download Sysmon64 from Sysinternals
try {{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $SysmonUrl -OutFile $SysmonExe -UseBasicParsing
    Write-Host "  sysmon64.exe downloaded." -ForegroundColor Green
}} catch {{
    Write-Host "  Warning: Could not download Sysmon64 — $($_.Exception.Message)" -ForegroundColor Yellow
}}

# Write hardened sysmon-config.xml to staging directory
$SysmonConfigContent = @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256,IMPHASH</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="exclude"/>
    <NetworkConnect onmatch="exclude">
      <Image condition="is">C:\Windows\System32\svchost.exe</Image>
    </NetworkConnect>
    <DriverLoad onmatch="exclude"/>
    <ImageLoad onmatch="exclude"/>
    <ProcessAccess onmatch="exclude"/>
    <FileCreateTime onmatch="exclude"/>
    <RawAccessRead onmatch="exclude"/>
    <RegistryEvent onmatch="exclude"/>
    <PipeEvent onmatch="exclude"/>
    <WmiEvent onmatch="exclude"/>
    <DnsQuery onmatch="exclude"/>
    <FileDelete onmatch="exclude"/>
  </EventFiltering>
</Sysmon>
'@
$SysmonConfigContent | Set-Content -Path $SysmonConfig -Encoding UTF8

# Install Sysmon silently with EULA accepted
if (Test-Path $SysmonExe) {{
    $sysmonProc = Start-Process -FilePath $SysmonExe `
        -ArgumentList "-i `"$SysmonConfig`" -accepteula -s" `
        -Wait -PassThru -NoNewWindow
    if ($sysmonProc.ExitCode -eq 0) {{
        Write-Host "  Sysmon installed successfully." -ForegroundColor Green
    }} else {{
        Write-Host "  Warning: Sysmon install exited $($sysmonProc.ExitCode)" -ForegroundColor Yellow
    }}
}} else {{
    Write-Host "  Warning: sysmon64.exe not found at $SysmonExe — skipping install." -ForegroundColor Yellow
}}

# Append Sysmon event channel reader to ossec.conf (idempotent)
if (Test-Path $OssecConf) {{
    $confContent = Get-Content $OssecConf -Raw
    if ($confContent -notmatch "Sysmon/Operational") {{
        $sysmonBlock = @'

  <!-- CyCentra 360: Sysmon kernel telemetry -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-Sysmon/Operational</location>
  </localfile>

'@
        $confContent = $confContent -replace "</ossec_config>", "$sysmonBlock</ossec_config>"
        Set-Content -Path $OssecConf -Value $confContent -Encoding UTF8
        Write-Host "  Sysmon eventchannel reader added to ossec.conf" -ForegroundColor Green
    }} else {{
        Write-Host "  Sysmon eventchannel already present in ossec.conf — skipping." -ForegroundColor Cyan
    }}
    try {{ NET STOP WazuhSvc 2>&1 | Out-Null }} catch {{}}
    try {{ NET STOP Wazuh 2>&1 | Out-Null }} catch {{}}
    Start-Sleep -Seconds 2
    try {{ NET START WazuhSvc 2>&1 | Out-Null }} catch {{}}
    try {{ NET START Wazuh 2>&1 | Out-Null }} catch {{}}
}} else {{
    Write-Host "  Warning: ossec.conf not found at $OssecConf — Sysmon channel not registered." -ForegroundColor Yellow
}}
Write-Host "  Sysmon kernel telemetry configured." -ForegroundColor Green
"""


def _read_installed_version() -> str:
    for vf in ("/opt/cycentra/version", "/opt/cycentra/.version"):
        if os.path.exists(vf):
            return open(vf).read().strip().lstrip("v")
    return "1.0.0"


@system_bp.route("/api/system/agent-installer", methods=["OPTIONS"])
def agent_installer_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/agent-installer", methods=["GET"])
def get_agent_installer():
    """Generate and stream a pre-configured agent installer script.

    Query params:
        format  unix (default) | windows
    """
    if not session.get("user_email"):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    fmt = request.args.get("format", "unix").lower()
    base_domain  = os.environ.get("BASE_DOMAIN", "").strip()
    server_url   = f"https://cy360.{base_domain}" if base_domain else request.host_url.rstrip("/")
    wazuh_manager = (
        os.environ.get("CY360_PUBLIC_IP") or
        os.environ.get("WAZUH_MANAGER_IP") or
        (f"cysiem.{base_domain}" if base_domain else request.host.split(":")[0])
    )
    version      = _read_installed_version()

    if fmt == "windows":
        content  = _INSTALLER_PS1.format(
            server_url=server_url,
            wazuh_manager=wazuh_manager,
            version=version,
        )
        filename = "agent-installer.ps1"
        mimetype = "text/plain"
    else:
        content  = _INSTALLER_SH.format(
            server_url=server_url,
            wazuh_manager=wazuh_manager,
            version=version,
        )
        filename = "agent-installer.sh"
        mimetype = "text/x-shellscript"

    resp = make_response(content)
    resp.headers["Content-Type"]        = f"{mimetype}; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return add_cors_headers(resp)


@system_bp.route("/api/system/agent-packages", methods=["GET"])
def list_agent_packages():
    """Return available agent packages from /var/lib/cycentra-agent-packages/."""
    if not session.get("user_email"):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    base_domain    = os.environ.get("BASE_DOMAIN", "").strip()
    server_url     = f"https://cy360.{base_domain}" if base_domain else request.host_url.rstrip("/")
    wazuh_manager  = (
        os.environ.get("CY360_PUBLIC_IP") or
        os.environ.get("WAZUH_MANAGER_IP") or
        (f"cysiem.{base_domain}" if base_domain else request.host.split(":")[0])
    )
    version        = _read_installed_version()
    packages       = []

    if _AGENT_PKG_DIR.exists():
        for f in sorted(_AGENT_PKG_DIR.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                st = f.stat()
                packages.append({
                    "name":        f.name,
                    "url":         f"{server_url}/agent-packages/{f.name}",
                    "size_bytes":  st.st_size,
                    "modified":    int(st.st_mtime),
                })

    return add_cors_headers(jsonify({
        "ok":           True,
        "version":      version,
        "server_url":   server_url,
        "wazuh_manager": wazuh_manager,
        "pkg_dir":      str(_AGENT_PKG_DIR),
        "packages":     packages,
    }))


@system_bp.route("/api/system/agent-packages/prune", methods=["DELETE"])
def prune_agent_packages():
    """Delete all packages from version groups older than the 3 most-recent versions."""
    if not session.get("user_email"):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    if not _AGENT_PKG_DIR.exists():
        return add_cors_headers(jsonify({"ok": True, "deleted": []}))

    all_pkgs = [f for f in _AGENT_PKG_DIR.iterdir() if f.is_file() and not f.name.startswith(".")]

    by_version = {}
    for f in all_pkgs:
        m = re.search(r"(\d+\.\d+\.\d+(?:\.\d+)?)", f.name)
        v = m.group(1) if m else "unknown"
        if v not in by_version:
            by_version[v] = {"files": [], "max_mtime": 0}
        by_version[v]["files"].append(f)
        mtime = f.stat().st_mtime
        if mtime > by_version[v]["max_mtime"]:
            by_version[v]["max_mtime"] = mtime

    sorted_versions = sorted(by_version.items(), key=lambda kv: kv[1]["max_mtime"], reverse=True)
    to_delete = [f for _, grp in sorted_versions[3:] for f in grp["files"]]

    deleted, errors = [], []
    for f in to_delete:
        try:
            f.unlink()
            deleted.append(f.name)
        except Exception as e:
            errors.append({"file": f.name, "error": str(e)})

    return add_cors_headers(jsonify({"ok": not errors, "deleted": deleted, "errors": errors}))


@system_bp.route("/api/system/agent-packages/prune", methods=["OPTIONS"])
def prune_agent_packages_options():
    return add_cors_headers(make_response("", 204))


# ── Phase 6: AI Investigation Stats ────────────────────────────────────────────

@system_bp.route("/api/system/ai-stats", methods=["GET"])
def system_ai_stats():
    """Return aggregate AI investigation engine stats for the portal Settings card.

    Returns:
      {
        patterns_total,         — total stored incident patterns
        avg_confidence_accuracy,— avg confidence score at resolution (as proxy for accuracy)
        phases_active,          — list of active phases ["phase1".."phase6"]
        last_pattern_at,        — ISO timestamp of most recent pattern
      }
    GET → viewer+
    """
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        import os as _os, psycopg2, psycopg2.extras

        db_url = (
            _os.environ.get("CYCENTRA_DB_URL")
            or _os.environ.get("CORRELATION_DB_URL")
            or _os.environ.get("DATABASE_URL",
               "postgresql://corruser:changeme@127.0.0.1:5433/correlation")
        ).replace("+asyncpg", "")

        conn = psycopg2.connect(db_url)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    COUNT(*)                                AS patterns_total,
                    AVG(confidence_at_resolution)           AS avg_confidence,
                    MAX(created_at)                         AS last_pattern_at
                FROM incident_patterns
            """)
            row = cur.fetchone() or {}
        conn.close()

        patterns_total   = int(row.get("patterns_total") or 0)
        avg_conf_raw     = row.get("avg_confidence")
        avg_confidence   = round(float(avg_conf_raw) * 100, 1) if avg_conf_raw else None
        last_pattern_at  = row.get("last_pattern_at")

    except Exception as exc:
        patterns_total  = 0
        avg_confidence  = None
        last_pattern_at = None

    # Determine which phases are active by probing for their artefacts
    phases_active = ["phase1", "phase2", "phase3", "phase4"]
    try:
        from pathlib import Path as _P
        if patterns_total > 0:
            phases_active.append("phase6")
        # Phase 5: check if any incidents have structured recommendations
        import os as _os, psycopg2
        db_url2 = (
            _os.environ.get("CYCENTRA_DB_URL")
            or _os.environ.get("DATABASE_URL",
               "postgresql://corruser:changeme@127.0.0.1:5433/correlation")
        ).replace("+asyncpg", "")
        conn2 = psycopg2.connect(db_url2)
        with conn2.cursor() as cur2:
            cur2.execute(
                "SELECT EXISTS(SELECT 1 FROM incidents "
                "WHERE recommendation IS NOT NULL LIMIT 1)"
            )
            has_rec = cur2.fetchone()[0]
        conn2.close()
        if has_rec:
            phases_active.append("phase5")
    except Exception:
        pass

    return add_cors_headers(jsonify({
        "patterns_total":          patterns_total,
        "avg_confidence_accuracy": avg_confidence,
        "phases_active":           sorted(set(phases_active)),
        "last_pattern_at":         last_pattern_at.isoformat() if last_pattern_at else None,
    }))
