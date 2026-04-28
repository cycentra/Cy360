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
  GET  /api/system/env/<target>  read env file (global|cysiemstack|cyiris|cysoar|cymisp|cysiem)
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
    "cyiris":      "/opt/cycentra/modules/cyiris/.env",
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
    "CYIRIS_OIDC_SECRET", "CYSOAR_OIDC_SECRET",
    "IRIS_SECRET", "IRIS_DB_PASS", "NODE_RED_CREDENTIAL_SECRET",
    "JWT_SECRET", "ADMIN_API_KEY", "SMTP_PASS",
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


def _sync_iris_to_siem_env(iris: dict) -> None:
    """Resolve effective CyIRIS config and write it into cysiemstack.env so the
    correlation engine picks it up immediately without a restart."""
    env_path = Path(_ENV_FILE_MAP["cysiemstack"])
    if not env_path.parent.exists():
        return

    mode = iris.get("mode", "disabled")

    if mode == "cloud":
        eff_url = os.environ.get("CLOUD_IRIS_URL", "https://cyiris.cycentra.com").rstrip("/")
        # Prefer env var; fall back to key stored in ai_settings.json by the UI
        eff_key = os.environ.get("CLOUD_IRIS_API_KEY", "").strip() or iris.get("apiKey", "").strip()
        customer_id = os.environ.get("CLOUD_IRIS_CUSTOMER_ID", "") or str(iris.get("customerId", "1"))
        enabled = "true" if eff_key else "false"
    elif mode == "local":
        eff_url = iris.get("url", "").rstrip("/")
        eff_key = iris.get("apiKey", "")
        customer_id = str(iris.get("customerId", "1"))
        enabled = "true" if (eff_url and eff_key) else "false"
    else:  # disabled
        eff_url, eff_key, customer_id, enabled = "", "", "1", "false"

    updates = {
        "IRIS_MODE":        mode,
        "IRIS_ENABLED":     enabled,
        "IRIS_URL":         eff_url,
        "IRIS_API_KEY":     eff_key,
        "IRIS_CUSTOMER_ID": customer_id,
        "IRIS_FP_THRESHOLD": str(iris.get("fpThreshold", "90.0")),
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
            if "iris" in data and data["iris"].get("apiKey"):
                data["iris"]["apiKey"] = "••••••••"
            return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({})


@system_bp.route("/api/ai/settings", methods=["POST"])
def ai_settings_post():
    data = request.get_json() or {}
    # Only accept known top-level keys to prevent arbitrary data storage
    allowed = {"provider", "fields", "prompts", "cymind_memory", "misp", "iris"}
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
        # Same guard for the iris block
        incoming_iris_key = payload.get("iris", {}).get("apiKey", "")
        if not incoming_iris_key or incoming_iris_key == _MASK:
            existing_iris_key = existing.get("iris", {}).get("apiKey", "")
            if existing_iris_key:
                payload.setdefault("iris", {})["apiKey"] = existing_iris_key
        existing.update(payload)
        AI_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        AI_SETTINGS_FILE.write_text(json.dumps(existing, indent=2))
        # Sync MISP settings into cysiemstack.env
        if "misp" in existing:
            _sync_misp_to_siem_env(existing["misp"])
        # Sync CyIRIS settings into cysiemstack.env
        if "iris" in existing:
            _sync_iris_to_siem_env(existing["iris"])
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


# ── CyIRIS connectivity test ──────────────────────────────────────────────────

@system_bp.route("/api/system/iris/test", methods=["OPTIONS"])
def iris_test_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/iris/test", methods=["POST"])
def iris_test():
    """Test connectivity to a DFIR IRIS instance using its REST API."""
    data    = request.get_json() or {}
    url     = data.get("url", "").rstrip("/")
    api_key = data.get("apiKey", "").strip()    # strip whitespace/newlines before comparison

    # If the UI sent an empty key with useStored=True (cloud mode, masked placeholder),
    # fall back to the key stored in ai_settings.json, then to the env var (same
    # pattern as the MISP handler — CLOUD_MISP_API_KEY).
    if (not api_key or api_key == "\u2022" * 8) and data.get("useStored"):
        try:
            stored = json.loads(AI_SETTINGS_FILE.read_text()) if AI_SETTINGS_FILE.exists() else {}
            api_key = stored.get("iris", {}).get("apiKey", "")
        except Exception:
            pass
        # Fallback to env var if still missing (cloud mode: key lives in .env, not in UI)
        if not api_key:
            api_key = os.environ.get("CLOUD_IRIS_API_KEY", "").strip()
        # Override the URL with CLOUD_IRIS_URL from env — the stored internal address
        # (e.g. http://127.0.0.1:4433) bypasses the nginx IAP (oauth2-proxy) gate that
        # sits in front of https://cyiris.DOMAIN and would block Bearer-token requests
        # with an HTML redirect.  Same resolution as iris_connector.py and
        # _sync_iris_to_siem_env().
        url = os.environ.get("CLOUD_IRIS_URL", url).rstrip("/")

    if not url:
        return jsonify({"ok": False, "error": "CyIRIS URL is required"}), 400
    if not api_key or api_key == "\u2022" * 8:
        return jsonify({"ok": False, "error": "CyIRIS API Key is required — enter your key in the field above"}), 400

    try:
        # GET /api/ping — lightweight auth-required ping endpoint built into IRIS
        resp = http_requests.get(
            f"{url}/api/ping",
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            timeout=8,
            verify=False,   # IRIS commonly runs with self-signed certs on-premise
        )
        if resp.status_code == 401:
            # Distinguish a genuine IRIS 401 (JSON body) from an oauth2-proxy / nginx
            # authentication-gateway 401 (HTML body).  If the Bearer token was blocked
            # by a reverse-proxy the fix is the URL, not the key.
            try:
                body401 = resp.json()
                if body401.get("status") == "error":
                    # Real IRIS 401 — key does not match any active IRIS user
                    return jsonify({"ok": False, "error": (
                        f"Invalid API key (401) — verify with: "
                        f"curl {url}/api/ping -H 'Authorization: Bearer YOUR_KEY' "
                        "— get key from IRIS: avatar \u2192 My Settings \u2192 API Key"
                    )}), 400
            except Exception:
                pass
            # Non-JSON 401 — likely from an nginx oauth2-proxy gate in front of IRIS.
            # Bearer tokens are not forwarded by oauth2-proxy; browser session cookie required.
            return jsonify({"ok": False, "error": (
                f"401 from an auth proxy — '{url}' is behind a login gateway that blocks "
                "API key access. Use the internal address (e.g. http://127.0.0.1:4433) "
                "to bypass it"
            )}), 400
        if resp.status_code == 403:
            # Distinguish a real IRIS 403 from a non-IRIS server (e.g. CyCentra's own
            # nginx at port 80 returning 403 when the user entered the wrong URL/port).
            try:
                err_body = resp.json()
                # IRIS error responses always carry {"status": "error", "message": ...}
                if err_body.get("status") == "error":
                    return jsonify({"ok": False, "error": f"Access denied — IRIS rejected the API key (403). Verify the key in IRIS → My Profile → API Key"}), 400
            except Exception:
                pass
            return jsonify({"ok": False, "error": "403 received — the URL may be wrong (e.g. pointing to the wrong port). Local CyIRIS listens on port 4433 by default"}), 400
        if resp.ok:
            # Validate the ping response is actually from a DFIR IRIS instance.
            # A plain nginx default page or proxy can return HTTP 200 with HTML/empty
            # body; without this check ver_resp.json() raises a cryptic JSONDecodeError.
            try:
                ping_data = resp.json()
                if ping_data.get("status") != "success":
                    return jsonify({"ok": False, "error": "Server responded but is not a DFIR IRIS instance — check the URL"}), 400
            except Exception:
                return jsonify({"ok": False, "error": "Server returned a non-JSON response — is the URL pointing to DFIR IRIS?"}), 400

            # Also fetch version info for a richer confirmation message
            ver_resp = http_requests.get(
                f"{url}/api/versions",
                headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
                timeout=5, verify=False,
            )
            version = "unknown"
            if ver_resp.ok:
                try:
                    ver_data = ver_resp.json()
                    version = ver_data.get("data", {}).get("iris_current", "unknown")
                except Exception:
                    pass    # version info is cosmetic — don't fail the whole test
            return jsonify({"ok": True, "message": f"DFIR IRIS v{version} — connected"})
        return jsonify({"ok": False, "error": f"IRIS returned HTTP {resp.status_code}"}), 400
    except http_requests.exceptions.SSLError as e:
        return jsonify({"ok": False, "error": f"SSL error — {e}"}), 400
    except http_requests.exceptions.ConnectionError:
        return jsonify({"ok": False, "error": "Cannot reach CyIRIS server — check URL and network"}), 400
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

    Called by CySOAR / CyIRIS / external modules that need MISP creds — they
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
    from core.config import CYSOAR_IMAGE, CYIRIS_IMAGE_APP, CYIRIS_IMAGE_DB
    return jsonify({
        "CYSOAR_IMAGE":     CYSOAR_IMAGE,
        "CYIRIS_IMAGE_APP": CYIRIS_IMAGE_APP,
        "CYIRIS_IMAGE_DB":  CYIRIS_IMAGE_DB,
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
    return os.environ.get("GH_TOKEN", "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").strip()


def _run_setup_in_background(flags: list[str], label: str) -> None:
    """Download the latest setup script and run it with the given flags.

    GH_TOKEN is read fresh from /opt/cycentra/.env at call-time (never from
    the HTTP request) so changes to .env after service start are always picked up.

    For private repos the GitHub API 2-step approach is required:
      1. GET /repos/cycentra/cycentra360/releases/latest  → find asset URL
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
                    "https://api.github.com/repos/cycentra/cycentra360/releases/latest",
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

    Uses GET /repos/cycentra/cycentra360/releases/latest — fast, no bundle download.
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
            "https://api.github.com/repos/cycentra/cycentra360/releases/latest",
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

_LIC_PATH       = Path("/opt/cycentra/cycentra.lic")
_LIC_LOCKFILE   = Path("/opt/cycentra/.license_expired")
_LIC_VALIDATOR  = Path("/opt/cycentra/license_validator.py")   # deployed copy


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
    """Return current license status — reads /opt/cycentra/cycentra.lic."""
    result = _run_validator(_LIC_PATH)
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
    {"name": "get_stats",                  "description": "High-level SIEM statistics: incidents, alerts, anomalies, uptime"},
    {"name": "list_incidents",             "description": "List incidents filtered by status / severity"},
    {"name": "get_incident",               "description": "Full details for a single incident by ID"},
    {"name": "list_alerts",                "description": "Enumerate raw alerts, optionally scoped to an incident"},
    {"name": "list_risk_scores",           "description": "Entity risk scores filtered by type and level"},
    {"name": "list_ueba_users",            "description": "UEBA user profiles with anomaly and activity data"},
    {"name": "get_ueba_anomalies",         "description": "Detailed behavioural anomalies for a specific user"},
    {"name": "wazuh_list_agents",          "description": "Enumerate Wazuh agents with optional status filter"},
    {"name": "wazuh_active_response",      "description": "Trigger a Wazuh active-response command on an agent"},
    {"name": "wazuh_get_agent_vulnerabilities", "description": "Wazuh vulnerability scan results for an agent"},
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
    """Merge cymind config into ai_settings.json and sync API key to cysiemstack.env."""
    existing = {}
    try:
        if AI_SETTINGS_FILE.exists():
            existing = json.loads(AI_SETTINGS_FILE.read_text())
    except Exception:
        pass
    existing["cymind_integration"] = cfg
    AI_SETTINGS_FILE.write_text(json.dumps(existing, indent=2))
    # Keep CYMIND_API_KEY in sync so the correlation engine can read it on restart
    env_path = Path(_ENV_FILE_MAP["cysiemstack"])
    if env_path.exists():
        lines = env_path.read_text().splitlines()
        result, found = [], False
        for line in lines:
            if re.match(r'^CYMIND_API_KEY\s*=', line) and not line.strip().startswith("#"):
                result.append(f"CYMIND_API_KEY={cfg.get('apiKey', '')}")
                found = True
            else:
                result.append(line)
        if not found:
            result.append(f"CYMIND_API_KEY={cfg.get('apiKey', '')}")
        try:
            env_path.write_text("\n".join(result) + "\n")
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
      chatApiKey  — pak_... API key generated in CyMind for the portal service account;
                    must be created in CyMind (Users → service account with analyst role →
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
        if raw and not raw.startswith("pak_"):
            return jsonify({"error": "Chat API key must start with 'pak_' — generate it in CyMind's API Keys section."}), 400
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
        logger.warning("cymind_enable: failed to auto-configure AI provider: %s", _e)

    return jsonify({
        "ok": True,
        "message": "Integration enabled. CyMind is connected and the portal service account is provisioned.",
        "nginxStatus": nginx_msg,
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

    # ── 3. Chat API key presence ───────────────────────────────────────────────
    results["chat_key"] = {
        "ok":  bool(cfg.get("chatApiKey")),
        "msg": "Chat API key set" if cfg.get("chatApiKey") else "Chat API key not set — create an analyst user in CyMind, generate an API key there, and paste it in System Settings → CyMind.",
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
        r = http_requests.get(f"{engine_url}/incidents",
                              params={"status": "open", "limit": 10}, timeout=_t)
        if r.ok:
            ctx["open_incidents"] = r.json()
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
        f"Source: CyCentra 360 (direct) | Timestamp: {now}\n",
    ]

    if "stats" in ctx:
        s = ctx["stats"]
        lines += [
            "## Overview",
            f"- Total alerts (24h): {s.get('total_alerts_24h', 'N/A')}",
            f"- Open incidents: {s.get('open_incidents', 'N/A')}",
            f"- Active agents: {s.get('active_agents', 'N/A')}",
            f"- Critical alerts: {s.get('critical_alerts', 'N/A')}",
            "",
        ]

    if ctx.get("open_incidents"):
        raw  = ctx["open_incidents"]
        rows = raw if isinstance(raw, list) else raw.get("incidents", raw.get("data", []))
        if rows:
            lines += ["## Open Incidents",
                      "| ID | Title | Severity | Risk Score | Created |",
                      "|---|---|---|---|---|"]
            for inc in rows[:10]:
                lines.append(
                    f"| {inc.get('id', inc.get('incident_id', '?'))} "
                    f"| {inc.get('title', '?')} "
                    f"| {inc.get('severity', '?')} "
                    f"| {inc.get('risk_score', '?')} "
                    f"| {inc.get('created_at', '?')} |"
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

    lines.append("--- END LIVE SIEM DATA ---\n")
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
            r = http_requests.post(
                f"{engine}/incidents/{inc_id}/transition",
                json={"to_status": "resolved", "comment": comment, "actor": actor_email},
                timeout=_t,
            )
            if r.ok:
                return {"success": True,
                        "message": f"Incident **{inc_id}** resolved.",
                        "data": r.json()}
            return {"success": False,
                    "message": f"Engine returned HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"success": False, "message": f"Could not reach engine: {e}"}

    # ── Mark single incident as false positive ────────────────────────────────
    elif action_type == "mark_false_positive":
        inc_id  = params.get("incident_id", "")
        comment = params.get("comment") or f"False positive — via CyMind agentic chat by {actor_email}"
        if not inc_id:
            return {"success": False, "message": "Missing incident_id"}
        try:
            r = http_requests.post(
                f"{engine}/incidents/{inc_id}/transition",
                json={"to_status": "false_positive", "comment": comment, "actor": actor_email},
                timeout=_t,
            )
            if r.ok:
                return {"success": True,
                        "message": f"Incident **{inc_id}** marked as false positive.",
                        "data": r.json()}
            return {"success": False,
                    "message": f"Engine returned HTTP {r.status_code}: {r.text[:200]}"}
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
    if body_json is not None:
        messages = body_json.get("messages", [])
        last_msg = messages[-1].get("content", "") if messages else ""
        if last_msg:
            action = _detect_action_intent(last_msg)
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

    limit_inc  = min(int(request.args.get("incidents", 5)), 20)
    limit_risk = min(int(request.args.get("risk",      5)), 20)
    limit_ueba = min(int(request.args.get("ueba",      5)), 20)

    context = {}

    # ── Stats ──────────────────────────────────────────────────────────────────
    try:
        r = http_requests.get(f"{engine_url}/stats", timeout=timeout)
        if r.ok:
            context["stats"] = r.json()
    except Exception:
        pass

    # ── Open incidents ─────────────────────────────────────────────────────────
    try:
        r = http_requests.get(
            f"{engine_url}/incidents",
            params={"status": "open", "limit": limit_inc},
            timeout=timeout,
        )
        if r.ok:
            context["open_incidents"] = r.json()
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
    logger.info("mcp_api_key_generated name=%s by=%s", name, session["user_email"])
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
    logger.info("mcp_api_key_revoked id=%s by=%s", key_id, session["user_email"])
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
