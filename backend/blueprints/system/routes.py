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
"""

import os
import re
import json
import shutil
import subprocess
import threading
from pathlib import Path

import requests as http_requests
from flask import Blueprint, request, jsonify, make_response, session

from core.helpers import add_cors_headers, get_misp_config
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
            pass

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
    api_key = data.get("apiKey", "")

    # If the UI sent an empty key with useStored=True (cloud mode, masked placeholder),
    # fall back to the key stored in ai_settings.json
    if (not api_key or api_key == "\u2022" * 8) and data.get("useStored"):
        try:
            stored = json.loads(AI_SETTINGS_FILE.read_text()) if AI_SETTINGS_FILE.exists() else {}
            api_key = stored.get("iris", {}).get("apiKey", "")
        except Exception:
            pass

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
            return jsonify({"ok": False, "error": "Invalid API key (401 Unauthorized)"}), 400
        if resp.status_code == 403:
            return jsonify({"ok": False, "error": "Access denied (403 Forbidden)"}), 400
        if resp.ok:
            # Also fetch version info for a richer confirmation message
            ver_resp = http_requests.get(
                f"{url}/api/versions",
                headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
                timeout=5, verify=False,
            )
            version = "unknown"
            if ver_resp.ok:
                ver_data = ver_resp.json()
                version = ver_data.get("data", {}).get("iris_current", "unknown")
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
        os.path.join(_this_dir, "..", "..", "..", "RELEASE_NOTES.md"),   # dev: blueprints/system/ → repo root
        os.path.join(_cwd, "RELEASE_NOTES.md"),                          # cwd = repo root
        os.path.join(_cwd, "..", "RELEASE_NOTES.md"),                     # cwd = backend/
        os.path.join(_cwd, "..", "..", "RELEASE_NOTES.md"),               # cwd = backend/blueprints/
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
    return os.environ.get("GH_TOKEN", "").strip()


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
    if not _get_server_gh_token():
        return jsonify({"ok": False, "error": "GH_TOKEN not configured on server (check /opt/cycentra/.env)"}), 400
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
    if not _get_server_gh_token():
        return jsonify({"ok": False, "error": "GH_TOKEN not configured on server (check /opt/cycentra/.env)"}), 400
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
    if not gh_token:
        return jsonify({"error": "GH_TOKEN not configured on server (check /opt/cycentra/.env)"}), 400

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
    public_url  = f"https://cysoc.{base_domain}/mcp/sse" if base_domain else f"{base_url}/mcp/sse"

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
