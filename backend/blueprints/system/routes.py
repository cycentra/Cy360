"""
blueprints/system/routes.py
=============================
System-level endpoints.

Routes:
  GET  /health                   liveness check
  POST /api/ai/test              test external AI provider connectivity
  GET  /api/ai/settings          retrieve persisted AI settings
  POST /api/ai/settings          persist AI settings (provider/model/keys)
  GET  /api/config               debug — dump non-secret env config
  GET  /api/system/version         current version + last 5 release notes
  GET  /api/system/latest-version   query Cloudsmith for latest published version (csToken required)
  POST /api/system/update           trigger cycentra-setup.sh --update (CS_TOKEN required)
  GET  /api/system/env/<target>  read env file (global|cysiemstack|cyiris|cysoar|cymisp|cysiem)
  PUT  /api/system/env/<target>  write env file
"""

import os
import re
import json
import subprocess
import threading

import requests as http_requests
from flask import Blueprint, request, jsonify, make_response

from core.helpers import add_cors_headers
from core.config import AI_SETTINGS_FILE

system_bp = Blueprint("system", __name__)

# ── Env file paths keyed by target name ──────────────────────────────────────
_ENV_FILE_MAP = {
    "global":      "/opt/cycentra/.env",
    "cysiemstack": "/opt/cycentra/cysiemstack.env",
    "cyiris":      "/opt/cycentra/modules/cyiris/.env",
    "cysoar":      "/opt/cycentra/modules/cysoar/.env",
    "cymisp":      "/opt/cycentra/modules/cymisp/.env",
    "cysiem":      "/opt/cycentra/.env",
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

        return jsonify({"ok": True, "message": f"Connected · {model}"})

    except http_requests.exceptions.ConnectionError:
        return jsonify({"ok": False, "error": "Cannot reach server"}), 400
    except http_requests.exceptions.Timeout:
        return jsonify({"ok": False, "error": "Connection timed out"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── AI settings persistence ────────────────────────────────────────────────────

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
            return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({})


@system_bp.route("/api/ai/settings", methods=["POST"])
def ai_settings_post():
    data = request.get_json() or {}
    # Only accept known top-level keys to prevent arbitrary data storage
    allowed = {"provider", "fields", "prompts", "cymind_memory"}
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
        # Same guard for the separate cymind_memory block
        incoming_cm_key = payload.get("cymind_memory", {}).get("apiKey", "")
        if not incoming_cm_key or incoming_cm_key == _MASK:
            existing_cm_key = existing.get("cymind_memory", {}).get("apiKey", "")
            if existing_cm_key:
                payload.setdefault("cymind_memory", {})["apiKey"] = existing_cm_key
        existing.update(payload)
        AI_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        AI_SETTINGS_FILE.write_text(json.dumps(existing, indent=2))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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

# Pattern matching sensitive key names and Cloudsmith auth tokens in URLs
_REDACT_KEY_RE  = re.compile(r'(?i)((?:password|secret|token|key|pass)\s*[=:]\s*)\S+')
_REDACT_URL_RE  = re.compile(r'(dl\.cloudsmith\.io/)([A-Za-z0-9_\-]{8,128})(/)')

def _redact_line(line: str) -> str:
    """Strip secrets and Cloudsmith tokens from a log line before storing."""
    line = _REDACT_KEY_RE.sub(r'\1[REDACTED]', line)
    line = _REDACT_URL_RE.sub(r'\1[TOKEN]\3', line)
    return line

_update_log: list[str] = []
_update_running = False

@system_bp.route("/api/system/update", methods=["OPTIONS"])
def update_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/update", methods=["POST"])
def system_update():
    """Trigger sudo cycentra-setup.sh --update in a background thread."""
    global _update_running, _update_log

    if _update_running:
        return jsonify({"ok": False, "error": "Update already in progress"}), 409

    data      = request.get_json() or {}
    cs_token  = data.get("csToken", "").strip()
    if not cs_token:
        return jsonify({"ok": False, "error": "CS_TOKEN is required"}), 400
    # Basic format guard — tokens are alphanumeric+hyphen, no shell metacharacters
    if not re.match(r'^[A-Za-z0-9_\-]{8,128}$', cs_token):
        return jsonify({"ok": False, "error": "Invalid CS_TOKEN format"}), 400

    setup_script = "/opt/cycentra/cycentra-setup.sh"
    if not os.path.exists(setup_script):
        return jsonify({"ok": False, "error": "Setup script not found on server"}), 404

    _update_log = ["[UPDATE] Starting update…"]
    _update_running = True

    def _run():
        global _update_running, _update_log
        try:
            env = {**os.environ, "CS_TOKEN": cs_token}
            proc = subprocess.Popen(
                ["sudo", "-E", "bash", setup_script, "--update"],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            for line in proc.stdout:
                _update_log.append(_redact_line(line.rstrip()))
                if len(_update_log) > 500:       # cap buffer
                    _update_log = _update_log[-500:]
            proc.wait()
            _update_log.append(f"[UPDATE] Finished with exit code {proc.returncode}")
        except Exception as e:
            _update_log.append(f"[UPDATE ERROR] {e}")
        finally:
            _update_running = False

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"ok": True, "message": "Update started"})


@system_bp.route("/api/system/update/log")
def system_update_log():
    """Poll the live update log."""
    return jsonify({"running": _update_running, "log": _update_log[-200:]})


# ── Latest version check ──────────────────────────────────────────────────────

@system_bp.route("/api/system/latest-version", methods=["OPTIONS"])
def latest_version_options():
    return add_cors_headers(make_response('', 204))


@system_bp.route("/api/system/latest-version", methods=["GET"])
def system_latest_version():
    """Query the latest published version from Cloudsmith without downloading the bundle.

    Fetches the first 4 KB of cycentra-setup.sh (always on Cloudsmith) and reads
    the _SCRIPT_VERSION variable that git-push.sh stamps before every release.
    Returns {current, latest, up_to_date} for the UI to act on.
    """
    cs_token = request.args.get("csToken", "").strip()
    if not cs_token:
        return jsonify({"error": "csToken is required"}), 400
    if not re.match(r'^[A-Za-z0-9_\-]{8,128}$', cs_token):
        return jsonify({"error": "Invalid CS_TOKEN format"}), 400

    # Read currently installed version
    current = "unknown"
    for vf in ("/opt/cycentra/version", "/opt/cycentra/.version"):
        if os.path.exists(vf):
            current = open(vf).read().strip()
            break

    # Fetch only the first 4 KB of setup.sh — enough to reach _SCRIPT_VERSION near the top
    cs_url = (
        f"https://dl.cloudsmith.io/{cs_token}/cycentra/cycentra360/raw/versions"
        f"/latest/cycentra-setup.sh"
    )
    latest = None
    try:
        resp = http_requests.get(
            cs_url, timeout=15,
            headers={"Range": "bytes=0-4095"},
        )
        if resp.status_code in (200, 206):
            m = re.search(r'^_SCRIPT_VERSION="(v[\d.]+)"', resp.text, re.MULTILINE)
            if m:
                latest = m.group(1)
    except Exception:
        pass

    if latest is None:
        return jsonify({
            "current": current,
            "latest":  None,
            "up_to_date": False,
            "error": "Could not read latest version — verify CS_TOKEN and connectivity",
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

