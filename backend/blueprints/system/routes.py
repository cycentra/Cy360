"""
blueprints/system/routes.py
=============================
System-level endpoints.

Routes:
  GET  /health               liveness check
  POST /api/ai/test          test external AI provider connectivity
  GET  /api/ai/settings      retrieve persisted AI settings
  POST /api/ai/settings      persist AI settings (provider/model/keys)
  GET  /api/config           debug — dump non-secret env config
"""

import os
import json

import requests as http_requests
from flask import Blueprint, request, jsonify, make_response

from core.helpers import add_cors_headers
from core.config import AI_SETTINGS_FILE

system_bp = Blueprint("system", __name__)


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
            # Strip stored API key from response — return masked version
            if "fields" in data and "apiKey" in data["fields"] and data["fields"]["apiKey"]:
                data["fields"]["apiKey"] = "••••••••"
            return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({})


@system_bp.route("/api/ai/settings", methods=["POST"])
def ai_settings_post():
    data = request.get_json() or {}
    # Only accept known top-level keys to prevent arbitrary data storage
    allowed = {"provider", "fields", "prompts"}
    payload = {k: v for k, v in data.items() if k in allowed}
    if not payload:
        return jsonify({"error": "No valid settings provided"}), 400
    try:
        # Merge with existing so a partial update doesn't wipe other keys
        existing = {}
        if AI_SETTINGS_FILE.exists():
            existing = json.loads(AI_SETTINGS_FILE.read_text())
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
