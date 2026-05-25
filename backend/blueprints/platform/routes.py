"""
blueprints/platform/routes.py
================================
Platform module install / uninstall / status API.
Written as a faithful port of the original monolithic app.py install logic.

Key design decisions (matching original app.py exactly):
  - CyIRIS: env built from master .env, then UI input overwrites via update().
             DB table is "user" (lowercase) — DFIR-IRIS schema.
  - CyMISP: nginx block built as a plain string (no helper abstraction).
             compose template includes cymisp_data volume + misp-config.php mount.
  - CySOAR: nginx injected as location /cysoar/ inside cysoc server block.
  - Uninstall: only CyMISP and CySOAR have dynamic nginx. CyIRIS nginx is
               now also dynamic (added on install, removed on uninstall).
"""

import os
import re
import shutil
import threading
import time
from pathlib import Path

import requests as _http_requests
from flask import Blueprint, request, jsonify, make_response, session

from core.config import MODULES_DIR
from core.helpers import run, add_cors_headers
from blueprints.platform.compose import (
    COMPOSE_TEMPLATES, VALID_MODULES,
    _CYSOAR_IMAGE     as CYSOAR_IMAGE,
    _CYIRIS_IMAGE_APP as CYIRIS_IMAGE_APP,
    _CYIRIS_IMAGE_DB  as CYIRIS_IMAGE_DB,
)
from blueprints.platform.state import load_state, save_state
from blueprints.platform.docker_utils import docker_containers_running

platform_bp  = Blueprint("platform", __name__)
NGINX_CONF   = Path("/etc/nginx/sites-available/cycentra-modules")


# ── Preflight ─────────────────────────────────────────────────────────────────

@platform_bp.route("/api/platform/install",   methods=["OPTIONS"])
@platform_bp.route("/api/platform/uninstall", methods=["OPTIONS"])
def platform_options():
    return add_cors_headers(make_response('', 204))


# ── Status ────────────────────────────────────────────────────────────────────

@platform_bp.route("/api/platform/status")
def platform_status():
    state  = load_state()
    result = {}
    for module_id in VALID_MODULES:
        saved    = state.get(module_id, {})
        log_file = MODULES_DIR / module_id / "install.log"
        last_log = ""
        if log_file.exists():
            try:
                lines    = [l.strip() for l in log_file.read_text().splitlines() if l.strip()]
                last_log = lines[-1] if lines else ""
            except Exception:
                pass
        if not saved:
            result[module_id] = {"status": "not_installed", "running": False}
            continue
        # CyMISP stays "installing" until misp_ready flag is set by post-install
        if saved.get("status") == "installing" and docker_containers_running(module_id):
            if module_id != "cymisp" or saved.get("misp_ready", False):
                saved["status"]  = "running"
                state[module_id] = saved
                save_state(state)
        if saved.get("status") in ("running", "degraded"):
            live             = docker_containers_running(module_id)
            saved["running"] = live
            saved["status"]  = "running" if live else "stopped"
        else:
            saved["running"] = False
        saved["last_log"]  = last_log
        result[module_id]  = saved
    return jsonify(result)


# ── Install ───────────────────────────────────────────────────────────────────

@platform_bp.route("/api/platform/install", methods=["POST"])
def platform_install():
    data      = request.get_json() or {}
    module_id = data.get("module", "").strip()
    if module_id not in VALID_MODULES:
        return jsonify({"error": f"Unknown module: {module_id}"}), 400
    rc, _, _ = run("docker info")
    if rc != 0:
        return jsonify({"error": "Docker not running"}), 503
    rc2, _, _ = run("docker compose version")
    if rc2 != 0:
        return jsonify({"error": "Docker Compose plugin not found"}), 503
    state = load_state()
    state[module_id] = {"status": "installing", "started_at": time.strftime('%Y-%m-%dT%H:%M:%SZ')}
    save_state(state)
    compose_yaml = COMPOSE_TEMPLATES.get(module_id) or data.get("compose_yaml") or ""
    if not compose_yaml:
        return jsonify({"error": "No compose template"}), 400
    env_vars = {k: v for k, v in (data.get("config") or {}).items()
                if v and not k.startswith("_")}
    threading.Thread(
        target=_install_module_async,
        args=(module_id, compose_yaml, env_vars),
        daemon=True,
    ).start()
    return jsonify({"status": "installing", "module": module_id,
                    "message": "Poll /api/platform/status for progress."})


# ── Uninstall ─────────────────────────────────────────────────────────────────

@platform_bp.route("/api/platform/uninstall", methods=["POST"])
def platform_uninstall():
    data      = request.get_json() or {}
    module_id = data.get("module", "").strip()
    if module_id not in VALID_MODULES:
        return jsonify({"error": f"Unknown module: {module_id}"}), 400
    module_dir  = MODULES_DIR / module_id
    errors      = []
    base_domain = os.environ.get("BASE_DOMAIN", "cycentra.com")

    if module_dir.exists():
        # 1. Graceful compose shutdown + volume removal
        run("docker compose down -v", cwd=str(module_dir), timeout=60)

        # 2. Force-remove known orphaned containers
        for c in {
            "cyiris": ["cyiris-cyiris-1", "cyiris-cyiris-db-1", "cyiris", "cyiris-db"],
            "cysoar": ["cysoar"],
            "cymisp": ["cymisp", "cymisp-db", "cymisp-redis"],
        }.get(module_id, []):
            run(f"docker rm -f {c} 2>/dev/null || true", timeout=10)

        # 3. Remove volumes
        rc, vols_out, _ = run(f"docker volume ls -q --filter name={module_id}", timeout=10)
        if rc == 0 and vols_out.strip():
            for vol in vols_out.strip().splitlines():
                run(f"docker volume rm -f {vol.strip()} 2>/dev/null || true", timeout=10)

        # 4. Remove nginx config
        if module_id == "cyiris":
            _nginx_remove_server_block(f"cyiris.{base_domain}")
        elif module_id == "cysoar":
            _nginx_remove_cysoar_location()
        elif module_id == "cymisp":
            _nginx_remove_server_block(f"cymisp.{base_domain}")

        # 5. Remove module directory
        try:
            shutil.rmtree(str(module_dir))
        except Exception as e:
            errors.append(str(e))

    state = load_state()
    state.pop(module_id, None)
    save_state(state)
    if errors:
        return jsonify({"status": "partial", "module": module_id, "errors": errors})
    return jsonify({"status": "uninstalled", "module": module_id})


# ── Logs ──────────────────────────────────────────────────────────────────────

@platform_bp.route("/api/platform/logs/<module_id>")
def platform_logs(module_id):
    if module_id not in VALID_MODULES:
        return jsonify({"error": "Unknown module"}), 400
    log_file = MODULES_DIR / module_id / "install.log"
    if not log_file.exists():
        return jsonify({"lines": [], "module": module_id})
    try:
        return jsonify({"lines": log_file.read_text().splitlines()[-100:],
                        "module": module_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Module update (pull latest image + restart) ───────────────────────────────

@platform_bp.route("/api/platform/update/<module_id>", methods=["OPTIONS"])
def platform_update_options(module_id):
    return add_cors_headers(make_response('', 204))


_update_in_progress: dict = {}
_update_lock = threading.Lock()


def _module_setup_script(module_id: str) -> str | None:
    """Return the path to the module's setup script on this server, if present."""
    candidates = {
        "cyiris": "/opt/cyiris/cyiris-setup.sh",
        "cysoar": "/opt/cysoar/cysoar-setup.sh",
    }
    path = candidates.get(module_id)
    if path and os.path.exists(path):
        return path
    return None


def _run_module_update(module_id: str, setup_script: str):
    """Background thread: run setup.sh --update for the given module."""
    log_dir  = MODULES_DIR / module_id
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "update.log"
    try:
        import subprocess as _sp
        with open(str(log_file), "w") as lf:
            lf.write(f"[update] Starting update for {module_id}\n")
            lf.flush()
            proc = _sp.Popen(
                ["bash", setup_script, "--update"],
                stdout=_sp.PIPE, stderr=_sp.STDOUT,
            )
            for line in iter(proc.stdout.readline, b""):
                text = line.decode(errors="replace")
                lf.write(text)
                lf.flush()
            proc.wait()
            lf.write(f"[update] Exit code: {proc.returncode}\n")
    except Exception as e:
        with open(str(log_file), "a") as lf:
            lf.write(f"[update] ERROR: {e}\n")
    finally:
        with _update_lock:
            _update_in_progress.pop(module_id, None)


@platform_bp.route("/api/platform/update/<module_id>", methods=["POST"])
def platform_update_module(module_id):
    from flask import session
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403

    if module_id not in {"cyiris", "cysoar"}:
        return jsonify({"error": f"Module '{module_id}' does not support self-update via this endpoint"}), 400

    with _update_lock:
        if _update_in_progress.get(module_id):
            return jsonify({"ok": False, "message": f"{module_id} update already in progress"}), 409

    setup_script = _module_setup_script(module_id)
    if not setup_script:
        return jsonify({"ok": False, "message": f"Setup script not found on this server for {module_id}. Ensure {module_id}-setup.sh was run at least once."}), 404

    with _update_lock:
        _update_in_progress[module_id] = True

    threading.Thread(
        target=_run_module_update,
        args=(module_id, setup_script),
        daemon=True,
    ).start()
    return jsonify({"ok": True, "message": f"Update started for {module_id}. The module will restart in ~30 seconds."})


@platform_bp.route("/api/platform/update-log/<module_id>")
def platform_update_log(module_id):
    if module_id not in {"cyiris", "cysoar"}:
        return jsonify({"error": "Unknown module"}), 400
    log_file = MODULES_DIR / module_id / "update.log"
    if not log_file.exists():
        return jsonify({"lines": [], "in_progress": _update_in_progress.get(module_id, False)})
    try:
        return jsonify({
            "lines": log_file.read_text().splitlines()[-100:],
            "in_progress": _update_in_progress.get(module_id, False),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Module version check ──────────────────────────────────────────────────────

_CONTAINER_MAP = {
    "cyiris": ["cyiris-cyiris-1", "cyiris"],
    "cysoar": ["cysoar"],
}
_GITHUB_REPO_MAP = {
    "cyiris": "cycentra/CyIRIS",
    "cysoar": "cycentra/CySOAR",
}


def _get_running_version(module_id: str) -> str | None:
    """Return the running container's OCI version label, or tag, or None."""
    for container in _CONTAINER_MAP.get(module_id, []):
        # Try OCI standard label first (set by GitHub Actions builds)
        rc, out, _ = run(
            f'docker inspect --format '
            f'"{{{{index .Config.Labels \\"org.opencontainers.image.version\\"}}}}"'
            f' {container}'
        )
        if rc == 0 and out.strip() and out.strip() not in ("", "<no value>"):
            return out.strip().lstrip("v")
        # Fallback: image:tag format
        rc2, img, _ = run(
            f'docker inspect --format "{{{{.Config.Image}}}}" {container}'
        )
        if rc2 == 0 and img.strip():
            parts = img.strip().rsplit(":", 1)
            tag = parts[-1] if len(parts) == 2 else ""
            if tag and tag not in ("latest", ""):
                return tag.lstrip("v")
    return None


def _get_latest_version(module_id: str) -> str | None:
    """Query GitHub Releases API for the latest published tag of a module."""
    repo = _GITHUB_REPO_MAP.get(module_id)
    if not repo:
        return None
    gh_token = (
        os.environ.get("GITHUB_TOKEN")
        or os.environ.get("GH_TOKEN", "")
    )
    if not gh_token:
        # Try reading from /opt/cycentra/.env directly
        try:
            for line in Path("/opt/cycentra/.env").read_text().splitlines():
                if line.startswith("GH_TOKEN=") or line.startswith("GITHUB_TOKEN="):
                    gh_token = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if gh_token:
                        break
        except Exception:
            pass
    headers = {"Accept": "application/vnd.github+json"}
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"
    try:
        resp = _http_requests.get(
            f"https://api.github.com/repos/{repo}/releases/latest",
            headers=headers,
            timeout=8,
        )
        if resp.status_code == 200:
            tag_name = resp.json().get("tag_name", "")
            return tag_name.lstrip("v") if tag_name else None
    except Exception:
        pass
    return None


@platform_bp.route("/api/platform/version/<module_id>")
def platform_module_version(module_id):
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    if module_id not in {"cyiris", "cysoar"}:
        return jsonify({"error": "Unknown module"}), 400

    running = _get_running_version(module_id)
    latest  = _get_latest_version(module_id)

    update_available = bool(
        running and latest
        and running != latest
        and latest not in ("latest",)
    )

    return jsonify({
        "module":           module_id,
        "running":          running,
        "latest":           latest,
        "update_available": update_available,
    })


# ── Debug ─────────────────────────────────────────────────────────────────────

@platform_bp.route("/api/debug/images")
def debug_images():
    return jsonify({
        "CYSOAR_IMAGE":    CYSOAR_IMAGE,
        "CYIRIS_IMAGE_APP": CYIRIS_IMAGE_APP,
        "CYIRIS_IMAGE_DB":  CYIRIS_IMAGE_DB,
        "SIEM_ENGINE_URL":  os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100"),
        "env_file_loaded":  os.path.exists("/opt/cycentra/.env") or os.path.exists(".env"),
    })


# ══════════════════════════════════════════════════════════════════════════════
# nginx HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _nginx_remove_server_block(subdomain: str):
    """
    Remove all server {} blocks for a given subdomain (HTTP redirect + HTTPS).
    Handles one level of nested braces (location {} inside server {}).
    """
    if not NGINX_CONF.exists():
        return
    content     = NGINX_CONF.read_text()
    new_content = re.sub(
        r'\nserver\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*server_name\s+' +
        re.escape(subdomain) +
        r'[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',
        '', content, flags=re.DOTALL
    )
    if new_content != content:
        NGINX_CONF.write_text(new_content)
        run("nginx -t && systemctl reload nginx", timeout=15)


def _nginx_remove_cysoar_location():
    """Remove the location /cysoar/ block from the portal server block."""
    if not NGINX_CONF.exists():
        return
    content     = NGINX_CONF.read_text()
    new_content = re.sub(
        r'[ \t]+location /cysoar/ \{[^{}]+\}\n', '', content, flags=re.DOTALL
    )
    if new_content != content:
        NGINX_CONF.write_text(new_content)
        run("nginx -t && systemctl reload nginx", timeout=15)


def _nginx_inject_cysoar(base_domain: str, log_fn):
    """
    Inject location /cysoar/ into the cysoc.DOMAIN server block.
    CySOAR is path-based — not a subdomain.
    Looks for the comment anchor setup.sh writes, falls back to finding
    the closing brace of the server block containing /oidc/.
    Idempotent.
    """
    if not NGINX_CONF.exists():
        log_fn("cysoar: nginx config not found — skipping /cysoar/ injection")
        return
    text = NGINX_CONF.read_text()
    if "location /cysoar/ {" in text:
        log_fn("cysoar: /cysoar/ location block already present")
        return

    block = (
        "    # IAP gate for /cysoar/ — oauth2-proxy validates session before proxying\n"
        "    location /cysoar/ {\n"
        "        auth_request        /oauth2/auth;\n"
        "        error_page 401    = @error401;\n"
        "        auth_request_set    $proxy_email $upstream_http_x_auth_request_email;\n"
        "        proxy_pass http://127.0.0.1:1880;\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Upgrade $http_upgrade;\n"
        "        proxy_set_header Connection $connection_upgrade;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Email $proxy_email;\n"
        "        proxy_read_timeout 120s;\n"
        "        proxy_buffering off;\n"
        "    }\n"
    )

    # Anchor 1: comment placed by setup.sh as explicit injection point
    anchor = "    # location /cysoar/ is injected here"
    if anchor in text:
        # Replace the ENTIRE comment line (anchor + any trailing text up to \n) with the block
        ins = text.find(anchor)
        eol = text.find("\n", ins)
        eol = eol if eol != -1 else len(text) - 1
        text = text[:ins] + block + text[eol + 1:]
        NGINX_CONF.write_text(text)
        rc, _, err = run("nginx -t && systemctl reload nginx", timeout=15)
        log_fn("cysoar: /cysoar/ location injected and nginx reloaded" if rc == 0
               else f"cysoar: WARNING — nginx reload failed: {err}")
        return

    # Anchor 2: find closing brace of server block containing /oidc/
    oidc_pos = text.find("location /oidc/")
    if oidc_pos != -1:
        # Walk forward to find the server-level closing brace
        depth = 0
        i     = oidc_pos
        while i < len(text):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                if depth == 0:
                    # This is the server-level closing brace
                    text = text[:i] + block + text[i:]
                    NGINX_CONF.write_text(text)
                    rc, _, err = run("nginx -t && systemctl reload nginx", timeout=15)
                    log_fn("cysoar: /cysoar/ injected before server closing brace" if rc == 0
                           else f"cysoar: WARNING — nginx reload failed: {err}")
                    return
                depth -= 1
            i += 1

    log_fn("cysoar: WARNING — could not find injection point — add location /cysoar/ manually")


def _nginx_add_cyiris(base_domain: str, log_fn):
    """Add the cyiris.DOMAIN server block with IAP oauth2-proxy auth_request gate."""
    if not NGINX_CONF.exists():
        log_fn("cyiris: nginx config not found")
        return
    existing = NGINX_CONF.read_text()
    if f"cyiris.{base_domain}" in existing:
        log_fn(f"cyiris: nginx block already present")
        return

    # Obtain a dedicated LE cert for cyiris.DOMAIN (webroot — nginx must be up)
    cyiris_cert = f"/etc/letsencrypt/live/cyiris.{base_domain}/fullchain.pem"
    import os as _os
    if not _os.path.exists(cyiris_cert):
        rc_cb, _, _ = run(
            f"certbot certonly --nginx --non-interactive --agree-tos"
            f" -d cyiris.{base_domain} 2>/dev/null || true",
            timeout=120,
        )
        log_fn(f"cyiris: certbot {'succeeded' if _os.path.exists(cyiris_cert) else 'failed — cert may be missing'}")

    block = (
        "\nserver {\n"
        "    listen 80; server_name cyiris." + base_domain + ";\n"
        "    return 301 https://$host$request_uri;\n"
        "}\n"
        "server {\n"
        "    listen 443 ssl http2; server_name cyiris." + base_domain + ";\n"
        "    ssl_certificate     /etc/letsencrypt/live/cyiris." + base_domain + "/fullchain.pem;\n"
        "    ssl_certificate_key /etc/letsencrypt/live/cyiris." + base_domain + "/privkey.pem;\n"
        "    include             /etc/letsencrypt/options-ssl-nginx.conf;\n"
        "    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;\n"
        "    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        "    add_header X-Frame-Options \"\" always;\n"
        "    add_header Content-Security-Policy \"frame-ancestors 'self' https://cy360." + base_domain + "\" always;\n"
        "    # IAP gate — oauth2-proxy validates the wildcard ." + base_domain + " session cookie\n"
        "    auth_request        /oauth2/auth;\n"
        "    error_page 401    = @error401;\n"
        "    auth_request_set    $proxy_email $upstream_http_x_auth_request_email;\n"
        "    location @error401 {\n"
        "        return 302 https://cy360." + base_domain + "/oauth2/sign_in?rd=https://$host$request_uri;\n"
        "    }\n"
        "    location = /oauth2/auth {\n"
        "        internal;\n"
        "        proxy_pass              http://127.0.0.1:4180;\n"
        "        proxy_pass_request_body off;\n"
        "        proxy_set_header        Content-Length \"\";\n"
        "        proxy_set_header        X-Original-URI $request_uri;\n"
        "        proxy_set_header        X-Scheme $scheme;\n"
        "    }\n"
        "    location = /logout {\n"
        "        return 302 https://cy360." + base_domain + "/oauth2/sign_out?rd=https://cy360." + base_domain + "/;\n"
        "    }\n"
        "    if ($request_method = OPTIONS) { return 204; }\n"
        "    location / {\n"
        "        proxy_pass http://127.0.0.1:4433;\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "        proxy_set_header X-Forwarded-Proto https;\n"
        "        proxy_set_header X-Email $proxy_email;\n"
        "        proxy_read_timeout 300;\n"
        "        proxy_buffer_size 128k;\n"
        "        proxy_buffers 4 256k;\n"
        "        proxy_cookie_flags ~ samesite=none secure;\n"
        "    }\n"
        "}\n"
    )
    NGINX_CONF.write_text(existing + block)
    rc, _, err = run("nginx -t && systemctl reload nginx", timeout=15)
    log_fn(f"cyiris: nginx block added for cyiris.{base_domain}" if rc == 0
           else f"cyiris: WARNING — nginx reload failed: {err}")


def _nginx_add_cymisp(base_domain: str, log_fn):
    """
    Add the cymisp.DOMAIN server block — exact string from original app.py.
    Only called after MISP is confirmed live and config is patched.
    """
    if not NGINX_CONF.exists():
        log_fn("cymisp: nginx config not found")
        return
    existing = NGINX_CONF.read_text()
    if f"cymisp.{base_domain}" in existing:
        log_fn("cymisp: nginx block already present")
        return

    block = (
        "\nserver {\n"
        "    listen 80; server_name cymisp." + base_domain + ";\n"
        "    return 301 https://$host$request_uri;\n"
        "}\n"
        "server {\n"
        "    listen 443 ssl http2; server_name cymisp." + base_domain + ";\n"
        "    ssl_certificate     /etc/letsencrypt/live/cy360." + base_domain + "/fullchain.pem;\n"
        "    ssl_certificate_key /etc/letsencrypt/live/cy360." + base_domain + "/privkey.pem;\n"
        "    include             /etc/letsencrypt/options-ssl-nginx.conf;\n"
        "    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;\n"
        "    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        "    add_header X-Content-Type-Options \"nosniff\" always;\n"
        "    location / {\n"
        "        proxy_pass https://127.0.0.1:8243/;\n"
        "        proxy_ssl_verify off;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        "        proxy_set_header X-Forwarded-Proto https;\n"
        "        proxy_set_header X-Forwarded-Host $host;\n"
        "        proxy_set_header X-Forwarded-Port 443;\n"
        "        proxy_read_timeout 300s;\n"
        "        add_header Content-Security-Policy \"default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:;\" always;\n"
        "    }\n"
        "}\n"
    )
    NGINX_CONF.write_text(existing + block)
    rc, _, err = run("nginx -t && systemctl reload nginx", timeout=15)
    log_fn("cymisp: nginx block added and reloaded" if rc == 0
           else f"cymisp: WARNING — nginx reload failed: {err}")


def _expand_ssl(module_id: str, base_domain: str, log_fn):
    """Expand the Let's Encrypt cert to cover a new module subdomain."""
    existing = NGINX_CONF.read_text() if NGINX_CONF.exists() else ""
    domains  = [f"cy360.{base_domain}", f"cyasm.{base_domain}", f"cysiem.{base_domain}"]
    for mod in ("cyiris", "cymisp"):
        if f"{mod}.{base_domain}" in existing:
            domains.append(f"{mod}.{base_domain}")
    new_sub = f"{module_id}.{base_domain}"
    if new_sub not in domains:
        domains.append(new_sub)
    rc, _, _ = run(
        "certbot --nginx --expand --non-interactive --agree-tos --domains "
        + ",".join(domains) + " 2>/dev/null || true",
        timeout=120,
    )
    log_fn(f"{module_id}: SSL cert expanded" if rc == 0
           else f"{module_id}: SSL expansion skipped (certbot not ready or DNS not resolving)")


# ══════════════════════════════════════════════════════════════════════════════
# INSTALL WORKER (runs in daemon thread)
# ══════════════════════════════════════════════════════════════════════════════

def _fail(module_id: str, error: str):
    state = load_state()
    state[module_id] = {"status": "failed", "error": error,
                        "installed_at": time.strftime('%Y-%m-%dT%H:%M:%SZ')}
    save_state(state)


def _install_module_async(module_id: str, compose_yaml: str, env_vars: dict):
    module_dir = MODULES_DIR / module_id
    module_dir.mkdir(parents=True, exist_ok=True)
    log_file   = module_dir / "install.log"

    def log(msg):
        with open(log_file, "a") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

    try:
        log(f"Starting installation of {module_id}")
        base_domain = os.environ.get("BASE_DOMAIN", "cycentra.com")

        # Always reload master .env so env vars set after Flask started are visible
        try:
            from dotenv import load_dotenv
            if os.path.exists("/opt/cycentra/.env"):
                load_dotenv("/opt/cycentra/.env", override=True)
            elif os.path.exists(".env"):
                load_dotenv(".env", override=True)
        except ImportError:
            pass

        # Write compose file
        compose_path = module_dir / "docker-compose.yml"
        compose_path.write_text(compose_yaml)
        log("Written docker-compose.yml")

        env_path   = module_dir / ".env"
        cyiris_env = {}   # always defined; populated below if module_id == "cyiris"

        # ── Per-module .env preparation ───────────────────────────────────────

        if module_id == "cyiris":
            # 1. Resolve password — Script 1 style
            _ui_password     = (env_vars.get("IRIS_ADM_PASSWORD") or "").strip()
            _master_password = (os.environ.get("IRIS_ADM_PASSWORD") or "").strip()
            _final_password  = _ui_password or _master_password

            if not _final_password:
                log("ERROR: IRIS_ADM_PASSWORD missing — aborting")
                raise ValueError("IRIS_ADM_PASSWORD is required")

            # 2. Build module .env
            cyiris_env = {
                "POSTGRES_PASSWORD":   os.environ.get("POSTGRES_PASSWORD") or os.environ.get("IRIS_DB_PASS", ""),
                "IRIS_SECRET_KEY":     os.environ.get("IRIS_SECRET_KEY") or os.environ.get("IRIS_SECRET", ""),
                "CYIRIS_OIDC_SECRET":  os.environ.get("CYIRIS_OIDC_SECRET", ""),
                "CYCENTRA_PORTAL_URL": os.environ.get("CYCENTRA_PORTAL_URL") or os.environ.get("FRONTEND_URL", ""),
                "IRIS_ADM_EMAIL":      os.environ.get("IRIS_ADM_EMAIL", "admin@cycentra.com"),
                "IRIS_ADM_PASSWORD":   _final_password,
                "BASE_DOMAIN":         base_domain,
            }
            env_vars.pop("IRIS_ADM_PASSWORD", None)
            cyiris_env.update(env_vars)
            env_path.write_text("\n".join(f"{k}={v}" for k, v in cyiris_env.items()))

            # 3. Write pgcrypto init script
            init_dir = module_dir / "db-init"
            init_dir.mkdir(parents=True, exist_ok=True)
            (init_dir / "01-pgcrypto.sql").write_text("CREATE EXTENSION IF NOT EXISTS pgcrypto;\n")

            # 4. Patch Compose file (CRITICAL: This is what Script 1 added)
            compose_text = compose_path.read_text()
            compose_text = compose_text.replace(
                "- cyiris_db_init:/docker-entrypoint-initdb.d",
                f"- {init_dir}:/docker-entrypoint-initdb.d"
            ).replace(
                'IRIS_ADM_PASSWORD: "${IRIS_ADM_PASSWORD}"',
                f'IRIS_ADM_PASSWORD: "{_final_password}"'
            )
            compose_path.write_text(compose_text)
            log(f"CyIRIS setup complete: hardcoded password into docker-compose.yml")

        elif module_id == "cysoar":
            # Pre-install cleanup — stale volumes cause httpStatic issues
            log("CySOAR pre-install cleanup — removing stale containers and volumes")
            run("docker compose down -v", cwd=str(module_dir), timeout=60)
            rc, c_out, _ = run("docker ps -aq --filter 'name=cysoar'", timeout=10)
            if rc == 0 and c_out.strip():
                old = [c.strip() for c in c_out.strip().split('\n') if c.strip()]
                if old:
                    run(f"docker rm -f {' '.join(old)}", timeout=30)
                    log(f"Removed {len(old)} stale containers")
            rc, v_out, _ = run("docker volume ls -q --filter 'name=cysoar'", timeout=10)
            if rc == 0 and v_out.strip():
                for vol in [v.strip() for v in v_out.strip().split('\n') if v.strip()]:
                    run(f"docker volume rm {vol}", timeout=10)
                    log(f"Removed stale volume: {vol}")
            log("CySOAR pre-install cleanup complete")

            cysoar_env = {
                # IAP mode: OIDC env vars removed — oauth2-proxy handles auth upstream
                "CYCENTRA_PORTAL_URL":      os.environ.get("CYCENTRA_PORTAL_URL") or os.environ.get("FRONTEND_URL", ""),
                "CYSOAR_SESSION_SECRET":    os.environ.get("NODE_RED_CREDENTIAL_SECRET", ""),
                "BASE_DOMAIN":              base_domain,
                "SMTP_HOST":                os.environ.get("SMTP_HOST", ""),
                "SMTP_PORT":                os.environ.get("SMTP_PORT", "587"),
                "SMTP_USER":                os.environ.get("SMTP_USER", ""),
                "SMTP_PASS":                os.environ.get("SMTP_PASS", ""),
                "SUPPORT_EMAIL":            os.environ.get("SUPPORT_EMAIL", "support@cycentra.com"),
            }
            cysoar_env.update(env_vars)
            env_path.write_text("\n".join(f"{k}={v}" for k, v in cysoar_env.items()))
            log(f"CySOAR .env written")

        else:
            # CyMISP and any future modules: write env_vars directly
            # For CyMISP, env_vars contains MISP_ADMIN_EMAIL, MISP_ADMIN_PASSPHRASE,
            # MISP_MYSQL_PASSWORD, MISP_MYSQL_ROOT_PASSWORD, REDIS_PASSWORD
            env_path.write_text("\n".join(f"{k}={v}" for k, v in env_vars.items()))
            log(f"Written .env with {len(env_vars)} variables")

        # ── GH pre-auth: login with token OR clear stale creds ─────────────
        # If GH_TOKEN is set: login properly so private/rate-limited pulls work.
        # If not set: logout to clear any stale/expired credentials stored in the
        # Docker credential store — this lets Docker fall back to anonymous pull,
        # which works fine for public ghcr.io images.
        if "ghcr.io" in compose_yaml:
            ghcr_token = os.environ.get("GH_TOKEN", "").strip()
            if ghcr_token:
                ghcr_user = os.environ.get("GH_USER", "ghcr")
                try:
                    import subprocess as _sp
                    _lr = _sp.run(
                        ["docker", "login", "ghcr.io", "-u", ghcr_user, "--password-stdin"],
                        input=ghcr_token,
                        capture_output=True, text=True, timeout=30,
                    )
                    if _lr.returncode == 0:
                        log("Logged in to ghcr.io with GH_TOKEN")
                    else:
                        log(f"WARNING: ghcr.io login failed: {_lr.stderr.strip()}")
                except Exception as _e:
                    log(f"WARNING: ghcr.io login error: {_e}")
            else:
                # Clear stale/expired creds; anonymous pull works for public images
                run("docker logout ghcr.io", timeout=10)
                log("Cleared stale ghcr.io credentials — using anonymous pull")

        # ── Pull images ───────────────────────────────────────────────────────
        log("Pulling Docker images...")
        rc, _, err = run("docker compose pull", cwd=str(module_dir), timeout=600)
        if rc != 0:
            log(f"ERROR pulling images: {err}")
            _fail(module_id, err)
            return

        # ── Start containers ──────────────────────────────────────────────────
        log("Starting containers...")
        rc, _, err = run("docker compose up -d", cwd=str(module_dir), timeout=120)
        if rc != 0:
            log(f"ERROR starting containers: {err}")
            _fail(module_id, err)
            return

        # ══════════════════════════════════════════════════════════════════════
        # POST-INSTALL HOOKS
        # ══════════════════════════════════════════════════════════════════════

        # ── CyMISP: wait for live, patch config, set credentials, nginx, SSL ──
        if module_id == "cymisp":
            misp_url = "https://cymisp." + base_domain
            log("CyMISP: waiting for MISP to initialise (8–12 min)...")
            misp_live = False

            for attempt in range(48):
                time.sleep(15)
                rc2, logs_out, _ = run(
                    "docker logs cymisp 2>&1 | grep 'MISP is now live'", timeout=10
                )
                if logs_out.strip():
                    misp_live = True
                    log(f"CyMISP: MISP is live (attempt {attempt + 1})")
                    break
                log(f"CyMISP: waiting... ({attempt + 1}/48)")

            if misp_live:
                # Patch baseurl in config.php
                sed_expr = (
                    "s|'baseurl' => '.*'|'baseurl' => '" + misp_url + "'|g;"
                    " s|'external_baseurl' => '.*'|'external_baseurl' => '" + misp_url + "'|g;"
                    " s|'rest_client_baseurl' => '.*'|'rest_client_baseurl' => '" + misp_url + "'|g"
                )
                rc2, _, err2 = run(
                    "docker exec cymisp sed -i \"" + sed_expr + "\" "
                    "/var/www/MISP/app/Config/config.php",
                    timeout=15
                )
                if rc2 == 0:
                    log("CyMISP: baseurl patched to " + misp_url)
                    # Save patched config to host — mounted as volume so it survives restarts
                    rc3, config_out, _ = run(
                        "docker exec cymisp cat /var/www/MISP/app/Config/config.php",
                        timeout=10
                    )
                    if rc3 == 0 and config_out:
                        (module_dir / "misp-config.php").write_text(config_out)
                        log("CyMISP: config.php saved to host")
                else:
                    log(f"CyMISP: WARNING — baseurl patch failed: {err2}")

                # Patch Redis password in config.php and PHP sessions
                redis_pass = env_vars.get("REDIS_PASSWORD", "redispassword")
                run(
                    "docker exec cymisp sed -i "
                    "\"s|'redis_password' => '.*'|'redis_password' => '" + redis_pass + "'|g\" "
                    "/var/www/MISP/app/Config/config.php",
                    timeout=10
                )
                run(
                    "docker exec cymisp bash -c \"find /etc/php -name 'www.conf' "
                    "-exec sed -i 's|auth=redispassword|auth=" + redis_pass + "|g' {} \\;\"",
                    timeout=10
                )
                log("CyMISP: Redis password patched")

                # Force admin credentials via database
                # MISP always creates admin@admin.test — we override via PDO
                admin_email = env_vars.get("MISP_ADMIN_EMAIL",      "admin@admin.test")
                admin_pass  = env_vars.get("MISP_ADMIN_PASSPHRASE", "admin")
                mysql_pass  = env_vars.get("MISP_MYSQL_PASSWORD",   "misp_db_pass")

                rc4, hash_out, _ = run(
                    "docker exec cymisp php -r \"echo password_hash('" +
                    admin_pass + "', PASSWORD_BCRYPT, ['cost'=>10]);\"",
                    timeout=10
                )
                if rc4 == 0 and hash_out.strip().startswith("$2y$"):
                    pw_hash = hash_out.strip().replace("$", "\\$")
                    run(
                        "docker exec cymisp php -r \""
                        "\\$conn = new PDO('mysql:host=cymisp-db;dbname=misp', 'misp', '" + mysql_pass + "');"
                        "\\$stmt = \\$conn->prepare('UPDATE users SET email=?, password=?, change_pw=0 WHERE id=1');"
                        "\\$stmt->execute(['" + admin_email + "', '" + pw_hash + "']);"
                        "echo 'done';\"",
                        timeout=15
                    )
                    log("CyMISP: credentials set — " + admin_email)
                else:
                    log("CyMISP: WARNING — could not hash password; defaults remain (admin@admin.test / admin)")

                state = load_state()
                state[module_id]["misp_ready"] = True
                save_state(state)
                log("CyMISP: fully ready — login at " + misp_url)
            else:
                log("CyMISP: WARNING — did not come live within 12 minutes")

            # Add nginx + expand SSL (done regardless of misp_live — nginx needed for access)
            _nginx_add_cymisp(base_domain, log)
            _expand_ssl("cymisp", base_domain, log)

        # Add nginx block + expand SSL
        if module_id == "cyiris":
            log("CyIRIS: Setup complete via environment injection. Finalizing Nginx...")
            _nginx_add_cyiris(base_domain, log)
            _expand_ssl("cyiris", base_domain, log)

            # Capture the admin API key from the IRIS DB and write it to
            # CLOUD_IRIS_API_KEY in the master .env so iris_test() and
            # iris_connector.py can use it without manual configuration.
            # IRIS auto-generates the key via secrets.token_urlsafe(64) in
            # post_init.py — it is never logged, so we query the DB directly.
            log("CyIRIS: waiting for DB to be ready...")
            _iris_key_captured = False
            for _attempt in range(24):   # up to 2 min
                time.sleep(5)
                rc_k, key_out, _ = run(
                    "docker exec cyiris-cyiris-db-1 psql -U iris -d iris_db -t "
                    "-c \"SELECT api_key FROM \\\"user\\\" WHERE name='administrator' LIMIT 1;\"",
                    timeout=10,
                )
                _key = (key_out or "").strip()
                if rc_k == 0 and _key:
                    _master_env = Path("/opt/cycentra/.env")
                    if _master_env.exists():
                        _env_text = _master_env.read_text()
                        # Update or append CLOUD_IRIS_API_KEY
                        if re.search(r"^CLOUD_IRIS_API_KEY=", _env_text, flags=re.MULTILINE):
                            _env_text = re.sub(
                                r"^CLOUD_IRIS_API_KEY=.*$", f"CLOUD_IRIS_API_KEY={_key}",
                                _env_text, flags=re.MULTILINE,
                            )
                        else:
                            _env_text = _env_text.rstrip("\n") + f"\nCLOUD_IRIS_API_KEY={_key}\n"
                        # Ensure CLOUD_IRIS_URL points to the local CyIRIS install.
                        # Remove ALL existing entries first (handles duplicates from
                        # prior installs) then append exactly one correct line.
                        _iris_url_default = "http://127.0.0.1:4433"
                        _env_text = re.sub(
                            r"^CLOUD_IRIS_URL=.*\n?", "",
                            _env_text, flags=re.MULTILINE,
                        )
                        _env_text = _env_text.rstrip("\n") + f"\nCLOUD_IRIS_URL={_iris_url_default}\n"
                        os.environ["CLOUD_IRIS_URL"] = _iris_url_default
                        log(f"CyIRIS: CLOUD_IRIS_URL set to {_iris_url_default} in master .env")
                        _master_env.write_text(_env_text)
                        os.environ["CLOUD_IRIS_API_KEY"] = _key
                        log(f"CyIRIS: CLOUD_IRIS_API_KEY captured and written to master .env")

                        # Activate mode=cloud in ai_settings.json so get_iris_config()
                        # returns a valid config without requiring a manual UI save.
                        _ai_file = Path("/opt/cycentra/ai_settings.json")
                        try:
                            _ai = json.loads(_ai_file.read_text()) if _ai_file.exists() else {}
                            _ai.setdefault("iris", {})["mode"] = "cloud"
                            _ai_file.parent.mkdir(parents=True, exist_ok=True)
                            _ai_file.write_text(json.dumps(_ai, indent=2))
                            log("CyIRIS: ai_settings.json → iris.mode=cloud activated")
                        except Exception as _ae:
                            log(f"CyIRIS: WARNING — ai_settings.json update failed: {_ae}")

                        # Sync integration settings into cysiemstack.env so the
                        # correlation engine activates without a manual restart.
                        _siem_path = Path("/opt/cycentra/cysiemstack.env")
                        if _siem_path.exists():
                            try:
                                _iris_updates = {
                                    "IRIS_MODE":        "cloud",
                                    "IRIS_ENABLED":     "true",
                                    "IRIS_URL":         _iris_url_default,
                                    "IRIS_API_KEY":     _key,
                                    "IRIS_CUSTOMER_ID": "1",
                                }
                                _siem_lines = _siem_path.read_text().splitlines()
                                _siem_result, _siem_seen = [], set()
                                for _sl in _siem_lines:
                                    _sk = _sl.split("=", 1)[0].strip()
                                    if _sk in _iris_updates:
                                        _siem_result.append(f"{_sk}={_iris_updates[_sk]}")
                                        _siem_seen.add(_sk)
                                    else:
                                        _siem_result.append(_sl)
                                for _sk, _sv in _iris_updates.items():
                                    if _sk not in _siem_seen:
                                        _siem_result.append(f"{_sk}={_sv}")
                                _siem_path.write_text("\n".join(_siem_result) + "\n")
                                log("CyIRIS: cysiemstack.env → IRIS_MODE=cloud, IRIS_ENABLED=true")
                            except Exception as _se:
                                log(f"CyIRIS: WARNING — cysiemstack.env update failed: {_se}")

                        _iris_key_captured = True
                    break
                log(f"CyIRIS: DB not ready yet ({_attempt + 1}/24)")
            if not _iris_key_captured:
                log("CyIRIS: WARNING — could not capture admin API key from DB; set CLOUD_IRIS_API_KEY manually")

        # ── CySOAR: inject /cysoar/ location into portal server ───────────────

        if module_id == "cysoar":
            for _ in range(6):
                time.sleep(5)
                # Check if the container is up and the service is responding
                rc_hc, _, _ = run("docker exec cysoar curl -sf http://localhost:1880/", timeout=5)
                
                if rc_hc == 0:
                    log("CySOAR: container is responding")
                    break
            else:
                # Optional: Add a warning if the loop finishes without breaking (success)
                log("WARNING: CySOAR container did not respond in time, attempting Nginx config anyway.")

            # This must align with the 'print' and 'for' to be inside the 'if'
            _nginx_inject_cysoar(base_domain, log)

            # ── IAP mode: no per-app OIDC needed ────────────────────────────────
            # Authentication is handled by oauth2-proxy + nginx auth_request.
            # CySOAR settings.js has no adminAuth — the container is open to
            # whatever nginx allows through (only authenticated users).
            log("CySOAR: IAP mode — no OIDC settings needed")
            run("docker restart cysoar", timeout=30)
            log("CySOAR: restarted")
        
        # ── Final state ───────────────────────────────────────────────────────
        time.sleep(5)
        running = docker_containers_running(module_id)
        state   = load_state()
        state[module_id] = {
            "status":       "running" if running else "degraded",
            "installed_at": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "compose_dir":  str(module_dir),
        }
        save_state(state)
        log(f"Done — status: {state[module_id]['status']}")

    except Exception as e:
        import traceback
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())
        _fail(module_id, str(e))
