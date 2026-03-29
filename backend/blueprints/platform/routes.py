"""
blueprints/platform/routes.py
================================
Platform module management API.

Routes:
  POST   /api/platform/install
  POST   /api/platform/uninstall
  GET    /api/platform/status
  GET    /api/platform/logs/<module_id>
  GET    /api/debug/images

Fixes vs previous version:
  1. CyIRIS password: env_vars (UI input) is checked FIRST for IRIS_ADM_PASSWORD,
     then falls back to master .env — so the UI-entered password always wins.
  2. nginx blocks: added _nginx_add_block() and _nginx_remove_block() helpers.
     All three modules (cyiris, cysoar, cymisp) now get nginx blocks on install
     and have them removed on uninstall.
  3. CyMISP: full post-install sequence restored (credentials, redis patch,
     nginx block, certbot SSL expansion).
"""

import os
import re
import shutil
import threading
import time
from pathlib import Path

from flask import Blueprint, request, jsonify, make_response

from core.config import MODULES_DIR
from core.helpers import run, add_cors_headers
from blueprints.platform.compose import (
    COMPOSE_TEMPLATES, VALID_MODULES,
    _CYSOAR_IMAGE as CYSOAR_IMAGE,
    _CYIRIS_IMAGE_APP as CYIRIS_IMAGE_APP,
    _CYIRIS_IMAGE_DB as CYIRIS_IMAGE_DB,
)
from blueprints.platform.state import load_state, save_state
from blueprints.platform.docker_utils import docker_containers_running

platform_bp = Blueprint("platform", __name__)

NGINX_CONF = Path("/etc/nginx/sites-available/cycentra-modules")


# ── Preflight ─────────────────────────────────────────────────────────────────

@platform_bp.route("/api/platform/install",   methods=["OPTIONS"])
@platform_bp.route("/api/platform/uninstall", methods=["OPTIONS"])
def platform_options():
    return add_cors_headers(make_response('', 204))


# ── nginx helpers ─────────────────────────────────────────────────────────────

def _nginx_block_for(module_id: str, base_domain: str) -> str:
    """Return the nginx server block text for a given module."""
    ssl_cert     = f"/etc/letsencrypt/live/cy360.{base_domain}/fullchain.pem"
    ssl_key      = f"/etc/letsencrypt/live/cy360.{base_domain}/privkey.pem"
    ssl_options  = "/etc/letsencrypt/options-ssl-nginx.conf"
    ssl_dhparam  = "/etc/letsencrypt/ssl-dhparams.pem"
    hsts         = 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
    xcto         = 'add_header X-Content-Type-Options "nosniff" always;'

    # Each module: subdomain + port + proxy settings
    configs = {
        "cyiris": {
            "subdomain": f"cyiris.{base_domain}",
            "upstream":  "http://127.0.0.1:4433",
            "extra": (
                "        proxy_http_version 1.1;\n"
                "        proxy_set_header Host $host;\n"
                "        proxy_set_header X-Real-IP $remote_addr;\n"
                "        proxy_set_header X-Forwarded-Proto https;\n"
                "        proxy_read_timeout 300;\n"
                "        proxy_buffer_size 128k;\n"
                "        proxy_buffers 4 256k;\n"
                "        proxy_cookie_flags ~ samesite=none secure;\n"
                '        add_header X-Frame-Options "" always;\n'
                f'        add_header Content-Security-Policy "frame-ancestors \'self\' https://cy360.{base_domain}" always;\n'
                f'        add_header Access-Control-Allow-Origin "https://cy360.{base_domain}" always;\n'
                '        add_header Access-Control-Allow-Credentials "true" always;\n'
                '        if ($request_method = OPTIONS) { return 204; }\n'
            ),
        },
        # CySOAR: path-based — handled by _nginx_inject_cysoar(), not _nginx_block_for()
        "cymisp": {
            "subdomain": f"cymisp.{base_domain}",
            "upstream":  "https://127.0.0.1:8243",
            "extra":     (
                "        proxy_ssl_verify off;\n"
                "        proxy_set_header Host $host;\n"
                "        proxy_set_header X-Real-IP $remote_addr;\n"
                "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
                "        proxy_set_header X-Forwarded-Proto https;\n"
                "        proxy_set_header X-Forwarded-Host $host;\n"
                "        proxy_set_header X-Forwarded-Port 443;\n"
                "        proxy_read_timeout 300s;\n"
                '        add_header Content-Security-Policy "default-src \'self\' \'unsafe-inline\' \'unsafe-eval\' data: blob:;" always;\n'
            ),
        },
    }

    cfg = configs.get(module_id)
    if not cfg:
        return ""

    subdomain = cfg["subdomain"]
    upstream  = cfg["upstream"]
    extra     = cfg["extra"]

    return (
        f"\nserver {{\n"
        f"    listen 80; server_name {subdomain};\n"
        f"    return 301 https://$host$request_uri;\n"
        f"}}\n"
        f"server {{\n"
        f"    listen 443 ssl http2; server_name {subdomain};\n"
        f"    ssl_certificate     {ssl_cert};\n"
        f"    ssl_certificate_key {ssl_key};\n"
        f"    include             {ssl_options};\n"
        f"    ssl_dhparam         {ssl_dhparam};\n"
        f"    {hsts}\n"
        f"    {xcto}\n"
        f"    location / {{\n"
        f"        proxy_pass {upstream};\n"
        f"        proxy_set_header Host $host;\n"
        f"{extra}"
        f"    }}\n"
        f"}}\n"
    )


def _nginx_add_block(module_id: str, base_domain: str, log_fn):
    """Add module's nginx server block and reload nginx. Idempotent."""
    if not NGINX_CONF.exists():
        log_fn(f"{module_id}: nginx config not found at {NGINX_CONF} — skipping nginx block")
        return

    subdomain = f"{module_id}.{base_domain}" if module_id != "cysiem" else f"cysiem.{base_domain}"
    existing  = NGINX_CONF.read_text()

    if subdomain in existing:
        log_fn(f"{module_id}: nginx block for {subdomain} already exists")
        return

    block = _nginx_block_for(module_id, base_domain)
    if not block:
        log_fn(f"{module_id}: no nginx block template for this module")
        return

    NGINX_CONF.write_text(existing + block)
    rc, _, err = run("nginx -t && systemctl reload nginx", timeout=15)
    if rc == 0:
        log_fn(f"{module_id}: nginx block added for {subdomain} and nginx reloaded")
    else:
        log_fn(f"{module_id}: WARNING — nginx reload failed: {err}")


def _nginx_remove_block(module_id: str, base_domain: str):
    """Remove module's nginx server block and reload nginx."""
    if not NGINX_CONF.exists():
        return

    subdomain = f"{module_id}.{base_domain}"
    content   = NGINX_CONF.read_text()

    # Remove all server blocks for this subdomain.
    # The regex handles one level of nested braces (location {} inside server {}).
    new_content = re.sub(
        r'\nserver\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*server_name\s+'
        + re.escape(subdomain)
        + r'[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',
        '', content, flags=re.DOTALL
    )

    if new_content != content:
        NGINX_CONF.write_text(new_content)
        run("nginx -t && systemctl reload nginx", timeout=15)


def _nginx_inject_cysoar(base_domain: str, log_fn):
    """
    Inject location /cysoar/ into the cy360.DOMAIN portal server block.
    CySOAR is path-based — not a subdomain. Idempotent.
    """
    if not NGINX_CONF.exists():
        log_fn("cysoar: nginx config not found — skipping /cysoar/ injection")
        return
    text = NGINX_CONF.read_text()
    if "location /cysoar/" in text:
        log_fn("cysoar: /cysoar/ location block already exists")
        return
    block = (
        "    location /cysoar/ {\n"
        "        proxy_pass http://127.0.0.1:1880/;\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Upgrade $http_upgrade;\n"
        "        proxy_set_header Connection $connection_upgrade;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_read_timeout 120s;\n"
        "        proxy_buffering off;\n"
        "    }\n"
    )
    # Anchor 1: comment placed by setup.sh exactly where we want to insert
    anchor_comment = "    # location /cysoar/ is injected here"
    if anchor_comment in text:
        ins  = text.find(anchor_comment)
        text = text[:ins] + block + text[ins:]
        NGINX_CONF.write_text(text)
        rc, _, err = run("nginx -t && systemctl reload nginx", timeout=15)
        log_fn("cysoar: /cysoar/ location injected and nginx reloaded" if rc == 0
               else f"cysoar: WARNING — nginx reload failed: {err}")
        return
    # Anchor 2: insert before the closing brace of the cy360 server block
    # Find the last } that closes a server block containing /oidc/
    oidc_pos = text.find("location /oidc/")
    if oidc_pos != -1:
        # Find the next server-level closing brace after /oidc/
        close = text.find("\n}", oidc_pos)
        if close != -1:
            ins  = close + 1  # insert before the newline+}
            text = text[:ins] + "\n" + block + text[ins:]
            NGINX_CONF.write_text(text)
            rc, _, err = run("nginx -t && systemctl reload nginx", timeout=15)
            log_fn("cysoar: /cysoar/ location injected and nginx reloaded" if rc == 0
                   else f"cysoar: WARNING — nginx reload failed: {err}")
            return
    log_fn("cysoar: WARNING — could not find anchor — add location /cysoar/ manually")


def _nginx_remove_cysoar():
    """Remove the /cysoar/ location block from the portal server block."""
    if not NGINX_CONF.exists():
        return
    text     = NGINX_CONF.read_text()
    new_text = re.sub(r'[ \t]+location /cysoar/ \{[^{}]+\}\n', '', text, flags=re.DOTALL)
    if new_text != text:
        NGINX_CONF.write_text(new_text)
        run("nginx -t && systemctl reload nginx", timeout=15)


def _expand_ssl_cert(module_id: str, base_domain: str, log_fn):
    """Expand the Let's Encrypt cert to cover the new module's subdomain."""
    # Build the full domain list from the existing nginx config
    existing   = NGINX_CONF.read_text() if NGINX_CONF.exists() else ""
    # Always include the core domains
    core       = [f"cy360.{base_domain}", f"cyscan.{base_domain}", f"cysiem.{base_domain}"]
    # Add any module subdomains already in the config
    for mod in ("cyiris", "cysoar", "cymisp"):
        if f"{mod}.{base_domain}" in existing:
            core.append(f"{mod}.{base_domain}")
    # Ensure the new one is included
    new_sub = f"{module_id}.{base_domain}"
    if new_sub not in core:
        core.append(new_sub)

    domains = ",".join(core)
    rc, _, err = run(
        f"certbot --nginx --expand --non-interactive --agree-tos --domains {domains} 2>/dev/null || true",
        timeout=120,
    )
    log_fn(f"{module_id}: SSL cert expanded to cover {new_sub}" if rc == 0
           else f"{module_id}: SSL expansion skipped (certbot not ready or domains not resolving)")


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

        saved["last_log"] = last_log
        result[module_id] = saved

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

    # Strip empty/private values from UI config
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

    module_dir = MODULES_DIR / module_id
    errors     = []

    if module_dir.exists():
        # 1. Graceful compose shutdown
        run("docker compose down -v", cwd=str(module_dir), timeout=60)

        # 2. Force-remove known container names
        container_names = {
            "cyiris": ["cyiris-cyiris-1", "cyiris-cyiris-db-1", "cyiris", "cyiris-db"],
            "cysoar": ["cysoar"],
            "cymisp": ["cymisp", "cymisp-db", "cymisp-redis"],
        }.get(module_id, [])
        for c in container_names:
            run(f"docker rm -f {c} 2>/dev/null || true", timeout=10)

        # 3. Remove all volumes matching module name
        rc, vols_out, _ = run(f"docker volume ls -q --filter name={module_id}", timeout=10)
        if rc == 0 and vols_out.strip():
            for vol in vols_out.strip().splitlines():
                run(f"docker volume rm -f {vol.strip()} 2>/dev/null || true", timeout=10)

        # 4. Remove nginx config for this module
        base_domain = os.environ.get("BASE_DOMAIN", "cycentra.com")
        if module_id in ("cyiris", "cymisp"):
            _nginx_remove_block(module_id, base_domain)
        elif module_id == "cysoar":
            _nginx_remove_cysoar()

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


# ── Debug ─────────────────────────────────────────────────────────────────────

@platform_bp.route("/api/debug/images")
def debug_images():
    return jsonify({
        "CYSOAR_IMAGE":     CYSOAR_IMAGE,
        "CYIRIS_IMAGE_APP": CYIRIS_IMAGE_APP,
        "CYIRIS_IMAGE_DB":  CYIRIS_IMAGE_DB,
        "SIEM_ENGINE_URL":  os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100"),
        "env_file_loaded":  os.path.exists("/opt/cycentra/.env") or os.path.exists(".env"),
    })


# ── Async install worker ──────────────────────────────────────────────────────

def _fail(module_id: str, error: str):
    state = load_state()
    state[module_id] = {
        "status":       "failed",
        "error":        error,
        "installed_at": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
    }
    save_state(state)


def _install_module_async(module_id: str, compose_yaml: str, env_vars: dict):
    """
    Runs in a daemon thread. Pulls images, starts containers,
    runs post-install hooks (password forcing, nginx, SSL), updates state.
    """
    module_dir = MODULES_DIR / module_id
    module_dir.mkdir(parents=True, exist_ok=True)
    log_file   = module_dir / "install.log"

    def log(msg):
        with open(log_file, "a") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

    try:
        log(f"Starting installation of {module_id}")
        base_domain = os.environ.get("BASE_DOMAIN", "cycentra.com")
        cyiris_env  = {}  # always defined; populated below if module_id == "cyiris"

        # Reload master .env so all env vars are current
        try:
            from dotenv import load_dotenv
            if os.path.exists("/opt/cycentra/.env"):
                load_dotenv("/opt/cycentra/.env", override=True)
            elif os.path.exists(".env"):
                load_dotenv(".env", override=True)
        except ImportError:
            pass

        compose_path = module_dir / "docker-compose.yml"
        compose_path.write_text(compose_yaml)
        log("Written docker-compose.yml")

        env_path = module_dir / ".env"

        # ── CyIRIS: build full env, UI password wins over .env default ────────
        if module_id == "cyiris":
            # FIX: check env_vars (UI input) FIRST, then fall back to master .env
            # This is what the original app.py did via cyiris_env.update(env_vars)
            _iris_adm_password = (
                env_vars.get("IRIS_ADM_PASSWORD")           # UI-entered password — WINS
                or os.environ.get("IRIS_ADM_PASSWORD")      # master .env fallback
            )
            if not _iris_adm_password:
                log("ERROR: IRIS_ADM_PASSWORD not provided and not set in /opt/cycentra/.env — aborting")
                raise ValueError("IRIS_ADM_PASSWORD is required")

            cyiris_env = {
                "POSTGRES_PASSWORD":   os.environ.get("POSTGRES_PASSWORD") or os.environ.get("IRIS_DB_PASS", ""),
                "IRIS_SECRET_KEY":     os.environ.get("IRIS_SECRET_KEY")   or os.environ.get("IRIS_SECRET", ""),
                "CYIRIS_OIDC_SECRET":  os.environ.get("CYIRIS_OIDC_SECRET", ""),
                "CYCENTRA_PORTAL_URL": os.environ.get("CYCENTRA_PORTAL_URL") or os.environ.get("FRONTEND_URL", ""),
                "IRIS_ADM_EMAIL":      os.environ.get("IRIS_ADM_EMAIL", "admin@cycentra.com"),
                "IRIS_ADM_PASSWORD":   _iris_adm_password,
            }
            # env_vars may contain IRIS_ADM_PASSWORD again — update() ensures UI value persists
            cyiris_env.update(env_vars)
            env_path.write_text("\n".join(f"{k}={v}" for k, v in cyiris_env.items()))
            log(f"Created cyiris .env ({len(cyiris_env)} vars) — password source: {'UI form' if env_vars.get('IRIS_ADM_PASSWORD') else 'master .env'}")

            # pgcrypto init script
            init_dir = module_dir / "db-init"
            init_dir.mkdir(parents=True, exist_ok=True)
            (init_dir / "01-pgcrypto.sql").write_text("CREATE EXTENSION IF NOT EXISTS pgcrypto;\n")
            compose_text = compose_path.read_text().replace(
                "- cyiris_db_init:/docker-entrypoint-initdb.d",
                f"- {init_dir}:/docker-entrypoint-initdb.d",
            )
            compose_path.write_text(compose_text)
            log("pgcrypto init script written")

        # ── CySOAR: clean stale volumes, write env ────────────────────────────
        elif module_id == "cysoar":
            log("CySOAR pre-install cleanup")
            run("docker compose down -v", cwd=str(module_dir), timeout=60)
            rc, c_out, _ = run("docker ps -aq --filter 'name=cysoar'", timeout=10)
            if rc == 0 and c_out.strip():
                old = [c.strip() for c in c_out.strip().split('\n') if c.strip()]
                if old:
                    run(f"docker rm -f {' '.join(old)}", timeout=30)
            rc, v_out, _ = run("docker volume ls -q --filter 'name=cysoar'", timeout=10)
            if rc == 0 and v_out.strip():
                for vol in [v.strip() for v in v_out.strip().split('\n') if v.strip()]:
                    run(f"docker volume rm {vol}", timeout=10)

            # Build CySOAR env from master .env + UI overrides
            cysoar_env = {
                "CYCENTRA_PORTAL_URL": os.environ.get("CYCENTRA_PORTAL_URL") or os.environ.get("FRONTEND_URL", ""),
                "CYSOAR_OIDC_SECRET":  os.environ.get("CYSOAR_OIDC_SECRET", ""),
                "BASE_DOMAIN":         base_domain,
            }
            cysoar_env.update(env_vars)
            env_path.write_text("\n".join(f"{k}={v}" for k, v in cysoar_env.items()))
            log("CySOAR pre-install cleanup complete")

        # ── CyMISP and others: write env_vars directly ────────────────────────
        else:
            # For CyMISP: env_vars contains MISP_ADMIN_EMAIL, MISP_ADMIN_PASSPHRASE, REDIS_PASSWORD
            env_path.write_text("\n".join(f"{k}={v}" for k, v in env_vars.items()))
            log(f"Created .env with {len(env_vars)} variables")

        # ── Pull + Start ──────────────────────────────────────────────────────
        log("Pulling Docker images…")
        rc, out, err = run("docker compose pull", cwd=str(module_dir), timeout=600)
        if rc != 0:
            log(f"ERROR pulling images: {err}")
            _fail(module_id, err)
            return

        log("Starting containers…")
        rc, out, err = run("docker compose up -d", cwd=str(module_dir), timeout=120)
        if rc != 0:
            log(f"ERROR starting containers: {err}")
            _fail(module_id, err)
            return

        # ══════════════════════════════════════════════════════════════════════
        # POST-INSTALL HOOKS
        # ══════════════════════════════════════════════════════════════════════

        # ── CyMISP post-install ────────────────────────────────────────────────
        if module_id == "cymisp":
            misp_url  = f"https://cymisp.{base_domain}"
            log("CyMISP: waiting for MISP to initialise (8–12 min)…")
            misp_live = False

            for attempt in range(48):
                time.sleep(15)
                rc2, logs_out, _ = run(
                    "docker logs cymisp 2>&1 | grep 'MISP is now live'", timeout=10
                )
                if logs_out.strip():
                    misp_live = True
                    log(f"CyMISP: MISP is live (attempt {attempt+1})")
                    break
                log(f"CyMISP: waiting… ({attempt+1}/48)")

            if misp_live:
                # Patch baseurl in config.php
                sed_expr = (
                    f"s|'baseurl' => '.*'|'baseurl' => '{misp_url}'|g;"
                    f" s|'external_baseurl' => '.*'|'external_baseurl' => '{misp_url}'|g;"
                    f" s|'rest_client_baseurl' => '.*'|'rest_client_baseurl' => '{misp_url}'|g"
                )
                rc2, _, err2 = run(
                    f'docker exec cymisp sed -i "{sed_expr}" /var/www/MISP/app/Config/config.php',
                    timeout=15,
                )
                if rc2 == 0:
                    log(f"CyMISP: baseurl patched to {misp_url}")
                    # Save patched config to host (survives restarts)
                    rc3, config_out, _ = run(
                        "docker exec cymisp cat /var/www/MISP/app/Config/config.php", timeout=10
                    )
                    if rc3 == 0 and config_out:
                        (module_dir / "misp-config.php").write_text(config_out)
                        log("CyMISP: config.php saved to host — survives restarts")
                else:
                    log(f"CyMISP: WARNING — baseurl patch failed: {err2}")

                # Patch Redis password in config.php and PHP sessions
                redis_pass = env_vars.get("REDIS_PASSWORD", "redispassword")
                run(
                    f"docker exec cymisp sed -i "
                    f"\"s|'redis_password' => '.*'|'redis_password' => '{redis_pass}'|g\" "
                    f"/var/www/MISP/app/Config/config.php",
                    timeout=10,
                )
                run(
                    f"docker exec cymisp bash -c \"find /etc/php -name 'www.conf' "
                    f"-exec sed -i 's|auth=redispassword|auth={redis_pass}|g' {{}} \\;\"",
                    timeout=10,
                )
                log("CyMISP: Redis password patched in config and PHP sessions")

                # Force admin credentials via database
                admin_email = env_vars.get("MISP_ADMIN_EMAIL",      "admin@admin.test")
                admin_pass  = env_vars.get("MISP_ADMIN_PASSPHRASE", "admin")
                mysql_pass  = env_vars.get("MISP_MYSQL_PASSWORD",   "misp_db_pass")

                rc4, hash_out, _ = run(
                    f"docker exec cymisp php -r \"echo password_hash('{admin_pass}', PASSWORD_BCRYPT, ['cost'=>10]);\"",
                    timeout=10,
                )
                if rc4 == 0 and hash_out.strip().startswith("$2y$"):
                    pw_hash = hash_out.strip().replace("$", "\\$")
                    run(
                        f"docker exec cymisp php -r \""
                        f"\\$conn = new PDO('mysql:host=cymisp-db;dbname=misp', 'misp', '{mysql_pass}');"
                        f"\\$stmt = \\$conn->prepare('UPDATE users SET email=?, password=?, change_pw=0 WHERE id=1');"
                        f"\\$stmt->execute(['{admin_email}', '{pw_hash}']);"
                        f"echo 'done';\"",
                        timeout=15,
                    )
                    log(f"CyMISP: credentials set — {admin_email}")
                else:
                    log("CyMISP: WARNING — could not hash password; defaults remain (admin@admin.test / admin)")

                state = load_state()
                state[module_id]["misp_ready"] = True
                save_state(state)
                log(f"CyMISP: fully ready — login at {misp_url}")
            else:
                log("CyMISP: WARNING — MISP did not come live within 12 minutes")

            # Add nginx block + expand SSL cert
            _nginx_add_block("cymisp", base_domain, log)
            _expand_ssl_cert("cymisp", base_domain, log)

        # ── CyIRIS post-install: force admin credentials via DB ───────────────
        if module_id == "cyiris":
            log("CyIRIS: waiting for app to initialise (up to 90s)…")
            app_container = "cyiris-cyiris-1"
            db_container  = "cyiris-cyiris-db-1"
            iris_ready    = False

            for attempt in range(18):
                time.sleep(5)
                rc_ping, _, _ = run(
                    f"docker exec {app_container} curl -sf http://localhost:8000/api/ping",
                    timeout=10,
                )
                if rc_ping == 0:
                    iris_ready = True
                    log(f"CyIRIS: app is up (attempt {attempt+1})")
                    break
                log(f"CyIRIS: waiting… ({attempt+1}/18)")

            if iris_ready:
                # Read password directly from env_vars (UI input) first,
                # then cyiris_env (which merged env_vars + master .env),
                # then master .env as last resort.
                admin_email    = (
                    env_vars.get("IRIS_ADM_EMAIL")
                    or cyiris_env.get("IRIS_ADM_EMAIL")
                    or os.environ.get("IRIS_ADM_EMAIL", "admin@cycentra.com")
                )
                admin_password = (
                    env_vars.get("IRIS_ADM_PASSWORD")        # UI form — highest priority
                    or cyiris_env.get("IRIS_ADM_PASSWORD")   # merged env
                    or os.environ.get("IRIS_ADM_PASSWORD", "")
                )
                if not admin_password:
                    log("CyIRIS: ERROR — IRIS_ADM_PASSWORD empty, cannot set credentials")
                else:
                    safe_pw = admin_password.replace("'", "\\'").replace('"', '\\"')
                    rc_h, hash_out, hash_err = run(
                        f'docker exec {app_container} python3 -c "'
                        f'from werkzeug.security import generate_password_hash;'
                        f'print(generate_password_hash(\\"{safe_pw}\\", method=\\"pbkdf2:sha256\\"))"',
                        timeout=15,
                    )
                    if rc_h == 0 and hash_out.strip().startswith("pbkdf2:"):
                        pw_hash = hash_out.strip()
                        rc_db, _, db_err = run(
                            f'docker exec {db_container} psql -U iris -d iris_db -c '
                            f'"UPDATE \\"User\\" SET password=\'{pw_hash}\', email=\'{admin_email}\' '
                            f'WHERE login=\'administrator\';"',
                            timeout=15,
                        )
                        if rc_db == 0:
                            log(f"CyIRIS: password forced via DB — username: administrator, email: {admin_email}")
                        else:
                            log(f"CyIRIS: ERROR — DB update failed: {db_err}")
                    else:
                        log(f"CyIRIS: WARNING — could not generate password hash: {hash_err}")
            else:
                log("CyIRIS: WARNING — app did not respond in 90s; check: docker logs cyiris-cyiris-1")

            # Add cyiris.DOMAIN nginx server block + expand SSL cert
            _nginx_add_block("cyiris", base_domain, log)
            _expand_ssl_cert("cyiris", base_domain, log)

        # ── CySOAR post-install ───────────────────────────────────────────────────
        # Inject /cysoar/ location block into the portal server on CySOAR install
        if module_id == "cysoar":
            _nginx_inject_cysoar(base_domain, log)
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
        log(f"EXCEPTION: {e}")
        import traceback
        log(traceback.format_exc())
        _fail(module_id, str(e))
