"""
blueprints/platform/routes.py
================================
Platform module management API.
Aligned with cycentra-setup.sh for dedicated SSL folder structures.
"""

import os
import re
import shutil
import threading
import time
from pathlib import Path

from flask import Blueprint, request, jsonify, make_response

# ── Imports & Globals ─────────────────────────────────────────────────────────
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

# This matches the path used in setup.sh
NGINX_CONF = Path("/etc/nginx/sites-available/cycentra-modules")

# ── [SECTION: SSL Path Resolver] ──────────────────────────────────────────────
# Purpose: Ensures routes.py looks in the dedicated folders created by setup.sh
def _get_ssl_paths(module_id: str, base_domain: str):
    """
    Returns dedicated cert paths. 
    CySOAR uses the portal (cy360) cert; others get their own folder.
    """
    folder = f"cy360.{base_domain}" if module_id == "cysoar" else f"{module_id}.{base_domain}"
    return {
        "cert": f"/etc/letsencrypt/live/{folder}/fullchain.pem",
        "key":  f"/etc/letsencrypt/live/{folder}/privkey.pem"
    }

# ── [SECTION: Nginx Helper Functions] ─────────────────────────────────────────
# Purpose: Generates module-specific server blocks with correct SSL paths.
def _nginx_block_for(module_id: str, base_domain: str) -> str:
    paths = _get_ssl_paths(module_id, base_domain)
    ssl_cert     = paths["cert"]
    ssl_key      = paths["key"]
    ssl_options  = "/etc/letsencrypt/options-ssl-nginx.conf"
    ssl_dhparam  = "/etc/letsencrypt/ssl-dhparams.pem"
    hsts         = 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
    xcto         = 'add_header X-Content-Type-Options "nosniff" always;'

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
    if not cfg: return ""

    subdomain = cfg["subdomain"]
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
        f"        proxy_pass {cfg['upstream']};\n"
        f"        proxy_set_header Host $host;\n"
        f"{cfg['extra']}"
        f"    }}\n"
        f"}}\n"
    )

def _nginx_add_block(module_id: str, base_domain: str, log_fn):
    """Add module's nginx server block and reload nginx. Idempotent."""
    if not NGINX_CONF.exists():
        log_fn(f"{module_id}: nginx config not found at {NGINX_CONF} - skipping")
        return

    subdomain = f"{module_id}.{base_domain}"
    existing  = NGINX_CONF.read_text()

    if subdomain in existing:
        log_fn(f"{module_id}: nginx block for {subdomain} already exists")
        return

    block = _nginx_block_for(module_id, base_domain)
    if not block: return

    NGINX_CONF.write_text(existing + block)
    rc, _, err = run("nginx -t && systemctl reload nginx", timeout=15)
    if rc == 0:
        log_fn(f"{module_id}: nginx block added for {subdomain} and nginx reloaded")
    else:
        log_fn(f"{module_id}: WARNING — nginx reload failed: {err}")

def _nginx_remove_block(module_id: str, base_domain: str):
    if not NGINX_CONF.exists(): return
    subdomain = f"{module_id}.{base_domain}"
    content   = NGINX_CONF.read_text()
    new_content = re.sub(
        r'\nserver\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*server_name\s+'
        + re.escape(subdomain)
        + r'[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',
        '', content, flags=re.DOTALL
    )
    if new_content != content:
        NGINX_CONF.write_text(new_content)
        run("nginx -t && systemctl reload nginx", timeout=15)

# ── [SECTION: CySOAR Path-Based Injection] ────────────────────────────────────
# Purpose: CySOAR is unique as it is a location block inside the main portal.
def _nginx_inject_cysoar(base_domain: str, log_fn):
    if not NGINX_CONF.exists(): return
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
    anchor_comment = "    # location /cysoar/ is injected here"
    if anchor_comment in text:
        ins = text.find(anchor_comment)
        text = text[:ins] + block + text[ins:]
        NGINX_CONF.write_text(text)
        rc, _, err = run("nginx -t && systemctl reload nginx", timeout=15)
        log_fn("cysoar: /cysoar/ location injected" if rc == 0 else f"cysoar: reload fail: {err}")
        return
    log_fn("cysoar: WARNING — could not find anchor for injection")

def _nginx_remove_cysoar():
    if not NGINX_CONF.exists(): return
    text = NGINX_CONF.read_text()
    new_text = re.sub(r'[ \t]+location /cysoar/ \{[^{}]+\}\n', '', text, flags=re.DOTALL)
    if new_text != text:
        NGINX_CONF.write_text(new_text)
        run("nginx -t && systemctl reload nginx", timeout=15)

# ── [SECTION: SSL Generation] ─────────────────────────────────────────────────
# Purpose: Replaces "expansion" with "dedicated generation" to match setup.sh
def _generate_module_ssl(module_id: str, base_domain: str, log_fn):
    if module_id == "cysoar": return # Handled by cy360 cert
    target_domain = f"{module_id}.{base_domain}"
    log_fn(f"{module_id}: Generating dedicated SSL for {target_domain}...")
    
    # Non-interactive generation using nginx plugin
    rc, _, err = run(
        f"certbot --nginx --non-interactive --agree-tos -d {target_domain}",
        timeout=120,
    )
    log_fn(f"{module_id}: SSL generated" if rc == 0 else f"{module_id}: SSL generation skipped: {err}")

# ── [SECTION: API Routes] ─────────────────────────────────────────────────────

@platform_bp.route("/api/platform/status")
def platform_status():
    state = load_state()
    result = {}
    for module_id in VALID_MODULES:
        saved = state.get(module_id, {})
        log_file = MODULES_DIR / module_id / "install.log"
        last_log = ""
        if log_file.exists():
            try:
                lines = [l.strip() for l in log_file.read_text().splitlines() if l.strip()]
                last_log = lines[-1] if lines else ""
            except: pass
        
        if not saved:
            result[module_id] = {"status": "not_installed", "running": False}
            continue

        if saved.get("status") == "installing" and docker_containers_running(module_id):
            if module_id != "cymisp" or saved.get("misp_ready", False):
                saved["status"] = "running"
                state[module_id] = saved
                save_state(state)

        live = docker_containers_running(module_id)
        saved["running"] = live
        saved["last_log"] = last_log
        result[module_id] = saved
    return jsonify(result)

@platform_bp.route("/api/platform/install", methods=["POST"])
def platform_install():
    data = request.get_json() or {}
    module_id = data.get("module", "").strip()
    if module_id not in VALID_MODULES:
        return jsonify({"error": f"Unknown module: {module_id}"}), 400

    state = load_state()
    state[module_id] = {"status": "installing", "started_at": time.strftime('%Y-%m-%dT%H:%M:%SZ')}
    save_state(state)

    compose_yaml = COMPOSE_TEMPLATES.get(module_id) or data.get("compose_yaml") or ""
    env_vars = {k: v for k, v in (data.get("config") or {}).items() if v and not k.startswith("_")}

    threading.Thread(target=_install_module_async, args=(module_id, compose_yaml, env_vars), daemon=True).start()
    return jsonify({"status": "installing", "module": module_id})

@platform_bp.route("/api/platform/uninstall", methods=["POST"])
def platform_uninstall():
    data = request.get_json() or {}
    module_id = data.get("module", "").strip()
    if module_id not in VALID_MODULES: return jsonify({"error": "Unknown module"}), 400

    module_dir = MODULES_DIR / module_id
    if module_dir.exists():
        run("docker compose down -v", cwd=str(module_dir), timeout=60)
        base_domain = os.environ.get("BASE_DOMAIN", "cycentra.com")
        if module_id in ("cyiris", "cymisp"): _nginx_remove_block(module_id, base_domain)
        elif module_id == "cysoar": _nginx_remove_cysoar()
        shutil.rmtree(str(module_dir))

    state = load_state()
    state.pop(module_id, None)
    save_state(state)
    return jsonify({"status": "uninstalled", "module": module_id})

# ── [SECTION: Async Install Worker] ───────────────────────────────────────────
# Purpose: The engine that handles image pulling, DB patching, and SSL alignment.

def _fail(module_id: str, error: str):
    state = load_state()
    state[module_id] = {"status": "failed", "error": error}
    save_state(state)

def _install_module_async(module_id: str, compose_yaml: str, env_vars: dict):
    module_dir = MODULES_DIR / module_id
    module_dir.mkdir(parents=True, exist_ok=True)
    log_file = module_dir / "install.log"
    def log(msg):
        with open(log_file, "a") as f: f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

    try:
        log(f"Starting installation of {module_id}")
        base_domain = os.environ.get("BASE_DOMAIN", "cycentra.com")
        cyiris_env = {}

        compose_path = module_dir / "docker-compose.yml"
        compose_path.write_text(compose_yaml)
        env_path = module_dir / ".env"

        # ── CyIRIS Logic ──
        if module_id == "cyiris":
            _iris_adm_password = env_vars.get("IRIS_ADM_PASSWORD") or os.environ.get("IRIS_ADM_PASSWORD")
            if not _iris_adm_password: raise ValueError("IRIS_ADM_PASSWORD required")

            cyiris_env = {
                "POSTGRES_PASSWORD": os.environ.get("POSTGRES_PASSWORD") or os.environ.get("IRIS_DB_PASS", ""),
                "IRIS_SECRET_KEY":   os.environ.get("IRIS_SECRET_KEY") or os.environ.get("IRIS_SECRET", ""),
                "IRIS_ADM_EMAIL":    os.environ.get("IRIS_ADM_EMAIL", "admin@cycentra.com"),
                "IRIS_ADM_PASSWORD": _iris_adm_password,
            }
            cyiris_env.update(env_vars)
            env_path.write_text("\n".join(f"{k}={v}" for k, v in cyiris_env.items()))
            
            init_dir = module_dir / "db-init"
            init_dir.mkdir(parents=True, exist_ok=True)
            (init_dir / "01-pgcrypto.sql").write_text("CREATE EXTENSION IF NOT EXISTS pgcrypto;\n")
            compose_text = compose_path.read_text().replace("- cyiris_db_init:/docker-entrypoint-initdb.d", f"- {init_dir}:/docker-entrypoint-initdb.d")
            compose_path.write_text(compose_text)

        # ── CySOAR Logic ──
        elif module_id == "cysoar":
            run("docker compose down -v", cwd=str(module_dir))
            cysoar_env = {"BASE_DOMAIN": base_domain}
            cysoar_env.update(env_vars)
            env_path.write_text("\n".join(f"{k}={v}" for k, v in cysoar_env.items()))

        else:
            env_path.write_text("\n".join(f"{k}={v}" for k, v in env_vars.items()))

        # ── Docker Pull & Up ──
        run("docker compose pull", cwd=str(module_dir), timeout=600)
        run("docker compose up -d", cwd=str(module_dir), timeout=120)

        # ── Post-Install: SSL & Nginx (ALIGNED WITH SETUP.SH) ──
        _generate_module_ssl(module_id, base_domain, log)
        if module_id in ("cyiris", "cymisp"): _nginx_add_block(module_id, base_domain, log)
        elif module_id == "cysoar": _nginx_inject_cysoar(base_domain, log)

        # ── CyMISP Post-Install Logic ──
        if module_id == "cymisp":
            misp_live = False
            for i in range(40):
                time.sleep(15)
                rc, out, _ = run("docker logs cymisp 2>&1 | grep 'MISP is now live'", timeout=10)
                if out: misp_live = True; break
            
            if misp_live:
                redis_pass = env_vars.get("REDIS_PASSWORD", "redispassword")
                run(f"docker exec cymisp sed -i \"s|'redis_password' => '.*'|'redis_password' => '{redis_pass}'|g\" /var/www/MISP/app/Config/config.php")
                state = load_state(); state[module_id]["misp_ready"] = True; save_state(state)

        # ── CyIRIS DB Force ──
        if module_id == "cyiris":
            time.sleep(30)
            admin_email = cyiris_env.get("IRIS_ADM_EMAIL")
            admin_password = cyiris_env.get("IRIS_ADM_PASSWORD")
            safe_pw = admin_password.replace("'", "\\'")
            rc_h, hash_out, _ = run(f'docker exec cyiris-cyiris-1 python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash(\\"{safe_pw}\\", method=\\"pbkdf2:sha256\\"))"')
            if rc_h == 0 and hash_out.strip():
                run(f'docker exec cyiris-cyiris-db-1 psql -U iris -d iris_db -c "UPDATE \\"User\\" SET password=\'{hash_out.strip()}\', email=\'{admin_email}\' WHERE login=\'administrator\';"')

        state = load_state()
        state[module_id]["status"] = "running"
        save_state(state)
        log("Installation complete")

    except Exception as e:
        log(f"ERROR: {e}")
        _fail(module_id, str(e))

# ── [SECTION: Logs & Debug] ───────────────────────────────────────────────────

@platform_bp.route("/api/platform/logs/<module_id>")
def platform_logs(module_id):
    log_file = MODULES_DIR / module_id / "install.log"
    if not log_file.exists(): return jsonify({"lines": []})
    return jsonify({"lines": log_file.read_text().splitlines()[-100:]})

@platform_bp.route("/api/debug/images")
def debug_images():
    return jsonify({"CYSOAR": CYSOAR_IMAGE, "CYIRIS_APP": CYIRIS_IMAGE_APP})