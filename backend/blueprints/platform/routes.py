import os
import re
import shutil
import threading
import time
from pathlib import Path
from flask import Blueprint, request, jsonify

from core.config import MODULES_DIR
from core.helpers import run
from blueprints.platform.compose import (
    COMPOSE_TEMPLATES, VALID_MODULES,
    _CYSOAR_IMAGE, _CYIRIS_IMAGE_APP, _CYIRIS_IMAGE_DB
)
from blueprints.platform.state import load_state, save_state
from blueprints.platform.docker_utils import docker_containers_running

platform_bp = Blueprint("platform", __name__)
NGINX_CONF = Path("/etc/nginx/sites-available/cycentra-modules")

# ── SSL PATH RESOLVER ────────────────────────────────────────────────────────
def _get_ssl_paths(module_id: str, base_domain: str):
    # Aligns with setup.sh: CySOAR shared, others dedicated
    folder = f"cy360.{base_domain}" if module_id == "cysoar" else f"{module_id}.{base_domain}"
    return {
        "cert": f"/etc/letsencrypt/live/{folder}/fullchain.pem",
        "key":  f"/etc/letsencrypt/live/{folder}/privkey.pem"
    }

# ── NGINX BLOCK GENERATOR (FOR IRIS/MISP) ────────────────────────────────────
def _nginx_block_for(module_id: str, base_domain: str) -> str:
    paths = _get_ssl_paths(module_id, base_domain)
    ssl_cert, ssl_key = paths["cert"], paths["key"]
    
    configs = {
        "cyiris": {
            "subdomain": f"cyiris.{base_domain}",
            "upstream":  "http://127.0.0.1:4433",
            "extra": (
                "        proxy_http_version 1.1;\n"
                "        proxy_set_header X-Real-IP $remote_addr;\n"
                "        proxy_set_header X-Forwarded-Proto https;\n"
                "        proxy_read_timeout 300;\n"
                "        proxy_buffer_size 128k;\n"
                "        proxy_buffers 4 256k;\n"
                "        proxy_cookie_flags ~ samesite=none secure;\n"
                f'        add_header Content-Security-Policy "frame-ancestors \'self\' https://cy360.{base_domain}" always;\n'
                f'        add_header Access-Control-Allow-Origin "https://cy360.{base_domain}" always;\n'
                '        add_header Access-Control-Allow-Credentials "true" always;\n'
            ),
        },
        "cymisp": {
            "subdomain": f"cymisp.{base_domain}",
            "upstream":  "https://127.0.0.1:8243",
            "extra": (
                "        proxy_ssl_verify off;\n"
                "        proxy_set_header X-Forwarded-Proto https;\n"
                "        proxy_set_header X-Forwarded-Port 443;\n"
                "        proxy_read_timeout 300s;\n"
                '        add_header Content-Security-Policy "default-src \'self\' \'unsafe-inline\' \'unsafe-eval\' data: blob:;" always;\n'
            ),
        },
    }

    cfg = configs.get(module_id)
    if not cfg: return ""

    return (
        f"\nserver {{ listen 80; server_name {cfg['subdomain']}; return 301 https://$host$request_uri; }}\n"
        f"server {{\n"
        f"    listen 443 ssl http2; server_name {cfg['subdomain']};\n"
        f"    ssl_certificate {ssl_cert}; ssl_certificate_key {ssl_key};\n"
        f"    include /etc/letsencrypt/options-ssl-nginx.conf; ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;\n"
        f"    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        f"    add_header X-Content-Type-Options \"nosniff\" always;\n"
        f"    location / {{\n"
        f"        proxy_pass {cfg['upstream']};\n"
        f"        proxy_set_header Host $host;\n"
        f"{cfg['extra']}"
        f"    }}\n"
        f"}}\n"
    )

# ── CYSOAR INJECTION & REMOVAL ───────────────────────────────────────────────
def _nginx_inject_cysoar(base_domain: str, log_fn):
    if not NGINX_CONF.exists(): return
    text = NGINX_CONF.read_text()
    if "location /cysoar/" in text: return

    cysoar_block = (
        "\n    location /cysoar/ {\n"
        "        proxy_pass http://127.0.0.1:1880/;\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Upgrade $http_upgrade;\n"
        "        proxy_set_header Connection $connection_upgrade;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_read_timeout 120s;\n"
        "        proxy_buffering off;\n"
        "    }\n"
    )
    # Inject before the final closing brace of the main portal block
    new_text = re.sub(r'(server\s*\{[^}]*server_name\s+cy360\.[^;]+;[^}]*)(\n\s*\})', r'\1' + cysoar_block + r'\2', text)
    NGINX_CONF.write_text(new_text)
    run("nginx -t && systemctl reload nginx", timeout=15)

def _nginx_remove_cysoar():
    if not NGINX_CONF.exists(): return
    text = NGINX_CONF.read_text()
    new_text = re.sub(r'[ \t]*location /cysoar/ \{[^{}]+\}\n', '', text, flags=re.DOTALL)
    NGINX_CONF.write_text(new_text)
    run("nginx -t && systemctl reload nginx", timeout=15)

# ── ASYNC INSTALL WORKER (The Core Engine) ───────────────────────────────────
def _install_module_async(module_id: str, env_vars: dict):
    module_dir = MODULES_DIR / module_id
    module_dir.mkdir(parents=True, exist_ok=True)
    log_file = module_dir / "install.log"
    def log(m): 
        with open(log_file, "a") as f: f.write(f"[{time.strftime('%H:%M:%S')}] {m}\n")

    try:
        base_domain = os.environ.get("BASE_DOMAIN", "cycentra.com")
        
        # 1. Prepare Docker Compose & Env
        compose_yaml = COMPOSE_TEMPLATES.get(module_id)
        if module_id == "cyiris":
            # Add db-init for pgcrypto (Required for Iris passwords)
            init_dir = module_dir / "db-init"
            init_dir.mkdir(parents=True, exist_ok=True)
            (init_dir / "01-pgcrypto.sql").write_text("CREATE EXTENSION IF NOT EXISTS pgcrypto;\n")
            compose_yaml = compose_yaml.replace("- cyiris_db_init:/docker-entrypoint-initdb.d", f"- {init_dir}:/docker-entrypoint-initdb.d")
        
        (module_dir / "docker-compose.yml").write_text(compose_yaml)
        (module_dir / ".env").write_text("\n".join(f"{k}={v}" for k, v in env_vars.items()))

        log(f"Deploying {module_id}...")
        run("docker compose pull", cwd=str(module_dir), timeout=300)
        run("docker compose up -d", cwd=str(module_dir), timeout=180)

        # 2. SSL & Nginx Routing
        if module_id != "cysoar":
            log(f"SSL: Generating cert for {module_id}.{base_domain}")
            run(f"certbot --nginx --non-interactive --agree-tos -d {module_id}.{base_domain}", timeout=120)

        if module_id in ("cyiris", "cymisp"):
            _nginx_add_block(module_id, base_domain, log)
        elif module_id == "cysoar":
            _nginx_inject_cysoar(base_domain, log)

        # 3. CyIRIS Password Force (Matches working snippet)
        if module_id == "cyiris":
            log("CyIRIS: Waiting for app health check...")
            app_cont = "cyiris-cyiris-1"
            db_cont = "cyiris-cyiris-db-1"
            for _ in range(20):
                time.sleep(10)
                rc, code, _ = run(f"docker exec {app_cont} curl -s -o /dev/null -w '%{{http_code}}' http://localhost:8000/", timeout=10)
                if rc == 0 and code.strip() in ("200", "302", "401"):
                    # Force password hash in DB
                    admin_pw = env_vars.get("IRIS_ADM_PASSWORD", "admin")
                    admin_email = env_vars.get("IRIS_ADM_EMAIL", "admin@admin.com")
                    rc_h, hash_out, _ = run(f'docker exec {app_cont} python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash(\'{admin_pw}\', method=\'pbkdf2:sha256\'))"')
                    if rc_h == 0:
                        run(f"docker exec {db_cont} psql -U iris -d iris_db -c \"UPDATE \\\"User\\\" SET password='{hash_out.strip()}', email='{admin_email}' WHERE login='administrator';\"")
                        log("CyIRIS: Admin credentials forced.")
                    break

        # 4. CyMISP Patching (Matches working snippet)
        if module_id == "cymisp":
            log("CyMISP: Waiting for boot (10m)...")
            for _ in range(48):
                time.sleep(15)
                _, logs, _ = run("docker logs cymisp 2>&1 | grep 'MISP is now live'", timeout=10)
                if logs.strip():
                    misp_url = f"https://cymisp.{base_domain}"
                    # BaseURL Patch
                    run(f"docker exec cymisp sed -i \"s|'baseurl' => '.*'|'baseurl' => '{misp_url}'|g\" /var/www/MISP/app/Config/config.php")
                    # Redis Patch
                    r_pass = env_vars.get("REDIS_PASSWORD", "redispassword")
                    run(f"docker exec cymisp sed -i \"s|'redis_password' => '.*'|'redis_password' => '{r_pass}'|g\" /var/www/MISP/app/Config/config.php")
                    # DB User Patch
                    m_pass = env_vars.get("MISP_MYSQL_PASSWORD", "misp_db_pass")
                    m_email = env_vars.get("MISP_ADMIN_EMAIL", "admin@admin.test")
                    m_admin_pw = env_vars.get("MISP_ADMIN_PASSPHRASE", "admin")
                    rc_ph, m_hash, _ = run(f"docker exec cymisp php -r \"echo password_hash('{m_admin_pw}', PASSWORD_BCRYPT);\"", timeout=10)
                    if rc_ph == 0:
                        pw_esc = m_hash.strip().replace("$", "\\$")
                        run(f"docker exec cymisp php -r \"\\$conn = new PDO('mysql:host=cymisp-db;dbname=misp', 'misp', '{m_pass}'); \\$stmt = \\$conn->prepare('UPDATE users SET email=?, password=?, change_pw=0 WHERE id=1'); \\$stmt->execute(['{m_email}', '{pw_esc}']);\"")
                    log("CyMISP: All patches applied.")
                    break

        state = load_state()
        state[module_id]["status"] = "running"
        save_state(state)
        log("Installation completed successfully.")

    except Exception as e:
        log(f"FATAL ERROR: {str(e)}")
        state = load_state(); state[module_id]["status"] = "failed"; save_state(state)

# ── API ENDPOINTS (STATUS, INSTALL, UNINSTALL) ───────────────────────────────
@platform_bp.route("/api/platform/status")
def platform_status():
    state = load_state()
    result = {}
    for mid in VALID_MODULES:
        saved = state.get(mid, {"status": "not_installed"})
        saved["running"] = docker_containers_running(mid)
        result[mid] = saved
    return jsonify(result)

@platform_bp.route("/api/platform/install", methods=["POST"])
def platform_install():
    data = request.json
    mid = data.get("module")
    state = load_state()
    state[mid] = {"status": "installing", "started_at": time.strftime('%Y-%m-%dT%H:%M:%SZ')}
    save_state(state)
    threading.Thread(target=_install_module_async, args=(mid, data.get("config", {})), daemon=True).start()
    return jsonify({"status": "installing"})

@platform_bp.route("/api/platform/uninstall", methods=["POST"])
def platform_uninstall():
    mid = request.json.get("module")
    module_dir = MODULES_DIR / mid
    if module_dir.exists():
        run("docker compose down -v", cwd=str(module_dir))
        if mid == "cysoar": _nginx_remove_cysoar()
        else: _nginx_remove_block(mid, os.environ.get("BASE_DOMAIN", "cycentra.com"))
        shutil.rmtree(str(module_dir))
    state = load_state(); state.pop(mid, None); save_state(state)
    return jsonify({"status": "uninstalled"})

def _nginx_add_block(mid, domain, log_fn):
    sub = f"{mid}.{domain}"
    existing = NGINX_CONF.read_text()
    if sub not in existing:
        NGINX_CONF.write_text(existing + _nginx_block_for(mid, domain))
        run("nginx -t && systemctl reload nginx")

def _nginx_remove_block(mid, domain):
    sub = f"{mid}.{domain}"
    txt = NGINX_CONF.read_text()
    new_txt = re.sub(r'\nserver\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*server_name\s+'+re.escape(sub)+r'[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', '', txt, flags=re.DOTALL)
    NGINX_CONF.write_text(new_txt)
    run("nginx -t && systemctl reload nginx")