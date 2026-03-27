"""
CyCentra 360 — Flask Backend  v4.2
====================================
Responsibilities:
  1. Google / Microsoft OAuth login for the portal
  2. OIDC Identity Provider for CyIRIS and CySOAR
  3. RBAC — per-user role stored in RBAC_FILE, enforced at token issuance
  4. Auth event logging → /var/log/cycentra/auth.log (Wazuh agent tails this)
  5. Platform module install / uninstall / status API
  6. ASM scan trigger / status / results API
  7. AI provider connection test API
  8. Health check endpoint
  9. CySIEM Correlation Engine proxy  ← NEW in v4.2

OIDC endpoints (all under /oidc/):
  GET  /oidc/.well-known/openid-configuration
  GET  /oidc/jwks
  GET  /oidc/authorize
  POST /oidc/token
  GET  /oidc/userinfo
  POST /oidc/introspect

CySIEM proxy endpoints (all under /api/siem/):
  GET  /api/siem/health
  GET  /api/siem/stats
  GET  /api/siem/incidents
  GET  /api/siem/incidents/<id>
  PATCH /api/siem/incidents/<id>
  GET  /api/siem/risk-scores
  GET  /api/siem/ueba/users
  GET  /api/siem/ueba/<username>
  GET  /api/siem/alerts
  POST /api/siem/alerts/ingest     (admin only)
  GET  /api/siem/config
  GET  /api/siem/engine/status
  POST /api/siem/engine/restart    (admin only)

RBAC roles:
  admin     — full access to all modules + admin API
  analyst   — cy360, cysiem, cyiris, cysoar, cyasm
  viewer    — cy360, cysiem read-only
  cyiris    — cy360, cyiris only
  cysoar    — cy360, cysoar only

RBAC file:   /opt/cycentra/rbac.json
Auth log:    /var/log/cycentra/auth.log
"""

from flask import Flask, request, redirect, jsonify, render_template_string, flash, url_for, session
import subprocess, re, os, json, glob, time, shutil, threading, uuid, hashlib, hmac as _hmac
import requests as http_requests
from functools import wraps
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Try production path first, then local development
    if os.path.exists("/opt/cycentra/.env"):
        load_dotenv("/opt/cycentra/.env")
    elif os.path.exists(".env"):
        load_dotenv(".env")
except ImportError:
    pass  # dotenv not installed, will use system environment only

try:
    from tenant_manager import validate_tenant
except ImportError:
    def validate_tenant(x): return x

try:
    import jwt as pyjwt
    _JWT_AVAILABLE = True
except ImportError:
    _JWT_AVAILABLE = False

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change_this_to_something_secure_32ch")

app.config.update(
    SESSION_COOKIE_SECURE   = True,
    SESSION_COOKIE_SAMESITE = "None",
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_DOMAIN   = "." + os.environ.get("BASE_DOMAIN", "cycentra.com"),
    PERMANENT_SESSION_LIFETIME = timedelta(days=1),
)

# ── Config ─────────────────────────────────────────────────────────────────────
GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
MS_CLIENT_ID         = os.environ.get("MICROSOFT_CLIENT_ID", "")
MS_CLIENT_SECRET     = os.environ.get("MICROSOFT_CLIENT_SECRET", "")

BASE_DOMAIN  = os.environ.get("BASE_DOMAIN", "cycentra.com")
FRONTEND_URL = os.environ.get("FRONTEND_URL", f"https://cy360.{BASE_DOMAIN}")
BASE_URL     = os.environ.get("BASE_URL",      f"https://cyscan.{BASE_DOMAIN}")


SCANS_DIR     = Path("/var/log/cycentra/cy-asm/scans")
ASM_LOGS      = Path("/var/log/cycentra/cy-asm/logs")
#ASM_DIR       = Path("/opt/cycentra/backend/cy-asm")
import site as _site
_SITE_PKG = Path(_site.getsitepackages()[0])
ASM_DIR       = _SITE_PKG / "cy_asm"

MODULES_DIR   = Path("/opt/cycentra/modules")
MODULES_STATE = Path("/opt/cycentra/modules_state.json")
RBAC_FILE     = Path("/opt/cycentra/rbac.json")
AUTH_LOG_FILE = Path("/var/log/cycentra/auth.log")

OIDC_CLIENTS = {
    "cyiris": {
        "client_secret":  os.environ.get("CYIRIS_OIDC_SECRET", ""),
        "redirect_uris":  [
            f"https://cy360.{BASE_DOMAIN}/cyiris/auth/oidc/callback",
            f"https://cyiris.{BASE_DOMAIN}/auth/oidc/callback"
        ],
        "allowed_scopes": ["openid", "email", "profile"],
        "allowed_roles":  ["admin", "analyst", "cyiris"],
    },
    "cysoar": {
        "client_secret":  os.environ.get("CYSOAR_OIDC_SECRET", ""),
        "redirect_uris":  [
            f"https://cy360.{BASE_DOMAIN}/cysoar/auth/callback",
            f"https://cy360.{BASE_DOMAIN}/node-red/auth/callback",
            f"https://cysoar.{BASE_DOMAIN}/auth/callback"
        ],
        "allowed_scopes": ["openid", "email", "profile"],
        "allowed_roles":  ["admin", "analyst", "cysoar"],
    },
}

JWT_SECRET = os.environ.get("JWT_SECRET", app.secret_key)
TOKEN_TTL  = 3600

# ── Image configuration ───────────────────────────────────────────────────────
# CySOAR  — always uses CyCentra custom image (ghcr.io/cycentra/cysoar)
# CyIRIS  — always uses standard upstream DFIR-IRIS images
CYSOAR_IMAGE        = os.environ.get("CYSOAR_IMAGE",     "ghcr.io/cycentra/cysoar:latest")
CYIRIS_IMAGE_APP    = os.environ.get("CYIRIS_IMAGE_APP", "ghcr.io/cycentra/cyiris:latest")
CYIRIS_IMAGE_DB     = os.environ.get("CYIRIS_IMAGE_DB",  "postgres:15-alpine")

# ── RBAC ───────────────────────────────────────────────────────────────────────

ROLE_APPS = {
    "admin":   ["cy360", "cysiem", "cyiris", "cysoar", "cyasm"],
    "analyst": ["cy360", "cysiem", "cyiris", "cysoar", "cyasm"],
    "viewer":  ["cy360", "cysiem"],
    "cyiris":  ["cy360", "cyiris"],
    "cysoar":  ["cy360", "cysoar"],
}
VALID_ROLES = set(ROLE_APPS.keys())


def _load_rbac() -> dict:
    try:
        if RBAC_FILE.exists():
            return json.loads(RBAC_FILE.read_text())
    except Exception:
        pass
    return {}


def _save_rbac(rbac: dict):
    RBAC_FILE.parent.mkdir(parents=True, exist_ok=True)
    RBAC_FILE.write_text(json.dumps(rbac, indent=2))


def get_user_role(email: str) -> str:
    return _load_rbac().get(email, {}).get("role", "viewer")


def get_user_apps(email: str) -> list:
    entry = _load_rbac().get(email, {})
    if "apps" in entry:
        return entry["apps"]
    return ROLE_APPS.get(entry.get("role", "viewer"), ["cy360"])


def user_can_access_client(email: str, client_id: str) -> bool:
    client = OIDC_CLIENTS.get(client_id)
    if not client:
        return False
    role = get_user_role(email)
    if role == "admin":
        return True
    if role in client["allowed_roles"]:
        return True
    if client_id in get_user_apps(email):
        return True
    return False


# ── Auth logging ───────────────────────────────────────────────────────────────

def _auth_event(event_type: str, email: str, client_id: str = "",
                result: str = "success", detail: str = "", ip: str = ""):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type":      event_type,
        "email":     email,
        "client_id": client_id,
        "result":    result,
        "role":      get_user_role(email) if email else "unknown",
        "ip":        ip or (request.remote_addr if request else ""),
        "detail":    detail,
    }
    try:
        AUTH_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AUTH_LOG_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass


# ── Utilities ──────────────────────────────────────────────────────────────────

def generate_tenant_id(domain):
    clean  = re.sub(r'^https?://', '', domain)
    clean  = re.sub(r'^www\.', '', clean)
    prefix = re.sub(r'[^a-z0-9]', '', clean.lower())[:8]
    return f"{prefix}-ten-01"


def run(cmd, cwd=None, timeout=300):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           cwd=cwd, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)


def load_state():
    try:
        if MODULES_STATE.exists():
            return json.loads(MODULES_STATE.read_text())
    except Exception:
        pass
    return {}


def save_state(state):
    try:
        MODULES_STATE.write_text(json.dumps(state, indent=2))
    except Exception as e:
        app.logger.error(f"State save error: {e}")


# ── Docker Compose templates ───────────────────────────────────────────────────

COMPOSE_TEMPLATES = {
    "cyiris": f"""
services:
  cyiris-db:
    image: {CYIRIS_IMAGE_DB}
    restart: always
    environment:
      POSTGRES_PASSWORD: "${{POSTGRES_PASSWORD:-iris_pg_pass}}"
      POSTGRES_USER: iris
      POSTGRES_DB: iris_db
    volumes:
      - cyiris_db_data:/var/lib/postgresql/data
      - cyiris_db_init:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U iris -d iris_db"]
      interval: 5s
      timeout: 5s
      retries: 10
      start_period: 10s

  cyiris:
    image: {CYIRIS_IMAGE_APP}
    restart: always
    command: ["app"]
    depends_on:
      cyiris-db:
        condition: service_healthy
    ports:
      - "4433:8000"
    environment:
      POSTGRES_SERVER: cyiris-db
      POSTGRES_PORT: "5432"
      POSTGRES_USER: iris
      POSTGRES_DB: iris_db
      POSTGRES_PASSWORD: "${{POSTGRES_PASSWORD:-iris_pg_pass}}"
      POSTGRES_ADMIN_USER: iris
      POSTGRES_ADMIN_PASSWORD: "${{POSTGRES_PASSWORD:-iris_pg_pass}}"
      IRIS_SECRET_KEY: "${{IRIS_SECRET_KEY:-change_in_production}}"
      IRIS_ADM_EMAIL: "${{IRIS_ADM_EMAIL:-admin@cycentra.com}}"
      IRIS_ADM_PASSWORD: "${{IRIS_ADM_PASSWORD}}"
      OIDC_ENABLED: "true"
      OIDC_ISSUER: "${{CYCENTRA_PORTAL_URL}}/oidc"
      OIDC_CLIENT_ID: "cyiris"
      OIDC_CLIENT_SECRET: "${{CYIRIS_OIDC_SECRET}}"
      OIDC_REDIRECT_URI: "${{CYCENTRA_PORTAL_URL}}/cyiris/auth/oidc/callback"
    volumes:
      - cyiris_app_data:/home/iris/iriswebapp/app/static/assets/files
      - cyiris_user_data:/home/iris/iriswebapp/user_data

volumes:
  cyiris_db_data:
  cyiris_db_init:
  cyiris_app_data:
  cyiris_user_data:
""",

    "cysoar": f"""
services:
  cysoar:
    image: {CYSOAR_IMAGE}
    container_name: cysoar
    restart: unless-stopped
    ports:
      - "1880:1880"
    environment:
      - NODE_RED_ENABLE_PROJECTS=true
      - CYCENTRA_PORTAL_URL=${{CYCENTRA_PORTAL_URL}}
      - OIDC_ISSUER=${{CYCENTRA_PORTAL_URL}}/oidc
      - OIDC_CLIENT_ID=cysoar
      - OIDC_CLIENT_SECRET=${{CYSOAR_OIDC_SECRET}}
      - SESSION_SECRET=${{CYSOAR_SESSION_SECRET}}
      - SMTP_HOST=${{SMTP_HOST:-}}
      - SMTP_PORT=${{SMTP_PORT:-587}}
      - SMTP_USER=${{SMTP_USER:-}}
      - SMTP_PASS=${{SMTP_PASS:-}}
      - SUPPORT_EMAIL=${{SUPPORT_EMAIL:-support@cycentra.com}}
    volumes:
      - cysoar_data:/data

volumes:
  cysoar_data:
""",
"cymisp": f"""
services:
  cymisp-db:
    image: mysql:8.0
    container_name: cymisp-db
    restart: unless-stopped
    environment:
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: ${{MISP_MYSQL_PASSWORD:-misp_db_pass}}
      MYSQL_ROOT_PASSWORD: ${{MISP_MYSQL_ROOT_PASSWORD:-misp_root_pass}}
    volumes:
      - cymisp_db_data:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s

  cymisp:
    image: ghcr.io/misp/misp-docker/misp-core:latest
    container_name: cymisp
    restart: unless-stopped
    ports:
      - "127.0.0.1:8200:80"
      - "127.0.0.1:8243:443"
    environment:
      - MISP_BASEURL=https://cymisp.{BASE_DOMAIN}
      - MISP_ADMIN_EMAIL=${{MISP_ADMIN_EMAIL:-admin@cycentra.local}}
      - MISP_ADMIN_PASSPHRASE=${{MISP_ADMIN_PASSPHRASE:-MISPadmin1234!}}
      - MYSQL_HOST=cymisp-db
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=${{MISP_MYSQL_PASSWORD:-misp_db_pass}}
      - REDIS_HOST=cymisp-redis
      - REDIS_PORT=6379
      - REDIS_PASSWORD=${{REDIS_PASSWORD}}  
      - PHP_SESSIONS_IN_REDIS=true
    depends_on:
      cymisp-db:
        condition: service_healthy
      cymisp-redis:
        condition: service_started

  cymisp-redis:
    image: redis:7-alpine
    container_name: cymisp-redis
    restart: unless-stopped
    command: redis-server --requirepass ${{REDIS_PASSWORD}}

volumes:
  cymisp_db_data:
""",
}

VALID_MODULES = set(COMPOSE_TEMPLATES.keys())


# ── Docker helpers ─────────────────────────────────────────────────────────────

def _docker_containers_running(module_id):
    module_dir = MODULES_DIR / module_id
    if not module_dir.exists():
        return False
    rc, out, _ = run("docker compose ps --format json", cwd=str(module_dir))
    if rc != 0 or not out:
        return False
    try:
        for line in [l for l in out.splitlines() if l.strip().startswith("{")]:
            obj = json.loads(line)
            if obj.get("State") == "running" or "Up" in obj.get("Status", ""):
                return True
    except Exception:
        rc2, out2, _ = run("docker compose ps", cwd=str(module_dir))
        return "Up" in out2
    return False


def _install_module_async(module_id, compose_yaml, env_vars):
    module_dir = MODULES_DIR / module_id
    module_dir.mkdir(parents=True, exist_ok=True)
    log_file   = module_dir / "install.log"

    def log(msg):
        with open(log_file, "a") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        app.logger.info(f"[{module_id}] {msg}")

    try:
        log(f"Starting installation of {module_id}")

        # Reload .env to pick up any changes made after Flask started
        try:
            from dotenv import load_dotenv
            if os.path.exists("/opt/cycentra/.env"):
                load_dotenv("/opt/cycentra/.env", override=True)
            elif os.path.exists(".env"):
                load_dotenv(".env", override=True)
        except ImportError:
            pass

        # Images are hardcoded in COMPOSE_TEMPLATES — no toggle needed
        # CySOAR=ghcr.io/cycentra/cysoar:latest  CyIRIS=ghcr.io/dfir-iris/iriswebapp_app:latest
        compose_path = module_dir / "docker-compose.yml"
        compose_path.write_text(compose_yaml)
        log(f"Written docker-compose.yml")

        env_path = module_dir / ".env"
        if module_id == "cyiris":
            # Build a complete .env for cyiris — the compose template needs these
            # exact var names. cycentra-setup.sh may use legacy names (IRIS_SECRET,
            # IRIS_DB_PASS) so we resolve both old and new names with fallbacks.
            _iris_adm_password = os.environ.get("IRIS_ADM_PASSWORD")
            if not _iris_adm_password:
                log("ERROR: IRIS_ADM_PASSWORD not set in /opt/cycentra/env — aborting install")
                raise ValueError("IRIS_ADM_PASSWORD is required in master .env")

            cyiris_env = {
                "POSTGRES_PASSWORD":   os.environ.get("POSTGRES_PASSWORD") or os.environ.get("IRIS_DB_PASS", ""),
                "IRIS_SECRET_KEY":     os.environ.get("IRIS_SECRET_KEY") or os.environ.get("IRIS_SECRET", ""),
                "CYIRIS_OIDC_SECRET":  os.environ.get("CYIRIS_OIDC_SECRET", ""),
                "CYCENTRA_PORTAL_URL": os.environ.get("CYCENTRA_PORTAL_URL") or os.environ.get("FRONTEND_URL", ""),
                "IRIS_ADM_EMAIL":      os.environ.get("IRIS_ADM_EMAIL", "admin@cycentra.com"),
                "IRIS_ADM_PASSWORD":   _iris_adm_password,   # ← from master .env only
            }
            cyiris_env.update(env_vars)   # UI-passed overrides win — NOW this works because keys match
            env_path.write_text("\n".join(f"{k}={v}" for k, v in cyiris_env.items()))
            log(f"Created cyiris .env with {len(cyiris_env)} variables")
        else:
            env_path.write_text("\n".join(f"{k}={v}" for k, v in env_vars.items()))
            log(f"Created .env with {len(env_vars)} variables")

        # CySOAR: clean old volumes that may have stale httpStatic config
        if module_id == "cysoar":
            log("CySOAR pre-install cleanup — removing stale containers and volumes")
            run("docker compose down -v", cwd=str(module_dir), timeout=60)
            rc, containers_out, _ = run("docker ps -aq --filter 'name=cysoar'", timeout=10)
            if rc == 0 and containers_out.strip():
                old = [c.strip() for c in containers_out.strip().split('\n') if c.strip()]
                if old:
                    run(f"docker rm -f {' '.join(old)}", timeout=30)
                    log(f"Removed {len(old)} old containers")
            rc, vols_out, _ = run("docker volume ls -q --filter 'name=cysoar'", timeout=10)
            if rc == 0 and vols_out.strip():
                old_vols = [v.strip() for v in vols_out.strip().split('\n') if v.strip()]
                for vol in old_vols:
                    rc2, _, _ = run(f"docker volume rm {vol}", timeout=10)
                    log(f"Removed volume {vol}" if rc2 == 0 else f"Could not remove {vol}")
            log("CySOAR pre-install cleanup complete")

        if module_id == "cyiris":
            init_dir = module_dir / "db-init"
            init_dir.mkdir(parents=True, exist_ok=True)
            (init_dir / "01-pgcrypto.sql").write_text(
                "CREATE EXTENSION IF NOT EXISTS pgcrypto;\n")
            compose_text = compose_path.read_text().replace(
                "- cyiris_db_init:/docker-entrypoint-initdb.d",
                f"- {init_dir}:/docker-entrypoint-initdb.d"
            )
            compose_path.write_text(compose_text)
            log("pgcrypto init script written")

        log("Pulling Docker images...")
        rc, out, err = run("docker compose pull", cwd=str(module_dir), timeout=600)
        if rc != 0:
            log(f"ERROR pulling images: {err}")
            state = load_state()
            state[module_id] = {"status": "failed", "error": err,
                                 "installed_at": time.strftime('%Y-%m-%dT%H:%M:%SZ')}
            save_state(state)
            return

        log("Starting containers...")
        rc, out, err = run("docker compose up -d", cwd=str(module_dir), timeout=120)
        if rc != 0:
            log(f"ERROR starting containers: {err}")
            state = load_state()
            state[module_id] = {"status": "failed", "error": err,
                                 "installed_at": time.strftime('%Y-%m-%dT%H:%M:%SZ')}
            save_state(state)
            return


        # ── CyMISP post-install: patch baseurl + nginx + SSL ──────────────────
        if module_id == "cymisp":
            base_domain = os.environ.get("BASE_DOMAIN", "cycentra.com")
            misp_url    = "https://cymisp." + base_domain
            log("CyMISP: waiting for MISP to initialise (8-12 min)...")

            misp_live = False
            for attempt in range(48):
                time.sleep(15)
                rc2, logs_out, _ = run("docker logs cymisp 2>&1 | grep 'MISP is now live'", timeout=10)
                if logs_out.strip():
                    log("CyMISP: MISP is live — patching baseurl config...")
                    misp_live = True
                    break
                log("CyMISP: waiting... (" + str(attempt+1) + "/48)")

            if misp_live:
                sed_expr = (
                    "s|'baseurl' => '.*'|'baseurl' => '" + misp_url + "'|g;"
                    " s|'external_baseurl' => '.*'|'external_baseurl' => '" + misp_url + "'|g;"
                    " s|'rest_client_baseurl' => '.*'|'rest_client_baseurl' => '" + misp_url + "'|g"
                )
                patch_cmd = "docker exec cymisp sed -i \"" + sed_expr + "\" /var/www/MISP/app/Config/config.php"
                rc2, _, err2 = run(patch_cmd, timeout=15)
                if rc2 == 0:
                    log("CyMISP: baseurl patched to " + misp_url)
                    # Save patched config to host as permanent volume mount
                    rc3, config_out, _ = run(
                        "docker exec cymisp cat /var/www/MISP/app/Config/config.php",
                        timeout=10
                    )
                    if rc3 == 0 and config_out:
                        (module_dir / "misp-config.php").write_text(config_out)
                        log("CyMISP: config.php saved to host — survives restarts")

                    redis_pass = env_vars.get("REDIS_PASSWORD", "redispassword")
                    run(
                        "docker exec cymisp sed -i "
                        "\"s|'redis_password' => '.*'|'redis_password' => '" + redis_pass + "'|g\" "
                        "/var/www/MISP/app/Config/config.php",
                        timeout=10
                    )
                    # Also patch PHP session save path
                    run(
                        "docker exec cymisp bash -c \"find /etc/php -name 'www.conf' "
                        "-exec sed -i 's|auth=redispassword|auth=" + redis_pass + "|g' {} \\;\"",
                        timeout=10
                    )
                    log("CyMISP: Redis password patched in config and PHP sessions")

                                        # ── Set admin credentials from form values ─────────────
                    # MISP always creates admin@admin.test on first boot regardless
                    # of env vars — we override via database after init
                    # Set credentials from form via direct database update
                    admin_email = env_vars.get("MISP_ADMIN_EMAIL", "admin@admin.test")
                    admin_pass  = env_vars.get("MISP_ADMIN_PASSPHRASE", "admin")
                    mysql_pass  = env_vars.get("MISP_MYSQL_PASSWORD", "misp_db_pass")

                    # Generate bcrypt hash of the password inside the container
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
                        log("CyMISP: WARNING — could not hash password, using defaults (admin@admin.test / admin)")
            else:
                log("CyMISP: WARNING — MISP did not come live within 12 minutes")

            nginx_block = (
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
            nginx_conf = Path("/etc/nginx/sites-available/cycentra-modules")
            if nginx_conf.exists():
                existing = nginx_conf.read_text()
                if ("cymisp." + base_domain) not in existing:
                    nginx_conf.write_text(existing + nginx_block)
                    rc2, _, _ = run("nginx -t && systemctl reload nginx", timeout=15)
                    log("CyMISP: nginx block added and reloaded" if rc2 == 0 else "CyMISP: WARNING — nginx reload failed")
                else:
                    log("CyMISP: nginx block already exists")

            cert_domains = (
                "cy360." + base_domain + ",cyscan." + base_domain + ","
                "cyiris." + base_domain + ",cysiem." + base_domain + ","
                "cymisp." + base_domain
            )
            rc2, _, _ = run(
                "certbot --nginx --expand --non-interactive --agree-tos --domains " + cert_domains + " 2>/dev/null || true",
                timeout=120,
            )
            log("CyMISP: SSL cert expanded" if rc2 == 0 else "CyMISP: SSL expansion skipped")
            state = load_state()
            state[module_id]["misp_ready"] = True
            save_state(state)
            log("CyMISP: fully ready — login at https://cymisp." + base_domain)

        # ── CyIRIS post-install: force admin credentials via DB ───────────────
        if module_id == "cyiris":
            log("CyIRIS: waiting for app to initialise (up to 90s)...")
            iris_ready = False
            # Container name format: <compose-project>-<service>-1
            # Compose project = directory name = "cyiris"
            app_container = "cyiris-cyiris-1"
            db_container  = "cyiris-cyiris-db-1"
            for attempt in range(18):
                time.sleep(5)
                rc_ping, _, _ = run(
                    f"docker exec {app_container} curl -sf http://localhost:8000/api/ping",
                    timeout=10
                )
                if rc_ping == 0:
                    iris_ready = True
                    log(f"CyIRIS: app is up (attempt {attempt+1})")
                    break
                log(f"CyIRIS: waiting for app... ({attempt+1}/18)")

            if iris_ready:
                admin_email    = cyiris_env.get("IRIS_ADM_EMAIL", "admin@cycentra.com")
                admin_password = cyiris_env.get("IRIS_ADM_PASSWORD")
                if not admin_password:
                    log("ERROR: IRIS_ADM_PASSWORD missing — cannot set admin credentials")
                    return
                
                # Generate password hash inside the app container (has werkzeug)
                safe_password = admin_password.replace("'", "\\'").replace('"', '\\"')
                rc_h, hash_out, hash_err = run(
                    f'docker exec {app_container} python3 -c "'
                    f'from werkzeug.security import generate_password_hash;'
                    f'print(generate_password_hash(\\"{safe_password}\\", method=\\"pbkdf2:sha256\\"))"',
                    timeout=15
                )
                if rc_h == 0 and hash_out.strip().startswith("pbkdf2:"):
                    pw_hash = hash_out.strip()
                    # Update both email and password for the administrator account
                    rc_db, _, db_err = run(
                        f'docker exec {db_container} psql -U iris -d iris_db -c '
                        f'"UPDATE \\"user\\" SET password=\'{pw_hash}\''
                        f'WHERE login=\'administrator\';"',
                        timeout=15
                    )
                    if rc_db == 0:
                        log(f"CyIRIS: password forced via DB — username: administrator")
                    else:
                        log(f"CyIRIS: ERROR — DB update failed. SQL error: {db_err}")
                        log(f"CyIRIS: FALLBACK — use password from logs: docker compose logs cyiris | grep 'admin'")
                else:
                    log(f"CyIRIS: WARNING — could not generate password hash: {hash_err}")
                    log(f"CyIRIS: use the password from container logs: docker compose logs cyiris | grep 'password >>>'")
            else:
                log("CyIRIS: WARNING — app did not respond in 90s, credentials not set")
                log("CyIRIS: use the password from container logs: docker compose logs cyiris | grep 'password >>>'")

        time.sleep(5)
        running = _docker_containers_running(module_id)
        state = load_state()
        state[module_id] = {
            "status":       "running" if running else "degraded",
            "installed_at": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "compose_dir":  str(module_dir),
        }
        save_state(state)
        log(f"Done — status: {state[module_id]['status']}")
    except Exception as e:
        log(f"EXCEPTION: {e}")
        state = load_state()
        state[module_id] = {"status": "failed", "error": str(e),
                             "installed_at": time.strftime('%Y-%m-%dT%H:%M:%SZ')}
        save_state(state)


# ── CORS ───────────────────────────────────────────────────────────────────────

CORS_ALLOWED_ORIGINS = {
    FRONTEND_URL, BASE_URL,
    f"https://cy360.{BASE_DOMAIN}",
    f"https://cyscan.{BASE_DOMAIN}",
    f"https://cyiris.{BASE_DOMAIN}",
    f"https://cysoar.{BASE_DOMAIN}",
    f"https://cysiem.{BASE_DOMAIN}",
    f"https://cymisp.{BASE_DOMAIN}",
}

def _cors_headers(response):
    origin = request.headers.get('Origin', '')
    if origin in CORS_ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Headers'] = \
        'Content-Type, Authorization, X-CyCentra-AdminKey'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, DELETE, OPTIONS'
    return response

@app.after_request
def add_cors(response):
    return _cors_headers(response)

@app.route('/api/<path:subpath>', methods=['OPTIONS'])
@app.route('/auth/<path:subpath>', methods=['OPTIONS'])
@app.route('/oidc/<path:subpath>', methods=['OPTIONS'])
def handle_options(subpath):
    from flask import make_response
    return _cors_headers(make_response('', 204))


# ── Health ─────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({
        "status":  "ok",
        "version": "4.2",
        "service": "cycentra360-backend",
    })

@app.route("/api/debug/images")
def debug_images():
    """Diagnostic endpoint to check image configuration."""
    return jsonify({
        "USE_CUSTOM_IMAGES":      os.environ.get("USE_CUSTOM_IMAGES", "no"),
        "CUSTOM_IMAGE_REGISTRY":  os.environ.get("CUSTOM_IMAGE_REGISTRY", "ghcr.io/cycentra"),
        "CYSOAR_IMAGE":           CYSOAR_IMAGE,
        "CYIRIS_IMAGE_APP":       CYIRIS_IMAGE_APP,
        "CYIRIS_IMAGE_DB":        CYIRIS_IMAGE_DB,
        "SIEM_ENGINE_URL":        os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100"),
        "env_file_loaded":        os.path.exists("/opt/cycentra/.env") or os.path.exists(".env"),
    })


# ── Platform Module API ────────────────────────────────────────────────────────

@app.route("/api/platform/install", methods=["POST", "OPTIONS"])
def platform_install():
    if request.method == "OPTIONS":
        from flask import make_response
        return _cors_headers(make_response('', 204))
    data      = request.get_json() or {}
    module_id = data.get("module", "").strip()
    if module_id not in VALID_MODULES:
        return jsonify({"error": f"Unknown module: {module_id}. Valid: {sorted(VALID_MODULES)}"}), 400
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
    threading.Thread(target=_install_module_async,
                     args=(module_id, compose_yaml, env_vars), daemon=True).start()
    return jsonify({"status": "installing", "module": module_id,
                    "message": "Poll /api/platform/status for progress."})


@app.route("/api/platform/status")
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
        if saved.get("status") == "installing" and _docker_containers_running(module_id):
            # cymisp needs extra time to initialise — don't mark running until post-install completes
            if module_id != "cymisp" or saved.get("misp_ready", False):
                saved["status"] = "running"
                state[module_id] = saved
                save_state(state)
        if saved.get("status") in ("running", "degraded"):
            live             = _docker_containers_running(module_id)
            saved["running"] = live
            saved["status"]  = "running" if live else "stopped"
        else:
            saved["running"] = False
        saved["last_log"]    = last_log
        result[module_id]    = saved
    return jsonify(result)


@app.route("/api/platform/uninstall", methods=["POST", "OPTIONS"])
def platform_uninstall():
    if request.method == "OPTIONS":
        from flask import make_response
        return _cors_headers(make_response('', 204))
    data      = request.get_json() or {}
    module_id = data.get("module", "").strip()
    if module_id not in VALID_MODULES:
        return jsonify({"error": f"Unknown module: {module_id}"}), 400
    module_dir = MODULES_DIR / module_id
    errors = []
    if module_dir.exists():
        # Step 1 — graceful compose shutdown with volume removal
        run("docker compose down -v", cwd=str(module_dir), timeout=60)

        # Step 2 — force remove any orphaned containers by known names
        container_names = {
            "cyiris": ["cyiris", "cyiris-db", "cyiris-worker", "cyiris-rabbitmq"],
            "cysoar": ["cysoar"],
            "cymisp": ["cymisp", "cymisp-db", "cymisp-redis"],
        }.get(module_id, [])

        for container in container_names:
            run(f"docker rm -f {container} 2>/dev/null || true", timeout=10)

        # Step 3 — force remove all volumes matching module name
        rc2, vols_out, _ = run(
            f"docker volume ls -q --filter name={module_id}", timeout=10)
        if rc2 == 0 and vols_out.strip():
            for vol in vols_out.strip().splitlines():
                run(f"docker volume rm -f {vol.strip()} 2>/dev/null || true", timeout=10)

        # Step 4 — remove nginx block for modules that added one (cymisp only currently)
        if module_id == "cymisp":
            import re as _re
            nginx_conf = Path("/etc/nginx/sites-available/cycentra-modules")
            if nginx_conf.exists():
                content = nginx_conf.read_text()
                base_domain = os.environ.get("BASE_DOMAIN", "cycentra.com")
                content = _re.sub(
                    r'\nserver \{[^{}]*server_name cymisp\.' +
                    _re.escape(base_domain) +
                    r';[^{}]*\}',
                    '', content, flags=_re.DOTALL
                )
                nginx_conf.write_text(content)
                run("nginx -t && systemctl reload nginx", timeout=15)

        # Step 5 — remove module directory
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


@app.route("/api/platform/logs/<module_id>")
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


# ── Scan API ───────────────────────────────────────────────────────────────────

@app.route("/api/scans/latest")
def get_latest_scan():
    all_files = glob.glob(str(SCANS_DIR / "**" / "scan_*.json"), recursive=True)
    if not all_files:
        return jsonify({"error": "No scans found"}), 404
    try:
        with open(sorted(all_files, key=os.path.getmtime, reverse=True)[0]) as f:
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/status")
def scan_status():
    log_file = ASM_LOGS / "cycentra_engine.log"
    running, progress, current_module, last_line = False, 0, "", ""
    module_keywords = [
        ("[dns reconnaissance]",    "DNS Reconnaissance",    8),
        ("[subdomain enumeration]", "Subdomain Enumeration", 18),
        ("[web analysis]",          "Web Analysis",          30),
        ("[crypto & ssl audit]",    "Crypto & SSL Audit",    42),
        ("[email security check]",  "Email Security Check",  52),
        ("[whois & history]",       "WHOIS & History",       58),
        ("[osint gathering]",       "OSINT Gathering",       65),
        ("[cloud infrastructure]",  "Cloud Infrastructure",  72),
        ("[dark web monitoring]",   "Dark Web Monitoring",   79),
        ("[supply chain analysis]", "Supply Chain Analysis", 86),
        ("[social engineering intel]","Social Engineering",  89),
        ("[mobile & api checks]",   "Mobile & API Checks",  92),
        ("[ai enrichment]",         "AI Risk Enrichment",    95),
        ("[portal json]",           "Generating Report",     98),
    ]
    try:
        if log_file.exists():
            age = time.time() - log_file.stat().st_mtime
            if age < 600:
                running = True
            with open(log_file, errors='replace') as f:
                lines = [l.strip() for l in f.readlines() if l.strip()]
            if lines:
                last_line = lines[-1]
                low = last_line.lower()
                if any(m in low for m in
                       ["portal json saved", "ndjson report saved", "scan complete", "all done"]):
                    running, progress, current_module = False, 100, "Complete"
                else:
                    for line in reversed(lines[-200:]):
                        ll = line.lower()
                        for key, mod, pct in module_keywords:
                            if key in ll:
                                current_module, progress = mod, pct
                                break
                        if current_module:
                            break
    except Exception as e:
        app.logger.error(f"[Scan] Status error: {e}")
    return jsonify({"running": running, "progress": progress,
                    "current_module": current_module, "last_log": last_line})


@app.route("/api/scan/trigger", methods=["POST", "OPTIONS"])
def trigger_scan():
    if request.method == "OPTIONS":
        from flask import make_response
        return _cors_headers(make_response('', 204))
    data   = request.get_json() or {}
    domain = data.get("domain", "").strip()
    uid    = data.get("uid", "anonymous")
    if not domain or "." not in domain:
        return jsonify({"error": "Invalid domain"}), 400
    user_dir = SCANS_DIR / uid
    user_dir.mkdir(parents=True, exist_ok=True)
    ASM_LOGS.mkdir(parents=True, exist_ok=True)
    scan_script = ASM_DIR / "cycentra_scan.py"

    #python_bin  = Path("/opt/cycentra/backend/venv/bin/python3")
    import sys as _sys
    python_bin = Path(_sys.executable)


    if not scan_script.exists():
        return jsonify({"error": f"Scan engine not found at {scan_script}"}), 503
    log_file = ASM_LOGS / "cycentra_engine.log"
    try:
        log_file.write_text(f"[{datetime.now().strftime('%H:%M:%S')}] Scan triggered for {domain} by {uid}\n")
    except Exception as le:
        app.logger.warning(f"[Scan] Could not initialise log file: {le}")
    env = os.environ.copy()
    env['CYCENTRA_OUTPUT_DIR'] = str(user_dir)
    env['CYCENTRA_USER_ID']    = uid
    try:
        subprocess.Popen(
            [str(python_bin), str(scan_script), domain, uid],
            stdout=open(log_file, "a"), stderr=subprocess.STDOUT,
            env=env, start_new_session=True,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"status": "started", "domain": domain, "uid": uid})


# ── AI provider test ───────────────────────────────────────────────────────────

@app.route("/api/ai/test", methods=["POST", "OPTIONS"])
def ai_test():
    if request.method == "OPTIONS":
        from flask import make_response
        return _cors_headers(make_response('', 204))
    data     = request.get_json() or {}
    provider = data.get("provider", "local")
    fields   = data.get("fields", {})
    try:
        if provider == "local":
            base_url = fields.get("baseUrl", "http://localhost:11434").rstrip("/")
            model    = fields.get("model", "llama3:8b")
            resp = http_requests.get(f"{base_url}/api/tags", timeout=8)
            if resp.status_code == 200:
                return jsonify({"ok": True, "message": f"Ollama connected · {model}"})
            return jsonify({"ok": False, "error": f"Ollama returned {resp.status_code}"}), 400
        elif provider in ("openai", "anthropic", "deepseek"):
            api_key = fields.get("apiKey", "")
            model   = fields.get("model", "")
            if not api_key:
                return jsonify({"ok": False, "error": "API key required"}), 400
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            if provider == "openai":
                resp = http_requests.post("https://api.openai.com/v1/chat/completions",
                    headers=headers,
                    json={"model": model or "gpt-4o-mini", "max_tokens": 5,
                          "messages": [{"role": "user", "content": "ping"}]}, timeout=15)
            elif provider == "anthropic":
                resp = http_requests.post("https://api.anthropic.com/v1/messages",
                    headers={**headers, "anthropic-version": "2023-06-01"},
                    json={"model": model or "claude-3-haiku-20240307", "max_tokens": 5,
                          "messages": [{"role": "user", "content": "ping"}]}, timeout=15)
            else:
                resp = http_requests.post("https://api.deepseek.com/v1/chat/completions",
                    headers=headers,
                    json={"model": model, "max_tokens": 16,
                          "messages": [{"role": "user", "content": "ping"}]}, timeout=15)
            if resp.status_code == 401:
                return jsonify({"ok": False, "error": "Invalid API key"}), 400
            return jsonify({"ok": True, "message": f"Connected · {model}"})
        else:
            return jsonify({"ok": False, "error": f"Unknown provider: {provider}"}), 400
    except http_requests.exceptions.ConnectionError:
        return jsonify({"ok": False, "error": "Cannot reach server"}), 400
    except http_requests.exceptions.Timeout:
        return jsonify({"ok": False, "error": "Connection timed out"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── RBAC management API ────────────────────────────────────────────────────────

@app.route("/api/rbac/users", methods=["GET", "POST"])
def rbac_users():
    if request.method == "GET":
        return jsonify(_load_rbac())
    data  = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    role  = data.get("role", "viewer")
    if not email or role not in VALID_ROLES:
        return jsonify({"error": "email and valid role required"}), 400
    rbac = _load_rbac()
    rbac[email] = {"role": role}
    _save_rbac(rbac)
    return jsonify({"status": "ok", "email": email, "role": role})


@app.route("/api/rbac/users/<email>", methods=["DELETE"])
def rbac_delete_user(email):
    rbac = _load_rbac()
    rbac.pop(email, None)
    _save_rbac(rbac)
    return jsonify({"status": "deleted", "email": email})


# ── Auth verify (nginx sub-request for module access gate) ─────────────────────

@app.route("/api/auth/verify")
def auth_verify():
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify({
        "email": email,
        "name":  session.get("user_name", ""),
        "uid":   session.get("user_uid", ""),
        "role":  get_user_role(email),
    })


# ── OAuth login ────────────────────────────────────────────────────────────────

@app.route("/auth/google")
def auth_google():
    import urllib.parse, base64
    redirect_target = request.args.get('redirect', FRONTEND_URL)
    callback = f"{BASE_URL}/auth/google/callback"
    state    = base64.urlsafe_b64encode(redirect_target.encode()).decode()
    params   = urllib.parse.urlencode({
        "client_id": GOOGLE_CLIENT_ID, "redirect_uri": callback,
        "response_type": "code", "scope": "openid email profile",
        "state": state, "access_type": "online",
    })
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?{params}")


# ── Auth log API ───────────────────────────────────────────────────────────────

@app.route("/api/auth/logs")
#@_require_admin
def auth_logs():
    n = int(request.args.get("n", 100))
    try:
        lines  = AUTH_LOG_FILE.read_text().splitlines()[-n:]
        events = []
        for line in lines:
            try:
                events.append(json.loads(line))
            except Exception:
                pass
        return jsonify({"events": events, "total": len(events)})
    except Exception:
        return jsonify({"events": [], "total": 0})


# ── Google OAuth ───────────────────────────────────────────────────────────────

def enc(s):
    return http_requests.utils.quote(str(s), safe='')



@app.route("/auth/google/callback")
def auth_google_callback():
    import base64
    code  = request.args.get("code")
    state = request.args.get("state", "")
    error = request.args.get("error")
    if error:
        _auth_event("login", "", "portal", "error", f"Google: {error}")
        return redirect(f"{FRONTEND_URL}?auth=error&message={enc(error)}")
    try:
        redirect_target = base64.urlsafe_b64decode(state.encode()).decode()
    except Exception:
        redirect_target = FRONTEND_URL
    if not code:
        return redirect(f"{FRONTEND_URL}?auth=error&message=no_code")

    resp = http_requests.post("https://oauth2.googleapis.com/token", data={
        "code": code, "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": f"{BASE_URL}/auth/google/callback",
        "grant_type": "authorization_code",
    }, timeout=10)
    if not resp.ok:
        _auth_event("login", "", "portal", "error", resp.text[:200])
        return redirect(f"{FRONTEND_URL}?auth=error&message={enc(resp.text[:200])}")

    info   = http_requests.get("https://www.googleapis.com/oauth2/v3/userinfo",
                 headers={"Authorization": f"Bearer {resp.json().get('access_token')}"}, timeout=10).json()
    name   = info.get("name", info.get("email", "Unknown"))
    email  = info.get("email", "")
    uid    = f"google_{info.get('sub', 'unknown')}"
    avatar = ''.join([w[0].upper() for w in name.split()[:2]])

    # ── After getting `email` from Google/Microsoft ──
    rbac = _load_rbac()
    if email not in rbac:
        _auth_event("login", email, "portal", "denied", "not in allowlist")
        return redirect(f"{FRONTEND_URL}?auth=error&message=Access+denied.+Your+account+is+not+registered.")

    session["user_email"] = email
    session["user_name"]  = name
    session["user_uid"]   = uid
    session.permanent     = True
    _auth_event("login", email, "portal", "success", "provider=google")

    return redirect(f"{redirect_target}?auth=success&provider=google"
                    f"&name={enc(name)}&email={enc(email)}&uid={enc(uid)}&avatar={enc(avatar)}"
                    f"&role={enc(get_user_role(email))}&apps={enc(json.dumps(get_user_apps(email)))}")


# ── Microsoft OAuth ────────────────────────────────────────────────────────────

@app.route("/auth/microsoft")
def auth_microsoft():
    import urllib.parse, base64
    redirect_target = request.args.get('redirect', FRONTEND_URL)
    callback = f"{BASE_URL}/auth/microsoft/callback"
    state    = base64.urlsafe_b64encode(redirect_target.encode()).decode()
    params   = urllib.parse.urlencode({
        "client_id": MS_CLIENT_ID, "redirect_uri": callback,
        "response_type": "code", "scope": "openid email profile User.Read",
        "state": state, "response_mode": "query",
    })
    return redirect(f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{params}")


@app.route("/auth/microsoft/callback")
def auth_microsoft_callback():
    import base64
    code  = request.args.get("code")
    state = request.args.get("state", "")
    error = request.args.get("error")
    if error:
        _auth_event("login", "", "portal", "error",
                    request.args.get('error_description', error))
        return redirect(f"{FRONTEND_URL}?auth=error&message={enc(request.args.get('error_description', error))}")
    try:
        redirect_target = base64.urlsafe_b64decode(state.encode()).decode()
    except Exception:
        redirect_target = FRONTEND_URL
    if not code:
        return redirect(f"{FRONTEND_URL}?auth=error&message=no_code")

    resp = http_requests.post(
        "https://login.microsoftonline.com/common/oauth2/v2.0/token", data={
            "code": code, "client_id": MS_CLIENT_ID, "client_secret": MS_CLIENT_SECRET,
            "redirect_uri": f"{BASE_URL}/auth/microsoft/callback",
            "grant_type": "authorization_code", "scope": "openid email profile User.Read",
        }, timeout=10)
    if not resp.ok:
        _auth_event("login", "", "portal", "error", resp.text[:200])
        return redirect(f"{FRONTEND_URL}?auth=error&message={enc(resp.text[:200])}")

    graph  = http_requests.get("https://graph.microsoft.com/v1.0/me",
                 headers={"Authorization": f"Bearer {resp.json().get('access_token')}"}, timeout=10).json()
    name   = graph.get("displayName", graph.get("userPrincipalName", "Unknown"))
    email  = graph.get("mail") or graph.get("userPrincipalName", "")
    uid    = f"microsoft_{graph.get('id', 'unknown')}"
    avatar = ''.join([w[0].upper() for w in name.split()[:2]])

    # ── After getting `email` from Google/Microsoft ──
    rbac = _load_rbac()
    if email not in rbac:
        _auth_event("login", email, "portal", "denied", "not in allowlist")
        return redirect(f"{FRONTEND_URL}?auth=error&message=Access+denied.+Your+account+is+not+registered.")

    session["user_email"] = email
    session["user_name"]  = name
    session["user_uid"]   = uid
    session.permanent     = True
    _auth_event("login", email, "portal", "success", "provider=microsoft")

    return redirect(f"{redirect_target}?auth=success&provider=microsoft"
                    f"&name={enc(name)}&email={enc(email)}&uid={enc(uid)}&avatar={enc(avatar)}"
                    f"&role={enc(get_user_role(email))}&apps={enc(json.dumps(get_user_apps(email)))}")


@app.route("/auth/logout")
def logout():
    email = session.get("user_email", "")
    session.clear()
    _auth_event("logout", email)
    return redirect(FRONTEND_URL)


# ── OIDC IdP endpoints ─────────────────────────────────────────────────────────

@app.route("/oidc/.well-known/openid-configuration")
def oidc_discovery():
    return jsonify({
        "issuer":                                BASE_URL,
        "authorization_endpoint":                f"{BASE_URL}/oidc/authorize",
        "token_endpoint":                        f"{BASE_URL}/oidc/token",
        "userinfo_endpoint":                     f"{BASE_URL}/oidc/userinfo",
        "introspection_endpoint":                f"{BASE_URL}/oidc/introspect",
        "jwks_uri":                              f"{BASE_URL}/oidc/jwks",
        "response_types_supported":              ["code"],
        "grant_types_supported":                 ["authorization_code"],
        "subject_types_supported":               ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "scopes_supported":                      ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "claims_supported":                      ["sub", "iss", "email", "name", "roles", "apps"],
    })


@app.route("/oidc/jwks")
def oidc_jwks():
    return jsonify({"keys": []})


@app.route("/oidc/authorize")
def oidc_authorize():
    import urllib.parse
    client_id    = request.args.get("client_id", "")
    redirect_uri = request.args.get("redirect_uri", "")
    state        = request.args.get("state", "")

    client = OIDC_CLIENTS.get(client_id)
    if not client:
        return jsonify({"error": "unknown_client"}), 400
    if redirect_uri not in client["redirect_uris"]:
        return jsonify({"error": "invalid_redirect_uri"}), 400

    user_email = session.get("user_email")
    if not user_email:
        return_to = request.url
        return redirect(f"{FRONTEND_URL}?oidc_return={urllib.parse.quote(return_to)}")

    if not user_can_access_client(user_email, client_id):
        params = urllib.parse.urlencode({
            "error": "access_denied",
            "error_description": f"Your account is not permitted to access {client_id}",
            "state": state,
        })
        return redirect(f"{redirect_uri}?{params}")

    code = hashlib.sha256(
        f"{user_email}:{client_id}:{state}:{time.time()}".encode()
    ).hexdigest()[:32]
    session[f"oidc_code_{code}"] = {
        "email": user_email, "client_id": client_id,
        "redirect_uri": redirect_uri, "expires": time.time() + 300,
    }
    params = urllib.parse.urlencode({"code": code, "state": state})
    return redirect(f"{redirect_uri}?{params}")


@app.route("/oidc/token", methods=["POST"])
def oidc_token():
    grant_type   = request.form.get("grant_type")
    code         = request.form.get("code")
    client_id    = request.form.get("client_id")
    client_secret= request.form.get("client_secret")
    redirect_uri = request.form.get("redirect_uri")

    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    client = OIDC_CLIENTS.get(client_id)
    if not client or client["client_secret"] != client_secret:
        return jsonify({"error": "invalid_client"}), 401

    code_data = session.pop(f"oidc_code_{code}", None)
    if not code_data or code_data.get("client_id") != client_id:
        return jsonify({"error": "invalid_grant"}), 400
    if time.time() > code_data.get("expires", 0):
        return jsonify({"error": "invalid_grant", "error_description": "Code expired"}), 400

    email = code_data["email"]
    now   = int(time.time())

    if _JWT_AVAILABLE:
        id_token = pyjwt.encode({
            "iss": BASE_URL, "sub": email, "aud": client_id,
            "iat": now, "exp": now + TOKEN_TTL,
            "email": email, "name": session.get("user_name", ""),
            "roles": [get_user_role(email)],
            "apps":  get_user_apps(email),
        }, JWT_SECRET, algorithm="HS256")
    else:
        import base64
        payload = json.dumps({"sub": email, "email": email, "iss": BASE_URL}).encode()
        id_token = base64.b64encode(payload).decode()

    access_token = hashlib.sha256(f"{email}:{now}:{uuid.uuid4()}".encode()).hexdigest()
    session[f"at_{access_token}"] = {"email": email, "client_id": client_id, "exp": now + TOKEN_TTL}

    _auth_event("oidc_token", email, client_id, "success")
    return jsonify({
        "access_token": access_token,
        "token_type":   "Bearer",
        "expires_in":   TOKEN_TTL,
        "id_token":     id_token,
        "scope":        "openid email profile",
    })


@app.route("/oidc/userinfo")
def oidc_userinfo():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip()
    data  = session.get(f"at_{token}")
    if not data or time.time() > data.get("exp", 0):
        return jsonify({"error": "invalid_token"}), 401
    email = data["email"]
    return jsonify({
        "sub":   email,
        "email": email,
        "name":  session.get("user_name", ""),
        "roles": [get_user_role(email)],
        "apps":  get_user_apps(email),
    })


@app.route("/oidc/introspect", methods=["POST"])
def oidc_introspect():
    token = request.form.get("token", "")
    data  = session.get(f"at_{token}")
    if not data or time.time() > data.get("exp", 0):
        return jsonify({"active": False})
    email = data["email"]
    return jsonify({
        "active":    True,
        "sub":       email,
        "email":     email,
        "client_id": data.get("client_id"),
        "exp":       data.get("exp"),
        "roles":     [get_user_role(email)],
    })


# ── Main index (cyscan.domain root) ───────────────────────────────────────────

# @app.route("/", methods=["GET", "POST"])
# def index():
#    return jsonify({
#        "service": "cycentra360-backend",
#        "version": "4.2",
#        "status":  "ok",
#        "docs":    f"{FRONTEND_URL}",
#    })


# ── Register blueprints ────────────────────────────────────────────────────────
# CySIEM Correlation Engine proxy — NEW in v4.2
# Provides /api/siem/* authenticated proxy to the FastAPI engine on :8100
from siem_proxy import siem_bp
app.register_blueprint(siem_bp)


# ── Main scan UI (cyscan.domain.com root) ─────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        if not domain or "." not in domain:
            flash("Please enter a valid domain name.", "danger")
            return redirect(url_for("index"))
        scan_script = ASM_DIR / "cycentra_scan.py"
        python_bin  = ASM_DIR / "venv" / "bin" / "python3"
        subprocess.Popen(
            [str(python_bin) if python_bin.exists() else "python3",
             str(scan_script), domain, validate_tenant(generate_tenant_id(domain))],
            cwd=str(ASM_DIR)
        )
        flash(f"Scan started for {domain}!", "success")
        return redirect(url_for("index"))

    return render_template_string("""
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>CyCentra ASM Scanner</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=Inter:wght@400;500&display=swap" rel="stylesheet">
<style>*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}:root{--bg:hsl(220,25%,6%);--card:hsl(220,22%,10%);--border:hsl(220,15%,18%);--primary:hsl(185,85%,50%);--primary-fg:hsl(220,25%,6%);--fg:hsl(210,20%,92%);--muted:hsl(215,15%,55%);--input-bg:hsl(220,18%,14%);--radius:0.75rem}body{background:var(--bg);color:var(--fg);font-family:'Inter',sans-serif;min-height:100vh;display:flex;justify-content:center;align-items:center;padding:2rem}.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:2.5rem;width:100%;max-width:560px}.badge{font-family:'Space Grotesk';font-size:.7rem;letter-spacing:.2em;text-transform:uppercase;color:var(--primary);margin-bottom:1rem;display:inline-block}h1{font-family:'Space Grotesk';font-size:1.8rem;margin-bottom:.5rem}.subtitle{color:var(--muted);font-size:.9rem;margin-bottom:2rem}.form-group{margin-bottom:1.25rem}label{font-size:.8rem;color:var(--muted);display:block;margin-bottom:.4rem}input,select{width:100%;background:var(--input-bg);border:1px solid var(--border);border-radius:.5rem;color:var(--fg);padding:.65rem .875rem;font-size:.9rem;outline:none}.checkbox{display:flex;align-items:center;gap:.5rem}.checkbox input{width:auto}.btn{margin-top:1.5rem;width:100%;padding:.9rem;background:var(--primary);color:var(--primary-fg);border:none;border-radius:.5rem;font-family:'Space Grotesk';font-weight:700;cursor:pointer}.alert{margin-bottom:1rem;padding:.75rem;border-radius:.5rem;font-size:.85rem}.alert-success{background:hsl(145 63% 25%/.3);border:1px solid hsl(145 63% 35%)}.alert-danger{background:hsl(0 70% 30%/.3);border:1px solid hsl(0 70% 45%)}</style></head>
<body><div class="card">
  <span class="badge">CyCentra 360</span><h1>External Attack Surface Scan</h1>
  <p class="subtitle">Launch automated reconnaissance & exposure assessment.</p>
  {% with messages = get_flashed_messages(with_categories=true) %}{% if messages %}{% for c,m in messages %}<div class="alert alert-{{c}}">{{m}}</div>{% endfor %}{% endif %}{% endwith %}
  <form method="POST" onsubmit="this.querySelector('button').innerText='Launching…';">
    <div class="form-group"><label>Target Domain *</label><input type="text" name="domain" placeholder="example.com" required></div>
    <div class="form-group"><label>Scan Type</label><select name="scan_type"><option value="standard">Standard</option><option value="deep">Deep</option><option value="passive">Passive</option></select></div>
    <div class="form-group"><label>Email (Optional)</label><input type="email" name="notify_email" placeholder="security@company.com"></div>
    <div class="form-group checkbox"><input type="checkbox" name="include_subdomains" checked><label style="margin:0;">Include Subdomains</label></div>
    <button class="btn" type="submit">Launch ASM Scan →</button>
  </form>
</div></body></html>
""")
# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", 5252))
    app.run(host="0.0.0.0", port=port, debug=False)
