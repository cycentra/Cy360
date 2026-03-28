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
from blueprints.platform.compose import COMPOSE_TEMPLATES, VALID_MODULES
from blueprints.platform.state import load_state, save_state
from blueprints.platform.docker_utils import docker_containers_running

platform_bp = Blueprint("platform", __name__)


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

        if saved.get("status") == "installing" and docker_containers_running(module_id):
            if module_id != "cymisp" or saved.get("misp_ready", False):
                saved["status"]       = "running"
                state[module_id]      = saved
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
        return jsonify({"error": f"Unknown module: {module_id}. Valid: {sorted(VALID_MODULES)}"}), 400

    rc, _, _ = run("docker info")
    if rc != 0:
        return jsonify({"error": "Docker not running"}), 503

    rc2, _, _ = run("docker compose version")
    if rc2 != 0:
        return jsonify({"error": "Docker Compose plugin not found"}), 503

    state              = load_state()
    state[module_id]   = {"status": "installing", "started_at": time.strftime('%Y-%m-%dT%H:%M:%SZ')}
    save_state(state)

    compose_yaml = COMPOSE_TEMPLATES.get(module_id) or data.get("compose_yaml") or ""
    if not compose_yaml:
        return jsonify({"error": "No compose template for this module"}), 400

    env_vars = {k: v for k, v in (data.get("config") or {}).items()
                if v and not k.startswith("_")}

    threading.Thread(
        target=_install_module_async,
        args=(module_id, compose_yaml, env_vars),
        daemon=True,
    ).start()

    return jsonify({
        "status":  "installing",
        "module":  module_id,
        "message": "Poll /api/platform/status for progress.",
    })


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
        run("docker compose down -v", cwd=str(module_dir), timeout=60)

        container_names = {
            "cyiris": ["cyiris", "cyiris-db", "cyiris-worker"],
            "cysoar": ["cysoar", "cysoar-rabbitmq"],
            "cymisp": ["cymisp", "cymisp-db", "cymisp-redis"],
        }.get(module_id, [])

        for container in container_names:
            run(f"docker rm -f {container} 2>/dev/null || true", timeout=10)

        rc2, vols_out, _ = run(
            f"docker volume ls -q --filter name={module_id}", timeout=10
        )
        if rc2 == 0 and vols_out.strip():
            for vol in vols_out.strip().splitlines():
                run(f"docker volume rm -f {vol.strip()} 2>/dev/null || true", timeout=10)

        # Remove nginx block added for cymisp
        if module_id == "cymisp":
            nginx_conf = Path("/etc/nginx/sites-available/cycentra-modules")
            if nginx_conf.exists():
                base_domain = os.environ.get("BASE_DOMAIN", "cycentra.com")
                content     = nginx_conf.read_text()
                content     = re.sub(
                    r'\nserver \{[^{}]*server_name cymisp\.' +
                    re.escape(base_domain) + r';[^{}]*\}',
                    '', content, flags=re.DOTALL,
                )
                nginx_conf.write_text(content)
                run("nginx -t && systemctl reload nginx", timeout=15)

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


# ── Install logs ──────────────────────────────────────────────────────────────

@platform_bp.route("/api/platform/logs/<module_id>")
def platform_logs(module_id):
    if module_id not in VALID_MODULES:
        return jsonify({"error": "Unknown module"}), 400

    log_file = MODULES_DIR / module_id / "install.log"
    if not log_file.exists():
        return jsonify({"lines": [], "module": module_id})

    try:
        return jsonify({
            "lines":  log_file.read_text().splitlines()[-100:],
            "module": module_id,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Debug images ──────────────────────────────────────────────────────────────

@platform_bp.route("/api/debug/images")
def debug_images():
    from core.config import CYSOAR_IMAGE, CYIRIS_IMAGE_APP, CYIRIS_IMAGE_DB
    return jsonify({
        "CYSOAR_IMAGE":      CYSOAR_IMAGE,
        "CYIRIS_IMAGE_APP":  CYIRIS_IMAGE_APP,
        "CYIRIS_IMAGE_DB":   CYIRIS_IMAGE_DB,
        "SIEM_ENGINE_URL":   os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100"),
        "env_file_loaded":   os.path.exists("/opt/cycentra/.env") or os.path.exists(".env"),
    })


# ── Async install worker ──────────────────────────────────────────────────────

def _install_module_async(module_id: str, compose_yaml: str, env_vars: dict):
    """
    Runs in a daemon thread. Pulls images, starts containers,
    runs any post-install hooks, and updates persistent state.
    """
    module_dir = MODULES_DIR / module_id
    module_dir.mkdir(parents=True, exist_ok=True)
    log_file   = module_dir / "install.log"

    def log(msg):
        with open(log_file, "a") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

    try:
        log(f"Starting installation of {module_id}")

        # Reload .env so late-set variables are picked up
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

        if module_id == "cyiris":
            _iris_adm_password = os.environ.get("IRIS_ADM_PASSWORD")
            if not _iris_adm_password:
                log("ERROR: IRIS_ADM_PASSWORD not set in /opt/cycentra/.env — aborting")
                raise ValueError("IRIS_ADM_PASSWORD is required")

            cyiris_env = {
                "POSTGRES_PASSWORD":   os.environ.get("POSTGRES_PASSWORD") or os.environ.get("IRIS_DB_PASS", ""),
                "IRIS_SECRET_KEY":     os.environ.get("IRIS_SECRET_KEY") or os.environ.get("IRIS_SECRET", ""),
                "CYIRIS_OIDC_SECRET":  os.environ.get("CYIRIS_OIDC_SECRET", ""),
                "CYCENTRA_PORTAL_URL": os.environ.get("CYCENTRA_PORTAL_URL") or os.environ.get("FRONTEND_URL", ""),
                "IRIS_ADM_EMAIL":      os.environ.get("IRIS_ADM_EMAIL", "admin@cycentra.com"),
                "IRIS_ADM_PASSWORD":   _iris_adm_password,
            }
            cyiris_env.update(env_vars)
            env_path.write_text("\n".join(f"{k}={v}" for k, v in cyiris_env.items()))
            log(f"Created cyiris .env with {len(cyiris_env)} variables")

            # pgcrypto init script
            init_dir = module_dir / "db-init"
            init_dir.mkdir(parents=True, exist_ok=True)
            (init_dir / "01-pgcrypto.sql").write_text(
                "CREATE EXTENSION IF NOT EXISTS pgcrypto;\n"
            )
            compose_text = compose_path.read_text().replace(
                "- cyiris_db_init:/docker-entrypoint-initdb.d",
                f"- {init_dir}:/docker-entrypoint-initdb.d",
            )
            compose_path.write_text(compose_text)
            log("pgcrypto init script written")

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
            env_path.write_text("\n".join(f"{k}={v}" for k, v in env_vars.items()))
            log("CySOAR pre-install cleanup complete")

        else:
            env_path.write_text("\n".join(f"{k}={v}" for k, v in env_vars.items()))
            log(f"Created .env with {len(env_vars)} variables")

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

        # ── CyMISP post-install ──────────────────────────────────────────────
        if module_id == "cymisp":
            base_domain = os.environ.get("BASE_DOMAIN", "cycentra.com")
            misp_url    = "https://cymisp." + base_domain
            log("CyMISP: waiting for MISP to initialise (8–12 min)…")
            misp_live = False
            for attempt in range(48):
                time.sleep(15)
                rc2, logs_out, _ = run(
                    "docker logs cymisp 2>&1 | grep 'MISP is now live'", timeout=10
                )
                if logs_out.strip():
                    misp_live = True
                    break
                log(f"CyMISP: waiting… ({attempt+1}/48)")

            if misp_live:
                sed_expr = (
                    f"s|'baseurl' => '.*'|'baseurl' => '{misp_url}'|g;"
                    f" s|'external_baseurl' => '.*'|'external_baseurl' => '{misp_url}'|g"
                )
                run(f"docker exec cymisp sed -i \"{sed_expr}\" /var/www/MISP/app/Config/config.php", timeout=15)
                state = load_state()
                state[module_id]["misp_ready"] = True
                save_state(state)
                log(f"CyMISP: fully ready — login at {misp_url}")

        # ── CyIRIS post-install: force admin credentials ─────────────────────
        if module_id == "cyiris":
            log("CyIRIS: waiting for app (up to 90s)…")
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
                admin_email    = cyiris_env.get("IRIS_ADM_EMAIL", "admin@cycentra.com")
                admin_password = cyiris_env.get("IRIS_ADM_PASSWORD", "CyIRIS@CHANGE")
                safe_pw        = admin_password.replace("'", "\\'").replace('"', '\\"')

                rc_h, hash_out, _ = run(
                    f'docker exec {app_container} python3 -c "'
                    f'from werkzeug.security import generate_password_hash;'
                    f'print(generate_password_hash(\\"{safe_pw}\\", method=\\"pbkdf2:sha256\\"))"',
                    timeout=15,
                )
                if rc_h == 0 and hash_out.strip().startswith("pbkdf2:"):
                    pw_hash = hash_out.strip()
                    run(
                        f'docker exec {db_container} psql -U iris -d iris_db -c '
                        f'"UPDATE \\"User\\" SET password=\'{pw_hash}\', email=\'{admin_email}\' '
                        f'WHERE login=\'administrator\';"',
                        timeout=15,
                    )
                    log(f"CyIRIS: credentials set — username: administrator | email: {admin_email}")
            else:
                log("CyIRIS: WARNING — app did not respond; check docker logs cyiris-cyiris-1")

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
        _fail(module_id, str(e))


def _fail(module_id: str, error: str):
    state = load_state()
    state[module_id] = {
        "status":       "failed",
        "error":        error,
        "installed_at": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
    }
    save_state(state)
