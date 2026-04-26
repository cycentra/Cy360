"""
blueprints/backup/routes.py
=============================
Backup & Restore for CyCentra 360.

Routes:
  GET    /api/backup/list                   list available backups
  POST   /api/backup/create                 run a backup now
  POST   /api/backup/restore/<backup_id>    restore config from a backup
  DELETE /api/backup/<backup_id>            delete a backup archive
  GET    /api/backup/download/<backup_id>   stream the archive to the browser
  GET    /api/backup/schedule               get backup schedule config
  PUT    /api/backup/schedule               save/update backup schedule
  DELETE /api/backup/schedule               disable scheduled backups

What gets backed up (all under /opt/cycentra/):
  - *.json files  (rbac, modules_state, ai_settings, schedules, …)
  - *.env / *.env files  (global, cysiemstack, per-module)
  - modules/*/  sub-configs
  - Optionally a pg_dump of the CySIEM / CyIRIS database if DB_URL is set
"""

import os
import json
import subprocess
import tarfile
import tempfile
import threading
from datetime import datetime
from pathlib import Path

from flask import Blueprint, request, jsonify, send_file, session

from core.helpers import add_cors_headers

backup_bp = Blueprint("backup", __name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
_BASE          = Path(os.environ.get("CYCENTRA_CONFIG_DIR", "/opt/cycentra"))
_BACKUP_DIR    = _BASE / "backups"
_SCHEDULE_FILE = _BASE / "backup_schedule.json"

# Files/dirs inside _BASE to include in every backup
_INCLUDE_PATTERNS = [
    "*.json",
    "*.env",
    "cysiemstack.env",
    "modules",        # whole modules/ subtree (configs only, not data volumes)
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_admin():
    role = session.get("role", "")
    if role != "admin":
        return jsonify({"error": "Admin required"}), 403
    return None


def _ensure_backup_dir():
    _BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def _backup_id_to_path(backup_id: str) -> Path | None:
    """Return the archive path for a backup_id, or None if it doesn't exist / is unsafe."""
    # Prevent path traversal
    if ".." in backup_id or "/" in backup_id:
        return None
    p = _BACKUP_DIR / backup_id
    return p if p.exists() and p.suffix in (".gz", ".tgz") else None


def _list_backups() -> list[dict]:
    if not _BACKUP_DIR.exists():
        return []
    entries = []
    for f in sorted(_BACKUP_DIR.glob("cycentra_backup_*.tar.gz"), reverse=True):
        stat = f.stat()
        entries.append({
            "id":       f.name,
            "created":  datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "size_mb":  round(stat.st_size / (1024 * 1024), 2),
            "size_bytes": stat.st_size,
        })
    return entries


def _do_backup() -> dict:
    """Create a .tar.gz snapshot of CyCentra config files. Returns {ok, id, path, error?}."""
    _ensure_backup_dir()
    ts      = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    archive = _BACKUP_DIR / f"cycentra_backup_{ts}.tar.gz"

    try:
        with tarfile.open(archive, "w:gz") as tar:
            for item in _BASE.iterdir():
                if item == _BACKUP_DIR:
                    continue  # never recurse into the backup dir itself
                if item.suffix in (".json", ".env") or item.name.endswith(".env"):
                    tar.add(item, arcname=item.name)
                elif item.is_dir() and item.name == "modules":
                    # Include module sub-configs but skip large data volumes
                    for sub in item.rglob("*"):
                        if sub.suffix in (".json", ".env") or sub.name.endswith(".env"):
                            tar.add(sub, arcname=str(sub.relative_to(_BASE)))

            # Optional: pg_dump if DB_URL is available
            db_url = os.environ.get("DATABASE_URL", "")
            if db_url:
                with tempfile.NamedTemporaryFile(suffix=".sql", delete=False) as tmp:
                    tmp_path = tmp.name
                try:
                    result = subprocess.run(
                        ["pg_dump", db_url, "-f", tmp_path],
                        capture_output=True, timeout=120,
                    )
                    if result.returncode == 0:
                        tar.add(tmp_path, arcname="database_dump.sql")
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass  # pg_dump not available or timed out — skip DB snapshot
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

        stat = archive.stat()
        return {"ok": True, "id": archive.name, "path": str(archive),
                "size_mb": round(stat.st_size / (1024 * 1024), 2)}
    except Exception as exc:
        if archive.exists():
            archive.unlink()
        return {"ok": False, "error": str(exc)}


def _do_restore(backup_id: str) -> dict:
    """
    Restore config files from a backup archive.
    Creates a pre-restore snapshot first so the current state is preserved.
    Returns {ok, restored, pre_backup_id?, error?}
    """
    path = _backup_id_to_path(backup_id)
    if path is None:
        return {"ok": False, "error": "Backup not found"}

    # Snapshot current state before overwriting
    pre = _do_backup()
    pre_id = pre.get("id") if pre.get("ok") else None

    try:
        with tarfile.open(path, "r:gz") as tar:
            members = tar.getmembers()
            safe = [m for m in members if not m.name.startswith("/") and ".." not in m.name]
            tar.extractall(path=str(_BASE), members=safe)

        return {"ok": True, "restored": len(safe),
                "pre_backup_id": pre_id,
                "message": f"Restored {len(safe)} files from {backup_id}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _load_schedule() -> dict:
    if _SCHEDULE_FILE.exists():
        try:
            return json.loads(_SCHEDULE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"enabled": False, "cron": "0 2 * * *", "retain_days": 30, "retain_count": 14}


def _save_schedule(cfg: dict):
    _SCHEDULE_FILE.write_text(json.dumps(cfg, indent=2))


def _apply_crontab(cfg: dict):
    """Write (or remove) the backup cron entry in the system crontab."""
    tag   = "# cycentra-backup-auto"
    entry = f"{cfg['cron']} root /opt/cycentra/run_backup.sh >> /var/log/cycentra/backup.log 2>&1  {tag}"

    try:
        cron_path = Path("/etc/cron.d/cycentra-backup")
        if cfg.get("enabled"):
            cron_path.write_text(entry + "\n")
            cron_path.chmod(0o644)
        else:
            if cron_path.exists():
                cron_path.unlink()
    except OSError:
        pass  # non-root environments — schedule stored in JSON, applied on next restart


# ── Routes ────────────────────────────────────────────────────────────────────

@backup_bp.route("/api/backup/list", methods=["GET", "OPTIONS"])
def backup_list():
    if request.method == "OPTIONS":
        return add_cors_headers(("", 204))
    err = _require_admin()
    if err:
        return err
    return jsonify({"backups": _list_backups()})


@backup_bp.route("/api/backup/create", methods=["POST", "OPTIONS"])
def backup_create():
    if request.method == "OPTIONS":
        return add_cors_headers(("", 204))
    err = _require_admin()
    if err:
        return err

    result = _do_backup()
    if result["ok"]:
        return jsonify({"ok": True, "backup": {
            "id":      result["id"],
            "size_mb": result["size_mb"],
        }})
    return jsonify({"ok": False, "error": result.get("error", "Backup failed")}), 500


@backup_bp.route("/api/backup/restore/<backup_id>", methods=["POST", "OPTIONS"])
def backup_restore(backup_id):
    if request.method == "OPTIONS":
        return add_cors_headers(("", 204))
    err = _require_admin()
    if err:
        return err

    result = _do_restore(backup_id)
    status = 200 if result["ok"] else 400
    return jsonify(result), status


@backup_bp.route("/api/backup/<backup_id>", methods=["DELETE", "OPTIONS"])
def backup_delete(backup_id):
    if request.method == "OPTIONS":
        return add_cors_headers(("", 204))
    err = _require_admin()
    if err:
        return err

    path = _backup_id_to_path(backup_id)
    if path is None:
        return jsonify({"ok": False, "error": "Backup not found"}), 404
    path.unlink()
    return jsonify({"ok": True})


@backup_bp.route("/api/backup/download/<backup_id>", methods=["GET", "OPTIONS"])
def backup_download(backup_id):
    if request.method == "OPTIONS":
        return add_cors_headers(("", 204))
    err = _require_admin()
    if err:
        return err

    path = _backup_id_to_path(backup_id)
    if path is None:
        return jsonify({"error": "Backup not found"}), 404
    return send_file(str(path), as_attachment=True,
                     download_name=backup_id,
                     mimetype="application/gzip")


@backup_bp.route("/api/backup/schedule", methods=["GET", "OPTIONS"])
def backup_schedule_get():
    if request.method == "OPTIONS":
        return add_cors_headers(("", 204))
    err = _require_admin()
    if err:
        return err
    return jsonify(_load_schedule())


@backup_bp.route("/api/backup/schedule", methods=["PUT"])
def backup_schedule_put():
    err = _require_admin()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    cfg = _load_schedule()
    if "enabled"      in body: cfg["enabled"]      = bool(body["enabled"])
    if "cron"         in body: cfg["cron"]          = str(body["cron"]).strip()
    if "retain_days"  in body: cfg["retain_days"]   = int(body["retain_days"])
    if "retain_count" in body: cfg["retain_count"]  = int(body["retain_count"])

    _save_schedule(cfg)
    _apply_crontab(cfg)
    return jsonify({"ok": True, "schedule": cfg})


@backup_bp.route("/api/backup/schedule", methods=["DELETE"])
def backup_schedule_delete():
    err = _require_admin()
    if err:
        return err

    cfg = _load_schedule()
    cfg["enabled"] = False
    _save_schedule(cfg)
    _apply_crontab(cfg)
    return jsonify({"ok": True, "message": "Scheduled backups disabled"})
