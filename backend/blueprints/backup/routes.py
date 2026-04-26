"""
blueprints/backup/routes.py
=============================
Backup & Restore for CyCentra 360.

Routes:
  GET    /api/backup/list                   list available backups with metadata
  POST   /api/backup/create                 run a backup now
  POST   /api/backup/restore/<backup_id>    restore from a backup archive
  DELETE /api/backup/<backup_id>            delete a backup archive
  GET    /api/backup/download/<backup_id>   stream archive to browser

Scheduling is managed by the system scheduler (blueprints/system/routes.py
via /api/system/schedules), not by these endpoints.  The scheduler writes
/opt/cycentra/run_backup.sh and a cron entry for the "backup" task.

What every backup archive contains
───────────────────────────────────
  /opt/cycentra/
    ├── *.json            rbac, modules_state, ai_settings, schedules, …
    ├── .env              core platform config (OAuth, BASE_DOMAIN, ports)
    ├── *.env             cysiemstack.env + any other top-level env files
    ├── *.lic             license file(s)
    └── modules/
        └── <module>/
            ├── .env      per-module env (cyiris, cysoar, cymisp, …)
            └── *.json    per-module config files

  database_dump.sql  (included when DATABASE_URL env var is set and
                      pg_dump is available on the PATH)

What is NOT backed up (by design)
───────────────────────────────────
  • Docker images / container state  — re-pullable via cycentra-setup.sh
  • Python source code               — re-deployable from git / package
  • Log files                        — large, historical only
"""

import os
import json
import subprocess
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path

from flask import Blueprint, request, jsonify, send_file, session

from core.helpers import add_cors_headers

backup_bp = Blueprint("backup", __name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
_BASE       = Path(os.environ.get("CYCENTRA_CONFIG_DIR", "/opt/cycentra"))
_BACKUP_DIR = _BASE / "backups"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_admin():
    role = session.get("role", "")
    if role != "admin":
        return jsonify({"error": "Admin required"}), 403
    return None


def _ensure_backup_dir():
    _BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def _backup_id_to_path(backup_id: str) -> Path | None:
    if ".." in backup_id or "/" in backup_id:
        return None
    p = _BACKUP_DIR / backup_id
    return p if p.exists() and p.name.endswith(".tar.gz") else None


def _collect_config_files() -> list[tuple[Path, str]]:
    """
    Return (source_path, archive_name) for every config file to include.
    archive_name is relative (no leading slash) so extraction lands under _BASE.
    """
    entries: list[tuple[Path, str]] = []

    # Top-level: *.json, .env, *.env, *.lic
    for item in sorted(_BASE.iterdir()):
        if not item.is_file() or item.parent == _BACKUP_DIR:
            continue
        if item.suffix in (".json", ".env", ".lic") or item.name == ".env":
            entries.append((item, item.name))

    # modules/  (recurse up to 4 levels deep, configs only)
    modules_dir = _BASE / "modules"
    if modules_dir.is_dir():
        for sub in sorted(modules_dir.rglob("*")):
            if not sub.is_file():
                continue
            if sub.suffix in (".json", ".env", ".lic") or sub.name == ".env":
                entries.append((sub, str(sub.relative_to(_BASE))))

    return entries


def _list_backups() -> list[dict]:
    if not _BACKUP_DIR.exists():
        return []
    out = []
    for f in sorted(_BACKUP_DIR.glob("cycentra_backup_*.tar.gz"), reverse=True):
        st = f.stat()
        out.append({
            "id":         f.name,
            "created":    datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "size_mb":    round(st.st_size / (1024 * 1024), 2),
            "size_bytes": st.st_size,
        })
    return out


def _do_backup() -> dict:
    """
    Create a .tar.gz snapshot.
    Returns {"ok": True, "id": ..., "size_mb": ..., "files": N}
         or {"ok": False, "error": ...}
    """
    _ensure_backup_dir()
    ts      = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    archive = _BACKUP_DIR / f"cycentra_backup_{ts}.tar.gz"

    try:
        config_files = _collect_config_files()
        if not config_files:
            return {"ok": False, "error": "No config files found under /opt/cycentra — is the platform installed?"}

        with tarfile.open(archive, "w:gz") as tar:
            for src, arcname in config_files:
                tar.add(src, arcname=arcname)

            # Optional PostgreSQL dump
            db_url = _resolve_db_url()
            if db_url:
                pg_dump_path = _pg_dump(db_url)
                if pg_dump_path:
                    try:
                        tar.add(pg_dump_path, arcname="database_dump.sql")
                    finally:
                        try:
                            os.unlink(pg_dump_path)
                        except OSError:
                            pass

        st = archive.stat()
        return {
            "ok":      True,
            "id":      archive.name,
            "path":    str(archive),
            "size_mb": round(st.st_size / (1024 * 1024), 2),
            "files":   len(config_files),
        }
    except Exception as exc:
        if archive.exists():
            archive.unlink()
        return {"ok": False, "error": str(exc)}


def _resolve_db_url() -> str:
    """Return a pg_dump-compatible URL from DATABASE_URL (strips +asyncpg driver prefix)."""
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        return ""
    # FastAPI/SQLAlchemy async drivers use  postgresql+asyncpg://...
    # pg_dump needs   postgresql://...
    url = url.replace("postgresql+asyncpg://", "postgresql://")
    url = url.replace("postgres+asyncpg://",   "postgresql://")
    return url


def _pg_dump(db_url: str) -> str | None:
    """Run pg_dump and return the path to the SQL file, or None on failure."""
    try:
        tmp = tempfile.NamedTemporaryFile(suffix=".sql", delete=False)
        tmp.close()
        result = subprocess.run(
            ["pg_dump", db_url, "-f", tmp.name],
            capture_output=True,
            timeout=120,
        )
        if result.returncode == 0 and os.path.getsize(tmp.name) > 0:
            return tmp.name
        os.unlink(tmp.name)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def _do_restore(backup_id: str) -> dict:
    """
    Restore config files from archive.
    Automatically creates a pre-restore snapshot before overwriting anything.
    """
    path = _backup_id_to_path(backup_id)
    if path is None:
        return {"ok": False, "error": "Backup not found"}

    # Safety snapshot of current state
    pre = _do_backup()
    pre_id = pre.get("id") if pre.get("ok") else None

    try:
        with tarfile.open(path, "r:gz") as tar:
            members = tar.getmembers()
            # Strict safety filter: no absolute paths, no path traversal
            safe = [
                m for m in members
                if not m.name.startswith("/")
                and ".." not in m.name
                and not m.name.startswith("database_dump")   # skip SQL — too destructive
            ]
            tar.extractall(path=str(_BASE), members=safe)

        return {
            "ok":            True,
            "restored":      len(safe),
            "pre_backup_id": pre_id,
            "message":       f"Restored {len(safe)} files from {backup_id}",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _write_backup_script(retain_count: int = 14, retain_days: int = 30):
    """
    Write /opt/cycentra/run_backup.sh — called by the system scheduler
    when the backup cron task is enabled.  The script uses tar directly
    (no Python runtime dependency) so it runs cleanly from cron.
    """
    script = f"""#!/bin/bash
# CyCentra 360 — Automated Backup
# Generated by the system scheduler — do not edit manually.
set -euo pipefail

BACKUP_DIR="{str(_BACKUP_DIR)}"
BASE="{str(_BASE)}"
TS=$(date +%Y%m%d_%H%M%S)
ARCHIVE="${{BACKUP_DIR}}/cycentra_backup_${{TS}}.tar.gz"
RETAIN_COUNT={retain_count}
RETAIN_DAYS={retain_days}
LOG="[$(date +'%Y-%m-%d %H:%M:%S')]"

mkdir -p "$BACKUP_DIR"
echo "$LOG CyCentra backup starting → $ARCHIVE"

# Collect files to include
mapfile -t CFG < <(find "$BASE" -maxdepth 1 \\( -name '*.json' -o -name '*.env' -o -name '*.lic' \\) -type f 2>/dev/null | sort)
mapfile -t MOD < <(find "$BASE/modules" -maxdepth 4 \\( -name '*.json' -o -name '*.env' -o -name '*.lic' \\) -type f 2>/dev/null | sort)
ALL_FILES=("${{CFG[@]:-}}" "${{MOD[@]:-}}")

if [ ${{#ALL_FILES[@]}} -eq 0 ]; then
    echo "$LOG WARNING: no config files found — backup skipped" >&2
    exit 0
fi

tar --transform "s|^${{BASE}}/||" -czf "$ARCHIVE" "${{ALL_FILES[@]}}" 2>/dev/null
echo "$LOG Archive: $ARCHIVE ($(du -sh "$ARCHIVE" | cut -f1))"

# Optional pg_dump
if [ -n "${{DATABASE_URL:-}}" ]; then
    DUMPFILE="${{BACKUP_DIR}}/cycentra_db_${{TS}}.sql"
    pg_dump "$DATABASE_URL" > "$DUMPFILE" 2>/dev/null \\
        && echo "$LOG DB dump: $DUMPFILE" \\
        || {{ echo "$LOG WARNING: pg_dump failed (non-fatal)" >&2; rm -f "$DUMPFILE"; }}
fi

# Prune: keep latest RETAIN_COUNT archives
ls -t "$BACKUP_DIR"/cycentra_backup_*.tar.gz 2>/dev/null | tail -n +$(( RETAIN_COUNT + 1 )) | xargs rm -f 2>/dev/null || true
# Prune: delete archives older than RETAIN_DAYS days
find "$BACKUP_DIR" -name 'cycentra_backup_*.tar.gz' -mtime +$RETAIN_DAYS -delete 2>/dev/null || true

echo "$LOG Backup complete."
"""
    try:
        script_path = _BASE / "run_backup.sh"
        script_path.write_text(script)
        script_path.chmod(0o755)
    except OSError:
        pass


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
            "files":   result.get("files", 0),
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
    return jsonify(result), (200 if result["ok"] else 400)


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
    return send_file(
        str(path),
        as_attachment=True,
        download_name=backup_id,
        mimetype="application/gzip",
    )
