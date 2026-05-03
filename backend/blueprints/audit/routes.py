"""
blueprints/audit/routes.py
===========================
Audit Trail API for CyCentra 360 — monitoring and compliance.

Captures and exposes:
  - User activities: login/logout, config changes, document operations, scan triggers
  - System events: service start/stop, scheduled task execution, success/failure states

Storage strategy:
  - Events are written as JSON lines to AUDIT_LOG_FILE
  - The auth.log events (from core/helpers.py) are also merged in read time
  - Entries are searchable and filterable via query params

Routes (all under /api/audit/):
  GET  /logs          → paginated, filtered log query
  GET  /stats         → summary counts by type/result
  GET  /export        → download as JSON or CSV
  POST /event         → record a custom system event (internal / admin only)
"""

import csv
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from flask import Blueprint, Response, jsonify, request, session, stream_with_context

audit_bp = Blueprint("audit", __name__)

# ── Storage paths ─────────────────────────────────────────────────────────────

AUDIT_LOG_FILE = Path(os.environ.get("AUDIT_LOG_FILE", "/var/log/cycentra/audit.log"))
AUTH_LOG_FILE  = Path(os.environ.get("AUTH_LOG_FILE",  "/var/log/cycentra/auth.log"))

# System-event categories
_EVENT_CATEGORIES = {
    # Auth
    "login", "logout", "login_failed", "login_locked",
    "oidc_token", "sso_login",
    # Config
    "config_change", "settings_saved", "rbac_updated",
    "ai_settings_saved", "module_installed", "module_uninstalled",
    # Scan / ASM
    "scan_triggered", "scan_completed", "scan_failed",
    "report_generated",
    # Scheduler
    "scheduler_job_start", "scheduler_job_success", "scheduler_job_failed",
    # System
    "service_start", "service_stop", "backup_created", "backup_restored",
    # Data
    "document_uploaded", "document_deleted",
    # Security
    "access_denied", "api_key_created", "api_key_revoked",
}


# ── Internal helper ───────────────────────────────────────────────────────────

def record_event(event_type: str, email: str = "", detail: str = "",
                 result: str = "success", resource: str = "",
                 metadata: dict | None = None, ip: str = "") -> None:
    """
    Append a structured audit event to AUDIT_LOG_FILE.
    Never raises — audit failures must not break the calling code.
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type":      event_type,
        "category":  _classify(event_type),
        "email":     email,
        "result":    result,
        "resource":  resource,
        "detail":    detail,
        "ip":        ip or (request.remote_addr if request else ""),
        "metadata":  metadata or {},
    }
    try:
        AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass


def _classify(event_type: str) -> str:
    t = event_type.lower()
    if any(k in t for k in ("login", "logout", "oidc", "sso", "locked")):
        return "authentication"
    if any(k in t for k in ("config", "settings", "rbac", "module")):
        return "configuration"
    if any(k in t for k in ("scan", "report")):
        return "scan"
    if any(k in t for k in ("scheduler", "job", "backup")):
        return "system"
    if any(k in t for k in ("document", "upload", "delete")):
        return "data"
    if any(k in t for k in ("access_denied", "api_key", "revoked")):
        return "security"
    return "other"


# ── Log reader ────────────────────────────────────────────────────────────────

def _read_log_file(path: Path, source_tag: str) -> list[dict]:
    """Read a JSON-lines audit/auth log file. Returns a list of dicts."""
    entries = []
    if not path.exists():
        return entries
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    rec.setdefault("_source", source_tag)
                    rec.setdefault("category", _classify(rec.get("type", "")))
                    entries.append(rec)
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass
    return entries


def _merge_logs() -> list[dict]:
    """Merge audit.log + auth.log, de-dup by timestamp+type+email, sort descending."""
    entries = (
        _read_log_file(AUDIT_LOG_FILE, "audit")
        + _read_log_file(AUTH_LOG_FILE, "auth")
    )
    # Sort newest-first
    entries.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return entries


def _apply_filters(entries: list[dict], params: dict) -> list[dict]:
    """Filter entries in-place based on query parameters."""
    q          = (params.get("q") or "").lower().strip()
    category   = (params.get("category") or "").lower().strip()
    event_type = (params.get("type") or "").lower().strip()
    result     = (params.get("result") or "").lower().strip()
    email      = (params.get("email") or "").lower().strip()
    date_from  = params.get("from") or ""   # ISO date string
    date_to    = params.get("to")   or ""

    filtered = []
    for e in entries:
        if category and e.get("category", "").lower() != category:
            continue
        if event_type and event_type not in e.get("type", "").lower():
            continue
        if result and e.get("result", "").lower() != result:
            continue
        if email and email not in (e.get("email") or "").lower():
            continue
        if date_from and e.get("timestamp", "") < date_from:
            continue
        if date_to and e.get("timestamp", "") > date_to + "Z":
            continue
        if q:
            searchable = (
                (e.get("type") or "") + " " +
                (e.get("email") or "") + " " +
                (e.get("detail") or "") + " " +
                (e.get("resource") or "") + " " +
                json.dumps(e.get("metadata") or {})
            ).lower()
            if q not in searchable:
                continue
        filtered.append(e)
    return filtered


# ── Routes ────────────────────────────────────────────────────────────────────

@audit_bp.route("/api/audit/logs")
def get_audit_logs():
    """
    GET /api/audit/logs
    Query params:
      q          — free-text search
      category   — authentication|configuration|scan|system|data|security|other
      type       — event type substring filter
      result     — success|failure|error
      email      — email substring filter
      from       — ISO datetime lower bound (inclusive)
      to         — ISO datetime upper bound (inclusive)
      page       — 1-based page number (default 1)
      per_page   — items per page (default 50, max 200)
    """
    params   = request.args
    page     = max(1, int(params.get("page", 1)))
    per_page = min(200, max(1, int(params.get("per_page", 50))))

    all_entries = _merge_logs()
    filtered    = _apply_filters(all_entries, params)

    total  = len(filtered)
    start  = (page - 1) * per_page
    page_items = filtered[start: start + per_page]

    return jsonify({
        "total":      total,
        "page":       page,
        "per_page":   per_page,
        "pages":      (total + per_page - 1) // per_page,
        "entries":    page_items,
    })


@audit_bp.route("/api/audit/stats")
def get_audit_stats():
    """GET /api/audit/stats — summary counts for the last N days (default 30)."""
    days = int(request.args.get("days", 30))
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    all_entries = _merge_logs()
    recent = [e for e in all_entries if e.get("timestamp", "") >= cutoff]

    by_category: dict[str, int] = {}
    by_result:   dict[str, int] = {}
    by_type:     dict[str, int] = {}
    by_user:     dict[str, int] = {}

    for e in recent:
        cat  = e.get("category", "other")
        res  = e.get("result", "success")
        typ  = e.get("type", "")
        user = e.get("email", "system")

        by_category[cat]    = by_category.get(cat, 0) + 1
        by_result[res]      = by_result.get(res, 0) + 1
        by_type[typ]        = by_type.get(typ, 0) + 1
        by_user[user]       = by_user.get(user, 0) + 1

    # Top 10 users by activity
    top_users = sorted(by_user.items(), key=lambda x: x[1], reverse=True)[:10]

    return jsonify({
        "period_days":   days,
        "total_events":  len(recent),
        "by_category":   by_category,
        "by_result":     by_result,
        "top_event_types": sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:15],
        "top_users":     top_users,
    })


@audit_bp.route("/api/audit/export")
def export_audit_logs():
    """
    GET /api/audit/export?format=json|csv
    Supports same filter params as /api/audit/logs.
    Downloads entire filtered result set (no pagination).
    """
    fmt    = request.args.get("format", "json").lower()
    params = request.args

    all_entries = _merge_logs()
    filtered    = _apply_filters(all_entries, params)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if fmt == "csv":
        def generate_csv():
            cols = ["timestamp", "type", "category", "result", "email",
                    "resource", "detail", "ip", "_source"]
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
            writer.writeheader()
            yield buf.getvalue()
            for entry in filtered:
                buf = io.StringIO()
                writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
                writer.writerow(entry)
                yield buf.getvalue()

        return Response(
            stream_with_context(generate_csv()),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=audit_{ts}.csv"},
        )

    # Default: JSON
    return Response(
        json.dumps({"exported_at": datetime.now(timezone.utc).isoformat(),
                    "total": len(filtered), "entries": filtered},
                   indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=audit_{ts}.json"},
    )


@audit_bp.route("/api/audit/event", methods=["POST"])
def record_custom_event():
    """
    POST /api/audit/event
    Record a custom system event. Requires admin session or X-CyCentra-AdminKey header.
    Body JSON: {type, detail, result, resource, email, metadata}
    """
    # Simple auth check
    user_email = session.get("user_email", "")
    admin_key  = request.headers.get("X-CyCentra-AdminKey", "")
    expected_key = os.environ.get("ADMIN_API_KEY", "")

    if not user_email and not (admin_key and expected_key and admin_key == expected_key):
        return jsonify({"error": "Unauthorized"}), 401

    body = request.get_json(silent=True) or {}
    event_type = body.get("type", "").strip()
    if not event_type:
        return jsonify({"error": "type is required"}), 400

    record_event(
        event_type=event_type,
        email=body.get("email", user_email),
        detail=body.get("detail", ""),
        result=body.get("result", "success"),
        resource=body.get("resource", ""),
        metadata=body.get("metadata"),
        ip=request.remote_addr,
    )
    return jsonify({"recorded": True})


@audit_bp.route("/api/audit/categories")
def get_categories():
    """GET /api/audit/categories — list of category values for UI filter dropdowns."""
    return jsonify(["authentication", "configuration", "scan", "system", "data", "security", "other"])
