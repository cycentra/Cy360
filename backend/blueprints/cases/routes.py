"""
blueprints/cases/routes.py
===========================
CyCases — native case management module for CyCentra 360.

All endpoints require minimum analyst role.  Restriction-protected
endpoints additionally enforce case_access_restrictions.
"""

import os
from datetime import datetime, timezone
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import Blueprint, jsonify, request, session
from werkzeug.utils import secure_filename

from blueprints.rbac.manager import get_user_role
from blueprints.cases.service import (
    open_case, acknowledge_case, add_comment,
    upload_evidence, add_ioc, get_graph_data, compute_metrics,
)
from blueprints.cases.checklist_templates import TEMPLATES

cases_bp = Blueprint("cases", __name__)


def _resolve_corr_db_url() -> str:
    """
    Resolve the correlation DB connection URL for psycopg2 (sync, Flask context).

    Priority:
      1. CORRELATION_DB_URL  env var (explicit override)
      2. CYCENTRA_DB_URL     env var (Flask's own DB — same host/port/db, corruser)
      3. DATABASE_URL from /opt/cycentra/cysiemstack.env, with asyncpg+ prefix stripped
      4. Hard-coded fallback (dev-only; will fail on real installs with custom passwords)
    """
    # 1. Explicit override
    url = os.environ.get("CORRELATION_DB_URL", "").strip()
    if url:
        return url

    # 2. CYCENTRA_DB_URL — same correlation DB, already set for Flask process
    url = os.environ.get("CYCENTRA_DB_URL", "").strip()
    if url:
        return url

    # 3. Parse cysiemstack.env — where the engine keeps DATABASE_URL
    try:
        from pathlib import Path
        env_file = Path("/opt/cycentra/cysiemstack.env")
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                if k.strip() == "DATABASE_URL":
                    # Strip SQLAlchemy async driver prefix if present
                    raw = v.strip().strip('"').strip("'")
                    return raw.replace("postgresql+asyncpg://", "postgresql://")
    except Exception:
        pass

    # 4. Dev fallback
    return "postgresql://corruser:changeme@127.0.0.1:5433/correlation"


_CORR_DB_URL = _resolve_corr_db_url()
_MAX_EVIDENCE_BYTES = 100 * 1024 * 1024  # 100 MB


def _db():
    try:
        conn = psycopg2.connect(_CORR_DB_URL)
        conn.cursor_factory = psycopg2.extras.RealDictCursor
        return conn
    except psycopg2.OperationalError as exc:
        import logging as _log
        _log.getLogger("cycentra.cases").error(
            "CyCases DB connection failed. URL resolved to: %s... Error: %s",
            _CORR_DB_URL[:50], exc,
        )
        raise


def _require_analyst(f):
    @wraps(f)
    def _inner(*args, **kwargs):
        email = session.get("user_email")
        if not email:
            return jsonify({"error": "Authentication required"}), 401
        role = get_user_role(email)
        if role not in ("admin", "analyst"):
            return jsonify({"error": "Analyst or admin role required"}), 403
        return f(*args, **kwargs)
    return _inner


def _require_admin(f):
    @wraps(f)
    def _inner(*args, **kwargs):
        email = session.get("user_email")
        if not email:
            return jsonify({"error": "Authentication required"}), 401
        if get_user_role(email) != "admin":
            return jsonify({"error": "Admin role required"}), 403
        return f(*args, **kwargs)
    return _inner


def _check_restriction(conn, incident_id: str, email: str, role: str) -> bool:
    """Return True if access is allowed. Admins always pass."""
    if role == "admin":
        return True
    cur = conn.cursor()
    cur.execute("SELECT allowed_emails FROM case_access_restrictions WHERE incident_id = %s", [incident_id])
    row = cur.fetchone()
    if not row:
        return True
    return email in (row["allowed_emails"] or [])


def _write_action_audit(conn, incident_id: str, action: str, actor: str,
                        comment: str = None, extra: dict = None):
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO audit_log (entity_type, entity_id, action, actor, comment, extra, created_at)
        VALUES ('incident', %s, %s, %s, %s, %s::jsonb, %s)
    """, [incident_id, action, actor,
          comment, psycopg2.extras.Json(extra or {}),
          datetime.now(timezone.utc)])


def _iso(v):
    if v is None:
        return None
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return str(v)


def _incident_to_dict(row: dict) -> dict:
    return {k: _iso(v) if isinstance(v, datetime) else v for k, v in row.items()}


# ── List cases ─────────────────────────────────────────────────────────────────

@cases_bp.route("/api/cases", methods=["GET"])
@_require_analyst
def list_cases():
    status     = request.args.get("status")
    severity   = request.args.get("severity")
    case_type  = request.args.get("type")
    assigned   = request.args.get("assigned_to")
    date_from  = request.args.get("date_from")
    date_to    = request.args.get("date_to")
    page       = max(1, int(request.args.get("page", 1)))
    per_page   = min(200, int(request.args.get("per_page", 50)))
    offset     = (page - 1) * per_page

    wheres = ["case_opened_at IS NOT NULL"]
    params = []
    if status:
        wheres.append("status = %s"); params.append(status)
    if severity:
        wheres.append("severity = %s"); params.append(severity)
    if case_type:
        wheres.append("case_type = %s"); params.append(case_type)
    if assigned:
        wheres.append("assigned_to = %s"); params.append(assigned)
    if date_from:
        wheres.append("case_opened_at >= %s"); params.append(date_from)
    if date_to:
        wheres.append("case_opened_at <= %s"); params.append(date_to)

    where_sql = " AND ".join(wheres)
    try:
        conn = _db()
        cur  = conn.cursor()
        cur.execute(f"SELECT COUNT(*) FROM incidents WHERE {where_sql}", params)
        total = cur.fetchone()["count"]
        cur.execute(
            f"SELECT id, status, severity, case_type, case_opened_at, case_ack_at, "
            f"case_mttd_seconds, case_mtta_seconds, case_restricted, assigned_to, "
            f"categories, first_seen, last_seen "
            f"FROM incidents WHERE {where_sql} ORDER BY case_opened_at DESC "
            f"LIMIT %s OFFSET %s",
            params + [per_page, offset],
        )
        cases = [_incident_to_dict(dict(r)) for r in cur.fetchall()]
        conn.close()
        return jsonify({"total": total, "page": page, "per_page": per_page, "cases": cases})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Get single case ─────────────────────────────────────────────────────────────

@cases_bp.route("/api/cases/<incident_id>", methods=["GET"])
@_require_analyst
def get_case(incident_id):
    email = session["user_email"]
    role  = get_user_role(email)
    try:
        conn = _db()
        if not _check_restriction(conn, incident_id, email, role):
            conn.close()
            return jsonify({"error": "Access restricted — you are not on the access list for this case"}), 403

        cur = conn.cursor()
        cur.execute("SELECT * FROM incidents WHERE id = %s", [incident_id])
        row = cur.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Incident not found"}), 404

        result = _incident_to_dict(dict(row))

        cur.execute("SELECT * FROM case_comments WHERE incident_id = %s ORDER BY created_at ASC", [incident_id])
        result["comments"] = [_incident_to_dict(dict(r)) for r in cur.fetchall()]

        cur.execute("""
            SELECT ci.*, mc.threat_level, mc.tags
            FROM case_iocs ci
            LEFT JOIN misp_ioc_cache mc ON mc.ioc_value = ci.ioc_value AND mc.ioc_type = ci.ioc_type
            WHERE ci.incident_id = %s AND ci.is_removed = FALSE
        """, [incident_id])
        result["iocs"] = [_incident_to_dict(dict(r)) for r in cur.fetchall()]

        cur.execute("SELECT * FROM case_evidence WHERE incident_id = %s AND is_deleted = FALSE ORDER BY uploaded_at DESC", [incident_id])
        result["evidence"] = [_incident_to_dict(dict(r)) for r in cur.fetchall()]

        # Checklist state
        case_type = result.get("case_type", "generic")
        template  = TEMPLATES.get(case_type, TEMPLATES["generic"])
        cur.execute("SELECT * FROM case_checklist_state WHERE incident_id = %s AND template_key = %s", [incident_id, case_type])
        state_rows = {r["step_index"]: dict(r) for r in cur.fetchall()}
        checklist = []
        for step in template:
            state = state_rows.get(step["index"], {})
            checklist.append({**step, "checked": state.get("checked", False),
                               "checked_by": state.get("checked_by"), "note": state.get("note")})
        result["checklist"] = checklist

        conn.close()
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Open case ───────────────────────────────────────────────────────────────────

@cases_bp.route("/api/cases", methods=["POST"])
@_require_analyst
def create_case():
    email = session["user_email"]
    body  = request.get_json(silent=True) or {}
    incident_id = body.get("incident_id", "").strip()
    if not incident_id:
        return jsonify({"error": "incident_id is required"}), 400
    case_type = body.get("case_type")
    try:
        conn = _db()
        result = open_case(conn, incident_id, email, case_type=case_type)
        _write_action_audit(conn, incident_id, "case_opened", email,
                            comment=f"Case opened via API by {email}")
        conn.commit()
        conn.close()
        return jsonify(result), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Patch case ──────────────────────────────────────────────────────────────────

@cases_bp.route("/api/cases/<incident_id>", methods=["PATCH"])
@_require_analyst
def patch_case(incident_id):
    email = session["user_email"]
    role  = get_user_role(email)
    body  = request.get_json(silent=True) or {}
    try:
        conn = _db()
        if not _check_restriction(conn, incident_id, email, role):
            conn.close()
            return jsonify({"error": "Access restricted"}), 403

        sets, params = [], []
        for field in ("status", "severity", "assigned_to", "case_type"):
            if field in body:
                sets.append(f"{field} = %s"); params.append(body[field])

        # First status change away from 'open' triggers acknowledgement
        if "status" in body and body["status"] not in ("open",):
            cur = conn.cursor()
            cur.execute("SELECT case_ack_at FROM incidents WHERE id = %s", [incident_id])
            row = cur.fetchone()
            if row and row["case_ack_at"] is None:
                acknowledge_case(conn, incident_id, email)

        if sets:
            sets.append("updated_at = %s"); params.append(datetime.now(timezone.utc))
            params.append(incident_id)
            cur = conn.cursor()
            cur.execute(f"UPDATE incidents SET {', '.join(sets)} WHERE id = %s", params)
            _write_action_audit(conn, incident_id, "case_updated", email,
                                comment=f"Case updated by {email}: {list(body.keys())}")
            conn.commit()

        cur = conn.cursor()
        cur.execute("SELECT * FROM incidents WHERE id = %s", [incident_id])
        result = _incident_to_dict(dict(cur.fetchone()))
        conn.close()
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Comments ────────────────────────────────────────────────────────────────────

@cases_bp.route("/api/cases/<incident_id>/comments", methods=["GET"])
@_require_analyst
def list_comments(incident_id):
    email = session["user_email"]
    role  = get_user_role(email)
    page     = max(1, int(request.args.get("page", 1)))
    per_page = min(200, int(request.args.get("per_page", 50)))
    offset   = (page - 1) * per_page
    try:
        conn = _db()
        if not _check_restriction(conn, incident_id, email, role):
            conn.close()
            return jsonify({"error": "Access restricted"}), 403
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM case_comments WHERE incident_id = %s", [incident_id])
        total = cur.fetchone()["count"]
        cur.execute("SELECT * FROM case_comments WHERE incident_id = %s ORDER BY created_at ASC LIMIT %s OFFSET %s",
                    [incident_id, per_page, offset])
        comments = [_incident_to_dict(dict(r)) for r in cur.fetchall()]
        conn.close()
        return jsonify({"total": total, "comments": comments})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@cases_bp.route("/api/cases/<incident_id>/comments", methods=["POST"])
@_require_analyst
def post_comment(incident_id):
    email = session["user_email"]
    role  = get_user_role(email)
    body  = request.get_json(silent=True) or {}
    text  = (body.get("body") or "").strip()
    if not text:
        return jsonify({"error": "Comment body is required"}), 400
    try:
        conn = _db()
        if not _check_restriction(conn, incident_id, email, role):
            conn.close()
            return jsonify({"error": "Access restricted"}), 403
        result = add_comment(conn, incident_id, email, text,
                             parent_id=body.get("parent_id"))
        conn.close()
        return jsonify(result), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Evidence ────────────────────────────────────────────────────────────────────

@cases_bp.route("/api/cases/<incident_id>/evidence", methods=["GET"])
@_require_analyst
def list_evidence(incident_id):
    email = session["user_email"]
    role  = get_user_role(email)
    try:
        conn = _db()
        if not _check_restriction(conn, incident_id, email, role):
            conn.close()
            return jsonify({"error": "Access restricted"}), 403
        cur = conn.cursor()
        cur.execute("SELECT * FROM case_evidence WHERE incident_id = %s AND is_deleted = FALSE ORDER BY uploaded_at DESC", [incident_id])
        rows = [_incident_to_dict(dict(r)) for r in cur.fetchall()]
        conn.close()
        return jsonify(rows)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@cases_bp.route("/api/cases/<incident_id>/evidence", methods=["POST"])
@_require_analyst
def upload_evidence_endpoint(incident_id):
    email = session["user_email"]
    role  = get_user_role(email)
    if "file" not in request.files:
        return jsonify({"error": "No file in request"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400
    file_bytes = f.read()
    if len(file_bytes) > _MAX_EVIDENCE_BYTES:
        return jsonify({"error": "File exceeds 100 MB limit"}), 413
    filename   = secure_filename(f.filename)
    description = request.form.get("description")
    try:
        conn = _db()
        if not _check_restriction(conn, incident_id, email, role):
            conn.close()
            return jsonify({"error": "Access restricted"}), 403
        result = upload_evidence(conn, incident_id, email, filename, file_bytes, description)
        conn.close()
        return jsonify(result), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@cases_bp.route("/api/cases/<incident_id>/evidence/<int:eid>/download", methods=["GET"])
@_require_analyst
def download_evidence(incident_id, eid):
    from flask import send_file
    email = session["user_email"]
    role  = get_user_role(email)
    try:
        conn = _db()
        if not _check_restriction(conn, incident_id, email, role):
            conn.close()
            return jsonify({"error": "Access restricted"}), 403
        cur = conn.cursor()
        cur.execute("SELECT storage_path, filename, mime_type FROM case_evidence WHERE id = %s AND incident_id = %s AND is_deleted = FALSE",
                    [eid, incident_id])
        row = cur.fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "Evidence not found"}), 404
        return send_file(row["storage_path"], download_name=row["filename"],
                         mimetype=row["mime_type"] or "application/octet-stream")
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── IOCs ────────────────────────────────────────────────────────────────────────

@cases_bp.route("/api/cases/<incident_id>/iocs", methods=["GET"])
@_require_analyst
def list_iocs(incident_id):
    email = session["user_email"]
    role  = get_user_role(email)
    try:
        conn = _db()
        if not _check_restriction(conn, incident_id, email, role):
            conn.close()
            return jsonify({"error": "Access restricted"}), 403
        cur = conn.cursor()
        cur.execute("""
            SELECT ci.*, mc.threat_level, mc.tags
            FROM case_iocs ci
            LEFT JOIN misp_ioc_cache mc ON mc.ioc_value = ci.ioc_value AND mc.ioc_type = ci.ioc_type
            WHERE ci.incident_id = %s AND ci.is_removed = FALSE
            ORDER BY ci.added_at DESC
        """, [incident_id])
        rows = [_incident_to_dict(dict(r)) for r in cur.fetchall()]
        conn.close()
        return jsonify(rows)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@cases_bp.route("/api/cases/<incident_id>/iocs", methods=["POST"])
@_require_analyst
def add_ioc_endpoint(incident_id):
    email = session["user_email"]
    role  = get_user_role(email)
    body  = request.get_json(silent=True) or {}
    ioc_value = (body.get("ioc_value") or "").strip()
    ioc_type  = (body.get("ioc_type") or "").strip()
    if not ioc_value or not ioc_type:
        return jsonify({"error": "ioc_value and ioc_type are required"}), 400
    try:
        conn = _db()
        if not _check_restriction(conn, incident_id, email, role):
            conn.close()
            return jsonify({"error": "Access restricted"}), 403
        result = add_ioc(conn, incident_id, ioc_value, ioc_type, email,
                         context_note=body.get("context_note"))
        conn.close()
        return jsonify(result), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@cases_bp.route("/api/cases/<incident_id>/iocs/<int:ioc_id>", methods=["DELETE"])
@_require_analyst
def remove_ioc(incident_id, ioc_id):
    email = session["user_email"]
    role  = get_user_role(email)
    try:
        conn = _db()
        if not _check_restriction(conn, incident_id, email, role):
            conn.close()
            return jsonify({"error": "Access restricted"}), 403
        cur = conn.cursor()
        cur.execute("""
            UPDATE case_iocs SET is_removed = TRUE, removed_by = %s, removed_at = %s
            WHERE id = %s AND incident_id = %s
        """, [email, datetime.now(timezone.utc), ioc_id, incident_id])
        _write_action_audit(conn, incident_id, "ioc_removed", email,
                            extra={"ioc_id": ioc_id})
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Checklist ───────────────────────────────────────────────────────────────────

@cases_bp.route("/api/cases/<incident_id>/checklist", methods=["GET"])
@_require_analyst
def get_checklist(incident_id):
    email = session["user_email"]
    role  = get_user_role(email)
    try:
        conn = _db()
        if not _check_restriction(conn, incident_id, email, role):
            conn.close()
            return jsonify({"error": "Access restricted"}), 403
        cur = conn.cursor()
        cur.execute("SELECT case_type FROM incidents WHERE id = %s", [incident_id])
        row = cur.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Incident not found"}), 404
        case_type = row["case_type"] or "generic"
        template  = TEMPLATES.get(case_type, TEMPLATES["generic"])
        cur.execute("SELECT * FROM case_checklist_state WHERE incident_id = %s AND template_key = %s", [incident_id, case_type])
        state_rows = {r["step_index"]: dict(r) for r in cur.fetchall()}
        conn.close()
        checklist = []
        for step in template:
            state = state_rows.get(step["index"], {})
            checklist.append({**step, "checked": state.get("checked", False),
                               "checked_by": state.get("checked_by"),
                               "checked_at": _iso(state.get("checked_at")),
                               "note": state.get("note")})
        return jsonify({"case_type": case_type, "steps": checklist})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@cases_bp.route("/api/cases/<incident_id>/checklist/<int:step_index>", methods=["PATCH"])
@_require_analyst
def patch_checklist_step(incident_id, step_index):
    email = session["user_email"]
    role  = get_user_role(email)
    body  = request.get_json(silent=True) or {}
    checked = body.get("checked", True)
    note    = body.get("note")
    try:
        conn = _db()
        if not _check_restriction(conn, incident_id, email, role):
            conn.close()
            return jsonify({"error": "Access restricted"}), 403
        cur = conn.cursor()
        cur.execute("SELECT case_type FROM incidents WHERE id = %s", [incident_id])
        row = cur.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Incident not found"}), 404
        case_type = row["case_type"] or "generic"
        now = datetime.now(timezone.utc)
        cur.execute("""
            INSERT INTO case_checklist_state (incident_id, template_key, step_index, checked, checked_by, checked_at, note)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (incident_id, template_key, step_index) DO UPDATE
                SET checked    = EXCLUDED.checked,
                    checked_by = EXCLUDED.checked_by,
                    checked_at = EXCLUDED.checked_at,
                    note       = COALESCE(EXCLUDED.note, case_checklist_state.note)
        """, [incident_id, case_type, step_index, checked,
              email if checked else None, now if checked else None, note])
        _write_action_audit(conn, incident_id, "checklist_step_toggled", email,
                            extra={"step_index": step_index, "checked": checked})
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "step_index": step_index, "checked": checked})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── SOAR trigger ─────────────────────────────────────────────────────────────────

@cases_bp.route("/api/cases/<incident_id>/trigger-playbook", methods=["POST"])
@_require_analyst
def trigger_playbook(incident_id):
    import requests as _req
    email = session["user_email"]
    role  = get_user_role(email)
    body  = request.get_json(silent=True) or {}
    flow  = body.get("flow_name", "").strip()
    try:
        conn = _db()
        if not _check_restriction(conn, incident_id, email, role):
            conn.close()
            return jsonify({"error": "Access restricted"}), 403
        cysoar_url = os.environ.get("CYSOAR_URL", "http://127.0.0.1:1880")
        try:
            r = _req.post(
                f"{cysoar_url}/webhook/incident",
                json={"incident_id": incident_id, "flow_name": flow, "actor": email},
                timeout=10,
            )
            result = r.json() if r.ok else {"status": "error", "http": r.status_code}
        except Exception as e:
            result = {"status": "error", "detail": str(e)}
        add_comment(conn, incident_id, "system",
                    f"CySOAR playbook '{flow or 'default'}' triggered by {email}. Status: {result.get('status', 'unknown')}.",
                    is_system=True)
        _write_action_audit(conn, incident_id, "soar_triggered", email,
                            extra={"flow": flow, "result": result})
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Graph ────────────────────────────────────────────────────────────────────────

@cases_bp.route("/api/cases/<incident_id>/graph", methods=["GET"])
@_require_analyst
def case_graph(incident_id):
    email = session["user_email"]
    role  = get_user_role(email)
    try:
        conn = _db()
        if not _check_restriction(conn, incident_id, email, role):
            conn.close()
            return jsonify({"error": "Access restricted"}), 403
        result = get_graph_data(conn, incident_id)
        conn.close()
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Metrics ───────────────────────────────────────────────────────────────────────

@cases_bp.route("/api/cases/metrics", methods=["GET"])
@_require_analyst
def case_metrics():
    try:
        conn = _db()
        result = compute_metrics(conn)
        conn.close()
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Access restriction ─────────────────────────────────────────────────────────

@cases_bp.route("/api/cases/<incident_id>/restrict", methods=["POST"])
@_require_admin
def restrict_case(incident_id):
    email = session["user_email"]
    body  = request.get_json(silent=True) or {}
    allowed_emails = body.get("allowed_emails", [])
    reason         = body.get("reason", "")
    if not allowed_emails:
        return jsonify({"error": "allowed_emails is required"}), 400
    try:
        conn = _db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO case_access_restrictions (incident_id, set_by, allowed_emails, reason)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (incident_id) DO UPDATE
                SET set_by = EXCLUDED.set_by,
                    set_at = NOW(),
                    allowed_emails = EXCLUDED.allowed_emails,
                    reason = EXCLUDED.reason
        """, [incident_id, email, allowed_emails, reason])
        cur.execute("UPDATE incidents SET case_restricted = TRUE, updated_at = %s WHERE id = %s",
                    [datetime.now(timezone.utc), incident_id])
        _write_action_audit(conn, incident_id, "case_restricted", email,
                            extra={"allowed_emails": allowed_emails})
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@cases_bp.route("/api/cases/<incident_id>/restrict", methods=["DELETE"])
@_require_admin
def unrestrict_case(incident_id):
    email = session["user_email"]
    try:
        conn = _db()
        cur = conn.cursor()
        cur.execute("DELETE FROM case_access_restrictions WHERE incident_id = %s", [incident_id])
        cur.execute("UPDATE incidents SET case_restricted = FALSE, updated_at = %s WHERE id = %s",
                    [datetime.now(timezone.utc), incident_id])
        _write_action_audit(conn, incident_id, "case_unrestricted", email)
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── ASM finding case ───────────────────────────────────────────────────────────
# Creates a lightweight tracking incident in the correlation DB from an ASM
# finding (no Wazuh alert required). The incident is tagged source=asm so it
# can be filtered separately from correlated incidents.

@cases_bp.route("/api/cases/asm", methods=["POST"])
@_require_analyst
def create_asm_case():
    """Open a CyCases investigation from an ASM vulnerability finding.

    Body: { vulnerability, severity, asset, module, description, recommendation, cve }
    Creates a synthetic tracking incident and immediately opens a case on it.
    """
    import hashlib as _hash
    email = session["user_email"]
    body  = request.get_json(silent=True) or {}

    vuln   = (body.get("vulnerability") or "ASM Finding").strip()[:200]
    sev    = (body.get("severity") or "medium").lower()
    if sev not in ("critical", "high", "medium", "low"):
        sev = "medium"
    asset  = (body.get("asset") or "unknown").strip()[:200]
    module = (body.get("module") or "asm").strip()[:100]
    desc   = (body.get("description") or "").strip()
    rec    = (body.get("recommendation") or "").strip()
    cve    = (body.get("cve") or "").strip()

    # Deterministic incident ID: ASM-<hash of asset+vuln+module> so re-raises
    # for the same finding reuse the existing case rather than duplicating.
    raw_key = f"{asset}|{vuln}|{module}".lower()
    inc_id  = "ASM-" + _hash.sha256(raw_key.encode()).hexdigest()[:8].upper()

    note_parts = [f"ASM Finding: {vuln}"]
    if cve:         note_parts.append(f"CVE: {cve}")
    note_parts.append(f"Asset: {asset}  Module: {module}")
    if desc:        note_parts.append(f"\nDescription: {desc}")
    if rec:         note_parts.append(f"\nRemediation: {rec}")
    notes = "\n".join(note_parts)

    try:
        conn = _db()
        cur  = conn.cursor()

        # Upsert the synthetic incident (idempotent)
        cur.execute("""
            INSERT INTO incidents
                (id, first_seen, last_seen, updated_at, status, severity,
                 alert_count, categories, notes)
            VALUES (%s, NOW(), NOW(), NOW(), 'investigating', %s, 0,
                    ARRAY['asm'], %s)
            ON CONFLICT (id) DO UPDATE
                SET last_seen  = NOW(),
                    updated_at = NOW(),
                    notes      = EXCLUDED.notes
        """, [inc_id, sev, notes])
        conn.commit()

        # Open the case (open_case is idempotent when already open)
        from blueprints.cases.service import open_case as _open_case
        result = _open_case(conn, inc_id, email, case_type="generic")
        _write_action_audit(conn, inc_id, "asm_case_opened", email,
                            extra={"asset": asset, "vuln": vuln, "severity": sev})
        conn.commit()
        conn.close()
        return jsonify({**result, "incident_id": inc_id}), 201

    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
