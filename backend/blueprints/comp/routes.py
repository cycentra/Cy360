"""
blueprints/comp/routes.py
==========================
Flask Blueprint — CyCentra GRC Compliance API.

All routes are gated with RBAC decorators consistent with the siem_proxy.py
pattern (session-based auth, role checks via blueprints.rbac.manager).

RBAC levels:
  viewer+   — any authenticated user with viewer, analyst, or admin role
  analyst+  — analyst or admin
  admin+    — admin only

Prefix: /api/comp/*
"""

import json
import logging
import uuid
from functools import wraps
from pathlib import Path

from flask import Blueprint, jsonify, request, session, send_file

log = logging.getLogger("cycentra.blueprints.comp")

comp_bp = Blueprint("comp", __name__, url_prefix="/api/comp")


# ── Auth decorators ───────────────────────────────────────────────────────────

def _get_role() -> str | None:
    email = session.get("user_email", "")
    if not email:
        return None
    from blueprints.rbac.manager import get_user_role
    return get_user_role(email)


def _email() -> str:
    return session.get("user_email", "")


def require_viewer(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        role = _get_role()
        if role not in ("admin", "analyst", "viewer"):
            return jsonify({"error": "Access denied"}), 403
        return f(*args, **kwargs)
    return decorated


def require_analyst(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        if _get_role() not in ("admin", "analyst"):
            return jsonify({"error": "Analyst or admin role required"}), 403
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        if _get_role() != "admin":
            return jsonify({"error": "Admin role required"}), 403
        return f(*args, **kwargs)
    return decorated


# ── Dashboard ─────────────────────────────────────────────────────────────────

@comp_bp.route("/dashboard", methods=["GET"])
@require_viewer
def compliance_dashboard():
    from cy_comp.services.compliance import get_dashboard_summary
    return jsonify(get_dashboard_summary())


@comp_bp.route("/framework-scores", methods=["GET"])
@require_viewer
def get_framework_scores():
    from cy_comp.services.compliance import get_latest_scores, compute_framework_scores
    refresh = request.args.get("refresh", "false").lower() == "true"
    if refresh:
        scores = compute_framework_scores()
    else:
        scores = get_latest_scores()
    return jsonify({"scores": scores})


@comp_bp.route("/dashboard/score-history", methods=["GET"])
@require_viewer
def get_score_history():
    from cy_comp.services.compliance import get_score_history as _hist
    framework = request.args.get("framework")
    limit     = int(request.args.get("limit", 10))
    return jsonify({"history": _hist(framework=framework or None, limit=limit)})


@comp_bp.route("/dashboard/alerts-by-day", methods=["GET"])
@require_viewer
def get_alerts_by_day():
    from cy_comp.services.compliance import get_alerts_by_day as _abd
    days = int(request.args.get("days", 14))
    return jsonify({"days": _abd(days=days)})


@comp_bp.route("/controls-view/<framework>", methods=["GET"])
@require_viewer
def get_controls_view(framework):
    """Merged controls list: questionnaire + auto-findings + alerts for one framework."""
    from cy_comp.services.compliance import get_controls_view as _cv
    return jsonify({"controls": _cv(framework)})


# ── Compliance Alerts (query existing alerts table — no duplicate storage) ─────

def _severity_from_level(level: int) -> str:
    if level >= 12: return "critical"
    if level >= 10: return "high"
    if level >= 7:  return "medium"
    return "low"


@comp_bp.route("/alerts", methods=["GET"])
@require_viewer
def list_compliance_alerts():
    from cy_comp.models import db
    page      = int(request.args.get("page", 1))
    per_page  = min(int(request.args.get("per_page", 50)), 200)
    severity  = request.args.get("severity")
    framework = request.args.get("framework")
    offset    = (page - 1) * per_page

    rows  = []
    total = 0
    try:
        with db() as conn:
            cur = conn.cursor()
            where  = ["is_compliance_relevant = TRUE"]
            params = []

            if severity:
                # Map severity label to rule_level range
                sev_ranges = {
                    "critical": "rule_level >= 12",
                    "high":     "rule_level >= 10 AND rule_level < 12",
                    "medium":   "rule_level >= 7 AND rule_level < 10",
                    "low":      "rule_level < 7",
                }
                rng = sev_ranges.get(severity)
                if rng:
                    where.append(rng)

            if framework:
                where.append("%s = ANY(compliance_frameworks)")
                params.append(framework)

            clause = "WHERE " + " AND ".join(where)

            cur.execute(f"SELECT COUNT(*) FROM alerts {clause};", params)
            total = (cur.fetchone() or [0])[0]

            cur.execute(
                f"""
                SELECT id, wazuh_id, timestamp, agent_name, agent_ip,
                       rule_id, rule_desc, rule_level, base_score, category,
                       mitre_id, mitre_tactic, src_ip, username,
                       incident_id,
                       compliance_frameworks, compliance_controls, compliance_confidence
                FROM alerts {clause}
                ORDER BY timestamp DESC
                LIMIT %s OFFSET %s;
                """,
                params + [per_page, offset]
            )
            for r in cur.fetchall():
                rule_level = int(r[7] or 0)
                rows.append({
                    "id":                   r[0],
                    "external_id":          r[1],
                    "source_type":          "correlation_engine",
                    "timestamp":            r[2].isoformat() if r[2] else None,
                    "agent_name":           r[3],
                    "agent_ip":             r[4],
                    "rule_id":              r[5],
                    "title":                r[6] or "Security alert",
                    "description":          r[6] or "",
                    "rule_level":           rule_level,
                    "base_score":           float(r[8] or 0),
                    "category":             r[9],
                    "mitre_technique":      r[10],
                    "mitre_tactic":         r[11],
                    "src_ip":               r[12],
                    "username":             r[13],
                    "incident_id":          r[14],
                    "severity":             _severity_from_level(rule_level),
                    "compliance_frameworks": r[15] or [],
                    "controls":             r[16] or {},
                    "compliance_confidence": float(r[17] or 0),
                })
    except Exception as exc:
        log.error("list_compliance_alerts: %s", exc)
        return jsonify({"error": str(exc)}), 500

    return jsonify({"alerts": rows, "total": total, "page": page, "per_page": per_page})


@comp_bp.route("/alerts/sync", methods=["POST"])
@require_analyst
def trigger_siem_sync():
    from cy_comp.services.siem_bridge import sync
    try:
        result = sync()
        return jsonify({"status": "ok", "result": result})
    except Exception as exc:
        log.error("trigger_siem_sync: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Risk Register ─────────────────────────────────────────────────────────────

@comp_bp.route("/risks/auto-populate", methods=["POST"])
@require_analyst
def auto_populate_risks():
    """Create risk register entries from breach/warning findings."""
    from cy_comp.services.risk import auto_populate_from_findings
    try:
        result = auto_populate_from_findings(created_by=_email())
        return jsonify({"status": "ok", "result": result})
    except Exception as exc:
        log.error("auto_populate_risks: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/risks", methods=["GET"])
@require_viewer
def list_risks():
    from cy_comp.services.risk import list_risks as _list
    return jsonify({"risks": _list(
        category=request.args.get("category"),
        status=request.args.get("status"),
    )})


@comp_bp.route("/risks", methods=["POST"])
@require_analyst
def create_risk():
    from cy_comp.services.risk import create_risk as _create
    data = request.get_json() or {}
    if not data.get("title"):
        return jsonify({"error": "title is required"}), 400
    try:
        risk = _create(data, created_by=_email())
        return jsonify(risk), 201
    except Exception as exc:
        log.error("create_risk: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/risks/heatmap", methods=["GET"])
@require_viewer
def get_risk_heatmap():
    from cy_comp.services.risk import get_heatmap
    return jsonify(get_heatmap())


@comp_bp.route("/risks/<risk_id>", methods=["GET"])
@require_viewer
def get_risk(risk_id):
    from cy_comp.services.risk import get_risk as _get
    risk = _get(risk_id)
    if not risk:
        return jsonify({"error": "Risk not found"}), 404
    return jsonify(risk)


@comp_bp.route("/risks/<risk_id>", methods=["PUT"])
@require_analyst
def update_risk(risk_id):
    from cy_comp.services.risk import update_risk as _update
    data = request.get_json() or {}
    risk = _update(risk_id, data)
    if not risk:
        return jsonify({"error": "Risk not found"}), 404
    return jsonify(risk)


@comp_bp.route("/risks/<risk_id>", methods=["DELETE"])
@require_admin
def delete_risk(risk_id):
    from cy_comp.services.risk import delete_risk as _delete
    if not _delete(risk_id):
        return jsonify({"error": "Risk not found"}), 404
    return jsonify({"status": "deleted", "id": risk_id})


@comp_bp.route("/risks/<risk_id>/analyze", methods=["POST"])
@require_analyst
def ai_analyze_risk(risk_id):
    from cy_comp.services.risk import get_risk as _get
    from cy_comp.services.ai_analysis import analyze_risk
    risk = _get(risk_id)
    if not risk:
        return jsonify({"error": "Risk not found"}), 404
    text = analyze_risk(risk, created_by=_email())
    return jsonify({"risk_id": risk_id, "analysis": text})


# ── Risk Appetite ─────────────────────────────────────────────────────────────

@comp_bp.route("/appetite", methods=["GET"])
@require_viewer
def get_appetite():
    from cy_comp.services.risk import get_appetite as _get
    return jsonify(_get())


@comp_bp.route("/appetite", methods=["PUT"])
@require_admin
def update_appetite():
    from cy_comp.services.risk import update_appetite as _update
    data = request.get_json() or {}
    return jsonify(_update(data, updated_by=_email()))


# ── Compliance Findings ───────────────────────────────────────────────────────

@comp_bp.route("/findings", methods=["GET"])
@require_viewer
def list_findings():
    from cy_comp.models import db
    framework   = request.args.get("framework")
    severity    = request.args.get("severity")
    status      = request.args.get("status")
    verdict     = request.args.get("verdict")
    source_type = request.args.get("source_type")
    page        = int(request.args.get("page", 1))
    per_page    = min(int(request.args.get("per_page", 50)), 200)
    offset      = (page - 1) * per_page

    rows  = []
    total = 0
    try:
        with db() as conn:
            cur = conn.cursor()
            where, params = [], []
            if framework:   where.append("framework = %s");   params.append(framework)
            if severity:    where.append("severity = %s");    params.append(severity)
            if status:      where.append("status = %s");      params.append(status)
            if verdict:     where.append("verdict = %s");     params.append(verdict)
            if source_type: where.append("source_type = %s"); params.append(source_type)
            clause = ("WHERE " + " AND ".join(where)) if where else ""

            cur.execute(f"SELECT COUNT(*) FROM cy_comp_findings {clause};", params)
            total = (cur.fetchone() or [0])[0]

            cur.execute(
                f"""
                SELECT id, framework, control_id, control_name, severity, title,
                       description, ai_analysis, remediation, status, source_type,
                       assigned_to, alert_id, created_by, created_at, updated_at,
                       verdict, auto_generated, alert_count, last_seen_at, questionnaire_gap
                FROM cy_comp_findings {clause}
                ORDER BY
                    CASE verdict WHEN 'breach' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
                    created_at DESC
                LIMIT %s OFFSET %s;
                """,
                params + [per_page, offset]
            )
            for r in cur.fetchall():
                rows.append({
                    "id":               r[0],
                    "framework":        r[1],
                    "control_id":       r[2],
                    "control_name":     r[3],
                    "severity":         r[4],
                    "title":            r[5],
                    "description":      r[6],
                    "ai_analysis":      r[7],
                    "remediation":      r[8],
                    "status":           r[9],
                    "source_type":      r[10],
                    "assigned_to":      r[11],
                    "alert_id":         r[12],
                    "created_by":       r[13],
                    "created_at":       r[14].isoformat() if r[14] else None,
                    "updated_at":       r[15].isoformat() if r[15] else None,
                    "verdict":          r[16],
                    "auto_generated":   r[17],
                    "alert_count":      r[18] or 0,
                    "last_seen_at":     r[19].isoformat() if r[19] else None,
                    "questionnaire_gap": r[20],
                })
    except Exception as exc:
        log.error("list_findings: %s", exc)
        return jsonify({"error": str(exc)}), 500

    return jsonify({"findings": rows, "total": total, "page": page, "per_page": per_page})


@comp_bp.route("/findings", methods=["POST"])
@require_analyst
def create_finding():
    from cy_comp.models import db
    data = request.get_json() or {}
    if not data.get("title") or not data.get("framework"):
        return jsonify({"error": "title and framework are required"}), 400
    fid = str(uuid.uuid4())
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_findings
                    (id, framework, control_id, control_name, severity, title,
                     description, remediation, status, source_type, assigned_to,
                     alert_id, created_by, created_at, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW());
                """,
                (
                    fid,
                    data["framework"],
                    data.get("control_id"),
                    data.get("control_name"),
                    data.get("severity", "medium"),
                    data["title"],
                    data.get("description"),
                    data.get("remediation"),
                    data.get("status", "open"),
                    data.get("source_type", "manual"),
                    data.get("assigned_to"),
                    data.get("alert_id"),
                    _email(),
                )
            )
        return jsonify({"id": fid, "status": "created"}), 201
    except Exception as exc:
        log.error("create_finding: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/findings/<finding_id>", methods=["PUT"])
@require_analyst
def update_finding(finding_id):
    from cy_comp.models import db
    data = request.get_json() or {}
    allowed = ("framework", "control_id", "control_name", "severity", "title",
               "description", "remediation", "status", "source_type", "assigned_to")
    fields, params = [], []
    for col in allowed:
        if col in data:
            fields.append(f"{col} = %s"); params.append(data[col])
    if not fields:
        return jsonify({"error": "No updatable fields provided"}), 400
    fields.append("updated_at = NOW()")
    params.append(finding_id)
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                f"UPDATE cy_comp_findings SET {', '.join(fields)} WHERE id = %s;",
                params
            )
            if cur.rowcount == 0:
                return jsonify({"error": "Finding not found"}), 404
        return jsonify({"id": finding_id, "status": "updated"})
    except Exception as exc:
        log.error("update_finding: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/findings/<finding_id>", methods=["DELETE"])
@require_admin
def delete_finding(finding_id):
    from cy_comp.models import db
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM cy_comp_findings WHERE id = %s;", (finding_id,))
            if cur.rowcount == 0:
                return jsonify({"error": "Finding not found"}), 404
        return jsonify({"status": "deleted", "id": finding_id})
    except Exception as exc:
        log.error("delete_finding: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/findings/<finding_id>/analyze", methods=["POST"])
@require_analyst
def ai_analyze_finding(finding_id):
    from cy_comp.models import db
    from cy_comp.services.ai_analysis import analyze_finding
    row = None
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, framework, control_id, control_name, severity,
                       title, description, status
                FROM cy_comp_findings WHERE id = %s;
                """,
                (finding_id,)
            )
            r = cur.fetchone()
            if r:
                row = {
                    "id": r[0], "framework": r[1], "control_id": r[2],
                    "control_name": r[3], "severity": r[4], "title": r[5],
                    "description": r[6], "status": r[7],
                }
    except Exception as exc:
        log.error("ai_analyze_finding lookup: %s", exc)
        return jsonify({"error": str(exc)}), 500

    if not row:
        return jsonify({"error": "Finding not found"}), 404

    text = analyze_finding(row, created_by=_email())
    return jsonify({"finding_id": finding_id, "analysis": text})


# ── Controls Library ──────────────────────────────────────────────────────────

@comp_bp.route("/controls", methods=["GET"])
@require_viewer
def list_controls():
    from cy_comp.models import db
    framework = request.args.get("framework")
    status    = request.args.get("status")
    page      = int(request.args.get("page", 1))
    per_page  = min(int(request.args.get("per_page", 100)), 500)
    offset    = (page - 1) * per_page

    rows  = []
    total = 0
    try:
        with db() as conn:
            cur = conn.cursor()
            where, params = [], []
            if framework: where.append("framework = %s"); params.append(framework)
            if status:    where.append("implementation_status = %s"); params.append(status)
            clause = ("WHERE " + " AND ".join(where)) if where else ""

            cur.execute(f"SELECT COUNT(*) FROM cy_comp_controls {clause};", params)
            total = (cur.fetchone() or [0])[0]

            cur.execute(
                f"""
                SELECT id, framework, control_id, title, description, category,
                       implementation_status, owner, evidence_count, last_reviewed,
                       created_at, updated_at
                FROM cy_comp_controls {clause}
                ORDER BY framework, control_id LIMIT %s OFFSET %s;
                """,
                params + [per_page, offset]
            )
            for r in cur.fetchall():
                rows.append({
                    "id": r[0], "framework": r[1], "control_id": r[2],
                    "title": r[3], "description": r[4], "category": r[5],
                    "implementation_status": r[6], "owner": r[7],
                    "evidence_count": r[8],
                    "last_reviewed": r[9].isoformat() if r[9] else None,
                    "created_at": r[10].isoformat() if r[10] else None,
                    "updated_at": r[11].isoformat() if r[11] else None,
                })
    except Exception as exc:
        log.error("list_controls: %s", exc)
        return jsonify({"error": str(exc)}), 500

    return jsonify({"controls": rows, "total": total, "page": page, "per_page": per_page})


@comp_bp.route("/controls", methods=["POST"])
@require_analyst
def create_control():
    from cy_comp.models import db
    data = request.get_json() or {}
    if not data.get("title") or not data.get("framework"):
        return jsonify({"error": "title and framework are required"}), 400
    cid = str(uuid.uuid4())
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_controls
                    (id, framework, control_id, title, description, category,
                     implementation_status, owner, implementation_guidance,
                     test_procedure, created_by, created_at, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW());
                """,
                (
                    cid, data["framework"],
                    data.get("control_id"),
                    data["title"],
                    data.get("description"),
                    data.get("category"),
                    data.get("implementation_status", "not_implemented"),
                    data.get("owner"),
                    data.get("implementation_guidance"),
                    data.get("test_procedure"),
                    _email(),
                )
            )
        return jsonify({"id": cid, "status": "created"}), 201
    except Exception as exc:
        log.error("create_control: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/controls/<control_id>", methods=["PUT"])
@require_analyst
def update_control(control_id):
    from cy_comp.models import db
    data    = request.get_json() or {}
    allowed = ("title", "description", "category", "implementation_status",
               "owner", "implementation_guidance", "test_procedure")
    fields, params = [], []
    for col in allowed:
        if col in data:
            fields.append(f"{col} = %s"); params.append(data[col])
    if not fields:
        return jsonify({"error": "No updatable fields provided"}), 400
    fields.append("updated_at = NOW()")
    params.append(control_id)
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                f"UPDATE cy_comp_controls SET {', '.join(fields)} WHERE id = %s;",
                params
            )
            if cur.rowcount == 0:
                return jsonify({"error": "Control not found"}), 404
        return jsonify({"id": control_id, "status": "updated"})
    except Exception as exc:
        log.error("update_control: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Evidence ──────────────────────────────────────────────────────────────────

@comp_bp.route("/evidence", methods=["GET"])
@require_viewer
def list_evidence():
    from cy_comp.models import db
    finding_id = request.args.get("finding_id")
    control_id = request.args.get("control_id")
    rows = []
    try:
        with db() as conn:
            cur = conn.cursor()
            where, params = [], []
            if finding_id: where.append("finding_id = %s"); params.append(finding_id)
            if control_id: where.append("control_id = %s"); params.append(control_id)
            clause = ("WHERE " + " AND ".join(where)) if where else ""
            cur.execute(
                f"""
                SELECT id, title, type, file_type, description,
                       finding_id, control_id, ai_gap_status, ai_gap_analysis,
                       uploaded_by, created_at
                FROM cy_comp_evidence {clause} ORDER BY created_at DESC;
                """,
                params
            )
            for r in cur.fetchall():
                rows.append({
                    "id": r[0], "title": r[1], "type": r[2], "file_type": r[3],
                    "description": r[4], "finding_id": r[5], "control_id": r[6],
                    "ai_gap_status": r[7], "ai_gap_analysis": r[8],
                    "uploaded_by": r[9],
                    "created_at": r[10].isoformat() if r[10] else None,
                })
    except Exception as exc:
        log.error("list_evidence: %s", exc)
        return jsonify({"error": str(exc)}), 500
    return jsonify({"evidence": rows})


@comp_bp.route("/evidence", methods=["POST"])
@require_analyst
def upload_evidence():
    from cy_comp.models import db
    data = request.get_json() or {}
    if not data.get("title"):
        return jsonify({"error": "title is required"}), 400
    eid = str(uuid.uuid4())
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_evidence
                    (id, title, type, file_type, description,
                     finding_id, control_id, uploaded_by, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,NOW());
                """,
                (
                    eid, data["title"],
                    data.get("type", "document"),
                    data.get("file_type"),
                    data.get("description"),
                    data.get("finding_id"),
                    data.get("control_id"),
                    _email(),
                )
            )
        return jsonify({"id": eid, "status": "created"}), 201
    except Exception as exc:
        log.error("upload_evidence: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/evidence/<evidence_id>", methods=["DELETE"])
@require_admin
def delete_evidence(evidence_id):
    from cy_comp.models import db
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM cy_comp_evidence WHERE id = %s;", (evidence_id,))
            if cur.rowcount == 0:
                return jsonify({"error": "Evidence not found"}), 404
        return jsonify({"status": "deleted", "id": evidence_id})
    except Exception as exc:
        log.error("delete_evidence: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Reports ───────────────────────────────────────────────────────────────────

@comp_bp.route("/reports", methods=["GET"])
@require_viewer
def list_reports():
    from cy_comp.models import db
    rows = []
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, title, framework, overall_score,
                       generated_by, pdf_path, created_at
                FROM cy_comp_reports ORDER BY created_at DESC LIMIT 50;
                """
            )
            for r in cur.fetchall():
                rows.append({
                    "id": r[0], "title": r[1], "framework": r[2],
                    "overall_score": r[3], "generated_by": r[4],
                    "has_pdf": bool(r[5]),
                    "created_at": r[6].isoformat() if r[6] else None,
                })
    except Exception as exc:
        log.error("list_reports: %s", exc)
        return jsonify({"error": str(exc)}), 500
    return jsonify({"reports": rows})


@comp_bp.route("/reports/generate", methods=["POST"])
@require_analyst
def generate_report():
    from cy_comp.services.report import create_report_job

    data        = request.get_json() or {}
    framework   = data.get("framework", "all")
    period_start = data.get("period_start", "")
    period_end   = data.get("period_end", "")
    email        = _email()

    # Create pending job row
    job_id = create_report_job(framework, period_start, period_end, email)

    # Schedule one-off APScheduler job using the existing scheduler instance
    try:
        from blueprints.scheduler.routes import _scheduler, _scheduler_owner
        from cy_comp.services.report import generate_report_job

        if _scheduler and _scheduler_owner:
            _scheduler.add_job(
                generate_report_job,
                trigger="date",       # one-off, run immediately
                args=[job_id],
                id=f"comp_report_{job_id}",
                replace_existing=True,
                misfire_grace_time=300,
            )
            log.info("generate_report: APScheduler job queued job_id=%s", job_id)
        else:
            # Not the scheduler-owning worker — run inline (non-optimal but safe fallback)
            log.warning("generate_report: scheduler not owned by this worker; running inline")
            import threading
            t = threading.Thread(target=generate_report_job, args=(job_id,), daemon=True)
            t.start()
    except Exception as exc:
        log.error("generate_report: scheduler enqueue failed: %s", exc)
        # Fall back to thread
        import threading
        from cy_comp.services.report import generate_report_job
        t = threading.Thread(target=generate_report_job, args=(job_id,), daemon=True)
        t.start()

    return jsonify({"job_id": job_id, "status": "pending"}), 202


@comp_bp.route("/reports/jobs/<job_id>", methods=["GET"])
@require_analyst
def poll_report_job(job_id):
    from cy_comp.services.report import poll_job
    job = poll_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@comp_bp.route("/reports/<report_id>/download", methods=["GET"])
@require_viewer
def download_report(report_id):
    from cy_comp.models import db
    import os
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT pdf_path, title FROM cy_comp_reports WHERE id = %s;",
                (report_id,)
            )
            row = cur.fetchone()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    if not row:
        return jsonify({"error": "Report not found"}), 404

    pdf_path, title = row
    if pdf_path and os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True,
                         download_name=f"{title or report_id}.pdf",
                         mimetype="application/pdf")

    # Fall back to JSON
    from cy_comp.services.report import REPORTS_DIR
    json_files = list(REPORTS_DIR.glob(f"*{report_id}*.json")) if REPORTS_DIR.exists() else []
    if json_files:
        return send_file(str(json_files[0]), as_attachment=True,
                         download_name=f"{title or report_id}.json",
                         mimetype="application/json")

    return jsonify({"error": "Report file not available"}), 404


# ── Policy Documents ──────────────────────────────────────────────────────────

@comp_bp.route("/policy-docs/collections", methods=["GET"])
@require_viewer
def list_collections():
    from cy_comp.services.policy_rag import list_collections as _list
    return jsonify({"collections": _list()})


@comp_bp.route("/policy-docs/collections", methods=["POST"])
@require_admin
def create_collection():
    from cy_comp.services.policy_rag import create_collection as _create
    data      = request.get_json() or {}
    framework = data.get("framework", "").strip()
    if not framework:
        return jsonify({"error": "framework is required"}), 400
    return jsonify(_create(framework)), 201


@comp_bp.route("/policy-docs/collections/<collection_id>/documents", methods=["GET"])
@require_viewer
def list_documents(collection_id):
    from cy_comp.services.policy_rag import list_documents as _list
    return jsonify({"documents": _list(collection_id)})


@comp_bp.route("/policy-docs/collections/<collection_id>/documents", methods=["POST"])
@require_analyst
def upload_document(collection_id):
    from cy_comp.services.policy_rag import upload_document as _upload
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file     = request.files["file"]
    metadata = {
        "framework": request.form.get("framework") or collection_id.replace("policy-", ""),
        "tag":       request.form.get("tag") or None,
    }
    try:
        doc = _upload(collection_id, file, metadata, uploaded_by=_email())
        return jsonify(doc), 201
    except Exception as exc:
        log.error("upload_document: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/policy-docs/documents/<doc_id>", methods=["DELETE"])
@require_admin
def delete_document(doc_id):
    from cy_comp.services.policy_rag import delete_document as _delete
    if not _delete(doc_id):
        return jsonify({"error": "Document not found"}), 404
    return jsonify({"status": "deleted", "id": doc_id})


@comp_bp.route("/policy-docs/collections/<collection_id>/reindex", methods=["POST"])
@require_admin
def reindex_collection(collection_id):
    from cy_comp.services.policy_rag import reindex_collection as _reindex
    return jsonify(_reindex(collection_id))


# ── Framework Documents (System Settings → Security Compliance) ───────────────

@comp_bp.route("/framework-docs/frameworks", methods=["GET"])
@require_admin
def list_framework_folders():
    from cy_comp.services.policy_rag import ensure_framework_collections as _ensure
    return jsonify({"frameworks": _ensure()})


@comp_bp.route("/framework-docs/<framework>/documents", methods=["GET"])
@require_viewer
def list_framework_docs(framework):
    from cy_comp.services.policy_rag import list_framework_docs as _list
    return jsonify({"documents": _list(framework)})


@comp_bp.route("/framework-docs/<framework>/documents", methods=["POST"])
@require_admin
def upload_framework_doc(framework):
    from cy_comp.services.policy_rag import upload_framework_doc as _upload
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    locked = request.form.get("locked", "false").lower() == "true"
    try:
        doc = _upload(framework, request.files["file"], locked, uploaded_by=_email())
        return jsonify(doc), 201
    except Exception as exc:
        log.error("upload_framework_doc: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/framework-docs/documents/<doc_id>/lock", methods=["PUT"])
@require_admin
def toggle_framework_lock(doc_id):
    from cy_comp.services.policy_rag import toggle_framework_doc_lock as _toggle
    data   = request.get_json() or {}
    locked = bool(data.get("locked", False))
    if _toggle(doc_id, locked):
        return jsonify({"status": "ok", "locked": locked})
    return jsonify({"error": "Document not found"}), 404


@comp_bp.route("/framework-docs/documents/<doc_id>", methods=["DELETE"])
@require_admin
def delete_framework_doc(doc_id):
    from cy_comp.services.policy_rag import delete_framework_doc as _delete
    ok, reason = _delete(doc_id)
    if ok:
        return jsonify({"status": "deleted", "id": doc_id})
    if "locked" in reason.lower():
        return jsonify({"error": reason}), 409
    return jsonify({"error": reason}), 404


# ── Settings ──────────────────────────────────────────────────────────────────

@comp_bp.route("/settings", methods=["GET"])
@require_admin
def get_comp_settings():
    import json as _json
    from core.config import AI_SETTINGS_FILE
    settings = {}
    if AI_SETTINGS_FILE.exists():
        try:
            settings = _json.loads(AI_SETTINGS_FILE.read_text())
        except Exception:
            pass

    # CyMind integration is stored under cymind_integration{} by the Platform Extensions flow
    cymind_int = settings.get("cymind_integration", {})
    global_cymind_enabled = bool(cymind_int.get("enabled")) and bool(
        cymind_int.get("apiKey") or cymind_int.get("chatApiKey")
    )
    global_cymind_url = (
        cymind_int.get("cymindUrl")
        or settings.get("fields", {}).get("baseUrl")
        or settings.get("cymind_url")
        or ""
    )

    return jsonify({
        # If global CyMind is enabled, URL is inherited and we surface it read-only
        "cymind_url":              global_cymind_url,
        "cymind_admin_key":        "***" if settings.get("cymind_admin_key") else "",
        "comp_reports_dir":        str(settings.get("comp_reports_dir", "/var/log/cycentra/cy-comp/reports")),
        "global_cymind_enabled":   global_cymind_enabled,
        "global_cymind_url":       global_cymind_url,
    })


@comp_bp.route("/settings", methods=["PUT"])
@require_admin
def update_comp_settings():
    import json as _json
    from core.config import AI_SETTINGS_FILE
    data = request.get_json() or {}
    allowed = ("cymind_url", "cymind_admin_key", "comp_reports_dir")
    try:
        current = {}
        if AI_SETTINGS_FILE.exists():
            current = _json.loads(AI_SETTINGS_FILE.read_text())
        for key in allowed:
            if key in data and data[key] not in (None, "***"):
                current[key] = data[key]
        AI_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        AI_SETTINGS_FILE.write_text(_json.dumps(current, indent=2))
        return jsonify({"status": "saved"})
    except Exception as exc:
        log.error("update_comp_settings: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/settings/siem-connections", methods=["GET"])
@require_admin
def list_siem_connections():
    from cy_comp.models import db
    rows = []
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, name, siem_type, host, port, username,
                       is_active, last_sync, created_at
                FROM cy_comp_siem_connections ORDER BY created_at DESC;
                """
            )
            for r in cur.fetchall():
                rows.append({
                    "id": r[0], "name": r[1], "siem_type": r[2], "host": r[3],
                    "port": r[4], "username": r[5], "is_active": r[6],
                    "last_sync": r[7].isoformat() if r[7] else None,
                    "created_at": r[8].isoformat() if r[8] else None,
                })
    except Exception as exc:
        log.error("list_siem_connections: %s", exc)
        return jsonify({"error": str(exc)}), 500
    return jsonify({"connections": rows})


@comp_bp.route("/settings/siem-connections", methods=["POST"])
@require_admin
def create_siem_connection():
    from cy_comp.models import db
    data = request.get_json() or {}
    if not data.get("name") or not data.get("siem_type"):
        return jsonify({"error": "name and siem_type are required"}), 400
    cid = str(uuid.uuid4())
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_siem_connections
                    (id, name, siem_type, host, port, username,
                     is_active, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,NOW());
                """,
                (
                    cid, data["name"], data["siem_type"],
                    data.get("host"), data.get("port", 55000),
                    data.get("username"), data.get("is_active", True),
                )
            )
        return jsonify({"id": cid, "status": "created"}), 201
    except Exception as exc:
        log.error("create_siem_connection: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/settings/siem-connections/<conn_id>", methods=["PUT"])
@require_admin
def update_siem_connection(conn_id):
    from cy_comp.models import db
    data    = request.get_json() or {}
    allowed = ("name", "siem_type", "host", "port", "username", "is_active")
    fields, params = [], []
    for col in allowed:
        if col in data:
            fields.append(f"{col} = %s"); params.append(data[col])
    if not fields:
        return jsonify({"error": "No updatable fields provided"}), 400
    params.append(conn_id)
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                f"UPDATE cy_comp_siem_connections SET {', '.join(fields)} WHERE id = %s;",
                params
            )
            if cur.rowcount == 0:
                return jsonify({"error": "Connection not found"}), 404
        return jsonify({"id": conn_id, "status": "updated"})
    except Exception as exc:
        log.error("update_siem_connection: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/settings/siem-connections/<conn_id>", methods=["DELETE"])
@require_admin
def delete_siem_connection(conn_id):
    from cy_comp.models import db
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM cy_comp_siem_connections WHERE id = %s;", (conn_id,))
            if cur.rowcount == 0:
                return jsonify({"error": "Connection not found"}), 404
        return jsonify({"status": "deleted", "id": conn_id})
    except Exception as exc:
        log.error("delete_siem_connection: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Questionnaire ─────────────────────────────────────────────────────────────

@comp_bp.route("/questionnaire/seed", methods=["POST"])
@require_admin
def seed_questionnaire_templates():
    from cy_comp.services.questionnaire import seed_templates
    force = request.get_json(silent=True) or {}
    try:
        result = seed_templates(force=bool(force.get("force")))
        return jsonify({"status": "ok", "result": result})
    except Exception as exc:
        log.error("seed_questionnaire_templates: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/questionnaire/hub", methods=["GET"])
@require_viewer
def questionnaire_hub():
    """All-frameworks completion + score summary for the hub page."""
    from cy_comp.services.questionnaire import get_all_completions
    return jsonify({"frameworks": get_all_completions()})


@comp_bp.route("/questionnaire/<framework>", methods=["GET"])
@require_viewer
def get_questionnaire(framework):
    """Templates + saved responses for one framework."""
    from cy_comp.services.questionnaire import get_templates, get_responses, score_framework
    templates  = get_templates(framework)
    responses  = get_responses(framework)
    scored     = score_framework(framework)
    return jsonify({
        "framework": framework,
        "templates": templates,
        "responses": responses,
        "score":     scored,
    })


@comp_bp.route("/questionnaire/<framework>/respond", methods=["POST"])
@require_analyst
def save_questionnaire_responses(framework):
    """Bulk-save answers for a framework. Body: {answers: [{question_id, response, notes?}]}"""
    from cy_comp.services.questionnaire import save_bulk_responses
    data    = request.get_json() or {}
    answers = data.get("answers", [])
    if not answers:
        return jsonify({"error": "No answers provided"}), 400
    try:
        result = save_bulk_responses(framework, answers, responded_by=_email())
        return jsonify({"status": "ok", "result": result})
    except Exception as exc:
        log.error("save_questionnaire_responses: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/questionnaire/<framework>/respond/<question_id>", methods=["PUT"])
@require_analyst
def save_single_response(framework, question_id):
    """Save one answer. Body: {response, notes?, evidence_refs?}"""
    from cy_comp.services.questionnaire import save_response
    data = request.get_json() or {}
    if "response" not in data:
        return jsonify({"error": "response is required"}), 400
    try:
        result = save_response(
            framework=framework,
            question_id=question_id,
            response=data["response"],
            notes=data.get("notes"),
            evidence_refs=data.get("evidence_refs"),
            responded_by=_email(),
        )
        return jsonify(result)
    except Exception as exc:
        log.error("save_single_response: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/questionnaire/<framework>/score", methods=["GET"])
@require_viewer
def get_questionnaire_score(framework):
    from cy_comp.services.questionnaire import score_framework
    return jsonify(score_framework(framework))


@comp_bp.route("/questionnaire/<framework>/generate-findings", methods=["POST"])
@require_analyst
def generate_questionnaire_findings(framework):
    """Create cy_comp_findings rows for all gap questions in a framework."""
    from cy_comp.services.questionnaire import generate_gap_findings
    try:
        result = generate_gap_findings(framework, created_by=_email())
        return jsonify({"status": "ok", "result": result})
    except Exception as exc:
        log.error("generate_questionnaire_findings: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Auto Findings ─────────────────────────────────────────────────────────────

@comp_bp.route("/findings/auto-generate", methods=["POST"])
@require_analyst
def auto_generate_findings():
    """
    Generate / refresh cy_comp_findings from compliance-relevant alerts.
    Body (optional): {framework: "nis2"}  — if omitted, runs for all frameworks.
    """
    from cy_comp.services.auto_findings import generate_findings_from_alerts
    data      = request.get_json(silent=True) or {}
    framework = data.get("framework")
    try:
        result = generate_findings_from_alerts(framework=framework, created_by=_email())
        return jsonify({"status": "ok", "result": result})
    except Exception as exc:
        log.error("auto_generate_findings: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/findings/verdicts", methods=["GET"])
@require_viewer
def findings_verdict_summary():
    """Breach / warning / compliant counts for the dashboard."""
    from cy_comp.services.auto_findings import get_findings_summary
    return jsonify(get_findings_summary())


@comp_bp.route("/findings/<finding_id>/remediation", methods=["GET"])
@require_viewer
def get_finding_remediation(finding_id):
    """Return remediation guidance for a specific finding (looks up MITRE technique)."""
    from cy_comp.models import db
    from cy_comp.services.auto_findings import get_remediation_for_mitre
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT control_id, title FROM cy_comp_findings WHERE id = %s;",
                (finding_id,)
            )
            row = cur.fetchone()
        if not row:
            return jsonify({"error": "Finding not found"}), 404
        control_id = row[0] or ""
        mitre_id   = control_id.split(",")[0].strip() if control_id else None
        rem        = get_remediation_for_mitre(mitre_id)
        return jsonify(rem)
    except Exception as exc:
        log.error("get_finding_remediation: %s", exc)
        return jsonify({"error": str(exc)}), 500
