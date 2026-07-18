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
    fw_param   = request.args.get("frameworks", "")
    frameworks = [f.strip() for f in fw_param.split(",") if f.strip()] or None
    return jsonify(get_dashboard_summary(frameworks=frameworks))


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


@comp_bp.route("/policy-docs/documents/<doc_id>/download", methods=["GET"])
@require_viewer
def download_policy_document(doc_id):
    """Serve the local Cy360-server copy of a policy document."""
    from core.config import POLICY_DOCS_DIR
    from cy_comp.services.policy_rag import get_document_file_path

    result = get_document_file_path(doc_id)
    if not result:
        return jsonify({"error": "Document not stored locally on this server"}), 404
    file_path, name = result

    candidate = Path(file_path)
    try:
        candidate = candidate.resolve()
        candidate.relative_to(POLICY_DOCS_DIR.resolve())
    except (ValueError, OSError):
        return jsonify({"error": "Invalid document path"}), 400

    if not candidate.is_file():
        return jsonify({"error": "Document file missing on disk"}), 404

    return send_file(str(candidate), as_attachment=True, download_name=name)


@comp_bp.route("/policy-docs/collections/<collection_id>/reindex", methods=["POST"])
@require_admin
def reindex_collection(collection_id):
    from cy_comp.services.policy_rag import reindex_collection as _reindex
    return jsonify(_reindex(collection_id))


# ── Policy Analysis (RAG → Questionnaire auto-scoring) ───────────────────────

@comp_bp.route("/policy-docs/upload-multi", methods=["POST"])
@require_analyst
def upload_document_multi():
    """
    Upload a policy document to the shared org-policies collection.
    Automatically detects which compliance frameworks the document covers and
    stores them in mapped_frameworks[].

    Multipart form:
      file      — document file (required)
      framework — optional hint for the primary framework
      tag       — optional label

    Response: {id, name, collection_id, framework, detected_frameworks[], indexed, ...}
    """
    from cy_comp.services.policy_rag import upload_document_multi_framework as _upload_multi
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    metadata = {
        "framework": request.form.get("framework") or None,
        "tag":       request.form.get("tag") or None,
    }
    try:
        doc = _upload_multi(request.files["file"], metadata, uploaded_by=_email())
        return jsonify(doc), 201
    except Exception as exc:
        log.error("upload_document_multi: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/policy-docs/analyze-framework", methods=["POST"])
@require_analyst
def analyze_policy_framework():
    """
    Start a background job that queries org-policies RAG for each questionnaire
    question in the given framework and scores answers via CyMind LLM.

    Body: {framework: str, overwrite: bool}   overwrite=true rewrites already-answered questions
    Returns: {job_id, framework, status: "pending"}   — poll analyze-jobs/{job_id} for progress
    """
    from cy_comp.services.policy_analysis import start_analysis_job
    data      = request.get_json() or {}
    framework = data.get("framework", "").strip().lower()
    overwrite = bool(data.get("overwrite", False))
    if not framework:
        return jsonify({"error": "framework is required"}), 400
    job_id = start_analysis_job(framework, overwrite, _email())
    return jsonify({"job_id": job_id, "framework": framework, "status": "pending"}), 202


@comp_bp.route("/policy-docs/analyze-jobs/<job_id>", methods=["GET"])
@require_viewer
def get_analysis_job(job_id):
    """Poll policy analysis job status."""
    from cy_comp.services.policy_analysis import get_job
    job = get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


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


# ── Statement of Applicability (SoA) — ISO 27001 Cl.6.1.3(d) ─────────────────

@comp_bp.route("/soa/iso27001", methods=["GET"])
@require_viewer
def get_soa():
    """Full SoA: all 93 Annex A controls with derived status, include/exclude, justification."""
    from cy_comp.services.soa import get_soa as _get_soa
    try:
        return jsonify(_get_soa())
    except Exception as exc:
        log.error("GET /soa/iso27001: %s", exc)
        return jsonify({"error": "Failed to load SoA"}), 500


@comp_bp.route("/soa/iso27001/<control_id>", methods=["PUT"])
@require_analyst
def update_soa_entry(control_id: str):
    """Update a single control's include/exclude decision and justification."""
    from cy_comp.services.soa import update_soa_entry as _update
    body = request.get_json(silent=True) or {}
    included      = bool(body.get("included", True))
    justification = body.get("justification") or None
    try:
        result = _update(
            control_id    = control_id,
            included      = included,
            justification = justification,
            updated_by    = _email(),
        )
        return jsonify(result)
    except Exception as exc:
        log.error("PUT /soa/iso27001/%s: %s", control_id, exc)
        return jsonify({"error": "Failed to update SoA entry"}), 500


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


@comp_bp.route("/questionnaire/<framework>/respond/<question_id>", methods=["DELETE"])
@require_analyst
def reset_single_response(framework, question_id):
    """Delete a single saved answer, returning the question to unanswered state."""
    from cy_comp.services.questionnaire import delete_response
    deleted = delete_response(framework, question_id)
    if not deleted:
        return jsonify({"error": "Response not found"}), 404
    return jsonify({"status": "reset", "framework": framework, "question_id": question_id})


@comp_bp.route("/questionnaire/<framework>/responses", methods=["DELETE"])
@require_analyst
def reset_framework_responses(framework):
    """
    Delete all saved answers for a single framework.
    Returns {deleted: N}.
    """
    from cy_comp.services.questionnaire import delete_framework_responses
    try:
        deleted = delete_framework_responses(framework)
        return jsonify({"status": "reset", "framework": framework, "deleted": deleted})
    except Exception as exc:
        log.error("reset_framework_responses(%s): %s", framework, exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/questionnaire/responses", methods=["DELETE"])
@require_admin
def reset_all_responses():
    """
    Delete ALL saved questionnaire answers across every framework.
    Admin-only. Returns {deleted: N}.
    """
    from cy_comp.services.questionnaire import delete_all_responses
    try:
        deleted = delete_all_responses()
        return jsonify({"status": "reset_all", "deleted": deleted})
    except Exception as exc:
        log.error("reset_all_responses: %s", exc)
        return jsonify({"error": str(exc)}), 500


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


# ── Cross-Framework Correlations & Propagation ────────────────────────────────

@comp_bp.route("/questionnaire/<framework>/correlations", methods=["GET"])
@require_viewer
def get_framework_correlations(framework):
    """
    Return all propagation suggestions for a framework.
    Finds every answered question in `framework` and identifies correlated
    questions in other frameworks that are still unanswered.

    Response: {framework, suggestions: [{cluster_id, cluster_theme, answered, suggestions:[]}]}
    """
    from cy_comp.services.questionnaire import get_propagation_suggestions
    try:
        result = get_propagation_suggestions(framework)
        return jsonify({"framework": framework, "suggestions": result})
    except Exception as exc:
        log.error("get_framework_correlations(%s): %s", framework, exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/questionnaire/propagate", methods=["POST"])
@require_analyst
def propagate_response():
    """
    Apply a source answer to selected correlated questions in other frameworks.

    Body: {
      source_question_id: str,
      source_framework:   str,
      response:           str,
      accepted_targets:   [question_id, ...]   — subset of correlated qids to propagate to
    }
    Response: {propagated, skipped, errors}
    """
    from cy_comp.services.questionnaire import propagate_response as _propagate
    data = request.get_json() or {}
    src_qid = data.get("source_question_id", "").strip()
    src_fw  = data.get("source_framework", "").strip()
    resp    = data.get("response", "").strip()
    targets = data.get("accepted_targets", [])

    if not src_qid or not src_fw or not resp:
        return jsonify({"error": "source_question_id, source_framework, and response are required"}), 400
    if not isinstance(targets, list) or not targets:
        return jsonify({"error": "accepted_targets must be a non-empty list"}), 400

    try:
        result = _propagate(
            source_question_id=src_qid,
            source_framework=src_fw,
            response=resp,
            target_question_ids=targets,
            responded_by=_email(),
        )
        return jsonify({"status": "ok", "result": result})
    except Exception as exc:
        log.error("propagate_response: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/questionnaire/reject-propagation", methods=["POST"])
@require_analyst
def reject_propagation():
    """
    Mark a specific correlated question as user-rejected, suppressing the suggestion.

    Body: {source_question_id: str, target_question_id: str}
    """
    from cy_comp.services.questionnaire import reject_propagation as _reject
    data = request.get_json() or {}
    src = data.get("source_question_id", "").strip()
    tgt = data.get("target_question_id", "").strip()
    if not src or not tgt:
        return jsonify({"error": "source_question_id and target_question_id are required"}), 400
    ok = _reject(src, tgt)
    if not ok:
        return jsonify({"error": "Correlation not found or already resolved"}), 404
    return jsonify({"status": "rejected", "source": src, "target": tgt})


@comp_bp.route("/question-correlations", methods=["GET"])
@require_viewer
def list_question_correlations():
    """
    Read-only view of the correlation table.
    Query params: cluster_id=  or  question_id=  (optional filters)

    Response: {correlations: [...], total: N}
    """
    from cy_comp.models import db as _db
    cluster_id  = request.args.get("cluster_id")
    question_id = request.args.get("question_id")
    rows = []
    try:
        with _db() as conn:
            cur = conn.cursor()
            where, params = [], []
            if cluster_id:
                where.append("cluster_id = %s")
                params.append(cluster_id)
            if question_id:
                where.append("(question_id_a = %s OR question_id_b = %s)")
                params.extend([question_id, question_id])
            clause = ("WHERE " + " AND ".join(where)) if where else ""
            cur.execute(
                f"""
                SELECT id, cluster_id, cluster_theme, framework_a, question_id_a,
                       framework_b, question_id_b, similarity_type, confidence
                FROM cy_comp_question_correlations {clause}
                ORDER BY cluster_id, framework_a, question_id_a
                LIMIT 1000;
                """,
                params
            )
            for r in cur.fetchall():
                rows.append({
                    "id":              r[0],
                    "cluster_id":      r[1],
                    "cluster_theme":   r[2],
                    "framework_a":     r[3],
                    "question_id_a":   r[4],
                    "framework_b":     r[5],
                    "question_id_b":   r[6],
                    "similarity_type": r[7],
                    "confidence":      float(r[8]),
                })
    except Exception as exc:
        log.error("list_question_correlations: %s", exc)
        return jsonify({"error": str(exc)}), 500
    return jsonify({"correlations": rows, "total": len(rows)})


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


@comp_bp.route("/findings/re-enrich-alerts", methods=["POST"])
@require_analyst
def re_enrich_alerts():
    """
    Reset compliance enrichment on all alerts so the siem_bridge re-tags them
    with the current (expanded) framework mappings.
    Safe to run after enrichment.py is updated.
    """
    from cy_comp.models import db
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE alerts SET is_compliance_relevant = NULL, compliance_frameworks = NULL, "
                "compliance_controls = NULL, compliance_confidence = NULL;"
            )
            reset_count = cur.rowcount
        from cy_comp.services.siem_bridge import enrich_alerts_pass
        result = enrich_alerts_pass(batch_size=5000)
        return jsonify({"status": "ok", "reset": reset_count, "enrichment": result})
    except Exception as exc:
        log.error("re_enrich_alerts: %s", exc)
        return jsonify({"error": str(exc)}), 500


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


# ══════════════════════════════════════════════════════════════════════════════
# NEW ROUTES — Gap closure enhancements
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. AI Control Recommendations ────────────────────────────────────────────

@comp_bp.route("/controls/recommend", methods=["POST"])
@require_analyst
def recommend_controls():
    """
    POST /api/comp/controls/recommend
    Body: {framework, gap_description}
    Returns AI-suggested control IDs and remediation priority.
    Uses existing suggest_controls() service — no new AI logic.
    """
    body = request.get_json(silent=True) or {}
    framework       = body.get("framework", "")
    gap_description = body.get("gap_description", "")
    if not framework or not gap_description:
        return jsonify({"error": "framework and gap_description are required"}), 400
    try:
        from cy_comp.services.ai_analysis import suggest_controls
        result = suggest_controls(framework, gap_description, created_by=_email())
        return jsonify(result)
    except Exception as exc:
        log.error("recommend_controls: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── 2. AI Policy Draft Generation ────────────────────────────────────────────

@comp_bp.route("/policy-docs/draft", methods=["POST"])
@require_analyst
def draft_policy_clause():
    """
    POST /api/comp/policy-docs/draft
    Body: {framework, control_id, control_name, gap_description, existing_policy_snippet?}
    Returns a draft policy clause + implementation guidance.
    """
    body = request.get_json(silent=True) or {}
    framework       = body.get("framework", "")
    control_id      = body.get("control_id", "")
    control_name    = body.get("control_name", "")
    gap_description = body.get("gap_description", "")
    if not framework or not gap_description:
        return jsonify({"error": "framework and gap_description are required"}), 400
    try:
        from cy_comp.services.ai_analysis import generate_policy_draft
        result = generate_policy_draft(
            framework=framework,
            control_id=control_id,
            control_name=control_name,
            gap_description=gap_description,
            existing_policy_snippet=body.get("existing_policy_snippet", ""),
            created_by=_email(),
        )
        return jsonify(result)
    except Exception as exc:
        log.error("draft_policy_clause: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/policy-docs/save-draft", methods=["POST"])
@require_analyst
def save_policy_draft():
    """
    POST /api/comp/policy-docs/save-draft
    Body: {text, filename?, framework?, tag?}
    Saves AI-generated policy clause text to the org-policies RAG collection.
    """
    body = request.get_json(silent=True) or {}
    text = (body.get("text") or "").strip()
    if not text:
        return jsonify({"error": "text is required"}), 400
    framework = body.get("framework", "")
    filename  = (body.get("filename") or "").strip() or \
                f"policy_clause_{framework}_{str(uuid.uuid4())[:8]}.txt"
    tag       = body.get("tag") or "security"
    try:
        from cy_comp.services.policy_rag import save_text_as_document
        doc = save_text_as_document(
            collection_id="org-policies",
            text=text,
            filename=filename,
            metadata={"framework": framework, "tag": tag},
            uploaded_by=_email(),
        )
        return jsonify(doc), 201
    except Exception as exc:
        log.error("save_policy_draft: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── 3. Executive Risk Copilot ─────────────────────────────────────────────────

@comp_bp.route("/ask", methods=["POST"])
@require_viewer
def executive_copilot():
    """
    POST /api/comp/ask
    Body: {question, frameworks?}
    Answers a natural-language question about the live compliance posture.
    Pre-loads the dashboard summary as context before calling CyMind.
    """
    body      = request.get_json(silent=True) or {}
    question  = (body.get("question") or "").strip()
    if not question:
        return jsonify({"error": "question is required"}), 400

    try:
        from cy_comp.services.compliance import get_dashboard_summary
        from cy_comp.services.ai_analysis import ask_copilot
        frameworks   = body.get("frameworks") or None
        context_data = get_dashboard_summary(frameworks=frameworks)
        answer       = ask_copilot(question, context_data, created_by=_email())
        return jsonify({"question": question, "answer": answer})
    except Exception as exc:
        log.error("executive_copilot: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── 4. What-If Score Simulation ───────────────────────────────────────────────

@comp_bp.route("/simulate", methods=["POST"])
@require_viewer
def simulate_score():
    """
    POST /api/comp/simulate
    Body: {framework, overrides: [{question_id, score}]}
    Returns {actual_score, simulated_score, delta, changed_questions}.
    Stateless — no DB writes.
    """
    body      = request.get_json(silent=True) or {}
    framework = body.get("framework", "")
    overrides = body.get("overrides", [])
    if not framework:
        return jsonify({"error": "framework is required"}), 400
    if not isinstance(overrides, list):
        return jsonify({"error": "overrides must be a list of {question_id, score}"}), 400
    try:
        from cy_comp.services.compliance import simulate_framework_score
        result = simulate_framework_score(framework, overrides)
        return jsonify(result)
    except Exception as exc:
        log.error("simulate_score: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── 5. On-Demand Score Refresh ────────────────────────────────────────────────

@comp_bp.route("/dashboard/refresh", methods=["POST"])
@require_analyst
def refresh_dashboard():
    """
    POST /api/comp/dashboard/refresh
    Triggers incremental SIEM sync + recomputes all framework scores.
    Returns updated scores immediately.
    Optional body: {frameworks: [...]} to scope refresh.
    """
    body       = request.get_json(silent=True) or {}
    frameworks = body.get("frameworks") or None
    try:
        from cy_comp.services.compliance import refresh_scores
        result = refresh_scores(frameworks=frameworks)
        return jsonify(result)
    except Exception as exc:
        log.error("refresh_dashboard: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── 6. Cyber Resilience Score ─────────────────────────────────────────────────

@comp_bp.route("/resilience-score", methods=["GET"])
@require_viewer
def get_resilience_score():
    """
    GET /api/comp/resilience-score
    Returns composite cyber resilience score (0-100) across 4 dimensions:
    resilience testing, incident recovery (MTTR), backup/recovery, continuity planning.
    """
    try:
        from cy_comp.services.compliance import get_resilience_score as _score
        return jsonify(_score())
    except Exception as exc:
        log.error("get_resilience_score: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── 7. Unified Board Report ────────────────────────────────────────────────────

@comp_bp.route("/reports/generate-board", methods=["POST"])
@require_analyst
def generate_board_report():
    """
    POST /api/comp/reports/generate-board
    Body: {period_start, period_end}
    Creates a job and schedules a board-ready PDF/JSON report.
    Aggregates all frameworks, top risks, critical findings, resilience score,
    alert trend, and top exposures into a single executive document.
    """
    body         = request.get_json(silent=True) or {}
    period_start = body.get("period_start", "")
    period_end   = body.get("period_end", "")
    if not period_start or not period_end:
        return jsonify({"error": "period_start and period_end are required"}), 400
    try:
        from cy_comp.services.report import create_board_report_job, generate_board_report_job
        job_id = create_board_report_job(
            requested_by=_email(),
            period_start=period_start,
            period_end=period_end,
        )
        try:
            from blueprints.scheduler.routes import _scheduler, _scheduler_owner
            _scheduler.add_job(
                generate_board_report_job,
                args=[job_id],
                id=f"board_report_{job_id}",
                replace_existing=True,
            )
        except Exception:
            import threading
            threading.Thread(target=generate_board_report_job, args=(job_id,), daemon=True).start()

        return jsonify({"job_id": job_id, "status": "pending"}), 202
    except Exception as exc:
        log.error("generate_board_report: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── 8. SIEM Evidence → cy_comp_evidence Bridge ────────────────────────────────

@comp_bp.route("/evidence/sync-siem", methods=["POST"])
@require_analyst
def sync_evidence_from_siem():
    """
    POST /api/comp/evidence/sync-siem
    Imports autonomous evidence items collected by the SIEM Investigation Engine
    into cy_comp_evidence, linked to compliance findings where possible.
    Idempotent — skips already-imported items via source_ref deduplication.
    Optional body: {limit: 200}
    """
    body  = request.get_json(silent=True) or {}
    limit = int(body.get("limit", 200))
    try:
        from cy_comp.services.siem_bridge import sync_siem_evidence_to_comp
        result = sync_siem_evidence_to_comp(limit=limit)
        return jsonify(result)
    except Exception as exc:
        log.error("sync_evidence_from_siem: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── 9. Exposure Register CRUD ─────────────────────────────────────────────────

@comp_bp.route("/exposure", methods=["GET"])
@require_viewer
def list_exposures():
    """
    GET /api/comp/exposure?status=open&severity=critical&asset=example.com
    Returns the exposure register, optionally filtered.
    """
    from cy_comp.models import db
    status   = request.args.get("status")
    severity = request.args.get("severity")
    asset    = request.args.get("asset")
    try:
        with db() as conn:
            cur = conn.cursor()
            where, params = [], []
            if status:
                where.append("status = %s"); params.append(status)
            if severity:
                where.append("severity = %s"); params.append(severity)
            if asset:
                where.append("asset ILIKE %s"); params.append(f"%{asset}%")
            clause = ("WHERE " + " AND ".join(where)) if where else ""
            cur.execute(
                f"""
                SELECT id, asset, asset_type, exposure_type, severity, title,
                       description, source, source_ref, cvss_score, cves,
                       remediation, status, financial_impact, business_impact,
                       assigned_to, due_date, resolved_at, created_by, created_at, updated_at
                FROM cy_comp_exposure
                {clause}
                ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                       WHEN 'medium' THEN 2 ELSE 3 END,
                         cvss_score DESC NULLS LAST, created_at DESC
                LIMIT 500;
                """,
                params
            )
            cols = ["id","asset","asset_type","exposure_type","severity","title",
                    "description","source","source_ref","cvss_score","cves",
                    "remediation","status","financial_impact","business_impact",
                    "assigned_to","due_date","resolved_at","created_by","created_at","updated_at"]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
            for r in rows:
                if r.get("due_date"):
                    r["due_date"] = r["due_date"].isoformat()
                if r.get("resolved_at"):
                    r["resolved_at"] = r["resolved_at"].isoformat()
                if r.get("created_at"):
                    r["created_at"] = r["created_at"].isoformat()
                if r.get("updated_at"):
                    r["updated_at"] = r["updated_at"].isoformat()
        return jsonify(rows)
    except Exception as exc:
        log.error("list_exposures: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/exposure", methods=["POST"])
@require_analyst
def create_exposure():
    """POST /api/comp/exposure — create a new exposure item."""
    import uuid as _uuid
    from cy_comp.models import db
    body = request.get_json(silent=True) or {}
    if not body.get("asset") or not body.get("title"):
        return jsonify({"error": "asset and title are required"}), 400
    try:
        import json as _json
        eid = str(_uuid.uuid4())
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_exposure
                    (id, asset, asset_type, exposure_type, severity, title,
                     description, source, source_ref, cvss_score, cves,
                     remediation, status, financial_impact, business_impact,
                     assigned_to, due_date, created_by, created_at, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW())
                RETURNING id;
                """,
                (
                    eid,
                    body.get("asset"),
                    body.get("asset_type", "host"),
                    body.get("exposure_type", "vulnerability"),
                    body.get("severity", "medium"),
                    body.get("title"),
                    body.get("description"),
                    body.get("source", "manual"),
                    body.get("source_ref"),
                    body.get("cvss_score"),
                    body.get("cves", []),
                    body.get("remediation"),
                    body.get("status", "open"),
                    body.get("financial_impact"),
                    body.get("business_impact"),
                    body.get("assigned_to"),
                    body.get("due_date"),
                    _email(),
                )
            )
        return jsonify({"id": eid, "status": "created"}), 201
    except Exception as exc:
        log.error("create_exposure: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/exposure/<exposure_id>", methods=["PUT"])
@require_analyst
def update_exposure(exposure_id):
    """PUT /api/comp/exposure/<id> — update status, remediation, assigned_to, etc."""
    from cy_comp.models import db
    body = request.get_json(silent=True) or {}
    try:
        fields, params = [], []
        for col in ("status","severity","remediation","assigned_to","due_date",
                    "resolved_at","financial_impact","business_impact","description"):
            if col in body:
                fields.append(f"{col} = %s"); params.append(body[col])
        if "status" in body and body["status"] == "resolved" and "resolved_at" not in body:
            fields.append("resolved_at = NOW()")
        if not fields:
            return jsonify({"error": "no updatable fields provided"}), 400
        fields.append("updated_at = NOW()")
        params.append(exposure_id)
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                f"UPDATE cy_comp_exposure SET {', '.join(fields)} WHERE id = %s;",
                params
            )
            if cur.rowcount == 0:
                return jsonify({"error": "Exposure not found"}), 404
        return jsonify({"id": exposure_id, "status": "updated"})
    except Exception as exc:
        log.error("update_exposure: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── 10. Import ASM supply-chain scan → exposure register ─────────────────────

@comp_bp.route("/exposure/import-asm", methods=["POST"])
@require_analyst
def import_asm_to_exposure():
    """
    POST /api/comp/exposure/import-asm
    Body: {scan_id} or empty (uses latest ASM scan JSON).
    Reads the ASM scan result file and imports supply_chain + vuln findings
    into cy_comp_exposure. Idempotent via source_ref deduplication.
    """
    import uuid as _uuid, os
    from cy_comp.models import db
    body    = request.get_json(silent=True) or {}
    scan_id = body.get("scan_id")
    ASM_DIR = os.environ.get("ASM_REPORTS_DIR", "/opt/cycentra/asm_scans")

    try:
        import json as _json, glob
        if scan_id:
            candidates = [f"{ASM_DIR}/{scan_id}.json"]
        else:
            candidates = sorted(glob.glob(f"{ASM_DIR}/*.json"), reverse=True)

        scan_data = None
        used_file = None
        for fpath in candidates:
            try:
                with open(fpath) as fh:
                    scan_data = _json.load(fh)
                    used_file = fpath
                    break
            except Exception:
                continue

        if not scan_data:
            return jsonify({"error": "No ASM scan file found"}), 404

        imported = skipped = 0
        domain   = scan_data.get("domain") or scan_data.get("target", "unknown")
        scan_ref = scan_id or os.path.basename(used_file).replace(".json", "")

        supply  = scan_data.get("supply_chain", {}).get("results", {})
        vulns   = supply.get("risks", [])
        scripts = supply.get("scripts", [])

        with db() as conn:
            cur = conn.cursor()
            for v in vulns:
                lib    = v.get("library", "unknown")
                osv_id = v.get("osv_id") or ""
                cves   = v.get("cve_ids") or []
                source_ref = f"asm:{scan_ref}:supply:{lib}:{osv_id}"
                cur.execute("SELECT id FROM cy_comp_exposure WHERE source_ref = %s LIMIT 1;", (source_ref,))
                if cur.fetchone():
                    skipped += 1
                    continue
                sev = v.get("severity", "medium").lower()
                if sev not in ("critical","high","medium","low"):
                    sev = "medium"
                cur.execute(
                    """
                    INSERT INTO cy_comp_exposure
                        (id, asset, asset_type, exposure_type, severity, title,
                         description, source, source_ref, cves, status, created_by, created_at, updated_at)
                    VALUES (%s,%s,'web_asset','supply_chain',%s,%s,%s,'asm',%s,%s,'open',%s,NOW(),NOW());
                    """,
                    (
                        str(_uuid.uuid4()), domain, sev,
                        f"Supply Chain: {lib} — {v.get('reason','vulnerable dependency')[:120]}",
                        v.get("reason",""),
                        source_ref, cves, _email(),
                    )
                )
                imported += 1

            # Also import vuln scanner findings if present
            vuln_results = scan_data.get("vuln_scan", {}).get("results", []) or []
            for vr in vuln_results[:100]:
                source_ref = f"asm:{scan_ref}:vuln:{vr.get('host','')}:{vr.get('port','')}"
                cur.execute("SELECT id FROM cy_comp_exposure WHERE source_ref = %s LIMIT 1;", (source_ref,))
                if cur.fetchone():
                    skipped += 1
                    continue
                sev = vr.get("severity", "medium").lower()
                if sev not in ("critical","high","medium","low"):
                    sev = "medium"
                cur.execute(
                    """
                    INSERT INTO cy_comp_exposure
                        (id, asset, asset_type, exposure_type, severity, title,
                         description, source, source_ref, cvss_score, status, created_by, created_at, updated_at)
                    VALUES (%s,%s,'host','vulnerability',%s,%s,%s,'asm',%s,%s,'open',%s,NOW(),NOW());
                    """,
                    (
                        str(_uuid.uuid4()),
                        vr.get("host", domain),
                        sev,
                        vr.get("title") or vr.get("name") or f"Vulnerability on {vr.get('host','')}:{vr.get('port','')}",
                        vr.get("description",""),
                        source_ref,
                        vr.get("cvss_score"),
                        _email(),
                    )
                )
                imported += 1

        return jsonify({
            "imported": imported, "skipped": skipped,
            "scan_file": used_file, "domain": domain,
        })
    except Exception as exc:
        log.error("import_asm_to_exposure: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── #2 Real-time risk scoring — SSE stream ────────────────────────────────────

@comp_bp.route("/dashboard/stream")
@require_viewer
def dashboard_stream():
    """
    GET /api/comp/dashboard/stream
    Server-Sent Events stream for live compliance score updates.
    Pushes 'score-update' events when new compliance-relevant alerts arrive.
    Emits 'heartbeat' every 30 s to keep the connection alive.

    Frontend:  const es = new EventSource('/api/comp/dashboard/stream', {withCredentials: true});
               es.addEventListener('score-update', e => setScores(JSON.parse(e.data).scores));
    """
    import time as _time
    from flask import Response, stream_with_context

    def _last_alert_ts():
        try:
            from cy_comp.models import db as _db
            with _db() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT MAX(timestamp) FROM alerts WHERE is_compliance_relevant = TRUE;"
                )
                row = cur.fetchone()
                return str(row[0]) if row and row[0] else None
        except Exception:
            return None

    def _scores():
        try:
            from cy_comp.services.compliance import get_latest_scores
            return get_latest_scores()
        except Exception:
            return []

    def generate():
        last_ts = _last_alert_ts()
        init = _scores()
        yield f"event: score-update\ndata: {json.dumps({'scores': init, 'reason': 'connected'})}\n\n"
        tick = 0
        while True:
            _time.sleep(30)
            tick += 1
            current_ts = _last_alert_ts()
            if current_ts != last_ts:
                scores = _scores()
                payload = {"scores": scores, "reason": "new_alerts", "ts": current_ts}
                yield f"event: score-update\ndata: {json.dumps(payload, default=str)}\n\n"
                last_ts = current_ts
            else:
                yield f"event: heartbeat\ndata: {json.dumps({'tick': tick})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


# ── #7 Continuous control validation ─────────────────────────────────────────

@comp_bp.route("/control-validations", methods=["GET"])
@require_viewer
def list_control_validations():
    """
    GET /api/comp/control-validations
    Returns latest result per technical validator.
    """
    try:
        from cy_comp.services.control_validator import get_validation_summary
        data = get_validation_summary()
        return jsonify({"validations": data, "count": len(data)})
    except Exception as exc:
        log.error("list_control_validations: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/control-validations/run", methods=["POST"])
@require_analyst
def run_control_validations():
    """
    POST /api/comp/control-validations/run
    Trigger an on-demand control validation run.
    Optional body: {"auto_finding": true}
    """
    try:
        body         = request.get_json(silent=True) or {}
        auto_finding = bool(body.get("auto_finding", True))
        from cy_comp.services.control_validator import run_all_validators
        result = run_all_validators(auto_finding=auto_finding)
        return jsonify(result)
    except Exception as exc:
        log.error("run_control_validations: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── #17 Predictive risk modeling ─────────────────────────────────────────────

@comp_bp.route("/predict", methods=["GET"])
@require_viewer
def predict_risk():
    """
    GET /api/comp/predict?framework=nis2&horizon=30,60,90
    Returns linear-regression + EWMA predictions for a framework.
    Omit framework param for portfolio-level summary.
    """
    try:
        framework = request.args.get("framework", "").strip() or None
        raw_h     = request.args.get("horizon", "30,60,90")
        horizons  = tuple(int(h) for h in raw_h.split(",") if h.strip().isdigit())
        if not horizons:
            horizons = (30, 60, 90)

        from cy_comp.services.prediction import predict_framework_score, get_portfolio_trend

        if framework:
            from cy_comp.services.compliance import SUPPORTED_FRAMEWORKS
            if framework not in SUPPORTED_FRAMEWORKS:
                return jsonify({"error": f"Unknown framework: {framework}"}), 400
            data = predict_framework_score(framework, horizons=horizons)
        else:
            data = get_portfolio_trend()

        return jsonify(data)
    except Exception as exc:
        log.error("predict_risk: %s", exc)
        return jsonify({"error": str(exc)}), 500


@comp_bp.route("/predict/all", methods=["GET"])
@require_viewer
def predict_all():
    """
    GET /api/comp/predict/all
    Returns 30/60/90-day predictions for every supported framework.
    """
    try:
        from cy_comp.services.prediction import predict_all_frameworks
        data = predict_all_frameworks()
        return jsonify(data)
    except Exception as exc:
        log.error("predict_all: %s", exc)
        return jsonify({"error": str(exc)}), 500
