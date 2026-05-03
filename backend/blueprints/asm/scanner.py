"""
blueprints/asm/scanner.py
==========================
Attack Surface Management scan API.

Routes:
  POST /api/scan/trigger        start a scan
  GET  /api/scan/status         poll progress
  GET  /api/scans/latest        fetch latest scan result JSON
  POST /api/asm/escalate        create CyIRIS case from an ASM finding
"""

import glob
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from flask import Blueprint, request, jsonify, make_response, session

from core.config import SCANS_DIR, ASM_LOGS, ASM_DIR, ASM_REPORTS_DIR
from core.helpers import add_cors_headers

asm_bp = Blueprint("asm", __name__)

# Module progress keywords — must match log output from cycentra_scan.py
_MODULE_KEYWORDS = [
    ("[dns reconnaissance]",     "DNS Reconnaissance",    8),
    ("[subdomain enumeration]",  "Subdomain Enumeration", 18),
    ("[web analysis]",           "Web Analysis",          30),
    ("[crypto & ssl audit]",     "Crypto & SSL Audit",    42),
    ("[email security check]",   "Email Security Check",  52),
    ("[whois & history]",        "WHOIS & History",       58),
    ("[osint gathering]",        "OSINT Gathering",       65),
    ("[cloud infrastructure]",   "Cloud Infrastructure",  72),
    ("[dark web monitoring]",    "Dark Web Monitoring",   79),
    ("[supply chain analysis]",  "Supply Chain Analysis", 86),
    ("[social engineering intel]","Social Engineering",   89),
    ("[mobile & api checks]",    "Mobile & API Checks",  92),
    ("[ai enrichment]",          "AI Risk Enrichment",   95),
    ("[portal json]",            "Generating Report",     98),
]


# ── Preflight ─────────────────────────────────────────────────────────────────

@asm_bp.route("/api/scan/trigger", methods=["OPTIONS"])
def scan_options():
    return add_cors_headers(make_response('', 204))


# ── Trigger scan ──────────────────────────────────────────────────────────────

_VALID_SCAN_TYPES = {"standard", "deep", "passive"}


@asm_bp.route("/api/scan/trigger", methods=["POST"])
def trigger_scan():
    data      = request.get_json() or {}
    domain    = data.get("domain", "").strip()
    uid       = data.get("uid", "anonymous")
    scan_type          = data.get("scan_type", "standard").strip().lower()
    include_subdomains = bool(data.get("include_subdomains", True))

    if not domain or "." not in domain:
        return jsonify({"error": "Invalid domain"}), 400

    # Reject unrecognised scan types rather than silently defaulting
    if scan_type not in _VALID_SCAN_TYPES:
        return jsonify({"error": f"Invalid scan_type '{scan_type}'. Must be one of: standard, deep, passive"}), 400

    user_dir = SCANS_DIR / uid
    user_dir.mkdir(parents=True, exist_ok=True)
    ASM_LOGS.mkdir(parents=True, exist_ok=True)

    scan_script = ASM_DIR / "cycentra_scan.py"
    if not scan_script.exists():
        return jsonify({"error": f"Scan engine not found at {scan_script}"}), 503

    python_bin = Path(sys.executable)
    log_file   = ASM_LOGS / "cycentra_engine.log"

    try:
        log_file.write_text(
            f"[{datetime.now().strftime('%H:%M:%S')}] {scan_type.upper()} scan triggered for {domain} by {uid}"
            f" (subdomains={'on' if include_subdomains else 'off'})\n"
        )
    except Exception:
        pass  # non-fatal — log init failure

    env = os.environ.copy()
    env["CYCENTRA_OUTPUT_DIR"]        = str(user_dir)
    env["CYCENTRA_USER_ID"]           = uid
    env["CYCENTRA_INCLUDE_SUBDOMAINS"] = "true" if include_subdomains else "false"

    try:
        subprocess.Popen(
            [str(python_bin), str(scan_script), domain, uid, scan_type],
            stdout=open(log_file, "a"),
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )
    except Exception as e:
        try:
            from blueprints.audit.routes import record_event
            record_event("scan_failed", email=uid, resource=domain,
                         detail=str(e), result="error",
                         metadata={"scan_type": scan_type})
        except Exception:
            pass
        return jsonify({"error": str(e)}), 500

    try:
        from blueprints.audit.routes import record_event
        record_event("scan_triggered", email=uid, resource=domain,
                     detail=f"{scan_type} scan started",
                     metadata={"scan_type": scan_type, "include_subdomains": include_subdomains})
    except Exception:
        pass

    return jsonify({
        "status":              "started",
        "domain":              domain,
        "uid":                 uid,
        "scan_type":           scan_type,
        "include_subdomains":  include_subdomains,
    })


# ── Scan status ───────────────────────────────────────────────────────────────

@asm_bp.route("/api/scan/status")
def scan_status():
    log_file = ASM_LOGS / "cycentra_engine.log"
    running, progress, current_module, last_line = False, 0, "", ""

    try:
        if log_file.exists():
            if time.time() - log_file.stat().st_mtime < 1800:  # 30 min — allows for slow AI enrichment
                running = True

            with open(log_file, errors='replace') as f:
                lines = [l.strip() for l in f.readlines() if l.strip()]

            if lines:
                last_line = lines[-1]
                low       = last_line.lower()

                if any(m in low for m in [
                    "portal json saved", "ndjson report saved",
                    "scan complete", "all done",
                ]):
                    running, progress, current_module = False, 100, "Complete"
                else:
                    for line in reversed(lines[-200:]):
                        ll = line.lower()
                        for key, mod, pct in _MODULE_KEYWORDS:
                            if key in ll:
                                current_module, progress = mod, pct
                                break
                        if current_module:
                            break

    except Exception as e:
        pass  # status polling must never error-out the frontend

    return jsonify({
        "running":        running,
        "progress":       progress,
        "current_module": current_module,
        "last_log":       last_line,
    })


# ── Latest scan result ────────────────────────────────────────────────────────

@asm_bp.route("/api/scans/latest")
def get_latest_scan():
    uid       = request.args.get("uid", "")
    search    = SCANS_DIR / uid / "scan_*.json" if uid else SCANS_DIR / "**" / "scan_*.json"
    all_files = glob.glob(str(search), recursive=True)

    if not all_files:
        return jsonify({"error": "No scans found"}), 404

    try:
        latest = sorted(all_files, key=os.path.getmtime, reverse=True)[0]
        with open(latest) as f:
            import json
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Scan history list ─────────────────────────────────────────────────────────

@asm_bp.route("/api/scans/list")
def list_scans():
    import json as _json
    uid   = request.args.get("uid", "")
    limit = min(int(request.args.get("limit", 15)), 50)

    search    = SCANS_DIR / uid / "scan_*.json" if uid else SCANS_DIR / "**" / "scan_*.json"
    all_files = glob.glob(str(search), recursive=True)

    if not all_files:
        return jsonify([])

    files_sorted = sorted(all_files, key=os.path.getmtime, reverse=True)[:limit]
    scans = []
    for f in files_sorted:
        try:
            with open(f) as fp:
                d = _json.load(fp)
            meta   = d.get("meta", {})
            assets = d.get("assets", [])
            vulns  = [v for a in assets for v in (a.get("vulnerabilities") or [])]
            scans.append({
                "scan_id":        meta.get("scan_id", os.path.basename(f)),
                "domain":         meta.get("domain", ""),
                "last_scan":      meta.get("last_scan", ""),
                "scan_type":      meta.get("scan_type", "standard"),
                "total_findings": len(vulns),
                "critical":       sum(1 for v in vulns if v.get("severity") == "Critical"),
                "high":           sum(1 for v in vulns if v.get("severity") == "High"),
                "subdomains":     d.get("subdomain_summary", {}).get("total", 0),
            })
        except Exception:
            continue
    return jsonify(scans)


# ── Fetch a specific historical scan by scan_id ───────────────────────────────

@asm_bp.route("/api/scans/<scan_id>")
def get_scan_by_id(scan_id):
    import json as _json
    uid       = request.args.get("uid", "")
    search    = SCANS_DIR / uid / "scan_*.json" if uid else SCANS_DIR / "**" / "scan_*.json"
    all_files = glob.glob(str(search), recursive=True)

    for f in all_files:
        try:
            with open(f) as fp:
                d = _json.load(fp)
            if d.get("meta", {}).get("scan_id") == scan_id:
                return jsonify(d)
        except Exception:
            continue
    return jsonify({"error": "Scan not found"}), 404


# ── PDF report listing ────────────────────────────────────────────────────────

@asm_bp.route("/api/scans/reports")
def list_pdf_reports():
    """Return the last 6 generated PDF reports across all tenants."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    all_pdfs = sorted(
        glob.glob(str(ASM_REPORTS_DIR / "**" / "*.pdf"), recursive=True),
        key=os.path.getmtime,
        reverse=True,
    )[:6]

    reports = []
    for p in all_pdfs:
        fname  = os.path.basename(p)
        # filename pattern: {type}_{domain}_{YYYYMMDDHHMMSS}.pdf
        base   = fname[:-4]          # strip .pdf
        parts  = base.split("_")
        rtype  = parts[0] if parts else "report"
        domain = "_".join(parts[1:-1]) if len(parts) >= 3 else ""
        ts_str = parts[-1] if len(parts) >= 2 else ""
        try:
            from datetime import datetime as _dt
            ts_iso = _dt.strptime(ts_str, "%Y%m%d%H%M%S").isoformat()
        except Exception:
            ts_iso = ""
        reports.append({
            "filename": fname,
            "type":     rtype,
            "domain":   domain,
            "modified": os.path.getmtime(p),
            "ts_iso":   ts_iso,
            "size_kb":  round(os.path.getsize(p) / 1024),
        })

    return jsonify(reports)


# ── PDF report download ───────────────────────────────────────────────────────

@asm_bp.route("/api/scans/reports/download")
def download_pdf_report():
    """Serve a PDF report file.  Only files within ASM_REPORTS_DIR are served."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    from flask import send_file

    filename = request.args.get("file", "").strip()
    # Reject path traversal attempts — filename only, no directory separators
    if not filename or "/" in filename or "\\" in filename or ".." in filename:
        return jsonify({"error": "Invalid filename"}), 400

    matches = glob.glob(str(ASM_REPORTS_DIR / "**" / filename), recursive=True)
    if not matches:
        return jsonify({"error": "Report not found"}), 404

    pdf_path = Path(matches[0])
    # Second-layer check: resolved path must still sit inside ASM_REPORTS_DIR
    try:
        pdf_path.resolve().relative_to(ASM_REPORTS_DIR.resolve())
    except ValueError:
        return jsonify({"error": "Access denied"}), 403

    if not pdf_path.is_file():
        return jsonify({"error": "File not found"}), 404

    return send_file(
        str(pdf_path),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


# ── ASM → CyIRIS escalation ───────────────────────────────────────────────────
#
# Severity → IRIS severity ID mapping (matches IRIS built-in severity table)
_ASM_SEV_MAP = {
    "critical": 1,
    "high":     2,
    "medium":   3,
    "low":      4,
}
# Severity → confidence-score proxy (used only for display context in the ticket)
_ASM_CONFIDENCE = {
    "critical": 95.0,
    "high":     80.0,
    "medium":   55.0,
    "low":      30.0,
}


@asm_bp.route("/api/asm/escalate", methods=["POST"])
def asm_escalate_to_iris():
    """Create a CyIRIS (DFIR IRIS) case from an ASM finding.

    Requires analyst or admin role.  Config is read live from ai_settings.json
    so no restart is needed after enabling CyIRIS in System Settings.
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    from blueprints.rbac.manager import get_user_role
    role = get_user_role(session["user_email"])
    if role not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403

    from core.helpers import get_iris_config
    import requests as _r

    cfg = get_iris_config()
    if not cfg:
        return jsonify({
            "error": "CyIRIS is not configured. Enable it in System Settings \u2192 Integrations \u2192 CyIRIS."
        }), 503

    body = request.get_json(silent=True) or {}
    vulnerability = body.get("vulnerability", "ASM Finding").strip()
    severity_raw  = str(body.get("severity", "medium")).lower()
    severity      = severity_raw if severity_raw in _ASM_SEV_MAP else "medium"
    description   = body.get("description", "")
    recommendation = body.get("recommendation", "")
    asset         = body.get("asset", "")
    module        = body.get("module", "")
    risk_score    = body.get("risk_score", None)
    cve           = body.get("cve", "")
    domain        = body.get("domain", asset or "unknown")
    analyst_email = session.get("user_email", "unknown")
    confidence    = _ASM_CONFIDENCE.get(severity, 55.0)

    case_name = f"[ASM] {vulnerability} \u2014 {asset or domain}"
    case_body = (
        f"## ASM Finding: {vulnerability}\n\n"
        f"**Asset:** `{asset or domain}`  \n"
        f"**Severity:** {severity.upper()}  \n"
        f"**Module:** {module or 'N/A'}  \n"
        f"**Confidence Score:** {confidence:.0f}  \n"
    )
    if risk_score is not None:
        case_body += f"**Risk Score:** {risk_score}  \n"
    if cve:
        case_body += f"**CVE:** {cve}  \n"
    if description:
        case_body += f"\n### Description\n{description}\n"
    if recommendation:
        case_body += f"\n### Recommended Remediation\n{recommendation}\n"
    case_body += f"\n---\n*Escalated manually by `{analyst_email}` via CyCentra360 ASM*"

    payload = {
        "case_name":        case_name,
        "case_description": case_body,
        "case_customer":    cfg["customerId"],
        "case_severity_id": _ASM_SEV_MAP[severity],
        "case_soc_id":      f"ASM-{asset or domain}-{module}".upper()[:60],
    }
    try:
        resp = _r.post(
            f"{cfg['url'].rstrip('/')}/api/v2/cases",
            headers={
                "Authorization": f"Bearer {cfg['apiKey']}",
                "Content-Type":  "application/json",
                "Accept":        "application/json",
            },
            json=payload,
            timeout=10,
            verify=False,  # IRIS commonly uses self-signed cert on-premise
        )
        if resp.status_code in (200, 201):
            data = resp.json()
            case = data if "case_id" in data else data.get("data", data)
            case_id  = case.get("case_id")
            case_url = f"{cfg['url'].rstrip('/')}/case?cid={case_id}" if case_id else cfg["url"]
            return jsonify({"case_id": case_id, "case_url": case_url, "case_name": case_name})
        return jsonify({"error": f"IRIS returned HTTP {resp.status_code}", "detail": resp.text[:300]}), 502
    except _r.exceptions.ConnectionError:
        return jsonify({"error": "Cannot reach CyIRIS. Check URL in System Settings."}), 503
    except _r.exceptions.Timeout:
        return jsonify({"error": "CyIRIS request timed out."}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── ASM finding / asset status management ─────────────────────────────────────
#
# Finding and asset statuses are stored in a lightweight JSON file because ASM
# scan output files are immutable historic artifacts.  The status overlay is
# keyed by a stable finding_id (constructed by the frontend as
# "<asset>:<vulnerability>:<module>" slugified) or by asset hostname.
#
# Status lifecycle:
#   open  →  investigating  →  in_review  →  resolved / false_positive
#
# All transitions require a non-empty audit comment from the analyst.

_ASM_STATUSES_FILE = Path("/opt/cycentra/asm_statuses.json")
_ASSET_STATUSES_FILE = Path("/opt/cycentra/asset_statuses.json")

_ASM_ALLOWED_TRANSITIONS = {
    "open":          {"investigating", "in_review", "resolved", "false_positive"},
    "investigating": {"in_review", "resolved", "false_positive"},
    "in_review":     {"resolved", "false_positive", "investigating"},
    "resolved":      {"investigating"},
    "false_positive":{"investigating"},
}


def _load_status_file(path: Path) -> dict:
    if path.exists():
        try:
            import json as _j
            return _j.loads(path.read_text())
        except Exception:
            pass
    return {}


def _save_status_file(path: Path, data: dict) -> None:
    import json as _j
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_j.dumps(data, indent=2))


# ── Preflight handlers ────────────────────────────────────────────────────────

@asm_bp.route("/api/asm/findings/<path:finding_id>/status", methods=["OPTIONS"])
def asm_finding_status_options(finding_id):
    return add_cors_headers(make_response('', 204))


@asm_bp.route("/api/asm/assets/<path:asset_id>/status", methods=["OPTIONS"])
def asm_asset_status_options(asset_id):
    return add_cors_headers(make_response('', 204))


# ── GET /api/asm/statuses — bulk status map ────────────────────────────────────

@asm_bp.route("/api/asm/statuses")
def asm_get_all_statuses():
    """Return combined status map for findings and assets."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    return jsonify({
        "findings": _load_status_file(_ASM_STATUSES_FILE),
        "assets":   _load_status_file(_ASSET_STATUSES_FILE),
    })


# ── POST /api/asm/findings/<id>/status ────────────────────────────────────────

@asm_bp.route("/api/asm/findings/<path:finding_id>/status", methods=["POST"])
def asm_finding_transition(finding_id):
    """Transition an ASM finding status with a mandatory audit comment."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403

    body = request.get_json(silent=True) or {}
    to_status = (body.get("to_status") or "").strip()
    comment   = (body.get("comment")   or "").strip()

    if not to_status:
        return jsonify({"error": "to_status is required"}), 422
    if not comment:
        return jsonify({"error": "Audit comment is required for status transitions."}), 422

    data      = _load_status_file(_ASM_STATUSES_FILE)
    entry     = data.get(finding_id, {"status": "open", "audit_log": []})
    from_status = entry.get("status", "open")

    allowed = _ASM_ALLOWED_TRANSITIONS.get(from_status, set())
    if to_status not in allowed:
        return jsonify({
            "error": f"Transition '{from_status}' → '{to_status}' is not allowed.",
            "allowed": sorted(allowed),
        }), 422

    from datetime import timezone as _tz
    ts = datetime.now(_tz.utc).isoformat()
    entry["status"] = to_status
    entry["audit_log"] = entry.get("audit_log", []) + [{
        "action":      "status_change",
        "from_status": from_status,
        "to_status":   to_status,
        "comment":     comment,
        "actor":       session["user_email"],
        "created_at":  ts,
    }]
    data[finding_id] = entry
    _save_status_file(_ASM_STATUSES_FILE, data)

    return jsonify({
        "finding_id":  finding_id,
        "status":      to_status,
        "from_status": from_status,
        "comment":     comment,
        "actor":       session["user_email"],
        "created_at":  ts,
    })


# ── GET /api/asm/findings/<id>/audit ─────────────────────────────────────────

@asm_bp.route("/api/asm/findings/<path:finding_id>/audit")
def asm_finding_audit(finding_id):
    """Return the audit trail for an ASM finding."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    data  = _load_status_file(_ASM_STATUSES_FILE)
    entry = data.get(finding_id, {})
    return jsonify(entry.get("audit_log", []))


# ── POST /api/asm/assets/<id>/status ──────────────────────────────────────────

@asm_bp.route("/api/asm/assets/<path:asset_id>/status", methods=["POST"])
def asm_asset_transition(asset_id):
    """Transition an asset status with a mandatory audit comment."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403

    body = request.get_json(silent=True) or {}
    to_status = (body.get("to_status") or "").strip()
    comment   = (body.get("comment")   or "").strip()

    if not to_status:
        return jsonify({"error": "to_status is required"}), 422
    if not comment:
        return jsonify({"error": "Audit comment is required for status transitions."}), 422

    data      = _load_status_file(_ASSET_STATUSES_FILE)
    entry     = data.get(asset_id, {"status": "open", "audit_log": []})
    from_status = entry.get("status", "open")

    allowed = _ASM_ALLOWED_TRANSITIONS.get(from_status, set())
    if to_status not in allowed:
        return jsonify({
            "error": f"Transition '{from_status}' → '{to_status}' is not allowed.",
            "allowed": sorted(allowed),
        }), 422

    from datetime import timezone as _tz
    ts = datetime.now(_tz.utc).isoformat()
    entry["status"] = to_status
    entry["audit_log"] = entry.get("audit_log", []) + [{
        "action":      "status_change",
        "from_status": from_status,
        "to_status":   to_status,
        "comment":     comment,
        "actor":       session["user_email"],
        "created_at":  ts,
    }]
    data[asset_id] = entry
    _save_status_file(_ASSET_STATUSES_FILE, data)

    return jsonify({
        "asset_id":    asset_id,
        "status":      to_status,
        "from_status": from_status,
        "comment":     comment,
        "actor":       session["user_email"],
        "created_at":  ts,
    })


# ── GET /api/asm/assets/<id>/audit ────────────────────────────────────────────

@asm_bp.route("/api/asm/assets/<path:asset_id>/audit")
def asm_asset_audit(asset_id):
    """Return the audit trail for an asset."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    data  = _load_status_file(_ASSET_STATUSES_FILE)
    entry = data.get(asset_id, {})
    return jsonify(entry.get("audit_log", []))


# ── POST /api/asm/auto-status — bulk confidence-score suggestions ─────────────

@asm_bp.route("/api/asm/auto-status", methods=["OPTIONS"])
def asm_auto_status_options():
    return add_cors_headers(make_response('', 204))


@asm_bp.route("/api/asm/auto-status", methods=["POST"])
def asm_auto_status():
    """Return automated status-transition suggestions based on confidence scores.

    Mirrors the State Transition Matrix in the frontend computeAutoStatus():
      open          → investigating : confidence ≥ 75  OR cvss ≥ 7.0  OR epss_pct ≥ 60
      investigating → in_review     : cvss ≥ 9.0       OR epss_pct ≥ 75  OR risk_score ≥ 8

    Read-only — does NOT write any state.
    Accepts:
      { findings: [ { id, severity, cvss, epss_pct, risk_score, current_status } ] }
    Returns:
      { suggestions: [ { id, current, suggested, reason } ], total: N }
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    body     = request.get_json(silent=True) or {}
    findings = body.get("findings") or []
    if not isinstance(findings, list):
        return jsonify({"error": "findings must be a list"}), 422

    suggestions = []
    for f in findings:
        sev    = str(f.get("severity") or "low").lower()
        base   = _ASM_CONFIDENCE.get(sev, 40.0)
        rs     = float(f.get("risk_score") or 0)
        conf   = min(100, max(0, round(base + (rs - 5) * 1.5)))
        cvss   = float(f.get("cvss") or 0)
        epss   = float(f.get("epss_pct") or 0)
        cur    = str(f.get("current_status") or "open").strip()
        to     = None
        reason = None

        if cur == "open":
            if conf >= 75 or cvss >= 7.0 or epss >= 60:
                to     = "investigating"
                reason = f"confidence={conf}, cvss={cvss}, epss={epss}%"
        elif cur == "investigating":
            if cvss >= 9.0 or epss >= 75 or rs >= 8:
                to     = "in_review"
                reason = f"cvss={cvss}, epss={epss}%, risk_score={rs}"

        if to:
            suggestions.append({
                "id":       f.get("id"),
                "current":  cur,
                "suggested": to,
                "reason":   reason,
            })

    return jsonify({"suggestions": suggestions, "total": len(suggestions)})

