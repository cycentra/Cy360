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
import hashlib
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from flask import Blueprint, request, jsonify, make_response, session

from core.config import SCANS_DIR, ASM_LOGS, ASM_DIR, ASM_REPORTS_DIR
from core.helpers import add_cors_headers

asm_bp = Blueprint("asm", __name__)


def _asm_id(asset: str, module: str) -> str:
    """Generate a deterministic ASM-XXXXX ID from asset+module (mirrors cycentra_scan._asm_finding_id)."""
    raw = f"{asset}|{module}".lower().encode()
    digest = hashlib.sha256(raw).hexdigest()
    return f"ASM-{digest[:5].upper()}"


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
# RFC-5322 simplified — good enough for a UI input guard (not a deliverability check)
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")


@asm_bp.route("/api/scan/trigger", methods=["POST"])
def trigger_scan():
    data      = request.get_json() or {}
    domain    = data.get("domain", "").strip()
    uid       = data.get("uid", "anonymous")
    scan_type          = data.get("scan_type", "standard").strip().lower()
    include_subdomains = bool(data.get("include_subdomains", True))
    notify_email       = data.get("notify_email", "").strip()

    if not domain or "." not in domain:
        return jsonify({"error": "Invalid domain"}), 400

    # Reject unrecognised scan types rather than silently defaulting
    if scan_type not in _VALID_SCAN_TYPES:
        return jsonify({"error": f"Invalid scan_type '{scan_type}'. Must be one of: standard, deep, passive"}), 400

    # Validate notify_email if provided — reject obviously malformed addresses
    if notify_email and not _EMAIL_RE.match(notify_email):
        return jsonify({"error": "Invalid notify_email address"}), 400

    # Guest users share a common directory — no per-session isolation or state history.
    # Authenticated users get their own isolated sub-directory.
    is_guest = uid.startswith("guest_")
    user_dir = SCANS_DIR / "guest" if is_guest else SCANS_DIR / uid
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
    env["CYCENTRA_OUTPUT_DIR"]         = str(user_dir)
    env["CYCENTRA_USER_ID"]            = uid
    env["CYCENTRA_INCLUDE_SUBDOMAINS"] = "true" if include_subdomains else "false"
    env["CYCENTRA_IS_GUEST"]           = "true" if is_guest else "false"
    if notify_email:
        env["CYCENTRA_NOTIFY_EMAIL"]   = notify_email

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
                     metadata={
                         "scan_type": scan_type,
                         "include_subdomains": include_subdomains,
                         "notify_email": notify_email or None,
                     })
    except Exception:
        pass

    return jsonify({
        "status":              "started",
        "domain":              domain,
        "uid":                 uid,
        "scan_type":           scan_type,
        "include_subdomains":  include_subdomains,
        "notify_email":        notify_email or None,
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
    uid = request.args.get("uid", "")
    # Guest UIDs share the common guest directory — never look in a uid-named folder
    if uid.startswith("guest_"):
        search = SCANS_DIR / "guest" / "scan_*.json"
    elif uid:
        search = SCANS_DIR / uid / "scan_*.json"
    else:
        search = SCANS_DIR / "**" / "scan_*.json"
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

def _scans_dir_for_uid(uid: str) -> Path:
    """Map a uid to its scans directory, matching scan-trigger storage logic."""
    if uid.startswith("guest_"):
        return SCANS_DIR / "guest"
    return SCANS_DIR / uid


@asm_bp.route("/api/scans/list")
def list_scans():
    import json as _json
    uid   = request.args.get("uid", "").strip()
    limit = min(int(request.args.get("limit", 15)), 50)

    # Scope to the requesting user's directory.
    # Never return a wildcard glob over all users — that would expose other
    # users' scan timelines.
    if uid:
        user_dir = _scans_dir_for_uid(uid)
    elif session.get("user_email"):
        user_dir = _scans_dir_for_uid(session["user_email"].strip())
    else:
        return jsonify([])  # unauthenticated with no uid — return empty

    # For SSO users also include scheduler scans in the timeline.
    search_dirs = [user_dir]
    if not uid.startswith("guest_"):
        scheduler_dir = SCANS_DIR / "scheduler"
        if scheduler_dir.is_dir():
            search_dirs.append(scheduler_dir)

    all_files = []
    for d in search_dirs:
        all_files.extend(glob.glob(str(d / "scan_*.json")))

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
    uid = request.args.get("uid", "").strip()

    # Mirror list_scans scoping: uid-owned dir + scheduler; never wildcard all users.
    if uid:
        search_dirs = [_scans_dir_for_uid(uid)]
        if not uid.startswith("guest_"):
            sched = SCANS_DIR / "scheduler"
            if sched.is_dir():
                search_dirs.append(sched)
    elif session.get("user_email"):
        search_dirs = [_scans_dir_for_uid(session["user_email"].strip()),
                       SCANS_DIR / "scheduler"]
    else:
        return jsonify({"error": "Scan not found"}), 404

    all_files = []
    for d in search_dirs:
        all_files.extend(glob.glob(str(d / "scan_*.json")))

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

# Directories whose PDF reports are always visible to any authenticated user
# (scheduler auto-scans run on behalf of the platform, not a specific user).
_SHARED_REPORT_DIRS = ("scheduler",)


def _reports_dir_for_uid(uid: str) -> Path:
    """Map a uid to its reports directory, mirroring scan-trigger logic."""
    if uid.startswith("guest_"):
        return ASM_REPORTS_DIR / "guest"
    return ASM_REPORTS_DIR / uid


@asm_bp.route("/api/scans/reports")
def list_pdf_reports():
    """Return the last 6 PDF reports owned by the current session user.

    Scans are stored under the OAuth uid (e.g. ``google_abc123``), not the
    email address.  This endpoint therefore resolves the lookup directory from
    ``session["user_uid"]`` first, falling back to ``session["user_email"]``
    for backwards-compatibility with sessions that pre-date the uid field.

    Scheduler reports (``_SHARED_REPORT_DIRS``) are always included.
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    session_email = session["user_email"].strip().lower()
    # Prefer the OAuth uid stored at login — this matches how scan files are written.
    session_uid   = session.get("user_uid", "").strip()

    uid = request.args.get("uid", "").strip()

    # If no uid supplied, use the OAuth uid (primary) or fall back to email.
    if not uid:
        uid = session_uid or session["user_email"].strip()

    # Security: allow access when uid matches the session's OAuth uid OR email.
    # Reject cross-user access unless the caller is an admin.
    allowed_ids = {i.lower() for i in (session_email, session_uid) if i}
    if uid.strip().lower() not in allowed_ids:
        try:
            from blueprints.rbac.manager import get_user_role
            if get_user_role(session_email) != "admin":
                return jsonify({"error": "Access denied"}), 403
        except Exception:
            return jsonify({"error": "Access denied"}), 403

    # Search both the uid-named directory and the email-named directory so that
    # reports generated before the uid fix are still surfaced.
    uid_dirs: list[Path] = [_reports_dir_for_uid(uid)]
    if session_uid and session_uid != uid:
        uid_dirs.append(_reports_dir_for_uid(session_email))

    # Collect PDFs from the user's own directory/directories and shared scheduler.
    search_dirs = uid_dirs[:]
    for shared in _SHARED_REPORT_DIRS:
        shared_path = ASM_REPORTS_DIR / shared
        if shared_path.is_dir():
            search_dirs.append(shared_path)

    all_pdfs = []
    for d in search_dirs:
        all_pdfs.extend(glob.glob(str(d / "*.pdf")))

    all_pdfs = sorted(all_pdfs, key=os.path.getmtime, reverse=True)[:6]

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
    """Serve a PDF report file owned by the current session user.

    Only files that sit inside the requesting user's own reports directory
    (or the shared scheduler directory) are served.  Cross-user access and
    path traversal are both rejected.
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    from flask import send_file

    filename = request.args.get("file", "").strip()
    # Reject path traversal attempts — filename only, no directory separators
    if not filename or "/" in filename or "\\" in filename or ".." in filename:
        return jsonify({"error": "Invalid filename"}), 400

    session_email = session["user_email"].strip().lower()
    session_uid   = session.get("user_uid", "").strip()

    uid = request.args.get("uid", "").strip()
    if not uid:
        uid = session_uid or session["user_email"].strip()

    # Security: allow uid == session's OAuth uid or email; reject cross-user unless admin.
    allowed_ids = {i.lower() for i in (session_email, session_uid) if i}
    if uid.strip().lower() not in allowed_ids:
        try:
            from blueprints.rbac.manager import get_user_role
            if get_user_role(session_email) != "admin":
                return jsonify({"error": "Access denied"}), 403
        except Exception:
            return jsonify({"error": "Access denied"}), 403

    # Build ordered list of candidate directories: uid-named first, email-named
    # as backwards-compat fallback, then shared scheduler dir.
    candidate_dirs = [_reports_dir_for_uid(uid)]
    if session_uid and session_uid != uid:
        candidate_dirs.append(_reports_dir_for_uid(session_email))
    for shared in _SHARED_REPORT_DIRS:
        candidate_dirs.append(ASM_REPORTS_DIR / shared)

    pdf_path: Path | None = None
    for d in candidate_dirs:
        candidate = d / filename
        if candidate.is_file():
            # Verify the resolved path is still inside ASM_REPORTS_DIR (path-traversal guard)
            try:
                candidate.resolve().relative_to(ASM_REPORTS_DIR.resolve())
                pdf_path = candidate
                break
            except ValueError:
                continue

    if pdf_path is None:
        return jsonify({"error": "Report not found"}), 404

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
        "case_soc_id":      _asm_id(asset or domain, module),
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
# TWO SEPARATE TRACKING SYSTEMS:
#
# 1. FINDING STATUS (vulnerabilities) — ticket workflow, stored globally.
#    Lifecycle: open → investigating → in_review → resolved / false_positive
#    Keyed by a stable finding_id ("<asset>:<vuln>:<module>" slug).
#
# 2. ASSET STATE (hosts / subdomains) — ASM lifecycle, stored PER USER.
#    Lifecycle: new → baseline / under_review / ignored
#               baseline → dropped (auto when not detected in latest scan)
#               dropped  → new / baseline (user re-activates)
#    Keyed by hostname.  State is never overwritten by a rescan unless the
#    auto-drop rule fires (baseline asset gone missing).

_ASM_STATUSES_FILE  = Path("/opt/cycentra/asm_statuses.json")
_ASM_STATES_BASE    = Path("/opt/cycentra/asm_states")   # per-user subdirs live here

# ── Finding workflow transition table ─────────────────────────────────────────

_ASM_ALLOWED_TRANSITIONS = {
    "open":           {"investigating", "in_review", "resolved", "false_positive"},
    "investigating":  {"in_review", "resolved", "false_positive"},
    "in_review":      {"resolved", "false_positive", "investigating"},
    "resolved":       {"investigating"},
    "false_positive": {"investigating"},
}

# ── Asset lifecycle transition table ─────────────────────────────────────────
#
# User-initiated transitions only.  The scan engine may also fire the
# auto-drop rule (baseline → dropped) but no other automatic transitions exist.

_ASSET_ALLOWED_TRANSITIONS = {
    "new":          {"baseline", "under_review", "ignored"},
    "baseline":     {"under_review", "ignored"},
    "under_review": {"baseline", "ignored", "new"},
    "ignored":      {"new", "baseline"},
    "dropped":      {"new", "baseline"},
}


# ── Shared helpers ────────────────────────────────────────────────────────────

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


def _asset_states_path(uid: str) -> Path:
    """Return the per-user asset state store path."""
    safe = re.sub(r"[^a-z0-9._@-]", "_", uid.strip().lower())[:80] or "unknown"
    return _ASM_STATES_BASE / safe / "asset_states.json"


def _load_asset_states(uid: str) -> dict:
    """Load the asset state store for a user.  Returns a fresh schema on first use."""
    path = _asset_states_path(uid)
    if path.exists():
        try:
            import json as _j
            data = _j.loads(path.read_text())
            if isinstance(data, dict) and "assets" in data:
                return data
        except Exception:
            pass
    return {"version": 1, "baseline": None, "assets": {}}


def _save_asset_states(uid: str, data: dict) -> None:
    import json as _j
    path = _asset_states_path(uid)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_j.dumps(data, indent=2))


# ── Preflight handlers ────────────────────────────────────────────────────────

@asm_bp.route("/api/asm/findings/<path:finding_id>/status", methods=["OPTIONS"])
def asm_finding_status_options(finding_id):
    return add_cors_headers(make_response('', 204))


@asm_bp.route("/api/asm/assets/<path:asset_id>/state", methods=["OPTIONS"])
def asm_asset_state_options(asset_id):
    return add_cors_headers(make_response('', 204))


@asm_bp.route("/api/asm/baseline", methods=["OPTIONS"])
def asm_baseline_options():
    return add_cors_headers(make_response('', 204))


# ── GET /api/asm/statuses — bulk status map ────────────────────────────────────

@asm_bp.route("/api/asm/statuses")
def asm_get_all_statuses():
    """Return combined finding status map and asset state map for the current user."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    uid = session["user_email"].strip()
    return jsonify({
        "findings":     _load_status_file(_ASM_STATUSES_FILE),
        "asset_states": _load_asset_states(uid),
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

    data        = _load_status_file(_ASM_STATUSES_FILE)
    entry       = data.get(finding_id, {"status": "open", "audit_log": []})
    from_status = entry.get("status", "open")

    allowed = _ASM_ALLOWED_TRANSITIONS.get(from_status, set())
    if to_status not in allowed:
        return jsonify({
            "error":   f"Transition '{from_status}' → '{to_status}' is not allowed.",
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


# ── POST /api/asm/assets/<id>/state — user-initiated asset state transition ────

@asm_bp.route("/api/asm/assets/<path:asset_id>/state", methods=["POST"])
def asm_asset_transition(asset_id):
    """Transition an asset to a new lifecycle state with a mandatory audit comment.

    Valid states: new | baseline | under_review | ignored | dropped
    All transitions require an explicit user action and a non-empty comment.

    Auto-transition (baseline → dropped) is performed by the scan engine and
    does not go through this endpoint.
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403

    body     = request.get_json(silent=True) or {}
    to_state = (body.get("to_state") or "").strip()
    comment  = (body.get("comment")  or "").strip()

    if not to_state:
        return jsonify({"error": "to_state is required"}), 422
    if to_state not in _ASSET_ALLOWED_TRANSITIONS:
        return jsonify({
            "error":  f"Unknown state '{to_state}'.",
            "valid":  sorted(_ASSET_ALLOWED_TRANSITIONS),
        }), 422
    if not comment:
        return jsonify({"error": "Audit comment is required for state transitions."}), 422

    uid        = session["user_email"].strip()
    store      = _load_asset_states(uid)
    assets     = store.setdefault("assets", {})
    entry      = assets.get(asset_id, {"state": "new", "first_seen": None, "audit_log": []})
    from_state = entry.get("state", "new")

    allowed = _ASSET_ALLOWED_TRANSITIONS.get(from_state, set())
    if to_state not in allowed:
        return jsonify({
            "error":   f"Transition '{from_state}' → '{to_state}' is not allowed.",
            "allowed": sorted(allowed),
        }), 422

    from datetime import timezone as _tz
    ts = datetime.now(_tz.utc).isoformat()
    entry["state"] = to_state
    entry.setdefault("first_seen", ts)
    entry["audit_log"] = entry.get("audit_log", []) + [{
        "action":     "state_change",
        "from_state": from_state,
        "to_state":   to_state,
        "comment":    comment,
        "actor":      uid,
        "created_at": ts,
    }]
    assets[asset_id] = entry
    store["assets"]  = assets
    _save_asset_states(uid, store)

    return jsonify({
        "asset_id":   asset_id,
        "state":      to_state,
        "from_state": from_state,
        "comment":    comment,
        "actor":      uid,
        "created_at": ts,
    })


# ── GET /api/asm/assets/<id>/audit ────────────────────────────────────────────

@asm_bp.route("/api/asm/assets/<path:asset_id>/audit")
def asm_asset_audit(asset_id):
    """Return the state audit trail for an asset."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    uid   = session["user_email"].strip()
    store = _load_asset_states(uid)
    entry = store.get("assets", {}).get(asset_id, {})
    return jsonify(entry.get("audit_log", []))


# ── GET /api/asm/asset-states — full asset state map for current user ─────────

@asm_bp.route("/api/asm/asset-states")
def asm_get_asset_states():
    """Return the full asset state map (all hosts) for the session user."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    uid   = session["user_email"].strip()
    store = _load_asset_states(uid)
    return jsonify(store)


# ── GET /api/asm/baseline ─────────────────────────────────────────────────────

@asm_bp.route("/api/asm/baseline")
def asm_get_baseline():
    """Return the current baseline definition for the session user."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    uid   = session["user_email"].strip()
    store = _load_asset_states(uid)
    return jsonify(store.get("baseline") or {"assets": [], "set_at": None, "set_by": None})


# ── POST /api/asm/baseline — promote assets to baseline ──────────────────────

@asm_bp.route("/api/asm/baseline", methods=["POST"])
def asm_set_baseline():
    """Promote a list of asset IDs to the baseline.

    Body: { "assets": ["example.com", "www.example.com", ...], "comment": "..." }

    Replaces the current baseline with the supplied list.  Each asset listed
    is transitioned to the 'baseline' state; assets previously in the baseline
    but omitted from the new list are transitioned to 'new'.
    """
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403

    body          = request.get_json(silent=True) or {}
    new_baseline  = body.get("assets") or []
    comment       = (body.get("comment") or "").strip()

    if not isinstance(new_baseline, list):
        return jsonify({"error": "assets must be a list of hostnames"}), 422
    if not comment:
        return jsonify({"error": "A comment describing the baseline is required."}), 422

    uid   = session["user_email"].strip()
    store = _load_asset_states(uid)
    assets = store.setdefault("assets", {})

    from datetime import timezone as _tz
    ts = datetime.now(_tz.utc).isoformat()

    old_baseline_set = set((store.get("baseline") or {}).get("assets", []))
    new_baseline_set = set(new_baseline)

    # Transition assets entering the baseline → 'baseline'
    for host in new_baseline_set:
        entry      = assets.get(host, {"state": "new", "first_seen": ts, "audit_log": []})
        from_state = entry.get("state", "new")
        if from_state != "baseline":
            entry["state"] = "baseline"
            entry.setdefault("first_seen", ts)
            entry["audit_log"] = entry.get("audit_log", []) + [{
                "action":     "state_change",
                "from_state": from_state,
                "to_state":   "baseline",
                "comment":    comment,
                "actor":      uid,
                "created_at": ts,
            }]
        assets[host] = entry

    # Assets removed from the baseline → revert to 'new'
    for host in old_baseline_set - new_baseline_set:
        entry      = assets.get(host, {"state": "baseline", "first_seen": ts, "audit_log": []})
        from_state = entry.get("state", "baseline")
        entry["state"] = "new"
        entry["audit_log"] = entry.get("audit_log", []) + [{
            "action":     "state_change",
            "from_state": from_state,
            "to_state":   "new",
            "comment":    f"Removed from baseline: {comment}",
            "actor":      uid,
            "created_at": ts,
        }]
        assets[host] = entry

    store["baseline"] = {
        "assets":   sorted(new_baseline_set),
        "set_at":   ts,
        "set_by":   uid,
        "comment":  comment,
    }
    store["assets"] = assets
    _save_asset_states(uid, store)

    return jsonify({
        "baseline": store["baseline"],
        "promoted": len(new_baseline_set - old_baseline_set),
        "removed":  len(old_baseline_set - new_baseline_set),
    })


# ── DELETE /api/asm/baseline/assets/<id> — remove one asset from baseline ─────

@asm_bp.route("/api/asm/baseline/assets/<path:asset_id>", methods=["DELETE"])
def asm_remove_from_baseline(asset_id):
    """Remove a single asset from the baseline, reverting it to 'new'."""
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403

    uid   = session["user_email"].strip()
    store = _load_asset_states(uid)
    assets        = store.setdefault("assets", {})
    baseline_cfg  = store.get("baseline") or {}
    baseline_list = list(baseline_cfg.get("assets", []))

    if asset_id not in baseline_list:
        return jsonify({"error": "Asset is not in the current baseline"}), 404

    from datetime import timezone as _tz
    ts = datetime.now(_tz.utc).isoformat()

    baseline_list.remove(asset_id)
    baseline_cfg["assets"] = baseline_list
    store["baseline"] = baseline_cfg

    entry      = assets.get(asset_id, {"state": "baseline", "first_seen": ts, "audit_log": []})
    from_state = entry.get("state", "baseline")
    entry["state"] = "new"
    entry["audit_log"] = entry.get("audit_log", []) + [{
        "action":     "state_change",
        "from_state": from_state,
        "to_state":   "new",
        "comment":    "Removed from baseline",
        "actor":      uid,
        "created_at": ts,
    }]
    assets[asset_id] = entry
    store["assets"]  = assets
    _save_asset_states(uid, store)

    return jsonify({"asset_id": asset_id, "state": "new", "removed_from_baseline": True})


# ── POST /api/asm/auto-status — bulk confidence-score suggestions (findings) ───

@asm_bp.route("/api/asm/auto-status", methods=["OPTIONS"])
def asm_auto_status_options():
    return add_cors_headers(make_response('', 204))


@asm_bp.route("/api/asm/auto-status", methods=["POST"])
def asm_auto_status():
    """Return automated finding-status transition suggestions based on confidence scores.

    This applies to vulnerability *findings* (not assets).
    State machine: open → investigating → in_review

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
                "id":        f.get("id"),
                "current":   cur,
                "suggested": to,
                "reason":    reason,
            })

    return jsonify({"suggestions": suggestions, "total": len(suggestions)})

