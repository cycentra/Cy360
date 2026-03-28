"""
blueprints/asm/scanner.py
==========================
Attack Surface Management scan API.

Routes:
  POST /api/scan/trigger      start a scan
  GET  /api/scan/status       poll progress
  GET  /api/scans/latest      fetch latest scan result JSON
"""

import glob
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from flask import Blueprint, request, jsonify, make_response

from core.config import SCANS_DIR, ASM_LOGS, ASM_DIR
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

@asm_bp.route("/api/scan/trigger", methods=["POST"])
def trigger_scan():
    data   = request.get_json() or {}
    domain = data.get("domain", "").strip()
    uid    = data.get("uid", "anonymous")

    if not domain or "." not in domain:
        return jsonify({"error": "Invalid domain"}), 400

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
            f"[{datetime.now().strftime('%H:%M:%S')}] Scan triggered for {domain} by {uid}\n"
        )
    except Exception as le:
        pass  # non-fatal — log init failure

    env = os.environ.copy()
    env["CYCENTRA_OUTPUT_DIR"] = str(user_dir)
    env["CYCENTRA_USER_ID"]    = uid

    try:
        subprocess.Popen(
            [str(python_bin), str(scan_script), domain, uid],
            stdout=open(log_file, "a"),
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"status": "started", "domain": domain, "uid": uid})


# ── Scan status ───────────────────────────────────────────────────────────────

@asm_bp.route("/api/scan/status")
def scan_status():
    log_file = ASM_LOGS / "cycentra_engine.log"
    running, progress, current_module, last_line = False, 0, "", ""

    try:
        if log_file.exists():
            if time.time() - log_file.stat().st_mtime < 600:
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
