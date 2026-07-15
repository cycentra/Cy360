"""
blueprints/detection_rules/routes.py
=======================================
Backend for the "Detection Rules" page (Platform Configuration section) —
lists and manages Sigma, YARA, correlation, and UEBA rules from one place.

Ownership split, and why:
  - Sigma: sigma_engine.py runs INSIDE this Flask process (collector_bridge.py/
    connector_bridge.py call it directly, not over HTTP), so this blueprint
    owns Sigma's DB tables directly (sigma_rule_toggles, custom_sigma_rules)
    via psycopg2 against CYCENTRA_DB_URL — same pattern as blueprints/itam.
    Every mutation calls sigma_engine.reset_engine() so the change is live
    on the very next event processed, no restart needed.
  - YARA: blueprints/edr/routes.py already owns full custom-YARA CRUD
    (edr_custom_yara_rules) — this blueprint does NOT duplicate it. The
    frontend's YARA tab calls /api/edr/yara-rules/custom directly.
  - Correlation + UEBA: owned by the separate correlation-engine service
    (cysiemstack/correlation_engine/main.py, port 8100) since that's the
    process that actually evaluates them per alert. This blueprint proxies
    to its /rules/* routes exactly like siem_proxy.py proxies incidents/
    alerts — the engine's own write handlers invalidate its in-memory rule
    cache right after commit, so "apply on save" happens with zero extra
    coordination from this side.
"""
from __future__ import annotations
import json
import uuid
from functools import wraps

import psycopg2
import psycopg2.extras
import yaml
from flask import Blueprint, jsonify, request, session

from blueprints.rbac.manager import get_user_role
from core.config import CYCENTRA_DB_URL
from cysiemstack.detection.sigma_engine import reset_engine, list_all_rules, SigmaRule
from siem_proxy import _proxy, require_siem_auth, require_siem_admin

detection_rules_bp = Blueprint("detection_rules", __name__, url_prefix="/api/detection-rules")


# ── RBAC ───────────────────────────────────────────────────────────────────────

def _role():
    email = session.get("user_email", "")
    return get_user_role(email) if email else None


def require_viewer(f):
    @wraps(f)
    def _w(*a, **kw):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*a, **kw)
    return _w


def require_admin(f):
    @wraps(f)
    def _w(*a, **kw):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        if _role() != "admin":
            return jsonify({"error": "Admin role required"}), 403
        return f(*a, **kw)
    return _w


# ── DB bootstrap (Sigma tables only — correlation/UEBA tables are owned and
#    created by the correlation-engine service via Base.metadata.create_all) ──

def ensure_tables(db_url: str) -> None:
    """Called by app.py after blueprint registration."""
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sigma_rule_toggles (
                  rule_id     TEXT PRIMARY KEY,
                  enabled     BOOLEAN NOT NULL DEFAULT TRUE,
                  updated_at  TIMESTAMPTZ DEFAULT NOW(),
                  updated_by  TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS custom_sigma_rules (
                  id          SERIAL PRIMARY KEY,
                  rule_key    TEXT UNIQUE NOT NULL,
                  title       TEXT NOT NULL,
                  level       TEXT DEFAULT 'medium',
                  logsource   JSONB DEFAULT '{}'::jsonb,
                  yaml_text   TEXT NOT NULL,
                  enabled     BOOLEAN NOT NULL DEFAULT TRUE,
                  created_at  TIMESTAMPTZ DEFAULT NOW(),
                  updated_at  TIMESTAMPTZ DEFAULT NOW(),
                  created_by  TEXT
                )
            """)
        conn.commit()
    finally:
        conn.close()


def _db():
    return psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)


# ── Sigma ────────────────────────────────────────────────────────────────────

@detection_rules_bp.route("/sigma", methods=["GET"])
@require_viewer
def list_sigma_rules():
    """Lists EVERY rule (bundled + imported + custom), including disabled
    ones — list_all_rules() builds a fresh engine rather than reading the
    live matching singleton's enabled-only `.rules`, so a disabled rule
    stays visible with a way back to re-enabling it instead of vanishing."""
    q         = (request.args.get("q") or "").strip().lower()
    source    = (request.args.get("source") or "").strip().lower()
    technique = (request.args.get("technique") or "").strip().upper()
    limit     = min(int(request.args.get("limit", 100)), 500)
    offset    = int(request.args.get("offset", 0))

    rules = list_all_rules()
    if q:
        rules = [r for r in rules if q in r.title.lower() or q in r.rule_id.lower()
                 or any(q in t.lower() for t in r.mitre_techniques)]
    if source:
        rules = [r for r in rules if r.source == source]
    if technique:
        rules = [r for r in rules if technique in r.mitre_techniques]

    total = len(rules)
    page = rules[offset:offset + limit]
    return jsonify({
        "total": total,
        "items": [
            {
                "rule_id": r.rule_id, "title": r.title, "level": r.level,
                "logsource": r.logsource, "source": r.source, "db_id": r.db_id,
                "enabled": r.enabled, "editable": r.source == "custom",
                "mitre_techniques": r.mitre_techniques, "mitre_tactics": r.mitre_tactics,
            }
            for r in page
        ],
    })


@detection_rules_bp.route("/sigma/refresh-corpus", methods=["POST"])
@require_admin
def refresh_sigma_corpus_route():
    """Manual trigger for the same refresh the weekly scheduled job runs
    (cysiemstack/detection/rule_corpus_refresh.py) — re-fetches SigmaHQ,
    validates, and only activates if the validation gate passes. Runs
    synchronously; a full refresh (git fetch + reimport + smoke test) can
    take anywhere from several seconds to a couple minutes depending on
    network conditions, same as the scheduled run."""
    from cysiemstack.detection.rule_corpus_refresh import refresh_sigma_corpus
    result = refresh_sigma_corpus()
    return jsonify(result), (200 if result.get("ok") else 502)


@detection_rules_bp.route("/yara/refresh-corpus", methods=["POST"])
@require_admin
def refresh_yara_corpus_route():
    """Manual trigger for the YARA (signature-base) corpus refresh — see
    refresh_sigma_corpus_route()'s docstring for the synchronous-timing note."""
    from cysiemstack.detection.rule_corpus_refresh import refresh_yara_corpus
    result = refresh_yara_corpus()
    return jsonify(result), (200 if result.get("ok") else 502)


@detection_rules_bp.route("/sigma", methods=["POST"])
@require_admin
def create_custom_sigma_rule():
    body = request.get_json(force=True) or {}
    yaml_text = body.get("yaml_text", "")
    try:
        data = yaml.safe_load(yaml_text)
        rule = SigmaRule(data, source="custom")  # validates title/detection/condition shape
    except Exception as exc:
        return jsonify({"error": f"Invalid Sigma rule: {exc}"}), 400

    rule_key = f"custom-{uuid.uuid4().hex[:12]}"
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO custom_sigma_rules (rule_key, title, level, logsource, yaml_text, created_by)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                (rule_key, rule.title, rule.level, json.dumps(rule.logsource), yaml_text,
                 session.get("user_email")),
            )
            new_id = cur.fetchone()[0]
        conn.commit()
    finally:
        conn.close()

    reset_engine()
    return jsonify({"ok": True, "id": new_id, "rule_id": rule_key}), 201


@detection_rules_bp.route("/sigma/<rule_key>", methods=["PUT"])
@require_admin
def update_custom_sigma_rule(rule_key):
    body = request.get_json(force=True) or {}
    yaml_text = body.get("yaml_text", "")
    try:
        data = yaml.safe_load(yaml_text)
        rule = SigmaRule(data, source="custom")
    except Exception as exc:
        return jsonify({"error": f"Invalid Sigma rule: {exc}"}), 400

    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE custom_sigma_rules
                   SET title=%s, level=%s, logsource=%s, yaml_text=%s, updated_at=NOW()
                   WHERE rule_key=%s""",
                (rule.title, rule.level, json.dumps(rule.logsource), yaml_text, rule_key),
            )
            if cur.rowcount == 0:
                return jsonify({"error": "Custom rule not found"}), 404
        conn.commit()
    finally:
        conn.close()

    reset_engine()
    return jsonify({"ok": True})


@detection_rules_bp.route("/sigma/<rule_key>", methods=["DELETE"])
@require_admin
def delete_custom_sigma_rule(rule_key):
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM custom_sigma_rules WHERE rule_key=%s", (rule_key,))
            if cur.rowcount == 0:
                return jsonify({"error": "Custom rule not found"}), 404
        conn.commit()
    finally:
        conn.close()

    reset_engine()
    return jsonify({"ok": True})


@detection_rules_bp.route("/sigma/<path:rule_id>/toggle", methods=["POST"])
@require_admin
def toggle_sigma_rule(rule_id):
    """Works for ANY currently-loaded rule (bundled/imported/custom) — a
    custom rule's own `enabled` column is the single source of truth for it,
    everything else goes through the generic sigma_rule_toggles override."""
    body = request.get_json(force=True) or {}
    enabled = bool(body.get("enabled", True))

    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM custom_sigma_rules WHERE rule_key=%s", (rule_id,))
            is_custom = cur.fetchone() is not None
            if is_custom:
                cur.execute(
                    "UPDATE custom_sigma_rules SET enabled=%s, updated_at=NOW() WHERE rule_key=%s",
                    (enabled, rule_id),
                )
            else:
                cur.execute(
                    """INSERT INTO sigma_rule_toggles (rule_id, enabled, updated_at, updated_by)
                       VALUES (%s, %s, NOW(), %s)
                       ON CONFLICT (rule_id) DO UPDATE SET enabled=%s, updated_at=NOW(), updated_by=%s""",
                    (rule_id, enabled, session.get("user_email"), enabled, session.get("user_email")),
                )
        conn.commit()
    finally:
        conn.close()

    reset_engine()
    return jsonify({"ok": True, "rule_id": rule_id, "enabled": enabled})


# ── Correlation + UEBA — thin proxy to the correlation-engine service ────────
# Same pattern as siem_proxy.py: forward the request, stream back the response.
# The engine is the single writer for these tables and invalidates its own
# rule cache right after each commit — nothing else to coordinate here.

@detection_rules_bp.route("/correlation", methods=["GET"])
@require_siem_auth
def list_correlation_rules():
    return _proxy("/rules/correlation")


@detection_rules_bp.route("/correlation/<rule_key>/toggle", methods=["POST"])
@require_siem_admin
def toggle_correlation_rule(rule_key):
    return _proxy(f"/rules/correlation/{rule_key}/toggle")


@detection_rules_bp.route("/correlation/custom", methods=["GET"])
@require_siem_auth
def list_custom_correlation_rules():
    return _proxy("/rules/correlation/custom")


@detection_rules_bp.route("/correlation/custom", methods=["POST"])
@require_siem_admin
def create_custom_correlation_rule():
    return _proxy("/rules/correlation/custom")


@detection_rules_bp.route("/correlation/custom/<int:rule_id>", methods=["PATCH"])
@require_siem_admin
def update_custom_correlation_rule(rule_id):
    return _proxy(f"/rules/correlation/custom/{rule_id}")


@detection_rules_bp.route("/correlation/custom/<int:rule_id>", methods=["DELETE"])
@require_siem_admin
def delete_custom_correlation_rule(rule_id):
    return _proxy(f"/rules/correlation/custom/{rule_id}")


@detection_rules_bp.route("/ueba", methods=["GET"])
@require_siem_auth
def list_ueba_rules():
    return _proxy("/rules/ueba")


@detection_rules_bp.route("/ueba/<rule_key>/toggle", methods=["POST"])
@require_siem_admin
def toggle_ueba_rule(rule_key):
    return _proxy(f"/rules/ueba/{rule_key}/toggle")


@detection_rules_bp.route("/ueba/custom", methods=["GET"])
@require_siem_auth
def list_custom_ueba_rules():
    return _proxy("/rules/ueba/custom")


@detection_rules_bp.route("/ueba/custom", methods=["POST"])
@require_siem_admin
def create_custom_ueba_rule():
    return _proxy("/rules/ueba/custom")


@detection_rules_bp.route("/ueba/custom/<int:rule_id>", methods=["PATCH"])
@require_siem_admin
def update_custom_ueba_rule(rule_id):
    return _proxy(f"/rules/ueba/custom/{rule_id}")


@detection_rules_bp.route("/ueba/custom/<int:rule_id>", methods=["DELETE"])
@require_siem_admin
def delete_custom_ueba_rule(rule_id):
    return _proxy(f"/rules/ueba/custom/{rule_id}")
