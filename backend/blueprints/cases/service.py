import hashlib
import pathlib
from datetime import datetime, timezone

EVIDENCE_ROOT = pathlib.Path("/opt/cycentra/evidence")


def _infer_case_type(categories: list, tactics: list) -> str:
    combined = " ".join(categories + tactics).lower()
    if "ransomware" in combined:   return "ransomware"
    if "phishing"   in combined:   return "phishing"
    if "brute"      in combined:   return "brute_force"
    if "exfil"      in combined:   return "data_exfil"
    if "lateral"    in combined:   return "lateral_movement"
    return "generic"


def open_case(conn, incident_id: str, opened_by: str, case_type: str = None) -> dict:
    """Set case_opened_at if not already set. Compute MTTD. Write system comment. Return updated incident row."""
    cur = conn.cursor()
    cur.execute("SELECT status, severity, first_seen, case_opened_at, categories, mitre_tactics FROM incidents WHERE id = %s", [incident_id])
    row = cur.fetchone()
    if not row:
        raise ValueError(f"Incident {incident_id} not found")

    status, severity, first_seen, case_opened_at, categories, mitre_tactics = row

    if case_opened_at is not None:
        cur.execute("SELECT id, status, severity, case_opened_at, case_type, case_mttd_seconds, case_mtta_seconds, case_restricted FROM incidents WHERE id = %s", [incident_id])
        return dict(zip([d[0] for d in cur.description], cur.fetchone()))

    now = datetime.now(timezone.utc)
    effective_type = case_type or _infer_case_type(categories or [], mitre_tactics or [])
    mttd = int((now - first_seen).total_seconds()) if first_seen else None

    cur.execute("""
        UPDATE incidents
        SET case_opened_at    = %s,
            case_type         = %s,
            case_mttd_seconds = %s,
            updated_at        = %s
        WHERE id = %s
    """, [now, effective_type, mttd, now, incident_id])

    cur.execute("""
        INSERT INTO case_comments (incident_id, author_email, body, is_system)
        VALUES (%s, 'system', %s, TRUE)
    """, [incident_id, f"Case opened by {opened_by}. Type: {effective_type}."])

    conn.commit()

    cur.execute("SELECT id, status, severity, case_opened_at, case_type, case_mttd_seconds, case_mtta_seconds, case_restricted FROM incidents WHERE id = %s", [incident_id])
    return dict(zip([d[0] for d in cur.description], cur.fetchone()))


def acknowledge_case(conn, incident_id: str, actor: str) -> dict:
    """Set case_ack_at if not set. Compute MTTA from case_opened_at. Return updated incident row."""
    cur = conn.cursor()
    cur.execute("SELECT case_opened_at, case_ack_at FROM incidents WHERE id = %s", [incident_id])
    row = cur.fetchone()
    if not row:
        raise ValueError(f"Incident {incident_id} not found")

    case_opened_at, case_ack_at = row
    if case_ack_at is not None:
        cur.execute("SELECT id, status, severity, case_opened_at, case_ack_at, case_mtta_seconds FROM incidents WHERE id = %s", [incident_id])
        return dict(zip([d[0] for d in cur.description], cur.fetchone()))

    now = datetime.now(timezone.utc)
    mtta = int((now - case_opened_at).total_seconds()) if case_opened_at else None

    cur.execute("""
        UPDATE incidents
        SET case_ack_at       = %s,
            case_mtta_seconds = %s,
            updated_at        = %s
        WHERE id = %s
    """, [now, mtta, now, incident_id])
    conn.commit()

    cur.execute("SELECT id, status, severity, case_opened_at, case_ack_at, case_mtta_seconds FROM incidents WHERE id = %s", [incident_id])
    return dict(zip([d[0] for d in cur.description], cur.fetchone()))


def add_comment(conn, incident_id: str, author_email: str, body: str,
                parent_id: int = None, is_system: bool = False) -> dict:
    """INSERT into case_comments. Never UPDATE. Return new comment row."""
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO case_comments (incident_id, author_email, body, parent_id, is_system)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id, incident_id, author_email, body, created_at, parent_id, is_system
    """, [incident_id, author_email, body, parent_id, is_system])
    row = cur.fetchone()
    conn.commit()
    return dict(zip([d[0] for d in cur.description], row))


def upload_evidence(conn, incident_id: str, uploaded_by: str, filename: str,
                    file_bytes: bytes, description: str = None) -> dict:
    """Compute SHA-256. Write to EVIDENCE_ROOT/<incident_id>/<sha256>.<ext>. INSERT case_evidence row."""
    import mimetypes
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    ext = pathlib.Path(filename).suffix.lstrip(".")
    dest_dir = EVIDENCE_ROOT / incident_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / f"{sha256}.{ext}" if ext else dest_dir / sha256

    cur = conn.cursor()
    cur.execute("SELECT id FROM case_evidence WHERE incident_id = %s AND sha256 = %s AND is_deleted = FALSE", [incident_id, sha256])
    if cur.fetchone():
        raise ValueError(f"Duplicate evidence: sha256 {sha256} already attached to {incident_id}")

    if not dest_path.exists():
        dest_path.write_bytes(file_bytes)

    mime_type = mimetypes.guess_type(filename)[0]
    cur.execute("""
        INSERT INTO case_evidence (incident_id, uploaded_by, filename, mime_type, file_size_bytes, sha256, storage_path, description)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id, incident_id, uploaded_by, uploaded_at, filename, mime_type, file_size_bytes, sha256, storage_path, description
    """, [incident_id, uploaded_by, filename, mime_type, len(file_bytes), sha256, str(dest_path), description])
    row = cur.fetchone()
    conn.commit()
    return dict(zip([d[0] for d in cur.description], row))


def add_ioc(conn, incident_id: str, ioc_value: str, ioc_type: str,
            added_by: str, context_note: str = None) -> dict:
    """Upsert case_ioc (restore if previously soft-removed). Return ioc dict."""
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO case_iocs (incident_id, ioc_value, ioc_type, added_by, context_note, is_removed)
        VALUES (%s, %s, %s, %s, %s, FALSE)
        ON CONFLICT (incident_id, ioc_value, ioc_type) DO UPDATE
            SET is_removed   = FALSE,
                removed_by   = NULL,
                removed_at   = NULL,
                context_note = COALESCE(EXCLUDED.context_note, case_iocs.context_note)
        RETURNING id, incident_id, ioc_value, ioc_type, added_by, added_at, context_note, is_removed
    """, [incident_id, ioc_value, ioc_type, added_by, context_note])
    row = cur.fetchone()
    conn.commit()
    return dict(zip([d[0] for d in cur.description], row))


def get_graph_data(conn, incident_id: str) -> dict:
    """Build graph from existing incident data. Stateless — no persistence."""
    cur = conn.cursor()

    cur.execute("""
        SELECT id, severity, categories, mitre_ids, mitre_tactics,
               affected_agents, affected_users, src_ips, correlated_rules
        FROM incidents WHERE id = %s
    """, [incident_id])
    row = cur.fetchone()
    if not row:
        return {"nodes": [], "edges": []}

    inc_id, severity, categories, mitre_ids, mitre_tactics, \
        affected_agents, affected_users, src_ips, correlated_rules = row

    nodes = [{"id": inc_id, "type": "incident", "label": inc_id, "severity": severity}]
    edges = []

    def _add(node_id, node_type, label):
        nodes.append({"id": node_id, "type": node_type, "label": label})
        edges.append({"source": node_id, "target": inc_id})

    for agent in (affected_agents or []):
        _add(f"host:{agent}", "host", agent)
    for user in (affected_users or []):
        _add(f"user:{user}", "user", user)
    for ip in (src_ips or []):
        _add(f"ip:{ip}", "ip", ip)

    # IOCs
    cur.execute("SELECT id, ioc_value, ioc_type FROM case_iocs WHERE incident_id = %s AND is_removed = FALSE", [incident_id])
    for ioc_id, ioc_value, ioc_type in cur.fetchall():
        _add(f"ioc:{ioc_id}", "ioc", ioc_value)

    # Alert IDs from correlated_rules
    rules = correlated_rules or []
    for rule in (rules if isinstance(rules, list) else []):
        rid = rule.get("rule_id") if isinstance(rule, dict) else str(rule)
        if rid:
            _add(f"alert:{rid}", "alert", f"Rule {rid}")

    return {"nodes": nodes, "edges": edges}


def compute_metrics(conn) -> dict:
    """Compute MTTD, MTTA, MTTR, open cases count, cases by severity, cases by type."""
    cur = conn.cursor()

    cur.execute("""
        SELECT severity,
               AVG(case_mttd_seconds) / 3600.0 AS avg_mttd_h,
               COUNT(*) AS cnt
        FROM incidents
        WHERE case_opened_at IS NOT NULL
          AND case_mttd_seconds IS NOT NULL
          AND case_opened_at > NOW() - INTERVAL '90 days'
        GROUP BY severity
    """)
    mttd_by_severity = {row[0]: {"avg_hours": round(float(row[1]), 2), "count": row[2]} for row in cur.fetchall()}

    cur.execute("""
        SELECT AVG(case_mtta_seconds) / 3600.0
        FROM incidents
        WHERE case_mtta_seconds IS NOT NULL
          AND case_opened_at > NOW() - INTERVAL '90 days'
    """)
    mtta_row = cur.fetchone()
    avg_mtta_h = round(float(mtta_row[0]), 2) if mtta_row and mtta_row[0] else None

    cur.execute("""
        SELECT AVG(EXTRACT(EPOCH FROM (closed_at - first_seen)) / 3600.0)
        FROM incidents
        WHERE closed_at IS NOT NULL
          AND first_seen IS NOT NULL
          AND closed_at > NOW() - INTERVAL '90 days'
          AND severity IN ('critical', 'high', 'medium')
    """)
    mttr_row = cur.fetchone()
    avg_mttr_h = round(float(mttr_row[0]), 2) if mttr_row and mttr_row[0] else None

    cur.execute("""
        SELECT COUNT(*) FROM incidents
        WHERE case_opened_at IS NOT NULL
          AND status IN ('open', 'investigating', 'in_review')
    """)
    open_cases = cur.fetchone()[0] or 0

    cur.execute("""
        SELECT severity, COUNT(*) FROM incidents
        WHERE case_opened_at IS NOT NULL
        GROUP BY severity
    """)
    cases_by_severity = {row[0]: row[1] for row in cur.fetchall()}

    cur.execute("""
        SELECT case_type, COUNT(*) FROM incidents
        WHERE case_opened_at IS NOT NULL
        GROUP BY case_type
    """)
    cases_by_type = {row[0]: row[1] for row in cur.fetchall()}

    return {
        "mttd_by_severity": mttd_by_severity,
        "avg_mtta_hours":    avg_mtta_h,
        "avg_mttr_hours":    avg_mttr_h,
        "open_cases":        open_cases,
        "cases_by_severity": cases_by_severity,
        "cases_by_type":     cases_by_type,
    }
