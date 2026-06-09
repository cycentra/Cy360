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


def _row(cur) -> dict | None:
    """Return the last fetchone() as a plain dict, regardless of cursor factory."""
    row = cur.fetchone()
    if row is None:
        return None
    if isinstance(row, dict):
        return dict(row)
    # tuple row — zip with description
    return dict(zip([d[0] for d in cur.description], row))


def _rows(cur) -> list[dict]:
    rows = cur.fetchall()
    if not rows:
        return []
    if rows and isinstance(rows[0], dict):
        return [dict(r) for r in rows]
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in rows]


def open_case(conn, incident_id: str, opened_by: str, case_type: str = None) -> dict:
    """Set case_opened_at if not already set. Compute MTTD. Write system comment."""
    cur = conn.cursor()
    cur.execute(
        "SELECT status, severity, first_seen, case_opened_at, categories, mitre_tactics "
        "FROM incidents WHERE id = %s",
        [incident_id],
    )
    row = _row(cur)
    if row is None:
        raise ValueError(f"Incident {incident_id} not found")

    if row["case_opened_at"] is not None:
        # Already has a case — return current state
        cur.execute(
            "SELECT id, status, severity, case_opened_at, case_type, "
            "case_mttd_seconds, case_mtta_seconds, case_restricted "
            "FROM incidents WHERE id = %s",
            [incident_id],
        )
        return _row(cur)

    now            = datetime.now(timezone.utc)
    first_seen     = row["first_seen"]
    categories     = row["categories"] or []
    mitre_tactics  = row["mitre_tactics"] or []
    effective_type = case_type or _infer_case_type(categories, mitre_tactics)
    mttd           = int((now - first_seen).total_seconds()) if first_seen else None

    cur.execute(
        """
        UPDATE incidents
        SET case_opened_at    = %s,
            case_type         = %s,
            case_mttd_seconds = %s,
            updated_at        = %s
        WHERE id = %s
        """,
        [now, effective_type, mttd, now, incident_id],
    )

    cur.execute(
        "INSERT INTO case_comments (incident_id, author_email, body, is_system) "
        "VALUES (%s, 'system', %s, TRUE)",
        [incident_id, f"Case opened by {opened_by}. Type: {effective_type}."],
    )

    conn.commit()

    cur.execute(
        "SELECT id, status, severity, case_opened_at, case_type, "
        "case_mttd_seconds, case_mtta_seconds, case_restricted "
        "FROM incidents WHERE id = %s",
        [incident_id],
    )
    return _row(cur)


def acknowledge_case(conn, incident_id: str, actor: str) -> dict:
    """Set case_ack_at if not set. Compute MTTA from case_opened_at."""
    cur = conn.cursor()
    cur.execute(
        "SELECT case_opened_at, case_ack_at FROM incidents WHERE id = %s",
        [incident_id],
    )
    row = _row(cur)
    if row is None:
        raise ValueError(f"Incident {incident_id} not found")

    if row["case_ack_at"] is not None:
        cur.execute(
            "SELECT id, status, severity, case_opened_at, case_ack_at, case_mtta_seconds "
            "FROM incidents WHERE id = %s",
            [incident_id],
        )
        return _row(cur)

    now          = datetime.now(timezone.utc)
    case_opened  = row["case_opened_at"]
    mtta         = int((now - case_opened).total_seconds()) if case_opened else None

    cur.execute(
        """
        UPDATE incidents
        SET case_ack_at       = %s,
            case_mtta_seconds = %s,
            updated_at        = %s
        WHERE id = %s
        """,
        [now, mtta, now, incident_id],
    )
    conn.commit()

    cur.execute(
        "SELECT id, status, severity, case_opened_at, case_ack_at, case_mtta_seconds "
        "FROM incidents WHERE id = %s",
        [incident_id],
    )
    return _row(cur)


def add_comment(conn, incident_id: str, author_email: str, body: str,
                parent_id: int = None, is_system: bool = False) -> dict:
    """INSERT into case_comments. Never UPDATE. Return new comment row."""
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO case_comments (incident_id, author_email, body, parent_id, is_system)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id, incident_id, author_email, body, created_at, parent_id, is_system
        """,
        [incident_id, author_email, body, parent_id, is_system],
    )
    result = _row(cur)
    conn.commit()
    return result


def upload_evidence(conn, incident_id: str, uploaded_by: str, filename: str,
                    file_bytes: bytes, description: str = None) -> dict:
    """SHA-256, write to EVIDENCE_ROOT/<incident_id>/<sha256>.<ext>, INSERT row."""
    import mimetypes
    sha256    = hashlib.sha256(file_bytes).hexdigest()
    ext       = pathlib.Path(filename).suffix.lstrip(".")
    dest_dir  = EVIDENCE_ROOT / incident_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / (f"{sha256}.{ext}" if ext else sha256)

    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM case_evidence WHERE incident_id = %s AND sha256 = %s AND is_deleted = FALSE",
        [incident_id, sha256],
    )
    if _row(cur):
        raise ValueError(f"Duplicate evidence: sha256 {sha256} already attached to {incident_id}")

    if not dest_path.exists():
        dest_path.write_bytes(file_bytes)

    mime_type = mimetypes.guess_type(filename)[0]
    cur.execute(
        """
        INSERT INTO case_evidence
            (incident_id, uploaded_by, filename, mime_type, file_size_bytes, sha256, storage_path, description)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id, incident_id, uploaded_by, uploaded_at, filename,
                  mime_type, file_size_bytes, sha256, storage_path, description
        """,
        [incident_id, uploaded_by, filename, mime_type, len(file_bytes), sha256, str(dest_path), description],
    )
    result = _row(cur)
    conn.commit()
    return result


def add_ioc(conn, incident_id: str, ioc_value: str, ioc_type: str,
            added_by: str, context_note: str = None) -> dict:
    """Upsert case_ioc (restore if previously soft-removed). Return ioc dict."""
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO case_iocs (incident_id, ioc_value, ioc_type, added_by, context_note, is_removed)
        VALUES (%s, %s, %s, %s, %s, FALSE)
        ON CONFLICT (incident_id, ioc_value, ioc_type) DO UPDATE
            SET is_removed   = FALSE,
                removed_by   = NULL,
                removed_at   = NULL,
                context_note = COALESCE(EXCLUDED.context_note, case_iocs.context_note)
        RETURNING id, incident_id, ioc_value, ioc_type, added_by, added_at, context_note, is_removed
        """,
        [incident_id, ioc_value, ioc_type, added_by, context_note],
    )
    result = _row(cur)
    conn.commit()
    return result


def get_graph_data(conn, incident_id: str) -> dict:
    """Build graph from existing incident data. Stateless — no persistence."""
    cur = conn.cursor()
    cur.execute(
        "SELECT id, severity, categories, mitre_ids, mitre_tactics, "
        "affected_agents, affected_users, src_ips, correlated_rules "
        "FROM incidents WHERE id = %s",
        [incident_id],
    )
    row = _row(cur)
    if not row:
        return {"nodes": [], "edges": []}

    nodes = [{"id": row["id"], "type": "incident", "label": row["id"], "severity": row["severity"]}]
    edges = []

    def _add(node_id, node_type, label):
        nodes.append({"id": node_id, "type": node_type, "label": label})
        edges.append({"source": node_id, "target": row["id"]})

    for agent in (row["affected_agents"] or []):
        _add(f"host:{agent}", "host", agent)
    for user in (row["affected_users"] or []):
        _add(f"user:{user}", "user", user)
    for ip in (row["src_ips"] or []):
        _add(f"ip:{ip}", "ip", ip)

    cur.execute(
        "SELECT id, ioc_value, ioc_type FROM case_iocs "
        "WHERE incident_id = %s AND is_removed = FALSE",
        [incident_id],
    )
    for ioc in _rows(cur):
        _add(f"ioc:{ioc['id']}", "ioc", ioc["ioc_value"])

    rules = row["correlated_rules"] or []
    for rule in (rules if isinstance(rules, list) else []):
        rid = rule.get("rule_id") if isinstance(rule, dict) else str(rule)
        if rid:
            _add(f"alert:{rid}", "alert", f"Rule {rid}")

    return {"nodes": nodes, "edges": edges}


def compute_metrics(conn) -> dict:
    """MTTD, MTTA, MTTR, status breakdown, trend, analyst distribution, ASM/SIEM split."""
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
    mttd_by_severity = {
        r["severity"]: {"avg_hours": round(float(r["avg_mttd_h"]), 2), "count": r["cnt"]}
        for r in _rows(cur)
    }

    cur.execute("""
        SELECT AVG(case_mtta_seconds) / 3600.0 AS avg
        FROM incidents
        WHERE case_mtta_seconds IS NOT NULL
          AND case_opened_at > NOW() - INTERVAL '90 days'
    """)
    mtta_row = _row(cur)
    avg_mtta_h = round(float(mtta_row["avg"]), 2) if mtta_row and mtta_row["avg"] else None

    cur.execute("""
        SELECT AVG(EXTRACT(EPOCH FROM (closed_at - first_seen)) / 3600.0) AS avg
        FROM incidents
        WHERE closed_at IS NOT NULL
          AND first_seen IS NOT NULL
          AND closed_at > NOW() - INTERVAL '90 days'
          AND severity IN ('critical', 'high', 'medium')
    """)
    mttr_row = _row(cur)
    avg_mttr_h = round(float(mttr_row["avg"]), 2) if mttr_row and mttr_row["avg"] else None

    cur.execute("""
        SELECT COUNT(*) AS cnt FROM incidents
        WHERE case_opened_at IS NOT NULL
          AND status IN ('open', 'investigating', 'in_review')
    """)
    open_cases = (_row(cur) or {}).get("cnt", 0) or 0

    cur.execute("SELECT COUNT(*) AS cnt FROM incidents WHERE case_opened_at IS NOT NULL")
    total_cases = (_row(cur) or {}).get("cnt", 0) or 0

    cur.execute("""
        SELECT severity, COUNT(*) AS cnt FROM incidents
        WHERE case_opened_at IS NOT NULL
        GROUP BY severity
    """)
    cases_by_severity = {r["severity"]: r["cnt"] for r in _rows(cur)}

    cur.execute("""
        SELECT case_type, COUNT(*) AS cnt FROM incidents
        WHERE case_opened_at IS NOT NULL
        GROUP BY case_type
    """)
    cases_by_type = {r["case_type"]: r["cnt"] for r in _rows(cur)}

    # Status breakdown
    cur.execute("""
        SELECT status, COUNT(*) AS cnt FROM incidents
        WHERE case_opened_at IS NOT NULL
        GROUP BY status
    """)
    cases_by_status = {r["status"]: r["cnt"] for r in _rows(cur)}

    # 30-day trend: cases opened per day
    cur.execute("""
        SELECT (case_opened_at AT TIME ZONE 'UTC')::date AS day, COUNT(*) AS cnt
        FROM incidents
        WHERE case_opened_at IS NOT NULL
          AND case_opened_at > NOW() - INTERVAL '30 days'
        GROUP BY 1
        ORDER BY 1
    """)
    trend_30d = [{"day": str(r["day"]), "count": r["cnt"]} for r in _rows(cur)]

    # Average age of still-open cases
    cur.execute("""
        SELECT AVG(EXTRACT(EPOCH FROM (NOW() - case_opened_at)) / 3600.0) AS avg_h
        FROM incidents
        WHERE case_opened_at IS NOT NULL
          AND status IN ('open', 'investigating', 'in_review')
    """)
    age_row = _row(cur)
    avg_age_h = round(float(age_row["avg_h"]), 1) if age_row and age_row["avg_h"] else None

    # Cases by assigned analyst (top 10)
    cur.execute("""
        SELECT COALESCE(assigned_to, 'Unassigned') AS analyst, COUNT(*) AS cnt
        FROM incidents
        WHERE case_opened_at IS NOT NULL
        GROUP BY 1
        ORDER BY cnt DESC
        LIMIT 10
    """)
    by_analyst = [{"analyst": r["analyst"], "count": r["cnt"]} for r in _rows(cur)]

    # ASM (External Exposure) vs SIEM (Internal) split
    cur.execute("""
        SELECT
          COUNT(*) FILTER (WHERE id LIKE 'ASM-%%')       AS asm_count,
          COUNT(*) FILTER (WHERE id NOT LIKE 'ASM-%%')   AS siem_count
        FROM incidents
        WHERE case_opened_at IS NOT NULL
    """)
    split_row = _row(cur) or {}
    asm_vs_siem = {
        "asm":  split_row.get("asm_count")  or 0,
        "siem": split_row.get("siem_count") or 0,
    }

    return {
        "total_cases":       total_cases,
        "open_cases":        open_cases,
        "mttd_by_severity":  mttd_by_severity,
        "avg_mtta_hours":    avg_mtta_h,
        "avg_mttr_hours":    avg_mttr_h,
        "avg_age_hours":     avg_age_h,
        "cases_by_severity": cases_by_severity,
        "cases_by_status":   cases_by_status,
        "cases_by_type":     cases_by_type,
        "by_analyst":        by_analyst,
        "trend_30d":         trend_30d,
        "asm_vs_siem":       asm_vs_siem,
    }
