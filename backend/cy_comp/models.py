"""
cy_comp/models.py
==================
DDL definitions for all 12 CyCentra GRC Compliance tables.

Naming convention: all tables prefixed with `cy_comp_` to avoid any conflict
with existing tables in the correlation PostgreSQL 16 cluster.

Connection: reuses CYCENTRA_DB_URL (same as cy_users / RBAC).

Usage:
  from cy_comp.models import ensure_tables, db
  ensure_tables()          # called once at app startup
  with db() as conn: ...   # yields a psycopg2 connection
"""

import logging
from contextlib import contextmanager

from core.config import CYCENTRA_DB_URL

log = logging.getLogger("cycentra.cy_comp.models")

# ── State guard ───────────────────────────────────────────────────────────────
_tables_ready: bool = False


# ── DB context manager ────────────────────────────────────────────────────────
@contextmanager
def db():
    """Yield a psycopg2 connection; auto-commits on clean exit, rolls back on error."""
    try:
        import psycopg2
    except ImportError:
        raise RuntimeError("psycopg2-binary not installed")
    conn = psycopg2.connect(CYCENTRA_DB_URL, connect_timeout=5)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── DDL statements ────────────────────────────────────────────────────────────

_DDL_STATEMENTS = [

    # 1. Risk Register
    """
    CREATE TABLE IF NOT EXISTS cy_comp_risks (
        id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        title           TEXT        NOT NULL,
        description     TEXT,
        category        TEXT,
        owner           TEXT,
        likelihood      INTEGER     CHECK (likelihood BETWEEN 1 AND 5),
        impact          INTEGER     CHECK (impact BETWEEN 1 AND 5),
        risk_score      INTEGER,
        appetite        TEXT        DEFAULT 'medium',
        status          TEXT        NOT NULL DEFAULT 'open',
        treatment       TEXT        DEFAULT 'mitigate',
        due_date        TIMESTAMPTZ,
        frameworks      JSONB       DEFAULT '[]',
        controls        JSONB       DEFAULT '[]',
        ai_analysis     TEXT,
        ai_mapped_controls JSONB    DEFAULT '{}',
        created_by      TEXT,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,

    # 2. Compliance Findings
    """
    CREATE TABLE IF NOT EXISTS cy_comp_findings (
        id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        framework       TEXT        NOT NULL,
        control_id      TEXT,
        control_name    TEXT,
        severity        TEXT        NOT NULL DEFAULT 'medium',
        title           TEXT        NOT NULL,
        description     TEXT,
        ai_analysis     TEXT,
        remediation     TEXT,
        evidence        JSONB       DEFAULT '[]',
        status          TEXT        NOT NULL DEFAULT 'open',
        source_type     TEXT        DEFAULT 'manual',
        assigned_to     TEXT,
        alert_id        TEXT,
        created_by      TEXT,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,

    # 3. Compliance Reports
    """
    CREATE TABLE IF NOT EXISTS cy_comp_reports (
        id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        title           TEXT        NOT NULL,
        framework       TEXT,
        period_start    TIMESTAMPTZ,
        period_end      TIMESTAMPTZ,
        overall_score   REAL,
        summary         TEXT,
        content_json    JSONB,
        pdf_path        TEXT,
        generated_by    TEXT,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,

    # 4. Policy Documents (RAG source)
    """
    CREATE TABLE IF NOT EXISTS cy_comp_policy_docs (
        id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        name            TEXT        NOT NULL,
        description     TEXT,
        file_path       TEXT,
        file_type       TEXT,
        collection_id   TEXT        NOT NULL,
        cymind_doc_id   TEXT,
        framework       TEXT,
        indexed         BOOLEAN     NOT NULL DEFAULT FALSE,
        uploaded_by     TEXT,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,

    # 5. SIEM Connections
    """
    CREATE TABLE IF NOT EXISTS cy_comp_siem_connections (
        id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        name            TEXT        NOT NULL,
        siem_type       TEXT        NOT NULL,
        host            TEXT,
        port            INTEGER     DEFAULT 55000,
        username        TEXT,
        password_enc    TEXT,
        api_key_enc     TEXT,
        extra_config    JSONB       DEFAULT '{}',
        is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
        last_sync       TIMESTAMPTZ,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,

    # 6. Framework Scores (cached compliance posture)
    """
    CREATE TABLE IF NOT EXISTS cy_comp_framework_scores (
        id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        framework       TEXT        NOT NULL,
        score           REAL        DEFAULT 0.0,
        total_controls  INTEGER     DEFAULT 0,
        passing         INTEGER     DEFAULT 0,
        failing         INTEGER     DEFAULT 0,
        critical_gaps   INTEGER     DEFAULT 0,
        computed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_cy_comp_fw_scores_framework ON cy_comp_framework_scores (framework);
    """,

    # 7. Controls Library
    """
    CREATE TABLE IF NOT EXISTS cy_comp_controls (
        id                      TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        framework               TEXT        NOT NULL,
        control_id              TEXT        NOT NULL,
        title                   TEXT        NOT NULL,
        description             TEXT,
        category                TEXT,
        implementation_status   TEXT        NOT NULL DEFAULT 'not_implemented',
        owner                   TEXT,
        implementation_guidance TEXT,
        test_procedure          TEXT,
        framework_mappings      JSONB       DEFAULT '{}',
        evidence_count          INTEGER     DEFAULT 0,
        last_reviewed           TIMESTAMPTZ,
        created_by              TEXT,
        created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_cy_comp_controls_framework ON cy_comp_controls (framework);
    """,

    # 8. Evidence Records
    """
    CREATE TABLE IF NOT EXISTS cy_comp_evidence (
        id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        title           TEXT        NOT NULL,
        type            TEXT        DEFAULT 'document',
        file_path       TEXT,
        file_type       TEXT,
        description     TEXT,
        finding_id      TEXT        REFERENCES cy_comp_findings (id) ON DELETE SET NULL,
        control_id      TEXT        REFERENCES cy_comp_controls (id) ON DELETE SET NULL,
        ai_gap_status   TEXT,
        ai_gap_analysis TEXT,
        uploaded_by     TEXT,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_cy_comp_evidence_finding ON cy_comp_evidence (finding_id);
    CREATE INDEX IF NOT EXISTS idx_cy_comp_evidence_control ON cy_comp_evidence (control_id);
    """,

    # 9. AI Audit Log
    """
    CREATE TABLE IF NOT EXISTS cy_comp_ai_audit_log (
        id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        entity_type     TEXT        NOT NULL,
        entity_id       TEXT,
        prompt_hash     TEXT,
        response_summary TEXT,
        model_used      TEXT,
        duration_ms     INTEGER,
        created_by      TEXT,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,

    # 10. Report Jobs (APScheduler tracking)
    """
    CREATE TABLE IF NOT EXISTS cy_comp_report_jobs (
        job_id          TEXT        PRIMARY KEY,
        status          TEXT        NOT NULL DEFAULT 'pending',
        requested_by    TEXT,
        framework       TEXT,
        period_start    TEXT,
        period_end      TEXT,
        progress        INTEGER     DEFAULT 0,
        result_path     TEXT,
        error           TEXT,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,

    # 11. Risk Appetite (thresholds per category / framework)
    """
    CREATE TABLE IF NOT EXISTS cy_comp_risk_appetite (
        id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        category        TEXT        NOT NULL,
        framework       TEXT,
        appetite_label  TEXT        NOT NULL DEFAULT 'medium',
        score_threshold INTEGER     NOT NULL DEFAULT 9,
        description     TEXT,
        updated_by      TEXT,
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (category, framework)
    );
    """,

    # 12. Compliance Alerts (live feed from SIEM bridge)
    """
    CREATE TABLE IF NOT EXISTS cy_comp_alerts (
        id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        alert_hash      TEXT        UNIQUE,
        external_id     TEXT,
        source_type     TEXT        DEFAULT 'correlation_engine',
        severity        TEXT        NOT NULL DEFAULT 'medium',
        framework       TEXT,
        control_id      TEXT,
        title           TEXT        NOT NULL,
        description     TEXT,
        agent_name      TEXT,
        agent_ip        TEXT,
        raw_data        JSONB       DEFAULT '{}',
        processed       BOOLEAN     NOT NULL DEFAULT FALSE,
        acknowledged    BOOLEAN     NOT NULL DEFAULT FALSE,
        finding_id      TEXT        REFERENCES cy_comp_findings (id) ON DELETE SET NULL,
        timestamp       TIMESTAMPTZ,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_cy_comp_alerts_hash      ON cy_comp_alerts (alert_hash);
    CREATE INDEX IF NOT EXISTS idx_cy_comp_alerts_framework ON cy_comp_alerts (framework);
    CREATE INDEX IF NOT EXISTS idx_cy_comp_alerts_severity  ON cy_comp_alerts (severity);
    """,

    # 13. Questionnaire Templates (framework-specific questions, seeded from code)
    """
    CREATE TABLE IF NOT EXISTS cy_comp_questionnaire_templates (
        id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        framework       TEXT        NOT NULL,
        section         TEXT        NOT NULL,
        question_id     TEXT        NOT NULL UNIQUE,
        question        TEXT        NOT NULL,
        guidance        TEXT,
        control_ref     TEXT,
        weight          INTEGER     NOT NULL DEFAULT 2,
        question_type   TEXT        NOT NULL DEFAULT 'yes_no',
        options         JSONB       DEFAULT '[]',
        order_idx       INTEGER     NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_cy_comp_qtpl_framework ON cy_comp_questionnaire_templates (framework);
    """,

    # 14. Questionnaire Responses (answers per user/session per framework)
    """
    CREATE TABLE IF NOT EXISTS cy_comp_questionnaire_responses (
        id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        framework       TEXT        NOT NULL,
        question_id     TEXT        NOT NULL,
        response        TEXT,
        score           INTEGER,
        notes           TEXT,
        evidence_refs   JSONB       DEFAULT '[]',
        responded_by    TEXT,
        responded_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        reviewed_by     TEXT,
        reviewed_at     TIMESTAMPTZ,
        UNIQUE (framework, question_id)
    );
    CREATE INDEX IF NOT EXISTS idx_cy_comp_qresp_framework ON cy_comp_questionnaire_responses (framework);
    """,

    # 15. Statement of Applicability — ISO 27001 Cl.6.1.3(d)
    #     One row per (framework, control_id); populated on first access, updated by analyst
    """
    CREATE TABLE IF NOT EXISTS cy_comp_soa_entries (
        id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        framework       TEXT        NOT NULL,
        control_id      TEXT        NOT NULL,
        included        BOOLEAN     NOT NULL DEFAULT TRUE,
        justification   TEXT,
        updated_by      TEXT,
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (framework, control_id)
    );
    CREATE INDEX IF NOT EXISTS idx_cy_comp_soa_framework ON cy_comp_soa_entries (framework);
    """,

    # 16. Cross-Framework Question Correlations
    #     Static pairs seeded from cy_comp/data/question_correlations.py.
    #     Stored bidirectionally (A→B and B→A) for O(1) lookup by question_id_a.
    """
    CREATE TABLE IF NOT EXISTS cy_comp_question_correlations (
        id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
        cluster_id      TEXT        NOT NULL,
        cluster_theme   TEXT        NOT NULL,
        framework_a     TEXT        NOT NULL,
        question_id_a   TEXT        NOT NULL,
        framework_b     TEXT        NOT NULL,
        question_id_b   TEXT        NOT NULL,
        similarity_type TEXT        NOT NULL DEFAULT 'equivalent',
        confidence      NUMERIC(4,2) NOT NULL DEFAULT 1.0,
        UNIQUE (question_id_a, question_id_b)
    );
    CREATE INDEX IF NOT EXISTS idx_cy_comp_qcorr_cluster ON cy_comp_question_correlations (cluster_id);
    CREATE INDEX IF NOT EXISTS idx_cy_comp_qcorr_qid_a  ON cy_comp_question_correlations (question_id_a);
    """,
]

# Column migrations for future schema evolution (idempotent ALTER TABLE)
_MIGRATE_COLUMNS: list[str] = [
    # Legacy cy_comp_alerts columns (kept for FK compatibility only — no longer populated)
    "ALTER TABLE cy_comp_alerts ADD COLUMN IF NOT EXISTS controls_json JSONB DEFAULT '{}';",
    "ALTER TABLE cy_comp_alerts ADD COLUMN IF NOT EXISTS rule_level INTEGER;",
    "ALTER TABLE cy_comp_alerts ADD COLUMN IF NOT EXISTS rule_id TEXT;",
    "ALTER TABLE cy_comp_alerts ADD COLUMN IF NOT EXISTS mitre_technique TEXT;",

    # ── Compliance enrichment columns on existing correlation engine tables ────
    # NULL = not yet processed, FALSE = processed + not relevant, TRUE = relevant
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS is_compliance_relevant BOOLEAN;",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS compliance_frameworks TEXT[];",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS compliance_controls JSONB DEFAULT '{}';",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS compliance_confidence NUMERIC(4,2);",

    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS compliance_frameworks TEXT[];",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS compliance_controls JSONB DEFAULT '{}';",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS compliance_confidence NUMERIC(4,2);",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS compliance_breach BOOLEAN DEFAULT FALSE;",

    # Verdict + auto-generated flag on findings
    "ALTER TABLE cy_comp_findings ADD COLUMN IF NOT EXISTS verdict TEXT DEFAULT 'open';",
    "ALTER TABLE cy_comp_findings ADD COLUMN IF NOT EXISTS auto_generated BOOLEAN DEFAULT FALSE;",
    "ALTER TABLE cy_comp_findings ADD COLUMN IF NOT EXISTS alert_count INTEGER DEFAULT 0;",
    "ALTER TABLE cy_comp_findings ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;",
    "ALTER TABLE cy_comp_findings ADD COLUMN IF NOT EXISTS questionnaire_gap BOOLEAN DEFAULT FALSE;",

    # Policy docs: doc_type distinguishes 'policy' (org) vs 'framework' (reference), locked prevents deletion
    "ALTER TABLE cy_comp_policy_docs ADD COLUMN IF NOT EXISTS doc_type TEXT DEFAULT 'policy';",
    "ALTER TABLE cy_comp_policy_docs ADD COLUMN IF NOT EXISTS locked BOOLEAN DEFAULT FALSE;",
    "ALTER TABLE cy_comp_policy_docs ADD COLUMN IF NOT EXISTS tag TEXT;",
    "ALTER TABLE cy_comp_policy_docs ADD COLUMN IF NOT EXISTS file_size BIGINT;",
    "CREATE INDEX IF NOT EXISTS idx_cy_comp_pdocs_type ON cy_comp_policy_docs(doc_type, framework);",

    # Indexes for compliance queries
    "CREATE INDEX IF NOT EXISTS idx_cy_comp_findings_auto ON cy_comp_findings(auto_generated, framework);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_is_compliance ON alerts(is_compliance_relevant, timestamp DESC) WHERE is_compliance_relevant = TRUE;",
    "CREATE INDEX IF NOT EXISTS idx_incidents_compliance ON incidents(compliance_breach, last_seen DESC) WHERE compliance_breach = TRUE;",

    # ── Cross-framework answer propagation columns ─────────────────────────────
    # propagated_from: question_id that was the source for this auto-filled answer
    # propagation_accepted: NULL=manual entry, TRUE=user accepted propagation, FALSE=user rejected
    "ALTER TABLE cy_comp_questionnaire_responses ADD COLUMN IF NOT EXISTS propagated_from TEXT;",
    "ALTER TABLE cy_comp_questionnaire_responses ADD COLUMN IF NOT EXISTS propagation_accepted BOOLEAN DEFAULT NULL;",

    # ── Multi-framework document mapping ──────────────────────────────────────
    # mapped_frameworks: detected framework keys the document covers (replaces single 'framework' text)
    "ALTER TABLE cy_comp_policy_docs ADD COLUMN IF NOT EXISTS mapped_frameworks TEXT[] DEFAULT '{}';",
]


def ensure_tables() -> None:
    """
    Create all 16 cy_comp_* tables if they do not exist.
    Also runs idempotent column migrations and seeds cross-framework correlations.
    Called once at Flask app startup via create_app().
    """
    global _tables_ready
    if _tables_ready:
        return
    try:
        with db() as conn:
            cur = conn.cursor()
            for stmt in _DDL_STATEMENTS:
                # Each DDL block may contain multiple semicolon-separated statements
                for sub in [s.strip() for s in stmt.split(";") if s.strip()]:
                    try:
                        cur.execute(sub)
                    except Exception as ddl_exc:
                        log.warning("cy_comp DDL skipped (%s...): %s", sub[:60], ddl_exc)
            for mig in _MIGRATE_COLUMNS:
                try:
                    cur.execute(mig)
                except Exception as m_exc:
                    log.debug("cy_comp migration skipped (%s): %s", mig[:60], m_exc)

            # Seed cross-framework question correlations (idempotent)
            try:
                from cy_comp.data.question_correlations import seed_correlations
                result = seed_correlations(conn)
                if result["inserted"]:
                    log.info("cy_comp: seeded %d correlation pairs", result["inserted"])
            except Exception as seed_exc:
                log.warning("cy_comp: correlation seed failed (non-fatal): %s", seed_exc)

        _tables_ready = True
        log.info("cy_comp: all 16 tables ensured (CYCENTRA_DB_URL=%s)", CYCENTRA_DB_URL)
    except Exception as exc:
        log.error("cy_comp: table init failed — GRC module unavailable: %s", exc)
