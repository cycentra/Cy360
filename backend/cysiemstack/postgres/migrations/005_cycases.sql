-- =============================================================================
-- 005_cycases.sql — Remove CyIRIS columns; introduce CyCases native tables
-- =============================================================================
-- Idempotent — safe to re-run on any existing or fresh installation.
--
-- Run manually:
--   PGPASSWORD=<pass> psql -h 127.0.0.1 -p 5433 -U corruser -d correlation \
--       -f 005_cycases.sql
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Drop CyIRIS columns from incidents
-- ---------------------------------------------------------------------------
ALTER TABLE incidents DROP COLUMN IF EXISTS iris_case_id;
ALTER TABLE incidents DROP COLUMN IF EXISTS iris_case_status;
ALTER TABLE incidents DROP COLUMN IF EXISTS iris_case_url;

-- ---------------------------------------------------------------------------
-- 2. Add CyCases columns to incidents
-- ---------------------------------------------------------------------------
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS case_opened_at    TIMESTAMPTZ;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS case_ack_at       TIMESTAMPTZ;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS case_type         TEXT NOT NULL DEFAULT 'generic';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS case_restricted   BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS case_mttd_seconds BIGINT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS case_mtta_seconds BIGINT;

-- ---------------------------------------------------------------------------
-- 3. Case comments — append-only threaded thread. body is never updated.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS case_comments (
    id            BIGSERIAL    PRIMARY KEY,
    incident_id   TEXT         NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author_email  TEXT         NOT NULL,
    body          TEXT         NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    parent_id     BIGINT       REFERENCES case_comments(id),
    is_system     BOOLEAN      NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS ix_case_comments_incident ON case_comments(incident_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- 4. Evidence vault — WORM. Files are never deleted from disk.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS case_evidence (
    id              BIGSERIAL   PRIMARY KEY,
    incident_id     TEXT        NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    uploaded_by     TEXT        NOT NULL,
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    filename        TEXT        NOT NULL,
    mime_type       TEXT,
    file_size_bytes BIGINT,
    sha256          TEXT        NOT NULL,
    storage_path    TEXT        NOT NULL,
    description     TEXT,
    is_deleted      BOOLEAN     NOT NULL DEFAULT FALSE,
    deleted_by      TEXT,
    deleted_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_case_evidence_incident ON case_evidence(incident_id);

-- ---------------------------------------------------------------------------
-- 5. Case IOC registry — references misp_ioc_cache for enrichment
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS case_iocs (
    id            BIGSERIAL   PRIMARY KEY,
    incident_id   TEXT        NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    ioc_value     TEXT        NOT NULL,
    ioc_type      TEXT        NOT NULL CHECK (ioc_type IN ('ip','domain','hash_md5','hash_sha256','url','email')),
    added_by      TEXT        NOT NULL,
    added_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    context_note  TEXT,
    is_removed    BOOLEAN     NOT NULL DEFAULT FALSE,
    removed_by    TEXT,
    removed_at    TIMESTAMPTZ,
    UNIQUE (incident_id, ioc_value, ioc_type)
);
CREATE INDEX IF NOT EXISTS ix_case_iocs_incident ON case_iocs(incident_id);
CREATE INDEX IF NOT EXISTS ix_case_iocs_value    ON case_iocs(ioc_value);

-- ---------------------------------------------------------------------------
-- 6. Checklist step state per case
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS case_checklist_state (
    id            BIGSERIAL   PRIMARY KEY,
    incident_id   TEXT        NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    template_key  TEXT        NOT NULL,
    step_index    INTEGER     NOT NULL,
    checked       BOOLEAN     NOT NULL DEFAULT FALSE,
    checked_by    TEXT,
    checked_at    TIMESTAMPTZ,
    note          TEXT,
    UNIQUE (incident_id, template_key, step_index)
);

-- ---------------------------------------------------------------------------
-- 7. Per-case access restriction for sensitive investigations
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS case_access_restrictions (
    id             BIGSERIAL   PRIMARY KEY,
    incident_id    TEXT        NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    set_by         TEXT        NOT NULL,
    set_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    allowed_emails TEXT[]      NOT NULL,
    reason         TEXT,
    UNIQUE (incident_id)
);
