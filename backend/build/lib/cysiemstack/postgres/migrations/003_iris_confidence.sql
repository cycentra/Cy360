-- =============================================================================
-- 003_iris_confidence.sql — CyIRIS integration + FP confidence columns
-- =============================================================================
-- Adds columns required since v1.0.104 (manual ticket escalation) and v1.0.103
-- (auto FP scoring).  These were NOT included in init.sql or prior migrations,
-- causing "column does not exist" errors after an upgrade to v1.0.103+.
--
-- Idempotent — safe to re-run on any existing or fresh installation.
--
-- Applied automatically by cycentra-setup.sh during upgrade.
-- Can also be run manually:
--   PGPASSWORD=<pass> psql -h 127.0.0.1 -p 5433 -U corruser -d correlation \
--       -f 003_iris_confidence.sql
-- =============================================================================

-- ── CyIRIS case linkage ───────────────────────────────────────────────────────
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS iris_case_id     INTEGER;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS iris_case_status TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS iris_case_url    TEXT;

-- ── False-positive confidence score (0–100) ───────────────────────────────────
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS confidence_score NUMERIC(5,1);

-- ── Campaign linkage (ENH-1, in case 001 wasn't applied) ─────────────────────
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS campaign_id     TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS campaign_peers  TEXT[];

-- ── Kill-chain tracking (ENH-2, in case 001 wasn't applied) ──────────────────
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS kill_chain_stage      INTEGER DEFAULT 0;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS kill_chain_stage_name TEXT;

-- ── Performance indexes (idempotent) ─────────────────────────────────────────
CREATE INDEX IF NOT EXISTS ix_incidents_status           ON incidents (status);
CREATE INDEX IF NOT EXISTS ix_incidents_severity         ON incidents (severity);
CREATE INDEX IF NOT EXISTS ix_incidents_last_seen        ON incidents (last_seen DESC);
CREATE INDEX IF NOT EXISTS ix_incidents_status_last_seen ON incidents (status, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_campaign_id
    ON incidents (campaign_id) WHERE campaign_id IS NOT NULL;

-- ── Analyst feedback table (ENH-6, in case 001 wasn't applied) ───────────────
CREATE TABLE IF NOT EXISTS correlation_feedback (
    id              BIGSERIAL PRIMARY KEY,
    submitted_at    TIMESTAMPTZ DEFAULT NOW(),
    incident_id     TEXT NOT NULL,
    analyst_email   TEXT,
    verdict         TEXT NOT NULL CHECK (verdict IN ('true_positive', 'false_positive', 'benign')),
    rules_fired     TEXT[],
    notes           TEXT
);
CREATE INDEX IF NOT EXISTS idx_feedback_rules   ON correlation_feedback USING GIN (rules_fired);
CREATE INDEX IF NOT EXISTS idx_feedback_verdict ON correlation_feedback (verdict);
