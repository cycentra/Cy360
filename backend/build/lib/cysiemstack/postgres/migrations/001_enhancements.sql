-- CyCentra Correlation Engine — Enhancement Migrations
-- Run: docker exec -i cysiemstack-postgres psql -U corruser -d correlation < 001_enhancements.sql
-- All statements are idempotent (IF NOT EXISTS / IF NOT EXISTS column checks).

-- ── ENH-2: Kill chain tracking ───────────────────────────────────────────────
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS kill_chain_stage INTEGER DEFAULT 0;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS kill_chain_stage_name TEXT;

-- ── ENH-1: Campaign correlation ──────────────────────────────────────────────
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS campaign_id TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS campaign_peers TEXT[];
CREATE INDEX IF NOT EXISTS idx_incidents_campaign_id
    ON incidents (campaign_id) WHERE campaign_id IS NOT NULL;

-- ── ENH-6: Analyst feedback loop ─────────────────────────────────────────────
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
