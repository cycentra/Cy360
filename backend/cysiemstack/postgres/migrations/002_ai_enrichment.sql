-- =============================================================================
-- 002_ai_enrichment.sql — Add AI enrichment + MISP columns to incidents table
-- =============================================================================
-- Idempotent — safe to re-run on any existing installation.
-- Applies to servers upgraded from a version before these columns were in init.sql.
--
-- Run manually:
--   PGPASSWORD=<pass> psql -h 127.0.0.1 -p 5433 -U corruser -d correlation \
--       -f 002_ai_enrichment.sql

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS llm_summary         TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS llm_remediation     TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS llm_generated_at    TIMESTAMPTZ;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS misp_enrichment     JSONB DEFAULT '{}';
