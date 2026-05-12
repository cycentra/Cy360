-- =============================================================================
-- 004_host_columns.sql — Add host name and OS columns to incidents table
-- =============================================================================
-- Adds affected_agent_names and affected_agent_os arrays so the portal can
-- display Host Name and Host OS columns in the Active Incidents table without
-- requiring a separate agent lookup.
--
-- Idempotent — safe to re-run on any existing or fresh installation.
--
-- Applied automatically by cycentra-setup.sh during upgrade.
-- Can also be run manually:
--   PGPASSWORD=<pass> psql -h 127.0.0.1 -p 5433 -U corruser -d correlation \
--       -f 004_host_columns.sql
-- =============================================================================

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS affected_agent_names TEXT[];
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS affected_agent_os    TEXT[];
