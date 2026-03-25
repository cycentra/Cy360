-- =============================================================================
-- init.sql — CySIEM Correlation Engine Database Schema
-- =============================================================================

-- ---------------------------------------------------------------------------
-- ALERTS — raw normalised Wazuh alerts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id              BIGSERIAL PRIMARY KEY,
    wazuh_id        TEXT UNIQUE,
    timestamp       TIMESTAMPTZ NOT NULL,
    received_at     TIMESTAMPTZ DEFAULT NOW(),
    agent_id        TEXT NOT NULL,
    agent_name      TEXT,
    agent_ip        TEXT,
    rule_id         INTEGER NOT NULL,
    rule_desc       TEXT,
    rule_level      INTEGER,
    base_score      NUMERIC(4,1),
    category        TEXT,
    mitre_id        TEXT,
    mitre_tactic    TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    username        TEXT,
    process_name    TEXT,
    file_path       TEXT,
    raw_log         TEXT,
    full_alert      JSONB,
    incident_id     TEXT,
    misp_ioc_match  BOOLEAN DEFAULT FALSE,
    misp_event_ids  INTEGER[],
    enriched        BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp   ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_id    ON alerts (agent_id);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id     ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_incident_id ON alerts (incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_username    ON alerts (username) WHERE username IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip      ON alerts (src_ip)   WHERE src_ip IS NOT NULL;

-- ---------------------------------------------------------------------------
-- INCIDENTS — correlated alert groups
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id                  TEXT PRIMARY KEY,
    first_seen          TIMESTAMPTZ NOT NULL,
    last_seen           TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    status              TEXT DEFAULT 'open',
    severity            TEXT DEFAULT 'low',
    alert_count         INTEGER DEFAULT 0,
    affected_agents     TEXT[],
    affected_users      TEXT[],
    src_ips             TEXT[],
    categories          TEXT[],
    mitre_ids           TEXT[],
    mitre_tactics       TEXT[],
    correlated_rules    JSONB DEFAULT '[]',
    ueba_flags          JSONB DEFAULT '[]',
    misp_enrichment     JSONB DEFAULT '{}',
    llm_summary         TEXT,
    llm_remediation     TEXT,
    llm_generated_at    TIMESTAMPTZ,
    risk_score          NUMERIC(5,1) DEFAULT 0,
    assigned_to         TEXT,
    notes               TEXT,
    closed_at           TIMESTAMPTZ,
    false_positive_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_status    ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity  ON incidents (severity);
CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents (last_seen DESC);

-- ---------------------------------------------------------------------------
-- UEBA BASELINES — rolling per-user behavioural profile
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ueba_baselines (
    id                  BIGSERIAL PRIMARY KEY,
    username            TEXT UNIQUE NOT NULL,
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    typical_hours       INTEGER[],
    typical_agents      TEXT[],
    avg_daily_events    NUMERIC(8,2) DEFAULT 0,
    avg_fail_rate       NUMERIC(5,4) DEFAULT 0,
    stddev_fail_rate    NUMERIC(5,4) DEFAULT 0,
    peer_group          TEXT,
    daily_stats         JSONB DEFAULT '[]'
);

-- ---------------------------------------------------------------------------
-- UEBA ANOMALIES — detected deviations
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ueba_anomalies (
    id                  BIGSERIAL PRIMARY KEY,
    detected_at         TIMESTAMPTZ DEFAULT NOW(),
    username            TEXT NOT NULL,
    anomaly_type        TEXT NOT NULL,
    description         TEXT,
    risk_contribution   INTEGER DEFAULT 0,
    alert_ids           TEXT[],
    incident_id         TEXT,
    resolved            BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_username ON ueba_anomalies (username);
CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_resolved ON ueba_anomalies (resolved) WHERE NOT resolved;

-- ---------------------------------------------------------------------------
-- RISK SCORES — composite 0–100 per entity
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_scores (
    id                  BIGSERIAL PRIMARY KEY,
    entity_id           TEXT NOT NULL,
    entity_name         TEXT,
    entity_type         TEXT,
    score               NUMERIC(5,1) DEFAULT 0,
    level               TEXT,
    score_breakdown     JSONB DEFAULT '{}',
    last_calculated     TIMESTAMPTZ DEFAULT NOW(),
    trend               TEXT DEFAULT 'stable',
    prev_score          NUMERIC(5,1),
    CONSTRAINT uq_risk_entity UNIQUE (entity_id, entity_type)
);

CREATE INDEX IF NOT EXISTS idx_risk_scores_score ON risk_scores (score DESC);
CREATE INDEX IF NOT EXISTS idx_risk_scores_type  ON risk_scores (entity_type);

-- ---------------------------------------------------------------------------
-- MISP IOC CACHE — avoids repeated MISP lookups
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS misp_ioc_cache (
    id          BIGSERIAL PRIMARY KEY,
    ioc_value   TEXT NOT NULL,
    ioc_type    TEXT NOT NULL,
    cached_at   TIMESTAMPTZ DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    is_hit      BOOLEAN DEFAULT FALSE,
    misp_events JSONB DEFAULT '[]',
    threat_level TEXT,
    tags        TEXT[],
    CONSTRAINT uq_misp_ioc UNIQUE (ioc_value, ioc_type)
);

-- ---------------------------------------------------------------------------
-- ENGINE STATS — operational metrics
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS engine_stats (
    id                  BIGSERIAL PRIMARY KEY,
    recorded_at         TIMESTAMPTZ DEFAULT NOW(),
    alerts_processed    BIGINT DEFAULT 0,
    incidents_created   INTEGER DEFAULT 0,
    incidents_updated   INTEGER DEFAULT 0,
    rules_fired         INTEGER DEFAULT 0,
    ueba_anomalies      INTEGER DEFAULT 0,
    misp_ioc_hits       INTEGER DEFAULT 0,
    llm_enrichments     INTEGER DEFAULT 0,
    processing_lag_ms   INTEGER DEFAULT 0
);

-- ---------------------------------------------------------------------------
-- VIEWS
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_open_incidents AS
SELECT
    i.*,
    rs.score  AS current_risk_score,
    rs.level  AS risk_level,
    rs.trend  AS risk_trend
FROM incidents i
LEFT JOIN risk_scores rs ON rs.entity_id = ANY(i.affected_agents) AND rs.entity_type = 'host'
WHERE i.status IN ('open', 'investigating')
ORDER BY
    CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
    i.last_seen DESC;

CREATE OR REPLACE VIEW v_top_risk_entities AS
SELECT * FROM risk_scores ORDER BY score DESC LIMIT 50;
