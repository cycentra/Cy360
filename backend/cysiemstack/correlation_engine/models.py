from datetime import datetime
from sqlalchemy import (
    Column, BigInteger, Text, Integer, Numeric, Boolean,
    TIMESTAMP, ARRAY, UniqueConstraint, Index
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from config import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.database_url,
    pool_size=10,
    max_overflow=20,
    echo=False,
)

AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Alert(Base):
    __tablename__ = "alerts"

    id              = Column(BigInteger, primary_key=True, autoincrement=True)
    wazuh_id        = Column(Text, unique=True, nullable=True)
    timestamp       = Column(TIMESTAMP(timezone=True), nullable=False)
    received_at     = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    agent_id        = Column(Text, nullable=False)
    agent_name      = Column(Text)
    agent_ip        = Column(Text)
    rule_id         = Column(Integer, nullable=False)
    rule_desc       = Column(Text)
    rule_level      = Column(Integer)
    base_score      = Column(Numeric(4, 1))
    category        = Column(Text)
    mitre_id        = Column(Text)
    mitre_tactic    = Column(Text)
    src_ip          = Column(Text)
    dst_ip          = Column(Text)
    username        = Column(Text)
    process_name    = Column(Text)
    file_path       = Column(Text)
    raw_log         = Column(Text)
    full_alert      = Column(JSONB)
    incident_id     = Column(Text, nullable=True)
    misp_ioc_match  = Column(Boolean, default=False)
    misp_event_ids  = Column(ARRAY(Integer))
    enriched        = Column(Boolean, default=False)


class Incident(Base):
    __tablename__ = "incidents"

    id                  = Column(Text, primary_key=True)
    first_seen          = Column(TIMESTAMP(timezone=True), nullable=False)
    last_seen           = Column(TIMESTAMP(timezone=True), nullable=False)
    updated_at          = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    status              = Column(Text, default="open")
    severity            = Column(Text, default="low")
    alert_count         = Column(Integer, default=0)
    affected_agents      = Column(ARRAY(Text))
    affected_agent_names = Column(ARRAY(Text))
    affected_users       = Column(ARRAY(Text))
    src_ips             = Column(ARRAY(Text))
    categories          = Column(ARRAY(Text))
    mitre_ids           = Column(ARRAY(Text))
    mitre_tactics       = Column(ARRAY(Text))
    correlated_rules    = Column(JSONB, default=list)
    ueba_flags          = Column(JSONB, default=list)
    misp_enrichment     = Column(JSONB, default=dict)
    llm_summary         = Column(Text)
    llm_remediation     = Column(Text)
    llm_generated_at    = Column(TIMESTAMP(timezone=True))
    risk_score          = Column(Numeric(5, 1), default=0)
    assigned_to         = Column(Text)
    notes               = Column(Text)
    closed_at           = Column(TIMESTAMP(timezone=True))
    false_positive_reason = Column(Text)
    # ENH-1: campaign linkage
    campaign_id    = Column(Text, nullable=True)
    campaign_peers = Column(ARRAY(Text), default=list)
    # ENH-2: kill chain tracking
    kill_chain_stage      = Column(Integer, default=0)
    kill_chain_stage_name = Column(Text, nullable=True)
    # CyIRIS integration
    iris_case_id     = Column(Integer, nullable=True)   # DFIR IRIS case ID
    iris_case_status = Column(Text, nullable=True)       # "open" | "closed"
    iris_case_url    = Column(Text, nullable=True)       # deep link to case in IRIS UI
    # fp_probability: multi-factor false-positive probability 0–100.
    # High score = likely FP/noise.  Replaces the old single-factor confidence_score.
    fp_probability   = Column(Numeric(5, 1), nullable=True)
    # asset_tier: CMDB criticality — 1=crown jewel, 2=business critical, 3=dev/low
    asset_tier       = Column(Integer, nullable=True)
    # soar_actions: list of action objects returned by CySOAR/Node-RED
    soar_actions     = Column(JSONB, default=list)

    __table_args__ = (
        # Speed up the common WHERE/ORDER BY patterns used by GET /incidents
        Index("ix_incidents_status",          "status"),
        Index("ix_incidents_severity",        "severity"),
        Index("ix_incidents_last_seen",       "last_seen"),
        Index("ix_incidents_status_last_seen", "status", "last_seen"),
    )


# ── Audit Log ─────────────────────────────────────────────────────────────────
# Immutable record of every status transition and manual action performed on
# incidents, ASM findings, or asset records.  Written by the ingestor pipeline
# (actor="system") and by the /transition endpoint (actor=analyst email).

class AuditLog(Base):
    __tablename__ = "audit_log"

    id           = Column(BigInteger, primary_key=True, autoincrement=True)
    entity_type  = Column(Text, nullable=False)   # "incident" | "asm_finding" | "asset"
    entity_id    = Column(Text, nullable=False)   # incident id, finding_id, or asset hostname
    action       = Column(Text, nullable=False)   # "status_change" | "iris_created" | "soar_triggered" | "auto_fp" | "comment"
    from_status  = Column(Text, nullable=True)
    to_status    = Column(Text, nullable=True)
    comment      = Column(Text, nullable=True)    # mandatory for analyst-initiated transitions
    actor        = Column(Text, nullable=False)   # email or "system"
    created_at   = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    extra        = Column(JSONB, default=dict)    # fp_score, rule_ids, iris_case_id, etc.

    __table_args__ = (
        Index("ix_audit_entity", "entity_type", "entity_id"),
    )


class UEBABaseline(Base):
    __tablename__ = "ueba_baselines"

    id                  = Column(BigInteger, primary_key=True, autoincrement=True)
    username            = Column(Text, unique=True, nullable=False)
    updated_at          = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    typical_hours       = Column(ARRAY(Integer))
    typical_agents      = Column(ARRAY(Text))
    avg_daily_events    = Column(Numeric(8, 2), default=0)
    avg_fail_rate       = Column(Numeric(5, 4), default=0)
    stddev_fail_rate    = Column(Numeric(5, 4), default=0)
    peer_group          = Column(Text)
    daily_stats         = Column(JSONB, default=list)


class UEBAAnomaly(Base):
    __tablename__ = "ueba_anomalies"

    id                  = Column(BigInteger, primary_key=True, autoincrement=True)
    detected_at         = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    username            = Column(Text, nullable=False)
    anomaly_type        = Column(Text, nullable=False)
    description         = Column(Text)
    risk_contribution   = Column(Integer, default=0)
    alert_ids           = Column(ARRAY(Text))
    incident_id         = Column(Text)
    resolved            = Column(Boolean, default=False)


class RiskScore(Base):
    __tablename__ = "risk_scores"
    __table_args__ = (UniqueConstraint("entity_id", "entity_type"),)

    id                  = Column(BigInteger, primary_key=True, autoincrement=True)
    entity_id           = Column(Text, nullable=False)
    entity_name         = Column(Text)
    entity_type         = Column(Text)
    score               = Column(Numeric(5, 1), default=0)
    level               = Column(Text)
    score_breakdown     = Column(JSONB, default=dict)
    last_calculated     = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    trend               = Column(Text, default="stable")
    prev_score          = Column(Numeric(5, 1))


class MISPIOCCache(Base):
    __tablename__ = "misp_ioc_cache"
    __table_args__ = (UniqueConstraint("ioc_value", "ioc_type"),)

    id          = Column(BigInteger, primary_key=True, autoincrement=True)
    ioc_value   = Column(Text, nullable=False)
    ioc_type    = Column(Text, nullable=False)
    cached_at   = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    expires_at  = Column(TIMESTAMP(timezone=True))
    is_hit      = Column(Boolean, default=False)
    misp_events = Column(JSONB, default=list)
    threat_level = Column(Text)
    tags        = Column(ARRAY(Text))



class HostPostureCache(Base):
    """Per-host security posture snapshot — refreshed hourly by host_service.py.

    Aggregates SCA pass rate, vulnerability counts, SIEM risk score, FIM/malware
    event counts, and compliance gap rate into a single composite posture score
    (0–100) with a letter grade.  Asset tier drives weighting in the overall
    internal posture score.
    """
    __tablename__ = "host_posture_cache"

    agent_id          = Column(Text, primary_key=True)
    agent_name        = Column(Text)
    agent_ip          = Column(Text)
    os_platform       = Column(Text)
    os_version        = Column(Text)
    wazuh_status      = Column(Text)          # active | disconnected | never_connected
    last_keepalive    = Column(TIMESTAMP(timezone=True))
    posture_score     = Column(Numeric(5, 1))
    posture_grade     = Column(Text)          # A+/A/B/C/D/F
    sca_score         = Column(Numeric(5, 1))
    sca_passed        = Column(Integer, default=0)
    sca_failed        = Column(Integer, default=0)
    sca_total         = Column(Integer, default=0)
    vuln_score        = Column(Numeric(5, 1))
    vuln_critical     = Column(Integer, default=0)
    vuln_high         = Column(Integer, default=0)
    vuln_medium       = Column(Integer, default=0)
    vuln_low          = Column(Integer, default=0)
    siem_risk         = Column(Numeric(5, 1))
    fim_event_count   = Column(Integer, default=0)
    malware_count     = Column(Integer, default=0)
    incident_count    = Column(Integer, default=0)
    compliance_score  = Column(Numeric(5, 1))
    mitre_techniques  = Column(ARRAY(Text))
    top_findings      = Column(JSONB, default=list)
    score_breakdown   = Column(JSONB, default=dict)
    asset_tier        = Column(Integer, default=3)  # 1=crown jewel, 2=biz critical, 3=standard
    computed_at       = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)

    __table_args__ = (
        Index("ix_host_posture_score",     "posture_score"),
        Index("ix_host_posture_grade",     "posture_grade"),
        Index("ix_host_posture_tier",      "asset_tier"),
        Index("ix_host_posture_computed",  "computed_at"),
    )


class CorrelationFeedback(Base):
    """ENH-6: analyst verdict on a fired incident."""
    __tablename__ = "correlation_feedback"

    id            = Column(BigInteger, primary_key=True, autoincrement=True)
    submitted_at  = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    incident_id   = Column(Text, nullable=False)
    analyst_email = Column(Text)
    verdict       = Column(Text, nullable=False)   # true_positive | false_positive | benign
    rules_fired   = Column(ARRAY(Text))
    notes         = Column(Text)


class FpPattern(Base):
    """Learned false-positive patterns — fingerprints of alerts analysts repeatedly close as FP."""
    __tablename__ = "fp_patterns"

    id           = Column(BigInteger, primary_key=True, autoincrement=True)
    fingerprint  = Column(Text, nullable=False, unique=True)
    raw_sample   = Column(Text)
    agent_id     = Column(Text)          # NULL = matches any host
    rule_id      = Column(Integer)
    description  = Column(Text)
    close_count  = Column(Integer, default=0)
    threshold    = Column(Integer, default=5)
    auto_close   = Column(Boolean, default=False)
    last_seen    = Column(TIMESTAMP(timezone=True))
    created_at   = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    updated_at   = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    created_by   = Column(Text)

    __table_args__ = (
        Index("ix_fp_patterns_fingerprint", "fingerprint"),
        Index("ix_fp_patterns_auto_close",  "auto_close"),
    )

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Create tables if they don't exist (init.sql is primary, this is fallback)."""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as exc:
        import logging
        logging.getLogger("cysiemstack").critical(
            "DATABASE CONNECTION FAILED — check DATABASE_URL in /opt/cycentra/cysiemstack.env\n"
            "  Error: %s\n"
            "  Ensure PostgreSQL is running on 127.0.0.1:5433 and corruser has access.",
            exc,
        )
        raise
