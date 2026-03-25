from datetime import datetime
from sqlalchemy import (
    Column, BigInteger, Text, Integer, Numeric, Boolean,
    TIMESTAMP, ARRAY, UniqueConstraint
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
    affected_agents     = Column(ARRAY(Text))
    affected_users      = Column(ARRAY(Text))
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

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Create tables if they don't exist (init.sql is primary, this is fallback)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
