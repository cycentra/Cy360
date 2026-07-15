"""
rule_cache.py
In-memory cache of rule-toggle state + custom correlation/UEBA rules, read by
correlator.py/ueba.py on every alert. Backed by the rule_toggles /
custom_correlation_rules / custom_ueba_rules tables (models.py).

The CRUD routes in main.py (POST/PUT/DELETE /rules/...) run in this same
process, so a write handler can just call invalidate() right after its commit
and the very next alert processed sees the change — no cross-process signal
needed. The TTL below is a safety net only (covers e.g. a second engine
worker process, or a write that reached the DB some other way), not the
primary "apply on save" mechanism.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field

import structlog
from sqlalchemy import select

from models import AsyncSessionLocal, RuleToggle, CustomCorrelationRule, CustomUebaRule

log = structlog.get_logger()

_TTL_SECONDS = 30.0


@dataclass
class _Cache:
    loaded_at: float = 0.0
    disabled_correlation: set[str] = field(default_factory=set)
    disabled_ueba: set[str] = field(default_factory=set)
    custom_correlation: list[dict] = field(default_factory=list)
    custom_ueba: list[dict] = field(default_factory=list)


_cache = _Cache()


def invalidate() -> None:
    """Force the next get_*() call to reload from the DB immediately."""
    _cache.loaded_at = 0.0


async def _reload_if_stale() -> None:
    if (time.monotonic() - _cache.loaded_at) < _TTL_SECONDS and _cache.loaded_at:
        return
    async with AsyncSessionLocal() as db:
        toggles = (await db.execute(select(RuleToggle).where(RuleToggle.enabled == False))).scalars().all()  # noqa: E712
        _cache.disabled_correlation = {t.rule_key for t in toggles if t.rule_kind == "correlation"}
        _cache.disabled_ueba = {t.rule_key for t in toggles if t.rule_kind == "ueba"}

        corr_rows = (await db.execute(
            select(CustomCorrelationRule).where(CustomCorrelationRule.enabled == True)  # noqa: E712
        )).scalars().all()
        _cache.custom_correlation = [
            {
                "rule_key": r.rule_key, "name": r.name, "description": r.description,
                "conditions": r.conditions or [], "window_minutes": r.window_minutes,
                "min_count": r.min_count, "severity_override": r.severity_override,
                "tags": r.tags or [],
            }
            for r in corr_rows
        ]

        ueba_rows = (await db.execute(
            select(CustomUebaRule).where(CustomUebaRule.enabled == True)  # noqa: E712
        )).scalars().all()
        _cache.custom_ueba = [
            {
                "rule_key": r.rule_key, "name": r.name, "description": r.description,
                "conditions": r.conditions or [], "window_minutes": r.window_minutes,
                "min_count": r.min_count, "entity_type": r.entity_type,
                "anomaly_type": r.anomaly_type, "risk_contribution": r.risk_contribution,
            }
            for r in ueba_rows
        ]
    _cache.loaded_at = time.monotonic()
    log.debug("rule_cache_reloaded",
              disabled_correlation=len(_cache.disabled_correlation),
              disabled_ueba=len(_cache.disabled_ueba),
              custom_correlation=len(_cache.custom_correlation),
              custom_ueba=len(_cache.custom_ueba))


async def get_disabled_correlation_keys() -> set[str]:
    await _reload_if_stale()
    return _cache.disabled_correlation


async def get_disabled_ueba_keys() -> set[str]:
    await _reload_if_stale()
    return _cache.disabled_ueba


async def get_custom_correlation_rules() -> list[dict]:
    await _reload_if_stale()
    return _cache.custom_correlation


async def get_custom_ueba_rules() -> list[dict]:
    await _reload_if_stale()
    return _cache.custom_ueba
