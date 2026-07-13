"""
cysiemstack/dedup.py
=======================
Cross-source duplicate suppression (Phase 4 of the CyDataLake initiative —
see docs/CYDATALAKE_MIGRATION_PLAN.md §8/§12). This problem didn't exist
before Phase 3: with a single source there was only ever one copy of a
given alert. Now the same underlying incident can legitimately arrive
twice — e.g. an endpoint alert from both SentinelOne and CyEDR, or (see the
Wazuh dual-path caveat in the migration doc §7) the same Wazuh alert via
both the existing file-tail and the new indexer-pull `WazuhConnector`.

This is a short-TTL Redis SETNX guard, not a semantic entity-resolution
engine — it collapses near-simultaneous duplicates of the *same* event
(same vendor, same entity, same description, same rounded-to-the-minute
timestamp), not conceptually-related-but-distinct alerts from different
detection logic. Deliberately conservative: a false "not a duplicate" just
means two alerts instead of one (the pre-Phase-3 status quo everywhere
except the Wazuh dual-path case); a false "is a duplicate" would silently
drop a real alert, which is the worse failure mode, hence the narrow key.
"""
from __future__ import annotations
import hashlib
import logging
import os
from typing import Any

_log = logging.getLogger(__name__)

_REDIS_URL  = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
_DEDUP_TTL  = int(os.environ.get("CYDATALAKE_DEDUP_TTL_SEC", "120"))
_KEY_PREFIX = "cysiemstack:dedup:"

_redis_client = None


def _get_redis():
    global _redis_client
    if _redis_client is None:
        try:
            import redis
            _redis_client = redis.from_url(_REDIS_URL, decode_responses=True)
        except Exception as exc:
            _log.error("Dedup: Redis connect failed: %s", exc)
    return _redis_client


def dedup_key(vendor: str, entity: str, description: str, timestamp_minute: str) -> str:
    raw = f"{vendor}|{entity}|{description}|{timestamp_minute}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def is_duplicate(key: str) -> bool:
    """Returns True if `key` was already seen within the TTL window (and
    therefore should be suppressed), False otherwise — including on any
    Redis failure, since failing open (allow the alert through) is safer
    than failing closed (silently drop a real alert)."""
    r = _get_redis()
    if r is None:
        return False
    try:
        # SET ... NX returns None if the key already existed — i.e. a duplicate.
        was_new = r.set(f"{_KEY_PREFIX}{key}", "1", nx=True, ex=_DEDUP_TTL)
        return not was_new
    except Exception as exc:
        _log.warning("Dedup: Redis check failed, failing open: %s", exc)
        return False


def envelope_dedup_key(vendor: str, envelope: dict[str, Any]) -> str:
    """Convenience wrapper for the synthetic-envelope shape produced by
    connector_bridge.py's _envelope()/_normalize_*() functions."""
    entity = (envelope.get("agent") or {}).get("name", "")
    description = (envelope.get("rule") or {}).get("description", "")
    ts = str(envelope.get("@timestamp", ""))[:16]  # minute resolution
    return dedup_key(vendor, entity, description, ts)
