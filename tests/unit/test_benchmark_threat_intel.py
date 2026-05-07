"""
Regression test — Threat Intel widget shows 0 despite MISP feeds enabled

Bug: _collect_threat_intel_score() in backend/blueprints/benchmark/routes.py
     calls f.get("enabled") on each item from /feeds/index, but MISP wraps
     each feed object under a "Feed" key:
       [{"Feed": {"id": "1", "enabled": 1, ...}}, ...]
     So f.get("enabled") returns None (top-level has only "Feed"), making
     enabled_n = 0 → feed_score = 0 → composite = 0 regardless of actual feeds.

Fix: unwrap "Feed" key before accessing "enabled":
     feed_obj = f.get("Feed", f)
     enabled_n = sum(1 for f in feeds if f.get("Feed", f).get("enabled"))

These tests FAIL on code before the fix and PASS after.
"""

import json
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Bootstrap: make the benchmark routes module importable without a full Flask
# app.  We stub heavy deps before importing.
# ---------------------------------------------------------------------------

# Ensure backend/ is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

# Stub out Flask, core.config, and other imports the module pulls in at the
# module level so we can import routes.py in a plain pytest environment.
_flask_mod = types.ModuleType("flask")
_flask_mod.Blueprint = MagicMock(return_value=MagicMock())
_flask_mod.jsonify = MagicMock(side_effect=lambda d: d)
_flask_mod.request = MagicMock()
_flask_mod.session = {}
sys.modules.setdefault("flask", _flask_mod)

_core = types.ModuleType("core")
_core_cfg = types.ModuleType("core.config")
_core_cfg.SCANS_DIR = "/tmp/scans"
sys.modules.setdefault("core", _core)
sys.modules.setdefault("core.config", _core_cfg)

# Stub functools.wraps usage in routes — already stdlib, no stub needed.

import importlib
import blueprints.benchmark.routes as _routes  # noqa: E402  (after sys.path setup)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(status_code: int, body) -> MagicMock:
    """Build a mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    return resp


# ---------------------------------------------------------------------------
# Test: MISP /feeds/index with "Feed" envelope — the bug scenario
# ---------------------------------------------------------------------------

class TestThreatIntelMispFeedWrapping(unittest.TestCase):
    """
    Verifies that _collect_threat_intel_score() correctly counts enabled feeds
    when the MISP API wraps each feed object under a "Feed" key.

    FAILS before the fix (enabled_n = 0 → score = 0).
    PASSES after the fix (enabled_n = 3 → feed_score = 40 → score > 0).
    """

    # A realistic MISP /feeds/index response — 3 enabled feeds, 1 disabled
    FEEDS_WRAPPED = [
        {"Feed": {"id": "1", "name": "CIRCL OSINT Feed", "enabled": 1}},
        {"Feed": {"id": "2", "name": "Botvrij.eu Data", "enabled": 1}},
        {"Feed": {"id": "3", "name": "Emerging Threats", "enabled": 1}},
        {"Feed": {"id": "4", "name": "Old Feed",          "enabled": 0}},
    ]

    # /attributes/statistics/type → {type: count}
    ATTR_STATS = {"ip-dst": "5000", "domain": "3000", "url": "2000"}

    # /attributes/restSearch → {"response": {"count": N}}
    ATTR_ACTIVE = {"response": {"count": 7000}}
    ATTR_TOTAL  = {"response": {"count": 10000}}

    def _mock_misp_config(self, routes_mod):
        """Patch _read_misp_config to return a valid config dict."""
        return patch.object(
            routes_mod, "_read_misp_config",
            return_value={"url": "https://misp.example.com",
                          "apiKey": "test-key",
                          "mode": "local"},
        )

    def test_feeds_enabled_count_with_wrapped_response(self):
        """
        When MISP returns the standard wrapped format,
        feeds_enabled must be >= 3 (not 0).
        This FAILS before the fix.
        """
        with self._mock_misp_config(_routes):
            with patch.object(_routes._req, "get") as mock_get, \
                 patch.object(_routes._req, "post") as mock_post:

                mock_get.return_value = _make_response(200, self.FEEDS_WRAPPED)
                mock_post.side_effect = [
                    _make_response(200, self.ATTR_STATS),   # /attributes/statistics/type
                    _make_response(200, self.ATTR_ACTIVE),  # restSearch to_ids=1
                    _make_response(200, self.ATTR_TOTAL),   # restSearch total
                ]

                result = _routes._collect_threat_intel_score()

        self.assertGreaterEqual(
            result.get("feeds_enabled", 0), 3,
            "feeds_enabled should be 3 but was "
            f"{result.get('feeds_enabled', 0)} — MISP Feed envelope not unwrapped"
        )

    def test_score_nonzero_with_wrapped_response(self):
        """
        Composite score must be > 0 when feeds are enabled.
        This FAILS before the fix (score == 0).
        """
        with self._mock_misp_config(_routes):
            with patch.object(_routes._req, "get") as mock_get, \
                 patch.object(_routes._req, "post") as mock_post:

                mock_get.return_value = _make_response(200, self.FEEDS_WRAPPED)
                mock_post.side_effect = [
                    _make_response(200, self.ATTR_STATS),
                    _make_response(200, self.ATTR_ACTIVE),
                    _make_response(200, self.ATTR_TOTAL),
                ]

                result = _routes._collect_threat_intel_score()

        self.assertGreater(
            result.get("score", 0), 0,
            f"score should be > 0 but was {result.get('score', 0)} — "
            "MISP Feed envelope not unwrapped"
        )

    def test_feed_score_full_40_with_three_enabled(self):
        """
        With 3+ enabled feeds, feed_score sub-signal should be 40.
        """
        with self._mock_misp_config(_routes):
            with patch.object(_routes._req, "get") as mock_get, \
                 patch.object(_routes._req, "post") as mock_post:

                mock_get.return_value = _make_response(200, self.FEEDS_WRAPPED)
                # Suppress attr/restSearch sub-scores to isolate feed_score
                mock_post.side_effect = [
                    _make_response(200, {}),          # stats → 0 attrs
                    _make_response(200, {"response": {"count": 0}}),
                    _make_response(200, {"response": {"count": 0}}),
                ]

                result = _routes._collect_threat_intel_score()

        # With only feed_score contributing, composite == feed_score
        self.assertEqual(
            result.get("score", 0), 40,
            f"Expected composite=40 from 3 enabled feeds, got {result.get('score',0)}"
        )

    def test_unwrapped_format_still_works(self):
        """
        If MISP ever returns unwrapped dicts (no "Feed" key), the fix must
        still work correctly (backward-compatible).
        """
        feeds_unwrapped = [
            {"id": "1", "name": "Feed A", "enabled": 1},
            {"id": "2", "name": "Feed B", "enabled": 1},
            {"id": "3", "name": "Feed C", "enabled": 1},
        ]
        with self._mock_misp_config(_routes):
            with patch.object(_routes._req, "get") as mock_get, \
                 patch.object(_routes._req, "post") as mock_post:

                mock_get.return_value = _make_response(200, feeds_unwrapped)
                mock_post.side_effect = [
                    _make_response(200, {}),
                    _make_response(200, {"response": {"count": 0}}),
                    _make_response(200, {"response": {"count": 0}}),
                ]

                result = _routes._collect_threat_intel_score()

        self.assertGreaterEqual(result.get("feeds_enabled", 0), 3)
        self.assertGreater(result.get("score", 0), 0)

    def test_disabled_misp_returns_score_none(self):
        """
        When MISP is disabled/unconfigured, score must be None (not 0).
        This is existing correct behavior — regression guard.
        """
        with patch.object(_routes, "_read_misp_config", return_value=None):
            result = _routes._collect_threat_intel_score()

        self.assertIsNone(result.get("score"),
                          "score should be None when MISP is disabled")


if __name__ == "__main__":
    unittest.main()
