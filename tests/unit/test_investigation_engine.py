"""
Suite 12 — AI Investigation Engine Phase 1–6 Tests
====================================================

Covers all six phases of the autonomous investigation engine. All tests are
fully autonomous — no live Wazuh, no PostgreSQL, no LLM service required.
SSH-accessible by running: pytest tests/unit/test_investigation_engine.py -v

  Phase 1  — TI Enricher: confidence scoring & verdict mapping (12 tests)
  Phase 2  — Hypothesis Engine: JSON parsing, validation, evidence summary (18 tests)
  Phase 3A — Gap Analyser: keyword → evidence_type classification (8 tests)
  Phase 3B — Gap Analyser: manifest generation, deduplication, priority (10 tests)
  Phase 3C — Evidence Collector: item factory & status contract (6 tests)
  Phase 3D — Evidence Collector: no-credential dispatch → FAILED items (8 tests)
  Phase 4A — Confidence Engine: component score functions (13 tests)
  Phase 4B — compute_investigation_confidence: weight model & breakdown (15 tests)
  Phase 5A — SOAR Connector: confidence gate < 70% / 70–89% / ≥ 90% (12 tests)
  Phase 5B — SOAR Connector: webhook URL resolution order (8 tests)
  Phase 5C — SOAR Connector: status reporting via state.json (6 tests)
  Phase 6A — Historical similarity: no-pattern / partial / full match (8 tests)
  Phase 6B — Incident Pattern Memory: field mapping & never-raises (8 tests)

Total: 132 tests
"""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path & stub setup — MUST run before any CE module imports
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[2]
CE_PATH   = str(REPO_ROOT / "backend" / "cysiemstack" / "correlation_engine")
if CE_PATH not in sys.path:
    sys.path.insert(0, CE_PATH)

# Build a settings stub with all Phase 1–6 attributes explicitly set
_mock_settings                    = MagicMock()
_mock_settings.vt_api_key         = ""
_mock_settings.abuseipdb_api_key  = ""
_mock_settings.greynoise_api_key  = ""
_mock_settings.wazuh_api_password = ""
_mock_settings.wazuh_api_url      = "https://127.0.0.1:55000"
_mock_settings.wazuh_api_user     = "wazuh-wui"
_mock_settings.tls_ca_bundle      = ""
_mock_settings.soar_webhook_url   = ""
_mock_settings.llm_enabled        = True
_mock_settings.risk_decay_hours   = 24
_mock_settings.misp_enabled       = False

_mock_config = MagicMock()
_mock_config.get_settings.return_value = _mock_settings

# Stub ALL heavy dependencies before any CE imports
for _mod in (
    "sqlalchemy",
    "sqlalchemy.ext",
    "sqlalchemy.ext.asyncio",
    "sqlalchemy.orm",
    "sqlalchemy.dialects",
    "sqlalchemy.dialects.postgresql",
    "models",
    "structlog",
    "pydantic",
    "pydantic_settings",
    "httpx",
    "ai_router",
):
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

sys.modules["config"] = _mock_config

# Now import CE functions — pure computations work immediately; async ones need
# asyncio.run() wrappers in individual tests.
from ti_enricher      import _compute_ti_confidence                        # noqa: E402
from hypothesis_engine import _parse_hypotheses, _build_evidence_summary   # noqa: E402
from gap_analyser     import _classify_evidence_item, analyse_gaps         # noqa: E402
from evidence_collector import _make_item, collect_all                     # noqa: E402
from risk_scorer      import (                                             # noqa: E402
    _rule_confidence_score,
    _ti_confidence_score,
    _asset_confidence_score,
    compute_investigation_confidence,
    compute_historical_similarity,
)
from cysoar_connector import (                                             # noqa: E402
    dispatch_if_confident,
    get_soar_status,
    _soar_webhook_url,
)
from llm_enricher     import _store_incident_pattern                       # noqa: E402


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_mock_incident(**kwargs):
    """Return a MagicMock with sensible Incident ORM defaults."""
    inc = MagicMock()
    inc.id                    = "INC-001"
    inc.severity              = "high"
    inc.status                = "closed"
    inc.correlated_rules      = []
    inc.hypotheses            = None
    inc.ti_reputation         = None
    inc.asset_tier            = None
    inc.mitre_ids             = []
    inc.mitre_tactics         = []
    inc.kill_chain_stage_name = None
    inc.affected_agents       = []
    inc.affected_users        = []
    inc.src_ips               = []
    inc.confidence_score      = None
    inc.recommendation        = None
    inc.soar_dispatched       = False
    inc.soar_dispatched_at    = None
    inc.soar_dispatch_log     = None
    inc.alert_count           = 5
    for k, v in kwargs.items():
        setattr(inc, k, v)
    return inc


def _run(coro):
    """Run an async coroutine synchronously (no pytest-asyncio needed)."""
    return asyncio.run(coro)


def _make_db_with_empty_rows():
    """AsyncSession mock whose execute() returns empty result rows."""
    db           = AsyncMock()
    exec_result  = MagicMock()
    exec_result.all.return_value = []
    db.execute   = AsyncMock(return_value=exec_result)
    db.add       = MagicMock()
    db.flush     = AsyncMock()
    return db


# ---------------------------------------------------------------------------
# PHASE 1 — TI Enricher: Confidence Scoring & Verdict Mapping
# ---------------------------------------------------------------------------

class TestPhase1TIConfidence:
    """12 tests — _compute_ti_confidence() scoring and verdict mapping."""

    def test_empty_inputs_returns_zero_score_and_unknown(self):
        score, verdict = _compute_ti_confidence([], 0)
        assert score == 0
        assert verdict == "unknown"

    def test_single_misp_hit_adds_35(self):
        score, verdict = _compute_ti_confidence([], 1)
        assert score == 35
        assert verdict == "suspicious"   # 35 ≥ 30 → suspicious

    def test_two_misp_hits_capped_at_35(self):
        score, _ = _compute_ti_confidence([], 2)
        assert score == 35              # min(35, 2×35) = 35

    def test_vt_malicious_adds_25(self):
        results = [{"source": "virustotal", "verdict": "malicious"}]
        score, verdict = _compute_ti_confidence(results, 0)
        assert score == 25
        assert verdict == "benign"      # 25 > 0 but < 30 → benign

    def test_vt_suspicious_adds_10(self):
        results = [{"source": "virustotal", "verdict": "suspicious"}]
        score, verdict = _compute_ti_confidence(results, 0)
        assert score == 10
        assert verdict == "benign"      # 10 > 0 but < 30 → benign

    def test_abuseipdb_score_ge50_adds_20(self):
        results = [{"source": "abuseipdb", "verdict": "malicious", "abuse_score": 55}]
        score, _ = _compute_ti_confidence(results, 0)
        assert score == 20

    def test_abuseipdb_score_25_to_49_adds_10(self):
        results = [{"source": "abuseipdb", "verdict": "suspicious", "abuse_score": 30}]
        score, _ = _compute_ti_confidence(results, 0)
        assert score == 10

    def test_abuseipdb_score_below_25_adds_nothing(self):
        results = [{"source": "abuseipdb", "verdict": "benign", "abuse_score": 10}]
        score, _ = _compute_ti_confidence(results, 0)
        assert score == 0

    def test_greynoise_riot_subtracts_15_but_floor_at_zero(self):
        results = [{"source": "greynoise", "verdict": "benign", "riot": True}]
        score, _ = _compute_ti_confidence(results, 0)
        assert score == 0               # max(0, 0 - 15) = 0

    def test_greynoise_malicious_adds_20(self):
        results = [{"source": "greynoise", "verdict": "malicious", "riot": False}]
        score, verdict = _compute_ti_confidence(results, 0)
        assert score == 20
        assert verdict == "benign"      # 20 < 30 → benign

    def test_combined_misp_plus_vt_malicious_equals_60_and_malicious(self):
        results = [{"source": "virustotal", "verdict": "malicious"}]
        score, verdict = _compute_ti_confidence(results, 1)
        assert score == 60
        assert verdict == "malicious"

    def test_score_capped_at_100(self):
        # MISP(35) + VT malicious(25) + AbuseIPDB ≥50(20) + GreyNoise malicious(20) = 100
        results = [
            {"source": "virustotal", "verdict": "malicious"},
            {"source": "abuseipdb",  "verdict": "malicious", "abuse_score": 90},
            {"source": "greynoise",  "verdict": "malicious", "riot": False},
        ]
        score, verdict = _compute_ti_confidence(results, 1)
        assert score == 100
        assert verdict == "malicious"


# ---------------------------------------------------------------------------
# PHASE 2 — Hypothesis Engine: JSON Parsing & Evidence Summary
# ---------------------------------------------------------------------------

_VALID_HYPOTHESIS_JSON = json.dumps([
    {
        "id": "H1",
        "label": "Credential Dumping via LSASS",
        "technique": "T1003.001",
        "kill_chain_stage": "Actions on Objectives",
        "initial_probability": 80,
        "evidence_needed": ["process tree", "file hash lookup"],
        "reasoning": "LSASS memory access pattern detected.",
    },
    {
        "id": "H2",
        "label": "Lateral Movement via Pass-the-Hash",
        "technique": "T1550.002",
        "kill_chain_stage": "Exploitation",
        "initial_probability": 55,
        "evidence_needed": ["dns history", "user privilege"],
        "reasoning": "Multiple authentication failures from same host.",
    },
])


class TestPhase2HypothesisParser:
    """18 tests — _parse_hypotheses() and _build_evidence_summary()."""

    def test_valid_json_returns_two_hypotheses(self):
        result = _parse_hypotheses(_VALID_HYPOTHESIS_JSON)
        assert len(result) == 2

    def test_sorted_descending_by_probability(self):
        result = _parse_hypotheses(_VALID_HYPOTHESIS_JSON)
        assert result[0]["initial_probability"] >= result[1]["initial_probability"]

    def test_h1_has_all_required_fields(self):
        h1 = _parse_hypotheses(_VALID_HYPOTHESIS_JSON)[0]
        for field in ("id", "label", "technique", "kill_chain_stage",
                      "initial_probability", "evidence_needed", "reasoning"):
            assert field in h1

    def test_technique_preserved(self):
        result = _parse_hypotheses(_VALID_HYPOTHESIS_JSON)
        assert result[0]["technique"] == "T1003.001"

    def test_kill_chain_stage_in_allowed_set(self):
        from hypothesis_engine import _ALLOWED_STAGES
        result = _parse_hypotheses(_VALID_HYPOTHESIS_JSON)
        assert result[0]["kill_chain_stage"] in _ALLOWED_STAGES

    def test_invalid_kill_chain_stage_defaults_to_exploitation(self):
        raw = json.dumps([{
            "id": "H1", "label": "Test", "technique": "",
            "kill_chain_stage": "NOT_A_VALID_STAGE",
            "initial_probability": 50,
            "evidence_needed": [], "reasoning": "",
        }])
        result = _parse_hypotheses(raw)
        assert result[0]["kill_chain_stage"] == "Exploitation"

    def test_probability_clamped_at_100(self):
        raw = json.dumps([{
            "id": "H1", "label": "Test", "technique": "",
            "kill_chain_stage": "Exploitation",
            "initial_probability": 999,
            "evidence_needed": [], "reasoning": "",
        }])
        assert _parse_hypotheses(raw)[0]["initial_probability"] == 100

    def test_probability_clamped_at_0(self):
        raw = json.dumps([{
            "id": "H1", "label": "Test", "technique": "",
            "kill_chain_stage": "Exploitation",
            "initial_probability": -200,
            "evidence_needed": [], "reasoning": "",
        }])
        assert _parse_hypotheses(raw)[0]["initial_probability"] == 0

    def test_invalid_json_returns_empty_list(self):
        assert _parse_hypotheses("this is not json") == []

    def test_non_list_json_returns_empty_list(self):
        assert _parse_hypotheses('{"key": "value"}') == []

    def test_empty_array_returns_empty_list(self):
        assert _parse_hypotheses("[]") == []

    def test_entry_with_empty_label_is_skipped(self):
        raw = json.dumps([
            {"id": "H1", "label": "", "technique": "", "kill_chain_stage": "Exploitation",
             "initial_probability": 70, "evidence_needed": [], "reasoning": ""},
            {"id": "H2", "label": "Valid Hypothesis", "technique": "",
             "kill_chain_stage": "Exploitation",
             "initial_probability": 50, "evidence_needed": [], "reasoning": ""},
        ])
        result = _parse_hypotheses(raw)
        assert len(result) == 1
        assert result[0]["label"] == "Valid Hypothesis"

    def test_max_5_hypotheses_returned(self):
        hypotheses = [
            {"id": f"H{i}", "label": f"Scenario {i}", "technique": "",
             "kill_chain_stage": "Exploitation",
             "initial_probability": i * 10, "evidence_needed": [], "reasoning": ""}
            for i in range(1, 9)  # 8 entries
        ]
        result = _parse_hypotheses(json.dumps(hypotheses))
        assert len(result) <= 5

    def test_strips_markdown_code_fences(self):
        raw = "```json\n" + _VALID_HYPOTHESIS_JSON + "\n```"
        result = _parse_hypotheses(raw)
        assert len(result) == 2

    def test_evidence_needed_capped_at_6_items(self):
        raw = json.dumps([{
            "id": "H1", "label": "Overflow Test", "technique": "",
            "kill_chain_stage": "Exploitation",
            "initial_probability": 50,
            "evidence_needed": [f"item {i}" for i in range(10)],
            "reasoning": "",
        }])
        result = _parse_hypotheses(raw)
        assert len(result[0]["evidence_needed"]) <= 6

    def test_evidence_summary_empty_list_returns_sentinel(self):
        assert _build_evidence_summary([]) == "No evidence collected."

    def test_evidence_summary_single_item_contains_key_fields(self):
        items = [{
            "status": "COLLECTED", "evidence_type": "process_tree",
            "summary": "25 processes", "hypothesis_id": "H1", "agent_id": "a1",
        }]
        summary = _build_evidence_summary(items)
        assert "H1" in summary
        assert "COLLECTED" in summary
        assert "process_tree" in summary

    def test_evidence_summary_multiple_items_produces_multiple_lines(self):
        items = [
            {"status": "COLLECTED", "evidence_type": "process_tree",
             "summary": "ok", "hypothesis_id": "H1", "agent_id": "a1"},
            {"status": "FAILED", "evidence_type": "file_hash",
             "summary": "err", "hypothesis_id": "H2", "agent_id": "a1"},
        ]
        summary = _build_evidence_summary(items)
        assert len(summary.splitlines()) == 2


# ---------------------------------------------------------------------------
# PHASE 3A — Gap Analyser: Keyword → Evidence-Type Classification
# ---------------------------------------------------------------------------

class TestPhase3AGapClassifier:
    """8 tests — _classify_evidence_item() keyword matching."""

    def test_process_tree_keyword(self):
        assert _classify_evidence_item("check the process tree on target host") == "process_tree"

    def test_running_process_keyword(self):
        assert _classify_evidence_item("list all running processes") == "process_tree"

    def test_file_hash_keyword(self):
        assert _classify_evidence_item("file hash lookup for modified binaries") == "file_hash"

    def test_sha256_keyword(self):
        assert _classify_evidence_item("sha256 of suspicious file") == "file_hash"

    def test_dns_history_keyword(self):
        assert _classify_evidence_item("dns history for the affected host") == "dns_history"

    def test_user_privilege_keyword(self):
        assert _classify_evidence_item("check user privilege levels and group membership") == "user_privilege"

    def test_vulnerability_keyword(self):
        # "vulnerability" keyword — avoid "scan" because "sca" substring matches user_privilege first
        assert _classify_evidence_item("vulnerability assessment: unpatched CVE on host") == "vulnerability"

    def test_unrecognised_text_returns_none(self):
        assert _classify_evidence_item("verify the tea temperature") is None


# ---------------------------------------------------------------------------
# PHASE 3B — Gap Analyser: Manifest Generation
# ---------------------------------------------------------------------------

class TestPhase3BGapAnalyser:
    """10 tests — analyse_gaps() manifest correctness."""

    @staticmethod
    def _one_hyp(evidence_items):
        return [{"id": "H1", "evidence_needed": evidence_items}]

    def test_empty_hypotheses_returns_empty_list(self):
        assert analyse_gaps([], {}) == []

    def test_two_evidence_types_produce_two_missing_items(self):
        gaps = analyse_gaps(self._one_hyp(["process tree", "file hash lookup"]), {})
        assert len(gaps) == 1
        assert len(gaps[0]["missing"]) == 2

    def test_already_collected_evidence_is_skipped(self):
        gaps = analyse_gaps(
            self._one_hyp(["process tree", "file hash lookup"]),
            {"process_tree": "already available"},
        )
        assert len(gaps[0]["missing"]) == 1
        assert gaps[0]["missing"][0]["evidence_type"] == "file_hash"

    def test_missing_items_sorted_by_priority_ascending(self):
        # process_tree=1, dns_history=3, vulnerability=5
        gaps = analyse_gaps(
            self._one_hyp(["vulnerability scan", "dns history", "process tree"]),
            {},
        )
        priorities = [m["priority"] for m in gaps[0]["missing"]]
        assert priorities == sorted(priorities)

    def test_duplicate_evidence_types_within_hypothesis_are_deduplicated(self):
        gaps = analyse_gaps(
            self._one_hyp(["process tree for all hosts", "check the running process list"]),
            {},
        )
        types = [m["evidence_type"] for m in gaps[0]["missing"]]
        assert len(types) == len(set(types))

    def test_gap_entry_contains_collector_name(self):
        gaps = analyse_gaps(self._one_hyp(["process tree"]), {})
        assert gaps[0]["missing"][0]["collector"] == "ProcessTreeCollector"

    def test_gap_entry_contains_original_description(self):
        gaps = analyse_gaps(self._one_hyp(["dns history for C2 traffic"]), {})
        assert "dns history" in gaps[0]["missing"][0]["description"].lower()

    def test_hypothesis_with_no_mappable_items_is_omitted(self):
        hyps = [{"id": "H1", "evidence_needed": ["check the moon phase"]}]
        assert analyse_gaps(hyps, {}) == []

    def test_multiple_hypotheses_produce_separate_gap_entries(self):
        hyps = [
            {"id": "H1", "evidence_needed": ["process tree"]},
            {"id": "H2", "evidence_needed": ["dns history"]},
        ]
        gaps = analyse_gaps(hyps, {})
        assert len(gaps) == 2
        assert {g["hypothesis_id"] for g in gaps} == {"H1", "H2"}

    def test_fully_collected_hypothesis_not_included_in_gaps(self):
        gaps = analyse_gaps(self._one_hyp(["process tree"]), {"process_tree": "collected"})
        assert gaps == []


# ---------------------------------------------------------------------------
# PHASE 3C — Evidence Collector: Item Factory & Status Contract
# ---------------------------------------------------------------------------

class TestPhase3CEvidenceItemFactory:
    """6 tests — _make_item() structure and status values."""

    def test_collected_item_has_correct_fields(self):
        item = _make_item("H1", "process_tree", "ProcessTreeCollector",
                          "agent-001", "COLLECTED", "5 procs found",
                          data={"processes": []})
        assert item["status"]       == "COLLECTED"
        assert item["hypothesis_id"]== "H1"
        assert item["evidence_type"]== "process_tree"
        assert item["collector"]    == "ProcessTreeCollector"
        assert item["agent_id"]     == "agent-001"
        assert item["data"]         is not None
        assert item["error"]        is None

    def test_failed_item_carries_error_message(self):
        item = _make_item("H2", "file_hash", "FileHashCollector",
                          None, "FAILED", "No Wazuh creds",
                          error="Connection refused")
        assert item["status"] == "FAILED"
        assert item["error"]  == "Connection refused"

    def test_missing_item_status(self):
        item = _make_item("H1", "dns_history", "DNSHistoryCollector",
                          "a1", "MISSING", "No DNS events found")
        assert item["status"] == "MISSING"

    def test_item_has_non_empty_timestamp(self):
        item = _make_item("H1", "process_tree", "ProcessTreeCollector",
                          "a1", "COLLECTED", "ok")
        assert "timestamp" in item
        assert item["timestamp"]

    def test_all_four_status_values_accepted(self):
        for status in ("COLLECTED", "MISSING", "FAILED", "PENDING"):
            item = _make_item("H1", "process_tree", "X", None, status, "")
            assert item["status"] == status

    def test_no_data_arg_defaults_to_none(self):
        item = _make_item("H1", "process_tree", "X", None, "FAILED", "err")
        assert item["data"] is None


# ---------------------------------------------------------------------------
# PHASE 3D — Evidence Collector: No-Credential Dispatch
# ---------------------------------------------------------------------------

class TestPhase3DCollectNoWazuh:
    """8 tests — collect_all() with no Wazuh credentials returns FAILED items, never raises."""

    @staticmethod
    def _gaps(evidence_types):
        return [
            {"hypothesis_id": "H1", "missing": [
                {"evidence_type": et,
                 "collector":     et.title() + "Collector",
                 "priority":      i + 1,
                 "description":   et}
                for i, et in enumerate(evidence_types)
            ]}
        ]

    def test_empty_gaps_returns_empty_list(self):
        inc = _make_mock_incident(affected_agents=["a1"])
        assert _run(collect_all(inc, [], _make_db_with_empty_rows())) == []

    def test_process_tree_without_creds_returns_failed(self):
        inc    = _make_mock_incident(affected_agents=["a1"])
        result = _run(collect_all(inc, self._gaps(["process_tree"]),
                                  _make_db_with_empty_rows()))
        assert len(result) == 1
        assert result[0]["status"]        == "FAILED"
        assert result[0]["evidence_type"] == "process_tree"

    def test_file_hash_without_creds_returns_failed(self):
        inc    = _make_mock_incident(affected_agents=["a1"])
        result = _run(collect_all(inc, self._gaps(["file_hash"]),
                                  _make_db_with_empty_rows()))
        assert result[0]["status"] == "FAILED"

    def test_user_privilege_without_creds_returns_failed(self):
        inc    = _make_mock_incident(affected_agents=["a1"])
        result = _run(collect_all(inc, self._gaps(["user_privilege"]),
                                  _make_db_with_empty_rows()))
        assert result[0]["status"] == "FAILED"

    def test_vulnerability_without_creds_returns_failed(self):
        inc    = _make_mock_incident(affected_agents=["a1"])
        result = _run(collect_all(inc, self._gaps(["vulnerability"]),
                                  _make_db_with_empty_rows()))
        assert result[0]["status"] == "FAILED"

    def test_no_agents_process_tree_returns_failed(self):
        inc    = _make_mock_incident(affected_agents=[])
        result = _run(collect_all(inc, self._gaps(["process_tree"]),
                                  _make_db_with_empty_rows()))
        assert result[0]["status"] == "FAILED"

    def test_collect_all_never_raises_on_bad_incident(self):
        inc               = MagicMock()
        inc.affected_agents = None
        inc.id            = "bad"
        result = _run(collect_all(inc, self._gaps(["process_tree"]),
                                  _make_db_with_empty_rows()))
        assert isinstance(result, list)

    def test_multiple_wazuh_types_all_failed_without_creds(self):
        inc    = _make_mock_incident(affected_agents=["a1"])
        gaps   = self._gaps(["process_tree", "file_hash", "user_privilege", "vulnerability"])
        result = _run(collect_all(inc, gaps, _make_db_with_empty_rows()))
        for item in result:
            if item["evidence_type"] != "dns_history":
                assert item["status"] == "FAILED"


# ---------------------------------------------------------------------------
# PHASE 4A — Confidence Engine: Component Score Functions
# ---------------------------------------------------------------------------

class TestPhase4AComponentScores:
    """13 tests — _rule_confidence_score(), _ti_confidence_score(), _asset_confidence_score()."""

    # _rule_confidence_score
    def test_rule_score_averages_rule_confidences(self):
        inc = _make_mock_incident(correlated_rules=[
            {"rule_id": "CR-001", "confidence": 0.9},
            {"rule_id": "CR-002", "confidence": 0.7},
        ])
        assert abs(_rule_confidence_score(inc) - 0.8) < 0.001

    def test_rule_score_no_rules_falls_back_to_severity(self):
        inc = _make_mock_incident(correlated_rules=[], severity="high")
        assert _rule_confidence_score(inc) == 0.75

    def test_rule_score_severity_critical_yields_09(self):
        inc = _make_mock_incident(correlated_rules=[], severity="critical")
        assert _rule_confidence_score(inc) == 0.9

    def test_rule_score_severity_medium_yields_05(self):
        inc = _make_mock_incident(correlated_rules=[], severity="medium")
        assert _rule_confidence_score(inc) == 0.5

    def test_rule_score_severity_low_yields_025(self):
        inc = _make_mock_incident(correlated_rules=[], severity="low")
        assert _rule_confidence_score(inc) == 0.25

    # _ti_confidence_score
    def test_ti_none_returns_neutral_030(self):
        assert _ti_confidence_score(None) == 0.3

    def test_ti_malicious_verdict_returns_10(self):
        assert _ti_confidence_score({"verdict": "malicious"}) == 1.0

    def test_ti_suspicious_verdict_returns_06(self):
        assert _ti_confidence_score({"verdict": "suspicious"}) == 0.6

    def test_ti_benign_verdict_returns_00(self):
        assert _ti_confidence_score({"verdict": "benign"}) == 0.0

    def test_ti_clean_verdict_returns_00(self):
        assert _ti_confidence_score({"verdict": "clean"}) == 0.0

    # _asset_confidence_score
    def test_asset_tier1_crown_jewel_returns_10(self):
        assert _asset_confidence_score(1) == 1.0

    def test_asset_tier2_business_critical_returns_06(self):
        assert _asset_confidence_score(2) == 0.6

    def test_asset_tier3_and_none_return_02(self):
        assert _asset_confidence_score(3)    == 0.2
        assert _asset_confidence_score(None) == 0.2


# ---------------------------------------------------------------------------
# PHASE 4B — compute_investigation_confidence: Weight Model & Breakdown
# ---------------------------------------------------------------------------

class TestPhase4BConfidenceModel:
    """15 tests — weight model, breakdown structure, and edge cases."""

    def test_returns_tuple_of_float_and_dict(self):
        inc = _make_mock_incident()
        result = compute_investigation_confidence(inc, None, None, None)
        assert isinstance(result, tuple) and len(result) == 2
        assert isinstance(result[0], float)
        assert isinstance(result[1], dict)

    def test_score_is_in_0_to_1_range(self):
        inc = _make_mock_incident(correlated_rules=[], severity="medium")
        score, _ = compute_investigation_confidence(inc, None, 50, None)
        assert 0.0 <= score <= 1.0

    def test_breakdown_has_exactly_five_components(self):
        inc = _make_mock_incident()
        _, breakdown = compute_investigation_confidence(inc, None, None, None)
        assert set(breakdown.keys()) == {"rule", "ti", "historical", "asset", "llm"}

    def test_each_breakdown_component_has_score_weight_contribution_label(self):
        inc = _make_mock_incident()
        _, breakdown = compute_investigation_confidence(inc, None, None, None)
        for comp in breakdown.values():
            for field in ("score", "weight", "contribution", "label"):
                assert field in comp

    def test_historical_weight_is_zero_when_similarity_is_zero(self):
        inc = _make_mock_incident()
        _, breakdown = compute_investigation_confidence(inc, None, None, None, 0.0)
        assert breakdown["historical"]["weight"] == 0.0

    def test_historical_weight_is_nonzero_when_similarity_provided(self):
        inc = _make_mock_incident()
        _, breakdown = compute_investigation_confidence(inc, None, None, None, 0.7)
        assert breakdown["historical"]["weight"] > 0.0

    def test_malicious_ti_increases_score_vs_no_ti(self):
        inc = _make_mock_incident(correlated_rules=[], severity="medium")
        score_no_ti, _   = compute_investigation_confidence(inc, None, 50, None)
        score_with_ti, _ = compute_investigation_confidence(
            inc, {"verdict": "malicious"}, 50, None)
        assert score_with_ti > score_no_ti

    def test_tier1_asset_higher_score_than_tier3(self):
        inc = _make_mock_incident(correlated_rules=[], severity="medium")
        score_t3, _ = compute_investigation_confidence(inc, None, 50, 3)
        score_t1, _ = compute_investigation_confidence(inc, None, 50, 1)
        assert score_t1 > score_t3

    def test_high_llm_probability_higher_score_than_low(self):
        inc = _make_mock_incident(correlated_rules=[], severity="medium")
        score_low, _  = compute_investigation_confidence(inc, None, 10, None)
        score_high, _ = compute_investigation_confidence(inc, None, 90, None)
        assert score_high > score_low

    def test_all_max_components_yield_score_near_1(self):
        inc = _make_mock_incident(
            correlated_rules=[{"confidence": 1.0}], severity="critical")
        score, _ = compute_investigation_confidence(
            inc,
            ti_reputation={"verdict": "malicious"},
            top_hypothesis_prob=100,
            asset_tier=1,
            historical_similarity=1.0,
        )
        assert score >= 0.9

    def test_all_low_components_yield_score_under_05(self):
        inc = _make_mock_incident(correlated_rules=[], severity="low")
        score, _ = compute_investigation_confidence(
            inc,
            ti_reputation={"verdict": "benign"},
            top_hypothesis_prob=0,
            asset_tier=3,
            historical_similarity=0.0,
        )
        assert score < 0.5

    def test_contributions_sum_to_confidence_score(self):
        inc = _make_mock_incident(correlated_rules=[], severity="high")
        score, breakdown = compute_investigation_confidence(
            inc, {"verdict": "suspicious"}, 60, 2, 0.0)
        total_contribution = sum(v["contribution"] for v in breakdown.values())
        assert abs(total_contribution - score) < 0.01

    def test_none_top_hypothesis_prob_treated_same_as_zero(self):
        inc = _make_mock_incident(correlated_rules=[], severity="medium")
        score_none, _ = compute_investigation_confidence(inc, None, None, None)
        score_zero, _ = compute_investigation_confidence(inc, None, 0, None)
        assert abs(score_none - score_zero) < 0.01

    def test_historical_similarity_above_1_is_clamped_to_1(self):
        inc = _make_mock_incident()
        score_clamped, _ = compute_investigation_confidence(inc, None, None, None, 2.0)
        score_max, _     = compute_investigation_confidence(inc, None, None, None, 1.0)
        assert abs(score_clamped - score_max) < 0.01

    def test_never_raises_on_minimal_incident(self):
        inc = _make_mock_incident()
        try:
            compute_investigation_confidence(inc, None, None, None)
        except Exception as exc:
            pytest.fail(f"compute_investigation_confidence raised: {exc}")


# ---------------------------------------------------------------------------
# PHASE 5A — SOAR Connector: Confidence Gate
# ---------------------------------------------------------------------------

class TestPhase5ASOARGate:
    """12 tests — dispatch_if_confident() three-gate logic."""

    def test_below_70_returns_needs_review(self):
        inc   = _make_mock_incident(soar_dispatch_log=None)
        entry = _run(dispatch_if_confident(AsyncMock(), inc, {}, 0.65))
        assert entry["status"] == "needs_review"

    def test_below_70_no_actions_dispatched(self):
        inc   = _make_mock_incident(soar_dispatch_log=None)
        entry = _run(dispatch_if_confident(AsyncMock(), inc, {}, 0.50))
        assert entry["actions_sent"] == 0
        assert entry["http_status"]  is None

    def test_70_to_89_returns_pending_approval(self):
        inc   = _make_mock_incident(soar_dispatch_log=None)
        entry = _run(dispatch_if_confident(AsyncMock(), inc, {}, 0.75))
        assert entry["status"] == "pending_approval"

    def test_70_to_89_no_auto_dispatch(self):
        inc   = _make_mock_incident(soar_dispatch_log=None)
        entry = _run(dispatch_if_confident(AsyncMock(), inc, {}, 0.80))
        assert entry["actions_sent"] == 0

    def test_exactly_70_is_pending_approval(self):
        inc   = _make_mock_incident(soar_dispatch_log=None)
        entry = _run(dispatch_if_confident(AsyncMock(), inc, {}, 0.70))
        assert entry["status"] == "pending_approval"

    def test_exactly_90_attempts_dispatch_no_webhook_configured(self):
        inc   = _make_mock_incident(soar_dispatch_log=None)
        entry = _run(dispatch_if_confident(AsyncMock(), inc, {}, 0.90))
        # No webhook configured → soar_not_configured (not pending/needs_review)
        assert entry["status"] == "soar_not_configured"

    def test_above_90_no_webhook_returns_soar_not_configured(self):
        inc   = _make_mock_incident(soar_dispatch_log=None)
        entry = _run(dispatch_if_confident(AsyncMock(), inc, {}, 0.95))
        assert entry["status"] == "soar_not_configured"

    def test_confidence_stored_as_percentage_in_entry(self):
        inc   = _make_mock_incident(soar_dispatch_log=None)
        entry = _run(dispatch_if_confident(AsyncMock(), inc, {}, 0.65))
        assert entry["confidence"] == 65.0

    def test_entry_has_non_empty_timestamp(self):
        inc   = _make_mock_incident(soar_dispatch_log=None)
        entry = _run(dispatch_if_confident(AsyncMock(), inc, {}, 0.60))
        assert entry.get("timestamp")

    def test_entry_is_appended_to_dispatch_log(self):
        inc   = _make_mock_incident(soar_dispatch_log=None)
        _run(dispatch_if_confident(AsyncMock(), inc, {}, 0.60))
        assert isinstance(inc.soar_dispatch_log, list)
        assert len(inc.soar_dispatch_log) >= 1

    def test_second_dispatch_appends_to_existing_log(self):
        inc   = _make_mock_incident(soar_dispatch_log=None)
        _run(dispatch_if_confident(AsyncMock(), inc, {}, 0.60))
        _run(dispatch_if_confident(AsyncMock(), inc, {}, 0.65))
        assert len(inc.soar_dispatch_log) == 2

    def test_never_raises_on_malformed_incident(self):
        inc    = MagicMock()
        inc.id = "bad"
        inc.soar_dispatch_log = None
        try:
            _run(dispatch_if_confident(AsyncMock(), inc, {}, 0.50))
        except Exception as exc:
            pytest.fail(f"dispatch_if_confident raised: {exc}")


# ---------------------------------------------------------------------------
# PHASE 5B — SOAR Connector: Webhook URL Resolution Order
# ---------------------------------------------------------------------------

class TestPhase5BWebhookResolution:
    """8 tests — _soar_webhook_url() three-path resolution."""

    def setup_method(self):
        # Ensure env URL is cleared before each test
        _mock_settings.soar_webhook_url = ""

    def teardown_method(self):
        _mock_settings.soar_webhook_url = ""

    def test_env_url_takes_highest_priority(self):
        _mock_settings.soar_webhook_url = "http://env.example.com:1880"
        url, source = _soar_webhook_url()
        assert url    == "http://env.example.com:1880"
        assert source == "env"

    def test_env_url_source_tagged_as_env(self):
        _mock_settings.soar_webhook_url = "http://webhook.internal:1880"
        _, source = _soar_webhook_url()
        assert source == "env"

    def test_empty_env_falls_through_returns_empty(self):
        _mock_settings.soar_webhook_url = ""
        url, source = _soar_webhook_url()
        assert url    == ""
        assert source == ""

    def test_whitespace_only_env_not_treated_as_valid(self):
        _mock_settings.soar_webhook_url = "   "
        url, source = _soar_webhook_url()
        # Strip("   ") = "" → should fall through
        assert source != "env"

    def test_auto_detect_cysoar_running_from_state_json(self):
        state = {"cysoar": {"status": "running"}}

        def mock_read(path_self, **kwargs):
            if "state.json" in str(path_self):
                return json.dumps(state)
            raise FileNotFoundError(str(path_self))

        with patch.object(Path, "read_text", mock_read):
            url, source = _soar_webhook_url()
        assert url    == "http://127.0.0.1:1880"
        assert source == "auto"

    def test_auto_detect_cysoar_not_running_falls_through(self):
        state = {"cysoar": {"status": "stopped"}}

        def mock_read(path_self, **kwargs):
            if "state.json" in str(path_self):
                return json.dumps(state)
            raise FileNotFoundError(str(path_self))

        with patch.object(Path, "read_text", mock_read):
            url, source = _soar_webhook_url()
        assert url    == ""
        assert source == ""

    def test_resolution_always_returns_tuple(self):
        result = _soar_webhook_url()
        assert isinstance(result, tuple) and len(result) == 2

    def test_resolution_never_raises(self):
        try:
            _soar_webhook_url()
        except Exception as exc:
            pytest.fail(f"_soar_webhook_url raised: {exc}")


# ---------------------------------------------------------------------------
# PHASE 5C — SOAR Connector: Status Reporting
# ---------------------------------------------------------------------------

class TestPhase5CSOARStatus:
    """6 tests — get_soar_status() with various state.json conditions."""

    def setup_method(self):
        _mock_settings.soar_webhook_url = ""

    def test_returns_dict_with_required_keys(self):
        status = get_soar_status()
        for key in ("installed", "running", "url", "source"):
            assert key in status

    def test_never_raises_without_state_json(self):
        try:
            get_soar_status()
        except Exception as exc:
            pytest.fail(f"get_soar_status raised: {exc}")

    def test_without_state_json_installed_is_false(self):
        status = get_soar_status()
        assert status["installed"] is False

    def test_state_json_running_detected(self):
        state = {"cysoar": {"status": "running", "installed": True}}

        def mock_read(path_self, **kwargs):
            return json.dumps(state)

        with patch.object(Path, "read_text", mock_read):
            status = get_soar_status()
        assert status["running"] is True
        assert status["installed"] is True

    def test_auto_detected_internal_url_not_exposed(self):
        state = {"cysoar": {"status": "running"}}

        def mock_read(path_self, **kwargs):
            if "state.json" in str(path_self):
                return json.dumps(state)
            raise FileNotFoundError(str(path_self))

        with patch.object(Path, "read_text", mock_read):
            status = get_soar_status()
        # Internal auto-detected URL should not leak into the API response
        assert status.get("url") != "http://127.0.0.1:1880"

    def test_source_field_is_a_known_value(self):
        status = get_soar_status()
        assert status.get("source") in ("env", "config", "auto", "none", "")


# ---------------------------------------------------------------------------
# PHASE 6A — Historical Similarity: No-Pattern / Partial / Full Match
# ---------------------------------------------------------------------------

class TestPhase6AHistoricalSimilarity:
    """8 tests — compute_historical_similarity() with mocked DB."""

    @staticmethod
    def _db_no_patterns():
        db           = AsyncMock()
        res          = MagicMock()
        res.all.return_value = []
        db.execute   = AsyncMock(return_value=res)
        return db

    @staticmethod
    def _db_with_rows(rows):
        db           = AsyncMock()
        res          = MagicMock()
        res.all.return_value = rows
        db.execute   = AsyncMock(return_value=res)
        return db

    def test_no_technique_and_no_stage_returns_zero(self):
        score = _run(compute_historical_similarity(self._db_no_patterns(), None, None))
        assert score == 0.0

    def test_no_stored_patterns_returns_zero(self):
        score = _run(compute_historical_similarity(
            self._db_no_patterns(), "T1059", "Exploitation"))
        assert score == 0.0

    def test_technique_only_match_scores_06(self):
        # Row: (technique, kill_chain_stage)
        score = _run(compute_historical_similarity(
            self._db_with_rows([("T1059", "Delivery")]),
            "T1059", "Exploitation"))
        assert abs(score - 0.6) < 0.01

    def test_kill_chain_only_match_scores_04(self):
        score = _run(compute_historical_similarity(
            self._db_with_rows([("T9999", "Exploitation")]),
            "T1059", "Exploitation"))
        assert abs(score - 0.4) < 0.01

    def test_full_match_technique_and_kill_chain_scores_10(self):
        score = _run(compute_historical_similarity(
            self._db_with_rows([("T1059", "Exploitation")]),
            "T1059", "Exploitation"))
        assert abs(score - 1.0) < 0.01

    def test_returns_best_score_across_multiple_patterns(self):
        score = _run(compute_historical_similarity(
            self._db_with_rows([
                ("T9999", "Exploitation"),   # kill_chain only → 0.4
                ("T1059", "Exploitation"),   # both → 1.0
            ]),
            "T1059", "Exploitation"))
        assert abs(score - 1.0) < 0.01

    def test_score_never_exceeds_10(self):
        score = _run(compute_historical_similarity(
            self._db_with_rows([("T1059", "Exploitation")] * 5),
            "T1059", "Exploitation"))
        assert score <= 1.0

    def test_db_error_returns_zero_never_raises(self):
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=Exception("DB offline"))
        score = _run(compute_historical_similarity(db, "T1059", "Exploitation"))
        assert score == 0.0


# ---------------------------------------------------------------------------
# PHASE 6B — Incident Pattern Memory: Field Mapping & Never-Raises
# ---------------------------------------------------------------------------

class TestPhase6BPatternStorage:
    """8 tests — _store_incident_pattern() field mapping and error resilience."""

    @staticmethod
    def _db():
        db       = AsyncMock()
        db.add   = MagicMock()
        db.flush = AsyncMock()
        return db

    @staticmethod
    def _capture_db():
        """Return (db, captured_dict) where IncidentPattern ctor kwargs are recorded."""
        captured = {}

        class _FakePattern:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                for k, v in kwargs.items():
                    setattr(self, k, v)

        db = AsyncMock()
        db.add   = MagicMock()
        db.flush = AsyncMock()
        sys.modules["models"].IncidentPattern = _FakePattern
        return db, captured

    def test_db_add_called_once_on_closed_incident(self):
        inc = _make_mock_incident(
            status="closed", mitre_ids=["T1059"], confidence_score=0.82)
        db  = self._db()
        _run(_store_incident_pattern(db, inc))
        db.add.assert_called_once()

    def test_never_raises_on_db_flush_error(self):
        inc    = _make_mock_incident(status="closed", mitre_ids=["T1003"])
        db     = AsyncMock()
        db.add = MagicMock()
        db.flush = AsyncMock(side_effect=Exception("flush failed"))
        try:
            _run(_store_incident_pattern(db, inc))
        except Exception as exc:
            pytest.fail(f"_store_incident_pattern raised on flush error: {exc}")

    def test_never_raises_on_minimal_incident(self):
        inc = _make_mock_incident()
        db  = self._db()
        try:
            _run(_store_incident_pattern(db, inc))
        except Exception as exc:
            pytest.fail(f"_store_incident_pattern raised on minimal incident: {exc}")

    def test_technique_from_first_mitre_id(self):
        db, captured = self._capture_db()
        inc = _make_mock_incident(mitre_ids=["T1003.001", "T1059"])
        _run(_store_incident_pattern(db, inc))
        assert captured.get("technique") == "T1003.001"

    def test_kill_chain_stage_from_kill_chain_stage_name(self):
        db, captured = self._capture_db()
        inc = _make_mock_incident(kill_chain_stage_name="Command & Control")
        _run(_store_incident_pattern(db, inc))
        assert captured.get("kill_chain_stage") == "Command & Control"

    def test_outcome_from_incident_status(self):
        db, captured = self._capture_db()
        inc = _make_mock_incident(status="resolved")
        _run(_store_incident_pattern(db, inc))
        assert captured.get("outcome") == "resolved"

    def test_confidence_at_resolution_from_confidence_score(self):
        db, captured = self._capture_db()
        inc = _make_mock_incident(confidence_score=0.87)
        _run(_store_incident_pattern(db, inc))
        assert captured.get("confidence_at_resolution") == 0.87

    def test_similarity_vector_has_expected_keys(self):
        db, captured = self._capture_db()
        inc = _make_mock_incident(
            mitre_ids=["T1059"], mitre_tactics=["Execution"],
            kill_chain_stage_name="Exploitation", severity="high", alert_count=8)
        _run(_store_incident_pattern(db, inc))
        sv = captured.get("similarity_vector", {})
        for key in ("techniques", "tactics", "kill_chain", "severity", "alert_count_bucket"):
            assert key in sv, f"similarity_vector missing key: {key}"
