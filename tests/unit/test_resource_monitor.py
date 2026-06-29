from __future__ import annotations
"""
Suite 11 — Resource Monitor End-to-End Tests

Tests the full alerting pipeline for CPU / memory / disk threshold monitoring:

  Phase 1 — Script output format
      Runs cy360_resource_check.sh with forced thresholds (CPU_THRESH=0 etc.)
      and validates the emitted JSON lines are well-formed and contain the
      expected fields.

  Phase 2 — Decoder prematch
      Verifies the Wazuh decoder prematch pattern in cy_cust_decoders.xml
      matches the exact output format produced by the script.

  Phase 3 — Wazuh rule XML structure
      Parses cy_cust_rules.xml and asserts rules 101004-101007 exist with
      correct attributes (level, decoded_as, group membership).

  Phase 4 — Correlator CR-056 unit tests
      Positive match, negative no-match, detail labels, result contract.

  Phase 5 — Full pipeline simulation
      Builds a raw Wazuh-style alert dict → normaliser → stored alert dict
      → correlator → verifies an incident detail is generated.
"""
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
REPO_ROOT   = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "CYSIEM-Config" / "agent_config"
RULES_FILE  = REPO_ROOT / "CYSIEM-Config" / "rules"   / "cy_cust_rules.xml"
DECODERS_FILE = REPO_ROOT / "CYSIEM-Config" / "decoders" / "cy_cust_decoders.xml"
LINUX_SCRIPT  = SCRIPTS_DIR / "cy360_resource_check.sh"
WIN_SCRIPT    = SCRIPTS_DIR / "cy360_resource_check.ps1"

# Stub heavy dependencies before importing correlation engine modules
for _mod in (
    "sqlalchemy", "sqlalchemy.ext", "sqlalchemy.ext.asyncio",
    "sqlalchemy.orm", "models", "structlog",
):
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

CE_PATH = str(REPO_ROOT / "backend" / "cysiemstack" / "correlation_engine")
if CE_PATH not in sys.path:
    sys.path.insert(0, CE_PATH)

from correlator import HighResourceUtilization  # noqa: E402
from normaliser  import normalise               # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _run_script_forced(extra_env: dict | None = None) -> list[dict]:
    """
    Run cy360_resource_check.sh with all thresholds set to 0 so every metric
    fires regardless of actual host load. Returns list of parsed JSON objects.
    """
    env = os.environ.copy()
    env.update({"CPU_THRESH": "0", "MEM_THRESH": "0", "DISK_THRESH": "0"})
    if extra_env:
        env.update(extra_env)

    result = subprocess.run(
        ["bash", str(LINUX_SCRIPT)],
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
    )
    assert result.returncode == 0, f"Script failed: {result.stderr}"
    lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    return [json.loads(l) for l in lines]


def _make_alert(**kw) -> dict:
    """Minimal normalised alert dict for correlator tests."""
    base = {
        "wazuh_id":    "w1",
        "rule_id":     "101004",
        "rule_desc":   "CyCentra 360: High CPU utilization 94% on host1 — threshold 90%",
        "agent_id":    "agent1",
        "agent_name":  "host1",
        "username":    None,
        "src_ip":      None,
        "category":    None,
        "timestamp":   datetime.now(timezone.utc),
        "base_score":  5.0,
        "file_path":   None,
        "process_name": None,
        "raw_log":     "",
    }
    base.update(kw)
    return base


def _raw_wazuh_alert(rule_id: int, rule_desc: str, level: int = 7,
                     agent_name: str = "host1") -> dict:
    """Build a raw Wazuh-style alert dict (pre-normaliser)."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {
            "id":          rule_id,
            "level":       level,
            "description": rule_desc,
            "groups":      ["resource_monitor"],
        },
        "agent": {
            "id":   "001",
            "name": agent_name,
            "ip":   "192.168.1.10",
        },
        "full_log": f"ossec: output: 'cy360-resource-check': {rule_desc}",
    }


# ===========================================================================
# Phase 1 — Script output format
# ===========================================================================
class TestScriptOutputFormat:
    """cy360_resource_check.sh emits valid, well-formed JSON when thresholds crossed."""

    @pytest.fixture(scope="class")
    def events(self):
        if not LINUX_SCRIPT.exists():
            pytest.skip(f"Script not found: {LINUX_SCRIPT}")
        if sys.platform == "win32":
            pytest.skip("bash not available on Windows runner")
        return _run_script_forced()

    def test_at_least_one_event_emitted(self, events):
        """Forcing all thresholds to 0 must produce at least one output line."""
        assert len(events) >= 1, "Script emitted no JSON lines with thresholds=0"

    def test_all_lines_valid_json(self, events):
        """Every output line must parse as valid JSON (no parse errors)."""
        assert len(events) >= 1

    def test_event_field_present(self, events):
        """Every event has an 'event' field."""
        for e in events:
            assert "event" in e, f"Missing 'event' field in: {e}"

    def test_event_names_are_known(self, events):
        """event field value is one of the three known types."""
        known = {"high_cpu", "high_memory", "high_disk"}
        for e in events:
            assert e["event"] in known, f"Unknown event type: {e['event']}"

    def test_cpu_event_has_cpu_percent(self, events):
        for e in [x for x in events if x["event"] == "high_cpu"]:
            assert "cpu_percent" in e
            assert isinstance(e["cpu_percent"], (int, float))
            assert 0 <= e["cpu_percent"] <= 100

    def test_disk_event_has_disk_percent(self, events):
        for e in [x for x in events if x["event"] == "high_disk"]:
            assert "disk_percent" in e
            assert isinstance(e["disk_percent"], (int, float))
            assert 0 <= e["disk_percent"] <= 100

    def test_memory_event_has_mem_percent(self, events):
        for e in [x for x in events if x["event"] == "high_memory"]:
            assert "mem_percent" in e
            assert isinstance(e["mem_percent"], (int, float))
            assert 0 <= e["mem_percent"] <= 100

    def test_threshold_field_present(self, events):
        for e in events:
            assert "threshold" in e, f"Missing 'threshold' in: {e}"
            assert isinstance(e["threshold"], (int, float))

    def test_host_field_present(self, events):
        for e in events:
            assert "host" in e, f"Missing 'host' in: {e}"
            assert isinstance(e["host"], str) and len(e["host"]) > 0

    def test_ts_field_is_iso8601(self, events):
        iso_re = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        for e in events:
            assert "ts" in e, f"Missing 'ts' in: {e}"
            assert iso_re.match(e["ts"]), f"ts not ISO-8601: {e['ts']}"

    def test_silent_below_threshold(self):
        """When all metrics are well under threshold, script emits nothing."""
        if not LINUX_SCRIPT.exists():
            pytest.skip(f"Script not found: {LINUX_SCRIPT}")
        if sys.platform == "win32":
            pytest.skip("bash not available on Windows runner")
        env = os.environ.copy()
        env.update({"CPU_THRESH": "101", "MEM_THRESH": "101", "DISK_THRESH": "101"})
        result = subprocess.run(
            ["bash", str(LINUX_SCRIPT)],
            capture_output=True, text=True, env=env, timeout=15,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == "", \
            f"Expected silent output with 101% thresholds, got: {result.stdout!r}"

    def test_three_distinct_event_types_emitted(self, events):
        """With all thresholds at 0, all three event types should fire."""
        types = {e["event"] for e in events}
        assert types == {"high_cpu", "high_memory", "high_disk"}, \
            f"Expected all three event types, got: {types}"


# ===========================================================================
# Phase 2 — Decoder prematch
# ===========================================================================
class TestDecoderPrematch:
    """The Wazuh decoder prematch must match the exact output header format."""

    WAZUH_OUTPUT_PREFIX = "ossec: output: 'cy360-resource-check':"

    def test_decoder_file_exists(self):
        assert DECODERS_FILE.exists(), f"Decoder file missing: {DECODERS_FILE}"

    def test_decoder_names_present(self):
        tree = ET.parse(DECODERS_FILE)
        root = tree.getroot()
        names = {d.get("name") for d in root.iter("decoder")}
        assert "cy360-resource-check" in names, \
            "Parent decoder 'cy360-resource-check' not found"
        assert "cy360-resource-check-json" in names, \
            "Child decoder 'cy360-resource-check-json' not found"

    def test_parent_decoder_prematch(self):
        tree = ET.parse(DECODERS_FILE)
        root = tree.getroot()
        parent = next(
            (d for d in root.iter("decoder")
             if d.get("name") == "cy360-resource-check"), None
        )
        assert parent is not None
        pm = parent.findtext("prematch") or ""
        # The Wazuh output format prefixes with "ossec: output: '<alias>': "
        assert "cy360-resource-check" in pm, \
            f"Prematch doesn't reference alias: {pm!r}"

    def test_child_decoder_has_json_plugin(self):
        tree = ET.parse(DECODERS_FILE)
        root = tree.getroot()
        child = next(
            (d for d in root.iter("decoder")
             if d.get("name") == "cy360-resource-check-json"), None
        )
        assert child is not None
        assert child.findtext("parent") == "cy360-resource-check"
        plugin = child.findtext("plugin_decoder") or ""
        assert "JSON" in plugin.upper(), \
            f"Child decoder must use JSON_Decoder, got: {plugin!r}"

    def test_prematch_matches_actual_output_format(self):
        """The prematch regex/string matches a real output line from the script."""
        tree = ET.parse(DECODERS_FILE)
        root = tree.getroot()
        parent = next(
            (d for d in root.iter("decoder")
             if d.get("name") == "cy360-resource-check"), None
        )
        pm_text = (parent.findtext("prematch") or "").strip()
        # The prematch is a substring match in Wazuh — verify it appears in
        # a realistic Wazuh-wrapped output line
        sample_line = f"{self.WAZUH_OUTPUT_PREFIX} {{\"event\":\"high_cpu\",\"cpu_percent\":94}}"
        assert pm_text in sample_line, (
            f"Prematch {pm_text!r} not found in sample output line: {sample_line!r}"
        )


# ===========================================================================
# Phase 3 — Wazuh rule XML structure
# ===========================================================================
class TestWazuhRuleXML:
    """cy_cust_rules.xml contains rules 101004-101007 with correct attributes."""

    @pytest.fixture(scope="class")
    def rule_map(self):
        assert RULES_FILE.exists(), f"Rules file missing: {RULES_FILE}"
        tree = ET.parse(RULES_FILE)
        root = tree.getroot()
        return {r.get("id"): r for r in root.iter("rule")}

    def test_rule_101004_exists(self, rule_map):
        assert "101004" in rule_map, "Rule 101004 (high_cpu) not found in cy_cust_rules.xml"

    def test_rule_101005_exists(self, rule_map):
        assert "101005" in rule_map, "Rule 101005 (high_disk) not found"

    def test_rule_101006_exists(self, rule_map):
        assert "101006" in rule_map, "Rule 101006 (high_memory) not found"

    def test_rule_101007_exists(self, rule_map):
        assert "101007" in rule_map, "Rule 101007 (sustained breach) not found"

    def test_rule_101004_level(self, rule_map):
        assert int(rule_map["101004"].get("level", 0)) == 7

    def test_rule_101005_level(self, rule_map):
        assert int(rule_map["101005"].get("level", 0)) == 7

    def test_rule_101006_level(self, rule_map):
        assert int(rule_map["101006"].get("level", 0)) == 7

    def test_rule_101007_level_higher(self, rule_map):
        """Sustained breach rule is severity level 10 (escalated)."""
        assert int(rule_map["101007"].get("level", 0)) == 10

    def test_threshold_rules_decoded_as_resource_check(self, rule_map):
        for rid in ("101004", "101005", "101006"):
            decoded = rule_map[rid].findtext("decoded_as") or ""
            assert "cy360-resource-check" in decoded, \
                f"Rule {rid} decoded_as does not reference cy360-resource-check decoder"

    def test_rules_have_descriptions(self, rule_map):
        for rid in ("101004", "101005", "101006", "101007"):
            desc = rule_map[rid].findtext("description") or ""
            assert len(desc) > 10, f"Rule {rid} has no meaningful description"

    def test_rules_in_resource_monitor_group(self, rule_map):
        for rid in ("101004", "101005", "101006", "101007"):
            group = rule_map[rid].findtext("group") or ""
            assert "resource_monitor" in group, \
                f"Rule {rid} not in resource_monitor group: {group!r}"

    def test_sustained_rule_references_threshold_rules(self, rule_map):
        """Rule 101007 must have if_sid referencing 101004, 101005, and 101006."""
        if_sid = rule_map["101007"].findtext("if_sid") or ""
        for dep in ("101004", "101005", "101006"):
            assert dep in if_sid, \
                f"Rule 101007 if_sid does not reference {dep}: {if_sid!r}"

    def test_sustained_rule_has_timeframe(self, rule_map):
        tf = rule_map["101007"].findtext("timeframe")
        assert tf is not None and int(tf) > 0, \
            "Rule 101007 missing or invalid timeframe"

    def test_sustained_rule_has_frequency(self, rule_map):
        freq = rule_map["101007"].findtext("frequency")
        assert freq is not None and int(freq) >= 3, \
            "Rule 101007 frequency should be ≥3"

    def test_cpu_rule_matches_high_cpu_event(self, rule_map):
        field = rule_map["101004"].findtext("field") or ""
        assert "high_cpu" in field, \
            f"Rule 101004 field element does not match 'high_cpu': {field!r}"

    def test_disk_rule_matches_high_disk_event(self, rule_map):
        field = rule_map["101005"].findtext("field") or ""
        assert "high_disk" in field, \
            f"Rule 101005 field element does not match 'high_disk': {field!r}"

    def test_memory_rule_matches_high_memory_event(self, rule_map):
        field = rule_map["101006"].findtext("field") or ""
        assert "high_memory" in field, \
            f"Rule 101006 field element does not match 'high_memory': {field!r}"


# ===========================================================================
# Phase 4 — Correlator CR-056 unit tests
# ===========================================================================
class TestCR056Correlator:
    """HighResourceUtilization correlation rule fires correctly."""

    rule = HighResourceUtilization()

    def test_positive_two_cpu_alerts_fire(self):
        alerts = [
            _make_alert(rule_id="101004", rule_desc="CyCentra 360: High CPU utilization 94% on web01"),
            _make_alert(rule_id="101004", rule_desc="CyCentra 360: High CPU utilization 96% on web01"),
        ]
        assert self.rule.match(alerts) is not None

    def test_positive_two_disk_alerts_fire(self):
        alerts = [
            _make_alert(rule_id="101005", rule_desc="CyCentra 360: High disk utilization 87% on db01"),
            _make_alert(rule_id="101005", rule_desc="CyCentra 360: High disk utilization 89% on db01"),
        ]
        assert self.rule.match(alerts) is not None

    def test_positive_two_memory_alerts_fire(self):
        alerts = [
            _make_alert(rule_id="101006", rule_desc="CyCentra 360: High memory utilization 92% on app01"),
            _make_alert(rule_id="101006", rule_desc="CyCentra 360: High memory utilization 93% on app01"),
        ]
        assert self.rule.match(alerts) is not None

    def test_positive_sustained_rule_id_fires(self):
        """The level-10 aggregator rule_id 101007 also triggers CR-056."""
        alerts = [
            _make_alert(rule_id="101007",
                        rule_desc="CyCentra 360: Sustained resource utilization breach on host1"),
            _make_alert(rule_id="101007",
                        rule_desc="CyCentra 360: Sustained resource utilization breach on host1"),
        ]
        assert self.rule.match(alerts) is not None

    def test_positive_keyword_match_without_rule_id(self):
        """Keyword match works even if rule_id is not a resource rule ID."""
        alerts = [
            _make_alert(rule_id="999", rule_desc="high cpu utilization alert on host1"),
            _make_alert(rule_id="999", rule_desc="high disk utilization alert on host1"),
        ]
        assert self.rule.match(alerts) is not None

    def test_positive_mixed_cpu_and_disk(self):
        """CPU + Disk alerts together label both resource types in detail."""
        alerts = [
            _make_alert(rule_id="101004", rule_desc="CyCentra 360: High CPU utilization 93% on host1"),
            _make_alert(rule_id="101005", rule_desc="CyCentra 360: High disk utilization 88% on host1"),
        ]
        result = self.rule.match(alerts)
        assert result is not None
        assert "CPU" in result["detail"]
        assert "Disk" in result["detail"]

    def test_positive_mixed_cpu_memory_disk(self):
        """All three resource types labeled in detail when all three fire."""
        alerts = [
            _make_alert(rule_id="101004", rule_desc="CyCentra 360: High CPU utilization 94% on host1"),
            _make_alert(rule_id="101005", rule_desc="CyCentra 360: High disk utilization 88% on host1"),
            _make_alert(rule_id="101006", rule_desc="CyCentra 360: High memory utilization 91% on host1"),
        ]
        result = self.rule.match(alerts)
        assert result is not None
        for label in ("CPU", "Disk", "Memory"):
            assert label in result["detail"], f"Expected {label!r} in detail: {result['detail']}"

    def test_negative_single_alert_does_not_fire(self):
        """One resource alert is not enough — requires 2+."""
        assert self.rule.match([
            _make_alert(rule_id="101004",
                        rule_desc="CyCentra 360: High CPU utilization 91% on host1"),
        ]) is None

    def test_negative_empty_list(self):
        assert self.rule.match([]) is None

    def test_negative_unrelated_alerts(self):
        assert self.rule.match([
            _make_alert(rule_desc="SSH login failed for root"),
            _make_alert(rule_desc="Failed password for admin from 1.2.3.4"),
        ]) is None

    def test_result_has_key_alert_ids(self):
        alerts = [
            _make_alert(wazuh_id="w100", rule_id="101004",
                        rule_desc="CyCentra 360: High CPU utilization 94% on host1"),
            _make_alert(wazuh_id="w101", rule_id="101005",
                        rule_desc="CyCentra 360: High disk utilization 88% on host1"),
        ]
        result = self.rule.match(alerts)
        assert result is not None
        assert "key_alert_ids" in result
        assert len(result["key_alert_ids"]) >= 1

    def test_result_confidence_is_0_80(self):
        alerts = [
            _make_alert(rule_id="101004", rule_desc="CyCentra 360: High CPU utilization 94%"),
            _make_alert(rule_id="101006", rule_desc="CyCentra 360: High memory utilization 92%"),
        ]
        result = self.rule.match(alerts)
        assert result is not None
        assert result["confidence"] == 0.80

    def test_result_confidence_in_range(self):
        alerts = [
            _make_alert(rule_id="101004", rule_desc="CyCentra 360: High CPU utilization 94%"),
            _make_alert(rule_id="101004", rule_desc="CyCentra 360: High CPU utilization 96%"),
        ]
        result = self.rule.match(alerts)
        assert result is not None
        assert 0.0 <= result["confidence"] <= 1.0

    def test_detail_contains_breach_count(self):
        """Detail must reference how many times the threshold was breached."""
        alerts = [
            _make_alert(rule_id="101004", rule_desc="CyCentra 360: High CPU utilization 94%"),
            _make_alert(rule_id="101004", rule_desc="CyCentra 360: High CPU utilization 95%"),
            _make_alert(rule_id="101004", rule_desc="CyCentra 360: High CPU utilization 97%"),
        ]
        result = self.rule.match(alerts)
        assert result is not None
        assert "3" in result["detail"] or "three" in result["detail"].lower(), \
            f"Detail does not mention breach count: {result['detail']}"

    def test_severity_is_medium(self):
        assert self.rule.severity == "medium"

    def test_tactics_contain_impact(self):
        assert "Impact" in self.rule.tactics

    def test_rule_id_is_cr056(self):
        assert self.rule.rule_id == "CR-056"


# ===========================================================================
# Phase 5 — Full pipeline simulation
# ===========================================================================
class TestFullPipeline:
    """
    End-to-end: raw Wazuh alert dict → normaliser → normalised alert →
    correlator → incident detail contains resource context.
    """

    def test_normaliser_passes_cpu_alert(self):
        """A level-7 high_cpu alert survives the normaliser (not dropped)."""
        raw = _raw_wazuh_alert(
            rule_id=101004,
            rule_desc="CyCentra 360: High CPU utilization 94% on web01 — threshold 90%",
            level=7,
            agent_name="web01",
        )
        normalised = normalise(raw)
        assert normalised is not None, "Normaliser unexpectedly dropped the resource alert"

    def test_normaliser_passes_disk_alert(self):
        raw = _raw_wazuh_alert(
            rule_id=101005,
            rule_desc="CyCentra 360: High disk utilization 88% on db01 — threshold 85%",
            level=7,
            agent_name="db01",
        )
        assert normalise(raw) is not None

    def test_normaliser_passes_memory_alert(self):
        raw = _raw_wazuh_alert(
            rule_id=101006,
            rule_desc="CyCentra 360: High memory utilization 92% on app01 — threshold 90%",
            level=7,
            agent_name="app01",
        )
        assert normalise(raw) is not None

    def test_normaliser_passes_sustained_alert(self):
        """Sustained breach rule (level 10) also survives normaliser."""
        raw = _raw_wazuh_alert(
            rule_id=101007,
            rule_desc="CyCentra 360: Sustained resource utilization breach on host1",
            level=10,
            agent_name="host1",
        )
        assert normalise(raw) is not None

    def test_normaliser_preserves_rule_id(self):
        raw = _raw_wazuh_alert(rule_id=101004,
                               rule_desc="CyCentra 360: High CPU utilization 94%")
        n = normalise(raw)
        assert n is not None
        assert str(n["rule_id"]) == "101004"

    def test_normaliser_preserves_agent_name(self):
        raw = _raw_wazuh_alert(rule_id=101004,
                               rule_desc="CyCentra 360: High CPU utilization 94%",
                               agent_name="my-server")
        n = normalise(raw)
        assert n is not None
        assert n["agent_name"] == "my-server"

    def test_pipeline_two_resource_alerts_fire_correlator(self):
        """
        Two normalised resource alerts from the same host trigger CR-056.
        Simulates the full flow: raw Wazuh events → normalise → correlate.
        """
        rule = HighResourceUtilization()

        raw1 = _raw_wazuh_alert(
            rule_id=101004,
            rule_desc="CyCentra 360: High CPU utilization 94% on host1 — threshold 90%",
            level=7, agent_name="host1",
        )
        raw2 = _raw_wazuh_alert(
            rule_id=101005,
            rule_desc="CyCentra 360: High disk utilization 87% on host1 — threshold 85%",
            level=7, agent_name="host1",
        )

        a1 = normalise(raw1)
        a2 = normalise(raw2)
        assert a1 is not None and a2 is not None, "Normaliser dropped one of the resource alerts"

        result = rule.match([a1, a2])
        assert result is not None, "CR-056 did not fire on two normalised resource alerts"
        assert result["confidence"] == 0.80
        assert "CPU" in result["detail"] or "Disk" in result["detail"]

    def test_pipeline_one_alert_does_not_fire_correlator(self):
        """A single resource alert does not create a correlated incident."""
        rule = HighResourceUtilization()
        raw = _raw_wazuh_alert(
            rule_id=101004,
            rule_desc="CyCentra 360: High CPU utilization 94% on host1",
            level=7,
        )
        a = normalise(raw)
        assert a is not None
        assert rule.match([a]) is None

    def test_pipeline_unrelated_alerts_do_not_fire(self):
        """Non-resource alerts going through the full pipeline do not trigger CR-056."""
        rule = HighResourceUtilization()
        raw1 = _raw_wazuh_alert(rule_id=5710,
                                rule_desc="sshd: Failed login attempt from 1.2.3.4",
                                level=5)
        raw2 = _raw_wazuh_alert(rule_id=5711,
                                rule_desc="sshd: Authentication failed for user admin",
                                level=5)
        a1 = normalise(raw1)
        a2 = normalise(raw2)
        # May be None if level < MIN_RULE_LEVEL, but neither should trigger CR-056
        alerts = [a for a in [a1, a2] if a is not None]
        result = rule.match(alerts) if len(alerts) >= 2 else None
        assert result is None

    def test_pipeline_script_output_becomes_valid_alert(self):
        """
        Simulates the complete end-to-end path:
        script output → Wazuh wraps in rule 101004 → normalise → correlate.
        """
        if not LINUX_SCRIPT.exists() or sys.platform == "win32":
            pytest.skip("bash script not available on this platform")

        # Force the script to emit at least a high_cpu event
        events = _run_script_forced()
        assert len(events) >= 1, "Script produced no events at threshold=0"

        # Pick any emitted event and simulate what Wazuh would produce
        ev = events[0]
        event_to_rule = {"high_cpu": 101004, "high_disk": 101005, "high_memory": 101006}
        rule_id = event_to_rule.get(ev["event"], 101004)
        desc = (
            f"CyCentra 360: High {ev['event'].split('_')[1]} utilization "
            f"{list(ev.values())[1]}% on {ev['host']} — threshold {ev['threshold']}%"
        )

        raw1 = _raw_wazuh_alert(rule_id=rule_id, rule_desc=desc, level=7,
                                agent_name=ev["host"])
        # Second alert (same type, same host)
        raw2 = _raw_wazuh_alert(rule_id=rule_id, rule_desc=desc, level=7,
                                agent_name=ev["host"])

        a1 = normalise(raw1)
        a2 = normalise(raw2)
        assert a1 is not None and a2 is not None

        result = HighResourceUtilization().match([a1, a2])
        assert result is not None, (
            f"Full pipeline failed to fire CR-056 for event: {ev}"
        )
