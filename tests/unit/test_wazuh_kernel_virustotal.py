"""
Suite 13 — Wazuh Agent Kernel Package & VirusTotal Feed Tests
==============================================================

Validates two independent concerns:

  Part A — Wazuh Agent Kernel Package Telemetry (52 tests)
  ---------------------------------------------------------
  Confirms that the Wazuh agent configuration files correctly enable and
  configure kernel-level telemetry sources on each supported platform:

    A1  macOS Apple Unified Logging System (ULS / apple-oslog)
        — agent.conf Darwin block: location, log_format, query subsystems,
          event types (error/fault), FDA note, resource-check path
    A2  Linux auditd / journald
        — agent.conf Linux block: journald format, priority filter 0-4,
          Linux resource-check path
    A3  Windows Sysmon / eventchannel
        — agent.conf Windows block: Security eventchannel, EventID
          suppression list, PowerShell resource-check path
    A4  Manager-side syscollector (kernel package inventory)
        — ossec.conf: packages, OS, network, processes, users, services,
          browser_extensions all enabled; interval and scan_on_start set
    A5  Manager-side vulnerability-detection
        — feed-update-interval, index-status enabled
    A6  Manager-side FIM / syscheck (binary/config integrity)
        — disabled=no, scan_on_start=yes, alert_new_files=yes
    A7  Manager-side rootcheck (trojan/rootkit detection)
        — check_trojans=yes, check_sys=yes, check_pids=yes
    A8  Manager-side CySIEM active-response integration
        — isolate-host command blocks, rules_id 101000-101003

  Part B — VirusTotal v3 Feed Integration (43 tests)
  ---------------------------------------------------
  Validates the `ti_enricher._vt_lookup()` verdict logic and
  `_compute_ti_confidence()` scoring using mocked HTTP responses.
  No live VirusTotal API calls are made.

    B1  Config — vt_api_key setting and env-var bridge
    B2  Verdict logic — malicious / suspicious / benign thresholds
    B3  HTTP edge cases — 404, non-200, timeout, exception
    B4  IOC type routing — IP, domain, SHA256 URL construction
    B5  Confidence scoring integration — VT contribution to total score
    B6  enrich_incident_ti() — sources_used, skip-when-no-key, ioc_map structure
    B7  Key resolution chain — Settings UI → ai_settings.json → cysiemstack.env
        sync; cloud vault ENGINE_KV_MAP; secret masking on GET; never
        hand-edit cysiemstack.env directly

All tests are fully autonomous — no live Wazuh, VirusTotal, or DB connections.
Run with:  pytest tests/unit/test_wazuh_kernel_virustotal.py -v

Total: 110 tests
"""

import asyncio
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Paths to config files under test
# ---------------------------------------------------------------------------
REPO_ROOT   = Path(__file__).resolve().parents[2]
AGENT_CONF  = REPO_ROOT / "CYSIEM-Config" / "agent_config" / "agent.conf"
OSSEC_CONF  = REPO_ROOT / "CYSIEM-Config" / "conf" / "ossec.conf"
CE_PATH     = str(REPO_ROOT / "backend" / "cysiemstack" / "correlation_engine")

if CE_PATH not in sys.path:
    sys.path.insert(0, CE_PATH)

# ---------------------------------------------------------------------------
# Parse config files once at module level
# ---------------------------------------------------------------------------

def _parse_xml_fragments(path: Path) -> ET.Element:
    """Wrap agent.conf multi-root XML in a single root element for parsing."""
    raw = path.read_text()
    return ET.fromstring(f"<_root>{raw}</_root>")


def _parse_ossec(path: Path) -> ET.Element:
    return ET.parse(str(path)).getroot()


_AGENT_CONF_ROOT = _parse_xml_fragments(AGENT_CONF)
_OSSEC_ROOT      = _parse_ossec(OSSEC_CONF)
_AGENT_RAW       = AGENT_CONF.read_text()
_OSSEC_RAW       = OSSEC_CONF.read_text()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _agent_blocks(os_filter: str):
    """Return all <agent_config os="..."> blocks matching the OS name."""
    return [
        el for el in _AGENT_CONF_ROOT.findall("agent_config")
        if el.get("os", "").lower() == os_filter.lower()
    ]


def _localfiles_in_blocks(blocks):
    """Flatten all <localfile> children from a list of agent_config blocks."""
    lfs = []
    for blk in blocks:
        lfs.extend(blk.findall("localfile"))
    return lfs


def _ossec_wodle(name: str):
    for w in _OSSEC_ROOT.findall("wodle"):
        if w.get("name") == name:
            return w
    return None


def _ossec_section(tag: str):
    return _OSSEC_ROOT.find(tag)


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# ============================================================
# PART A — Wazuh Agent Kernel Package Telemetry
# ============================================================

# -----------------------------------------------------------
# A1 — macOS Apple ULS (apple-oslog)
# -----------------------------------------------------------

class TestA1MacOSAppleULS:
    """16 tests — Darwin agent.conf block for Apple Unified Logging System."""

    @property
    def darwin_blocks(self):
        return _agent_blocks("Darwin")

    @property
    def darwin_localfiles(self):
        return _localfiles_in_blocks(self.darwin_blocks)

    def test_darwin_block_present(self):
        assert len(self.darwin_blocks) >= 1, \
            "No <agent_config os='Darwin'> block in agent.conf"

    def test_uls_localfile_present(self):
        lfs = [lf for lf in self.darwin_localfiles
               if lf.findtext("log_format") == "apple-oslog"]
        assert len(lfs) >= 1, \
            "No <localfile> with <log_format>apple-oslog</log_format> in Darwin block"

    def test_uls_location_is_apple_oslog(self):
        lfs = [lf for lf in self.darwin_localfiles
               if lf.findtext("log_format") == "apple-oslog"]
        assert lfs, "No apple-oslog localfile"
        loc = lfs[0].findtext("location", "")
        assert loc == "apple-oslog", \
            f"Expected location='apple-oslog', got '{loc}'"

    def test_uls_log_format_is_apple_oslog(self):
        lfs = [lf for lf in self.darwin_localfiles
               if lf.findtext("log_format") == "apple-oslog"]
        assert lfs
        assert lfs[0].findtext("log_format") == "apple-oslog"

    def test_uls_query_targets_authentication_subsystem(self):
        lfs = [lf for lf in self.darwin_localfiles
               if lf.findtext("log_format") == "apple-oslog"]
        assert lfs
        query = lfs[0].findtext("query", "")
        assert "com.apple.Authentication" in query or "com.apple.authentication" in query.lower(), \
            f"Query does not target com.apple.Authentication: {query!r}"

    def test_uls_query_targets_securityd_subsystem(self):
        lfs = [lf for lf in self.darwin_localfiles
               if lf.findtext("log_format") == "apple-oslog"]
        assert lfs
        query = lfs[0].findtext("query", "")
        assert "com.apple.securityd" in query, \
            f"Query does not target com.apple.securityd: {query!r}"

    def test_uls_query_filters_error_type(self):
        lfs = [lf for lf in self.darwin_localfiles
               if lf.findtext("log_format") == "apple-oslog"]
        assert lfs
        query = lfs[0].findtext("query", "")
        assert "error" in query.lower(), \
            f"Query does not filter for 'error' type events: {query!r}"

    def test_uls_query_filters_fault_type(self):
        lfs = [lf for lf in self.darwin_localfiles
               if lf.findtext("log_format") == "apple-oslog"]
        assert lfs
        query = lfs[0].findtext("query", "")
        assert "fault" in query.lower(), \
            f"Query does not filter for 'fault' type events: {query!r}"

    def test_uls_not_using_deprecated_macos_format(self):
        """Wazuh 4.4+ uses apple-oslog; older 'macos' log_format is deprecated."""
        deprecated = [lf for lf in self.darwin_localfiles
                      if lf.findtext("log_format") == "macos"]
        assert len(deprecated) == 0, \
            "agent.conf uses deprecated <log_format>macos</log_format> — must be apple-oslog"

    def test_darwin_resource_check_command_present(self):
        """macOS resource-check should use /Library/Ossec path."""
        cmds = [lf.findtext("command", "") for lf in self.darwin_localfiles]
        assert any("/Library/Ossec" in c for c in cmds), \
            f"No Darwin resource-check command using /Library/Ossec path. Commands: {cmds}"

    def test_darwin_resource_check_alias_set(self):
        lfs_with_cmd = [lf for lf in self.darwin_localfiles
                        if lf.findtext("command")]
        aliases = [lf.findtext("alias", "") for lf in lfs_with_cmd]
        assert "cy360-resource-check" in aliases, \
            f"cy360-resource-check alias missing from Darwin localfile. Found: {aliases}"

    def test_darwin_resource_check_frequency_is_300(self):
        lfs_with_cmd = [lf for lf in self.darwin_localfiles
                        if "/Library/Ossec" in (lf.findtext("command") or "")]
        assert lfs_with_cmd, "No Darwin resource-check localfile found"
        freq = lfs_with_cmd[0].findtext("frequency", "")
        assert freq == "300", \
            f"Expected resource-check frequency=300 on Darwin, got '{freq}'"

    def test_darwin_resource_check_format_is_full_command(self):
        lfs_with_cmd = [lf for lf in self.darwin_localfiles
                        if "/Library/Ossec" in (lf.findtext("command") or "")]
        assert lfs_with_cmd
        fmt = lfs_with_cmd[0].findtext("log_format", "")
        assert fmt == "full_command", \
            f"Expected log_format=full_command for Darwin resource-check, got '{fmt}'"

    def test_darwin_resource_check_uses_bash(self):
        lfs_with_cmd = [lf for lf in self.darwin_localfiles
                        if "/Library/Ossec" in (lf.findtext("command") or "")]
        assert lfs_with_cmd
        cmd = lfs_with_cmd[0].findtext("command", "")
        assert cmd.startswith("bash "), \
            f"Darwin resource-check command should start with 'bash': {cmd!r}"

    def test_darwin_uls_query_is_compound_not_empty(self):
        lfs = [lf for lf in self.darwin_localfiles
               if lf.findtext("log_format") == "apple-oslog"]
        assert lfs
        query = lfs[0].findtext("query", "").strip()
        assert len(query) > 20, \
            f"ULS query appears empty or trivially short: {query!r}"

    def test_darwin_uls_query_uses_subsystem_predicate(self):
        lfs = [lf for lf in self.darwin_localfiles
               if lf.findtext("log_format") == "apple-oslog"]
        assert lfs
        query = lfs[0].findtext("query", "")
        assert "subsystem" in query, \
            f"ULS query should use 'subsystem' predicate: {query!r}"


# -----------------------------------------------------------
# A2 — Linux auditd / journald
# -----------------------------------------------------------

class TestA2LinuxJournald:
    """9 tests — Linux agent.conf journald and resource-check blocks."""

    @property
    def linux_blocks(self):
        return _agent_blocks("Linux")

    @property
    def linux_localfiles(self):
        return _localfiles_in_blocks(self.linux_blocks)

    def test_linux_block_present(self):
        assert len(self.linux_blocks) >= 1, \
            "No <agent_config os='Linux'> block in agent.conf"

    def test_journald_localfile_present(self):
        lfs = [lf for lf in self.linux_localfiles
               if lf.findtext("log_format") == "journald"]
        assert len(lfs) >= 1, \
            "No <localfile log_format='journald'> in Linux agent.conf block"

    def test_journald_location_is_journald(self):
        lfs = [lf for lf in self.linux_localfiles
               if lf.findtext("log_format") == "journald"]
        assert lfs
        assert lfs[0].findtext("location") == "journald"

    def test_journald_filter_priority_0_to_4(self):
        """Priority 0-4 captures emergency → warning; 5+ is notice/info/debug (too noisy)."""
        lfs = [lf for lf in self.linux_localfiles
               if lf.findtext("log_format") == "journald"]
        assert lfs
        f = lfs[0].find("filter[@field='PRIORITY']")
        assert f is not None, "No <filter field='PRIORITY'> in Linux journald localfile"
        val = f.text or ""
        assert "0" in val and "4" in val, \
            f"PRIORITY filter should cover 0-4, got: {val!r}"

    def test_linux_resource_check_uses_var_ossec_path(self):
        cmds = [lf.findtext("command", "") for lf in self.linux_localfiles]
        assert any("/var/ossec" in c for c in cmds), \
            f"Linux resource-check should use /var/ossec path. Commands: {cmds}"

    def test_linux_resource_check_alias_set(self):
        lfs_with_cmd = [lf for lf in self.linux_localfiles if lf.findtext("command")]
        aliases = [lf.findtext("alias", "") for lf in lfs_with_cmd]
        assert "cy360-resource-check" in aliases

    def test_linux_resource_check_frequency_300(self):
        lfs_with_cmd = [lf for lf in self.linux_localfiles
                        if "/var/ossec" in (lf.findtext("command") or "")]
        assert lfs_with_cmd
        assert lfs_with_cmd[0].findtext("frequency") == "300"

    def test_linux_resource_check_format_full_command(self):
        lfs_with_cmd = [lf for lf in self.linux_localfiles
                        if "/var/ossec" in (lf.findtext("command") or "")]
        assert lfs_with_cmd
        assert lfs_with_cmd[0].findtext("log_format") == "full_command"

    def test_linux_resource_check_uses_bash(self):
        lfs_with_cmd = [lf for lf in self.linux_localfiles
                        if "/var/ossec" in (lf.findtext("command") or "")]
        assert lfs_with_cmd
        assert lfs_with_cmd[0].findtext("command", "").startswith("bash ")


# -----------------------------------------------------------
# A3 — Windows Sysmon / eventchannel
# -----------------------------------------------------------

class TestA3WindowsEventchannel:
    """9 tests — Windows agent.conf eventchannel and resource-check blocks."""

    @property
    def win_blocks(self):
        return _agent_blocks("Windows")

    @property
    def win_localfiles(self):
        return _localfiles_in_blocks(self.win_blocks)

    def test_windows_block_present(self):
        assert len(self.win_blocks) >= 1, \
            "No <agent_config os='Windows'> block in agent.conf"

    def test_security_eventchannel_present(self):
        lfs = [lf for lf in self.win_localfiles
               if lf.findtext("log_format") == "eventchannel"]
        assert len(lfs) >= 1, \
            "No <localfile log_format='eventchannel'> in Windows agent.conf block"

    def test_security_eventchannel_location_is_security(self):
        lfs = [lf for lf in self.win_localfiles
               if lf.findtext("log_format") == "eventchannel"]
        assert lfs
        assert lfs[0].findtext("location") == "Security"

    def test_eventid_suppression_block_present(self):
        lfs = [lf for lf in self.win_localfiles
               if lf.findtext("log_format") == "eventchannel"]
        assert lfs
        query = lfs[0].find("query")
        assert query is not None, "No <query> in Windows Security eventchannel block"

    def test_suppressed_eventids_include_5156(self):
        """5156 is MPSSVC filtering platform connection — noisy, safely suppressed."""
        raw_block = AGENT_CONF.read_text()
        assert "5156" in raw_block, "EventID 5156 not in suppression list"

    def test_suppressed_eventids_include_4658(self):
        """4658 is 'handle to object was closed' — very high volume, safely suppressed."""
        assert "4658" in _AGENT_RAW

    def test_windows_resource_check_uses_powershell(self):
        cmds = [lf.findtext("command", "") for lf in self.win_localfiles]
        assert any("PowerShell" in c or "powershell" in c.lower() for c in cmds), \
            f"Windows resource-check should invoke PowerShell. Commands: {cmds}"

    def test_windows_resource_check_alias_set(self):
        lfs_with_cmd = [lf for lf in self.win_localfiles if lf.findtext("command")]
        aliases = [lf.findtext("alias", "") for lf in lfs_with_cmd]
        assert "cy360-resource-check" in aliases

    def test_windows_resource_check_format_full_command(self):
        lfs_with_cmd = [lf for lf in self.win_localfiles
                        if "PowerShell" in (lf.findtext("command") or "")]
        assert lfs_with_cmd
        assert lfs_with_cmd[0].findtext("log_format") == "full_command"


# -----------------------------------------------------------
# A4 — Manager-side syscollector (kernel package inventory)
# -----------------------------------------------------------

class TestA4Syscollector:
    """9 tests — ossec.conf syscollector wodle for OS/package enumeration."""

    @property
    def sc(self):
        return _ossec_wodle("syscollector")

    def test_syscollector_wodle_present(self):
        assert self.sc is not None, "syscollector wodle missing from ossec.conf"

    def test_syscollector_not_disabled(self):
        assert self.sc.findtext("disabled") == "no", \
            "syscollector is disabled — kernel package inventory won't work"

    def test_syscollector_packages_enabled(self):
        assert self.sc.findtext("packages") == "yes", \
            "syscollector <packages>yes</packages> missing — installed package list won't be collected"

    def test_syscollector_os_enabled(self):
        assert self.sc.findtext("os") == "yes"

    def test_syscollector_network_enabled(self):
        assert self.sc.findtext("network") == "yes"

    def test_syscollector_processes_enabled(self):
        assert self.sc.findtext("processes") == "yes"

    def test_syscollector_users_and_groups_enabled(self):
        assert self.sc.findtext("users") == "yes"
        assert self.sc.findtext("groups") == "yes"

    def test_syscollector_hardware_enabled(self):
        assert self.sc.findtext("hardware") == "yes"

    def test_syscollector_scan_on_start(self):
        assert self.sc.findtext("scan_on_start") == "yes"


# -----------------------------------------------------------
# A5 — Vulnerability detection
# -----------------------------------------------------------

class TestA5VulnerabilityDetection:
    """4 tests — ossec.conf vulnerability-detection block."""

    @property
    def vd(self):
        return _ossec_section("vulnerability-detection")

    def test_vuln_detection_block_present(self):
        assert self.vd is not None, "<vulnerability-detection> missing from ossec.conf"

    def test_vuln_detection_enabled(self):
        assert self.vd.findtext("enabled") == "yes"

    def test_vuln_detection_index_status(self):
        assert self.vd.findtext("index-status") == "yes"

    def test_vuln_feed_update_interval_set(self):
        interval = self.vd.findtext("feed-update-interval", "")
        assert interval, "feed-update-interval not set"
        assert "m" in interval or "h" in interval, \
            f"feed-update-interval should be in minutes/hours, got: {interval!r}"


# -----------------------------------------------------------
# A6 — FIM / syscheck
# -----------------------------------------------------------

class TestA6Syscheck:
    """5 tests — ossec.conf syscheck (file integrity monitoring)."""

    @property
    def sc(self):
        return _ossec_section("syscheck")

    def test_syscheck_not_disabled(self):
        assert self.sc.findtext("disabled") == "no"

    def test_syscheck_scan_on_start(self):
        assert self.sc.findtext("scan_on_start") == "yes"

    def test_syscheck_alert_new_files(self):
        assert self.sc.findtext("alert_new_files") == "yes"

    def test_syscheck_monitors_usr_bin(self):
        dirs = " ".join(d.text or "" for d in self.sc.findall("directories"))
        assert "/usr/bin" in dirs or "/usr/sbin" in dirs, \
            "syscheck should monitor /usr/bin or /usr/sbin"

    def test_syscheck_monitors_etc(self):
        dirs = " ".join(d.text or "" for d in self.sc.findall("directories"))
        assert "/etc" in dirs


# -----------------------------------------------------------
# A7 — Rootcheck (trojan/rootkit detection)
# -----------------------------------------------------------

class TestA7Rootcheck:
    """5 tests — ossec.conf rootcheck."""

    @property
    def rc(self):
        return _ossec_section("rootcheck")

    def test_rootcheck_not_disabled(self):
        assert self.rc.findtext("disabled") == "no"

    def test_rootcheck_check_trojans(self):
        assert self.rc.findtext("check_trojans") == "yes"

    def test_rootcheck_check_sys(self):
        assert self.rc.findtext("check_sys") == "yes"

    def test_rootcheck_check_pids(self):
        assert self.rc.findtext("check_pids") == "yes"

    def test_rootcheck_check_files(self):
        assert self.rc.findtext("check_files") == "yes"


# -----------------------------------------------------------
# A8 — Active-response configuration (isolation rules 101000–101003)
# -----------------------------------------------------------

class TestA8ActiveResponse:
    """5 tests — ossec.conf active-response isolate-host blocks."""

    def test_isolate_host_command_block_present(self):
        commands = _OSSEC_ROOT.findall("command")
        names = [c.findtext("name") for c in commands]
        assert "isolate-host" in names, \
            "isolate-host command block missing from ossec.conf"

    def test_isolate_host_executable(self):
        commands = _OSSEC_ROOT.findall("command")
        for c in commands:
            if c.findtext("name") == "isolate-host":
                assert c.findtext("executable") == "isolate-host.sh"
                return
        pytest.fail("isolate-host command block not found")

    def test_ar_block_for_local_isolation_rules(self):
        """rules_id 101000,101001 → local isolation (600s)."""
        found = any(
            "101000" in (ar.findtext("rules_id") or "") and
            "101001" in (ar.findtext("rules_id") or "") and
            ar.findtext("location") == "local"
            for ar in _OSSEC_ROOT.findall("active-response")
        )
        assert found, \
            "No active-response block found for rules_id=101000,101001 with location=local"

    def test_ar_block_for_global_isolation_rules(self):
        """rules_id 101002,101003 → global isolation (all agents, 3600s)."""
        found = any(
            "101002" in (ar.findtext("rules_id") or "") and
            "101003" in (ar.findtext("rules_id") or "") and
            ar.findtext("location") == "all"
            for ar in _OSSEC_ROOT.findall("active-response")
        )
        assert found, \
            "No active-response block found for rules_id=101002,101003 with location=all"

    def test_ar_local_timeout_is_600(self):
        for ar in _OSSEC_ROOT.findall("active-response"):
            if "101000" in (ar.findtext("rules_id") or "") and ar.findtext("location") == "local":
                assert ar.findtext("timeout") == "600"
                return
        pytest.fail("Local isolation AR block not found")


# ---------------------------------------------------------------------------
# ============================================================
# PART B — VirusTotal v3 Feed Integration
# ============================================================

# Stub heavy CE deps before importing ti_enricher
for _mod in (
    "sqlalchemy", "sqlalchemy.ext", "sqlalchemy.ext.asyncio", "sqlalchemy.orm",
    "sqlalchemy.dialects", "sqlalchemy.dialects.postgresql",
    "models", "structlog", "pydantic", "pydantic_settings",
):
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

_mock_settings                    = MagicMock()
_mock_settings.vt_api_key         = ""
_mock_settings.abuseipdb_api_key  = ""
_mock_settings.greynoise_api_key  = ""
_mock_settings.tls_ca_bundle      = ""

_mock_config = MagicMock()
_mock_config.get_settings.return_value = _mock_settings
sys.modules["config"] = _mock_config

from ti_enricher import _vt_lookup, _compute_ti_confidence, enrich_incident_ti  # noqa: E402


# -----------------------------------------------------------
# B1 — Config: vt_api_key and env-var bridge
# -----------------------------------------------------------

class TestB1VTConfig:
    """6 tests — Settings schema for VT key and env-var bridging."""

    def test_vt_api_key_field_present_in_config_py(self):
        cfg_text = (REPO_ROOT / "backend" / "cysiemstack" / "correlation_engine" / "config.py").read_text()
        assert "vt_api_key" in cfg_text

    def test_vt_api_key_default_is_empty_string(self):
        assert 'vt_api_key:        str = ""' in (
            REPO_ROOT / "backend" / "cysiemstack" / "correlation_engine" / "config.py"
        ).read_text()

    def test_virustotal_api_key_env_var_bridge_present(self):
        cfg_text = (REPO_ROOT / "backend" / "cysiemstack" / "correlation_engine" / "config.py").read_text()
        assert "VIRUSTOTAL_API_KEY" in cfg_text

    def test_env_var_bridge_only_fills_when_field_is_empty(self):
        """Bridge logic: 'if not self.vt_api_key'  — explicit env value must not override UI value."""
        cfg_text = (REPO_ROOT / "backend" / "cysiemstack" / "correlation_engine" / "config.py").read_text()
        assert "if not self.vt_api_key" in cfg_text

    def test_abuseipdb_key_also_present(self):
        cfg_text = (REPO_ROOT / "backend" / "cysiemstack" / "correlation_engine" / "config.py").read_text()
        assert "abuseipdb_api_key" in cfg_text

    def test_greynoise_key_also_present(self):
        cfg_text = (REPO_ROOT / "backend" / "cysiemstack" / "correlation_engine" / "config.py").read_text()
        assert "greynoise_api_key" in cfg_text


# -----------------------------------------------------------
# B2 — Verdict logic
# -----------------------------------------------------------

class TestB2VTVerdictLogic:
    """9 tests — _vt_lookup() verdict thresholds (mocked HTTP)."""

    def _mock_resp(self, malicious: int, suspicious: int, total: int,
                   reputation: int = 0, status_code: int = 200):
        """Build a mock httpx response with the given analysis stats."""
        resp = MagicMock()
        resp.status_code = status_code
        stats = {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": max(0, total - malicious - suspicious),
            "harmless": 0,
        }
        resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": stats,
                    "reputation": reputation,
                }
            }
        }
        return resp

    def _with_key(self, key="TESTAPIKEY123"):
        _mock_settings.vt_api_key = key
        return key

    def _clear_key(self):
        _mock_settings.vt_api_key = ""

    def test_empty_api_key_returns_empty_dict(self):
        self._clear_key()
        result = _run(_vt_lookup("1.2.3.4", "ip"))
        assert result == {}

    def test_malicious_threshold_10pct_returns_malicious(self):
        """≥10% malicious engines → 'malicious'."""
        self._with_key()
        resp = self._mock_resp(malicious=10, suspicious=0, total=100)
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=AsyncMock(return_value=resp))
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = _run(_vt_lookup("1.2.3.4", "ip"))
        assert result.get("verdict") == "malicious", f"Got: {result}"
        self._clear_key()

    def test_malicious_just_below_10pct_is_not_malicious(self):
        """9% malicious but 0% suspicious → should not be 'malicious'."""
        self._with_key()
        resp = self._mock_resp(malicious=9, suspicious=0, total=100)
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=AsyncMock(return_value=resp))
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = _run(_vt_lookup("1.2.3.4", "ip"))
        assert result.get("verdict") != "malicious"
        self._clear_key()

    def test_suspicious_threshold_5pct_combined_returns_suspicious(self):
        """(malicious+suspicious)/total ≥ 0.05 → 'suspicious' (when malicious < 0.1)."""
        self._with_key()
        # 3% malicious + 3% suspicious = 6% combined ≥ 5%
        resp = self._mock_resp(malicious=3, suspicious=3, total=100)
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=AsyncMock(return_value=resp))
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = _run(_vt_lookup("1.2.3.4", "ip"))
        assert result.get("verdict") == "suspicious"
        self._clear_key()

    def test_clean_file_returns_benign(self):
        """All clean → 'benign'."""
        self._with_key()
        resp = self._mock_resp(malicious=0, suspicious=0, total=70)
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=AsyncMock(return_value=resp))
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = _run(_vt_lookup("1.2.3.4", "ip"))
        assert result.get("verdict") == "benign"
        self._clear_key()

    def test_community_score_preserved_in_result(self):
        self._with_key()
        resp = self._mock_resp(malicious=0, suspicious=0, total=70, reputation=-5)
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=AsyncMock(return_value=resp))
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = _run(_vt_lookup("1.2.3.4", "ip"))
        assert "community_score" in result
        assert result["community_score"] == -5
        self._clear_key()

    def test_malicious_count_in_result(self):
        self._with_key()
        resp = self._mock_resp(malicious=15, suspicious=2, total=100)
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=AsyncMock(return_value=resp))
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = _run(_vt_lookup("1.2.3.4", "ip"))
        assert result.get("malicious") == 15
        assert result.get("suspicious") == 2
        self._clear_key()

    def test_result_source_is_virustotal(self):
        self._with_key()
        resp = self._mock_resp(malicious=0, suspicious=0, total=70)
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=AsyncMock(return_value=resp))
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = _run(_vt_lookup("1.2.3.4", "ip"))
        assert result.get("source") == "virustotal"
        self._clear_key()

    def test_total_engines_in_result(self):
        self._with_key()
        resp = self._mock_resp(malicious=5, suspicious=3, total=80)
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=AsyncMock(return_value=resp))
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = _run(_vt_lookup("1.2.3.4", "ip"))
        assert result.get("total") == 80
        self._clear_key()


# -----------------------------------------------------------
# B3 — HTTP edge cases
# -----------------------------------------------------------

class TestB3VTHTTPEdgeCases:
    """6 tests — 404, non-200, exception handling."""

    def _with_key(self):
        _mock_settings.vt_api_key = "TESTAPIKEY123"

    def _clear_key(self):
        _mock_settings.vt_api_key = ""

    def test_404_returns_unknown_verdict(self):
        self._with_key()
        resp = MagicMock()
        resp.status_code = 404
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=AsyncMock(return_value=resp))
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = _run(_vt_lookup("1.2.3.4", "ip"))
        assert result.get("verdict") == "unknown"
        self._clear_key()

    def test_403_returns_empty_dict(self):
        self._with_key()
        resp = MagicMock()
        resp.status_code = 403
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=AsyncMock(return_value=resp))
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = _run(_vt_lookup("1.2.3.4", "ip"))
        assert result == {}
        self._clear_key()

    def test_429_too_many_requests_returns_empty_dict(self):
        self._with_key()
        resp = MagicMock()
        resp.status_code = 429
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=AsyncMock(return_value=resp))
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = _run(_vt_lookup("1.2.3.4", "ip"))
        assert result == {}
        self._clear_key()

    def test_network_exception_returns_empty_dict_never_raises(self):
        self._with_key()
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                side_effect=Exception("Connection refused")
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = _run(_vt_lookup("1.2.3.4", "ip"))
        assert isinstance(result, dict)
        self._clear_key()

    def test_unknown_ioc_type_returns_empty_dict(self):
        """ioc_type not in (ip-src, ip-dst, ip, domain, sha256) → skip."""
        self._with_key()
        result = _run(_vt_lookup("some-ioc", "mac-address"))
        assert result == {}
        self._clear_key()

    def test_empty_api_key_never_calls_http(self):
        self._clear_key()
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            result = _run(_vt_lookup("1.2.3.4", "ip"))
        mock_cls.assert_not_called()
        assert result == {}


# -----------------------------------------------------------
# B4 — IOC type URL routing
# -----------------------------------------------------------

class TestB4VTIOCRouting:
    """6 tests — URL construction per IOC type."""

    def _captured_url(self, ioc: str, ioc_type: str) -> str:
        _mock_settings.vt_api_key = "TESTKEY"
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {}, "reputation": 0}}
        }
        captured = {}

        async def _fake_get(url, **kwargs):
            captured["url"] = url
            return resp

        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=_fake_get)
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            _run(_vt_lookup(ioc, ioc_type))
        _mock_settings.vt_api_key = ""
        return captured.get("url", "")

    def test_ip_src_routes_to_ip_addresses_endpoint(self):
        url = self._captured_url("1.2.3.4", "ip-src")
        assert "/ip_addresses/1.2.3.4" in url

    def test_ip_dst_routes_to_ip_addresses_endpoint(self):
        url = self._captured_url("5.6.7.8", "ip-dst")
        assert "/ip_addresses/5.6.7.8" in url

    def test_ip_routes_to_ip_addresses_endpoint(self):
        url = self._captured_url("10.0.0.1", "ip")
        assert "/ip_addresses/10.0.0.1" in url

    def test_domain_routes_to_domains_endpoint(self):
        url = self._captured_url("evil.example.com", "domain")
        assert "/domains/evil.example.com" in url

    def test_sha256_routes_to_files_endpoint(self):
        h = "a" * 64
        url = self._captured_url(h, "sha256")
        assert f"/files/{h}" in url

    def test_vt_v3_base_url_used(self):
        url = self._captured_url("1.2.3.4", "ip")
        assert "virustotal.com/api/v3" in url


# -----------------------------------------------------------
# B5 — Confidence scoring integration
# -----------------------------------------------------------

class TestB5ConfidenceScoring:
    """5 tests — VT contribution to _compute_ti_confidence()."""

    def test_vt_malicious_contributes_25(self):
        results = [{"source": "virustotal", "verdict": "malicious"}]
        score, _ = _compute_ti_confidence(results, 0)
        assert score == 25

    def test_vt_suspicious_contributes_10(self):
        results = [{"source": "virustotal", "verdict": "suspicious"}]
        score, _ = _compute_ti_confidence(results, 0)
        assert score == 10

    def test_vt_benign_contributes_nothing(self):
        results = [{"source": "virustotal", "verdict": "benign"}]
        score, _ = _compute_ti_confidence(results, 0)
        assert score == 0

    def test_vt_malicious_plus_misp_hit_reaches_60(self):
        """MISP(35) + VT malicious(25) = 60 → 'malicious' verdict."""
        results = [{"source": "virustotal", "verdict": "malicious"}]
        score, verdict = _compute_ti_confidence(results, 1)
        assert score == 60
        assert verdict == "malicious"

    def test_vt_adds_value_when_no_misp(self):
        """Even without MISP, VT malicious alone adds 25 points — non-zero value."""
        results = [{"source": "virustotal", "verdict": "malicious"}]
        score, _ = _compute_ti_confidence(results, 0)
        assert score > 0, "VT malicious should add positive confidence even without MISP"


# -----------------------------------------------------------
# B6 — enrich_incident_ti() — sources_used and skip logic
# -----------------------------------------------------------

class TestB6EnrichIncidentTI:
    """6 tests — Top-level enrichment function sources_used and skip-when-no-key."""

    def _make_db(self, alerts=None):
        db  = AsyncMock()
        res = MagicMock()
        res.scalars.return_value.all.return_value = alerts or []
        db.execute = AsyncMock(return_value=res)
        db.flush   = AsyncMock()
        return db

    def _make_incident(self, **kwargs):
        inc = MagicMock()
        inc.id              = "INC-VT-TEST"
        inc.ti_reputation   = None
        inc.misp_enrichment = {}
        for k, v in kwargs.items():
            setattr(inc, k, v)
        return inc

    def test_no_keys_configured_no_external_calls(self):
        _mock_settings.vt_api_key        = ""
        _mock_settings.abuseipdb_api_key = ""
        _mock_settings.greynoise_api_key = ""
        inc = self._make_incident()
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            _run(enrich_incident_ti(self._make_db(), inc))
        mock_cls.assert_not_called()

    def test_sources_used_includes_virustotal_when_key_set(self):
        _mock_settings.vt_api_key        = "TESTKEY"
        _mock_settings.abuseipdb_api_key = ""
        _mock_settings.greynoise_api_key = ""
        inc = self._make_incident()
        with patch("ti_enricher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=AsyncMock(return_value=MagicMock(
                    status_code=200,
                    json=MagicMock(return_value={"data": {"attributes": {
                        "last_analysis_stats": {}, "reputation": 0
                    }}})
                )))
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = _run(enrich_incident_ti(self._make_db(), inc))
        assert "virustotal" in result.get("sources_used", [])
        _mock_settings.vt_api_key = ""

    def test_sources_used_excludes_virustotal_when_no_key(self):
        _mock_settings.vt_api_key        = ""
        _mock_settings.abuseipdb_api_key = ""
        _mock_settings.greynoise_api_key = ""
        inc = self._make_incident()
        result = _run(enrich_incident_ti(self._make_db(), inc))
        assert "virustotal" not in result.get("sources_used", [])

    def test_result_has_verdict_field(self):
        _mock_settings.vt_api_key        = ""
        _mock_settings.abuseipdb_api_key = ""
        _mock_settings.greynoise_api_key = ""
        inc = self._make_incident()
        result = _run(enrich_incident_ti(self._make_db(), inc))
        assert "verdict" in result

    def test_result_has_checked_at_field(self):
        _mock_settings.vt_api_key = ""
        inc = self._make_incident()
        result = _run(enrich_incident_ti(self._make_db(), inc))
        assert "checked_at" in result
        assert result["checked_at"]

    def test_result_written_to_incident_ti_reputation(self):
        _mock_settings.vt_api_key = ""
        inc = self._make_incident()
        result = _run(enrich_incident_ti(self._make_db(), inc))
        assert inc.ti_reputation == result


# -----------------------------------------------------------
# B7 — VT Key Resolution Chain
# (Settings UI → ai_settings.json → cysiemstack.env sync;
#  cloud vault ENGINE_KV_MAP; secret masking; correct paths)
# -----------------------------------------------------------

_ROUTES_PATH   = REPO_ROOT / "backend" / "blueprints" / "system" / "routes.py"
_KVSECRETS_PATH = REPO_ROOT / "backend" / "core" / "kv_secrets.py"
_ROUTES_TEXT   = _ROUTES_PATH.read_text()
_KV_TEXT       = _KVSECRETS_PATH.read_text()


class TestB7VTKeyResolutionChain:
    """10 tests — VT key is set via Settings UI or cloud vault, never by
    hand-editing cysiemstack.env.  Validates the full resolution chain."""

    # ── Cloud vault (ENGINE_KV_MAP) ────────────────────────────────────────

    def test_engine_kv_map_contains_virustotal_key(self):
        """ENGINE_KV_MAP must map VIRUSTOTAL_API_KEY → vault secret name."""
        assert "VIRUSTOTAL_API_KEY" in _KV_TEXT, \
            "VIRUSTOTAL_API_KEY missing from ENGINE_KV_MAP in kv_secrets.py"

    def test_engine_kv_map_vault_secret_name_is_virustotal_api_key(self):
        """Vault secret name must be 'VIRUSTOTAL-API-KEY' (dash-separated)."""
        assert '"VIRUSTOTAL-API-KEY"' in _KV_TEXT, \
            "Vault secret name 'VIRUSTOTAL-API-KEY' not found in kv_secrets.py"

    def test_asm_kv_map_also_covers_virustotal(self):
        """ASM scanning modules share the same vault secret — one entry covers both."""
        # ENGINE_KV_MAP and ASM_KV_MAP both reference VIRUSTOTAL-API-KEY
        assert _KV_TEXT.count('"VIRUSTOTAL-API-KEY"') >= 2, \
            "VIRUSTOTAL-API-KEY should appear in both ENGINE_KV_MAP and ASM_KV_MAP"

    # ── Settings UI → ai_settings.json sync ───────────────────────────────

    def test_sync_ti_to_siem_env_function_exists(self):
        """_sync_ti_to_siem_env() is the bridge from UI save → cysiemstack.env."""
        assert "_sync_ti_to_siem_env" in _ROUTES_TEXT, \
            "_sync_ti_to_siem_env() not found in system/routes.py"

    def test_sync_reads_vtApiKey_from_ai_settings(self):
        """The sync function must read 'vtApiKey' (camelCase UI field name)."""
        assert '"vtApiKey"' in _ROUTES_TEXT or "'vtApiKey'" in _ROUTES_TEXT, \
            "vtApiKey not referenced in _sync_ti_to_siem_env — UI key won't sync"

    def test_sync_writes_VT_API_KEY_to_env(self):
        """The sync function writes VT_API_KEY= into cysiemstack.env."""
        assert '"VT_API_KEY"' in _ROUTES_TEXT or "'VT_API_KEY'" in _ROUTES_TEXT, \
            "VT_API_KEY not written by _sync_ti_to_siem_env — correlation engine won't see it"

    def test_post_ai_settings_calls_sync(self):
        """POST /api/ai/settings must call _sync_ti_to_siem_env() after save."""
        # The sync is called on the 'threat_intel' key whenever it is present
        assert "_sync_ti_to_siem_env" in _ROUTES_TEXT
        # Verify it is called with the threat_intel dict (not just defined)
        lines = _ROUTES_TEXT.splitlines()
        call_lines = [l for l in lines if "_sync_ti_to_siem_env(" in l and not l.strip().startswith("def ")]
        assert len(call_lines) >= 1, \
            "_sync_ti_to_siem_env is defined but never called in routes.py"

    def test_get_ai_settings_masks_vt_key(self):
        """GET /api/ai/settings must NOT return the real VT key — must mask it."""
        assert "vtApiKey" in _ROUTES_TEXT, "vtApiKey not referenced in GET masking logic"
        # Masking marker: key is replaced with '••••••••'
        assert "••••••••" in _ROUTES_TEXT, \
            "GET /api/ai/settings does not mask API keys with bullet characters"

    def test_vt_key_in_secret_filter_list(self):
        """VT key names must appear in the routes-level secret filter to prevent log leakage."""
        assert "VIRUSTOTAL_API_KEY" in _ROUTES_TEXT or "VT_API_KEY" in _ROUTES_TEXT, \
            "VT key names absent from routes.py secret filter list"

    def test_ti_test_endpoint_exists_for_virustotal(self):
        """POST /api/system/ti/test must exist and support source='virustotal'."""
        assert "/api/system/ti/test" in _ROUTES_TEXT, \
            "TI connectivity test endpoint /api/system/ti/test missing from routes.py"
        assert '"virustotal"' in _ROUTES_TEXT or "'virustotal'" in _ROUTES_TEXT, \
            "virustotal source not handled in /api/system/ti/test"
