"""
Suite 02 — UEBA Detector Tests (Detectors 1-17 + host-based)

Tests every UEBA detector in analyse_alert() and _analyse_host_alert()
for trigger conditions (positive) and non-trigger conditions (negative).

DB operations are mocked: _get_or_create_baseline / _record_anomaly /
_update_baseline are all stubbed so tests run without a live database.
"""
import sys
import os
import asyncio
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, AsyncMock, patch, call

# ---------------------------------------------------------------------------
# Stub heavy dependencies before importing ueba
# ---------------------------------------------------------------------------
for _mod in (
    'sqlalchemy', 'sqlalchemy.ext', 'sqlalchemy.ext.asyncio',
    'sqlalchemy.orm', 'models', 'structlog',
):
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '../../backend/cysiemstack/correlation_engine'))

from ueba import (   # noqa: E402
    analyse_alert, _analyse_host_alert,
    RISK_CONTRIBUTIONS, AUTH_SUCCESS_IDS, AUTH_FAIL_IDS, PRIVESC_IDS,
    SERVICE_PATTERNS, DORMANT_THRESHOLD_DAYS,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_NOW = datetime.now(timezone.utc)


def _a(**kw):
    """Minimal alert dict."""
    base = {
        'wazuh_id':     'w1',
        'rule_id':      0,
        'rule_desc':    '',
        'agent_id':     'agent1',
        'agent_name':   'host1',
        'username':     'alice',
        'src_ip':       None,
        'category':     None,
        'timestamp':    _NOW,
        'base_score':   5.0,
        'file_path':    None,
        'process_name': None,
        'raw_log':      '',
    }
    base.update(kw)
    return base


def _make_baseline(**kw):
    """Build a MagicMock UEBABaseline with sane defaults."""
    b = MagicMock()
    b.typical_hours    = list(range(7, 20))      # 7-19 business hours
    b.typical_agents   = ['agent1', 'agent2']
    b.avg_daily_events = 100.0
    b.avg_fail_rate    = 0.05
    b.stddev_fail_rate = 0.02
    b.daily_stats      = []
    b.updated_at       = _NOW - timedelta(days=1)  # active yesterday by default
    for k, v in kw.items():
        setattr(b, k, v)
    return b


def _make_anomaly(anomaly_type='off_hours_login'):
    a = MagicMock()
    a.anomaly_type = anomaly_type
    return a


class _UEBAFixture:
    """Mixin: run analyse_alert with DB stubs; return (anomalies, recorded_calls)."""

    @staticmethod
    async def _run(alert, recent_alerts=None, baseline=None, entity_type='user'):
        recent_alerts = recent_alerts or []
        bl = baseline or _make_baseline()

        recorded_types = []

        async def _fake_record(_db, _username, anomaly_type, *args, **kw):
            anomaly = _make_anomaly(anomaly_type)
            recorded_types.append(anomaly_type)
            return anomaly

        async def _fake_get_bl(_db, _username):
            return bl

        async def _fake_update_bl(_bl, *args, **kw):
            pass

        with patch('ueba._get_or_create_baseline', side_effect=_fake_get_bl), \
             patch('ueba._record_anomaly',          side_effect=_fake_record), \
             patch('ueba._update_baseline',         side_effect=_fake_update_bl):

            db = AsyncMock()
            anomalies = await analyse_alert(db, alert, recent_alerts, 'INC-001', entity_type)

        return anomalies, recorded_types

    @staticmethod
    async def _run_host(alert, recent_alerts=None):
        recent_alerts = recent_alerts or []
        recorded_types = []

        async def _fake_record(_db, _username, anomaly_type, *args, **kw):
            anomaly = _make_anomaly(anomaly_type)
            recorded_types.append(anomaly_type)
            return anomaly

        with patch('ueba._record_anomaly', side_effect=_fake_record):
            db = AsyncMock()
            host_entity = f"host:{alert['agent_id']}"
            anomalies = await _analyse_host_alert(
                db, alert, recent_alerts, 'INC-001', host_entity)

        return anomalies, recorded_types


# ===========================================================================
# Suite 02-A: RISK_CONTRIBUTIONS completeness
# ===========================================================================
class TestRiskContributions:
    EXPECTED_TYPES = {
        'off_hours_login', 'high_auth_fail_rate', 'new_agent_access',
        'multi_host_burst', 'svc_account_interactive', 'privilege_escalation',
        'impossible_travel', 'dormant_account_login', 'concurrent_session',
        'activity_volume_spike', 'suspicious_process', 'repeated_privesc_attempt',
        'mfa_fatigue', 'data_staging', 'wmi_execution', 'token_theft',
        'crypto_miner',
    }

    def test_all_expected_types_present(self):
        missing = self.EXPECTED_TYPES - set(RISK_CONTRIBUTIONS.keys())
        assert not missing, f"Missing anomaly types: {missing}"

    def test_all_scores_in_range(self):
        bad = {k: v for k, v in RISK_CONTRIBUTIONS.items() if not (1 <= v <= 100)}
        assert not bad, f"Risk scores out of 1-100 range: {bad}"

    def test_no_anomaly_type_has_zero_score(self):
        zeros = [k for k, v in RISK_CONTRIBUTIONS.items() if v == 0]
        assert not zeros, f"Zero-score anomaly types: {zeros}"

    def test_high_severity_types_high_score(self):
        """impossible_travel and svc_account_interactive should score ≥50."""
        assert RISK_CONTRIBUTIONS['impossible_travel'] >= 50
        assert RISK_CONTRIBUTIONS['svc_account_interactive'] >= 50

    def test_constant_sets_non_empty(self):
        assert len(AUTH_SUCCESS_IDS) >= 2
        assert len(AUTH_FAIL_IDS)    >= 4
        assert len(PRIVESC_IDS)      >= 3
        assert len(SERVICE_PATTERNS) >= 4


# ===========================================================================
# Suite 02-B: User-based detector tests (analyse_alert)
# ===========================================================================

class TestDetector01_OffHoursLogin(_UEBAFixture):
    """off_hours_login — fires when login is outside 07-19 AND not in typical_hours."""

    @pytest.mark.asyncio
    async def test_fires_at_3am(self):
        ts = _NOW.replace(hour=3)
        bl = _make_baseline(typical_hours=list(range(7, 20)))  # 7-19, no hour 3
        alert = _a(rule_id=5715, timestamp=ts)
        _, types = await self._run(alert, baseline=bl)
        assert 'off_hours_login' in types

    @pytest.mark.asyncio
    async def test_fires_at_midnight(self):
        ts = _NOW.replace(hour=0)
        bl = _make_baseline(typical_hours=list(range(7, 20)))
        alert = _a(rule_id=5715, timestamp=ts)
        _, types = await self._run(alert, baseline=bl)
        assert 'off_hours_login' in types

    @pytest.mark.asyncio
    async def test_no_fire_business_hours(self):
        ts = _NOW.replace(hour=10)
        bl = _make_baseline(typical_hours=list(range(7, 20)))
        alert = _a(rule_id=5715, timestamp=ts)
        _, types = await self._run(alert, baseline=bl)
        assert 'off_hours_login' not in types

    @pytest.mark.asyncio
    async def test_no_fire_if_no_prior_baseline(self):
        """User with no established baseline (typical_hours < 5) should not fire."""
        ts = _NOW.replace(hour=3)
        bl = _make_baseline(typical_hours=[9, 10])  # only 2 hours — < 5
        alert = _a(rule_id=5715, timestamp=ts)
        _, types = await self._run(alert, baseline=bl)
        assert 'off_hours_login' not in types

    @pytest.mark.asyncio
    async def test_no_fire_on_auth_fail(self):
        """Only AUTH_SUCCESS triggers off_hours check."""
        ts = _NOW.replace(hour=3)
        bl = _make_baseline(typical_hours=list(range(7, 20)))
        alert = _a(rule_id=5710, timestamp=ts)  # failure, not success
        _, types = await self._run(alert, baseline=bl)
        assert 'off_hours_login' not in types

    @pytest.mark.asyncio
    async def test_no_fire_if_hour_in_typical(self):
        """3 AM already in typical_hours (night-shift worker) → no fire."""
        ts = _NOW.replace(hour=3)
        bl = _make_baseline(typical_hours=list(range(0, 24)))  # 24-hour worker
        alert = _a(rule_id=5715, timestamp=ts)
        _, types = await self._run(alert, baseline=bl)
        assert 'off_hours_login' not in types


class TestDetector02_HighAuthFailRate(_UEBAFixture):
    """high_auth_fail_rate — fires when fail_rate >= threshold AND recent_fails >= 5."""

    @pytest.mark.asyncio
    async def test_fires_on_high_fail_rate(self):
        bl = _make_baseline(avg_fail_rate=0.02)
        # 9 failures in 10 alerts → rate = 9/10 = 0.90; threshold = max(0.15, 0.06) = 0.15
        recent = [_a(rule_id=5710, username='alice') for _ in range(9)]
        alert  = _a(rule_id=5710)
        _, types = await self._run(alert, recent_alerts=recent, baseline=bl)
        assert 'high_auth_fail_rate' in types

    @pytest.mark.asyncio
    async def test_no_fire_below_5_failures(self):
        bl = _make_baseline(avg_fail_rate=0.02)
        recent = [_a(rule_id=5710, username='alice') for _ in range(3)]
        alert  = _a(rule_id=5710)
        _, types = await self._run(alert, recent_alerts=recent, baseline=bl)
        assert 'high_auth_fail_rate' not in types

    @pytest.mark.asyncio
    async def test_no_fire_on_success(self):
        bl = _make_baseline(avg_fail_rate=0.02)
        recent = [_a(rule_id=5710, username='alice') for _ in range(9)]
        alert  = _a(rule_id=5715)  # success, not failure
        _, types = await self._run(alert, recent_alerts=recent, baseline=bl)
        assert 'high_auth_fail_rate' not in types

    @pytest.mark.asyncio
    async def test_threshold_is_3x_baseline_or_15pct(self):
        """When baseline is 0% (new user), threshold falls back to 0.15."""
        bl = _make_baseline(avg_fail_rate=0.0)
        # 5 fails out of 10 = 50% > 15%
        recent = [_a(rule_id=5710, username='alice') for _ in range(5)]
        alert  = _a(rule_id=5710)
        _, types = await self._run(alert, recent_alerts=recent, baseline=bl)
        assert 'high_auth_fail_rate' in types


class TestDetector03_NewAgentAccess(_UEBAFixture):
    """new_agent_access — fires when login to unknown agent (not in typical_agents)."""

    @pytest.mark.asyncio
    async def test_fires_on_unknown_agent(self):
        bl = _make_baseline(typical_agents=['trusted-host', 'work-laptop'])
        alert = _a(rule_id=5715, agent_id='unknown-server', agent_name='unknown-server')
        _, types = await self._run(alert, baseline=bl)
        assert 'new_agent_access' in types

    @pytest.mark.asyncio
    async def test_no_fire_for_known_agent(self):
        bl = _make_baseline(typical_agents=['trusted-host', 'work-laptop'])
        alert = _a(rule_id=5715, agent_id='trusted-host')
        _, types = await self._run(alert, baseline=bl)
        assert 'new_agent_access' not in types

    @pytest.mark.asyncio
    async def test_no_fire_when_no_baseline_agents(self):
        """If typical_agents is empty (new user), skip the check."""
        bl = _make_baseline(typical_agents=[])
        alert = _a(rule_id=5715, agent_id='any-host')
        _, types = await self._run(alert, baseline=bl)
        assert 'new_agent_access' not in types

    @pytest.mark.asyncio
    async def test_no_fire_on_auth_failure(self):
        bl = _make_baseline(typical_agents=['trusted-host'])
        alert = _a(rule_id=5710, agent_id='unknown-server')  # failure, not success
        _, types = await self._run(alert, baseline=bl)
        assert 'new_agent_access' not in types


class TestDetector04_MultiHostBurst(_UEBAFixture):
    """multi_host_burst — fires when activity across 4+ hosts within 10 min."""

    @pytest.mark.asyncio
    async def test_fires_with_4_hosts_in_window(self):
        base_ts = _NOW
        recent = [
            _a(agent_id=f'host{i}', timestamp=base_ts - timedelta(minutes=i))
            for i in range(3)
        ]
        alert = _a(agent_id='host3', timestamp=base_ts)
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'multi_host_burst' in types

    @pytest.mark.asyncio
    async def test_no_fire_with_3_hosts(self):
        base_ts = _NOW
        recent = [
            _a(agent_id=f'host{i}', timestamp=base_ts - timedelta(minutes=i))
            for i in range(2)
        ]
        alert = _a(agent_id='host2', timestamp=base_ts)
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'multi_host_burst' not in types

    @pytest.mark.asyncio
    async def test_no_fire_when_hosts_outside_window(self):
        """Hosts visited > 10 min ago do not count."""
        base_ts = _NOW
        recent = [
            _a(agent_id=f'host{i}', timestamp=base_ts - timedelta(minutes=15 + i))
            for i in range(5)
        ]
        alert = _a(agent_id='current', timestamp=base_ts)
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'multi_host_burst' not in types


class TestDetector05_SvcAccountInteractive(_UEBAFixture):
    """svc_account_interactive — fires when service account does interactive login."""

    @pytest.mark.asyncio
    async def test_fires_on_svc_prefix(self):
        alert = _a(rule_id=5715, username='svc_deploy')
        _, types = await self._run(alert)
        assert 'svc_account_interactive' in types

    @pytest.mark.asyncio
    async def test_fires_on_daemon_pattern(self):
        alert = _a(rule_id=5715, username='daemon_backup')
        _, types = await self._run(alert)
        assert 'svc_account_interactive' in types

    @pytest.mark.asyncio
    async def test_fires_on_admin_suffix(self):
        alert = _a(rule_id=5715, username='deploy_admin')
        _, types = await self._run(alert)
        assert 'svc_account_interactive' in types

    @pytest.mark.asyncio
    async def test_no_fire_for_regular_user(self):
        alert = _a(rule_id=5715, username='alice')
        _, types = await self._run(alert)
        assert 'svc_account_interactive' not in types

    @pytest.mark.asyncio
    async def test_fires_on_service_keyword(self):
        alert = _a(rule_id=5715, username='serviceaccount_x')
        _, types = await self._run(alert)
        assert 'svc_account_interactive' in types


class TestDetector06_PrivilegeEscalation(_UEBAFixture):
    """privilege_escalation — fires on privesc rule_id + corroborating context."""

    @pytest.mark.asyncio
    async def test_fires_for_service_account(self):
        alert = _a(rule_id=5400, username='svc_deploy', timestamp=_NOW.replace(hour=10))
        _, types = await self._run(alert)
        assert 'privilege_escalation' in types

    @pytest.mark.asyncio
    async def test_fires_for_off_hours(self):
        alert = _a(rule_id=5400, username='alice', timestamp=_NOW.replace(hour=2))
        _, types = await self._run(alert)
        assert 'privilege_escalation' in types

    @pytest.mark.asyncio
    async def test_fires_when_preceded_by_fail(self):
        recent = [_a(rule_id=5710, username='alice')]
        alert  = _a(rule_id=5400, username='alice', timestamp=_NOW.replace(hour=10))
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'privilege_escalation' in types

    @pytest.mark.asyncio
    async def test_no_fire_regular_user_business_hours_no_prior_fail(self):
        """Normal admin doing sudo in business hours with no preceding failure → no fire."""
        bl = _make_baseline()
        alert = _a(rule_id=5400, username='alice', timestamp=_NOW.replace(hour=10))
        _, types = await self._run(alert, recent_alerts=[], baseline=bl)
        assert 'privilege_escalation' not in types

    @pytest.mark.asyncio
    async def test_no_fire_non_privesc_rule(self):
        alert = _a(rule_id=5715, username='alice')
        _, types = await self._run(alert)
        assert 'privilege_escalation' not in types


class TestDetector07_ImpossibleTravel(_UEBAFixture):
    """impossible_travel — same user on different agents within 2 min."""

    @pytest.mark.asyncio
    async def test_fires_on_rapid_host_switch(self):
        t0 = _NOW
        recent = [_a(rule_id=5715, username='alice', agent_id='server-a',
                     timestamp=t0 - timedelta(seconds=60))]
        alert = _a(rule_id=5715, username='alice', agent_id='server-b', timestamp=t0)
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'impossible_travel' in types

    @pytest.mark.asyncio
    async def test_no_fire_within_5_minutes(self):
        t0 = _NOW
        recent = [_a(rule_id=5715, username='alice', agent_id='server-a',
                     timestamp=t0 - timedelta(minutes=5))]
        alert = _a(rule_id=5715, username='alice', agent_id='server-b', timestamp=t0)
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'impossible_travel' not in types

    @pytest.mark.asyncio
    async def test_no_fire_same_agent(self):
        t0 = _NOW
        recent = [_a(rule_id=5715, username='alice', agent_id='server-a',
                     timestamp=t0 - timedelta(seconds=30))]
        alert = _a(rule_id=5715, username='alice', agent_id='server-a', timestamp=t0)
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'impossible_travel' not in types

    @pytest.mark.asyncio
    async def test_no_fire_on_failure_event(self):
        t0 = _NOW
        recent = [_a(rule_id=5715, username='alice', agent_id='server-a',
                     timestamp=t0 - timedelta(seconds=30))]
        alert = _a(rule_id=5710, username='alice', agent_id='server-b', timestamp=t0)
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'impossible_travel' not in types


class TestDetector08_DormantAccountLogin(_UEBAFixture):
    """dormant_account_login — fires when account inactive ≥ 90 days logs in."""

    @pytest.mark.asyncio
    async def test_fires_after_90_day_gap(self):
        bl = _make_baseline(
            avg_daily_events=50.0,
            updated_at=_NOW - timedelta(days=91),
        )
        alert = _a(rule_id=5715)
        _, types = await self._run(alert, baseline=bl)
        assert 'dormant_account_login' in types

    @pytest.mark.asyncio
    async def test_no_fire_within_90_days(self):
        bl = _make_baseline(
            avg_daily_events=50.0,
            updated_at=_NOW - timedelta(days=30),
        )
        alert = _a(rule_id=5715)
        _, types = await self._run(alert, baseline=bl)
        assert 'dormant_account_login' not in types

    @pytest.mark.asyncio
    async def test_no_fire_when_account_never_active(self):
        """avg_daily_events == 0 means never established — skip dormant check."""
        bl = _make_baseline(avg_daily_events=0.0, updated_at=_NOW - timedelta(days=365))
        alert = _a(rule_id=5715)
        _, types = await self._run(alert, baseline=bl)
        assert 'dormant_account_login' not in types

    @pytest.mark.asyncio
    async def test_threshold_constant_is_90(self):
        assert DORMANT_THRESHOLD_DAYS == 90


class TestDetector09_ConcurrentSession(_UEBAFixture):
    """concurrent_session — same user, two different agents within 30 seconds."""

    @pytest.mark.asyncio
    async def test_fires_on_concurrent_logins(self):
        t0 = _NOW
        recent = [_a(rule_id=5715, username='alice', agent_id='server-a',
                     timestamp=t0 - timedelta(seconds=15))]
        alert = _a(rule_id=5715, username='alice', agent_id='server-b', timestamp=t0)
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'concurrent_session' in types

    @pytest.mark.asyncio
    async def test_no_fire_outside_30s_window(self):
        t0 = _NOW
        recent = [_a(rule_id=5715, username='alice', agent_id='server-a',
                     timestamp=t0 - timedelta(seconds=60))]
        alert = _a(rule_id=5715, username='alice', agent_id='server-b', timestamp=t0)
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'concurrent_session' not in types

    @pytest.mark.asyncio
    async def test_no_fire_same_agent(self):
        t0 = _NOW
        recent = [_a(rule_id=5715, username='alice', agent_id='server-a',
                     timestamp=t0 - timedelta(seconds=5))]
        alert = _a(rule_id=5715, username='alice', agent_id='server-a', timestamp=t0)
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'concurrent_session' not in types


class TestDetector10_ActivityVolumeSpike(_UEBAFixture):
    """activity_volume_spike — fires when event count is 10× hourly baseline."""

    @pytest.mark.asyncio
    async def test_fires_on_spike(self):
        # baseline: 24 events/day = 1/hour → max(1, 1) = 1.
        # 20 recent + 1 current = 21 events → spike_ratio = 21/1 = 21 >= 10 ✓
        bl = _make_baseline(avg_daily_events=24.0)
        recent = [_a(rule_id=5715) for _ in range(20)]
        alert  = _a(rule_id=5715)
        _, types = await self._run(alert, recent_alerts=recent, baseline=bl)
        assert 'activity_volume_spike' in types

    @pytest.mark.asyncio
    async def test_no_fire_below_threshold(self):
        # baseline: 2400 events/day = 100/hour. 20 events = 0.2x — no spike
        bl = _make_baseline(avg_daily_events=2400.0)
        recent = [_a(rule_id=5715) for _ in range(19)]
        alert  = _a(rule_id=5715)
        _, types = await self._run(alert, recent_alerts=recent, baseline=bl)
        assert 'activity_volume_spike' not in types

    @pytest.mark.asyncio
    async def test_no_fire_when_no_baseline(self):
        """avg_daily_events == 0 → skip check."""
        bl = _make_baseline(avg_daily_events=0.0)
        recent = [_a(rule_id=5715) for _ in range(100)]
        alert  = _a(rule_id=5715)
        _, types = await self._run(alert, recent_alerts=recent, baseline=bl)
        assert 'activity_volume_spike' not in types

    @pytest.mark.asyncio
    async def test_fires_on_fim_category_spike(self):
        # baseline: 24/day → 1/hour → spike_ratio = 21/1 = 21 >= 10 ✓
        bl = _make_baseline(avg_daily_events=24.0)
        recent = [_a(category='fim') for _ in range(20)]
        alert  = _a(category='fim')
        _, types = await self._run(alert, recent_alerts=recent, baseline=bl)
        assert 'activity_volume_spike' in types


class TestDetector11_SuspiciousProcess(_UEBAFixture):
    """suspicious_process — fires when known attack tool is in process_name."""

    @pytest.mark.asyncio
    async def test_fires_on_mimikatz(self):
        alert = _a(process_name='mimikatz.exe', category='malware')
        _, types = await self._run(alert)
        assert 'suspicious_process' in types

    @pytest.mark.asyncio
    async def test_fires_on_meterpreter(self):
        alert = _a(process_name='meterpreter_shell', category='system')
        _, types = await self._run(alert)
        assert 'suspicious_process' in types

    @pytest.mark.asyncio
    async def test_fires_on_cobalt(self):
        alert = _a(process_name='cobaltstrike_beacon', category='malware')
        _, types = await self._run(alert)
        assert 'suspicious_process' in types

    @pytest.mark.asyncio
    async def test_fires_on_rubeus(self):
        alert = _a(process_name='Rubeus.exe', category='malware')
        _, types = await self._run(alert)
        assert 'suspicious_process' in types

    @pytest.mark.asyncio
    async def test_no_fire_for_common_process(self):
        alert = _a(process_name='svchost.exe', category='system')
        _, types = await self._run(alert)
        assert 'suspicious_process' not in types

    @pytest.mark.asyncio
    async def test_no_fire_without_malware_category(self):
        alert = _a(process_name='mimikatz.exe', category='network')
        _, types = await self._run(alert)
        assert 'suspicious_process' not in types

    @pytest.mark.asyncio
    async def test_no_fire_without_process_name(self):
        alert = _a(process_name=None, category='malware')
        _, types = await self._run(alert)
        assert 'suspicious_process' not in types


class TestDetector12_RepeatedPrivescAttempt(_UEBAFixture):
    """repeated_privesc_attempt — ≥3 privesc events in recent context, triggered by auth fail."""

    @pytest.mark.asyncio
    async def test_fires_with_3_recent_privesc(self):
        recent = [_a(rule_id=5400) for _ in range(3)]
        alert  = _a(rule_id=5710)  # auth fail triggers the check
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'repeated_privesc_attempt' in types

    @pytest.mark.asyncio
    async def test_no_fire_with_2_recent_privesc(self):
        recent = [_a(rule_id=5400) for _ in range(2)]
        alert  = _a(rule_id=5710)
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'repeated_privesc_attempt' not in types

    @pytest.mark.asyncio
    async def test_no_fire_on_success_event(self):
        """Check is only triggered when the current alert is an auth failure."""
        recent = [_a(rule_id=5400) for _ in range(3)]
        alert  = _a(rule_id=5715)  # success — does not trigger repeated_privesc check
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'repeated_privesc_attempt' not in types


class TestDetector13_MFAFatigue(_UEBAFixture):
    """mfa_fatigue — fires when ≥8 MFA prompts in recent context."""

    @pytest.mark.asyncio
    async def test_fires_on_8_prompts(self):
        recent = [_a(rule_desc='mfa prompt sent', username='alice') for _ in range(8)]
        alert  = _a(rule_desc='mfa prompt sent')
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'mfa_fatigue' in types

    @pytest.mark.asyncio
    async def test_fires_on_duo_push(self):
        recent = [_a(rule_desc='Duo push sent', username='alice') for _ in range(8)]
        alert  = _a(rule_desc='Duo push sent')
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'mfa_fatigue' in types

    @pytest.mark.asyncio
    async def test_no_fire_with_7_prompts(self):
        recent = [_a(rule_desc='mfa prompt sent', username='alice') for _ in range(7)]
        alert  = _a(rule_desc='mfa prompt sent')
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'mfa_fatigue' not in types

    @pytest.mark.asyncio
    async def test_no_fire_different_username(self):
        """Prompts to other users don't count for alice."""
        recent = [_a(rule_desc='mfa prompt sent', username='bob') for _ in range(10)]
        alert  = _a(rule_desc='mfa prompt sent', username='alice')
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'mfa_fatigue' not in types


class TestDetector14_DataStaging(_UEBAFixture):
    """data_staging — fires when archive tool + ≥10 prior FIM events."""

    @pytest.mark.asyncio
    async def test_fires_on_7z_with_fim_context(self):
        recent = [_a(category='fim') for _ in range(10)]
        alert  = _a(rule_desc='7z  archive created')
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'data_staging' in types

    @pytest.mark.asyncio
    async def test_fires_on_tar_with_fim_context(self):
        recent = [_a(category='fim') for _ in range(10)]
        alert  = _a(rule_desc='tar czf backup created')
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'data_staging' in types

    @pytest.mark.asyncio
    async def test_no_fire_archive_but_no_fim(self):
        alert = _a(rule_desc='7z  archive created')
        _, types = await self._run(alert, recent_alerts=[])
        assert 'data_staging' not in types

    @pytest.mark.asyncio
    async def test_no_fire_fim_no_archive(self):
        recent = [_a(category='fim') for _ in range(20)]
        alert  = _a(rule_desc='user login')
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'data_staging' not in types

    @pytest.mark.asyncio
    async def test_fires_archive_in_raw_log(self):
        recent = [_a(category='fim') for _ in range(10)]
        alert  = _a(raw_log='winrar compress selected files')
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'data_staging' in types


class TestDetector15_WMIExecution(_UEBAFixture):
    """wmi_execution — fires on any WMI signal in rule_desc or raw_log."""

    @pytest.mark.asyncio
    async def test_fires_on_wmic_in_desc(self):
        alert = _a(rule_desc='wmic  process call create cmd')
        _, types = await self._run(alert)
        assert 'wmi_execution' in types

    @pytest.mark.asyncio
    async def test_fires_on_wmiprvse(self):
        alert = _a(rule_desc='wmiprvse.exe spawned process')
        _, types = await self._run(alert)
        assert 'wmi_execution' in types

    @pytest.mark.asyncio
    async def test_fires_on_invoke_wmimethod(self):
        alert = _a(raw_log='invoke-wmimethod -class Win32_Process')
        _, types = await self._run(alert)
        assert 'wmi_execution' in types

    @pytest.mark.asyncio
    async def test_no_fire_on_normal_alert(self):
        alert = _a(rule_desc='user logged in successfully')
        _, types = await self._run(alert)
        assert 'wmi_execution' not in types


class TestDetector16_TokenTheft(_UEBAFixture):
    """token_theft — fires on keyword OR ≥5 distinct src_ips for same user."""

    @pytest.mark.asyncio
    async def test_fires_on_cookie_theft_keyword(self):
        alert = _a(rule_desc='cookie theft session hijack')
        _, types = await self._run(alert)
        assert 'token_theft' in types

    @pytest.mark.asyncio
    async def test_fires_on_pass_the_cookie(self):
        alert = _a(rule_desc='pass-the-cookie replay detected')
        _, types = await self._run(alert)
        assert 'token_theft' in types

    @pytest.mark.asyncio
    async def test_fires_on_5_distinct_ips(self):
        recent = [
            _a(rule_id=5715, username='alice', src_ip=f'10.0.0.{i}')
            for i in range(5)
        ]
        alert = _a(rule_id=5715, username='alice', src_ip='10.0.0.99')
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'token_theft' in types

    @pytest.mark.asyncio
    async def test_no_fire_on_4_distinct_ips(self):
        """Threshold raised to 5 to avoid false positives on VPN users."""
        recent = [
            _a(rule_id=5715, username='alice', src_ip=f'10.0.0.{i}')
            for i in range(4)
        ]
        alert = _a(rule_id=5715, username='alice', src_ip='10.0.0.99')
        _, types = await self._run(alert, recent_alerts=recent)
        # 4 IPs in recent + 1 in recent without counting current → 4 distinct
        assert 'token_theft' not in types

    @pytest.mark.asyncio
    async def test_no_fire_on_different_username_ips(self):
        """IPs from other users don't count toward alice's token theft score."""
        recent = [
            _a(rule_id=5715, username='bob', src_ip=f'10.0.0.{i}')
            for i in range(5)
        ]
        alert = _a(rule_id=5715, username='alice', src_ip='10.0.0.99')
        _, types = await self._run(alert, recent_alerts=recent)
        assert 'token_theft' not in types


class TestDetector17_CryptoMiner(_UEBAFixture):
    """crypto_miner — fires on mining signals in rule_desc or raw_log."""

    @pytest.mark.asyncio
    async def test_fires_on_xmrig(self):
        alert = _a(rule_desc='xmrig process started')
        _, types = await self._run(alert)
        assert 'crypto_miner' in types

    @pytest.mark.asyncio
    async def test_fires_on_stratum_protocol(self):
        alert = _a(rule_desc='connection to stratum+tcp://pool.minexmr.com')
        _, types = await self._run(alert)
        assert 'crypto_miner' in types

    @pytest.mark.asyncio
    async def test_fires_on_nicehash(self):
        alert = _a(raw_log='nicehash mining started port 3333')
        _, types = await self._run(alert)
        assert 'crypto_miner' in types

    @pytest.mark.asyncio
    async def test_no_fire_on_normal_log(self):
        alert = _a(rule_desc='system check completed successfully')
        _, types = await self._run(alert)
        assert 'crypto_miner' not in types


# ===========================================================================
# Suite 02-C: Host-based UEBA detectors (_analyse_host_alert)
# ===========================================================================

class TestHostMultiHostBurst(_UEBAFixture):
    """Host-based multi_host_burst — agent touches 4+ peers in 10 min."""

    @pytest.mark.asyncio
    async def test_fires_on_4_peers(self):
        base_ts = _NOW
        recent = [
            _a(agent_id=f'peer{i}', timestamp=base_ts - timedelta(minutes=i))
            for i in range(3)
        ]
        alert = _a(agent_id='attacker', src_ip='1.2.3.4', timestamp=base_ts)
        _, types = await self._run_host(alert, recent_alerts=recent)
        assert 'multi_host_burst' in types

    @pytest.mark.asyncio
    async def test_no_fire_on_3_peers(self):
        base_ts = _NOW
        recent = [
            _a(agent_id=f'peer{i}', timestamp=base_ts - timedelta(minutes=i))
            for i in range(2)
        ]
        alert = _a(agent_id='scanner', timestamp=base_ts)
        _, types = await self._run_host(alert, recent_alerts=recent)
        assert 'multi_host_burst' not in types


class TestHostImpossibleTravel(_UEBAFixture):
    """Host-based impossible_travel — same agent seen from two IPs within 2 min."""

    @pytest.mark.asyncio
    async def test_fires_on_ip_change(self):
        t0 = _NOW
        recent = [_a(agent_id='victim', src_ip='1.2.3.4', timestamp=t0 - timedelta(seconds=60))]
        alert = _a(agent_id='victim', src_ip='5.6.7.8', timestamp=t0)
        _, types = await self._run_host(alert, recent_alerts=recent)
        assert 'impossible_travel' in types

    @pytest.mark.asyncio
    async def test_no_fire_same_ip(self):
        t0 = _NOW
        recent = [_a(agent_id='victim', src_ip='1.2.3.4', timestamp=t0 - timedelta(seconds=60))]
        alert = _a(agent_id='victim', src_ip='1.2.3.4', timestamp=t0)
        _, types = await self._run_host(alert, recent_alerts=recent)
        assert 'impossible_travel' not in types

    @pytest.mark.asyncio
    async def test_no_fire_without_src_ip(self):
        t0 = _NOW
        recent = [_a(agent_id='victim', src_ip='1.2.3.4', timestamp=t0 - timedelta(seconds=60))]
        alert = _a(agent_id='victim', src_ip=None, timestamp=t0)
        _, types = await self._run_host(alert, recent_alerts=recent)
        assert 'impossible_travel' not in types


class TestHostC2Beaconing(_UEBAFixture):
    """Host-based C2 beaconing — ≥5 outbound events with low time variance."""

    @pytest.mark.asyncio
    async def test_fires_on_regular_beaconing(self):
        """5 outbound events at exact 60s intervals → CV ≈ 0 (< 0.25)."""
        base_ts = _NOW
        recent = [
            _a(agent_id='victim', rule_id=18100 + i,
               timestamp=base_ts - timedelta(seconds=300 - i * 60))
            for i in range(5)
        ]
        alert = _a(agent_id='victim', src_ip='evil.c2', timestamp=base_ts)
        _, types = await self._run_host(alert, recent_alerts=recent)
        assert 'c2_beaconing' in types

    @pytest.mark.asyncio
    async def test_no_fire_with_high_variance(self):
        """Irregular intervals → high CV → no beacon detection."""
        base_ts = _NOW
        gaps = [1, 300, 1, 600, 2]   # highly irregular
        ts = base_ts - timedelta(seconds=sum(gaps))
        recent = []
        for g in gaps:
            ts += timedelta(seconds=g)
            recent.append(_a(agent_id='victim', rule_id=18101, timestamp=ts))
        alert = _a(agent_id='victim', timestamp=base_ts)
        _, types = await self._run_host(alert, recent_alerts=recent)
        assert 'c2_beaconing' not in types

    @pytest.mark.asyncio
    async def test_no_fire_with_fewer_than_5_outbound(self):
        base_ts = _NOW
        recent = [
            _a(agent_id='victim', rule_id=18101,
               timestamp=base_ts - timedelta(seconds=i * 60))
            for i in range(4)
        ]
        alert = _a(agent_id='victim', timestamp=base_ts)
        _, types = await self._run_host(alert, recent_alerts=recent)
        assert 'c2_beaconing' not in types


# ===========================================================================
# Suite 02-D: Route integration — no username returns empty list
# ===========================================================================
class TestAnalyseAlertNoUsername(_UEBAFixture):

    @pytest.mark.asyncio
    async def test_returns_empty_on_none_username(self):
        """User-based analyse_alert with no username → [] (not an error)."""
        alert = _a(username=None, rule_id=5715)
        anomalies, _ = await self._run(alert)
        assert anomalies == []

    @pytest.mark.asyncio
    async def test_host_path_invoked_when_entity_type_host(self):
        """entity_type='host' routes to _analyse_host_alert regardless of username."""
        alert = _a(username='alice', rule_id=5715)
        with patch('ueba._analyse_host_alert', new_callable=AsyncMock) as mock_host:
            mock_host.return_value = []
            db = AsyncMock()
            await analyse_alert(db, alert, [], 'INC-001', entity_type='host')
            mock_host.assert_called_once()
