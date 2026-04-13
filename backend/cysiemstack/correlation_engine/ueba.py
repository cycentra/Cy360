"""
ueba.py
User and Entity Behaviour Analytics — rule-based anomaly detectors.

7 detectors with rolling baselines (updated per alert):
  1. off_hours_login         — Login outside 07:00–19:00 not in user's pattern
  2. high_auth_fail_rate     — Failure rate 3× above user's baseline
  3. new_agent_access        — Login to host not in user's typical set
  4. multi_host_burst        — Activity across 4+ hosts in 10 minutes
  5. svc_account_interactive — Service account doing interactive activity
  6. privilege_escalation    — Any sudo/su event
  7. impossible_travel       — Same user on 2 different hosts within 2 minutes
"""
from datetime import datetime, timezone, timedelta
from typing import Optional
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models import UEBABaseline, UEBAAnomaly, Incident

log = structlog.get_logger()

# Risk contribution scores per anomaly type
RISK_CONTRIBUTIONS = {
    'off_hours_login':        35,
    'high_auth_fail_rate':    40,
    'new_agent_access':       25,
    'multi_host_burst':       45,
    'svc_account_interactive': 55,
    'privilege_escalation':   40,
    'impossible_travel':      60,
}

AUTH_SUCCESS_IDS = {5715, 5718}
AUTH_FAIL_IDS    = {5710, 5711, 5716, 5719, 5720, 2502}
PRIVESC_IDS      = {5400, 5402, 5501, 18101, 18104}
SERVICE_PATTERNS = ('svc_', 'svc-', 'daemon', 'service', 'system', '_svc', '-svc', 'admin')


async def _get_or_create_baseline(db: AsyncSession, username: str) -> UEBABaseline:
    result = await db.execute(
        select(UEBABaseline).where(UEBABaseline.username == username)
    )
    baseline = result.scalar_one_or_none()
    if not baseline:
        baseline = UEBABaseline(
            username       = username,
            typical_hours  = [],
            typical_agents = [],
            avg_daily_events = 0,
            avg_fail_rate  = 0,
            stddev_fail_rate = 0,
            daily_stats    = [],
        )
        db.add(baseline)
        await db.flush()
    return baseline


async def _record_anomaly(
    db: AsyncSession,
    username: str,
    anomaly_type: str,
    description: str,
    incident_id: str,
    alert_ids: list,
) -> UEBAAnomaly:
    contribution = RISK_CONTRIBUTIONS.get(anomaly_type, 20)
    anomaly = UEBAAnomaly(
        username          = username,
        anomaly_type      = anomaly_type,
        description       = description,
        risk_contribution = contribution,
        alert_ids         = [str(a) for a in alert_ids if a],
        incident_id       = incident_id,
        resolved          = False,
    )
    db.add(anomaly)

    # Also flag on the incident
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if incident:
        flags = list(incident.ueba_flags or [])
        if anomaly_type not in flags:
            flags.append(anomaly_type)
            incident.ueba_flags = flags

    await db.flush()
    return anomaly


async def analyse_alert(
    db: AsyncSession,
    alert: dict,
    recent_alerts: list[dict],
    incident_id: str,
    entity_type: str = "user",
) -> list[UEBAAnomaly]:
    """
    Run all UEBA detectors against the current alert + recent context.

    When entity_type='user' (default), user-based detectors run on alert.username.
    When entity_type='host', host-based detectors run on alert.agent_id /
    alert.agent_name — covers multi-host burst, C2 beaconing, impossible travel.

    Returns list of UEBAAnomaly objects created this call.
    """
    username = alert.get('username')

    # Host-based path: derive a synthetic username from the agent to reuse
    # existing anomaly infrastructure (baseline keyed on 'username' column).
    if not username or entity_type == "host":
        if entity_type == "host":
            # Use host sentinel so we don't mix user/host baselines
            host_entity = f"host:{alert.get('agent_id', 'unknown')}"
            return await _analyse_host_alert(db, alert, recent_alerts, incident_id, host_entity)
        return []

    baseline  = await _get_or_create_baseline(db, username)
    anomalies = []
    ts        = alert['timestamp']
    hour      = ts.hour
    rule_id   = alert['rule_id']
    agent_id  = alert['agent_id']

    # ── 1. Off-hours login ─────────────────────────────────────────────────────
    if rule_id in AUTH_SUCCESS_IDS:
        typical = set(baseline.typical_hours or [])
        is_off_hours = not (7 <= hour <= 19)
        if is_off_hours and hour not in typical and len(typical) >= 5:
            anomalies.append(await _record_anomaly(
                db, username, 'off_hours_login',
                f"Login at {hour:02d}:00 — outside typical hours {min(typical, default=7)}-{max(typical, default=19)}",
                incident_id, [alert.get('wazuh_id')],
            ))

    # ── 2. High auth failure rate ──────────────────────────────────────────────
    if rule_id in AUTH_FAIL_IDS:
        recent_fails = sum(1 for a in recent_alerts if a['rule_id'] in AUTH_FAIL_IDS)
        recent_total = len(recent_alerts) + 1
        fail_rate = recent_fails / recent_total if recent_total > 0 else 0
        baseline_rate = float(baseline.avg_fail_rate or 0)
        threshold = max(0.15, baseline_rate * 3)
        if fail_rate >= threshold and recent_fails >= 5:
            anomalies.append(await _record_anomaly(
                db, username, 'high_auth_fail_rate',
                f"Fail rate {fail_rate:.0%} — {recent_fails} failures in 2h window (baseline {baseline_rate:.0%})",
                incident_id, [alert.get('wazuh_id')],
            ))

    # ── 3. New agent access ────────────────────────────────────────────────────
    if rule_id in AUTH_SUCCESS_IDS:
        typical_agents = set(baseline.typical_agents or [])
        if typical_agents and agent_id not in typical_agents:
            anomalies.append(await _record_anomaly(
                db, username, 'new_agent_access',
                f"Login to {alert.get('agent_name', agent_id)} — not in typical host set ({len(typical_agents)} known hosts)",
                incident_id, [alert.get('wazuh_id')],
            ))

    # ── 4. Multi-host burst ────────────────────────────────────────────────────
    burst_window = timedelta(minutes=10)
    burst_cutoff = ts - burst_window
    recent_hosts = {a['agent_id'] for a in recent_alerts if a['timestamp'] >= burst_cutoff}
    recent_hosts.add(agent_id)
    if len(recent_hosts) >= 4:
        anomalies.append(await _record_anomaly(
            db, username, 'multi_host_burst',
            f"Activity across {len(recent_hosts)} hosts in 10 minutes: {', '.join(list(recent_hosts)[:4])}",
            incident_id, [alert.get('wazuh_id')],
        ))

    # ── 5. Service account interactive ────────────────────────────────────────
    if any(p in username.lower() for p in SERVICE_PATTERNS):
        if rule_id in AUTH_SUCCESS_IDS | {5501, 5502}:
            anomalies.append(await _record_anomaly(
                db, username, 'svc_account_interactive',
                f"Service account {username} performing interactive session on {alert.get('agent_name')}",
                incident_id, [alert.get('wazuh_id')],
            ))

    # ── 6. Privilege escalation ────────────────────────────────────────────────
    if rule_id in PRIVESC_IDS:
        anomalies.append(await _record_anomaly(
            db, username, 'privilege_escalation',
            f"Privilege escalation (rule {rule_id}) by {username} on {alert.get('agent_name')}",
            incident_id, [alert.get('wazuh_id')],
        ))

    # ── 7. Impossible travel ───────────────────────────────────────────────────
    if rule_id in AUTH_SUCCESS_IDS and recent_alerts:
        travel_window = timedelta(minutes=2)
        recent_success = [
            a for a in recent_alerts
            if a['rule_id'] in AUTH_SUCCESS_IDS
            and a['agent_id'] != agent_id
            and ts - a['timestamp'] <= travel_window
        ]
        if recent_success:
            other = recent_success[0]
            anomalies.append(await _record_anomaly(
                db, username, 'impossible_travel',
                f"{username} on {alert.get('agent_name')} and {other.get('agent_id')} within {(ts - other['timestamp']).seconds}s",
                incident_id, [alert.get('wazuh_id'), other.get('rule_id')],
            ))

    # ── Update baseline ────────────────────────────────────────────────────────
    await _update_baseline(baseline, alert, recent_alerts)
    await db.flush()

    if anomalies:
        log.info('ueba_anomalies', username=username, count=len(anomalies),
                 types=[a.anomaly_type for a in anomalies])

    return anomalies


async def _update_baseline(
    baseline: UEBABaseline,
    alert: dict,
    recent: list[dict],
) -> None:
    """Incrementally update user baseline from new alert data."""
    ts    = alert['timestamp']
    hour  = ts.hour
    agent = alert['agent_id']

    # Update typical hours (rolling unique set, max 24)
    hours = list(set((baseline.typical_hours or []) + [hour]))[:24]
    baseline.typical_hours = hours

    # Update typical agents (rolling unique set, max 20)
    agents = list(set((baseline.typical_agents or []) + [agent]))[:20]
    baseline.typical_agents = agents

    # Update fail rate (EWMA, alpha=0.1)
    alpha   = 0.1
    is_fail = int(alert['rule_id'] in {5710, 5711, 5716})
    old     = float(baseline.avg_fail_rate or 0)
    baseline.avg_fail_rate = round(old * (1 - alpha) + is_fail * alpha, 4)

    # Update avg daily events (EWMA)
    daily_event_count = len(recent) + 1
    old_avg = float(baseline.avg_daily_events or 0)
    baseline.avg_daily_events = round(old_avg * 0.95 + daily_event_count * 0.05, 2)

    baseline.updated_at = datetime.now(timezone.utc)


# ── Host-based UEBA detectors ─────────────────────────────────────────────────

async def _analyse_host_alert(
    db: AsyncSession,
    alert: dict,
    recent_alerts: list[dict],
    incident_id: str,
    host_entity: str,
) -> list[UEBAAnomaly]:
    """Host-centric UEBA detectors when no username is available.

    Detectors:
      • multi_host_burst     — same agent seen talking to 4+ peers in 10 min
      • impossible_travel    — same agent_id appearing on two IPs within 2 min
      • C2 beaconing pattern — repeated outbound events at narrow time variance
    """
    anomalies: list = []
    ts       = alert['timestamp']
    agent_id = alert['agent_id']

    # ── Multi-host burst (host touches 4+ agents in 10 min) ───────────────────
    burst_cutoff = ts - timedelta(minutes=10)
    burst_agents = {a['agent_id'] for a in recent_alerts if a['timestamp'] >= burst_cutoff}
    burst_agents.add(agent_id)
    if len(burst_agents) >= 4:
        anomalies.append(await _record_anomaly(
            db, host_entity, 'multi_host_burst',
            f"Host-based burst: activity across {len(burst_agents)} agents in 10 min: "
            f"{', '.join(list(burst_agents)[:4])}",
            incident_id, [alert.get('wazuh_id')],
        ))

    # ── Impossible travel (same host appears on two src_ips within 2 min) ─────
    travel_window = timedelta(minutes=2)
    current_ip = alert.get('src_ip')
    if current_ip:
        recent_ips = {
            a.get('src_ip') for a in recent_alerts
            if a.get('src_ip')
            and a['agent_id'] == agent_id
            and ts - a['timestamp'] <= travel_window
            and a.get('src_ip') != current_ip
        }
        if recent_ips:
            anomalies.append(await _record_anomaly(
                db, host_entity, 'impossible_travel',
                f"Agent {alert.get('agent_name', agent_id)} seen from {current_ip} "
                f"and {next(iter(recent_ips))} within 2 minutes",
                incident_id, [alert.get('wazuh_id')],
            ))

    # ── C2 beaconing pattern (≥5 outbound events with tight inter-arrival) ────
    # Look for repeated network/outbound events with low time variance
    outbound_ts = sorted(
        a['timestamp'] for a in recent_alerts
        if a['agent_id'] == agent_id
        and a.get('rule_id', 0) >= 18100   # generic outbound / network rule range
    )
    if len(outbound_ts) >= 5:
        intervals = [
            (outbound_ts[i + 1] - outbound_ts[i]).total_seconds()
            for i in range(len(outbound_ts) - 1)
        ]
        avg_iv = sum(intervals) / len(intervals)
        if avg_iv > 0:
            variance = sum((x - avg_iv) ** 2 for x in intervals) / len(intervals)
            cv = (variance ** 0.5) / avg_iv   # coefficient of variation
            if cv < 0.25 and avg_iv < 600:   # tight interval < 10 min
                anomalies.append(await _record_anomaly(
                    db, host_entity, 'multi_host_burst',
                    f"C2 beaconing pattern on {alert.get('agent_name', agent_id)}: "
                    f"{len(outbound_ts)} outbound events, avg interval {avg_iv:.0f}s (CV={cv:.2f})",
                    incident_id, [alert.get('wazuh_id')],
                ))

    if anomalies:
        log.info('ueba_host_anomalies', host=host_entity, count=len(anomalies),
                 types=[a.anomaly_type for a in anomalies])

    return anomalies
