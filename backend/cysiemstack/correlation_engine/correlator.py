"""
correlator.py
10 temporal correlation rules — MITRE ATT&CK aligned.

Each rule inspects the full alert list of an incident and pattern-matches
sequences of events that indicate a known attack chain. When fired, the
rule appends itself to incident.correlated_rules and may escalate severity.
"""
from typing import Optional
from datetime import timedelta
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models import Alert, Incident

log = structlog.get_logger()

# ── ENH-2: MITRE ATT&CK kill chain stage map ─────────────────────────────────
KILL_CHAIN_MAP = {
    'Reconnaissance':        1,
    'Resource Development':  2,
    'Initial Access':        3,
    'Execution':             4,
    'Persistence':           5,
    'Privilege Escalation':  6,
    'Defense Evasion':       7,
    'Credential Access':     8,
    'Discovery':             9,
    'Lateral Movement':      10,
    'Collection':            11,
    'Exfiltration':          12,
    'Impact':                13,
}


def _update_kill_chain(incident, tactics: list) -> None:
    """Update incident kill chain to the furthest MITRE tactic stage reached."""
    for tactic in tactics:
        stage = KILL_CHAIN_MAP.get(tactic, 0)
        if stage > (incident.kill_chain_stage or 0):
            incident.kill_chain_stage      = stage
            incident.kill_chain_stage_name = tactic



class CorrelationRule:
    def __init__(self, rule_id, name, description, severity, tactics, window_minutes):
        self.rule_id     = rule_id
        self.name        = name
        self.description = description
        self.severity    = severity
        self.tactics     = tactics
        self.window      = timedelta(minutes=window_minutes)

    def match(self, alerts: list[dict]) -> Optional[dict]:
        raise NotImplementedError


# ── CR-001: SSH Brute Force → Successful Login ────────────────────────────────
class SSHBruteForceLogin(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-001', 'SSH Brute Force → Login',
            'Multiple SSH failures followed by successful authentication',
            'high', ['Credential Access', 'Initial Access'], 15
        )

    def match(self, alerts):
        failures = [a for a in alerts if a['rule_id'] in (5710, 5711, 5716)]
        success  = [a for a in alerts if a['rule_id'] in (5715, 5718)]
        if len(failures) >= 5 and success:
            return {
                'key_alert_ids': [failures[0].get('wazuh_id'), success[0].get('wazuh_id')],
                'detail': f"{len(failures)} SSH failures then success on {success[0].get('agent_name')}",
                'confidence': min(len(failures) / 20.0, 1.0),
            }
        return None


# ── CR-002: Login → Privilege Escalation ─────────────────────────────────────
class LoginPrivEsc(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-002', 'Login → Privilege Escalation',
            'Authentication followed by sudo/su privilege escalation',
            'high', ['Privilege Escalation'], 30
        )

    def match(self, alerts):
        logins  = [a for a in alerts if a['rule_id'] in (5715, 5718) and a.get('username')]
        privesc = [a for a in alerts if a['rule_id'] in (5400, 5402, 18101, 18104)]
        for login in logins:
            for pe in privesc:
                if (pe.get('agent_id') == login.get('agent_id') and
                        pe['timestamp'] > login['timestamp']):
                    return {
                        'key_alert_ids': [login.get('wazuh_id'), pe.get('wazuh_id')],
                        'detail': f"User {login.get('username')} logged in then escalated on {login.get('agent_name')}",
                        'confidence': 0.85,
                    }
        return None


# ── CR-003: Full Compromise Chain ────────────────────────────────────────────
class FullCompromiseChain(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-003', 'Full Compromise Chain',
            'Auth → PrivEsc → FIM/Malware — complete attack chain',
            'critical', ['Initial Access', 'Privilege Escalation', 'Execution', 'Impact'], 90
        )

    def match(self, alerts):
        auth    = [a for a in alerts if a['rule_id'] in (5715, 5718)]
        privesc = [a for a in alerts if a['rule_id'] in (5400, 18101, 18104)]
        impact  = [a for a in alerts if a.get('category') in ('fim', 'malware')]
        if not (auth and privesc and impact):
            return None
        hosts = (set(a['agent_id'] for a in auth) &
                 set(a['agent_id'] for a in privesc) &
                 set(a['agent_id'] for a in impact))
        if hosts:
            h = list(hosts)[0]
            return {
                'key_alert_ids': [
                    next(a.get('wazuh_id') for a in auth if a['agent_id'] == h),
                    next(a.get('wazuh_id') for a in privesc if a['agent_id'] == h),
                    next(a.get('wazuh_id') for a in impact if a['agent_id'] == h),
                ],
                'detail': f"Full chain on {h}: auth → privesc → {impact[0].get('category')}",
                'confidence': 1.0,
            }
        return None


# ── CR-004: Web Exploitation → File System Change ────────────────────────────
class WebToFIM(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-004', 'Web Exploit → File Modification',
            'Web attack alert followed by file system change (FIM)',
            'high', ['Initial Access', 'Persistence'], 30
        )

    def match(self, alerts):
        web = [a for a in alerts if a.get('category') == 'web' and
               any(k in (a.get('rule_desc') or '').lower()
                   for k in ('attack', 'exploit', 'traversal', 'injection', 'rce', 'shell'))]
        fim = [a for a in alerts if a.get('category') == 'fim']
        if web and fim:
            return {
                'key_alert_ids': [web[0].get('wazuh_id'), fim[0].get('wazuh_id')],
                'detail': f"Web attack then FIM change on {web[0].get('agent_name')}",
                'confidence': 0.80,
            }
        return None


# ── CR-005: Lateral Movement ─────────────────────────────────────────────────
class LateralMovement(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-005', 'Lateral Movement',
            'Same source IP successfully authenticated to 3+ different hosts',
            'high', ['Lateral Movement'], 360
        )

    def match(self, alerts):
        logins = [a for a in alerts if a['rule_id'] in (5715, 5718) and a.get('src_ip')]
        if not logins:
            return None
        by_src: dict = {}
        for alert in logins:
            src = alert['src_ip']
            by_src.setdefault(src, set()).add(alert['agent_id'])
        for src, hosts in by_src.items():
            if len(hosts) >= 3:
                related = [a for a in logins if a['src_ip'] == src]
                return {
                    'key_alert_ids': [a.get('wazuh_id') for a in related[:3]],
                    'detail': f"Source {src} reached {len(hosts)} hosts",
                    'confidence': min(len(hosts) / 5.0, 1.0),
                }
        return None


# ── CR-006: Host Takeover ─────────────────────────────────────────────────────
class HostTakeover(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-006', 'Host Takeover',
            'Rootkit + FIM + anomalous process — host likely fully compromised',
            'critical', ['Defense Evasion', 'Persistence'], 60
        )

    def match(self, alerts):
        rootkit = [a for a in alerts if 510 <= a['rule_id'] <= 535]
        fim     = [a for a in alerts if a.get('category') == 'fim']
        procs   = [a for a in alerts if a.get('category') == 'malware']
        if rootkit and fim:
            return {
                'key_alert_ids': [rootkit[0].get('wazuh_id'), fim[0].get('wazuh_id')],
                'detail': f"Rootkit + FIM activity on {rootkit[0].get('agent_name')}",
                'confidence': 0.95,
            }
        return None


# ── CR-007: Account Creation → Login ─────────────────────────────────────────
class AccountCreationLogin(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-007', 'Account Creation → Login',
            'New account created, then same account logs in (persistence indicator)',
            'medium', ['Persistence'], 120
        )

    def match(self, alerts):
        created = [a for a in alerts if a['rule_id'] in (5902, 5903) and a.get('username')]
        logins  = [a for a in alerts if a['rule_id'] in (5715, 5718) and a.get('username')]
        for c in created:
            for l in logins:
                if c['username'] == l['username'] and l['timestamp'] > c['timestamp']:
                    return {
                        'key_alert_ids': [c.get('wazuh_id'), l.get('wazuh_id')],
                        'detail': f"Account {c['username']} created then used",
                        'confidence': 0.75,
                    }
        return None


# ── CR-008: Port Scan → Exploitation Attempt ─────────────────────────────────
class ScanThenExploit(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-008', 'Port Scan → Exploitation',
            'Network scan activity followed by exploitation attempt',
            'high', ['Reconnaissance'], 30
        )

    def match(self, alerts):
        scans   = [a for a in alerts if a.get('category') == 'scan']
        exploits = [a for a in alerts if
                    any(k in (a.get('rule_desc') or '').lower()
                        for k in ('exploit', 'attack', 'injection', 'overflow', 'rce'))]
        if scans and exploits:
            return {
                'key_alert_ids': [scans[0].get('wazuh_id'), exploits[0].get('wazuh_id')],
                'detail': f"Scan from {scans[0].get('src_ip')} then exploit attempt",
                'confidence': 0.70,
            }
        return None


# ── CR-009: Data Exfiltration Indicators ─────────────────────────────────────
class DataExfiltration(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-009', 'Data Exfiltration Indicators',
            'Large outbound transfer + file access + external connection patterns',
            'high', ['Exfiltration'], 60
        )

    def match(self, alerts):
        fim = [a for a in alerts if a.get('category') == 'fim']
        net = [a for a in alerts if
               any(k in (a.get('rule_desc') or '').lower()
                   for k in ('outbound', 'transfer', 'upload', 'curl', 'wget', 'scp', 'rsync'))]
        if fim and net:
            return {
                'key_alert_ids': [fim[0].get('wazuh_id'), net[0].get('wazuh_id')],
                'detail': f"FIM activity + network transfer on {fim[0].get('agent_name')}",
                'confidence': 0.80,
            }
        return None


# ── CR-010: Service Account Anomaly ──────────────────────────────────────────
class ServiceAccountAnomaly(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-010', 'Service Account Anomaly',
            'Service account (daemon/svc/system) performing interactive or unusual activity',
            'medium', ['Defense Evasion', 'Privilege Escalation'], 30
        )

    SERVICE_PATTERNS = ('svc_', 'svc-', 'daemon', 'service', 'system', '_svc', '-svc')

    def match(self, alerts):
        svc_alerts = [
            a for a in alerts
            if a.get('username') and
            any(p in a['username'].lower() for p in self.SERVICE_PATTERNS) and
            a['rule_id'] in (5715, 5718, 5400, 5402)
        ]
        if len(svc_alerts) >= 2:
            return {
                'key_alert_ids': [a.get('wazuh_id') for a in svc_alerts[:2]],
                'detail': f"Service account {svc_alerts[0]['username']} doing interactive activity",
                'confidence': min(len(svc_alerts) / 4.0, 1.0),
            }
        return None



# ── CR-011: Windows Event Log Cleared ────────────────────────────────────────
class EventLogCleared(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-011', 'Event Log Cleared',
            'Windows security or system event log was cleared — common anti-forensics step',
            'high', ['Defense Evasion'], 20
        )

    def match(self, alerts):
        cleared = [a for a in alerts if a['rule_id'] in (18101, 18104, 60101, 60102)]
        if cleared:
            return {
                'key_alert_ids': [cleared[0].get('wazuh_id')],
                'detail': f"Event log cleared on {cleared[0].get('agent_name')}",
                'confidence': 0.95,
            }
        return None


# ── CR-012: DNS Tunnelling ────────────────────────────────────────────────────
class DNSTunnelling(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-012', 'DNS Tunnelling Indicator',
            'High-frequency DNS queries from single host — possible data exfil or C2',
            'medium', ['Exfiltration', 'Command and Control'], 10
        )

    def match(self, alerts):
        dns = [a for a in alerts if
               'dns' in (a.get('rule_desc') or '').lower() or
               a['rule_id'] in (82200, 82201, 82202)]
        by_host: dict = {}
        for a in dns:
            by_host.setdefault(a['agent_id'], []).append(a)
        for host, host_alerts in by_host.items():
            if len(host_alerts) >= 20:
                return {
                    'key_alert_ids': [host_alerts[0].get('wazuh_id')],
                    'detail': f"{len(host_alerts)} DNS queries from {host_alerts[0].get('agent_name')}",
                    'confidence': min(len(host_alerts) / 50.0, 1.0),
                }
        return None


# ── CR-013: Credential Dumping ────────────────────────────────────────────────
class CredentialDumping(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-013', 'Credential Dumping',
            'LSASS access or mimikatz indicators followed by new login from unknown IP',
            'critical', ['Credential Access'], 30
        )

    def match(self, alerts):
        dump = [a for a in alerts if
                any(k in (a.get('rule_desc') or '').lower()
                    for k in ('lsass', 'mimikatz', 'sekurlsa', 'credential dump', 'ntds'))]
        logins = [a for a in alerts if a['rule_id'] in (5715, 5718) and a.get('src_ip')]
        if dump and logins:
            return {
                'key_alert_ids': [dump[0].get('wazuh_id'), logins[0].get('wazuh_id')],
                'detail': f"Credential dump on {dump[0].get('agent_name')} then login from {logins[0].get('src_ip')}",
                'confidence': 0.90,
            }
        return None


# ── CR-014: Ransomware Indicators ─────────────────────────────────────────────
class RansomwareIndicators(CorrelationRule):
    RANSOM_EXTS = ('.encrypted', '.locked', '.ransom', '.crypt', '.enc', '.pay2decrypt')

    def __init__(self):
        super().__init__(
            'CR-014', 'Ransomware Indicators',
            'Mass FIM changes across multiple file types + outbound network activity',
            'critical', ['Impact'], 20
        )

    def match(self, alerts):
        fim = [a for a in alerts if a.get('category') == 'fim' and a.get('file_path')]
        encrypted = [a for a in fim if
                     any(a['file_path'].endswith(ext) for ext in self.RANSOM_EXTS) or
                     'ransom' in (a.get('rule_desc') or '').lower()]
        bulk_fim  = len(fim) >= 30
        net = [a for a in alerts if
               any(k in (a.get('rule_desc') or '').lower()
                   for k in ('outbound', 'external connection', 'wget', 'curl'))]
        if (encrypted or bulk_fim) and net:
            return {
                'key_alert_ids': [(encrypted or fim)[0].get('wazuh_id'), net[0].get('wazuh_id')],
                'detail': f"Mass FIM changes ({len(fim)}) + outbound connection — ransomware suspected",
                'confidence': 0.85 if encrypted else 0.65,
            }
        return None


# ── CR-015: C2 Beacon Detection ───────────────────────────────────────────────
class C2Beacon(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-015', 'C2 Beacon Pattern',
            'Periodic outbound connections to same IP at regular intervals — C2 beaconing',
            'high', ['Command and Control'], 120
        )

    def match(self, alerts):
        net = [a for a in alerts if
               a.get('src_ip') and (
                   a.get('category') == 'network' or
                   any(k in (a.get('rule_desc') or '').lower()
                       for k in ('outbound', 'connection established')))]
        if len(net) < 5:
            return None
        by_dst: dict = {}
        for a in net:
            dst = a.get('src_ip')
            if dst:
                by_dst.setdefault(dst, []).append(a['timestamp'])
        for dst, times in by_dst.items():
            if len(times) < 5:
                continue
            times_sorted = sorted(times)
            gaps = [(times_sorted[i + 1] - times_sorted[i]).seconds
                    for i in range(len(times_sorted) - 1)]
            avg_gap  = sum(gaps) / len(gaps)
            variance = sum((g - avg_gap) ** 2 for g in gaps) / len(gaps)
            if avg_gap > 30 and variance < (avg_gap * 0.3) ** 2:
                first = next(a for a in net if a.get('src_ip') == dst)
                return {
                    'key_alert_ids': [first.get('wazuh_id')],
                    'detail': f"Regular {int(avg_gap)}s beacon to {dst} from {first.get('agent_name')}",
                    'confidence': min(len(times) / 10.0, 1.0),
                }
        return None
# ── Rule registry ─────────────────────────────────────────────────────────────
ALL_RULES: list[CorrelationRule] = [
    SSHBruteForceLogin(),
    LoginPrivEsc(),
    FullCompromiseChain(),
    WebToFIM(),
    LateralMovement(),
    HostTakeover(),
    AccountCreationLogin(),
    ScanThenExploit(),
    DataExfiltration(),
    ServiceAccountAnomaly(),
    # ENH-5: new rules
    EventLogCleared(),
    DNSTunnelling(),
    CredentialDumping(),
    RansomwareIndicators(),
    C2Beacon(),
]


# ── Main runner ───────────────────────────────────────────────────────────────

async def run_correlation(
    db: AsyncSession,
    incident: Incident,
    new_alert: dict,
) -> list[dict]:
    """
    Run all correlation rules against the incident's full alert set.
    Updates incident.correlated_rules with any newly-fired rules.
    Returns list of newly-fired rule dicts.
    """
    # Fetch all alerts for this incident
    result = await db.execute(
        select(Alert).where(Alert.incident_id == incident.id)
    )
    db_alerts = result.scalars().all()

    alerts = [
        {
            'wazuh_id':   a.wazuh_id,
            'rule_id':    a.rule_id,
            'rule_desc':  a.rule_desc,
            'agent_id':   a.agent_id,
            'agent_name': a.agent_name,
            'username':   a.username,
            'src_ip':     str(a.src_ip) if a.src_ip else None,
            'category':   a.category,
            'timestamp':  a.timestamp,
            'base_score': float(a.base_score or 0),
        }
        for a in db_alerts
    ]

    already_fired = {r['rule_id'] for r in (incident.correlated_rules or [])}
    newly_fired   = []
    sev_order     = ['low', 'medium', 'high', 'critical']

    for rule in ALL_RULES:
        if rule.rule_id in already_fired:
            continue
        # ENH-4: filter alerts to this rule's specific time window
        if new_alert.get('timestamp'):
            window_cutoff  = new_alert['timestamp'] - rule.window
            windowed_alerts = [a for a in alerts if a['timestamp'] >= window_cutoff]
        else:
            windowed_alerts = alerts
        match = rule.match(windowed_alerts)
        if match:
            entry = {
                'rule_id':     rule.rule_id,
                'name':        rule.name,
                'description': rule.description,
                'severity':    rule.severity,
                'tactics':     rule.tactics,
                'detail':      match.get('detail', ''),
                'key_alerts':  match.get('key_alert_ids', []),
                'confidence':  match.get('confidence', 0.5),
            }
            newly_fired.append(entry)

            # Escalate incident severity
            if sev_order.index(rule.severity) > sev_order.index(incident.severity or 'low'):
                incident.severity = rule.severity

    if newly_fired:
        incident.correlated_rules = (incident.correlated_rules or []) + newly_fired
        await db.flush()
        log.info('correlation_fired',
                 incident_id=incident.id,
                 rules=[r['rule_id'] for r in newly_fired])

    return newly_fired
