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
    'Command and Control':   12,
    'Exfiltration':          13,
    'Impact':                14,
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
            earliest_web_ts = min(a['timestamp'] for a in web)
            # FIM change must occur AFTER the web attack — a co-occurring cron-triggered
            # file write would otherwise fire this rule on every deployment.
            post_attack_fim = [f for f in fim if f['timestamp'] > earliest_web_ts]
            if not post_attack_fim:
                return None
            return {
                'key_alert_ids': [web[0].get('wazuh_id'), post_attack_fim[0].get('wazuh_id')],
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
            earliest_fim_ts = min(a['timestamp'] for a in fim)
            # Network transfer must occur AFTER file access — a background system-update
            # network event would otherwise fire this rule alongside any FIM activity.
            post_fim_net = [n for n in net if n['timestamp'] > earliest_fim_ts]
            if not post_fim_net:
                return None
            return {
                'key_alert_ids': [fim[0].get('wazuh_id'), post_fim_net[0].get('wazuh_id')],
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


# =============================================================================
# CR-016 → CR-035  — Advanced detection rules
# =============================================================================

# ── CR-016: Password Spraying ─────────────────────────────────────────────────
class PasswordSpraying(CorrelationRule):
    def __init__(self):
        super().__init__(
            'CR-016', 'Password Spraying',
            '1 failed login attempt across 20+ different usernames from a single source IP',
            'high', ['Credential Access', 'Initial Access'], 5
        )

    def match(self, alerts):
        fails = [a for a in alerts if a['rule_id'] in (5710, 5711, 5716, 18102) and a.get('src_ip')]
        if not fails:
            return None
        by_src: dict = {}
        for a in fails:
            by_src.setdefault(a['src_ip'], set()).add(a.get('username') or a.get('agent_id', ''))
        for src, victims in by_src.items():
            if len(victims) >= 20:
                related = [a for a in fails if a['src_ip'] == src]
                return {
                    'key_alert_ids': [related[0].get('wazuh_id')],
                    'detail': f"Password spray from {src} targeting {len(victims)} accounts",
                    'confidence': min(len(victims) / 50.0, 1.0),
                }
        return None


# ── CR-017: Windows Brute Force → Successful Login ───────────────────────────
class WindowsBruteForce(CorrelationRule):
    """Windows Event 4625 failures → 4624 success — distinct from CR-001 (SSH only)."""
    WIN_FAIL    = {60122, 60123, 60204}   # EventID 4625 variants
    WIN_SUCCESS = {60106, 60137, 60138}   # EventID 4624 variants

    def __init__(self):
        super().__init__(
            'CR-017', 'Windows Brute Force → Login',
            'Multiple Windows auth failures (4625) followed by successful logon (4624)',
            'high', ['Credential Access', 'Initial Access'], 15
        )

    def match(self, alerts):
        fails   = [a for a in alerts if a['rule_id'] in self.WIN_FAIL]
        success = [a for a in alerts if a['rule_id'] in self.WIN_SUCCESS]
        if len(fails) >= 5 and success:
            return {
                'key_alert_ids': [fails[0].get('wazuh_id'), success[0].get('wazuh_id')],
                'detail': f"{len(fails)} Windows auth failures then success on {success[0].get('agent_name')}",
                'confidence': min(len(fails) / 20.0, 1.0),
            }
        return None


# ── CR-018: Dormant Account Rebirth ──────────────────────────────────────────
class DormantAccountRebirth(CorrelationRule):
    """Account inactive in the alert DB for 90+ days suddenly logs in."""
    DORMANT_DAYS = 90

    def __init__(self):
        super().__init__(
            'CR-018', 'Dormant Account Rebirth',
            f'Account with no activity for {DormantAccountRebirth.DORMANT_DAYS}+ days suddenly authenticates',
            'high', ['Initial Access', 'Persistence'], 60
        )

    # Auth failure rule IDs used for corroborating context check
    _AUTH_FAIL_IDS = frozenset({5710, 5711, 5716, 5719, 5720, 2502})

    def match(self, alerts):
        logins = [a for a in alerts if a['rule_id'] in (5715, 5718, 60106, 60137) and a.get('username')]
        if not logins:
            return None
        usernames_with_prior = {a.get('username') for a in alerts
                                if a['rule_id'] not in (5715, 5718, 60106, 60137)}
        for login in logins:
            uname = login.get('username')
            if uname and uname not in usernames_with_prior:
                prior_alerts = [a for a in alerts if a.get('username') == uname
                                and a.get('wazuh_id') != login.get('wazuh_id')]
                if not prior_alerts:
                    # A first-time login from a new employee or a fresh agent has no
                    # alert history either. Require at least one corroborating signal
                    # before treating this as a dormant-account rebirth:
                    #   • off-hours login (outside 07:00–19:00)
                    #   • external src_ip (already filtered to public IPs by normaliser)
                    #   • preceded by an auth failure from the same user
                    login_hour = login['timestamp'].hour
                    is_off_hours = not (7 <= login_hour <= 19)
                    has_external_ip = bool(login.get('src_ip'))
                    preceded_by_fail = any(
                        a.get('username') == uname and a['rule_id'] in self._AUTH_FAIL_IDS
                        for a in alerts
                    )
                    if not (is_off_hours or has_external_ip or preceded_by_fail):
                        continue
                    return {
                        'key_alert_ids': [login.get('wazuh_id')],
                        'detail': f"Account {uname} logged in with no prior activity in observation window",
                        'confidence': 0.72,
                    }
        return None


# ── CR-019: Domain Admin Group Modification ───────────────────────────────────
class DomainAdminGroupChange(CorrelationRule):
    """Windows Event 4732 — member added to privileged group."""
    WIN_GROUP_CHANGE = {60148, 60149, 60150, 60271, 60272}
    PRIV_GROUPS = ('domain admins', 'administrators', 'enterprise admins',
                   'schema admins', 'group policy creator', 'backup operators')

    def __init__(self):
        super().__init__(
            'CR-019', 'Privileged Group Membership Change',
            'Account added to Domain Admins, Administrators, or equivalent privileged group',
            'critical', ['Privilege Escalation', 'Persistence'], 60
        )

    def match(self, alerts):
        changes = [
            a for a in alerts
            if a['rule_id'] in self.WIN_GROUP_CHANGE or
            any(g in (a.get('rule_desc') or '').lower() for g in self.PRIV_GROUPS)
        ]
        if changes:
            return {
                'key_alert_ids': [changes[0].get('wazuh_id')],
                'detail': f"Privileged group change on {changes[0].get('agent_name')}: {changes[0].get('rule_desc', '')[:80]}",
                'confidence': 0.92,
            }
        return None


# ── CR-020: Kerberos / Golden Ticket Anomaly ──────────────────────────────────
class GoldenTicketAnomaly(CorrelationRule):
    """Kerberos TGS requests with anomalous lifetimes or encryption types."""
    KERB_IDS = {60210, 60211, 60212, 60213}  # Wazuh Kerberos rules (EventID 4769/4770)
    GOLDEN_KEYWORDS = ('rc4-hmac', '0x17', 'ticket lifetime', 'forwardable', 'renewable',
                       'golden ticket', 'kerberoast', 'pass-the-ticket')

    def __init__(self):
        super().__init__(
            'CR-020', 'Kerberos Ticket Anomaly',
            'Kerberos TGS request with suspicious encryption or lifetime — possible Golden Ticket',
            'critical', ['Credential Access', 'Lateral Movement'], 30
        )

    def match(self, alerts):
        kerb = [
            a for a in alerts
            if a['rule_id'] in self.KERB_IDS or
            any(k in (a.get('rule_desc') or '').lower() for k in self.GOLDEN_KEYWORDS)
        ]
        if kerb:
            return {
                'key_alert_ids': [kerb[0].get('wazuh_id')],
                'detail': f"Kerberos anomaly on {kerb[0].get('agent_name')}: {kerb[0].get('rule_desc', '')[:80]}",
                'confidence': 0.80,
            }
        return None


# ── CR-021: Registry Persistence ─────────────────────────────────────────────
class RegistryPersistence(CorrelationRule):
    """FIM alert on autorun registry keys followed by new process execution."""
    RUN_KEY_PATHS = (
        'currentversion\\run', 'currentversion\\runonce',
        'currentversion\\runservices', 'winlogon\\userinit',
        'policies\\explorer\\run',
    )

    def __init__(self):
        super().__init__(
            'CR-021', 'Registry Persistence',
            'Modification of autorun registry key (Run/RunOnce) indicating boot persistence',
            'high', ['Persistence'], 30
        )

    def match(self, alerts):
        reg = [
            a for a in alerts
            if (a.get('category') == 'fim' or 'registry' in (a.get('rule_desc') or '').lower()) and
            a.get('file_path') and
            any(k in (a['file_path'] or '').lower() for k in self.RUN_KEY_PATHS)
        ]
        if not reg:
            reg = [a for a in alerts if
                   any(k in (a.get('rule_desc') or '').lower()
                       for k in ('run key', 'runonce', 'autorun', 'registry persistence'))]
        if reg:
            return {
                'key_alert_ids': [reg[0].get('wazuh_id')],
                'detail': f"Registry autorun key modified on {reg[0].get('agent_name')}: {(reg[0].get('file_path') or '')[-60:]}",
                'confidence': 0.85,
            }
        return None


# ── CR-022: Scheduled Task Abuse ─────────────────────────────────────────────
class ScheduledTaskAbuse(CorrelationRule):
    """New scheduled task pointing to suspicious paths (Temp, AppData, Public)."""
    SUSPICIOUS_PATHS = ('\\temp\\', '\\appdata\\', '\\public\\', '\\programdata\\',
                        '/tmp/', '/var/tmp/', 'c:\\windows\\temp')
    TASK_RULE_IDS = {60280, 60281, 60282}  # Wazuh rules for EventID 4698/4702

    def __init__(self):
        super().__init__(
            'CR-022', 'Scheduled Task Abuse',
            'Scheduled task created or modified pointing to a suspicious temp/user-writable path',
            'high', ['Persistence', 'Execution'], 30
        )

    def match(self, alerts):
        tasks = [
            a for a in alerts
            if (a['rule_id'] in self.TASK_RULE_IDS or
                any(k in (a.get('rule_desc') or '').lower()
                    for k in ('scheduled task', 'task scheduler', 'schtask'))) and
            any(p in ((a.get('rule_desc') or '') + (a.get('file_path') or '')).lower()
                for p in self.SUSPICIOUS_PATHS)
        ]
        if tasks:
            return {
                'key_alert_ids': [tasks[0].get('wazuh_id')],
                'detail': f"Suspicious scheduled task on {tasks[0].get('agent_name')}: {tasks[0].get('rule_desc', '')[:80]}",
                'confidence': 0.80,
            }
        return None


# ── CR-023: Process Injection (Browser → System Process) ──────────────────────
class ProcessInjection(CorrelationRule):
    """Browser or Office app spawning a shell/system process — classic injection."""
    PARENT_PROCS = ('chrome.exe', 'msedge.exe', 'firefox.exe', 'iexplore.exe',
                    'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe')
    CHILD_PROCS  = ('cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                    'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe')

    def __init__(self):
        super().__init__(
            'CR-023', 'Process Injection Indicator',
            'Browser or Office process spawning a system/shell process as child',
            'high', ['Defense Evasion', 'Execution'], 15
        )

    def match(self, alerts):
        injection = [
            a for a in alerts
            if any(p in (a.get('rule_desc') or '').lower() for p in self.PARENT_PROCS) and
               any(c in (a.get('rule_desc') or '').lower() for c in self.CHILD_PROCS)
        ]
        if not injection:
            injection = [
                a for a in alerts
                if a.get('process_name') and
                   any(p in a['process_name'].lower() for p in self.CHILD_PROCS) and
                   any(k in (a.get('rule_desc') or '').lower()
                       for k in ('parent', 'spawned by', 'child process'))
            ]
        if injection:
            return {
                'key_alert_ids': [injection[0].get('wazuh_id')],
                'detail': f"Suspicious parent→child process on {injection[0].get('agent_name')}: {injection[0].get('rule_desc', '')[:80]}",
                'confidence': 0.85,
            }
        return None


# ── CR-024: Suspicious Encoded Command (Living off the Land) ──────────────────
class EncodedCommandExecution(CorrelationRule):
    """PowerShell -EncodedCommand / -enc — LOLBin execution technique."""
    LOL_KEYWORDS = ('-encodedcommand', '-enc ', 'encodedcommand', 'frombase64string',
                    'iex(', 'invoke-expression', 'downloadstring', 'hidden -w', 'bypass')

    def __init__(self):
        super().__init__(
            'CR-024', 'Encoded / Obfuscated Command Execution',
            'PowerShell or script interpreter executing a Base64-encoded or obfuscated command',
            'high', ['Execution', 'Defense Evasion'], 20
        )

    def match(self, alerts):
        lol = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() for k in self.LOL_KEYWORDS) or
               any(k in (a.get('raw_log') or '').lower() for k in self.LOL_KEYWORDS)
        ]
        if lol:
            return {
                'key_alert_ids': [lol[0].get('wazuh_id')],
                'detail': f"Obfuscated command on {lol[0].get('agent_name')}: {lol[0].get('rule_desc', '')[:80]}",
                'confidence': 0.88,
            }
        return None


# ── CR-025: Web Shell Execution ───────────────────────────────────────────────
class WebShellExecution(CorrelationRule):
    """Web server process (IIS/Apache) spawning a shell — classic web shell."""
    WEB_PROCS   = ('w3wp.exe', 'httpd', 'apache2', 'nginx', 'php-fpm', 'tomcat')
    SHELL_PROCS = ('cmd.exe', 'powershell.exe', 'bash', 'sh', 'python', 'perl', 'ruby')

    def __init__(self):
        super().__init__(
            'CR-025', 'Web Shell Execution',
            'Web server process spawning a system shell — likely web shell activity',
            'critical', ['Initial Access', 'Execution', 'Persistence'], 20
        )

    def match(self, alerts):
        webshell = [
            a for a in alerts
            if any(w in (a.get('rule_desc') or '').lower() for w in self.WEB_PROCS) and
               any(s in (a.get('rule_desc') or '').lower() for s in self.SHELL_PROCS)
        ]
        if not webshell:
            webshell = [a for a in alerts if
                        any(k in (a.get('rule_desc') or '').lower()
                            for k in ('web shell', 'webshell', 'shell upload'))]
        if webshell:
            return {
                'key_alert_ids': [webshell[0].get('wazuh_id')],
                'detail': f"Web shell on {webshell[0].get('agent_name')}: {webshell[0].get('rule_desc', '')[:80]}",
                'confidence': 0.95,
            }
        return None


# ── CR-026: Security Tool Disabled ───────────────────────────────────────────
class SecurityToolDisabled(CorrelationRule):
    """AV/EDR/firewall service stopped or disabled."""
    SECURITY_SERVICES = ('wdefend', 'windefend', 'mssecflt', 'sense', 'mssense',
                         'carbonblack', 'crowdstrike', 'cylance', 'sophos', 'eset',
                         'symantec', 'mcafee', 'trend', 'avast', 'kaspersky',
                         'ufw', 'firewalld', 'iptables')
    STOP_IDS = {7036, 7045, 60100, 60101}  # Service control manager rules

    def __init__(self):
        super().__init__(
            'CR-026', 'Security Tool Disabled',
            'AV, EDR or firewall service stopped or disabled — anti-forensic step',
            'critical', ['Defense Evasion'], 15
        )

    def match(self, alerts):
        disabled = [
            a for a in alerts
            if (a['rule_id'] in self.STOP_IDS or
                any(k in (a.get('rule_desc') or '').lower()
                    for k in ('service stopped', 'service disabled', 'antivirus disabled'))) and
            any(s in (a.get('rule_desc') or '').lower() for s in self.SECURITY_SERVICES)
        ]
        if not disabled:
            disabled = [a for a in alerts if
                        any(k in (a.get('rule_desc') or '').lower()
                            for k in ('tamper protection', 'real-time protection disabled',
                                      'windows defender disabled', 'av disabled'))]
        if disabled:
            return {
                'key_alert_ids': [disabled[0].get('wazuh_id')],
                'detail': f"Security service disabled on {disabled[0].get('agent_name')}: {disabled[0].get('rule_desc', '')[:80]}",
                'confidence': 0.95,
            }
        return None


# ── CR-027: Unusual Outbound Port ─────────────────────────────────────────────
class UnusualOutboundPort(CorrelationRule):
    """Internal host connecting outbound on classic malware/C2 ports."""
    SUSPICIOUS_PORTS = ('4444', '1234', '6667', '6666', '9001', '9002',
                        '31337', '1337', '8888', '2222')

    def __init__(self):
        super().__init__(
            'CR-027', 'Unusual Outbound Port',
            'Outbound connection on a port commonly associated with malware, RATs or C2 frameworks',
            'high', ['Command and Control'], 30
        )

    def match(self, alerts):
        suspicious = [
            a for a in alerts
            if a.get('src_ip') and
               any(f':{p}' in (a.get('rule_desc') or '') or
                   f'port {p}' in (a.get('rule_desc') or '').lower() or
                   f'dstport={p}' in (a.get('raw_log') or '').lower()
                   for p in self.SUSPICIOUS_PORTS)
        ]
        if suspicious:
            return {
                'key_alert_ids': [suspicious[0].get('wazuh_id')],
                'detail': f"Unusual outbound port from {suspicious[0].get('agent_name')}: {suspicious[0].get('rule_desc', '')[:80]}",
                'confidence': 0.78,
            }
        return None


# ── CR-028: RDP to Internet ───────────────────────────────────────────────────
class RDPToInternet(CorrelationRule):
    """Internal host initiating RDP (3389) connection to an external IP."""
    def __init__(self):
        super().__init__(
            'CR-028', 'RDP to External Host',
            'Internal workstation connecting outbound on port 3389 (RDP) to internet IP',
            'high', ['Lateral Movement', 'Exfiltration'], 30
        )

    def match(self, alerts):
        rdp_out = [
            a for a in alerts
            if a.get('src_ip') and (
                ':3389' in (a.get('rule_desc') or '') or
                'port 3389' in (a.get('rule_desc') or '').lower() or
                'rdp' in (a.get('rule_desc') or '').lower()
            ) and
            any(k in (a.get('rule_desc') or '').lower()
                for k in ('outbound', 'egress', 'connection established', 'attempted'))
        ]
        if rdp_out:
            return {
                'key_alert_ids': [rdp_out[0].get('wazuh_id')],
                'detail': f"Outbound RDP from {rdp_out[0].get('agent_name')} to {rdp_out[0].get('src_ip')}",
                'confidence': 0.82,
            }
        return None


# ── CR-029: Internal Subnet Scanning ─────────────────────────────────────────
class InternalSubnetScan(CorrelationRule):
    """Single host contacting 20+ internal IPs in a short window."""
    def __init__(self):
        super().__init__(
            'CR-029', 'Internal Subnet Scan',
            'Single host scanning its own subnet — reconnaissance or worm propagation',
            'medium', ['Discovery', 'Reconnaissance'], 10
        )

    def match(self, alerts):
        scan_alerts = [
            a for a in alerts
            if a.get('category') == 'scan' or
               any(k in (a.get('rule_desc') or '').lower()
                   for k in ('port scan', 'host scan', 'sweep', 'arp scan', 'ping sweep'))
        ]
        by_host: dict = {}
        for a in scan_alerts:
            by_host.setdefault(a['agent_id'], []).append(a)
        for host, host_alerts in by_host.items():
            if len(host_alerts) >= 20:
                return {
                    'key_alert_ids': [host_alerts[0].get('wazuh_id')],
                    'detail': f"{len(host_alerts)} scan events from {host_alerts[0].get('agent_name')} on internal subnet",
                    'confidence': min(len(host_alerts) / 50.0, 1.0),
                }
        return None


# ── CR-030: Large Upload to Cloud Storage ────────────────────────────────────
class LargeCloudUpload(CorrelationRule):
    """Sustained outbound to known cloud storage domains."""
    CLOUD_HOSTS = ('mega.nz', 'mega.co.nz', 'dropbox.com', 'drive.google.com',
                   'onedrive.live.com', 'box.com', 'wetransfer.com', 'anonfiles.com',
                   'gofile.io', 'transfer.sh', 'filebin.net', 'mediafire.com')

    def __init__(self):
        super().__init__(
            'CR-030', 'Large Upload to Cloud Storage',
            'Multiple outbound connections to cloud storage / file-sharing services — possible exfiltration',
            'high', ['Exfiltration'], 30
        )

    def match(self, alerts):
        uploads = [
            a for a in alerts
            if any(host in (a.get('rule_desc') or '').lower() or
                   host in (a.get('raw_log') or '').lower()
                   for host in self.CLOUD_HOSTS)
        ]
        by_host: dict = {}
        for a in uploads:
            by_host.setdefault(a['agent_id'], []).append(a)
        for host, host_alerts in by_host.items():
            if len(host_alerts) >= 3:
                return {
                    'key_alert_ids': [host_alerts[0].get('wazuh_id')],
                    'detail': f"{len(host_alerts)} cloud storage connections from {host_alerts[0].get('agent_name')}",
                    'confidence': min(len(host_alerts) / 10.0, 0.9),
                }
        return None


# ── CR-031: Cloud Console Login without MFA ──────────────────────────────────
class CloudLoginNoMFA(CorrelationRule):
    """AWS ConsoleLogin with mfaUsed=No, or Azure AD login MFA bypass."""
    def __init__(self):
        super().__init__(
            'CR-031', 'Cloud Console Login without MFA',
            'AWS or Azure console login where MFA was not used — policy violation',
            'high', ['Initial Access'], 30
        )

    def match(self, alerts):
        no_mfa = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower()
                   for k in ('mfaused: no', 'mfa not used', 'without mfa',
                              'console login', 'mfa bypass', 'no mfa'))
        ]
        if no_mfa:
            return {
                'key_alert_ids': [no_mfa[0].get('wazuh_id')],
                'detail': f"Cloud login without MFA: {no_mfa[0].get('rule_desc', '')[:80]}",
                'confidence': 0.90,
            }
        return None


# ── CR-032: Privileged Cloud IAM Change ──────────────────────────────────────
class CloudIAMPrivilegeChange(CorrelationRule):
    """AWS CreateUser+AttachPolicy(Admin) or Azure AD global admin role assignment."""
    IAM_KEYWORDS = ('administratoraccess', 'global administrator', 'privileged role',
                    'createuser', 'attachuserpolicy', 'add member to role',
                    'iam admin', 'owner role assigned')

    def __init__(self):
        super().__init__(
            'CR-032', 'Privileged Cloud IAM Change',
            'New admin user or admin policy attached in AWS/Azure without change record',
            'critical', ['Privilege Escalation', 'Persistence'], 60
        )

    def match(self, alerts):
        iam = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() for k in self.IAM_KEYWORDS)
        ]
        if iam:
            return {
                'key_alert_ids': [iam[0].get('wazuh_id')],
                'detail': f"Cloud IAM privilege change: {iam[0].get('rule_desc', '')[:80]}",
                'confidence': 0.88,
            }
        return None


# ── CR-033: Mass Cloud Resource Deletion ─────────────────────────────────────
class MassCloudDeletion(CorrelationRule):
    """5+ cloud resource deletion events within 10 minutes."""
    DELETE_KEYWORDS = ('deletebucket', 'deleteobject', 'dropbucket',
                       'storageaccounts/delete', 'delete blob', 'deleteinstance',
                       's3 bucket deleted', 'resource deleted')

    def __init__(self):
        super().__init__(
            'CR-033', 'Mass Cloud Resource Deletion',
            '5+ cloud storage or resource deletion events — potential destructive attack or data wipe',
            'critical', ['Impact'], 10
        )

    def match(self, alerts):
        deletes = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() for k in self.DELETE_KEYWORDS)
        ]
        if len(deletes) >= 5:
            return {
                'key_alert_ids': [deletes[0].get('wazuh_id')],
                'detail': f"{len(deletes)} cloud resource deletions in window",
                'confidence': min(len(deletes) / 10.0, 1.0),
            }
        return None


# ── CR-034: Mail Forwarding Rule Created ─────────────────────────────────────
class MailForwardingRule(CorrelationRule):
    """O365 / Exchange inbox rule forwarding mail to external address."""
    FWD_KEYWORDS = ('new-inboxrule', 'forwardto', 'forwardsmbcc', 'redirectto',
                    'mail forward', 'forwarding rule', 'inbox rule', 'auto-forward')

    def __init__(self):
        super().__init__(
            'CR-034', 'Suspicious Mail Forwarding Rule',
            'Inbox forwarding rule created directing mail to external address — BEC indicator',
            'high', ['Collection', 'Exfiltration'], 60
        )

    def match(self, alerts):
        fwd = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() for k in self.FWD_KEYWORDS)
        ]
        if fwd:
            return {
                'key_alert_ids': [fwd[0].get('wazuh_id')],
                'detail': f"Mail forwarding rule created: {fwd[0].get('rule_desc', '')[:80]}",
                'confidence': 0.88,
            }
        return None


# ── CR-035: OAuth App Consent Grant ──────────────────────────────────────────
class OAuthConsentGrant(CorrelationRule):
    """Azure AD / O365 user grants 3rd-party app broad permissions."""
    CONSENT_KEYWORDS = ('consent to application', 'app consent', 'oauth consent',
                        'mail.read', 'files.readwrite', 'contacts.read',
                        'application permission granted', 'delegated permission')

    def __init__(self):
        super().__init__(
            'CR-035', 'Suspicious OAuth App Consent',
            'User granted 3rd-party app permissions to read mail, files or contacts — OAuth phishing',
            'high', ['Collection', 'Initial Access'], 60
        )

    def match(self, alerts):
        consent = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() for k in self.CONSENT_KEYWORDS)
        ]
        if consent:
            return {
                'key_alert_ids': [consent[0].get('wazuh_id')],
                'detail': f"OAuth consent grant: {consent[0].get('rule_desc', '')[:80]}",
                'confidence': 0.85,
            }
        return None


# =============================================================================
# CR-036 → CR-055  — Gap-closure rules (MITRE coverage expansion)
# =============================================================================

# ── CR-036: WMI Command Execution ─────────────────────────────────────────────
class WMIExecution(CorrelationRule):
    """WMI used to execute commands remotely or spawn processes (T1047)."""
    WMI_KEYWORDS = ('wmic ', 'wmic.exe', 'wmiprvse', 'winmgmt',
                    'win32_process create', 'wmi commandlinetemplate',
                    'wbemexec', 'invokewmimethod', 'invoke-wmimethodf')

    def __init__(self):
        super().__init__(
            'CR-036', 'WMI Command Execution',
            'WMI used to execute processes or commands — T1047 lateral execution vector',
            'high', ['Execution', 'Lateral Movement'], 30
        )

    def match(self, alerts):
        wmi = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() or k in (a.get('raw_log') or '').lower()
                   for k in self.WMI_KEYWORDS)
        ]
        if wmi:
            return {
                'key_alert_ids': [wmi[0].get('wazuh_id')],
                'detail': f"WMI execution on {wmi[0].get('agent_name')}: {wmi[0].get('rule_desc', '')[:80]}",
                'confidence': 0.85,
            }
        return None


# ── CR-037: Pass-the-Hash / NTLM Relay ────────────────────────────────────────
class PassTheHash(CorrelationRule):
    """NTLM authentication with mismatched logon type or tool signatures (T1550.002)."""
    PTH_KEYWORDS = ('pass-the-hash', 'pass the hash', 'ntlm relay', 'ntlmrelayx',
                    'impacket', 'wce.exe', 'mimikatz sekurlsa::pth',
                    'logon type 3', 'logon type: 3')
    PTH_RULE_IDS = {60106, 60122, 60137, 60204}  # Windows logon type 3 without Kerberos

    def __init__(self):
        super().__init__(
            'CR-037', 'Pass-the-Hash / NTLM Lateral Auth',
            'NTLM pass-the-hash pattern — network logon without password entry (T1550.002)',
            'critical', ['Lateral Movement', 'Credential Access'], 30
        )

    def match(self, alerts):
        pth = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() for k in self.PTH_KEYWORDS)
        ]
        if pth:
            return {
                'key_alert_ids': [pth[0].get('wazuh_id')],
                'detail': f"Pass-the-hash indicator on {pth[0].get('agent_name')}: {pth[0].get('rule_desc', '')[:80]}",
                'confidence': 0.88,
            }
        # Heuristic: Logon type 3 from an anomalous source arriving after a cred dump
        ntlm_logons = [a for a in alerts if a['rule_id'] in self.PTH_RULE_IDS and a.get('src_ip')]
        cred_dump   = [a for a in alerts if
                       any(k in (a.get('rule_desc') or '').lower()
                           for k in ('lsass', 'mimikatz', 'credential dump', 'ntds'))]
        if ntlm_logons and cred_dump:
            return {
                'key_alert_ids': [cred_dump[0].get('wazuh_id'), ntlm_logons[0].get('wazuh_id')],
                'detail': f"Cred dump followed by NTLM network logon from {ntlm_logons[0].get('src_ip')}",
                'confidence': 0.80,
            }
        return None


# ── CR-038: MFA Push Bombing / Fatigue ────────────────────────────────────────
class MFAPushBombing(CorrelationRule):
    """10+ MFA prompts to same user in short window with no failure (T1621)."""
    MFA_PROMPT_KEYWORDS = ('mfa prompt', 'push notification', 'authenticator request',
                           'duo push', 'mfa challenge', 'mfa request sent',
                           'second factor required', 'otp sent', 'verification code sent')
    MFA_SUCCESS_KEYWORDS = ('mfa approved', 'mfa accepted', 'second factor success',
                            'authentication succeeded', 'mfa success')

    def __init__(self):
        super().__init__(
            'CR-038', 'MFA Push Bombing / Fatigue',
            '10+ MFA prompts to same user without failure — push bombing to wear down target (T1621)',
            'high', ['Credential Access', 'Initial Access'], 30
        )

    def match(self, alerts):
        mfa_prompts = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() for k in self.MFA_PROMPT_KEYWORDS)
            and a.get('username')
        ]
        if not mfa_prompts:
            return None
        by_user: dict = {}
        for a in mfa_prompts:
            by_user.setdefault(a['username'], []).append(a)
        for user, user_alerts in by_user.items():
            if len(user_alerts) >= 10:
                return {
                    'key_alert_ids': [user_alerts[0].get('wazuh_id')],
                    'detail': f"MFA push bombing: {len(user_alerts)} prompts to {user} in 30-min window",
                    'confidence': min(len(user_alerts) / 20.0, 1.0),
                }
        return None


# ── CR-039: Session Cookie / Token Theft ──────────────────────────────────────
class SessionCookieTheft(CorrelationRule):
    """Web session from new geo/IP immediately after login elsewhere (T1539, T1528)."""
    COOKIE_KEYWORDS = ('cookie theft', 'session hijack', 'token replay', 'stolen token',
                       'session_id from new ip', 'session fixation', 'pass-the-cookie')

    def __init__(self):
        super().__init__(
            'CR-039', 'Session Cookie / Token Theft',
            'Web session reuse from a new IP/geo without re-authentication — T1539/T1528',
            'high', ['Credential Access', 'Initial Access'], 60
        )

    def match(self, alerts):
        # Direct keyword match
        cookie = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() for k in self.COOKIE_KEYWORDS)
        ]
        if cookie:
            return {
                'key_alert_ids': [cookie[0].get('wazuh_id')],
                'detail': f"Session token theft indicator: {cookie[0].get('rule_desc', '')[:80]}",
                'confidence': 0.82,
            }
        # Heuristic: same username, login from IP-A then immediate O365/web session from IP-B
        logins = [a for a in alerts if a['rule_id'] in {5715, 5718, 60106, 60137}
                  and a.get('username') and a.get('src_ip')]
        by_user: dict = {}
        for a in logins:
            by_user.setdefault(a['username'], []).append(a)
        for user, user_logins in by_user.items():
            ips = {a['src_ip'] for a in user_logins}
            if len(ips) >= 3:  # same user, 3+ distinct source IPs
                return {
                    'key_alert_ids': [user_logins[0].get('wazuh_id')],
                    'detail': f"User {user} authenticated from {len(ips)} distinct IPs in window",
                    'confidence': 0.70,
                }
        return None


# ── CR-040: Cryptomining / Resource Hijacking ─────────────────────────────────
class CryptominingDetection(CorrelationRule):
    """XMRig, stratum protocol, or known mining pool connections (T1496)."""
    MINING_KEYWORDS = ('xmrig', 'stratum+tcp', 'stratum+ssl', 'cryptonight', 'monero',
                       'mining pool', 'coinhive', 'minexmr', 'xmrpool', 'supportxmr',
                       'nanopool', 'f2pool', 'nicehash', 'ethermine')
    MINING_PORTS    = ('3333', '4444', '9999', '14444', '45700', '45560')

    def __init__(self):
        super().__init__(
            'CR-040', 'Cryptomining / Resource Hijacking',
            'XMRig or mining pool connection detected — cryptomining malware (T1496)',
            'high', ['Impact'], 30
        )

    def match(self, alerts):
        mining = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() or k in (a.get('raw_log') or '').lower()
                   for k in self.MINING_KEYWORDS)
        ]
        if mining:
            return {
                'key_alert_ids': [mining[0].get('wazuh_id')],
                'detail': f"Cryptomining on {mining[0].get('agent_name')}: {mining[0].get('rule_desc', '')[:80]}",
                'confidence': 0.92,
            }
        port_hits = [
            a for a in alerts
            if any(f':{p}' in (a.get('rule_desc') or '') or
                   f'port {p}' in (a.get('rule_desc') or '').lower()
                   for p in self.MINING_PORTS)
        ]
        if len(port_hits) >= 3:
            return {
                'key_alert_ids': [port_hits[0].get('wazuh_id')],
                'detail': f"{len(port_hits)} connections on mining pool ports from {port_hits[0].get('agent_name')}",
                'confidence': 0.75,
            }
        return None


# ── CR-041: Shadow Copy Deletion ──────────────────────────────────────────────
class ShadowCopyDeletion(CorrelationRule):
    """vssadmin/wmic delete shadows — ransomware pre-encryption step (T1490)."""
    SHADOW_KEYWORDS = ('vssadmin delete shadows', 'wmic shadowcopy delete',
                       'delete shadows', 'bcdedit /set recoveryenabled no',
                       'bcdedit.exe /set', 'wbadmin delete catalog',
                       'diskshadow /s', 'deleteallshadows', 'resize shadowstorage')

    def __init__(self):
        super().__init__(
            'CR-041', 'Shadow Copy / Backup Deletion',
            'VSS shadow copies or backup catalog deleted — ransomware precursor (T1490)',
            'critical', ['Impact', 'Defense Evasion'], 15
        )

    def match(self, alerts):
        shadow = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() or k in (a.get('raw_log') or '').lower()
                   for k in self.SHADOW_KEYWORDS)
        ]
        if shadow:
            return {
                'key_alert_ids': [shadow[0].get('wazuh_id')],
                'detail': f"Shadow copy deletion on {shadow[0].get('agent_name')}: {shadow[0].get('rule_desc', '')[:80]}",
                'confidence': 0.97,
            }
        return None


# ── CR-042: LOLBAS Download Cradle ────────────────────────────────────────────
class LOLBASDownloadCradle(CorrelationRule):
    """certutil/bitsadmin/mshta/regsvr32 used to download payloads (T1218, T1105)."""
    LOLBAS_DOWNLOAD = ('certutil -urlcache', 'certutil.exe -urlcache',
                       'certutil -decode', 'bitsadmin /transfer', 'bitsadmin.exe',
                       'mshta http', 'mshta.exe http', 'regsvr32 /s /n /u /i:http',
                       'regsvr32.exe /s', 'wscript http', 'cscript http',
                       'rundll32.exe javascript', 'ieexec.exe', 'mavinject.exe',
                       'installutil.exe', 'odbcconf.exe', 'xwizard.exe')

    def __init__(self):
        super().__init__(
            'CR-042', 'LOLBAS Download Cradle',
            'certutil/bitsadmin/mshta used to download remote payload (T1218/T1105)',
            'high', ['Defense Evasion', 'Command and Control', 'Execution'], 20
        )

    def match(self, alerts):
        lolbas = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() or k in (a.get('raw_log') or '').lower()
                   for k in self.LOLBAS_DOWNLOAD)
        ]
        if lolbas:
            return {
                'key_alert_ids': [lolbas[0].get('wazuh_id')],
                'detail': f"LOLBAS download cradle on {lolbas[0].get('agent_name')}: {lolbas[0].get('rule_desc', '')[:80]}",
                'confidence': 0.90,
            }
        return None


# ── CR-043: DGA / High-Entropy Domain (C2) ────────────────────────────────────
class DGADetection(CorrelationRule):
    """Multiple queries to high-entropy domains — likely DGA malware (T1568.002)."""
    import math

    @staticmethod
    def _entropy(s: str) -> float:
        from math import log2
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((v / n) * log2(v / n) for v in freq.values())

    def __init__(self):
        super().__init__(
            'CR-043', 'DGA / High-Entropy Domain Query',
            'Multiple DNS queries to high-entropy domain names — DGA C2 indicator (T1568.002)',
            'high', ['Command and Control'], 30
        )

    def match(self, alerts):
        dga_kw = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower()
                   for k in ('dga', 'domain generation', 'high entropy domain',
                              'suspicious dns', 'random domain'))
        ]
        if dga_kw:
            return {
                'key_alert_ids': [dga_kw[0].get('wazuh_id')],
                'detail': f"DGA domain query: {dga_kw[0].get('rule_desc', '')[:80]}",
                'confidence': 0.80,
            }
        return None


# ── CR-044: Automated Collection (Bulk File Reads) ────────────────────────────
class AutomatedCollection(CorrelationRule):
    """30+ FIM/file-access events in 5 minutes — bulk data staging (T1119)."""
    COLLECTION_KEYWORDS = ('find / -name', 'find /home', 'dir /s', 'robocopy',
                           'xcopy /s', 'cp -r', 'rsync -r', 'tar -czf',
                           'compress-archive', 'get-childitem -recurse')

    def __init__(self):
        super().__init__(
            'CR-044', 'Automated Data Collection',
            'Bulk file enumeration or mass FIM events — automated staging (T1119)',
            'high', ['Collection'], 5
        )

    def match(self, alerts):
        collection_cmd = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() or k in (a.get('raw_log') or '').lower()
                   for k in self.COLLECTION_KEYWORDS)
        ]
        if collection_cmd:
            return {
                'key_alert_ids': [collection_cmd[0].get('wazuh_id')],
                'detail': f"Automated collection command on {collection_cmd[0].get('agent_name')}",
                'confidence': 0.78,
            }
        fim_events = [a for a in alerts if a.get('category') == 'fim']
        by_host: dict = {}
        for a in fim_events:
            by_host.setdefault(a['agent_id'], []).append(a)
        for host, host_alerts in by_host.items():
            if len(host_alerts) >= 30:
                return {
                    'key_alert_ids': [host_alerts[0].get('wazuh_id')],
                    'detail': f"Mass file access: {len(host_alerts)} FIM events in 5 min on {host_alerts[0].get('agent_name')}",
                    'confidence': min(len(host_alerts) / 60.0, 0.85),
                }
        return None


# ── CR-045: Archive / Compress Collected Data ─────────────────────────────────
class ArchiveCollectedData(CorrelationRule):
    """zip/rar/7z/tar operations on sensitive directories (T1560)."""
    ARCHIVE_TOOLS   = ('7z ', '7z.exe', 'winrar', 'rar.exe', 'zip ', 'gzip', 'tar czf',
                       'compress-archive', 'zstd', 'bzip2', 'pack200')
    SENSITIVE_PATHS = ('/etc/', '/home/', '/var/log/', 'c:\\users\\', 'c:\\windows\\system32',
                       'documents', 'desktop', 'downloads', '\\appdata\\')

    def __init__(self):
        super().__init__(
            'CR-045', 'Archive / Compress Collected Data',
            'Compression tool operating on sensitive directory — pre-exfil staging (T1560)',
            'high', ['Collection', 'Exfiltration'], 15
        )

    def match(self, alerts):
        archive = [
            a for a in alerts
            if any(t in (a.get('rule_desc') or '').lower() or t in (a.get('raw_log') or '').lower()
                   for t in self.ARCHIVE_TOOLS) and
               any(p in (a.get('rule_desc') or '').lower() or p in (a.get('raw_log') or '').lower()
                   for p in self.SENSITIVE_PATHS)
        ]
        if archive:
            return {
                'key_alert_ids': [archive[0].get('wazuh_id')],
                'detail': f"Archive tool on sensitive path: {archive[0].get('rule_desc', '')[:80]}",
                'confidence': 0.82,
            }
        return None


# ── CR-046: Phishing Attachment Execution ─────────────────────────────────────
class PhishingAttachmentExec(CorrelationRule):
    """Email attachment (macro/script) followed by child process execution (T1566.001)."""
    EMAIL_PROCS   = ('outlook.exe', 'thunderbird.exe', 'office365')
    MACRO_SIGNALS = ('macro enabled', 'vba macro', 'xlm macro', 'auto_open',
                     'document_open', 'workbook_open', 'shellexecute from word',
                     'office macro', 'winword spawned', 'excel spawned')

    def __init__(self):
        super().__init__(
            'CR-046', 'Phishing Attachment / Macro Execution',
            'Email client or Office macro spawning child process — spearphishing payload (T1566.001)',
            'critical', ['Initial Access', 'Execution'], 20
        )

    def match(self, alerts):
        macro = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() for k in self.MACRO_SIGNALS)
        ]
        if macro:
            return {
                'key_alert_ids': [macro[0].get('wazuh_id')],
                'detail': f"Macro/phishing execution on {macro[0].get('agent_name')}: {macro[0].get('rule_desc', '')[:80]}",
                'confidence': 0.90,
            }
        return None


# ── CR-047: Startup Folder Persistence ────────────────────────────────────────
class StartupFolderPersistence(CorrelationRule):
    """File dropped into Windows Startup folder or Linux /etc/init.d (T1547.001)."""
    STARTUP_PATHS = ('\\start menu\\programs\\startup\\', '\\startup\\',
                     '/etc/init.d/', '/etc/rc.d/', '/etc/xdg/autostart/',
                     '~/.config/autostart/', 'appdata\\roaming\\microsoft\\windows\\start menu')

    def __init__(self):
        super().__init__(
            'CR-047', 'Startup Folder / Autostart Persistence',
            'File written to Startup folder or autostart directory — boot persistence (T1547.001)',
            'high', ['Persistence'], 20
        )

    def match(self, alerts):
        startup = [
            a for a in alerts
            if (a.get('category') == 'fim' or 'file' in (a.get('rule_desc') or '').lower()) and
               any(p in ((a.get('file_path') or '') + (a.get('rule_desc') or '')).lower()
                   for p in self.STARTUP_PATHS)
        ]
        if startup:
            return {
                'key_alert_ids': [startup[0].get('wazuh_id')],
                'detail': f"Startup persistence: file in autostart path on {startup[0].get('agent_name')}",
                'confidence': 0.88,
            }
        return None


# ── CR-048: Linux Cron Persistence ────────────────────────────────────────────
class CronPersistence(CorrelationRule):
    """Crontab modification or new file in /etc/cron.* (T1053.003)."""
    CRON_KEYWORDS = ('crontab -e', 'crontab modified', '/etc/cron.d/', '/etc/cron.daily/',
                     '/etc/crontab', '/var/spool/cron/', 'new cron', 'cron job added',
                     'systemctl enable', 'systemd timer', '.timer unit')

    def __init__(self):
        super().__init__(
            'CR-048', 'Cron / Scheduled Task Persistence (Linux)',
            'Crontab or systemd timer modified — Linux persistence (T1053.003)',
            'high', ['Persistence', 'Execution'], 20
        )

    def match(self, alerts):
        cron = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() or k in (a.get('raw_log') or '').lower()
                   for k in self.CRON_KEYWORDS)
        ]
        if cron:
            return {
                'key_alert_ids': [cron[0].get('wazuh_id')],
                'detail': f"Cron/timer modification on {cron[0].get('agent_name')}: {cron[0].get('rule_desc', '')[:80]}",
                'confidence': 0.82,
            }
        return None


# ── CR-049: Access Token Manipulation ─────────────────────────────────────────
class AccessTokenManipulation(CorrelationRule):
    """Token impersonation, CreateProcessWithToken, or runas abuse (T1134)."""
    TOKEN_KEYWORDS = ('seimpersonateprivilege', 'createprocesswithtoken', 'impersonateloggedonuser',
                      'duplicatetoken', 'adjusttokenprivileges', 'juicypotato', 'rottenpotato',
                      'printspoofer', 'sweetpotato', 'godpotato', 'token impersonation',
                      'runas /netonly', 'impersonate token')

    def __init__(self):
        super().__init__(
            'CR-049', 'Access Token Manipulation',
            'Token impersonation or privilege token abuse — T1134 lateral privilege escalation',
            'critical', ['Privilege Escalation', 'Defense Evasion'], 20
        )

    def match(self, alerts):
        token = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() or k in (a.get('raw_log') or '').lower()
                   for k in self.TOKEN_KEYWORDS)
        ]
        if token:
            return {
                'key_alert_ids': [token[0].get('wazuh_id')],
                'detail': f"Token manipulation on {token[0].get('agent_name')}: {token[0].get('rule_desc', '')[:80]}",
                'confidence': 0.90,
            }
        return None


# ── CR-050: Remote Service Creation ───────────────────────────────────────────
class RemoteServiceCreation(CorrelationRule):
    """sc.exe or PsExec creating a service on a remote host (T1543.003, T1021)."""
    SVC_KEYWORDS = ('sc \\\\', 'sc.exe \\\\', 'sc create', 'psexec \\\\', 'psexesvc',
                    'remotely installed service', 'svcctl', 'service remotely created',
                    'new service installed on remote', 'openscmanager')

    def __init__(self):
        super().__init__(
            'CR-050', 'Remote Service Creation',
            'Service created on a remote host via sc.exe or PsExec (T1543.003 / T1021)',
            'critical', ['Lateral Movement', 'Persistence', 'Execution'], 30
        )

    def match(self, alerts):
        svc = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() or k in (a.get('raw_log') or '').lower()
                   for k in self.SVC_KEYWORDS)
        ]
        if svc:
            return {
                'key_alert_ids': [svc[0].get('wazuh_id')],
                'detail': f"Remote service creation on {svc[0].get('agent_name')}: {svc[0].get('rule_desc', '')[:80]}",
                'confidence': 0.88,
            }
        return None


# ── CR-051: DLL Hijacking / Side-Loading ──────────────────────────────────────
class DLLHijacking(CorrelationRule):
    """Suspicious DLL loaded from non-standard path by a trusted process (T1574)."""
    DLL_KEYWORDS = ('dll hijack', 'dll sideload', 'dll side-load', 'dll search order',
                    'phantom dll', 'dll planting', 'dll load from appdata',
                    'loaded from user directory', 'loaded from temp', 'hijacked dll')

    def __init__(self):
        super().__init__(
            'CR-051', 'DLL Hijacking / Side-Loading',
            'Trusted process loaded DLL from non-standard/writable path (T1574)',
            'high', ['Defense Evasion', 'Persistence', 'Privilege Escalation'], 20
        )

    def match(self, alerts):
        dll = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() for k in self.DLL_KEYWORDS)
        ]
        if dll:
            return {
                'key_alert_ids': [dll[0].get('wazuh_id')],
                'detail': f"DLL hijacking on {dll[0].get('agent_name')}: {dll[0].get('rule_desc', '')[:80]}",
                'confidence': 0.85,
            }
        return None


# ── CR-052: Application-Layer C2 (HTTPS Long-Poll) ────────────────────────────
class HTTPSLongPollC2(CorrelationRule):
    """Sustained HTTPS connections > 10 min to non-CDN IPs — C2 keep-alive (T1071.001)."""
    C2_FRAMEWORK_KEYWORDS = ('cobalt strike', 'cobaltstrike', 'cs beacon', 'metasploit',
                             'empire c2', 'havoc c2', 'sliver c2', 'brute ratel',
                             'c2 callback', 'implant callback', 'beacon checkin',
                             'long-poll https', 'http long poll')

    def __init__(self):
        super().__init__(
            'CR-052', 'Application-Layer C2 (HTTPS Long-Poll)',
            'Sustained HTTPS connection or C2 framework beacon pattern (T1071.001)',
            'critical', ['Command and Control'], 120
        )

    def match(self, alerts):
        c2 = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() for k in self.C2_FRAMEWORK_KEYWORDS)
        ]
        if c2:
            return {
                'key_alert_ids': [c2[0].get('wazuh_id')],
                'detail': f"C2 framework pattern on {c2[0].get('agent_name')}: {c2[0].get('rule_desc', '')[:80]}",
                'confidence': 0.92,
            }
        return None


# ── CR-053: Credentials in Files / Env Variables ──────────────────────────────
class CredentialsInFiles(CorrelationRule):
    """grep/find searching for passwords in files — T1552.001 credential harvesting."""
    CRED_SEARCH_KEYWORDS = ('grep -r password', 'grep password', 'grep passwd', 'grep secret',
                            'grep aws_access', 'find . -name .env', 'find / -name password',
                            'cat /etc/shadow', 'cat /etc/passwd', 'type c:\\windows\\repair\\sam',
                            'reg query hklm\\sam', 'reg query hkcu\\passwords',
                            'credential file', 'password file found')

    def __init__(self):
        super().__init__(
            'CR-053', 'Credentials in Files / Registry',
            'Search for credential files or password strings in filesystem (T1552.001)',
            'high', ['Credential Access'], 15
        )

    def match(self, alerts):
        cred = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() or k in (a.get('raw_log') or '').lower()
                   for k in self.CRED_SEARCH_KEYWORDS)
        ]
        if cred:
            return {
                'key_alert_ids': [cred[0].get('wazuh_id')],
                'detail': f"Credential file search on {cred[0].get('agent_name')}: {cred[0].get('rule_desc', '')[:80]}",
                'confidence': 0.85,
            }
        return None


# ── CR-054: Network Share / SMB Enumeration ───────────────────────────────────
class SMBShareEnumeration(CorrelationRule):
    """net view, net share, or SharpHound-style AD enumeration (T1135, T1087)."""
    SMB_KEYWORDS = ('net view', 'net share', 'net use', 'sharphound', 'bloodhound',
                    'powerview', 'invoke-sharefinder', 'invoke-enumdomainusers',
                    'get-netshare', 'smb enum', 'smb discovery', '\\\\*\\ipc$',
                    'smbclient -l', 'crackmapexec smb', 'impacket smbclient')

    def __init__(self):
        super().__init__(
            'CR-054', 'SMB / Network Share Enumeration',
            'Active network share or AD enumeration — lateral movement reconnaissance (T1135/T1087)',
            'medium', ['Discovery', 'Lateral Movement'], 20
        )

    def match(self, alerts):
        smb = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() or k in (a.get('raw_log') or '').lower()
                   for k in self.SMB_KEYWORDS)
        ]
        if smb:
            return {
                'key_alert_ids': [smb[0].get('wazuh_id')],
                'detail': f"SMB/AD enumeration on {smb[0].get('agent_name')}: {smb[0].get('rule_desc', '')[:80]}",
                'confidence': 0.80,
            }
        return None


# ── CR-055: Impersonation via SID History / DCSync ────────────────────────────
class DCSyncAttack(CorrelationRule):
    """DCSync (replication rights abuse) or SID history injection (T1003.006, T1134.005)."""
    DCSYNC_KEYWORDS = ('drsuapi', 'drsreplicasynccreds', 'dcsync', 'dc sync',
                       'replicatesinglobject', 'getncchanges', 'directory replication',
                       'replication rights', 'sid history', 'sidhistory injection',
                       'mimikatz lsadump::dcsync', 'impacket secretsdump')

    def __init__(self):
        super().__init__(
            'CR-055', 'DCSync / Directory Replication Attack',
            'DCSync replication abuse or SID history injection — domain credential harvest (T1003.006)',
            'critical', ['Credential Access', 'Privilege Escalation'], 20
        )

    def match(self, alerts):
        dcsync = [
            a for a in alerts
            if any(k in (a.get('rule_desc') or '').lower() or k in (a.get('raw_log') or '').lower()
                   for k in self.DCSYNC_KEYWORDS)
        ]
        if dcsync:
            return {
                'key_alert_ids': [dcsync[0].get('wazuh_id')],
                'detail': f"DCSync/replication attack on {dcsync[0].get('agent_name')}: {dcsync[0].get('rule_desc', '')[:80]}",
                'confidence': 0.95,
            }
        return None



# ── CR-056: Sustained Resource Utilization Breach ─────────────────────────────
class HighResourceUtilization(CorrelationRule):
    """CPU, disk, or memory threshold breach reported by cy360_resource_check (T1496, T1499)."""
    RESOURCE_RULE_IDS  = frozenset({'101004', '101005', '101006', '101007'})
    RESOURCE_KEYWORDS  = (
        'high cpu utilization', 'high disk utilization', 'high memory utilization',
        'cycentra 360: high cpu', 'cycentra 360: high disk', 'cycentra 360: high memory',
        'sustained resource utilization', 'resource threshold',
    )

    def __init__(self):
        super().__init__(
            'CR-056', 'Sustained Resource Utilization Breach',
            'CPU, disk, or memory utilization repeatedly exceeds thresholds — '
            'potential DoS, cryptomining, ransomware encryption load, or runaway process (T1496/T1499)',
            'medium', ['Impact'], 5
        )

    def match(self, alerts):
        hits = [
            a for a in alerts
            if (str(a.get('rule_id', '')) in self.RESOURCE_RULE_IDS or
                any(k in (a.get('rule_desc') or '').lower() for k in self.RESOURCE_KEYWORDS))
        ]
        if len(hits) < 2:
            return None
        agent  = hits[0].get('agent_name', 'unknown')
        types  = set()
        for a in hits:
            desc = (a.get('rule_desc') or '').lower()
            if 'cpu'    in desc: types.add('CPU')
            if 'disk'   in desc: types.add('Disk')
            if 'memory' in desc: types.add('Memory')
        resource_label = '/'.join(sorted(types)) or 'Resource'
        return {
            'key_alert_ids': [a.get('wazuh_id') for a in hits[:3]],
            'detail': (
                f"{resource_label} utilization threshold breached {len(hits)}x on {agent}"
            ),
            'confidence': 0.80,
        }


# ── Rule registry ─────────────────────────────────────────────────────────────
ALL_RULES: list[CorrelationRule] = [
    # ── Original 15 rules ─────────────────────────────────────────────────────
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
    # ENH-5: rules batch 2
    EventLogCleared(),
    DNSTunnelling(),
    CredentialDumping(),
    RansomwareIndicators(),
    C2Beacon(),
    # ── CR-016 → CR-035: Windows, Cloud & Endpoint rules ─────────────────────
    PasswordSpraying(),
    WindowsBruteForce(),
    DormantAccountRebirth(),
    DomainAdminGroupChange(),
    GoldenTicketAnomaly(),
    RegistryPersistence(),
    ScheduledTaskAbuse(),
    ProcessInjection(),
    EncodedCommandExecution(),
    WebShellExecution(),
    SecurityToolDisabled(),
    UnusualOutboundPort(),
    RDPToInternet(),
    InternalSubnetScan(),
    LargeCloudUpload(),
    CloudLoginNoMFA(),
    CloudIAMPrivilegeChange(),
    MassCloudDeletion(),
    MailForwardingRule(),
    OAuthConsentGrant(),
    # ── CR-036 → CR-055: Gap-closure rules (ATT&CK coverage expansion) ────────
    WMIExecution(),
    PassTheHash(),
    MFAPushBombing(),
    SessionCookieTheft(),
    CryptominingDetection(),
    ShadowCopyDeletion(),
    LOLBASDownloadCradle(),
    DGADetection(),
    AutomatedCollection(),
    ArchiveCollectedData(),
    PhishingAttachmentExec(),
    StartupFolderPersistence(),
    CronPersistence(),
    AccessTokenManipulation(),
    RemoteServiceCreation(),
    DLLHijacking(),
    HTTPSLongPollC2(),
    CredentialsInFiles(),
    SMBShareEnumeration(),
    DCSyncAttack(),
    HighResourceUtilization(),
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
