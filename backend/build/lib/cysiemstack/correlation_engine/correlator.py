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
                    return {
                        'key_alert_ids': [login.get('wazuh_id')],
                        'detail': f"Account {uname} logged in with no prior activity in observation window",
                        'confidence': 0.65,
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
