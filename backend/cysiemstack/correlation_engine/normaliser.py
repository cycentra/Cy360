"""
normaliser.py
Converts raw Wazuh alert JSON (from Filebeat) into a structured alert dict
that every downstream stage expects. Drops alerts that cannot be usefully
processed (missing agent, zero-level events, etc.).

Output dict keys:
  wazuh_id, timestamp, agent_id, agent_name, agent_ip,
  rule_id, rule_desc, rule_level, base_score,
  category, mitre_id, mitre_tactic,
  src_ip, dst_ip, username, process_name, file_path,
  raw_log, full_alert
"""
import re
import math
from datetime import datetime, timezone
from typing import Optional

# ── GeoIP enrichment (graceful no-op if DB absent) ────────────────────────────
try:
    import geoip2.database as _geoip2_db
    _GEOIP_READER  = _geoip2_db.Reader("/opt/cycentra/geoip/GeoLite2-City.mmdb")
    _GEOIP_ENABLED = True
except Exception:
    _GEOIP_READER  = None
    _GEOIP_ENABLED = False

# Rule IDs that indicate SSH / auth events (used for category mapping)
SSH_RULE_IDS     = {5715, 5716, 5718, 5719, 5720, 5710, 5711, 2502}
AUTH_RULE_IDS    = {18100, 18101, 18102, 18103, 18104, 5400, 5500, 5502}
FIM_RULE_IDS     = set(range(550, 600)) | {2904}
MALWARE_RULE_IDS = {554, 87105, 87106, 100200, 100201, 100210, 100211}
WEB_RULE_IDS     = set(range(31100, 31200)) | set(range(30100, 30200))
SCAN_RULE_IDS    = {40001, 40002, 40003}
# Wazuh SCA (Security Configuration Assessment) rule IDs — policy scan results
# 19001-19023: individual check pass/fail/notapplicable; 19100+ are summary rules
SCA_RULE_IDS     = set(range(19001, 19024)) | set(range(19100, 19120))
# ASM (Attack Surface Management) findings — pushed by edr_bridge.push_asm_finding()
# 200100=critical, 200101=high, 200102=medium, 200103=escalated
# Range 200100-200199 is unoccupied by Wazuh rules (cy_cust_rules.xml stops at 101042).
# These IDs are never loaded into Wazuh — recognised only by this normaliser.
ASM_RULE_IDS       = set(range(200100, 200110))
# ITAM anomalies — pushed by edr_bridge.push_itam_anomaly()
# 200200=cve_critical, 200201=cve_high, 200202=iot_high_risk, 200203=shadow_ai
ITAM_VULN_RULE_IDS = {200200, 200201}
ITAM_IOT_RULE_IDS  = {200202}
ITAM_AI_RULE_IDS   = {200203}

# Min rule level to ingest — drop noisy debug/info events below this
MIN_RULE_LEVEL = 3

# ── Suppression filters ───────────────────────────────────────────────────────
# Alerts matching either list are silently dropped before any DB write or UEBA
# analysis. Add rule IDs or lowercased description substrings as needed.
#
# Rule 5710  — sshd: Attempt to login using a non-existent user
# Rule 5711  — sshd: Attempt to login using a non-existent user (double-check variant)
# Rule 5702  — sshd: Reverse lookup error (DNS noise)
# Rule 5703  — sshd: error: Could not get shadow information (PAM config noise)
SUPPRESSED_RULE_IDS: frozenset[int] = frozenset({
    5710,   # Attempt to login using a non-existent user
    5711,   # Non-existent user login (scanner variant)
    5702,   # Reverse lookup error
    5703,   # PAM shadow lookup error
})

# Lowercased substrings — any alert whose rule_desc contains one of these is dropped.
# Keep phrases specific enough to avoid false suppression.
SUPPRESSED_DESC_FRAGMENTS: tuple[str, ...] = (
    "attempt to login using a non-existent user",
    "invalid user",
    "reverse lookup error",
    "could not get shadow information",
)
# ─────────────────────────────────────────────────────────────────────────────

# Map Wazuh rule levels (0-15) to base score (used in risk scoring)
def _level_to_score(level: int) -> float:
    """Logarithmic mapping: level 3→4.1, level 7→6.2, level 12→7.6, level 15→8.2 (max)

    Formula: min(15.0, log(level+1, base=1.4))
    The compressed range 4.1–8.2 means grouper.py thresholds must use values
    within this range — see SIEM_SEVERITY_TUNING.md for the full threshold table.
    """
    if level <= 0:
        return 0.0
    return round(min(15.0, math.log(level + 1, 1.4)), 1)


def _extract_ip(text: str) -> Optional[str]:
    """Extract the first valid public IP from a string."""
    if not text:
        return None
    # Basic IPv4 pattern
    matches = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', str(text))
    for ip in matches:
        parts = [int(p) for p in ip.split('.')]
        if all(0 <= p <= 255 for p in parts):
            # Skip private ranges
            if (parts[0] == 10 or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168) or
                parts[0] in (127, 0, 169)):
                continue
            return ip
    return None


def _lookup_geoip(ip: str) -> dict:
    """Return geo dict {country_iso, country_name, city, lat, lon} or {}."""
    if not _GEOIP_ENABLED or not ip:
        return {}
    try:
        r = _GEOIP_READER.city(ip)
        return {
            'country_iso':  r.country.iso_code,
            'country_name': r.country.name,
            'city':         r.city.name,
            'lat':          float(r.location.latitude  or 0),
            'lon':          float(r.location.longitude or 0),
        }
    except Exception:
        return {}


# ── Cloud integration source map ─────────────────────────────────────────────
# Maps Wazuh rule groups → normalised cloud source category string.
# Order matters: check most-specific groups first.
_CLOUD_SOURCE_MAP: dict[str, str] = {
    'office365': 'o365',
    'o365':      'o365',
    'azure':     'azure',
    'msaz':      'azure',
    'aws':       'aws',
    'cloudtrail':'aws',
    'gcp':       'gcp',
    'github':    'github',
}


def _classify_category(rule_id: int, groups: list) -> str:
    """Map rule ID and groups to a high-level category string.

    Cloud integration sources (office365, azure, aws, gcp, github) are checked
    BEFORE generic auth/web/scan labels.  This prevents O365 sign-in failure
    alerts — whose Wazuh rule groups include both 'office365' and
    'authentication_failed' — from being mis-categorised as 'authentication'.
    FIM and malware remain above cloud so e.g. an O365 malware-detection event
    is still labelled 'malware'.
    """
    if rule_id in FIM_RULE_IDS or 'syscheck' in groups:
        return 'fim'
    if rule_id in MALWARE_RULE_IDS or 'virus' in groups or 'malware' in groups:
        return 'malware'
    # SCA — checked before cloud/auth so hardening-failure alerts are never
    # misclassified as generic 'system' events.
    if rule_id in SCA_RULE_IDS or 'sca' in groups:
        return 'sca'
    # ASM / ITAM synthetic rule IDs — checked before generic cloud/auth labels
    if rule_id in ASM_RULE_IDS or 'asm' in groups:
        return 'asm'
    if rule_id in ITAM_VULN_RULE_IDS or 'vulnerability' in groups:
        return 'vulnerability'
    if rule_id in ITAM_IOT_RULE_IDS:
        return 'asm'
    if rule_id in ITAM_AI_RULE_IDS:
        return 'system'
    # Cloud integration sources — must be checked before generic 'authentication'
    # so that O365/Azure/AWS alert groups are not swallowed by the auth check.
    for grp in groups:
        if grp in _CLOUD_SOURCE_MAP:
            return _CLOUD_SOURCE_MAP[grp]
    if rule_id in SSH_RULE_IDS or 'sshd' in groups or 'authentication' in groups:
        return 'authentication'
    if rule_id in AUTH_RULE_IDS or 'pam' in groups or 'sudo' in groups:
        return 'authentication'
    if rule_id in WEB_RULE_IDS or 'web' in groups or 'apache' in groups or 'nginx' in groups:
        return 'web'
    if rule_id in SCAN_RULE_IDS:
        return 'scan'
    if 'vulnerability-detector' in groups:
        return 'vulnerability'
    if 'network_scan' in groups or 'nmap' in groups:
        return 'scan'
    return 'system'


def _extract_username(alert: dict) -> Optional[str]:
    """Extract username from various Wazuh alert fields."""
    # Common locations across Wazuh decoders
    data = alert.get('data', {}) or {}
    for path in [
        ['data', 'dstuser'],
        ['data', 'srcuser'],
        ['data', 'win', 'eventdata', 'targetUserName'],
        ['data', 'win', 'eventdata', 'subjectUserName'],
        ['predecoder', 'user'],
    ]:
        val = alert
        for key in path:
            if isinstance(val, dict):
                val = val.get(key)
            else:
                val = None
                break
        # Note: 'root' is intentionally NOT excluded — root activity is
        # security-relevant and must be tracked by UEBA and risk scoring.
        if val and isinstance(val, str) and val not in ('SYSTEM', ''):
            return val.strip()

    # Office 365 / Exchange Online — user identity in data.office365
    o365 = data.get('office365') or {}
    for key in ('UserId', 'MailboxOwnerUPN'):
        v = o365.get(key, '')
        if v and isinstance(v, str) and '@' in v:
            return v.strip()

    # Check syscheck
    if alert.get('syscheck', {}).get('uname_after'):
        return alert['syscheck']['uname_after']

    return None


def normalise(raw: dict) -> Optional[dict]:
    """
    Convert a raw Wazuh alert dict to a normalised alert dict.
    Returns None if the alert should be dropped.
    """
    rule  = raw.get('rule',  {}) or {}
    agent = raw.get('agent', {}) or {}

    # Required fields
    rule_id    = rule.get('id')
    rule_level = rule.get('level', 0)

    if not rule_id or not isinstance(rule_id, int) and not str(rule_id).isdigit():
        return None
    rule_id = int(rule_id)

    if rule_level < MIN_RULE_LEVEL:
        return None

    # Suppression: drop noisy / low-value alert types before any processing
    if rule_id in SUPPRESSED_RULE_IDS:
        return None
    rule_desc_raw = rule.get('description', '') or ''
    if any(frag in rule_desc_raw.lower() for frag in SUPPRESSED_DESC_FRAGMENTS):
        return None

    agent_id   = agent.get('id', '000')
    agent_name = agent.get('name') or 'manager'
    # Agent ID '000' is the Wazuh Manager's own local agent — valid, not filtered.
    # Normalise it to the manager name so downstream grouping works correctly.
    if not agent_id:
        return None
    if agent_id == '000':
        agent_id = agent_name

    # Timestamp
    ts_str = raw.get('timestamp')
    try:
        if ts_str:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        else:
            ts = datetime.now(timezone.utc)
    except (ValueError, AttributeError):
        ts = datetime.now(timezone.utc)

    # Rule metadata
    rule_desc = rule.get('description', '')
    groups    = rule.get('groups', [])

    # MITRE
    mitre     = rule.get('mitre', {}) or {}
    mitre_ids = mitre.get('id', [])
    mitre_tac = mitre.get('tactic', [])
    mitre_id  = mitre_ids[0] if mitre_ids else None
    mitre_tactic = mitre_tac[0] if mitre_tac else None

    # IPs
    src_ip = (
        _extract_ip(raw.get('data', {}).get('srcip', '')) or
        _extract_ip(raw.get('data', {}).get('src_ip', '')) or
        _extract_ip(str(raw.get('data', {}).get('url', '')))
    )

    # Username
    username = _extract_username(raw)

    # File path (FIM)
    syscheck  = raw.get('syscheck', {}) or {}
    file_path = syscheck.get('path') or raw.get('data', {}).get('file')

    # Process
    process_name = raw.get('data', {}).get('command') or raw.get('data', {}).get('processName')

    # Category
    category = _classify_category(rule_id, groups)

    # SCA extra fields — populated for 'sca' category alerts
    sca_extras: dict = {}
    if category == 'sca':
        sca_block = raw.get('data', {}).get('sca', {}) or {}
        check     = sca_block.get('check', {}) or {}
        sca_extras = {
            'sca_policy_id':   sca_block.get('policy_id'),
            'sca_policy_name': sca_block.get('policy', {}).get('name') if isinstance(sca_block.get('policy'), dict) else None,
            'sca_check_id':    check.get('id'),
            'sca_check_title': check.get('title'),
            'sca_result':      check.get('result'),      # 'passed' | 'failed' | 'not applicable'
            'sca_rationale':   check.get('rationale'),
            'sca_remediation': check.get('remediation'),
        }

    # Raw log
    raw_log = raw.get('full_log') or raw.get('message') or ''

    # GeoIP lookup (no-op if DB not present)
    geo = _lookup_geoip(src_ip) if src_ip else {}

    return {
        'wazuh_id':     raw.get('id'),
        'timestamp':    ts,
        'agent_id':     agent_id,
        'agent_name':   agent.get('name', agent_id),
        'agent_ip':     agent.get('ip'),
        'rule_id':      rule_id,
        'rule_desc':    rule_desc,
        'rule_level':   rule_level,
        'base_score':   _level_to_score(rule_level),
        'category':     category,
        'mitre_id':     mitre_id,
        'mitre_tactic': mitre_tactic,
        'src_ip':       src_ip,
        'dst_ip':       None,
        'username':     username,
        'process_name': process_name,
        'file_path':    file_path,
        'raw_log':      raw_log[:2000] if raw_log else '',  # cap at 2KB
        'full_alert':   raw,
        'geo':          geo,
        **sca_extras,
    }
