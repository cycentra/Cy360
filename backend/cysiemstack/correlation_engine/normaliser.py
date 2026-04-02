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

# Rule IDs that indicate SSH / auth events (used for category mapping)
SSH_RULE_IDS     = {5715, 5716, 5718, 5719, 5720, 5710, 5711, 2502}
AUTH_RULE_IDS    = {18100, 18101, 18102, 18103, 18104, 5400, 5500, 5502}
FIM_RULE_IDS     = set(range(550, 600)) | {2904}
MALWARE_RULE_IDS = {554, 87105, 87106, 100200, 100201}
WEB_RULE_IDS     = set(range(31100, 31200)) | set(range(30100, 30200))
SCAN_RULE_IDS    = {40001, 40002, 40003}

# Min rule level to ingest — drop noisy debug/info events below this
MIN_RULE_LEVEL = 3

# Map Wazuh rule levels (0-15) to base score (used in risk scoring)
def _level_to_score(level: int) -> float:
    """Logarithmic mapping: level 3→1.0, level 7→5.0, level 12→10.0, level 15→13.0"""
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


def _classify_category(rule_id: int, groups: list) -> str:
    """Map rule ID and groups to a high-level category string."""
    if rule_id in FIM_RULE_IDS or 'syscheck' in groups:
        return 'fim'
    if rule_id in MALWARE_RULE_IDS or 'virus' in groups or 'malware' in groups:
        return 'malware'
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
        if val and isinstance(val, str) and val not in ('root', 'SYSTEM', ''):
            return val.strip()

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

    # Raw log
    raw_log = raw.get('full_log') or raw.get('message') or ''

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
    }
