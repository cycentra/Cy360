#!/var/ossec/framework/python/bin/python3
import sys
import json
import requests
import socket
import re
import ipaddress
import time

# --- Settings ---
LLM_API_URL = "http://116.203.115.95:11434/api/generate"
MODEL_NAME = "mranv/siem-llama-3.1:v1"
WAZUH_QUEUE = "/var/ossec/queue/sockets/queue"

def log_debug(msg):
    with open('/var/ossec/logs/integrations.log', 'a') as f:
        f.write(f"DEBUG: {msg}\n")

def send_to_wazuh(msg, agent_id, agent_name, agent_ip):
    """Send enriched data to Wazuh with retry logic"""
    max_retries = 3
    retry_delay = 0.5

    json_str = json.dumps(msg)
    if agent_id == "000":
        formatted_msg = f"1:ai-enrichment:{json_str}"
    else:
        formatted_msg = f"1:[{agent_id}] ({agent_name}) any->ai-enrichment:{json_str}"

    for attempt in range(max_retries):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.connect(WAZUH_QUEUE)
            sock.send(formatted_msg.encode())
            sock.close()
            return True
        except socket.error as e:
            if attempt < max_retries - 1:
                log_debug(f"Socket Error (attempt {attempt + 1}/{max_retries}): {str(e)} - Retrying...")
                time.sleep(retry_delay)
            else:
                log_debug(f"Socket Error (final attempt): {str(e)}")
                return False
        except Exception as e:
            log_debug(f"Unexpected Socket Error: {str(e)}")
            return False

    return False

def is_valid_ip(ip_str):
    """Validate if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except (ValueError, TypeError):
        return False

def is_blockable_ip(ip_str):
    """Check if IP is safe to block (not 0.0.0.0, private, loopback, etc)"""
    try:
        if not ip_str or ip_str == '0.0.0.0' or ip_str.startswith('Local:') or ip_str == 'Unknown':
            return False
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_unspecified:
            return False
        return True
    except (ValueError, TypeError):
        return False

def is_attack_related(alert):
    """Determine if alert is attack-related based on rule groups and description"""
    groups = alert.get('rule', {}).get('groups', [])
    rule_desc = alert.get('rule', {}).get('description', '').lower()

    attack_groups = [
        'authentication_failed', 'authentication_failures',
        'attack', 'exploit', 'web_attack', 'brute_force',
        'sql_injection', 'ids', 'intrusion_detection',
        'invalid_login', 'multiple_drops', 'scan'
    ]

    attack_keywords = [
        'brute force', 'sql injection', 'attack', 'exploit',
        'intrusion', 'unauthorized', 'failed login', 'multiple failed',
        'port scan', 'dos', 'ddos'
    ]

    for group in groups:
        if any(attack_group in group.lower() for attack_group in attack_groups):
            return True

    if any(keyword in rule_desc for keyword in attack_keywords):
        return True

    return False

def main():
    try:
        if len(sys.argv) < 2:
            return

        alert_file = sys.argv[1]
        with open(alert_file, 'r') as f:
            line = f.readline()
            if not line:
                return
            alert = json.loads(line)

        agent_info = alert.get('agent', {})
        agent_id = agent_info.get('id', '000')
        agent_name = agent_info.get('name', 'manager')
        agent_ip = agent_info.get('ip', 'any')

        # Prevent recursive processing of CyAI-generated alerts
        llm_check = alert.get('data', {}).get('llm_model')
        if llm_check == 'CyAI':
            log_debug(f"Skipping recursive alert from CyAI")
            return

        groups = alert.get('rule', {}).get('groups', [])
        data = alert.get('data', {})

        initial_srcip = data.get('srcip') or data.get('address') or data.get('src_ip')
        is_vulnerability = "vulnerability-detector" in groups

        srcip = initial_srcip
        event_context = "UNKNOWN"

        if is_vulnerability:
            srcip = agent_ip if agent_ip != '0.0.0.0' else f"Local:{agent_name}"
            event_context = "VULNERABILITY"
        elif not srcip or srcip == '0.0.0.0':
            if is_attack_related(alert):
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', alert.get('full_log', ''))
                if match and is_valid_ip(match.group(1)):
                    potential_ip = match.group(1)
                    if potential_ip != agent_ip and potential_ip != '0.0.0.0':
                        srcip = potential_ip
                        event_context = "ATTACK"
                    else:
                        log_debug(f"Skipping alert with internal/invalid IP: {potential_ip}")
                        return
                else:
                    log_debug(f"Skipping alert - no valid external IP found")
                    return
            else:
                srcip = agent_ip if agent_ip != '0.0.0.0' else f"Local:{agent_name}"
                event_context = "INTERNAL_EVENT"
        else:
            event_context = "ATTACK"

        rule_desc = alert.get('rule', {}).get('description', 'Unknown')
        original_full_log = alert.get('full_log', alert.get('data', {}))
        alert_id = alert.get('id', 'N/A')

        log_debug(f"[{event_context}] Processing ID: {alert_id} | Identity: {srcip}")

        prompt = f"""
Analyze this Wazuh alert:
Type: {event_context}
Alert: {rule_desc}
Log: {original_full_log}

Task: Provide a high-level summary and technically granular, step-by-step remediation instructions.
Respond ONLY with a JSON object using this exact structure:
{{
  "summary": "concise clear summary - one to two sentences explaining security event.",
  "recommendation": "1. Step one\\n2. Step two",
  "severity": "Choose EXACTLY one severity word from this list: CRITICAL, HIGH, MEDIUM, or LOW.",
  "action": "Choose EXACTLY one action word from this list: block, review, or ignore"
}}
Formatting Rules:
- 'summary': Keep it under 20 words.
- 'recommendation': For every step, you MUST include:
    1. The EXACT file path or URL to be checked (e.g., /var/ossec/logs/ossec.log).
    2. The SPECIFIC string, error code, or pattern to look for.
    3. The EXACT command or configuration change needed to fix it.
    4. If it is a Wazuh-specific fix, reference the official Wazuh documentation structure (documentation.wazuh.com).
"""
        payload = {
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }

        response = None
        for attempt in range(3):
            try:
                r = requests.post(LLM_API_URL, json=payload, timeout=40)
                r.raise_for_status()
                response = r
                break
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                log_debug(f"Ollama Busy (attempt {attempt+1}/3). Retrying in 2s...")
                time.sleep(2)

        if not response:
            log_debug(f"Final Attempt Failed for ID {alert_id}. Service Refused Connection.")
            return

        ai_raw = response.json().get('response', '{}')
        try:
            ai_data = json.loads(ai_raw)
        except json.JSONDecodeError as e:
            log_debug(f"LLM JSON Parse Error: {str(e)} | Raw: {ai_raw[:200]}")
            ai_data = {"summary": "LLM parsing failed", "recommendation": "Manual review required", "severity": "LOW", "action": "review"}

        raw_recommendation = ai_data.get('recommendation', 'N/A')
        if isinstance(raw_recommendation, (list, dict)):
            sanitized_rec = json.dumps(raw_recommendation)
        else:
            sanitized_rec = str(raw_recommendation)

        enrichment = {
            "ai_outcome": ai_data.get('summary', 'Analysis unavailable'),
            "ai_recommendation": sanitized_rec,
            "ai_severity": ai_data.get('severity', 'LOW').upper(),
            "ai_action": ai_data.get('action', 'review').lower(),
            "original_alert_id": alert_id,
            "srcip": srcip,
            "event_type": event_context,
            "agent_id": agent_id,
            "llm_model": "CyAI"
        }

        if event_context in ["VULNERABILITY", "INTERNAL_EVENT"]:
            enrichment["ai_action"] = "review"

        if enrichment["ai_action"] == "block" and not is_blockable_ip(srcip):
            enrichment["ai_action"] = "review"

        success = send_to_wazuh(enrichment, agent_id, agent_name, agent_ip)
        if success:
            log_debug(f"Enrichment sent successfully for alert {alert_id}")

    except Exception as e:
        log_debug(f"Script Crash: {str(e)}")

if __name__ == "__main__":
    main()
