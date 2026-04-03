"""
llm_enricher.py
Incident narrative generation via LLM.

Uses ai_router.call_llm() — whichever provider is configured in the portal's
AI Settings page (CyMind, Ollama, Anthropic, Gemini, DeepSeek) is used
automatically.  No separate API keys needed here.

Generates:
  1. Analyst summary   — plain English incident narrative
  2. Remediation steps — prioritised, asset-specific response steps

Only triggers for critical/high incidents with ≥3 alerts.
Falls back gracefully if the LLM service is unavailable.
"""
from datetime import datetime, timezone
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models import Incident, Alert
from config import get_settings
from ai_router import call_llm

log = structlog.get_logger()
settings = get_settings()

SYSTEM_PROMPT = """You are a senior SOC analyst assistant. You receive structured incident data from a Wazuh SIEM correlation engine and produce:

1. ANALYST_SUMMARY: A concise (2–3 sentence) plain-English narrative describing what happened, who was affected, and why it matters. No jargon. Actionable.

2. REMEDIATION_STEPS: Numbered list of prioritised, asset-specific remediation steps. Include exact file paths, commands, and Wazuh documentation references where relevant.

Format your response EXACTLY as:
ANALYST_SUMMARY:
<your summary here>

REMEDIATION_STEPS:
1. <step one>
2. <step two>
...

Be concise. Analysts are busy. No preamble."""


def _build_context(incident: Incident, alerts: list[Alert]) -> str:
    mitre_ids  = ', '.join(incident.mitre_ids or []) or 'None'
    corr_rules = '\n'.join(
        f"  [{r['rule_id']}] {r['name']}: {r.get('detail', r.get('description', ''))}"
        for r in (incident.correlated_rules or [])
    ) or '  None triggered'

    misp = incident.misp_enrichment or {}
    if misp.get('ioc_hits'):
        misp_section = 'Threat Intelligence (MISP):\n' + '\n'.join(
            f"  - {h['ioc']} ({h['type']}): {h['threat_level']} threat"
            for h in misp['ioc_hits']
        )
    else:
        misp_section = 'Threat Intelligence: No MISP IOC matches.'

    top_alerts = sorted(alerts, key=lambda a: float(a.base_score or 0), reverse=True)[:8]
    alert_lines = '\n'.join(
        f"  [{a.timestamp.strftime('%H:%M:%S')}] [{a.rule_id}] {a.rule_desc}"
        f" | {a.agent_name} | user:{a.username or 'N/A'} | src:{a.src_ip or 'N/A'}"
        for a in top_alerts
    )

    return f"""INCIDENT: {incident.id}
Severity: {(incident.severity or 'unknown').upper()}
First Seen: {incident.first_seen.strftime('%Y-%m-%d %H:%M UTC')}
Last Seen:  {incident.last_seen.strftime('%Y-%m-%d %H:%M UTC')}
Alert Count: {incident.alert_count}

Affected Hosts: {', '.join(incident.affected_agents or [])}
Affected Users: {', '.join(incident.affected_users or [])}
Source IPs: {', '.join(str(ip) for ip in (incident.src_ips or []))}

MITRE ATT&CK: {mitre_ids}
Tactics: {', '.join(incident.mitre_tactics or [])}

Correlation Rules Triggered:
{corr_rules}

{misp_section}

Top Alerts:
{alert_lines}
"""


def _parse_response(raw: str) -> tuple[str, str]:
    summary = ''
    remediation = ''
    try:
        if 'ANALYST_SUMMARY:' in raw and 'REMEDIATION_STEPS:' in raw:
            parts = raw.split('REMEDIATION_STEPS:')
            summary = parts[0].replace('ANALYST_SUMMARY:', '').strip()
            remediation = parts[1].strip() if len(parts) > 1 else ''
        else:
            summary = raw.strip()
    except Exception:
        summary = raw.strip()
    return summary, remediation


async def enrich_incident(db: AsyncSession, incident: Incident) -> dict:
    """Generate LLM narrative for an incident. Returns dict or empty dict."""
    if not settings.llm_enabled:
        return {}

    result = await db.execute(select(Alert).where(Alert.incident_id == incident.id))
    alerts = result.scalars().all()
    if not alerts:
        return {}

    context      = _build_context(incident, alerts)
    user_prompt  = f"Analyse this security incident:\n\n{context}\n\nProvide ANALYST_SUMMARY and REMEDIATION_STEPS."

    try:
        raw = await call_llm(SYSTEM_PROMPT, user_prompt, timeout=120.0)
        summary, remediation = _parse_response(raw)

        incident.llm_summary      = summary
        incident.llm_remediation  = remediation
        incident.llm_generated_at = datetime.now(timezone.utc)
        await db.flush()

        log.info('llm_enrichment_done', incident_id=incident.id)
        return {'summary': summary, 'remediation': remediation}

    except Exception as e:
        log.warning('llm_enrichment_failed', incident_id=incident.id, error=str(e))
        return {}
