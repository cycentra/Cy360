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
import httpx
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models import Incident, Alert
from config import get_settings
from ai_router import call_llm, _load as _load_ai_settings

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


async def _store_to_cymind_memory(incident: Incident, summary: str, remediation: str) -> None:
    """
    Fire-and-forget: store a correlated SIEM incident into CyMind episodic memory
    so analysts can query it via the CyMind chat window.
    Only runs when CyMind is the configured AI provider (or always if CyMind
    credentials are present in ai_settings.json).
    Never blocks or raises — incident processing is never affected.
    """
    try:
        cfg    = _load_ai_settings()
        fields = cfg.get("fields", {})
        # Support both cymind-as-primary-provider and cymind fields present in any config
        base_url = fields.get("baseUrl", "").rstrip("/")
        api_key  = fields.get("apiKey", "")
        if not base_url or not api_key:
            return  # CyMind not configured — skip silently

        src_ips = [str(ip) for ip in (incident.src_ips or [])]
        severity_raw = (incident.severity or "medium").lower()
        severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        severity = severity_map.get(severity_raw, "medium")

        alert_type = (
            (incident.correlated_rules or [{}])[0].get("name")
            or (incident.mitre_tactics or ["unknown"])[0]
        )

        payload = {
            "incident_id":    str(incident.id),
            "alert_type":     alert_type,
            "severity":       severity,
            "source_ip":      src_ips[0] if src_ips else "",
            "destination":    ", ".join(incident.affected_agents or []),
            "rule_ids":       [str(r.get("rule_id", "")) for r in (incident.correlated_rules or [])],
            "description":    f"Hosts: {', '.join(incident.affected_agents or [])} | Users: {', '.join(incident.affected_users or [])}",
            "analyst_notes":  summary,
            "outcome":        "open",
            "resolution":     remediation,
            "ttps":           list(incident.mitre_ids or []),
            "tags":           ["wazuh", "correlation"] + list(incident.mitre_tactics or []),
            "timestamp":      incident.first_seen.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base_url}/api/v1/rag/memory/incident",
                json=payload,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            )
            resp.raise_for_status()
            log.debug("cymind_memory_stored", incident_id=incident.id)
    except Exception as e:
        log.debug("cymind_memory_store_skipped", incident_id=getattr(incident, "id", "?"), reason=str(e))


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

        # Store into CyMind episodic memory for analyst chat queries (fire-and-forget)
        await _store_to_cymind_memory(incident, summary, remediation)

        log.info('llm_enrichment_done', incident_id=incident.id)
        return {'summary': summary, 'remediation': remediation}

    except Exception as e:
        log.warning('llm_enrichment_failed', incident_id=incident.id, error=str(e))
        return {}
