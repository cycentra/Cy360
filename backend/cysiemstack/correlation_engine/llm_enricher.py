from __future__ import annotations

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
import re
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

1. ANALYST_SUMMARY: A clear, complete plain-English narrative (3–5 sentences) describing what happened, who was affected, the attack progression observed, and why it matters. No jargon. Actionable. Include affected usernames/hosts when available.

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

    # Include both highest-severity and most-recent alerts for comprehensive context.
    # For cloud incidents (all alerts similar score), recency captures the attack timeline.
    by_score  = sorted(alerts, key=lambda a: float(a.base_score or 0), reverse=True)[:5]
    by_recent = sorted(alerts, key=lambda a: a.timestamp, reverse=True)[:5]
    seen_ids  = set()
    top_alerts = []
    for a in by_score + by_recent:
        if id(a) not in seen_ids:
            seen_ids.add(id(a))
            top_alerts.append(a)
    top_alerts = top_alerts[:10]
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
    """Parse LLM response — tolerates format deviations."""
    summary = ''
    remediation = ''
    try:
        # Primary: expect exact marker format
        if 'ANALYST_SUMMARY:' in raw and 'REMEDIATION_STEPS:' in raw:
            parts = raw.split('REMEDIATION_STEPS:')
            summary     = parts[0].replace('ANALYST_SUMMARY:', '').strip()
            remediation = parts[1].strip() if len(parts) > 1 else ''
        # Fallback 1: only summary marker present — rest is remediation
        elif 'ANALYST_SUMMARY:' in raw:
            summary = raw.replace('ANALYST_SUMMARY:', '').strip()
        # Fallback 2: numbered list pattern — first paragraph is summary, numbered list is remediation
        else:
            lines = raw.strip().split('\n')
            numbered = [l for l in lines if re.match(r'^\s*\d+[\.\)]', l)]
            if numbered:
                first_numbered = next(i for i, l in enumerate(lines) if re.match(r'^\s*\d+[\.\)]', l))
                summary     = '\n'.join(lines[:first_numbered]).strip()
                remediation = '\n'.join(lines[first_numbered:]).strip()
            else:
                summary = raw.strip()
    except Exception:
        summary = raw.strip()
    return summary, remediation


_RECOMMENDATION_SYSTEM_PROMPT = """You are a senior SOC incident responder. Given a security incident with its analyst summary and investigation hypotheses, produce a structured response plan in JSON.

Return ONLY valid JSON in this exact schema (no markdown, no prose outside the JSON):
{
  "executive_summary": "<2-3 sentence plain-English summary of the threat and recommended response>",
  "containment": [
    {"action": "<specific action>", "priority": "immediate|high|medium", "detail": "<command or config change>"}
  ],
  "eradication": [
    {"action": "<specific action>", "priority": "high|medium|low", "detail": "<steps to remove threat>"}
  ],
  "recovery": [
    {"action": "<specific action>", "priority": "high|medium|low", "detail": "<restoration steps>"}
  ]
}

Rules:
- containment: 2-4 items. Stop the bleeding first.
- eradication: 2-4 items. Remove the threat root cause.
- recovery: 2-3 items. Restore normal operations.
- All actions must reference specific hosts, users, or IPs from the incident where available.
- Be specific. No filler steps like "contact IT". No preamble."""


async def generate_structured_recommendation(
    incident: Incident,
    context: str,
    confidence_score: float,
) -> dict | None:
    """Phase 5: Generate structured Containment/Eradication/Recovery recommendation.

    Only runs when confidence_score >= 0.50. Returns structured dict or None on failure.
    The existing free-text llm_remediation is kept as a fallback for < 50% confidence.
    """
    if confidence_score < 0.50:
        return None

    hypotheses_text = ""
    if incident.hypotheses:
        top = incident.hypotheses[0]
        hypotheses_text = (
            f"\nTop Hypothesis: {top.get('label', '')} "
            f"({top.get('initial_probability', 0)}% probability)\n"
            f"Technique: {top.get('technique', 'N/A')} | "
            f"Kill-chain: {top.get('kill_chain_stage', 'N/A')}"
        )

    user_prompt = (
        f"Incident context:\n{context}\n"
        f"{hypotheses_text}\n"
        f"Analyst Summary: {incident.llm_summary or 'Not yet generated'}\n\n"
        f"Confidence score: {round(confidence_score * 100, 1)}%\n\n"
        "Generate a structured response plan in JSON."
    )

    try:
        raw = await call_llm(_RECOMMENDATION_SYSTEM_PROMPT, user_prompt, timeout=90.0)
        # Strip markdown fences if present
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            cleaned = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        import json as _json
        rec = _json.loads(cleaned)

        # Validate required keys
        required = {"executive_summary", "containment", "eradication", "recovery"}
        if not required.issubset(rec.keys()):
            log.warning("recommendation_schema_invalid", incident_id=incident.id,
                        keys=list(rec.keys()))
            return None

        log.info("structured_recommendation_done", incident_id=incident.id)
        return rec

    except Exception as exc:
        log.warning("structured_recommendation_failed", incident_id=incident.id, error=str(exc))
        return None


async def _store_to_cymind_memory(incident: Incident, summary: str, remediation: str) -> None:
    """
    Fire-and-forget: store a correlated SIEM incident into CyMind episodic memory
    so analysts can query it via the CyMind chat window.
    Only runs when CyMind is the configured AI provider (or always if CyMind
    credentials are present in ai_settings.json).
    Never blocks or raises — incident processing is never affected.
    """
    try:
        cfg = _load_ai_settings()
        # Prefer the dedicated cymind_memory block (set independently of the active LLM provider).
        # Fall back to active provider fields only when provider == 'cymind'.
        cm = cfg.get("cymind_memory") or {}
        if cm.get("baseUrl") and cm.get("apiKey"):
            base_url = cm["baseUrl"].rstrip("/")
            api_key  = cm["apiKey"]
        elif cfg.get("provider") == "cymind":
            fields   = cfg.get("fields", {})
            base_url = fields.get("baseUrl", "").rstrip("/")
            api_key  = fields.get("apiKey", "")
        else:
            return  # CyMind not configured — skip silently
        if not base_url or not api_key:
            return

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


async def _store_incident_pattern(db: AsyncSession, incident: Incident) -> None:
    """Phase 6: Persist a resolved/closed incident as a reusable investigation pattern.

    Called from the transition endpoint when status moves to 'closed' or 'resolved'.
    Extends (does not replace) _store_to_cymind_memory().
    Never raises — incident pipeline is never affected.
    """
    try:
        from models import IncidentPattern

        # Extract primary technique (first MITRE ID) and kill-chain stage
        technique   = (incident.mitre_ids or [None])[0]
        kill_chain  = incident.kill_chain_stage_name

        # Build payload indicators: src IPs + affected users + top correlated rule IDs
        payload_indicators = {
            "src_ips":        [str(ip) for ip in (incident.src_ips or [])],
            "users":          list(incident.affected_users or []),
            "agents":         list(incident.affected_agents or []),
            "rule_ids":       [
                str(r.get("rule_id", ""))
                for r in (incident.correlated_rules or [])
                if isinstance(r, dict) and r.get("rule_id")
            ],
        }

        # Build similarity vector: boolean features for technique + kill-chain
        # (simple feature encoding — sufficient for the current scoring model)
        all_mitre = list(incident.mitre_ids or [])
        all_tactics = list(incident.mitre_tactics or [])
        similarity_vector = {
            "techniques": all_mitre[:5],
            "tactics":    all_tactics[:5],
            "kill_chain": kill_chain or "",
            "severity":   incident.severity or "medium",
            "alert_count_bucket": (
                "high" if (incident.alert_count or 0) >= 20
                else "medium" if (incident.alert_count or 0) >= 5
                else "low"
            ),
        }

        pattern = IncidentPattern(
            source_incident_id       = incident.id,
            technique                = technique,
            kill_chain_stage         = kill_chain,
            process_chain            = incident.correlated_rules or [],
            payload_indicators       = payload_indicators,
            response_actions         = incident.recommendation or {},
            outcome                  = incident.status,
            confidence_at_resolution = incident.confidence_score,
            similarity_vector        = similarity_vector,
        )
        db.add(pattern)
        # Caller is responsible for committing — this is called inside transition_incident
        await db.flush()
        log.info("incident_pattern_stored", incident_id=incident.id,
                 technique=technique, kill_chain=kill_chain)

    except Exception as exc:
        log.debug("incident_pattern_store_skipped",
                  incident_id=getattr(incident, "id", "?"), reason=str(exc))


async def enrich_incident(db: AsyncSession, incident: Incident, on_demand: bool = False) -> dict:
    """Generate LLM narrative for an incident. Returns dict or empty dict.

    on_demand=True bypasses the LLM_ENABLED flag — used when an analyst
    explicitly triggers analysis from the portal (regardless of whether
    automated enrichment is disabled in cysiemstack.env).

    Phase 2: also generates structured hypotheses after the narrative. The
    hypothesis step is additive — a failure there does not fail this function.
    """
    if not on_demand and not settings.llm_enabled:
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

    except Exception as e:
        log.warning('llm_enrichment_failed', incident_id=incident.id, error=str(e))
        if on_demand:
            raise  # Surface real error to the analyst — don't swallow on-demand failures
        return {}

    # ── Phase 2: Structured hypothesis generation ─────────────────────────────
    # Runs after the narrative so a hypothesis failure never blocks the summary.
    from hypothesis_engine import generate_hypotheses
    hypotheses = await generate_hypotheses(incident, context)
    if hypotheses:
        incident.hypotheses             = hypotheses
        incident.hypothesis_generated_at = datetime.now(timezone.utc)
        # Wire top hypothesis kill_chain_stage into kill_chain_stage_name so
        # compute_fp_score() (called after enrich_incident in ingestor.py) uses it.
        top = hypotheses[0]
        if top.get("kill_chain_stage") and not incident.kill_chain_stage_name:
            incident.kill_chain_stage_name = top["kill_chain_stage"]
        await db.flush()

        # ── Phase 3+4: Evidence collection + confidence (fire-and-forget) ────
        # Opens its own session so the parent request session can commit and close.
        import asyncio
        asyncio.create_task(
            _collect_evidence_and_score(incident.id)
        )

    return {
        'summary':                  incident.llm_summary,
        'remediation':              incident.llm_remediation,
        'hypotheses':               incident.hypotheses,
        'hypothesis_generated_at':  (
            incident.hypothesis_generated_at.isoformat()
            if incident.hypothesis_generated_at else None
        ),
        'evidence_log':             incident.evidence_log,
        'evidence_coverage':        (
            float(incident.evidence_coverage)
            if incident.evidence_coverage is not None else None
        ),
        'confidence_score':         (
            float(incident.confidence_score)
            if incident.confidence_score is not None else None
        ),
        'confidence_breakdown':     incident.confidence_breakdown,
        'confidence_computed_at':   (
            incident.confidence_computed_at.isoformat()
            if incident.confidence_computed_at else None
        ),
        # Phase 5: recommendation + SOAR dispatch state
        'recommendation':           getattr(incident, 'recommendation', None),
        'soar_dispatched':          getattr(incident, 'soar_dispatched', False),
        'soar_dispatched_at':       (
            incident.soar_dispatched_at.isoformat()
            if getattr(incident, 'soar_dispatched_at', None) else None
        ),
        'soar_dispatch_log':        getattr(incident, 'soar_dispatch_log', None),
    }


async def _collect_evidence_and_score(incident_id: str) -> None:
    """Background task: gap analysis → evidence collection → re-evaluation → confidence.

    Opens its own DB session and commits independently.
    Total timeout: 30 s for evidence collection, 90 s per LLM call.
    Never raises — all exceptions are logged and swallowed.
    """
    from models import AsyncSessionLocal, Incident
    from sqlalchemy import select
    import asyncio

    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Incident).where(Incident.id == incident_id))
            incident = result.scalar_one_or_none()
            if not incident or not incident.hypotheses:
                return

            # Phase 3a: Gap analysis
            from gap_analyser import analyse_gaps
            gaps = analyse_gaps(incident.hypotheses, {})

            # Phase 3b: Evidence collection (30 s total timeout)
            from evidence_collector import collect_all
            try:
                evidence_log = await asyncio.wait_for(
                    collect_all(incident, gaps, db),
                    timeout=30.0,
                )
            except asyncio.TimeoutError:
                log.warning("evidence_collection_timeout", incident_id=incident_id)
                evidence_log = []

            # Coverage = collected / total requested
            total_requested = sum(len(g["missing"]) for g in gaps)
            collected_count = sum(1 for e in evidence_log if e.get("status") == "COLLECTED")
            coverage = round(collected_count / total_requested, 4) if total_requested > 0 else 0.0

            incident.evidence_log          = evidence_log or []
            incident.evidence_collected_at = datetime.now(timezone.utc)
            incident.evidence_coverage     = coverage
            await db.flush()

            # Phase 4a: Re-evaluate hypotheses with evidence
            from hypothesis_engine import re_evaluate_hypotheses
            updated_hyps = await re_evaluate_hypotheses(incident, evidence_log)
            if updated_hyps:
                incident.hypotheses = updated_hyps

            # Phase 4b: Compute investigation confidence
            from risk_scorer import compute_investigation_confidence, compute_historical_similarity
            top_prob = (
                updated_hyps[0]["initial_probability"]
                if updated_hyps else None
            )
            # Phase 6: use real historical similarity when patterns exist
            top_technique  = (incident.mitre_ids or [None])[0]
            hist_sim = await compute_historical_similarity(
                db,
                technique        = top_technique,
                kill_chain_stage = incident.kill_chain_stage_name,
            )
            conf_score, conf_breakdown = compute_investigation_confidence(
                incident,
                ti_reputation         = incident.ti_reputation,
                top_hypothesis_prob   = top_prob,
                asset_tier            = incident.asset_tier,
                historical_similarity = hist_sim,
            )
            incident.confidence_score       = conf_score
            incident.confidence_breakdown   = conf_breakdown
            incident.confidence_computed_at = datetime.now(timezone.utc)

            # Phase 5a: Generate structured recommendation (≥ 50% confidence)
            if conf_score >= 0.50:
                # Rebuild context for the recommendation prompt
                result2 = await db.execute(select(Alert).where(Alert.incident_id == incident_id))
                alerts2 = result2.scalars().all()
                ctx2 = _build_context(incident, alerts2)
                recommendation = await generate_structured_recommendation(
                    incident, ctx2, conf_score
                )
                if recommendation:
                    incident.recommendation = recommendation

            await db.flush()

            # Phase 5b: Confidence-gated SOAR dispatch (fire-and-forget — already in async ctx)
            if incident.recommendation:
                from cysoar_connector import dispatch_if_confident
                dispatch_entry = await dispatch_if_confident(
                    db, incident, incident.recommendation, float(conf_score)
                )

            await db.commit()
            log.info(
                "evidence_and_confidence_done",
                incident_id=incident_id,
                evidence_items=len(evidence_log),
                coverage=coverage,
                confidence=conf_score,
            )

    except Exception as exc:
        log.warning(
            "evidence_and_confidence_failed",
            incident_id=incident_id,
            error=str(exc),
        )
