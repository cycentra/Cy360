"""
cy_comp/services/ai_analysis.py
=================================
AI enrichment via the CyMind LLM endpoint.

Uses the same LLM endpoint as the Correlation Engine: reads CYMIND_API_URL
from ai_settings.json.  Every call is logged to cy_comp_ai_audit_log.

Methods:
  analyze_risk(risk_dict)
  analyze_finding(finding_dict)
  suggest_controls(framework, gap_description)
"""

import hashlib
import json
import logging
import time
import uuid
from typing import Optional

import requests

from cy_comp.models import db
from cy_comp.services.policy_rag import get_cymind_url, get_admin_key

log = logging.getLogger("cycentra.cy_comp.ai_analysis")

_GRC_SYSTEM_PROMPT = (
    "You are a GRC (Governance, Risk & Compliance) expert. "
    "Analyse compliance risks and findings for organisations subject to "
    "NIS2, DORA, ISO 27001, SOC 2, NIST CSF, and PCI DSS. "
    "Be concise, practical, and cite specific control references where relevant. "
    "Never fabricate standards or control IDs."
)

_DEFAULT_MODEL = "llama3"


def _load_llm_settings() -> dict:
    try:
        from cy_comp.services.policy_rag import _load_cymind_settings
        return _load_cymind_settings()
    except Exception:
        return {}


def _get_model() -> str:
    settings = _load_llm_settings()
    return settings.get("model") or settings.get("model_name") or _DEFAULT_MODEL


def _call_llm(prompt: str, system: str = _GRC_SYSTEM_PROMPT,
              max_tokens: int = 600) -> tuple[str, int]:
    """
    Call CyMind /api/chat endpoint.
    Returns (response_text, duration_ms).
    """
    url   = get_cymind_url()
    key   = get_admin_key()
    model = _get_model()

    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"

    payload = {
        "model":      model,
        "messages": [
            {"role": "system",  "content": system},
            {"role": "user",    "content": prompt},
        ],
        "max_tokens":  max_tokens,
        "temperature": 0.1,
        "stream":      False,
    }

    t0 = time.time()
    try:
        resp = requests.post(
            f"{url}/api/chat",
            headers=headers,
            json=payload,
            timeout=60,
        )
        duration_ms = int((time.time() - t0) * 1000)
        if resp.ok:
            data = resp.json()
            text = (
                data.get("message", {}).get("content")
                or data.get("choices", [{}])[0].get("message", {}).get("content")
                or data.get("response")
                or ""
            )
            return text.strip(), duration_ms
        log.warning("_call_llm: HTTP %s — %s", resp.status_code, resp.text[:200])
    except Exception as exc:
        duration_ms = int((time.time() - t0) * 1000)
        log.error("_call_llm: %s", exc)

    return "", duration_ms


def _log_audit(entity_type: str, entity_id: str, prompt: str,
               response: str, model: str, duration_ms: int,
               created_by: str) -> None:
    """Write to cy_comp_ai_audit_log. Never raises."""
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_ai_audit_log
                    (id, entity_type, entity_id, prompt_hash, response_summary,
                     model_used, duration_ms, created_by, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,NOW());
                """,
                (
                    str(uuid.uuid4()),
                    entity_type, entity_id, prompt_hash,
                    response[:500] if response else None,
                    model, duration_ms, created_by,
                )
            )
    except Exception as exc:
        log.warning("_log_audit: %s", exc)


def analyze_risk(risk_dict: dict, created_by: str = "system") -> str:
    """
    Generate an AI risk narrative for the given risk.
    Persists to cy_comp_risks.ai_analysis and logs to audit table.
    Returns the analysis text.
    """
    prompt = f"""Analyse this organisational risk and provide a concise professional assessment:

Risk Title: {risk_dict.get('title')}
Category: {risk_dict.get('category')}
Description: {risk_dict.get('description') or 'Not provided'}
Likelihood (1-5): {risk_dict.get('likelihood')}
Impact (1-5): {risk_dict.get('impact')}
Risk Score: {risk_dict.get('risk_score')} / 25
Treatment Strategy: {risk_dict.get('treatment')}
Relevant Frameworks: {', '.join(risk_dict.get('frameworks') or []) or 'NIS2, ISO 27001'}

Provide:
1. A 2-3 sentence professional risk narrative
2. Key threat vectors for this risk
3. Specific recommended controls (cite ISO 27001 Annex A or NIS2 Article 21 where applicable)
4. Residual risk assessment if treatment is applied

Keep response under 300 words. Be specific and actionable."""

    model = _get_model()
    text, duration_ms = _call_llm(prompt, max_tokens=600)
    _log_audit("risk", risk_dict.get("id", ""), prompt, text, model, duration_ms, created_by)

    if text and risk_dict.get("id"):
        try:
            from cy_comp.services.risk import update_risk
            update_risk(risk_dict["id"], {"ai_analysis": text})
        except Exception as exc:
            log.warning("analyze_risk update_risk: %s", exc)

    return text or "AI analysis unavailable — CyMind unreachable."


def analyze_finding(finding_dict: dict, created_by: str = "system") -> str:
    """
    Generate an AI analysis for a compliance finding.
    Returns the analysis text.
    """
    prompt = f"""Analyse this compliance finding and provide actionable guidance:

Framework: {finding_dict.get('framework', '').upper()}
Control: {finding_dict.get('control_id')} — {finding_dict.get('control_name')}
Severity: {finding_dict.get('severity', '').upper()}
Title: {finding_dict.get('title')}
Description: {finding_dict.get('description') or 'Not provided'}
Current Status: {finding_dict.get('status')}

Provide:
1. Root cause analysis (2-3 sentences)
2. Specific remediation steps (numbered list)
3. Timeline recommendation (immediate/short-term/long-term)
4. Related controls that should also be reviewed

Keep response under 400 words."""

    model = _get_model()
    text, duration_ms = _call_llm(prompt, max_tokens=800)
    _log_audit("finding", finding_dict.get("id", ""), prompt, text, model, duration_ms, created_by)

    # Persist analysis to finding record
    if text and finding_dict.get("id"):
        try:
            with db() as conn:
                cur = conn.cursor()
                cur.execute(
                    "UPDATE cy_comp_findings SET ai_analysis=%s, updated_at=NOW() WHERE id=%s;",
                    (text, finding_dict["id"])
                )
        except Exception as exc:
            log.warning("analyze_finding persist: %s", exc)

    return text or "AI analysis unavailable — CyMind unreachable."


def score_question_from_policy(question: str, control_ref: str,
                               framework: str, chunks: list[str]) -> dict:
    """
    Use CyMind LLM to score a single questionnaire question against retrieved policy chunks.

    Returns {score: 0|1|2, justification: str, evidence_snippet: str}.
    Score key: 2=Pass, 1=Partial, 0=Fail/no evidence.
    Fails safe to score=0 on any parse error so the pipeline never writes bad data.
    """
    chunks_text = "\n---\n".join(chunks[:5])  # cap at 5 to stay within token budget

    prompt = (
        f"Framework: {framework.upper()}\n"
        f"Control Reference: {control_ref}\n"
        f"Compliance Question: {question}\n\n"
        f"Policy Document Excerpts:\n{chunks_text}\n\n"
        "Based ONLY on the policy excerpts above, score compliance with this control.\n"
        "Respond with ONLY valid JSON — no markdown fences, no preamble:\n"
        '{"score": <0|1|2>, '
        '"justification": "<1-2 sentence explanation>", '
        '"evidence_snippet": "<direct verbatim quote from policy, or empty string>"}\n\n'
        "Score key: 2=Pass (explicit policy language covers this control), "
        "1=Partial (partially addressed), 0=Fail (no relevant policy found). "
        "Be conservative — only score 2 when the policy text is explicit and unambiguous."
    )

    system = (
        "You are a GRC compliance analyst performing a policy gap assessment. "
        "Your task is to determine whether an organisation's policy documents demonstrate "
        "compliance with a specific control requirement. Be conservative and precise. "
        "Respond only with the requested JSON object."
    )

    model = _get_model()
    text, duration_ms = _call_llm(prompt, system=system, max_tokens=300)
    _log_audit("policy_question_score", control_ref, prompt, text, model, duration_ms, "policy_analysis")

    try:
        clean = text.strip()
        if clean.startswith("```"):
            parts = clean.split("```")
            clean = parts[1][4:] if parts[1].startswith("json") else parts[1]
        result = json.loads(clean.strip())
        result["score"] = max(0, min(2, int(result.get("score", 0))))
        result.setdefault("justification", "")
        result.setdefault("evidence_snippet", "")
        return result
    except Exception:
        log.warning("score_question_from_policy: parse error for %s: %.120s", control_ref, text)
        return {"score": 0, "justification": "LLM parse error", "evidence_snippet": ""}


def suggest_controls(framework: str, gap_description: str,
                     created_by: str = "system") -> dict:
    """
    Suggest specific controls for a compliance gap.
    Returns {framework, suggestions, raw_json}.
    """
    prompt = f"""Map the following compliance gap to specific controls.

Framework: {framework.upper()}
Gap Description: {gap_description}

Return ONLY valid JSON in this exact format (no markdown, no explanation):
{{
  "{framework.lower()}": ["control-id-1", "control-id-2"],
  "iso27001": ["A.X.Y"],
  "nist": ["AC-1"],
  "remediation_priority": "immediate|short_term|long_term",
  "effort": "low|medium|high"
}}

Only include frameworks where a genuine mapping exists. Use exact control IDs."""

    model = _get_model()
    text, duration_ms = _call_llm(prompt, max_tokens=400)
    _log_audit("control_suggestion", "", prompt, text, model, duration_ms, created_by)

    parsed = {}
    try:
        clean  = text.strip().replace("```json", "").replace("```", "").strip()
        parsed = json.loads(clean) if clean else {}
    except Exception:
        parsed = {"error": "Could not parse", "raw": text[:200]}

    return {"framework": framework, "suggestions": parsed, "raw": text}
