"""
hypothesis_engine.py
Structured attack hypothesis generation — Phase 2 of the AI Investigation Engine.

Generates a ranked list of attack hypotheses with probabilities, MITRE technique
labels, kill-chain stage tags, evidence requirements, and LLM reasoning.

This module is additive: existing ANALYST_SUMMARY + REMEDIATION_STEPS generated
by llm_enricher.py are untouched. Returns [] on any LLM failure — the caller
must handle an empty list gracefully. Never raises.
"""
import json
import re
import structlog
from ai_router import call_llm

log = structlog.get_logger()

_ALLOWED_STAGES = frozenset({
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "Command & Control", "Actions on Objectives",
})

HYPOTHESIS_SYSTEM_PROMPT = """\
You are a senior threat analyst producing structured attack hypotheses for a SIEM \
correlation engine. Output ONLY a valid JSON array — no preamble, no commentary, \
no markdown fences.

Schema (array of 1–5 hypotheses, ranked by initial_probability descending):
[
  {
    "id": "H1",
    "label": "<short attack scenario name, max 8 words>",
    "technique": "<MITRE ATT&CK technique ID e.g. T1059.001, or empty string>",
    "kill_chain_stage": "<one of: Reconnaissance | Weaponization | Delivery | Exploitation | Installation | Command & Control | Actions on Objectives>",
    "initial_probability": <integer 0-100>,
    "evidence_needed": ["<item 1>", "<item 2>", ...],
    "reasoning": "<1-2 sentences why this hypothesis fits the data>"
  }
]

Rules:
- H1 = highest probability. Assign IDs H1..H5.
- evidence_needed: 2-4 specific, collectable items (process tree, DNS history, \
file hash lookup, user privilege listing, vulnerability scan results, network flow).
- technique: most specific applicable technique ID; empty string if unknown.
- kill_chain_stage: exactly one value from the allowed list.
- initial_probability: integer 0-100. Keep < 60 when evidence is ambiguous.
- Output ONLY the JSON array, nothing else.\
"""


def _parse_hypotheses(raw: str) -> list[dict]:
    """Parse and validate LLM hypothesis JSON. Returns [] on any parse failure."""
    try:
        clean = re.sub(r"```(?:json)?\s*|\s*```", "", raw.strip())
        data = json.loads(clean)
        if not isinstance(data, list):
            return []
        validated: list[dict] = []
        for i, h in enumerate(data[:5]):
            if not isinstance(h, dict):
                continue
            label = str(h.get("label", "")).strip()
            if not label:
                continue
            stage = str(h.get("kill_chain_stage", "")).strip()
            if stage not in _ALLOWED_STAGES:
                stage = "Exploitation"
            prob = h.get("initial_probability", 0)
            try:
                prob = max(0, min(100, int(prob)))
            except (TypeError, ValueError):
                prob = 0
            evidence = h.get("evidence_needed", [])
            if not isinstance(evidence, list):
                evidence = []
            validated.append({
                "id":                   h.get("id", f"H{i + 1}"),
                "label":                label,
                "technique":            str(h.get("technique", "")).strip(),
                "kill_chain_stage":     stage,
                "initial_probability":  prob,
                "evidence_needed":      [str(e) for e in evidence[:6]],
                "reasoning":            str(h.get("reasoning", "")).strip(),
            })
        return sorted(validated, key=lambda x: x["initial_probability"], reverse=True)
    except Exception as exc:
        log.debug("hypothesis_parse_failed", error=str(exc), raw_snippet=raw[:200])
        return []


RE_EVAL_SYSTEM_PROMPT = """\
You are a senior threat analyst re-scoring attack hypotheses after receiving new \
forensic evidence. Output ONLY a valid JSON array — no preamble, no commentary, \
no markdown fences.

Update the initial_probability of each hypothesis based on the collected evidence \
and refine the reasoning. Keep all other fields identical to the input. If evidence \
CONFIRMS a hypothesis, raise its probability. If it CONTRADICTS, lower it. \
If the evidence is inconclusive for a hypothesis, keep the probability unchanged.

Output ONLY the JSON array. Same IDs, same fields — only initial_probability and \
reasoning may change.\
"""


def _build_evidence_summary(evidence_log: list[dict]) -> str:
    """Convert evidence log to a compact context string for the LLM."""
    if not evidence_log:
        return "No evidence collected."
    lines = []
    for item in evidence_log:
        status  = item.get("status", "UNKNOWN")
        ev_type = item.get("evidence_type", "?")
        summary = item.get("summary", "")
        hyp_id  = item.get("hypothesis_id", "?")
        agent   = item.get("agent_id") or "N/A"
        lines.append(f"  [{hyp_id}] {ev_type} [{status}] — {summary} (agent: {agent})")
    return "\n".join(lines)


async def re_evaluate_hypotheses(
    incident,
    evidence_log: list[dict],
) -> list[dict]:
    """Second LLM pass: update hypothesis probabilities with collected evidence.

    Args:
        incident:     Incident ORM object (used for ID logging and .hypotheses).
        evidence_log: Phase 3 evidence items (may contain COLLECTED, MISSING, FAILED).

    Returns updated hypotheses list. On any failure returns the original list
    unchanged — never raises, never returns [].
    """
    original = incident.hypotheses or []
    if not original:
        return []

    evidence_summary = _build_evidence_summary(evidence_log)

    user_prompt = (
        "Re-evaluate these attack hypotheses with the collected forensic evidence:\n\n"
        "ORIGINAL HYPOTHESES:\n"
        f"{__import__('json').dumps(original, indent=2)}\n\n"
        "COLLECTED EVIDENCE:\n"
        f"{evidence_summary}\n\n"
        "Return ONLY the updated JSON array. Adjust initial_probability and reasoning "
        "based on evidence. Keep all other fields unchanged."
    )

    try:
        raw = await call_llm(RE_EVAL_SYSTEM_PROMPT, user_prompt, timeout=90.0)
        updated = _parse_hypotheses(raw)

        if updated and len(updated) == len(original):
            # Map by ID — only transfer probability + reasoning, preserve everything else
            updated_map = {h["id"]: h for h in updated}
            result = []
            for orig_h in original:
                if orig_h["id"] in updated_map:
                    new_h = dict(orig_h)
                    new_h["initial_probability"] = updated_map[orig_h["id"]]["initial_probability"]
                    new_h["reasoning"]           = updated_map[orig_h["id"]].get("reasoning", orig_h.get("reasoning", ""))
                    result.append(new_h)
                else:
                    result.append(orig_h)
            # Re-sort by updated probability
            result.sort(key=lambda x: x["initial_probability"], reverse=True)
            log.info(
                "hypotheses_re_evaluated",
                incident_id=getattr(incident, "id", "?"),
                top_prob=result[0]["initial_probability"] if result else None,
            )
            return result
        # Mismatched count — use original
        log.debug(
            "hypothesis_re_eval_count_mismatch",
            expected=len(original), got=len(updated),
        )
        return original
    except Exception as exc:
        log.warning(
            "hypothesis_re_eval_failed",
            incident_id=getattr(incident, "id", "?"),
            error=str(exc),
        )
        return original


async def generate_hypotheses(incident, context_bundle: str) -> list[dict]:
    """Generate ranked attack hypotheses for an incident.

    Args:
        incident:       Incident ORM object (used only for logging).
        context_bundle: Pre-built incident context string from llm_enricher._build_context().

    Returns a validated list of hypothesis dicts sorted by probability (highest first).
    Returns [] on any failure — never raises.
    """
    user_prompt = (
        "Generate attack hypotheses for this security incident:\n\n"
        f"{context_bundle}\n\n"
        "Return only a valid JSON array of hypotheses ordered by probability descending."
    )
    try:
        raw = await call_llm(HYPOTHESIS_SYSTEM_PROMPT, user_prompt, timeout=90.0)
        hypotheses = _parse_hypotheses(raw)
        log.info(
            "hypotheses_generated",
            incident_id=getattr(incident, "id", "?"),
            count=len(hypotheses),
            top_label=hypotheses[0]["label"] if hypotheses else None,
        )
        return hypotheses
    except Exception as exc:
        log.warning(
            "hypothesis_generation_failed",
            incident_id=getattr(incident, "id", "?"),
            error=str(exc),
        )
        return []
