from __future__ import annotations

"""
gap_analyser.py
Evidence Gap Analysis — Phase 3 of the AI Investigation Engine.

Examines each hypothesis's evidence_needed list and maps items to collector
types the engine knows how to invoke. Returns a per-hypothesis gap manifest
so evidence_collector.py knows exactly what to collect.

Never raises — returns [] on any failure. Called from llm_enricher.py
as the first step of the fire-and-forget background collection task.
"""

import structlog

log = structlog.get_logger()

# ── Evidence-type keyword mapping ─────────────────────────────────────────────
# Keys are collector type identifiers; values are keyword fragments to match
# against evidence_needed strings (case-insensitive).
_TYPE_KEYWORDS: dict[str, list[str]] = {
    "process_tree": [
        "process tree", "process list", "running process", "parent process",
        "process chain", "child process", "spawned process", "process execution",
    ],
    "file_hash": [
        "file hash", "sha256", "md5", "sha1", "file integrity", "file check",
        "hash lookup", "file modification", "malware hash", "binary hash",
    ],
    "dns_history": [
        "dns", "domain query", "dns lookup", "dns history", "dns resolution",
        "network dns", "domain resolution", "outbound dns", "c2 domain",
    ],
    "user_privilege": [
        "privilege", "user privilege", "group membership", "sudo access",
        "sca", "user account", "access rights", "permission", "role",
        "user rights", "admin rights", "elevated privilege",
    ],
    "vulnerability": [
        "vulnerability", "cve", "patch status", "vuln scan", "exploit",
        "security patch", "unpatched", "software version", "vulnerable",
    ],
}

_COLLECTOR_FOR_TYPE: dict[str, str] = {
    "process_tree":    "ProcessTreeCollector",
    "file_hash":       "FileHashCollector",
    "dns_history":     "DNSHistoryCollector",
    "user_privilege":  "UserPrivilegeCollector",
    "vulnerability":   "VulnerabilityCollector",
}

# Priority: lower number = collect first
_PRIORITY: dict[str, int] = {
    "process_tree":    1,
    "file_hash":       2,
    "dns_history":     3,
    "user_privilege":  4,
    "vulnerability":   5,
}


def _classify_evidence_item(text: str) -> str | None:
    """Return the evidence_type for a given evidence_needed text, or None."""
    t = text.lower()
    for ev_type, keywords in _TYPE_KEYWORDS.items():
        if any(kw in t for kw in keywords):
            return ev_type
    return None


def analyse_gaps(
    hypotheses: list[dict],
    available_evidence: dict,
) -> list[dict]:
    """Determine what evidence is still needed for each hypothesis.

    Args:
        hypotheses:         List of hypothesis dicts (from hypothesis_engine.py).
        available_evidence: Dict keyed by evidence_type of already-collected
                            items. Empty {} means nothing collected yet.

    Returns a list of gap dicts (one per hypothesis that has gaps):
    [{
        "hypothesis_id": "H1",
        "missing": [{
            "evidence_type": "process_tree",
            "collector":     "ProcessTreeCollector",
            "priority":      1,
            "description":   "<original evidence_needed text>",
        }, ...]
    }]

    Returns [] on any failure — never raises.
    """
    if not hypotheses:
        return []

    already_collected = set(available_evidence.keys()) if available_evidence else set()

    gaps: list[dict] = []
    try:
        for hyp in hypotheses:
            hyp_id = hyp.get("id", "H?")
            missing: list[dict] = []

            for item_text in (hyp.get("evidence_needed") or []):
                ev_type = _classify_evidence_item(item_text)
                if ev_type is None:
                    continue  # unmappable item — skip
                if ev_type in already_collected:
                    continue  # already available

                missing.append({
                    "evidence_type": ev_type,
                    "collector":     _COLLECTOR_FOR_TYPE[ev_type],
                    "priority":      _PRIORITY[ev_type],
                    "description":   item_text,
                })

            if missing:
                # Sort by priority, deduplicate by evidence_type within this hypothesis
                seen_types: set[str] = set()
                deduped: list[dict] = []
                for m in sorted(missing, key=lambda x: x["priority"]):
                    if m["evidence_type"] not in seen_types:
                        seen_types.add(m["evidence_type"])
                        deduped.append(m)

                gaps.append({"hypothesis_id": hyp_id, "missing": deduped})

        log.debug(
            "gap_analysis_done",
            hypotheses=len(hypotheses),
            gap_count=sum(len(g["missing"]) for g in gaps),
        )
    except Exception as exc:
        log.warning("gap_analysis_failed", error=str(exc))
        return []

    return gaps
