"""
cysiemstack/detection/sigma_engine.py
========================================
CyDataLake — Phase 0 decision implemented: a lightweight Sigma-rule-subset
matcher for CyCollector's raw generic logs (the ONE topic in the whole
CyDataLake pipeline that still needs real detection — every vendor
connector already ships pre-detected alerts, see
docs/CYDATALAKE_MIGRATION_PLAN.md §0/§4).

This is NOT the `pysigma` library. pySigma is a rule-CONVERSION toolkit
(Sigma YAML → a target SIEM's query language, e.g. Elasticsearch DSL or
Splunk SPL) — it isn't designed to evaluate a rule directly against an
arbitrary Python event dict at runtime, which is what collector_bridge.py
needs at ingest time. Reusing it here would mean standing up a conversion
backend for a query language nothing runs, which is more moving parts for
less capability than just matching the standard Sigma YAML `detection:`
block shape directly. Hence: a small, self-contained subset covering what
the bundled starter rules need — plain-value/list-value field matching with
`contains`/`startswith`/`endswith`/`re` modifiers, and boolean condition
expressions (`and`/`or`/`not`/parentheses). No aggregation (count-over-time)
support — repeated single-event matches from the same host already cluster
into one incident via the correlation engine's existing time-window
grouping (grouper.py), so brute-force-style detections don't need it here.

Full Sigma-spec parity (timeframe/aggregation, `logsource` backend
targeting, etc.) is future work if this subset proves too limited — it is
deliberately not attempted now given no live traffic has validated even
this smaller surface yet.
"""
from __future__ import annotations
import fnmatch
import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

import yaml

_log = logging.getLogger(__name__)

_DEFAULT_RULES_DIR = Path(__file__).parent / "rules"

# level → rule_id, mirrors normaliser._level_to_score()/grouper._score_to_severity()
# See docs/CYDATALAKE_MIGRATION_PLAN.md §11 — reserved range 101150-101153 for
# Sigma-matched CyCollector events (distinct from the flat undetected 101100 bucket).
SIGMA_RULE_IDS = {"critical": 101150, "high": 101151, "medium": 101152, "low": 101153}

# Reserved range 101380-101383 — Sigma-matched CLOUD CONNECTOR events (office365/
# azure/aws/gcp in connector_bridge.py), distinct from SIGMA_RULE_IDS above so an
# operator can tell "matched a real Sigma rule via CyCollector" from "matched a
# real Sigma rule via a cloud connector" apart in the Alert Feed.
CONNECTOR_SIGMA_RULE_IDS = {"critical": 101380, "high": 101381, "medium": 101382, "low": 101383}


class SigmaRule:
    def __init__(self, data: dict[str, Any]):
        self.title = data["title"]
        self.rule_id = data.get("id", "")
        self.level = str(data.get("level", "medium")).lower()
        if self.level not in SIGMA_RULE_IDS:
            self.level = "medium"
        detection = data["detection"]
        self.condition = detection["condition"]
        self.selections = {k: v for k, v in detection.items() if k != "condition"}

    @staticmethod
    def _match_field(field_expr: str, value: Any, haystack: str) -> bool:
        _, _, modifier = field_expr.partition("|")
        values = value if isinstance(value, list) else [value]
        for v in values:
            v = str(v).lower()
            h = haystack.lower()
            if modifier in ("", "contains") and v in h:
                return True
            if modifier == "startswith" and h.startswith(v):
                return True
            if modifier == "endswith" and h.endswith(v):
                return True
            if modifier == "re" and re.search(str(value), haystack):
                return True
        return False

    def _match_selection(self, selection: Any, haystack: str) -> bool:
        # Sigma spec has two distinct list shapes under a selection name —
        # both found in the real imported corpus (see
        # docs/CYDATALAKE_MIGRATION_PLAN.md §4 for how these were discovered):
        #   - a list of MAPS = OR of AND-groups (e.g. "Granting Of Permissions
        #     To An Account")
        #   - a list of plain STRINGS = bare keyword/full-text search, no
        #     field name at all (e.g. "Number Of Resource Creation Or
        #     Deployment Activities" — a `keywords:` block)
        if isinstance(selection, list):
            if selection and isinstance(selection[0], dict):
                return any(self._match_selection(group, haystack) for group in selection)
            return any(str(kw).lower() in haystack.lower() for kw in selection)
        # Otherwise: all field expressions within one selection are AND'ed.
        return all(self._match_field(field_expr, value, haystack)
                   for field_expr, value in selection.items())

    def _expand_wildcard_groups(self, expr: str, results: dict[str, bool]) -> str:
        """Expand Sigma's `1 of x*` / `all of x*` / `1 of them` / `all of them`
        group syntax into an explicit or/and expression over matching selection
        names, before the plain name->True/False substitution runs. This one
        piece of syntax covers roughly a third of real SigmaHQ rules (verified
        against a 135-rule sample pulled from the live SigmaHQ repo while
        building this engine — see docs/CYDATALAKE_MIGRATION_PLAN.md §4)."""
        names = list(results.keys())

        def _replace(m: re.Match) -> str:
            quantifier, pattern = m.group(1), m.group(2)
            if pattern == "them":
                matched = names
            else:
                matched = fnmatch.filter(names, pattern)
            if not matched:
                return "False"
            joiner = " and " if quantifier == "all of" else " or "
            return "(" + joiner.join(matched) + ")"

        return re.sub(r"\b(1 of|all of)\s+([\w*]+)(?=[\s)]|$)", _replace, expr)

    def evaluate(self, haystack: str) -> bool:
        results = {name: self._match_selection(sel, haystack) for name, sel in self.selections.items()}
        expr = self._expand_wildcard_groups(self.condition, results)
        for name in sorted(results, key=len, reverse=True):
            expr = re.sub(rf"\b{re.escape(name)}\b", str(results[name]), expr)
        if not re.fullmatch(r"[\sTrueFalseandornot()]+", expr):
            raise ValueError(f"Unsafe/unknown token in condition {self.condition!r} -> {expr!r}")
        return bool(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 — whitelisted-token boolean expr only


def _build_haystack(event: dict[str, Any]) -> str:
    return " ".join([
        str(event.get("message", "")),
        str(event.get("program", "")),
        json.dumps(event.get("raw") or {}),
        json.dumps(event.get("metadata") or {}),
    ])


class SigmaEngine:
    def __init__(self, rules_dir: Path = _DEFAULT_RULES_DIR, include_imported: bool = False):
        """`include_imported=False` (the default) loads ONLY the 3 hand-written,
        hand-tested starter rules directly under rules/ — NOT the 279-rule
        rules/imported/ corpus pulled from SigmaHQ.

        This default is deliberate, not conservative-for-no-reason: testing
        the imported corpus against synthetic events during development
        surfaced real false-positive collisions from short/common field
        values (e.g. a rule keyed on `event_type_id: 3` matched an SSH log
        line purely because it contains the substring "3" somewhere, e.g. in
        an IP address) — a direct consequence of this engine's haystack/
        substring matching having no per-field structured lookup or
        logsource-based rule routing (see docs/CYDATALAKE_MIGRATION_PLAN.md
        §4 for the full writeup). The imported corpus is real, was verified
        to load and evaluate its condition logic correctly against 279 live
        SigmaHQ rules, and is a legitimate head start — but it needs curation
        or (better) real per-field matching before being safe to run against
        production traffic unattended. Set SIGMA_IMPORTED_RULES_ENABLED=true
        to opt in anyway (e.g. for testing against a specific known-good
        subset)."""
        self.rules: list[SigmaRule] = []
        if include_imported:
            # rglob — the imported/ subtree organizes rules into per-category
            # directories (imported/cloud/aws_cloudtrail/, etc.).
            paths = sorted(Path(rules_dir).rglob("*.yml"))
        else:
            # glob (not rglob) — top-level starter rules only, imported/ skipped.
            paths = sorted(Path(rules_dir).glob("*.yml"))
        for path in paths:
            try:
                data = yaml.safe_load(path.read_text())
                self.rules.append(SigmaRule(data))
            except Exception as exc:
                _log.error("Sigma engine: failed to load rule %s: %s", path, exc)
        _log.info("Sigma engine: loaded %d rule(s) from %s (include_imported=%s)",
                   len(self.rules), rules_dir, include_imported)

    def match(self, event: dict[str, Any]) -> Optional[SigmaRule]:
        return self._match_haystack(_build_haystack(event))

    def match_raw(self, raw: dict[str, Any]) -> Optional[SigmaRule]:
        """Match directly against a raw event dict's JSON text — for sources
        (cloud connectors) whose events aren't wrapped in CyCollector's
        {message, program, raw, metadata} shape; the raw record itself is
        already what a real Sigma rule's field selectors expect to search."""
        return self._match_haystack(json.dumps(raw))

    def _match_haystack(self, haystack: str) -> Optional[SigmaRule]:
        for rule in self.rules:
            try:
                if rule.evaluate(haystack):
                    return rule
            except Exception as exc:
                _log.warning("Sigma engine: rule %r evaluation failed: %s", rule.title, exc)
        return None


_engine: Optional[SigmaEngine] = None


def get_engine() -> SigmaEngine:
    global _engine
    if _engine is None:
        import os
        include_imported = os.environ.get("SIGMA_IMPORTED_RULES_ENABLED", "false").lower() == "true"
        _engine = SigmaEngine(include_imported=include_imported)
    return _engine
