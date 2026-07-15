"""
cysiemstack/detection/sigma_engine.py
========================================
CyDataLake — Phase 0 decision implemented: a lightweight Sigma-rule-subset
matcher for CyCollector's raw generic logs and the cloud connectors (the
topics in the CyDataLake pipeline that need real detection rather than
vendor-native pre-detected alerts — see docs/CYDATALAKE_MIGRATION_PLAN.md
§0/§4).

This is NOT the `pysigma` library. pySigma is a rule-CONVERSION toolkit
(Sigma YAML → a target SIEM's query language, e.g. Elasticsearch DSL or
Splunk SPL) — it isn't designed to evaluate a rule directly against an
arbitrary Python event dict at runtime, which is what collector_bridge.py
needs at ingest time. Reusing it here would mean standing up a conversion
backend for a query language nothing runs, which is more moving parts for
less capability than just matching the standard Sigma YAML `detection:`
block shape directly. Hence: a small, self-contained subset covering
plain-value/list-value field matching with `contains`/`startswith`/
`endswith`/`re` modifiers (default = exact match, with `*`/`?` wildcard
support), boolean condition expressions (`and`/`or`/`not`/parentheses),
`1 of x*`/`all of x*`/`1 of them`/`all of them` group expansion, and
`logsource` (product/category/service) rule routing. No aggregation
(count-over-time) support — repeated single-event matches from the same
host already cluster into one incident via the correlation engine's
existing time-window grouping (grouper.py), so brute-force-style
detections don't need it here.

Field matching is REAL per-field lookup against the event's structured
data (recursive key search + dotted-path support), not a flattened
haystack/substring search. Earlier revisions of this engine did substring
matching over a joined text blob of the whole event — that produced real
false positives during testing (e.g. a rule keyed on `event_type_id: 3`
matched any event containing the substring "3" anywhere, such as inside an
IP address), because there was no per-field structured lookup and no
logsource-based rule routing. Both gaps are now closed: `matches_logsource()`
filters which rules are even evaluated against a given event based on the
hint the calling bridge provides (its vendor/OS), and `_lookup_field()`
resolves the actual field the rule asks for instead of searching the whole
event text. The only place a flattened-text search still happens is Sigma's
bare `keywords:` block shape (a list of plain strings with no field name at
all) — that block has no field to look up by definition, so full-text
search is the correct semantics for it, not a workaround.

Because the root-cause matching bug is fixed, the imported SigmaHQ corpus
(`rules/imported/`) is loaded by default — see `get_engine()`. The
`SIGMA_IMPORTED_RULES_ENABLED` env var remains as an emergency rollback
switch (set to `false` to fall back to the 3 hand-written starter rules
only) in case a broadened rule corpus surfaces a noisy rule in production
that needs to be pulled without a code deploy — Sigma-matched alerts feed
the same auto-case-opening path as every other HIGH/CRITICAL alert, so a
kill switch stays cheap insurance even with the fix in place.
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

_MAX_LOOKUP_DEPTH = 6

# Canonicalizes the handful of naming variants seen across SigmaHQ rule
# `logsource.product` values and this platform's own vendor/OS names, so
# `matches_logsource()` can compare them without every bridge needing to
# know Sigma's exact vocabulary (e.g. rules use `m365`, connector_bridge.py
# calls its vendor `office365`).
_PRODUCT_ALIASES = {
    "m365": "office365", "o365": "office365", "office365": "office365",
    "azuread": "azure", "aad": "azure", "azure": "azure",
    "aws": "aws",
    "gcp": "gcp", "google_cloud_platform": "gcp",
    "windows": "windows",
    "linux": "linux",
    "macos": "macos", "osx": "macos", "darwin": "macos",
}


def _canon_product(value: Any) -> str:
    return _PRODUCT_ALIASES.get(str(value).lower(), str(value).lower())


class SigmaRule:
    def __init__(self, data: dict[str, Any], source: str = "bundled", db_id: Optional[int] = None):
        self.title = data["title"]
        self.rule_id = data.get("id", "") or self.title
        self.level = str(data.get("level", "medium")).lower()
        if self.level not in SIGMA_RULE_IDS:
            self.level = "medium"
        self.logsource = {k: str(v).lower() for k, v in (data.get("logsource") or {}).items() if v}
        detection = data["detection"]
        self.condition = detection["condition"]
        self.selections = {k: v for k, v in detection.items() if k != "condition"}
        # source: "bundled" (rules/*.yml) | "imported" (rules/imported/**) |
        # "custom" (DB-backed, added/edited via the Detection Rules UI).
        # Only "custom" rules are editable/deletable through the API — see
        # blueprints/detection_rules/routes.py.
        self.source = source
        self.db_id = db_id
        self.enabled = True  # overwritten by SigmaEngine.__init__ from DB toggle/custom-rule state

    def matches_logsource(self, hint: Optional[dict[str, str]]) -> bool:
        """True if this rule is even eligible to run against an event from
        the given source. A rule with no `logsource:` block, or a bridge
        that supplies no hint, is permissive (matches everything) — routing
        only rejects when BOTH sides declare a value for the same key and
        those values disagree, so this never silently drops rules just
        because a bridge hasn't been taught to supply every field yet."""
        if not self.logsource or not hint:
            return True
        for key in ("product", "category", "service"):
            rule_val = self.logsource.get(key)
            hint_val = hint.get(key)
            if not rule_val or not hint_val:
                continue
            if key == "product":
                if _canon_product(rule_val) != _canon_product(hint_val):
                    return False
            elif rule_val != hint_val:
                return False
        return True

    @staticmethod
    def _lookup_field(root: Any, field: str) -> tuple[bool, list]:
        """Resolve a Sigma field name against the event's actual structure.
        Supports dotted paths (`userIdentity.type`) and, failing that, a
        depth-limited recursive search for a case-insensitive key match
        anywhere in the nested dict/list — real SigmaHQ rules reference
        fields at varying nesting depth across vendors (top-level for
        CyCollector's `message`, nested for AWS CloudTrail's
        `userIdentity.type`, etc.)."""
        if "." in field:
            cur = root
            for part in field.split("."):
                if not isinstance(cur, dict):
                    cur = None
                    break
                match_key = next((k for k in cur if k.lower() == part.lower()), None)
                if match_key is None:
                    cur = None
                    break
                cur = cur[match_key]
            else:
                return True, (cur if isinstance(cur, list) else [cur])

        def _search(node: Any, depth: int) -> tuple[bool, list]:
            if depth > _MAX_LOOKUP_DEPTH:
                return False, []
            if isinstance(node, dict):
                match_key = next((k for k in node if k.lower() == field.lower()), None)
                if match_key is not None:
                    v = node[match_key]
                    return True, (v if isinstance(v, list) else [v])
                for v in node.values():
                    found, vals = _search(v, depth + 1)
                    if found:
                        return found, vals
            elif isinstance(node, list):
                for item in node:
                    found, vals = _search(item, depth + 1)
                    if found:
                        return found, vals
            return False, []

        return _search(root, 0)

    @classmethod
    def _match_field(cls, field_expr: str, expected: Any, root: dict) -> bool:
        field, _, modifier = field_expr.partition("|")
        found, values = cls._lookup_field(root, field)

        if expected is None:
            # Sigma `field: null` means "field absent or explicitly null"
            return (not found) or all(v is None for v in values)
        if not found:
            return False

        expecteds = expected if isinstance(expected, list) else [expected]
        for v in values:
            vs = str(v).lower()
            for exp in expecteds:
                if exp is None:
                    continue
                es = str(exp).lower()
                if modifier == "contains" and es in vs:
                    return True
                if modifier == "startswith" and vs.startswith(es):
                    return True
                if modifier == "endswith" and vs.endswith(es):
                    return True
                if modifier == "re" and re.search(str(exp), str(v)):
                    return True
                if modifier == "":
                    if any(ch in es for ch in "*?"):
                        if fnmatch.fnmatch(vs, es):
                            return True
                    elif vs == es:
                        return True
        return False

    def _match_selection(self, selection: Any, root: dict) -> bool:
        # Sigma spec has two distinct list shapes under a selection name —
        # both found in the real imported corpus (see
        # docs/CYDATALAKE_MIGRATION_PLAN.md §4 for how these were discovered):
        #   - a list of MAPS = OR of AND-groups (e.g. "Granting Of Permissions
        #     To An Account")
        #   - a list of plain STRINGS = bare keyword/full-text search, no
        #     field name at all (e.g. "Number Of Resource Creation Or
        #     Deployment Activities" — a `keywords:` block). This is the one
        #     shape with no field to look up, so full-text search over the
        #     whole event is the correct semantics here, not a fallback.
        if isinstance(selection, list):
            if selection and isinstance(selection[0], dict):
                return any(self._match_selection(group, root) for group in selection)
            haystack = _haystack_of(root)
            return any(str(kw).lower() in haystack for kw in selection)
        # Otherwise: all field expressions within one selection are AND'ed.
        return all(self._match_field(field_expr, value, root)
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

    def evaluate(self, root: dict) -> bool:
        results = {name: self._match_selection(sel, root) for name, sel in self.selections.items()}
        expr = self._expand_wildcard_groups(self.condition, results)
        for name in sorted(results, key=len, reverse=True):
            expr = re.sub(rf"\b{re.escape(name)}\b", str(results[name]), expr)
        if not re.fullmatch(r"[\sTrueFalseandornot()]+", expr):
            raise ValueError(f"Unsafe/unknown token in condition {self.condition!r} -> {expr!r}")
        return bool(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 — whitelisted-token boolean expr only


def _haystack_of(root: dict) -> str:
    """Full-text fallback used ONLY for Sigma's field-less `keywords:` list
    shape (see `_match_selection` above) — every other match path resolves
    a real field via `_lookup_field` instead of searching flattened text."""
    try:
        return json.dumps(root, default=str).lower()
    except Exception:
        return str(root).lower()


def _build_root_from_event(event: dict[str, Any]) -> dict[str, Any]:
    """CyCollector's envelope shape is {message, program, source_type, raw,
    metadata, timestamp} — Sigma rules for auditd/journald-style sources
    reference the structured fields inside `raw`/`metadata` (when the
    reader captured them) as well as the well-known `message`/`program`
    fields, so merge all of it into one lookup root."""
    root: dict[str, Any] = {}
    root.update(event.get("metadata") or {})
    root.update(event.get("raw") or {})
    root["message"] = event.get("message", "")
    root["program"] = event.get("program", "")
    root["source_type"] = event.get("source_type", "")
    return root


class SigmaEngine:
    def __init__(self, rules_dir: Path = _DEFAULT_RULES_DIR, include_imported: bool = True):
        """`include_imported=True` (the default) loads both the 3 hand-written
        starter rules and the full `rules/imported/` SigmaHQ corpus. This was
        opt-in in an earlier revision because the matcher did flattened
        haystack/substring search with no logsource routing — that root
        cause is fixed (see module docstring / `matches_logsource()` /
        `_lookup_field()`), so the corpus is safe to load by default.
        `SIGMA_IMPORTED_RULES_ENABLED=false` remains as an emergency
        rollback switch (see `get_engine()`)."""
        # all_rules holds EVERY rule regardless of enabled state (bundled +
        # imported + custom) — the Detection Rules UI lists/toggles from this
        # so a disabled rule stays visible with a way back to re-enabling it.
        # `rules` is the enabled-only subset actually used for matching.
        self.all_rules: list[SigmaRule] = []
        if include_imported:
            # rglob — the imported/ subtree organizes rules into per-category
            # directories (imported/cloud/aws/, imported/windows/, etc.).
            paths = sorted(Path(rules_dir).rglob("*.yml"))
        else:
            # glob (not rglob) — top-level starter rules only, imported/ skipped.
            paths = sorted(Path(rules_dir).glob("*.yml"))
        for path in paths:
            try:
                data = yaml.safe_load(path.read_text())
                source = "imported" if "imported" in path.parts else "bundled"
                self.all_rules.append(SigmaRule(data, source=source))
            except Exception as exc:
                _log.error("Sigma engine: failed to load rule %s: %s", path, exc)

        # DB-backed layer (blueprints/detection_rules/routes.py owns writes):
        # per-rule enable/disable overrides for ANY rule above, plus fully
        # user-authored custom rules. Best-effort — a DB hiccup here should
        # never take detection down entirely, so this degrades to "disk rules
        # only, all enabled" rather than raising.
        try:
            disabled_ids, custom_rows = _load_sigma_db_state()
            for r in self.all_rules:
                r.enabled = r.rule_id not in disabled_ids
            for row in custom_rows:
                try:
                    data = yaml.safe_load(row["yaml_text"])
                    rule = SigmaRule(data, source="custom", db_id=row["id"])
                    rule.enabled = bool(row["enabled"])
                    self.all_rules.append(rule)
                except Exception as exc:
                    _log.error("Sigma engine: failed to load custom rule %s: %s", row.get("rule_key"), exc)
        except Exception as exc:
            _log.warning("Sigma engine: DB-backed rule state unavailable, using disk rules only: %s", exc)

        self.rules = [r for r in self.all_rules if r.enabled]
        _log.info("Sigma engine: loaded %d/%d enabled rule(s) from %s (include_imported=%s)",
                   len(self.rules), len(self.all_rules), rules_dir, include_imported)

    def match(self, event: dict[str, Any], logsource_hint: Optional[dict[str, str]] = None) -> Optional[SigmaRule]:
        return self._match_root(_build_root_from_event(event), logsource_hint)

    def match_raw(self, raw: dict[str, Any], logsource_hint: Optional[dict[str, str]] = None) -> Optional[SigmaRule]:
        """Match directly against a raw event dict — for sources (cloud
        connectors) whose events aren't wrapped in CyCollector's {message,
        program, raw, metadata} shape; the raw record itself is already
        the structure a real Sigma rule's field selectors expect."""
        return self._match_root(raw, logsource_hint)

    def _match_root(self, root: dict[str, Any], logsource_hint: Optional[dict[str, str]]) -> Optional[SigmaRule]:
        for rule in self.rules:
            if not rule.matches_logsource(logsource_hint):
                continue
            try:
                if rule.evaluate(root):
                    return rule
            except Exception as exc:
                _log.warning("Sigma engine: rule %r evaluation failed: %s", rule.title, exc)
        return None


def _load_sigma_db_state() -> tuple[set[str], list[dict[str, Any]]]:
    """Read sigma_rule_toggles (disabled bundled/imported rule_ids) and ALL
    custom_sigma_rules rows (both enabled and disabled — each row's own
    `enabled` column decides whether SigmaEngine.rules includes it, but
    SigmaEngine.all_rules always includes every custom rule so a disabled
    one stays visible/re-enableable in the UI) from the correlation Postgres
    DB. Owned/written by blueprints/detection_rules/routes.py — this is a
    read-only consumer. Tables may not exist yet on a fresh install (the
    blueprint creates them lazily on first use), so a missing-table error is
    treated the same as "no overrides configured" rather than an error."""
    import os
    import psycopg2
    import psycopg2.extras

    db_url = os.environ.get("CYCENTRA_DB_URL", "").strip()
    if not db_url:
        try:
            from core.config import CYCENTRA_DB_URL as _cfg_url
            db_url = _cfg_url
        except Exception:
            return set(), []
    if not db_url:
        return set(), []

    conn = psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor, connect_timeout=3)
    try:
        with conn.cursor() as cur:
            try:
                cur.execute("SELECT rule_id FROM sigma_rule_toggles WHERE enabled = false")
                disabled = {row["rule_id"] for row in cur.fetchall()}
            except Exception:
                disabled = set()
            try:
                cur.execute("SELECT id, rule_key, yaml_text, enabled FROM custom_sigma_rules")
                custom_rows = [dict(row) for row in cur.fetchall()]
            except Exception:
                custom_rows = []
        return disabled, custom_rows
    finally:
        conn.close()


def _resolve_include_imported() -> bool:
    import os
    # Default ON now that logsource routing + real per-field matching
    # replaced the haystack/substring matcher. Set to "false" (or "0"/
    # "no") to fall back to the 3 starter rules only — kept as a fast
    # server-side rollback lever, not because the corpus is expected to
    # need it under normal operation.
    return os.environ.get("SIGMA_IMPORTED_RULES_ENABLED", "true").strip().lower() not in (
        "false", "0", "no",
    )


_engine: Optional[SigmaEngine] = None


def get_engine() -> SigmaEngine:
    global _engine
    if _engine is None:
        _engine = SigmaEngine(include_imported=_resolve_include_imported())
    return _engine


def reset_engine() -> None:
    """Force the next get_engine() call to rebuild from disk + DB state.
    Called by blueprints/detection_rules/routes.py right after any Sigma
    create/edit/delete/toggle so the change is active on the very next
    event — no restart, no polling delay."""
    global _engine
    _engine = None


def list_all_rules() -> list[SigmaRule]:
    """For the Detection Rules UI's listing endpoint — returns the cached
    singleton's all_rules (bundled + imported + custom, including disabled
    ones with enabled=False, so a disabled rule stays visible with a way
    back to re-enabling it instead of vanishing).

    This used to build a brand-new SigmaEngine from scratch on every call —
    a full ~3,700-rule disk parse + DB round-trip on every page load,
    search keystroke, and pagination click. That was unnecessary caution:
    reset_engine() already invalidates the cached singleton on every Sigma
    write in blueprints/detection_rules/routes.py, so the cache is never
    stale by more than the current request. Reuse get_engine() instead."""
    return get_engine().all_rules
