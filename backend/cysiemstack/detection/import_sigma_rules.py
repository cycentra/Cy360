#!/usr/bin/env python3
"""
cysiemstack/detection/import_sigma_rules.py
==============================================
Bulk-imports SigmaHQ rules into cysiemstack/detection/rules/imported/,
filtering to what this engine (sigma_engine.py) can actually load and
evaluate. Run it against a fresh SigmaHQ clone to (re)pull the full corpus
or pick up upstream updates — full-corpus import is the current default
posture (see sigma_engine.get_engine()), not an opt-in curated subset.

Usage (single pass over the whole upstream rules/ tree — preserves
upstream subdirectory structure under --dest, see the collision-avoidance
note below):
    git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma-upstream
    python3 import_sigma_rules.py /tmp/sigma-upstream/rules \
        --dest rules/imported

Can also be pointed at a single upstream subdirectory if you want to
refresh/add just one category:
    python3 import_sigma_rules.py /tmp/sigma-upstream/rules/cloud/aws \
        --dest rules/imported/cloud/aws

What gets filtered out (and why — see docs/CYDATALAKE_MIGRATION_PLAN.md §4
for the full writeup, this is a summary):
  - Rules with a `count(`/`| count`/`near`/`timeframe` aggregation condition —
    this engine has no aggregation support (by design; repeated single-event
    matches already cluster via the correlation engine's grouper.py).
  - Rules containing an unfilled `<placeholder text>` value (a documented
    Sigma authoring convention for "customize this before use") — these
    match almost everything if loaded as-is and were the cause of a real
    false-positive bug found while building this importer.
  - Rules whose `detection.condition` doesn't parse/evaluate cleanly against
    SigmaRule's condition grammar (reported, not silently dropped).

Field-matching false positives (e.g. a rule keyed on `event_type_id: 3`
matching any event containing the substring "3") were a structural
limitation of the OLD haystack/substring matcher with no logsource-based
rule routing. sigma_engine.py now does real per-field lookup
(`SigmaRule._lookup_field`) plus `logsource` product/category/service
routing (`SigmaRule.matches_logsource`), which is why the imported corpus
graduated from opt-in to loaded-by-default. This importer still can't
statically prove a rule is noise-free against YOUR traffic — validate new
imports with validate_sigma_rules.py (shadow-mode sample check) before
assuming zero false positives, and SIGMA_IMPORTED_RULES_ENABLED=false stays
available as a fast rollback if a real deployment turns up a noisy rule.
"""
from __future__ import annotations
import argparse
import re
import shutil
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent.parent))  # backend/ on path
from cysiemstack.detection.sigma_engine import SigmaRule  # noqa: E402

_AGG_KEYWORDS = re.compile(r"\bcount\s*\(|\|\s*count\b|\bnear\b", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(r"<[A-Za-z][^<>]{2,80}>")


def _contains_placeholder(obj) -> bool:
    if isinstance(obj, str):
        return bool(_PLACEHOLDER_RE.search(obj))
    if isinstance(obj, dict):
        return any(_contains_placeholder(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_placeholder(v) for v in obj)
    return False


def _is_compatible(data: dict) -> tuple[bool, str]:
    detection = data.get("detection")
    if not detection or "condition" not in detection:
        return False, "no detection/condition block"

    condition = str(detection["condition"])
    if _AGG_KEYWORDS.search(condition) or "timeframe" in detection:
        return False, "aggregation (count/near/timeframe) — not supported"

    if _contains_placeholder(detection):
        return False, "unfilled <placeholder> value — needs manual site-specific config"

    try:
        rule = SigmaRule(data)
        fake = {name: False for name in rule.selections}
        expr = rule._expand_wildcard_groups(rule.condition, fake)
        for name in sorted(fake, key=len, reverse=True):
            expr = re.sub(rf"\b{re.escape(name)}\b", "False", expr)
        if not re.fullmatch(r"[\sTrueFalseandornot()]+", expr):
            return False, f"condition syntax unsupported: {condition!r}"
        eval(expr, {"__builtins__": {}}, {})  # noqa: S307
    except Exception as exc:
        return False, f"failed to load: {exc}"

    return True, "ok"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source_dir", help="Directory of upstream Sigma .yml files (searched recursively)")
    parser.add_argument("--dest", required=True, help="Destination directory under rules/imported/")
    args = parser.parse_args()

    src = Path(args.source_dir)
    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)

    imported, skipped = 0, 0
    skip_reasons: dict[str, int] = {}
    seen_names: dict[str, int] = {}

    for path in sorted(src.rglob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text())
        except Exception as exc:
            print(f"SKIP  {path.name}: YAML parse error: {exc}")
            skipped += 1
            continue

        ok, reason = _is_compatible(data)
        if ok:
            # Preserve the upstream relative directory structure instead of
            # flattening into dest/path.name — a full-corpus bulk import
            # pulls thousands of rules from many upstream subdirectories,
            # and filenames collide across categories (e.g. the same
            # generic rule name reused under both windows/ and linux/).
            # Flattening would silently clobber one with the other.
            rel = path.relative_to(src)
            out_path = dest / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if out_path.exists():
                seen_names[str(rel)] = seen_names.get(str(rel), 1) + 1
                out_path = out_path.with_name(f"{out_path.stem}__{seen_names[str(rel)]}{out_path.suffix}")
            shutil.copy(path, out_path)
            imported += 1
        else:
            skipped += 1
            skip_reasons[reason.split(":")[0]] = skip_reasons.get(reason.split(":")[0], 0) + 1

    print(f"\nImported {imported} rule(s) into {dest}")
    print(f"Skipped {skipped} rule(s):")
    for reason, count in sorted(skip_reasons.items(), key=lambda x: -x[1]):
        print(f"  {count:4d}  {reason}")
    print("\nImported rules load by default at runtime now (SIGMA_IMPORTED_RULES_ENABLED=false "
          "to roll back to the 3 starter rules only) — see sigma_engine.py. Run "
          "validate_sigma_rules.py before deploying a fresh import.")


if __name__ == "__main__":
    main()
