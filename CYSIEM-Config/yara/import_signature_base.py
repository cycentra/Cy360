#!/usr/bin/env python3
"""
CYSIEM-Config/yara/import_signature_base.py
==============================================
Regenerates the imported section of cycentra.yar from a fresh
Neo23x0/signature-base clone, preserving the hand-written CyCentra_* rules
at the top of the file untouched.

Usage:
    git clone --depth 1 https://github.com/Neo23x0/signature-base /tmp/signature-base
    python3 CYSIEM-Config/yara/import_signature_base.py \
        /tmp/signature-base/yara CYSIEM-Config/yara/cycentra.yar

Curated category allowlist (see ATTRIBUTION.md for the full rationale):
  gen_, generic_, crime_, mal_, hktl_, htkl_, webshell, vuln_, vul_, susp_,
  pua_, pup_, thor-hacktools, thor-webshells
Deliberately excluded: apt_* (threat-actor-specific, largest category by far),
expl_*/exploit_* (exploit-kit-specific).

Compatibility filter (file-level, not per-rule — see the module docstring
in the git history / ATTRIBUTION.md for why per-rule splitting was
abandoned): drops any file referencing the cuckoo sandbox module or the
filename/filepath/extension/filetype external variables, since CyEDR's
scan invocation is a single recursive `yara -r rulefile path` pass with no
per-file externals defined.

ALWAYS re-run `yarac <output> /tmp/check.yarc` after regenerating — this
script's filter is necessary but not sufficient; a newer signature-base
commit may introduce syntax this filter doesn't yet account for.
"""
from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path

CATEGORY_PREFIXES = (
    "gen_", "generic_", "crime_", "mal_", "hktl_", "htkl_", "webshell",
    "vuln_", "vul_", "susp_", "pua_", "pup_", "thor-hacktools", "thor-webshells",
)
EXTERNAL_VAR_RE = re.compile(r"\b(filename|filepath|extension|filetype)\b")
CUCKOO_RE = re.compile(r'import\s+"cuckoo"')
IMPORT_MARKER = "// =============================================================================\n// Imported from Neo23x0/signature-base"


def _select_candidates(src_dir: Path) -> list[Path]:
    candidates = []
    for prefix in CATEGORY_PREFIXES:
        candidates.extend(src_dir.glob(f"{prefix}*.yar"))
    return sorted(set(candidates))


def _filter_and_merge(paths: list[Path]) -> tuple[str, int, int]:
    kept_imports: set[str] = set()
    kept_bodies: list[str] = []
    kept, dropped = 0, 0

    for path in paths:
        text = path.read_text(errors="ignore")
        if CUCKOO_RE.search(text) or EXTERNAL_VAR_RE.search(text):
            dropped += 1
            continue
        for m in re.finditer(r'^import\s+"(\w+)"', text, re.MULTILINE):
            kept_imports.add(m.group(1))
        body = re.sub(r'^import\s+"\w+"\s*\n', "", text, flags=re.MULTILINE)
        kept_bodies.append(f"// ---- source: {path.name} ----\n{body.rstrip()}\n")
        kept += 1

    header = "".join(f'import "{m}"\n' for m in sorted(kept_imports))
    return header + "\n" + "\n".join(kept_bodies), kept, dropped


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source_dir", help="Path to a signature-base clone's yara/ directory")
    parser.add_argument("dest_file", help="Path to cycentra.yar — hand-written rules before the "
                                           "import marker are preserved; everything after is replaced")
    parser.add_argument("--commit", default="", help="signature-base commit SHA, for the header comment")
    args = parser.parse_args()

    src_dir = Path(args.source_dir)
    dest = Path(args.dest_file)

    existing = dest.read_text() if dest.exists() else ""
    marker_idx = existing.find(IMPORT_MARKER)
    preserved = existing[:marker_idx].rstrip() + "\n" if marker_idx != -1 else existing.rstrip() + "\n"

    candidates = _select_candidates(src_dir)
    merged, kept, dropped = _filter_and_merge(candidates)

    commit_note = f"commit {args.commit}, " if args.commit else ""
    import_header = (
        "\n// =============================================================================\n"
        f"// Imported from Neo23x0/signature-base (github.com/Neo23x0/signature-base), {commit_note}\n"
        "// regenerated via import_signature_base.py. See ATTRIBUTION.md for full rationale,\n"
        "// license terms, and the compatibility-filter details.\n"
        "// =============================================================================\n"
    )

    dest.write_text(preserved + import_header + merged)
    print(f"Kept {kept} file(s), dropped {dropped} file(s) (external-var-dependent or cuckoo-based)")
    print(f"Wrote {dest} — remember to run: yarac {dest} /tmp/check.yarc")


if __name__ == "__main__":
    main()
