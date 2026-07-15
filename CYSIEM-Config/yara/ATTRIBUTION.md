# cycentra.yar — Attribution

`cycentra.yar` contains two sections:

1. **CyCentra hand-written rules** (23 rules, `CyCentra_*` naming) — original,
   at the top of the file.
2. **Imported rules** (1,595 rules) — sourced, unmodified in content (only
   each file's own `import` statement was hoisted to a shared header to
   avoid duplicate import lines), from
   [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base),
   commit `43b2b2faafdaeb7f00102673f62555a2feb04c1b` (2026-06-17). Licensed
   under the **Detection Rule License (DRL) 1.1** (full text below /
   https://github.com/SigmaHQ/Detection-Rule-License) — a permissive
   license: commercial use, modification, and redistribution are allowed,
   provided attribution is retained.

**Attribution is satisfied by NOT stripping the `author`/`reference` meta
fields from any imported rule, and by keeping this file alongside them.**

## Why a curated subset, not the full corpus

signature-base's `yara/` directory has 751 files. Two categories were
excluded entirely:

- **`apt_*` (318 files)** — threat-actor/campaign-specific IOC rules. Narrow
  applicability for a default bundled ruleset, and the largest single
  category by file count.
- **`expl_*`/`exploit_*` (54 files)** — exploit-kit-specific signatures.

From the remaining ~380 files, 340 were kept; 15 more were dropped because
they reference external variables (`filename`, `filepath`, `extension`,
`filetype`) or the `cuckoo` sandbox module that CyEDR's scan invocation
doesn't supply — it runs a single recursive `yara -r rulefile path` pass per
scan, not a per-file invocation with externals defined. Filtering happened
at the **file level**, not by extracting individual rule blocks — regex-
splitting real-world YARA source around block comments and nested braces is
unreliable; dropping a whole file over a handful of incompatible rules is a
small, safe cost. See `import_signature_base.py` for the exact filter logic.

**Result: 1,618 total rules** (23 CyCentra + 1,595 imported), verified with
a real `yarac` compile — **zero errors, zero warnings** — and a real scan
timing test (`yara -r cycentra.yar /usr/bin`, 884 files / 80MB) completed in
0.47s with zero false positives on legitimate system binaries.

## Re-importing / refreshing

```
git clone --depth 1 https://github.com/Neo23x0/signature-base /tmp/signature-base
python3 CYSIEM-Config/yara/import_signature_base.py /tmp/signature-base/yara CYSIEM-Config/yara/cycentra.yar
```

This regenerates the imported section only — the 23 hand-written `CyCentra_*`
rules at the top of the file are preserved by the script, not re-fetched.
**Always re-run `yarac <file> /tmp/check.yarc` after any refresh** — a newer
signature-base commit may introduce rules with syntax this filter doesn't
yet account for.

## Detection Rule License (DRL) 1.1

Full text: https://github.com/SigmaHQ/Detection-Rule-License

Summary (not a substitute for the full text): permits use, copying,
modification, merging, publishing, and distribution of the licensed
detection rules, including for commercial purposes, provided the original
author/reference attribution is preserved. Provided "as is", without
warranty of any kind.
