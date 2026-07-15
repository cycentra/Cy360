# Imported Sigma Rules — Attribution

The `.yml` files under this directory are sourced, unmodified, from the
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) public repository, commit
`65b39fa48afc2739ed01df03ef61c68be995bb36` (2026-07-14). They are licensed
under the **Detection Rule License (DRL) 1.1** (full text below /
https://github.com/SigmaHQ/Detection-Rule-License) — a permissive license:
commercial use, modification, and redistribution are allowed, provided
attribution is retained.

**Attribution is satisfied by NOT stripping the `author:` field from any
rule file, and by keeping this file alongside them.** Do not remove author
fields when editing/tuning a rule copied from this directory.

## Provenance

Full-corpus import performed 2026-07-14 as part of the v1.0.213 root-cause
false-positive fix (real per-field matching + logsource routing replaced
the earlier haystack/substring matcher — see
`docs/CYDATALAKE_MIGRATION_PLAN.md` §4). 3,736 rules imported (out of 3,749
candidates scanned; 13 rejected for unfilled `<placeholder>` values), via
`import_sigma_rules.py`, which now preserves the upstream subdirectory
structure under `--dest` rather than flattening filenames — a full-corpus
import pulls thousands of files from many upstream categories and
filenames collide across them.

| Directory | Source (upstream SigmaHQ path) | Count |
|---|---|---|
| `rules/` | `rules/` (production rule set: application, category, cloud, identity, linux, macos, network, web, windows) | 3,129 |
| `emerging-threats/` | `rules-emerging-threats/` (fast-response rules for actively-exploited/high-profile threats) | 467 |
| `threat-hunting/` | `rules-threat-hunting/` (broader/lower-confidence hunting rules, not incident-grade alone) | 140 |

Deliberately NOT imported from the same upstream repo: `rules-placeholder/`
(every rule requires manual site-specific configuration — would all be
rejected by the placeholder filter anyway), `unsupported/` (SigmaHQ
maintainers flag these as not reliably convertible/evaluable), `deprecated/`
(superseded by newer rules already present in `rules/`), and
`rules-compliance/` (3 rules, compliance-framework mapping rather than
threat detection — out of scope for this engine).

Rules are NOT re-checked for whether a corresponding connector/logsource
exists in this platform yet — `logsource.product` values for `okta`,
`onelogin`, and `cisco` (the `identity/` subtree) currently have no
connector supplying that hint, so those specific rules load but stay
dormant until such a connector exists. This is intentional: rule coverage
is expected to lead connector coverage as more integrations are added (see
the product-owner decision recorded in
`docs/CYDATALAKE_MIGRATION_PLAN.md` §4).

Validate any future re-import with
`python3 -m cysiemstack.detection.validate_sigma_rules` before deploying
(`backend/cysiemstack/detection/validate_sigma_rules.py`) — an offline
benign+known-bad fixture smoke test, not a substitute for watching real
production traffic on rule IDs 101150-101153/101380-101383 after the
refresh.

## Detection Rule License (DRL) 1.1

Full text: https://github.com/SigmaHQ/Detection-Rule-License

Summary (not a substitute for the full text): permits use, copying,
modification, merging, publishing, and distribution of the licensed
detection rules, including for commercial purposes, provided the original
copyright/attribution notice is preserved. Provided "as is", without
warranty of any kind.
