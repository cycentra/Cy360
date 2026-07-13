# Imported Sigma Rules — Attribution

The `.yml` files under this directory are sourced, unmodified, from the
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) public repository, fetched
2026-07-13. They are licensed under the **Detection Rule License (DRL) 1.1**
(full text below / https://github.com/SigmaHQ/Detection-Rule-License) — a
permissive license: commercial use, modification, and redistribution are
allowed, provided attribution is retained.

**Attribution is satisfied by NOT stripping the `author:` field from any
rule file, and by keeping this file alongside them.** Do not remove author
fields when editing/tuning a rule copied from this directory.

## Provenance

280 rules pulled 2026-07-13, filtered to the subset that parses and
evaluates cleanly against `cysiemstack/detection/sigma_engine.py`'s
condition grammar (verified against this exact batch — see
`docs/CYDATALAKE_MIGRATION_PLAN.md` §4 for the compatibility test results
and what "compatible" means here):

| Directory | Source (upstream SigmaHQ path) | Count |
|---|---|---|
| `cloud/aws_cloudtrail/` | `rules/cloud/aws/cloudtrail/` | 55 |
| `cloud/azure_signin_logs/` | `rules/cloud/azure/signin_logs/` | 24 |
| `cloud/azure_activity_logs/` | `rules/cloud/azure/activity_logs/` | 35 |
| `cloud/azure_audit_logs/` | `rules/cloud/azure/audit_logs/` | 45 |
| `cloud/azure_identity_protection/` | `rules/cloud/azure/identity_protection/` | 19 |
| `cloud/azure_pim/` | `rules/cloud/azure/privileged_identity_management/` | 7 |
| `cloud/gcp_audit/` | `rules/cloud/gcp/audit/` | 16 |
| `cloud/m365_audit/` | `rules/cloud/m365/audit/` | 4 |
| `cloud/m365_exchange/` | `rules/cloud/m365/exchange/` | 1 |
| `cloud/m365_threat_detection/` | `rules/cloud/m365/threat_detection/` | 1 |
| `cloud/m365_threat_management/` | `rules/cloud/m365/threat_management/` | 13 |
| `identity/okta/` | `rules/identity/okta/` | 21 |
| `identity/cisco_duo/` | `rules/identity/cisco_duo/` | 1 |
| `identity/onelogin/` | `rules/identity/onelogin/` | 2 |
| `linux/auditd/` | `rules/linux/auditd/` | 6 |
| `windows/process_creation/` | `rules/windows/process_creation/` (sample — ~1000 exist upstream, only 30 pulled) | 30 |

**Not yet imported:** the other ~970 `windows/process_creation` rules, and
every other SigmaHQ category (windows non-process-creation, macos, network,
web, application, category). Re-run `../import_sigma_rules.py` against a
full local clone of SigmaHQ to pull in more — see that script's docstring.

## Known limitation — read before assuming full Sigma-spec matching

`sigma_engine.py` matches against a **flattened text representation** of
each event (message + program + JSON-dumped raw/metadata), not per-field
structured lookup. A plain field selector like `eventName: 'ConsoleLogin'`
(no `|contains` modifier — strict equality per the real Sigma spec) is
matched here as a **substring search** across that flattened text, not an
exact per-field equality check. In practice this still catches true
positives when the event's raw JSON is included in the haystack (the field
name and value both appear as literal text), but it is looser than strict
Sigma semantics and could occasionally false-positive if the same substring
appears in an unrelated field. This is a known approximation, not a bug —
building true structured per-field matching would require normalizing every
source's fields into a consistent per-logsource schema first (tracked as
open follow-on work, see docs/CYDATALAKE_MIGRATION_PLAN.md §4).

## Full DRL 1.1 text

Permission is hereby granted, free of charge, to any person obtaining a copy of this rule set and associated documentation files (the "Rules"), to deal in the Rules without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Rules, and to permit persons to whom the Rules are furnished to do so, subject to the following conditions:

If you share the Rules (including in modified form), you must retain the following if it is supplied within the Rules:

1. identification of the authors(s) ("author" field) of the Rule and any others designated to receive attribution, in any reasonable manner requested by the Rule author (including by pseudonym if designated).
2. a URI or hyperlink to the Rule set or explicit Rule to the extent reasonably practicable
3. indicate the Rules are licensed under this Detection Rule License, and include the text of, or the URI or hyperlink to, this Detection Rule License to the extent reasonably practicable

If you use the Rules (including in modified form) on data, messages based on matches with the Rules must retain the following if it is supplied within the Rules:

1. identification of the authors(s) ("author" field) of the Rule and any others designated to receive attribution, in any reasonable manner requested by the Rule author (including by pseudonym if designated).

THE RULES ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE RULES OR THE USE OR OTHER DEALINGS IN THE RULES.
