---
name: bug-fix
description: Workflow for diagnosing and patching bugs in CyCentra 360. Enforces root cause analysis before any code is written and a regression test before any PR opens. Testing depth is calibrated to the type and layer of the bug. Hotfix path for production-down incidents.
triggers:
  - event: issues.labeled
    conditions:
      - label.name: "bug"
      - label.name: "regression"
      - label.name: "hotfix"
---

# Workflow: Bug Fix

## Core Principle

No code before RCA. No PR before regression test. The RELEASE_NOTES history of this project shows 30+ bugs that were variations of previously fixed issues — reading history first prevents repeating them.

---

## Step 1 — Auto-Triage (immediate on label)

Same routing logic as feature-development workflow, but default assignee for unclassified bugs is `cyra-bugfix`. For `hotfix` label: add `priority:critical`, notify @cyra-devops. Add label `status:triage-complete`.

---

## Step 2 — RELEASE_NOTES Historical Search (within 10 minutes)

Assigned agent searches RELEASE_NOTES.md for the symptom. Post result as comment:

```
## Historical Bug Search — #[N]

Symptom: [what the issue reports]

RELEASE_NOTES matches:
- v1.0.X: [description of similar fix] — [file that was fixed]
- None found — appears novel

Classification:
- Layer: Backend Flask / Correlation Engine / ASM Scanner / Frontend React / Shell Script / CI
- Category: [Auth / Env var / Circular import / Docker / DB / API contract / UI state / RBAC]
- Likely first file: path/to/file — [why]
```

---

## Step 3 — Reproduction Confirmation

Agent confirms bug is reproducible. If not reproducible within 20 minutes, request from reporter:
- Flask logs: `journalctl -u cycentra --since "1 hour ago"`
- Version: `cat /opt/cycentra/version`
- Browser console screenshot (for portal bugs)
- Engine status: `systemctl status cysiemstack-engine` (for SIEM bugs)

Add label `status:needs-repro` (waiting) or `status:reproduced` (confirmed).

---

## Step 4 — RCA Comment (mandatory before any code)

```
## RCA — #[N]

Symptom: [what the user reports]

Root cause:
- File: path/to/file.py, line [N]
- Code path: user calls [endpoint] → [function()] does [thing] → when [condition], 
  this causes [effect] because [technical reason]

Historical match: v1.0.X — [similar fix] / None — novel

Minimal fix:
- Files to change: path/to/file.py ([N] lines changed)
- Strategy: [one sentence]

Regression test:
tests/unit/test_[module].py::test_[regression_name]
This test FAILS on current code, PASSES after fix.
```

Add label `status:rca-complete`.

---

## Step 5 — Regression Test First

Branch: `bugfix/<issue-number>-<slug>`.

Write the regression test. Commit it. Verify it fails against current code. This is not optional — it proves the test catches the bug.

---

## Step 6 — Minimal Patch

Apply the fix. Change the fewest lines possible. No refactors. No unrelated improvements. One bug per PR.

Verify:
- Regression test now passes
- Suite 01 still passes
- RELEASE_NOTES entry written using release-notes-writer skill

---

## Step 7 — Testing Depth for Bug Fixes

Bug fix testing uses the feature-development Testing Depth Matrix PLUS these additions:

| Bug category | Additional suite |
|-------------|-----------------|
| Any auth or session bug | + Suite 04 (OWASP) forced |
| Any env var bug in setup.sh | + Suite 09 (Infra) to verify template |
| Any SIEM or correlation bug | + Suite 06 (Correlation accuracy) |
| Any CORS or route protection bug | + Suite 03 (API contract) forced |
| `hotfix` label | Suite 01 + Suite 03 + layer-specific suite only |

---

## Step 8 — Hotfix Fast-Track

If labelled `hotfix` (production-down):
- Historical search: 2 minutes max
- RCA: required, abbreviated format acceptable
- PR targets `main` directly
- cyra-test: Suite 01 + Suite 03 + affected-layer suite only (expedited)
- cyra-devops: patch release tag created immediately after merge
