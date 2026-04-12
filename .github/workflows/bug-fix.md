---
name: bug-fix
description: Workflow for diagnosing and patching bugs in CyCentra 360. Enforces root cause analysis before any code is written. Agent implements fix, opens PR with auto-merge label, pipeline releases automatically. No testing gate, no human merge/approve/reject.
triggers:
  - event: issues.labeled
    conditions:
      - label.name: "bug"
      - label.name: "regression"
      - label.name: "hotfix"
---

# Workflow: Bug Fix

## Core Principle

No code before RCA. The RELEASE_NOTES history of this project shows 30+ bugs that were variations of previously fixed issues — reading history first prevents repeating them.

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
```

Add label `status:rca-complete`.

---

## Step 5 — Minimal Patch on Branch

Branch: `bugfix/<issue-number>-<slug>`. Commit format: `fix(scope): description — closes #N`.

Apply the fix. Change the fewest lines possible. No refactors. No unrelated improvements. One bug per PR.

Pre-PR self-validation:
```
[ ] Python AST check passes for all modified .py files
[ ] Frontend: npm run build passes with 0 errors (if portal files changed)
[ ] RELEASE_NOTES entry written (new ## vX.X.X block at top of RELEASE_NOTES.md)
```

---

## Step 6 — PR Opens with auto-merge Label

Agent opens the PR and **immediately adds the `auto-merge` label**.

- `agent-auto-merge.yml` fires on the label event
- PR is merged automatically — no human approval required
- `agent-release.yml` stamps version, creates git tag, triggers `deploy.yml`
- `deploy.yml` builds and publishes the GitHub Release
- Issue is closed automatically via `closes #N` in PR description

---

## Step 7 — Hotfix Fast-Track

If labelled `hotfix` (production-down):
- Historical search: 2 minutes max
- RCA: required, abbreviated format acceptable
- Branch targets `main` directly
- PR opens immediately with `auto-merge` label — release pipeline fires automatically
