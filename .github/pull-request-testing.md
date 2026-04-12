---
name: pull-request-testing
description: Automated testing workflow. Fires on every PR opened or updated. Determines testing depth from the changed file list, runs applicable suites via the test scripts, posts a structured report, and manages tests:passed, tests:failed, and blocked labels. cyra-test executes this workflow.
triggers:
  - event: pull_request.opened
  - event: pull_request.synchronize
  - event: issues.labeled
    conditions:
      - label.name: "needs:testing"
---

# Workflow: Pull Request Testing

## Activation

Fires on:
- Any PR opened or updated (new commits pushed = synchronize event)
- Any issue or PR with label `needs:testing` added
- Comment `/retest` on a PR (re-runs all applicable suites)

---

## Execution (by cyra-test)

1. Compute changed files: `git diff --name-only HEAD~1 HEAD`
2. Apply Testing Depth Matrix from feature-development workflow to determine suite list
3. Run: `tests/run-all.sh --suite <computed comma-separated list>`
4. Collect pass/fail counts and stdout from each suite's exit code
5. Post (or update existing) test report comment on the PR
6. Set labels

---

## Test Report Comment

cyra-test posts one comment per PR. On re-run it UPDATES the existing comment — never creates a duplicate.

```markdown
## 🧪 cyra-test — PR #[N] Test Report

**Commit:** `[SHA]` | **Author:** @[author] | **Run:** #[N]  
**Changed files:** [N] total — [N] Python, [N] JSX, [N] Shell  
**Selected suites:** [01, 02, 03, ...] — computed from changed files

| # | Suite | Status | Tests | Pass | Fail | Duration |
|---|-------|--------|-------|------|------|---------|
| 01 | Smoke & Validation | ✅ PASS | 8 | 8 | 0 | 12s |
| 02 | Unit Tests | ✅ PASS | 52 | 52 | 0 | 38s |
| 03 | API Contract | ✅ PASS | 21 | 21 | 0 | 24s |

**Coverage (modified files):** Backend 84% ✅ (min 80%) | Frontend build ✅

---

### ✅ Overall: PASS — ready to merge

---
(If failures exist:)

### ❌ Blocking failures:
- [01] backend/siem_proxy.py line 4: `from app import get_user_role` — circular import (v4.3 regression)
- [04 A01] POST /api/platform/install returned 200 for viewer role — access control bypass

**Labels set:** `tests:failed` `blocked`  
**To retry:** comment `/retest` on this PR
```

---

## Label Management

| Outcome | Add | Remove |
|---------|-----|--------|
| All blocking suites pass | `tests:passed` | `tests:failed`, `blocked`, `needs:testing` |
| Any blocking suite fails | `tests:failed`, `blocked` | `tests:passed` |
| Suite 05 (load) fails only | no blocking label | — |

---

## Suite Blocking Classification

| Suite | Blocking |
|-------|---------|
| 01 Smoke & Validation | YES — always |
| 02 Unit Tests | YES — coverage < 80% for modified files |
| 03 API Contract | YES — unprotected route or missing CORS |
| 04 OWASP Security | YES — any A01/A03/A07 finding |
| 05 Load & Performance | NO — warning only |
| 06 Correlation Accuracy | YES — rule raises exception |
| 07 ASM Modules | YES — module raises exception or invalid schema |
| 08 Frontend Build | YES — build failure |
| 09 Infrastructure | YES — shellcheck errors (warnings non-blocking) |
| 10 E2E Integration | YES — auth bypass or RBAC failure |
