---
name: feature-development
description: End-to-end workflow for implementing a new CyCentra 360 feature or enhancement. Handles automatic agent routing, implementation governance, cross-agent review, and depth-calibrated automated testing. Testing depth is computed from the actual files changed — not chosen manually.
triggers:
  - event: issues.labeled
    conditions:
      - label.name: "feature"
      - label.name: "enhancement"
  - event: issues.assigned
---

# Workflow: Feature Development

## Trigger

Fires when an issue is labelled `feature` or `enhancement`, or when an issue is assigned to a specific agent.

---

## Step 1 — Automatic Agent Routing (fires immediately on label)

GitHub Actions reads the issue title and body and routes to the correct agent:

| Issue body contains | Assign to | Add label |
|--------------------|-----------|-----------|
| `cy_asm`, `scan`, `module`, `vulnerability`, `subdomain`, `asset discovery` | `cyra-asm` | `agent:cyra-asm` |
| `correlat`, `siem`, `incident`, `ueba`, `rule`, `iris`, `wazuh` | `cyra-siem` | `agent:cyra-siem` |
| `auth`, `oauth`, `oidc`, `rbac`, `role`, `cookie`, `session` | `cyra-rbac` | `agent:cyra-rbac` |
| `setup.sh`, `deploy.yml`, `ci`, `release`, `pyproject`, `bundle`, `artifact` | `cyra-devops` | `agent:cyra-devops` |
| Anything else (portal, blueprint, API, fullstack, page, component) | `cyra-360` | `agent:cyra-360` |

For ambiguous issues with multiple keyword categories: assign highest-match agent as primary, add secondary agent label for review.

Action: add label `status:assigned`.

---

## Step 2 — Implementation Plan Comment (target: within 30 minutes)

The assigned agent posts an implementation plan comment before writing any code. The plan must include:
- Classification (feature / enhancement / backend-only / frontend-only / fullstack)
- Complete file list: files to create and modify with one-line description of the change
- RBAC level for any new routes
- New env vars needed (if any)
- Cross-agent notifications needed
- Predicted test suites that cyra-test will run (based on expected file changes)

Agent adds label `status:planning`.

---

## Step 3 — Implementation on Branch

Agent implements on a branch named `feature/<issue-number>-<slug>`. Commit format: `feat(scope): description — closes #N`.

**Self-monitoring rules during implementation (agent enforces these internally):**
- `backend/app.py` stays under 70 lines — if approaching, extract new capability to a Blueprint
- `portal/src/App.jsx` stays under 120 lines — if approaching, extract to a page component
- Every new `/api/` route has RBAC decorator (session check + role check where needed)
- Every new POST/PUT/DELETE path has OPTIONS preflight handler
- No `from app import` anywhere in blueprint files
- IRIS config always via `get_iris_config()` from `core.helpers`

**Cross-agent notification triggers during implementation:**
- New env var added → comment "@cyra-devops: new env var `VAR_NAME` needs cycentra-setup.sh .env template"
- Schema change in `adaptCyCentraJSON` or scan result → comment "@cyra-asm: schema change — please verify module output still parses correctly"
- New SIEM engine endpoint → comment "@cyra-siem: new engine endpoint added — please verify proxy route and RBAC"
- New `/api/` route → cyra-rbac is automatically requested as reviewer when PR opens

Agent adds label `status:in-progress`.

---

## Step 4 — Pre-PR Self-Validation (agent runs before opening PR)

```
[ ] Python AST check: python3 -c "import ast; ast.parse(open('file.py').read())" passes for all new/modified .py files
[ ] Frontend: npm run build passes with 0 errors and 0 circular import warnings
[ ] All new routes have auth check (→ 401) and role check where needed (→ 403)
[ ] All non-GET paths have OPTIONS handler returning 204
[ ] env-var-auditor skill run if any os.environ usage added or changed
[ ] RELEASE_NOTES entry drafted using release-notes-writer skill
[ ] app.py still under 70 lines, App.jsx still under 120 lines
```

---

## Step 5 — PR Opens → Testing Depth Computed Automatically

When PR is opened or updated, GitHub Actions:
1. Computes changed file list from `git diff --name-only`
2. Applies the Testing Depth Matrix below to determine which suites to run
3. Runs `tests/run-all.sh --suite <computed list>`
4. cyra-test posts the test report comment on the PR

### Testing Depth Matrix

| Changed file pattern | Suites that run automatically |
|---------------------|-------------------------------|
| Any `.py` in `backend/` | 01, 02 |
| `backend/blueprints/` any file | 01, 02, 03 |
| `backend/blueprints/auth/**` or `/rbac/**` or `/oidc/**` | 01, 02, 03, 04, 10 |
| `backend/siem_proxy.py` | 01, 02, 03, 04, 06, 10 |
| `backend/cysiemstack/correlation_engine/correlator.py` | 01, 02, 06 |
| `backend/cysiemstack/correlation_engine/ueba.py` | 01, 02, 06 |
| `backend/cysiemstack/correlation_engine/main.py` | 01, 02, 03, 05 |
| `backend/cysiemstack/correlation_engine/iris_connector.py` | 01, 02, 03 |
| `backend/blueprints/asm/scanner.py` | 01, 02, 03, 07 |
| `backend/cy_asm/**` | 01, 02, 07 |
| `portal/src/**` any | 01, 08 |
| `cycentra-setup.sh` | 01, 09 |
| `.github/workflows/deploy.yml` | 01, 09 |
| `backend/pyproject.toml` | 01, 09 |
| `RELEASE_NOTES.md` only | 01 |
| 10+ files changed | 01, 02, 03, 04, 07, 08, 10 |
| SIEM + portal changed together | 01, 02, 03, 04, 05, 06, 10 |
| Label `security-test` added to PR | + 04 forced |
| Label `load-test` added to PR | + 05 forced |

**Suite 01 always runs regardless of scope.**

---

## Step 6 — Cross-Agent Review (parallel with testing)

While cyra-test runs, cyra-rbac is automatically requested as reviewer if the PR adds any `/api/` route. cyra-rbac posts the route review table and approves or requests changes.

---

## Step 7 — Merge Gate

PR can only merge when ALL of these are true:
- Label `tests:passed` present (set by cyra-test)
- No label `blocked` present
- cyra-rbac has approved (if new routes were added)
- No unresolved `needs:review` conversations
- RELEASE_NOTES entry present in the diff
- Suite 01 confirms `app.py` ≤ 70 lines and `App.jsx` ≤ 120 lines

---

## Step 8 — Post-Merge

GitHub Actions:
- Close linked issue (requires `closes #N` in PR description)
- Change `status:in-progress` → `status:merged`
- If commit has tag `v*.*.*`: notify @cyra-devops to run release workflow
