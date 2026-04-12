---
name: feature-development
description: End-to-end fully-automated workflow for implementing a new CyCentra 360 feature or enhancement. Assign issue to agent — agent implements, opens PR with auto-merge label, pipeline releases automatically. No human merge/approve/reject. No testing gate.
triggers:
  - event: issues.labeled
    conditions:
      - label.name: "feature"
      - label.name: "enhancement"
  - event: issues.assigned
---

# Workflow: Feature Development

## Fully Automated — No Human Steps Required

Assign an issue → agent does everything → code is released automatically.

**End-to-end flow:**
1. Issue is labelled `feature` or `enhancement` (or assigned directly)
2. Agent is routed automatically, implements changes, and opens a PR
3. Agent adds `auto-merge` label to the PR
4. `agent-auto-merge.yml` merges the PR without human approval
5. `agent-release.yml` stamps the version, creates the git tag, and triggers `deploy.yml`
6. `deploy.yml` builds the wheel + portal bundle and publishes the GitHub Release
7. `agent-post-release.yml` verifies all artifacts are correct

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

Agent adds label `status:in-progress`.

---

## Step 4 — Pre-PR Self-Validation (agent runs before opening PR)

```
[ ] Python AST check: python3 -c "import ast; ast.parse(open('file.py').read())" passes for all new/modified .py files
[ ] Frontend: npm run build passes with 0 errors and 0 circular import warnings
[ ] All new routes have auth check (→ 401) and role check where needed (→ 403)
[ ] All non-GET paths have OPTIONS handler returning 204
[ ] env-var-auditor skill run if any os.environ usage added or changed
[ ] RELEASE_NOTES entry written (new ## vX.X.X block at top of RELEASE_NOTES.md)
[ ] app.py still under 70 lines, App.jsx still under 120 lines
```

---

## Step 5 — PR Opens with auto-merge Label

Agent opens the PR and **immediately adds the `auto-merge` label**.

- `agent-auto-merge.yml` fires on the label event
- PR is merged automatically — no human approval or review required
- `agent-release.yml` is dispatched after merge, stamps the version, creates the git tag
- `deploy.yml` builds wheel + portal and publishes the GitHub Release
- Issue is closed automatically via `closes #N` in PR description

Agent adds label `status:merged` after PR merges.

---

## Step 6 — Post-Merge (automated)

GitHub Actions runs automatically:
- `agent-release.yml` — reads version from `RELEASE_NOTES.md`, stamps `cycentra-setup.sh`, updates `pyproject.toml`, creates annotated git tag, pushes to main
- `deploy.yml` — builds React SPA + Python wheel, assembles 3-artifact bundle, publishes GitHub Release
- `agent-post-release.yml` — verifies all 3 release assets are present and correct; creates a `hotfix` issue if any check fails
