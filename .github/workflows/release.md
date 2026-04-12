---
name: release
description: Release workflow for CyCentra 360. Fully automated — fires on every merge to main. No human steps. cyra-devops owns this workflow.
triggers:
  - event: push.tags
    pattern: "v*.*.*"
  - event: push.branches
    pattern: "main"
  - event: issues.labeled
    conditions:
      - label.name: "release"
---

# Workflow: Release

## Fully Automated — No Human Steps

Every merge to `main` triggers the complete release pipeline automatically.

**Pipeline chain:**
1. PR is merged (by `agent-auto-merge.yml` on the `auto-merge` label)
2. `agent-release.yml` fires on the `push` to `main` event
3. `deploy.yml` is dispatched by `agent-release.yml` after tagging
4. `agent-post-release.yml` verifies the release assets

---

## agent-release.yml — Auto-Tag and Publish

Fires on every push to main (no test gate). Steps:

```
1. Read latest version from RELEASE_NOTES.md (top ## vX.X.X entry)
2. Validate entry has a category heading (### Feature, ### Bug Fix, etc.) and description
3. Check tag vX.X.X does not already exist (skip if duplicate)
4. Stamp _WIZARD_VERSION_ in cycentra-setup.sh with version + timestamp
5. Update backend/pyproject.toml version field
6. Commit stamped files: "chore: stamp version vX.X.X [skip ci]"
7. Create annotated git tag with RELEASE_NOTES content as annotation
8. Push commit + tag to main
9. Dispatch deploy.yml via workflow_dispatch (GITHUB_TOKEN pushes do not trigger workflows)
10. Post release summary comment on the merged PR
```

---

## deploy.yml — CI Pipeline (fires on tag dispatch from agent-release)

Three jobs run in parallel then sequence:

**Job 1: build-portal** (Node 20)
- `npm ci && npm run build`
- Uploads `portal-dist` artifact

**Job 2: build-wheel** (Python 3.12)
- Stamps version into `pyproject.toml`
- `python -m build --wheel --outdir ../dist/`
- Uploads `python-wheel` artifact

**Job 3: publish** (needs both artifacts)
- Downloads both artifacts
- Installs SHC, compiles `cycentra-setup.sh` → `cycentra-setup-bin`
- Assembles 3-artifact bundle: portal dist + wheel + RELEASE_NOTES.md + manifest.json
- Publishes versioned + `latest` aliases to GitHub Packages
- Creates GitHub Release with assets: `cycentra-release.tar.gz`, `cycentra-setup.sh`, `*.whl`

---

## agent-post-release.yml — Post-Release Verification

Fires automatically on GitHub Release published event. Checks:

```
[ ] 3 assets on GitHub Release: cycentra-release.tar.gz, cycentra-setup.sh, *.whl
[ ] Wheel present inside cycentra-release.tar.gz
[ ] RELEASE_NOTES.md present inside cycentra-release.tar.gz
[ ] manifest.json present with 'wheel' key
[ ] _WIZARD_VERSION_ placeholder replaced in released cycentra-setup.sh
```

On failure: creates a GitHub Issue labelled `hotfix` + `priority:critical` so cyra-bugfix and cyra-devops pick it up immediately.

---

## RELEASE_NOTES.md Format (required for agent-release.yml to proceed)

Every PR must include a new version block at the TOP of RELEASE_NOTES.md:

```markdown
## v1.0.NNN

### Feature  (or: Bug Fix / Enhancement / Chore / Hotfix / Security)

- Short description of what changed and why
```

agent-release.yml will fail (and skip the release) if:
- No `## vX.X.X` block found
- Block has no `### Category` heading
- Block has fewer than 3 non-empty lines

---

## Version Numbering

```
v1.0.NNN
  ^      — major: reserved for architecture rewrites
    ^    — minor: reserved for significant feature milestones
      ^^^ — patch: every regular release increments this
```

Never skip a number. Never reuse a number. Never delete a tag. If a release fails verification, the fix becomes the next increment.
