---
name: release
description: Release workflow for CyCentra 360. Governs every tagged release from pre-release gate through CI pipeline validation, 3-artifact bundle integrity check, GitHub Release creation, and post-release verification. cyra-devops executes this workflow.
triggers:
  - event: push.tags
    pattern: "v*.*.*"
  - event: issues.labeled
    conditions:
      - label.name: "release"
---

# Workflow: Release

## Pre-Release Gate (cyra-devops checks before creating the git tag)

All of these must be true before tagging:

```
[ ] RELEASE_NOTES.md has entry ## v1.0.NNN for this exact version
[ ] Entry has root cause + fix description (not vague language)
[ ] All PRs for this release are merged to main
[ ] main branch has a green CI run (no failing checks)
[ ] No PR with label blocked or tests:failed merged in the last 24h
[ ] backend/pyproject.toml version field matches the tag about to be created
```

Verify entry exists:
```bash
grep "^## v1.0.NNN" RELEASE_NOTES.md || echo "MISSING — do not tag"
```

---

## CI Pipeline (deploy.yml fires automatically on tag push)

Three jobs run in sequence:

**Job 1: build-portal** (Node 20)
- `npm ci && npm run build`
- Uploads `portal-dist` artifact

**Job 2: build-wheel** (Python 3.12)
- Stamps version into `pyproject.toml`
- `python -m build --wheel --outdir ../dist/`
- Uploads `python-wheel` artifact

**Job 3: publish**
- Downloads both artifacts
- Installs SHC, compiles `cycentra-setup.sh` → `cycentra-setup-bin`
- Assembles bundle (CRITICAL — v1.0.112 fix must be present):

```bash
mkdir -p cycentra-release/dist
# Copy all 3 artifact types:
cp -r portal/dist   cycentra-release/portal/dist
cp -r db            cycentra-release/db
cp dist/*.whl       cycentra-release/dist/      # ← wheel MUST be in bundle
cp cycentra-setup.sh cycentra-release/
cp cycentra-setup-bin cycentra-release/
cp RELEASE_NOTES.md  cycentra-release/
# Write manifest with wheel filename:
echo '{"version":"'$VER'","wheel":"'$(basename dist/*.whl)'"}' > cycentra-release/manifest.json
tar -czf cycentra-release.tar.gz cycentra-release/
```

- Publishes versioned + `latest` aliases to GitHub Packages
- Creates GitHub Release with 3 assets: `cycentra-release.tar.gz`, `cycentra-setup.sh`, `dist/*.whl`

---

## Post-Release Verification (cyra-test runs within 30 minutes)

Run `tests/09-infra-tests.sh --release-check`:

```
[ ] GitHub Release exists with correct tag
[ ] 3 assets attached: cycentra-release.tar.gz, cycentra-setup.sh, *.whl
[ ] tar -tzf cycentra-release.tar.gz | grep ".whl" → returns result
[ ] tar -tzf cycentra-release.tar.gz | grep "RELEASE_NOTES.md" → returns result
[ ] cat manifest.json | jq '.wheel' → not null
[ ] cycentra-setup.sh download via 2-step Releases API works with GH_TOKEN
[ ] GitHub Packages latest alias updated
```

---

## If Post-Release Check Fails

1. cyra-devops creates `hotfix` issue with `priority:critical` immediately
2. Failed release tag is left intact — old bundle still downloadable
3. Customers who updated to broken version: next `--update` with patch version will fix
4. cyra-bugfix fast-tracks patch through bug-fix workflow
5. cyra-devops creates `v1.0.NNN+1` tag within 2 hours of identifying the regression

---

## Version Numbering

```
v1.0.NNN
  ^      — major: reserved for architecture rewrites (like the v4.3 Blueprint refactor)
    ^    — minor: reserved for significant feature milestones
      ^^^ — patch: every regular release increments this
```

Never skip a number. Never reuse a number. Never delete a tag. If a release fails validation, the fix becomes the next increment.
