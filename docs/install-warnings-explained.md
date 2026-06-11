# CyCentra 360 — Install Warning Reference

This document explains the three diagnostic messages that can appear during a
fresh `cycentra-setup.sh` run, why they fire, and what (if anything) requires
action.

---

## 1. kibanaserver password unknown

### Message (before fix)
```
⚠ kibanaserver password unknown — opensearch.username/password may be missing
  from opensearch_dashboards.yml. Dashboard→OpenSearch auth will fail if so.
```

### Why it fires

`opensearch_dashboards.yml` (the Wazuh Dashboard config) needs a service-account
credential pair (`opensearch.username: kibanaserver` / `opensearch.password`) so
the Dashboard process can authenticate internally to the OpenSearch indexer.

The setup script checks for this at **Step 4.1** (line ~581). It looks in three
places for the password:

1. An already-active uncommented line in the yml with a real password value.
2. The in-memory variable `_CYSIEM_KS_PASS`, populated during a fresh Wazuh
   all-in-one install from `~/wazuh-install-files.tar`.
3. The tar file itself, if it still exists on disk.

On a server where Wazuh was already installed (re-run, `--update`, or a server
that had Wazuh set up separately), none of these three sources contain the
password — so the warning fires.

### Why it is a false alarm on a CyCentra 360 server

The script configures OIDC authentication at **Step 4.3b** (line ~1459), which
runs *after* Step 4.1. Step 4.3b writes:

```yaml
opensearch_security.auth.type: openid
opensearch_security.openid.connect_url: "https://cyasm.<domain>/oidc/..."
opensearch_security.openid.client_id: "cysiem"
opensearch_security.openid.client_secret: "<CYSIEM_OIDC_SECRET>"
```

When `auth.type: openid` is active, the Wazuh Dashboard authenticates to
OpenSearch via the OIDC token chain — the `kibanaserver` username/password is
completely bypassed and its absence has no effect.

### Fix applied (v1.0.414+)

The script now:

1. Checks if `opensearch_security.auth.type: openid` is already present in the
   yml (re-run / `--update`). If so, logs an info message and skips the block.
2. If OIDC is not yet active but `CYSIEM_OIDC_SECRET` is set (meaning Step 4.3b
   will configure it this same run), the message is demoted from `warn` to `info`.
3. The genuine `warn` is retained only when OIDC is neither active nor will be
   configured — the one case where the kibanaserver credential truly matters.

### When action IS required

Only if you are running Wazuh **without** CyCentra's OIDC configuration (e.g.
a standalone Wazuh install where Step 4.3b is intentionally skipped). In that
case, manually inject the credential:

```bash
# Find the password from the Wazuh install archive
tar -xOf ~/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt \
  | grep -A 1 "^username: kibanaserver$"

# Inject into the dashboard config
echo 'opensearch.username: kibanaserver'       >> /etc/wazuh-dashboard/opensearch_dashboards.yml
echo 'opensearch.password: "<PASSWORD_HERE>"'  >> /etc/wazuh-dashboard/opensearch_dashboards.yml
systemctl restart wazuh-dashboard
```

---

## 2. docker-maintenance.sh not found in bundle

### Message (before fix)
```
⚠ docker-maintenance.sh not found in bundle — skipping deployment
```

### Why it fires

The setup script, after downloading the GitHub release bundle, tries to copy
`docker-maintenance.sh` to `/opt/cycentra/docker-maintenance.sh` so the Scheduler
can reference a known path.

The bundle (`cycentra-release.tar.gz`) is assembled by the GitHub Actions CI
workflow (`.github/workflows/deploy.yml`). That workflow **does not include
`docker-maintenance.sh`** — it only bundles:

```
portal/dist/
cycentra-setup  (compiled binary)
RELEASE_NOTES.md
VERSION
*.whl
CYSIEM-Config/
rbac.default.json
manifest.json
```

`docker-maintenance.sh` is present in `build-package.sh` (the local dev
installer builder) but not in `deploy.yml` (the CI release builder). The
script at `/opt/cycentra/` can therefore never be populated via the CI bundle.

### Why it is not an error

The Flask backend generates and writes the script itself. When an admin opens
System Settings → Scheduler and saves a docker-maintenance schedule,
`POST /api/system/schedules` calls `_write_docker_maintenance_script()` in
`backend/blueprints/system/routes.py`. This function writes the full script
content (embedded as a Python string in the source) directly to
`/opt/cycentra/docker-maintenance.sh` with `chmod 755`.

The file is re-written on every scheduler save, so it is always in sync with
the version of the backend that is running.

### Fix applied (v1.0.414+)

The `warn` is replaced with:
- `success` if the file already exists at `/opt/cycentra/` (previous install or
  prior `--update` that had it in the bundle).
- `info` if the file does not exist, explaining that it will be created
  automatically when the Scheduler is saved in the UI.

### If the file is needed before first UI interaction

SSH to the server and trigger the scheduler endpoint directly:

```bash
# As the cycentra service user, or with the admin session cookie:
curl -s -X POST https://cy360.<domain>/api/system/schedules \
  -H "Content-Type: application/json" \
  -d '{"schedules":{"docker_maintenance":{"enabled":true,"frequency":"monthly"}}}'
```

Or copy from the repo:

```bash
scp -P 2026 /path/to/repo/docker-maintenance.sh root@<server>:/opt/cycentra/docker-maintenance.sh
chmod 750 /opt/cycentra/docker-maintenance.sh
```

---

## 3. license_validator.py not found — license enforcement disabled

### Message (before fix)
```
⚠ license_validator.py not found — license enforcement disabled
```

### Why it fires

After downloading the bundle, setup.sh tries to deploy `license_validator.py`
to `/opt/cycentra/license_validator.py`. It looks in two locations:

1. `_SCRIPT_BASE/license_validator.py` — directory of the running script.
2. `BUNDLE_DIR/license_validator.py` — inside the extracted release tarball.

`build-package.sh` (the local dev builder) explicitly copies
`backend/core/license_validator.py` into the installer tarball. However, the
GitHub Actions CI workflow (`deploy.yml`) does **not** include this file in the
release bundle it pushes to GitHub Packages. The file therefore never reaches a
server that installs from the CI-built bundle.

### Why it is not an error

There are two independent self-healing mechanisms:

**Mechanism 1 — Flask in-package fallback (license UI always works)**

The license upload and check endpoints in
`backend/blueprints/system/routes.py` use `_run_validator()`:

```python
validator = Path("/opt/cycentra/license_validator.py")   # deployed copy
if not validator.exists():
    # Fall back to source copy inside the backend package
    validator = Path(__file__).parent.parent.parent / "core" / "license_validator.py"
```

`backend/core/license_validator.py` ships inside the installed Python wheel.
If the deployed copy is absent, the backend silently uses the in-package copy.
The license upload UI, the license status API, and the license expiry check all
work correctly without any deployed copy.

**Mechanism 2 — Daily watchdog (needs deployed copy)**

A separate cron-based watchdog (configured at line ~2027 in setup.sh) calls
`python3 /opt/cycentra/license_validator.py` daily. If the file is absent, the
watchdog logs a warning and skips the check — services are **not** stopped. The
watchdog will use the deployed copy once it is present from a future `--update`.

### Fix applied (v1.0.414+)

The `warn` is replaced with:
- `success` if `/opt/cycentra/license_validator.py` already exists (kept from a
  previous install).
- `info` explaining both fallback mechanisms if neither deployed copy is found.

### Root cause fix (deploy.yml)

The permanent fix is to add `license_validator.py` to the CI bundle in
`.github/workflows/deploy.yml`:

```yaml
# In the "Build customer release bundle" step, add:
[[ -f backend/core/license_validator.py ]] && \
  cp backend/core/license_validator.py cycentra-release/license_validator.py || true
```

This ensures every fresh install from a CI-built bundle deploys the file
immediately without needing a subsequent `--update`.

---

## Summary

| Warning | Root cause | Action needed |
|---|---|---|
| kibanaserver password unknown | Check runs before OIDC is configured (step 4.1 fires before step 4.3b) | None — OIDC replaces kibanaserver auth entirely |
| docker-maintenance.sh not found | File absent from CI bundle; only in local dev builder | None — Flask writes it on first Scheduler save |
| license_validator.py not found | File absent from CI bundle; only in local dev builder | None — Flask uses in-package fallback; watchdog skips gracefully |

All three messages were `warn` level but none represent a functional failure on a
standard CyCentra 360 installation. They have been corrected to `info` or
suppressed entirely in `v1.0.414`.
