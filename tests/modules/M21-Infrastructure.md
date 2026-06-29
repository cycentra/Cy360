# M21 — Infrastructure (Setup Script & CI/CD)
**Files:** `cycentra-setup.sh`, `.github/workflows/deploy.yml` (if present)
**Run Date:** 2026-06-29

---

## Module Scope

Main installer and CI/CD infrastructure. `cycentra-setup.sh` handles full platform deployment (Docker, PostgreSQL, Wazuh, nginx, SSL). Build pipeline in `build-package.sh` creates versioned release tarballs in `dist/`.

---

## AI-Executable Tests (Automated)

### A1 — Setup Script

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `set -euo pipefail` present | ✅ PASS | 4 occurrences found |
| A1.02 | No bare `clear` command | ✅ PASS | Guarded (`[[ -t 1 ]] && clear`) |
| A1.03 | `shellcheck --severity=error` → 0 errors | MANUAL | shellcheck not available in local env |
| A1.04 | No unguarded grep | MANUAL | Requires shellcheck |
| A1.05 | `DATABASE_URL` fallback for `POSTGRES_PASSWORD` | ✅ PASS | Fallback present |

### A2 — Deploy Pipeline

| # | Test | Result | Detail |
|---|------|--------|--------|
| A2.01 | `deploy.yml` concurrency block | SKIP | No CI workflow found locally (server-side) |
| A2.02 | `deploy.yml` Python 3.12 + Node 20 | SKIP | Same |
| A2.03 | `dist/*.whl` in bundle before tar | SKIP | Same |

### A3 — Release Notes

| # | Test | Result | Detail |
|---|------|--------|--------|
| A3.01 | `docs/RELEASE_NOTES.md` has versioned entry | ✅ PASS | File exists with version entries |

### A4 — Build Package

| # | Test | Result | Detail |
|---|------|--------|--------|
| A4.01 | `build-package.sh` syntax | ✅ PASS | Bash script valid |
| A4.02 | Latest dist tarball: v1.0.103 | ✅ PASS | `dist/cycentra-360-installer-v1.0.103.tar.gz` exists |
| A4.03 | Agent packages present for all platforms | ✅ PASS | .deb/.rpm/.pkg/.msi all present for v1.0.103 |

---

## Manual Test Suite

### M-INFRA-01: Fresh Install
**Steps:**
1. Provision clean Ubuntu 22.04 VM
2. Run `bash cycentra-setup.sh`
3. Verify all containers start: backend, frontend, postgres, wazuh-manager, nginx
4. Navigate to `https://<server>/` — verify portal loads
5. Verify SSL certificate valid

### M-INFRA-02: Upgrade
**Steps:**
1. Install v1.0.102 on test VM
2. Run v1.0.103 setup script
3. Verify all containers updated without data loss
4. Verify DB schema migrations applied (`ALTER TABLE IF NOT EXISTS`)

### M-INFRA-03: SSL Certificate Renewal
**Steps:**
1. Simulate certificate expiry (set system date forward)
2. Trigger cert renewal
3. Verify nginx picks up new certificate without restart

### M-INFRA-04: Docker Maintenance
**Steps:**
1. Run `docker-maintenance.sh`
2. Verify old images pruned
3. Verify running containers unaffected

### M-INFRA-05: Installer Package
**Steps:**
1. Extract `cycentra-360-installer-v1.0.103.tar.gz`
2. Verify all required files present: `cycentra-setup.sh`, agent packages, dist WHL files
3. Run installer from extracted package — verify same result as online install

### M-INFRA-06: Rollback
**Steps:**
1. Backup current installation
2. Install new version
3. If issues detected, restore from backup
4. Verify rollback succeeds without data corruption
