# M13 — Backup & Restore
**File:** `backend/blueprints/backup/routes.py`
**Run Date:** 2026-06-29

---

## Module Scope

Backup and restore functionality for platform configuration, RBAC data, and compliance assessments. Supports scheduled backups via APScheduler.

**Endpoints:**
- `POST /api/backup/create` — Create backup snapshot
- `GET /api/backup/list` — List available backups
- `POST /api/backup/restore/<backup_id>` — Restore from backup
- `GET /api/backup/download/<backup_id>` — Download backup file
- `POST /api/backup/schedule` — Configure backup schedule

---

## AI-Executable Tests (Automated)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `backup_bp` imports cleanly | ✅ PASS | Blueprint importable |
| A1.02 | AST syntax `backup/routes.py` | ✅ PASS | Compiles cleanly |
| A1.03 | Unauthenticated → 401 | ✅ PASS | Auth guard active |
| A1.04 | Viewer cannot create backup → 403 | ✅ PASS | Admin-only enforced |
| A1.05 | Viewer cannot restore → 403 | ✅ PASS | Admin-only enforced |

---

## Manual Test Suite

### M-BKP-01: Manual Backup Creation
**Steps:**
1. Log in as admin
2. Navigate to Settings → Backup → Create Backup
3. Verify backup file created with timestamp in name
4. Verify backup listed in backup history
5. Download backup — verify it's a valid archive (tar.gz)

### M-BKP-02: Restore from Backup
**Steps:**
1. Make a known configuration change (add a user to RBAC)
2. Create a backup BEFORE the change
3. Apply the change
4. Restore from the pre-change backup
5. Verify the change is reverted
6. Verify platform continues to function after restore

### M-BKP-03: Scheduled Backup
**Steps:**
1. Configure daily backup at 02:00 UTC
2. Verify APScheduler job created
3. Wait for scheduled time or manually trigger
4. Verify backup created automatically

### M-BKP-04: Backup Integrity
**Steps:**
1. Create backup
2. Corrupt the backup file (edit a byte)
3. Attempt restore
4. Verify restore fails gracefully with error (no partial restore)
