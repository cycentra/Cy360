# M15 — Background Scheduler
**File:** `backend/blueprints/scheduler/routes.py`
**Run Date:** 2026-06-29

---

## Module Scope

APScheduler-based job management. Schedules: integration health checks, compliance auto-assessments, ASM scan recurrence, SMTP alerts, backup jobs, and report generation.

**Endpoints:**
- `GET /api/scheduler/jobs` — List all scheduled jobs
- `POST /api/scheduler/jobs` — Create new job
- `DELETE /api/scheduler/jobs/<id>` — Remove job
- `POST /api/scheduler/jobs/<id>/pause` — Pause job
- `POST /api/scheduler/jobs/<id>/resume` — Resume job
- `GET /api/scheduler/jobs/<id>/history` — Job execution history

---

## AI-Executable Tests (Automated)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `scheduler_bp` imports cleanly | ✅ PASS | Blueprint importable |
| A1.02 | AST syntax `scheduler/routes.py` | ✅ PASS | Compiles cleanly |
| A1.03 | Integration health job type recognized | ❌ FAIL | `test_integration_health.py::TestSchedulerWiring` — job type key changed |
| A1.04 | Health monitor auto-registered in init | ❌ FAIL | Same test — mock path mismatch |
| A1.05 | Unauthenticated → 401 | ✅ PASS | Auth guard active |
| A1.06 | Viewer cannot create/delete jobs → 403 | ✅ PASS | Admin-only enforced |

**Root cause for A1.03/A1.04:** `test_integration_health.py::TestSchedulerWiring` patches the scheduler at an old import path. The integration health auto-registration function was moved or renamed. Tests need update to patch new location.

---

## Manual Test Suite

### M-SCHED-01: View Scheduled Jobs
**Steps:**
1. Navigate to Settings → Scheduler
2. Verify list shows: integration health check, backup job, report generation
3. Verify each job shows: next run time, interval, last status

### M-SCHED-02: Create Scan Schedule
**Steps:**
1. Create new ASM scan job: target=company.com, schedule=daily at 03:00 UTC
2. Verify job appears in job list
3. Verify scan triggers at scheduled time
4. Verify scan results available after completion

### M-SCHED-03: Pause/Resume Job
**Steps:**
1. Pause integration health check job
2. Verify job status changes to "paused"
3. Wait for what would have been a check cycle
4. Verify no check was performed (last_check timestamp unchanged)
5. Resume job — verify checks resume

### M-SCHED-04: Job History
**Steps:**
1. View history for integration health check job
2. Verify each execution shows: start_time, end_time, status, errors
3. Identify any failed executions
