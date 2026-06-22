# g-cyra-test — Test Run History

> New runs are **prepended** at the top of this file.
> Each entry is a summary; the full checklist lives in `tests/TEST_RUN_REPORT.md`.
> For the inventory of what is tested see `docs/TEST_INVENTORY.md`.

---

<!-- g-cyra-test: INSERT NEW RUN ABOVE THIS LINE -->

---

## Run: 2026-06-22 11:30 UTC — ✅ PASSED

**Trigger:** Manual — review INVESTIGATION_ENGINE_PLAN.md; add Phase 1–6 autonomous tests
**Branch:** main (local) | **Commit:** working tree
**Suites:** 12 (new) | **Files changed:** 6
**Result:** PASSED | **Total:** 132/132 passed

**Failures:** None

**Notes:** New Suite 12 adds 132 fully autonomous tests (no live Wazuh/DB/LLM) covering all 6 phases of the AI Investigation Engine. Added `from __future__ import annotations` to 4 CE files for Python 3.9 local-test compatibility (no logic change; production runs Python 3.12). All phases confirmed operational.

Full checklist: see `tests/TEST_RUN_REPORT.md` (this run).

## Run: 2026-06-19 — v1.0.62 — ❌ BLOCKED

**Suites:** ALL (01–10) | **Trigger:** Manual (perform all tests)
**pytest:** 608 passed / 13 failed / 35 errors (excluding test_benchmark_threat_intel.py; env: Python 3.9 local)

**Blocking failures:**
1. `App.jsx` 412 lines (limit 120)
2. `app.py` 97 lines (limit 70)
3. `iris_connector.py` obsolete — 4 `TestFPAutoClose` setups fail; tests must be updated to use `cases_bp` (CyCases is now built-in)
4. Platform status schema no longer includes `cyiris` — CyCases is a built-in module, not a Docker-managed module (`compose.py` VALID_MODULES = {cysoar, cymisp})

**Passing highlights:** 55 correlation rules (CR-001→CR-055), 17 UEBA detectors, agent installer — all 416+111+51 tests green. Shellcheck 0 errors. SECRET_KEY raises if empty. SESSION_COOKIE_HTTPONLY=True. app.debug=False. No hardcoded secrets.

**Non-blocking:** INTEGRATION_PATCH.py not a real module; `"Informational"` vs `"info"` severity mismatch in vuln_scanner; Python 3.9 blocks 48 tests that would pass on 3.12.

---
