"""
PATCH 4 — Register benchmark bands auto-update job into APScheduler
====================================================================
File patched: backend/blueprints/scheduler/routes.py

Inserts the benchmark job registration block immediately before
_scheduler.start() — the exact pattern used by all other platform jobs.

Run from repo root:
    python3 benchmark-patch/PATCH_4_scheduler_registration.py
"""

import pathlib
import sys

TARGET = pathlib.Path("backend/blueprints/scheduler/routes.py")

FIND = """\
    _scheduler.start()
    log.info("scheduler: started with %d jobs", len(_scheduler.get_jobs()))"""

REPLACE = """\
    # ── Benchmark bands auto-update (monthly, opt-in) ─────────────────────────
    # Reads BENCHMARK_AUTO_UPDATE from env — set in /opt/cycentra/.env.
    # Fires on the 1st of each month at 03:00 UTC.
    # Safe no-op when _AUTO_UPDATE is False or the import fails.
    try:
        from blueprints.benchmark.routes import register_benchmark_scheduler, _AUTO_UPDATE
        if _AUTO_UPDATE:
            register_benchmark_scheduler(_scheduler)
    except Exception as _bench_exc:
        log.warning("scheduler: benchmark job registration failed: %s", _bench_exc)

    _scheduler.start()
    log.info("scheduler: started with %d jobs", len(_scheduler.get_jobs()))"""


def main():
    if not TARGET.exists():
        print(f"✗  {TARGET} not found — run from repo root.")
        sys.exit(1)

    content = TARGET.read_text()

    if "register_benchmark_scheduler" in content:
        print("✓  Already patched — benchmark scheduler registration already present.")
        sys.exit(0)

    if FIND not in content:
        print("✗  Search string not found in scheduler/routes.py.")
        print("   Expected to find:")
        print(f"   {repr(FIND[:80])}")
        print()
        print("   Check the actual lines around _scheduler.start():")
        for i, line in enumerate(content.splitlines(), 1):
            if "_scheduler.start" in line or "started with" in line:
                print(f"   line {i}: {line}")
        sys.exit(1)

    TARGET.write_text(content.replace(FIND, REPLACE, 1))
    print(f"✓  Patched {TARGET}")
    print()
    print("Next: restart the backend to activate the job.")
    print("  Local:      pkill -f 'python3 app.py'; cd backend && python3 app.py &")
    print("  Production: sudo systemctl restart cycentra-backend")
    print()
    print("Confirm in the backend log on startup:")
    print("  [benchmark] Monthly bands update job registered (runs 1st of month, 03:00)")


if __name__ == "__main__":
    main()
