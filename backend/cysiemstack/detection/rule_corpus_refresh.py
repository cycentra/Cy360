"""
cysiemstack/detection/rule_corpus_refresh.py
================================================
Scheduled + on-demand refresh for the two community-sourced detection
corpora (Sigma from SigmaHQ, YARA from Neo23x0/signature-base) so coverage
against evolving threats doesn't silently go stale — previously
import_sigma_rules.py / CYSIEM-Config/yara/import_signature_base.py were
on-demand-only, no automation re-ran them.

Safety model (same principle both refreshers share): fetch into a
temporary location, validate there, and only replace the live rules if
validation passes. A bad/partial upstream fetch or a rule that breaks
compilation leaves the previous corpus running untouched — it never
silently degrades detection coverage. Every run is logged either way.

Targets refreshed (see the "why here, not the repo source" note below):
  - Sigma:  backend/cysiemstack/detection/rules/imported/ — this IS the
    live path SigmaEngine reads from at runtime (sigma_engine._DEFAULT_RULES_DIR),
    not a separate build artifact, so refreshing it in place matches how
    the engine already works — no separate deploy step needed beyond the
    existing reset_engine() call this module already makes.
  - YARA:   the DEPLOYED cycentra.yar at EDR_PKG_DIR (default
    /var/lib/cycentra-agent-packages/edr/cycentra.yar) — deliberately NOT
    CYSIEM-Config/yara/cycentra.yar in the repo. That file is a committed
    dev asset (see its ATTRIBUTION.md); having a background job on a
    running server rewrite git-tracked source would cause uncommitted
    drift with no audit trail. Agents already read the deployed copy on
    their own schedule (hourly IOC sync, or immediately via Fleet Scan),
    so refreshing it there is the correct "runtime" location, same
    distinction as Sigma above just split across two different paths.

Run manually: python3 -m cysiemstack.detection.rule_corpus_refresh sigma
              python3 -m cysiemstack.detection.rule_corpus_refresh yara
Registered on a schedule via register_rule_corpus_scheduler() (called from
blueprints/scheduler/routes.py's init_scheduler(), same pattern as the ITAM
NVD/KEV/CVE/OUI refresh jobs).
"""
from __future__ import annotations
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger(__name__)

SIGMA_UPSTREAM_URL = "https://github.com/SigmaHQ/sigma"
SIGMA_UPSTREAM_DIR = Path(os.environ.get("SIGMA_UPSTREAM_DIR", "/opt/cycentra/rule-sources/sigma-upstream"))
SIGMA_SOURCE_SUBDIRS = ("rules", "rules-emerging-threats", "rules-threat-hunting")
# Below this fraction of the CURRENT imported rule count, treat the fetch as
# suspect (truncated clone, upstream restructure, network issue mid-fetch)
# rather than a genuine shrink — genuine upstream rule removals happen, but
# not at this scale in one run.
SIGMA_MIN_RATIO = 0.85

SIGBASE_UPSTREAM_URL = "https://github.com/Neo23x0/signature-base"
SIGBASE_UPSTREAM_DIR = Path(os.environ.get("SIGBASE_UPSTREAM_DIR", "/opt/cycentra/rule-sources/signature-base"))
YARA_CATEGORY_PREFIXES = (
    "gen_", "generic_", "crime_", "mal_", "hktl_", "htkl_", "webshell",
    "vuln_", "vul_", "susp_", "pua_", "pup_", "thor-hacktools", "thor-webshells",
)
YARA_EXTERNAL_VAR_RE = re.compile(r"\b(filename|filepath|extension|filetype)\b")
YARA_CUCKOO_RE = re.compile(r'import\s+"cuckoo"')
EDR_PKG_DIR = Path(os.environ.get("EDR_PKG_DIR", "/var/lib/cycentra-agent-packages/edr"))


def _git_clone_or_pull(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if (dest / ".git").exists():
        subprocess.run(["git", "-C", str(dest), "fetch", "--depth", "1", "origin"], check=True,
                        capture_output=True, timeout=300)
        subprocess.run(["git", "-C", str(dest), "reset", "--hard", "origin/HEAD"], check=True,
                        capture_output=True, timeout=60)
    else:
        if dest.exists():
            shutil.rmtree(dest)
        subprocess.run(["git", "clone", "--depth", "1", url, str(dest)], check=True,
                        capture_output=True, timeout=300)


# ── Sigma ────────────────────────────────────────────────────────────────────

def refresh_sigma_corpus() -> dict:
    """Re-fetch SigmaHQ, re-run the same compatibility filter
    import_sigma_rules.py uses, and atomically swap rules/imported/ if the
    result looks sane. Returns a status dict; never raises — callers (the
    scheduler, the manual-refresh API route) both just want a result to log
    or show, not an exception to handle."""
    from cysiemstack.detection.sigma_engine import _DEFAULT_RULES_DIR, reset_engine
    from cysiemstack.detection.import_sigma_rules import _is_compatible
    import yaml

    live_imported_dir = _DEFAULT_RULES_DIR / "imported"
    before_count = len(list(live_imported_dir.rglob("*.yml"))) if live_imported_dir.exists() else 0

    try:
        _git_clone_or_pull(SIGMA_UPSTREAM_URL, SIGMA_UPSTREAM_DIR)
    except Exception as exc:
        return _fail("sigma", f"git fetch failed: {exc}", before_count)

    staging = Path(tempfile.mkdtemp(prefix="sigma-refresh-"))
    try:
        imported_count, skipped = 0, 0
        for subdir in SIGMA_SOURCE_SUBDIRS:
            src = SIGMA_UPSTREAM_DIR / subdir
            if not src.exists():
                continue
            for path in sorted(src.rglob("*.yml")):
                try:
                    data = yaml.safe_load(path.read_text())
                except Exception:
                    skipped += 1
                    continue
                ok, _reason = _is_compatible(data)
                if not ok:
                    skipped += 1
                    continue
                rel = path.relative_to(src)
                out_path = staging / subdir / rel
                out_path.parent.mkdir(parents=True, exist_ok=True)
                if out_path.exists():
                    out_path = out_path.with_name(f"{out_path.stem}__dup{out_path.suffix}")
                shutil.copy(path, out_path)
                imported_count += 1

        if before_count and imported_count < before_count * SIGMA_MIN_RATIO:
            return _fail(
                "sigma",
                f"fetched only {imported_count} rules vs current {before_count} "
                f"(below {SIGMA_MIN_RATIO:.0%} threshold) — suspected bad/partial fetch, not activating",
                before_count,
            )
        if imported_count == 0:
            return _fail("sigma", "fetch produced zero compatible rules — not activating", before_count)

        # Smoke-test the STAGED corpus in isolation before touching the live
        # directory — build a throwaway engine pointed at a dir containing
        # the current starter rules + the staged import, run the same
        # benign/known-bad fixtures validate_sigma_rules.py uses.
        smoke_ok, smoke_detail = _smoke_test_staged_sigma(staging)
        if not smoke_ok:
            return _fail("sigma", f"post-import smoke test failed: {smoke_detail}", before_count)

        # Atomic-ish swap: new dir in first, then remove the old one.
        swap_target = live_imported_dir.parent / f"imported.new-{datetime.now(timezone.utc):%Y%m%d%H%M%S}"
        shutil.move(str(staging), str(swap_target))
        if live_imported_dir.exists():
            shutil.rmtree(live_imported_dir)
        swap_target.rename(live_imported_dir)

        reset_engine()
        _log.info("rule_corpus_refresh: sigma refreshed — %d rules (%d skipped)", imported_count, skipped)
        return {"ok": True, "kind": "sigma", "rule_count": imported_count, "skipped": skipped,
                "previous_count": before_count, "refreshed_at": datetime.now(timezone.utc).isoformat()}
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _smoke_test_staged_sigma(staging_imported_dir: Path) -> tuple[bool, str]:
    from cysiemstack.detection.sigma_engine import SigmaEngine, _DEFAULT_RULES_DIR
    from cysiemstack.detection.validate_sigma_rules import FIXTURES

    probe_dir = Path(tempfile.mkdtemp(prefix="sigma-probe-"))
    try:
        for starter in _DEFAULT_RULES_DIR.glob("*.yml"):
            shutil.copy(starter, probe_dir / starter.name)
        shutil.copytree(staging_imported_dir, probe_dir / "imported")

        try:
            engine = SigmaEngine(rules_dir=probe_dir, include_imported=True)
        except Exception as exc:
            return False, f"engine failed to build from staged rules: {exc}"

        failures = 0
        for label, kind, payload, hint, expect_match in FIXTURES:
            matched = engine.match(payload, logsource_hint=hint) if kind == "event" \
                else engine.match_raw(payload, logsource_hint=hint)
            if (matched is not None) != expect_match:
                failures += 1
        if failures:
            return False, f"{failures}/{len(FIXTURES)} offline fixtures failed against staged corpus"
        return True, "ok"
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)


# ── YARA ─────────────────────────────────────────────────────────────────────

def refresh_yara_corpus() -> dict:
    """Re-fetch signature-base, re-apply the same curated-category +
    compatibility filter import_signature_base.py uses, validate with a
    real `yarac` compile, and only then replace the DEPLOYED cycentra.yar
    (EDR_PKG_DIR) — never the repo source, see module docstring."""
    deployed_path = EDR_PKG_DIR / "cycentra.yar"
    before_count = 0
    if deployed_path.exists():
        before_count = len(re.findall(r'^\s*(?:private\s+|global\s+)*rule\s+\w+',
                                       deployed_path.read_text(errors="ignore"), re.MULTILINE))

    try:
        _git_clone_or_pull(SIGBASE_UPSTREAM_URL, SIGBASE_UPSTREAM_DIR)
    except Exception as exc:
        return _fail("yara", f"git fetch failed: {exc}", before_count)

    yara_src = SIGBASE_UPSTREAM_DIR / "yara"
    if not yara_src.exists():
        return _fail("yara", "signature-base clone has no yara/ directory — upstream layout changed?", before_count)

    candidates = []
    for prefix in YARA_CATEGORY_PREFIXES:
        candidates.extend(yara_src.glob(f"{prefix}*.yar"))
    candidates = sorted(set(candidates))

    kept_imports: set[str] = set()
    kept_bodies: list[str] = []
    kept, dropped = 0, 0
    for path in candidates:
        text = path.read_text(errors="ignore")
        if YARA_CUCKOO_RE.search(text) or YARA_EXTERNAL_VAR_RE.search(text):
            dropped += 1
            continue
        for m in re.finditer(r'^import\s+"(\w+)"', text, re.MULTILINE):
            kept_imports.add(m.group(1))
        body = re.sub(r'^import\s+"\w+"\s*\n', "", text, flags=re.MULTILINE)
        kept_bodies.append(f"// ---- source: {path.name} ----\n{body.rstrip()}\n")
        kept += 1

    if kept == 0:
        return _fail("yara", "fetch produced zero compatible rule files — not activating", before_count)

    # Preserve the hand-written CyCentra_* header from whatever's currently
    # deployed (falls back to none if this is the very first refresh on a
    # host that never had cycentra.yar staged at all).
    preserved = ""
    if deployed_path.exists():
        existing = deployed_path.read_text(errors="ignore")
        marker = existing.find("// ----")
        preserved = (existing[:marker].rstrip() + "\n") if marker != -1 else existing.rstrip() + "\n"

    header = "".join(f'import "{m}"\n' for m in sorted(kept_imports))
    merged = preserved + "\n" + header + "\n" + "\n".join(kept_bodies)

    with tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False) as tf:
        tf.write(merged)
        staged_path = Path(tf.name)

    try:
        proc = subprocess.run(["yarac", str(staged_path), str(staged_path) + "c"],
                               capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            return _fail("yara", f"yarac compile failed: {proc.stderr.strip()[:500]}", before_count)

        after_count = len(re.findall(r'^\s*(?:private\s+|global\s+)*rule\s+\w+', merged, re.MULTILINE))
        EDR_PKG_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy(staged_path, deployed_path)
        _log.info("rule_corpus_refresh: yara refreshed — %d rules (%d files dropped)", after_count, dropped)
        return {"ok": True, "kind": "yara", "rule_count": after_count, "files_dropped": dropped,
                "previous_count": before_count, "refreshed_at": datetime.now(timezone.utc).isoformat()}
    finally:
        staged_path.unlink(missing_ok=True)
        Path(str(staged_path) + "c").unlink(missing_ok=True)


def _fail(kind: str, reason: str, previous_count: int) -> dict:
    _log.error("rule_corpus_refresh: %s refresh NOT applied — %s (previous corpus left running)", kind, reason)
    return {"ok": False, "kind": kind, "error": reason, "previous_count": previous_count,
            "refreshed_at": datetime.now(timezone.utc).isoformat()}


# ── Scheduler registration ────────────────────────────────────────────────────

def register_rule_corpus_scheduler(sched) -> None:
    """Called from blueprints/scheduler/routes.py's init_scheduler(). Weekly
    cadence — these corpora don't need daily refresh, and every run does a
    real yarac compile / Sigma engine build, not free. Staggered 30 minutes
    apart from each other and from the existing Sunday 03:30 OUI refresh."""
    from apscheduler.triggers.cron import CronTrigger

    def _sigma_job():
        refresh_sigma_corpus()

    def _yara_job():
        refresh_yara_corpus()

    sched.add_job(_sigma_job, CronTrigger(day_of_week="sun", hour=4, minute=0),
                  id="rule_corpus_sigma_refresh", name="Sigma Rule Corpus Refresh (Weekly)",
                  replace_existing=True, misfire_grace_time=3600)
    sched.add_job(_yara_job, CronTrigger(day_of_week="sun", hour=4, minute=30),
                  id="rule_corpus_yara_refresh", name="YARA Rule Corpus Refresh (Weekly)",
                  replace_existing=True, misfire_grace_time=3600)
    _log.info("scheduler: rule corpus refresh jobs registered (Sigma Sun 04:00 UTC, YARA Sun 04:30 UTC)")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    kind = sys.argv[1] if len(sys.argv) > 1 else ""
    if kind == "sigma":
        print(refresh_sigma_corpus())
    elif kind == "yara":
        print(refresh_yara_corpus())
    else:
        print("Usage: python3 -m cysiemstack.detection.rule_corpus_refresh {sigma|yara}")
        sys.exit(1)
