"""blueprints/itam/nvd_mirror.py — Local NVD CVE cache.

Downloads CVEs from NVD API 2.0 and stores them in PostgreSQL, eliminating
per-request rate-limit exposure on the public NVD API. Serves as the primary
CVE lookup source for ITAM software enrichment.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import psycopg2.extras

log = logging.getLogger(__name__)

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE_SIZE = 2000


# ── Schema ─────────────────────────────────────────────────────────────────────

def ensure_nvd_tables(conn: Any) -> None:
    """Create nvd_cves and nvd_sync_state tables if they do not exist."""
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS nvd_cves (
                cve_id       TEXT PRIMARY KEY,
                severity     VARCHAR(10),
                score        FLOAT,
                epss_score   FLOAT,
                epss_pct     FLOAT,
                is_kev       BOOLEAN DEFAULT FALSE,
                description  TEXT,
                published    TIMESTAMPTZ,
                modified     TIMESTAMPTZ,
                fetched_at   TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_nvd_severity ON nvd_cves(severity);
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS nvd_sync_state (
                id               INTEGER PRIMARY KEY DEFAULT 1,
                last_full_sync   TIMESTAMPTZ,
                last_incr_sync   TIMESTAMPTZ,
                total_cves       INTEGER DEFAULT 0
            );
        """)
        cur.execute("""
            INSERT INTO nvd_sync_state (id) VALUES (1) ON CONFLICT DO NOTHING;
        """)
    conn.commit()


# ── Parsing ────────────────────────────────────────────────────────────────────

def _parse_cve_item(vuln: dict) -> dict | None:
    """Parse one NVD 2.0 vulnerability entry.

    Returns a dict with keys: cve_id, severity, score, description,
    published, modified — or None if the entry is malformed.

    CVSS priority: v3.1 → v3.0 → v2.
    Description: first English entry, truncated to 500 chars.
    """
    cve_obj = vuln.get("cve", {})
    cve_id = cve_obj.get("id", "").strip()
    if not cve_id:
        return None

    severity = "none"
    score: float = 0.0
    metrics = cve_obj.get("metrics", {})
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            raw_sev = (cvss_data.get("baseSeverity") or "none").lower()
            raw_score = float(cvss_data.get("baseScore") or 0.0)
            if raw_sev and raw_sev != "none":
                severity = raw_sev
                score = raw_score
                break

    description = ""
    for desc in cve_obj.get("descriptions", []):
        if desc.get("lang") == "en":
            description = (desc.get("value") or "")[:500]
            break

    published = cve_obj.get("published")
    modified = cve_obj.get("lastModified")

    return {
        "cve_id":      cve_id,
        "severity":    severity,
        "score":       score,
        "description": description,
        "published":   published,
        "modified":    modified,
    }


# ── Upsert helper ──────────────────────────────────────────────────────────────

def _upsert_cves(conn: Any, items: list[dict]) -> int:
    """Bulk-upsert parsed CVE dicts into nvd_cves. Returns count of rows affected."""
    if not items:
        return 0
    count = 0
    with conn.cursor() as cur:
        for item in items:
            cur.execute(
                """
                INSERT INTO nvd_cves
                    (cve_id, severity, score, description, published, modified, fetched_at)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (cve_id) DO UPDATE SET
                    severity    = EXCLUDED.severity,
                    score       = EXCLUDED.score,
                    description = EXCLUDED.description,
                    modified    = EXCLUDED.modified,
                    fetched_at  = NOW()
                """,
                (
                    item["cve_id"],
                    item["severity"],
                    item["score"],
                    item["description"],
                    item["published"],
                    item["modified"],
                ),
            )
            count += cur.rowcount
    conn.commit()
    return count


# ── Incremental sync ───────────────────────────────────────────────────────────

def sync_nvd_incremental(conn: Any, api_key: str = "", days_back: int = 8) -> int:
    """Download CVEs modified in the last *days_back* days and upsert them.

    Rate limiting: 0.6 s/page with API key, 6.0 s/page without.
    Updates nvd_sync_state.last_incr_sync and total_cves on completion.
    Returns total count of rows upserted.
    """
    now = datetime.now(timezone.utc)
    start_dt = now - timedelta(days=days_back)
    start_str = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_str = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    delay = 0.6 if api_key else 6.0
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    total_upserted = 0
    start_index = 0
    page = 0

    with httpx.Client(timeout=30.0) as http:
        while True:
            page += 1
            params = {
                "lastModStartDate":  start_str,
                "lastModEndDate":    end_str,
                "startIndex":        start_index,
                "resultsPerPage":    _PAGE_SIZE,
            }
            try:
                resp = http.get(_NVD_BASE, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                log.error("[NVD] incremental sync: page %d request failed: %s", page, exc)
                break

            vulns = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)

            parsed = [_parse_cve_item(v) for v in vulns]
            parsed = [p for p in parsed if p is not None]
            upserted = _upsert_cves(conn, parsed)
            total_upserted += upserted

            log.info(
                "[NVD] incremental sync: page %d, %d CVEs upserted so far",
                page, total_upserted,
            )

            start_index += len(vulns)
            if start_index >= total_results or not vulns:
                break

            time.sleep(delay)

    # Update sync state
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE nvd_sync_state
            SET last_incr_sync = NOW(),
                total_cves     = (SELECT COUNT(*) FROM nvd_cves)
            WHERE id = 1
            """,
        )
    conn.commit()

    log.info("[NVD] incremental sync complete: %d CVEs upserted total", total_upserted)
    return total_upserted


# ── Full sync ──────────────────────────────────────────────────────────────────

def sync_nvd_full(conn: Any, api_key: str = "", start_year: int = 2020) -> int:
    """Full sync of all CVEs from *start_year* through now.

    Designed to run in APScheduler as a long-running background job (minutes
    to hours depending on year range and API key presence).
    Updates nvd_sync_state.last_full_sync on completion.
    Returns total count of rows upserted.
    """
    delay = 0.6 if api_key else 6.0
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    now = datetime.now(timezone.utc)
    # Use pubStartDate / pubEndDate to scope to start_year–now
    pub_start = f"{start_year}-01-01T00:00:00.000Z"
    pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    total_upserted = 0
    start_index = 0
    total_results: int | None = None
    page = 0
    total_pages: int | None = None

    with httpx.Client(timeout=60.0) as http:
        while True:
            page += 1
            params = {
                "pubStartDate":   pub_start,
                "pubEndDate":     pub_end,
                "startIndex":     start_index,
                "resultsPerPage": _PAGE_SIZE,
            }
            try:
                resp = http.get(_NVD_BASE, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                log.error("[NVD] full sync: page %d request failed: %s", page, exc)
                break

            # Capture totals from first page
            if total_results is None:
                total_results = data.get("totalResults", 0)
                total_pages = max(1, -(-total_results // _PAGE_SIZE))  # ceil division
                log.info(
                    "[NVD] full sync started: %d total CVEs (~%d pages)",
                    total_results, total_pages,
                )

            vulns = data.get("vulnerabilities", [])
            parsed = [_parse_cve_item(v) for v in vulns]
            parsed = [p for p in parsed if p is not None]
            upserted = _upsert_cves(conn, parsed)
            total_upserted += upserted

            log.info(
                "[NVD] full sync: page %d/%s — %d CVEs upserted",
                page,
                str(total_pages) if total_pages is not None else "?",
                total_upserted,
            )

            start_index += len(vulns)
            if not vulns or (total_results is not None and start_index >= total_results):
                break

            time.sleep(delay)

    # Update sync state
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE nvd_sync_state
            SET last_full_sync = NOW(),
                total_cves     = (SELECT COUNT(*) FROM nvd_cves)
            WHERE id = 1
            """,
        )
    conn.commit()

    log.info("[NVD] full sync complete: %d CVEs upserted total", total_upserted)
    return total_upserted


# ── Local lookup ───────────────────────────────────────────────────────────────

def lookup_cves_local(conn: Any, name: str, version: str = "") -> list[dict]:
    """Query local nvd_cves for CVEs matching a package name.

    Uses ILIKE '%name%' on description (CPE matching is a future enhancement).
    Excludes rows where score = 0. Returns up to 10 results ordered by score DESC.
    Returns [] gracefully if the nvd_cves table does not yet exist.

    Return shape mirrors software_inventory.py's NVD API caller:
      [{"id": "CVE-...", "severity": "high", "score": 7.5, "description": "...",
        "epss_score": 0.012, "epss_pct": 0.45, "is_kev": false}]
    """
    if not name or not name.strip():
        return []

    search_term = f"%{name.strip()}%"

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT cve_id, severity, score, description,
                       epss_score, epss_pct, is_kev
                FROM nvd_cves
                WHERE description ILIKE %s
                  AND score > 0
                ORDER BY score DESC
                LIMIT 10
                """,
                (search_term,),
            )
            rows = cur.fetchall()
    except Exception as exc:
        # Table may not exist on first startup — degrade gracefully
        log.debug("[NVD] lookup_cves_local: skipping (%s)", exc)
        return []

    results: list[dict] = []
    for row in rows:
        results.append({
            "id":          row["cve_id"],
            "severity":    row["severity"] or "none",
            "score":       float(row["score"] or 0.0),
            "description": row["description"] or "",
            "epss_score":  float(row["epss_score"] or 0.0),
            "epss_pct":    float(row["epss_pct"] or 0.0),
            "is_kev":      bool(row["is_kev"]),
        })
    return results


# ── Mirror health check ────────────────────────────────────────────────────────

def is_mirror_populated(conn: Any) -> bool:
    """Return True if nvd_cves holds more than 1 000 rows (mirror is usable).

    Used by callers to decide whether to fall back to the live NVD API.
    """
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM nvd_cves;")
            row = cur.fetchone()
            return (row[0] if row else 0) > 1000
    except Exception:
        return False
