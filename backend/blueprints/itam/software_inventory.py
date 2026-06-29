"""blueprints/itam/software_inventory.py — Software inventory storage and CVE enrichment for ITAM."""
from __future__ import annotations

import logging
import re
import time
from typing import Any

import httpx
import psycopg2.extras

log = logging.getLogger(__name__)

SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "none": 0,
    "unknown": 0,
}

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_OS_NOISE_RE = re.compile(
    r"^(libx|libgtk|locales|tzdata|ca-certificates|fonts-|adduser|base-files|coreutils|dpkg)",
    re.IGNORECASE,
)

# ── Schema ─────────────────────────────────────────────────────────────────────

_CREATE_SW_TABLE = """
CREATE TABLE IF NOT EXISTS software_inventory (
    id               SERIAL PRIMARY KEY,
    asset_id         INTEGER NOT NULL,
    name             TEXT NOT NULL,
    version          TEXT,
    vendor           TEXT,
    package_manager  VARCHAR(20),
    architecture     VARCHAR(20),
    cve_count        INTEGER DEFAULT 0,
    highest_severity VARCHAR(10) DEFAULT 'none',
    cves             JSONB DEFAULT '[]'::jsonb,
    last_scanned     TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(asset_id, name, version)
);
"""

_CREATE_SW_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_sw_asset ON software_inventory(asset_id);",
    "CREATE INDEX IF NOT EXISTS idx_sw_sev ON software_inventory(highest_severity) WHERE cve_count > 0;",
]

_NETWORK_ASSETS_COLUMNS = [
    ("hardware_info",        "JSONB DEFAULT '{}'"),
    ("services",             "JSONB DEFAULT '[]'"),
    ("local_users",          "JSONB DEFAULT '[]'"),
    ("software_count",       "INTEGER DEFAULT 0"),
    ("vuln_count",           "INTEGER DEFAULT 0"),
    ("highest_cve_severity", "VARCHAR(10) DEFAULT 'none'"),
    ("last_deep_scan",       "TIMESTAMPTZ"),
]


def ensure_software_tables(conn: Any) -> None:
    with conn.cursor() as cur:
        cur.execute(_CREATE_SW_TABLE)
        for idx_sql in _CREATE_SW_INDEXES:
            cur.execute(idx_sql)
        for col_name, col_def in _NETWORK_ASSETS_COLUMNS:
            cur.execute(
                f"ALTER TABLE network_assets ADD COLUMN IF NOT EXISTS {col_name} {col_def};"
            )
    conn.commit()


# ── Upsert ─────────────────────────────────────────────────────────────────────

def upsert_software(conn: Any, asset_id: int, packages: list[dict]) -> int:
    inserted = 0
    with conn.cursor() as cur:
        for pkg in packages:
            name = (pkg.get("name") or "").strip()
            if not name or _OS_NOISE_RE.match(name):
                continue
            version = (pkg.get("version") or "").strip()
            vendor = (pkg.get("vendor") or "").strip()
            pm = (pkg.get("package_manager") or "").strip()
            arch = (pkg.get("architecture") or "").strip()

            cur.execute(
                """
                INSERT INTO software_inventory
                    (asset_id, name, version, vendor, package_manager, architecture, last_scanned)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (asset_id, name, version) DO UPDATE SET
                    vendor          = EXCLUDED.vendor,
                    package_manager = EXCLUDED.package_manager,
                    last_scanned    = NOW()
                """,
                (asset_id, name, version, vendor, pm, arch),
            )
            inserted += cur.rowcount
    conn.commit()
    return inserted


# ── CVE enrichment ─────────────────────────────────────────────────────────────

def _parse_nvd_response(data: dict) -> list[dict]:
    cves: list[dict] = []
    for item in data.get("vulnerabilities", []):
        cve_obj = item.get("cve", {})
        cve_id = cve_obj.get("id", "")

        severity = "none"
        score: float = 0.0
        metrics = cve_obj.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_key, [])
            if entries:
                data_entry = entries[0].get("cvssData", {})
                raw_sev = (data_entry.get("baseSeverity") or "none").lower()
                raw_score = float(data_entry.get("baseScore") or 0.0)
                if raw_sev and raw_sev != "none":
                    severity = raw_sev
                    score = raw_score
                    break

        description = ""
        for desc in cve_obj.get("descriptions", []):
            if desc.get("lang") == "en":
                description = (desc.get("value") or "")[:200]
                break

        if cve_id:
            cves.append({"cve_id": cve_id, "severity": severity, "score": score, "description": description})
    return cves


def enrich_asset_cves(
    conn: Any,
    asset_id: int,
    api_key: str = "",
    max_packages: int = 50,
) -> int:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT id, name, version FROM software_inventory
            WHERE asset_id = %s AND cve_count = 0
            ORDER BY id
            LIMIT %s
            """,
            (asset_id, max_packages),
        )
        rows = list(cur.fetchall())

    total_vulns = 0
    delay = 0.6 if api_key else 6.0
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    with httpx.Client(timeout=30.0) as http:
        for row in rows:
            row_id = row["id"]
            name = row["name"] or ""
            version = row["version"] or ""
            keyword = f"{name} {version}".strip()

            try:
                resp = http.get(
                    _NVD_BASE,
                    params={"keywordSearch": keyword, "resultsPerPage": 10},
                    headers=headers,
                )
                resp.raise_for_status()
                cves = _parse_nvd_response(resp.json())
            except Exception as exc:
                log.warning("NVD lookup failed for %s %s: %s", name, version, exc)
                cves = []

            cve_count = len(cves)
            highest = "none"
            for cve in cves:
                sev = cve.get("severity", "none")
                if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(highest, 0):
                    highest = sev

            import json as _json
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE software_inventory
                    SET cve_count = %s, highest_severity = %s, cves = %s::jsonb
                    WHERE id = %s
                    """,
                    (cve_count, highest, _json.dumps(cves), row_id),
                )
            conn.commit()
            total_vulns += cve_count
            time.sleep(delay)

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT
                COALESCE(SUM(cve_count), 0)            AS vuln_count,
                COUNT(*)                               AS software_count,
                COALESCE(
                    (
                        SELECT highest_severity
                        FROM software_inventory
                        WHERE asset_id = %s AND cve_count > 0
                        ORDER BY CASE highest_severity
                            WHEN 'critical' THEN 4
                            WHEN 'high'     THEN 3
                            WHEN 'medium'   THEN 2
                            WHEN 'low'      THEN 1
                            ELSE 0
                        END DESC
                        LIMIT 1
                    ),
                    'none'
                ) AS highest_cve_severity
            FROM software_inventory
            WHERE asset_id = %s
            """,
            (asset_id, asset_id),
        )
        agg = cur.fetchone()

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE network_assets
            SET vuln_count           = %s,
                highest_cve_severity = %s,
                software_count       = %s
            WHERE id = %s
            """,
            (
                int(agg["vuln_count"] if agg else 0),
                str(agg["highest_cve_severity"] if agg else "none"),
                int(agg["software_count"] if agg else 0),
                asset_id,
            ),
        )
    conn.commit()
    return total_vulns


# ── Summary ────────────────────────────────────────────────────────────────────

def get_asset_software_summary(conn: Any, asset_id: int) -> dict:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT hostname, ip_address, hardware_info, services, local_users, last_deep_scan
            FROM network_assets
            WHERE id = %s
            """,
            (asset_id,),
        )
        asset = cur.fetchone()

    if not asset:
        return {
            "asset_id": asset_id,
            "hostname": "",
            "ip_address": "",
            "hardware_info": {},
            "services": [],
            "local_users": [],
            "last_deep_scan": None,
            "software": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        }

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT
                COUNT(*)                                          AS total,
                COUNT(*) FILTER (WHERE highest_severity = 'critical') AS critical,
                COUNT(*) FILTER (WHERE highest_severity = 'high')     AS high,
                COUNT(*) FILTER (WHERE highest_severity = 'medium')   AS medium,
                COUNT(*) FILTER (WHERE highest_severity = 'low')      AS low
            FROM software_inventory
            WHERE asset_id = %s
            """,
            (asset_id,),
        )
        counts = cur.fetchone()

    last_scan = asset["last_deep_scan"]
    return {
        "asset_id": asset_id,
        "hostname": asset["hostname"] or "",
        "ip_address": asset["ip_address"] or "",
        "hardware_info": asset["hardware_info"] or {},
        "services": asset["services"] or [],
        "local_users": asset["local_users"] or [],
        "last_deep_scan": last_scan.isoformat() if last_scan else None,
        "software": {
            "total":    int(counts["total"]    if counts else 0),
            "critical": int(counts["critical"] if counts else 0),
            "high":     int(counts["high"]     if counts else 0),
            "medium":   int(counts["medium"]   if counts else 0),
            "low":      int(counts["low"]      if counts else 0),
        },
    }
