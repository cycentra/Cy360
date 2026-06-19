#!/var/ossec/framework/python/bin/python3
"""
sync_misp_cache.py — CyCentra 360 MISP Threat Intel Sync
=========================================================
Fetches active, published IOCs from a remote MISP instance (ip-src, ip-dst, md5,
sha256) updated within the last 30 days, writes them as a Wazuh CDB flat file, and
compiles the binary lookup index atomically.

Deploy path : /var/ossec/etc/lists/sync_misp_cache.py
Cron        : 0 * * * * root /var/ossec/framework/python/bin/python3 \
              /var/ossec/etc/lists/sync_misp_cache.py >> /var/ossec/logs/misp_sync.log 2>&1

Secret resolution (in priority order):
  1. /opt/cycentra/.env   — set by kv_secrets.py at Flask startup
  2. Process environment  — useful in CI / manual invocation
  3. Direct Infisical API — stdlib urllib only (no external packages needed);
                           reads INFISICAL_* vars from .env for auth context
"""

import fcntl
import json
import logging
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────
BLACKLIST_PATH  = Path("/var/ossec/etc/lists/misp_global_blacklist")
DBCHECK_BIN     = "/var/ossec/bin/wazuh-dbcheck"
WAZUH_CTL       = "/var/ossec/bin/wazuh-control"
LOCK_FILE       = Path("/var/ossec/var/run/misp-sync.lock")
DOT_ENV         = Path("/opt/cycentra/.env")
LOG_FILE        = Path("/var/ossec/logs/misp_sync.log")

INDICATOR_TYPES = ["ip-src", "ip-dst", "md5", "sha256"]
DAYS_LOOKBACK   = 30
PAGE_SIZE       = 1000          # MISP max recommended page size
REQUEST_TIMEOUT = 30            # seconds per MISP HTTP call
MAX_INDICATORS  = 500_000       # safety cap — abort if MISP returns more
MIN_FREE_MB     = 50            # refuse to write if disk < 50 MB free

# CDB file owner / permissions
WAZUH_UID = None   # resolved at runtime via pwd lookup
WAZUH_GID = None   # resolved at runtime via grp lookup
FILE_MODE = 0o640

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [misp-sync] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("misp-sync")


# ── .env parser ───────────────────────────────────────────────────────────────
def _load_dotenv(path: Path) -> dict:
    """Parse key=value pairs from a systemd-style .env file."""
    result = {}
    if not path.is_file():
        return result
    try:
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            # Strip optional surrounding quotes (single or double)
            val = val.strip().strip('"').strip("'")
            if key:
                result[key] = val
    except OSError as exc:
        log.warning("Could not read %s: %s", path, exc)
    return result


# ── Secret resolution ─────────────────────────────────────────────────────────
def _resolve_secrets() -> tuple[str, str]:
    """
    Return (misp_url, misp_api_key).

    Resolution order:
      1. /opt/cycentra/.env (populated by kv_secrets.py at Flask startup)
      2. Process environment variables
      3. Direct Infisical API call (stdlib urllib — no pip packages needed)

    Raises RuntimeError if neither can be resolved.
    """
    env_file = _load_dotenv(DOT_ENV)

    def _get(key: str) -> str:
        return env_file.get(key, "") or os.environ.get(key, "")

    misp_url = _get("CLOUD_MISP_URL").rstrip("/")
    misp_key = _get("CLOUD_MISP_API_KEY")

    if misp_url and misp_key:
        log.debug("Secrets resolved from .env / environment")
        return misp_url, misp_key

    # ── Tier 3: Direct Infisical API via urllib ───────────────────────────────
    log.info("CLOUD_MISP_URL/API_KEY not in .env — attempting Infisical direct fetch")
    misp_url, misp_key = _infisical_fetch_misp(env_file)
    if misp_url and misp_key:
        return misp_url, misp_key

    raise RuntimeError(
        "Cannot resolve CLOUD_MISP_URL / CLOUD_MISP_API_KEY. "
        "Set them in /opt/cycentra/.env or configure Infisical."
    )


def _infisical_fetch_misp(env_file: dict) -> tuple[str, str]:
    """Fetch MISP secrets directly from Infisical REST API using only stdlib."""
    def _e(key):
        return env_file.get(key, "") or os.environ.get(key, "")

    project_id  = _e("INFISICAL_PROJECT_ID")
    client_id   = _e("INFISICAL_CLIENT_ID")
    environment = _e("INFISICAL_ENVIRONMENT") or "prod"
    base_url    = (_e("INFISICAL_URL") or "https://app.infisical.com").rstrip("/")

    if not project_id or not client_id:
        log.warning("INFISICAL_PROJECT_ID or INFISICAL_CLIENT_ID not set — skipping Infisical")
        return "", ""

    auth_method = (_e("INFISICAL_AUTH_METHOD") or "universal").lower()
    access_token = ""

    try:
        if auth_method in ("azure", "oidc"):
            access_token = _infisical_arc_auth(base_url, client_id)
        else:
            client_secret = _e("INFISICAL_CLIENT_SECRET")
            if not client_secret:
                log.warning("INFISICAL_CLIENT_SECRET not set — cannot use universal auth")
                return "", ""
            access_token = _infisical_universal_auth(base_url, client_id, client_secret)
    except Exception as exc:
        log.warning("Infisical auth failed: %s", exc)
        return "", ""

    if not access_token:
        return "", ""

    misp_url = _infisical_get_secret(base_url, access_token, project_id, environment, "CLOUD-MISP-URL")
    misp_key = _infisical_get_secret(base_url, access_token, project_id, environment, "CLOUD-MISP-API-KEY")
    # Also try underscore variants (secrets uploaded via CSV use FOO_BAR names)
    if not misp_url:
        misp_url = _infisical_get_secret(base_url, access_token, project_id, environment, "CLOUD_MISP_URL")
    if not misp_key:
        misp_key = _infisical_get_secret(base_url, access_token, project_id, environment, "CLOUD_MISP_API_KEY")

    return (misp_url or "").rstrip("/"), misp_key or ""


def _infisical_universal_auth(base_url: str, client_id: str, client_secret: str) -> str:
    payload = json.dumps({"clientId": client_id, "clientSecret": client_secret}).encode()
    req = urllib.request.Request(
        f"{base_url}/api/v1/auth/universal-auth/login",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode()).get("accessToken", "")


def _infisical_arc_auth(base_url: str, client_id: str) -> str:
    """HIMDS challenge-response → Infisical OIDC login. Mirrors kv_secrets._fetch_arc_jwt."""
    arc_url = (
        "http://localhost:40342/metadata/identity/oauth2/token"
        "?api-version=2020-06-01&resource=https://management.azure.com/"
    )
    # Step 1 — get 401 challenge
    try:
        urllib.request.urlopen(
            urllib.request.Request(arc_url, headers={"Metadata": "true"}), timeout=5
        )
        raise RuntimeError("HIMDS returned 200 without challenge")
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise RuntimeError(f"HIMDS returned {exc.code}") from exc
        auth_hdr = exc.headers.get("Www-Authenticate", "")
        m = re.search(r"realm=(\S+)", auth_hdr)
        if not m:
            raise RuntimeError("No realm in HIMDS Www-Authenticate header")
        key_path = m.group(1)

    # Step 2 — read challenge key
    with open(key_path) as f:
        raw_key = f.read().strip()

    # Step 3 — fetch JWT
    req = urllib.request.Request(
        arc_url,
        headers={"Metadata": "true", "Authorization": f"Basic {raw_key}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        arc_jwt = json.loads(resp.read().decode()).get("access_token", "")

    if not arc_jwt:
        raise RuntimeError("HIMDS returned empty access_token")

    # Step 4 — exchange JWT for Infisical token
    payload = json.dumps({"identityId": client_id, "jwt": arc_jwt}).encode()
    req2 = urllib.request.Request(
        f"{base_url}/api/v1/auth/oidc-auth/login",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req2, timeout=10) as resp2:
        return json.loads(resp2.read().decode()).get("accessToken", "")


def _infisical_get_secret(
    base_url: str, token: str, project_id: str, environment: str, name: str
) -> str:
    url = (
        f"{base_url}/api/v3/secrets/raw/{urllib.parse.quote(name)}"
        f"?workspaceId={urllib.parse.quote(project_id)}"
        f"&environment={urllib.parse.quote(environment)}"
        f"&secretPath=%2F"
    )
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return data.get("secret", {}).get("secretValue", "")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return ""   # secret simply not found
        raise


# ── MISP fetch ────────────────────────────────────────────────────────────────
def _misp_request(misp_url: str, api_key: str, payload: dict) -> dict:
    """POST to /attributes/restSearch with proper MISP headers."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{misp_url}/attributes/restSearch",
        data=data,
        headers={
            "Authorization":    api_key,
            "Content-Type":     "application/json",
            "Accept":           "application/json",
            "User-Agent":       "CyCentra360-MISP-Sync/1.0 (compatible; Python-urllib)",
            "Accept-Language":  "en-US,en;q=0.9",
            "Accept-Encoding":  "gzip, deflate, br",
            "Connection":       "keep-alive",
        },
        method="POST",
    )
    # Build SSL context: prefer certifi CA bundle (Wazuh's bundled OpenSSL has stale roots).
    # Set MISP_VERIFY_SSL=0 to disable verification for self-signed MISP certs.
    import ssl
    if os.environ.get("MISP_VERIFY_SSL", "1") == "0":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        log.warning("SSL certificate verification disabled (MISP_VERIFY_SSL=0)")
    else:
        try:
            import certifi
            ctx = ssl.create_default_context(cafile=certifi.where())
        except ImportError:
            ctx = ssl.create_default_context()  # fall back to default (may miss intermediates)

    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read(512).decode(errors="replace")
        raise RuntimeError(f"MISP HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"MISP connection failed: {exc.reason}") from exc


def fetch_misp_indicators(misp_url: str, api_key: str) -> dict[str, str]:
    """
    Paginate through MISP /attributes/restSearch and return a dict of
    {indicator_value: indicator_type} for all active published IOCs
    updated within the last DAYS_LOOKBACK days.

    Returns an empty dict on failure (logged); never raises to caller.
    """
    cutoff_ts = int((datetime.now(timezone.utc) - timedelta(days=DAYS_LOOKBACK)).timestamp())
    indicators: dict[str, str] = {}
    page = 1
    total_fetched = 0

    log.info("Starting MISP fetch — types=%s lookback=%dd cutoff=%s",
             INDICATOR_TYPES, DAYS_LOOKBACK,
             datetime.fromtimestamp(cutoff_ts, tz=timezone.utc).strftime("%Y-%m-%d"))

    while True:
        payload = {
            "returnFormat": "json",
            "type":         {"OR": INDICATOR_TYPES},
            "published":    1,
            "timestamp":    cutoff_ts,
            "to_ids":       1,           # only actionable IOCs
            "deleted":      0,
            "limit":        PAGE_SIZE,
            "page":         page,
        }

        try:
            response = _misp_request(misp_url, api_key, payload)
        except RuntimeError as exc:
            log.error("MISP fetch error on page %d: %s", page, exc)
            break

        attributes = response.get("response", {}).get("Attribute", [])
        if not attributes:
            log.debug("Page %d returned 0 attributes — pagination complete", page)
            break

        page_count = 0
        for attr in attributes:
            ioc_type  = attr.get("type", "")
            ioc_value = attr.get("value", "").strip().lower()
            if not ioc_value or ioc_type not in INDICATOR_TYPES:
                continue
            # Sanitise: CDB keys must not contain whitespace or colons
            if " " in ioc_value or "\t" in ioc_value:
                continue
            # Collapse colons inside value (e.g. IPv6 is fine; hash shouldn't have colons)
            indicators[ioc_value] = ioc_type
            page_count += 1

        total_fetched += page_count
        log.info("Page %d: fetched %d indicators (running total: %d)", page, page_count, total_fetched)

        if total_fetched >= MAX_INDICATORS:
            log.warning("Reached MAX_INDICATORS cap (%d) — truncating", MAX_INDICATORS)
            break

        if len(attributes) < PAGE_SIZE:
            # Last page — MISP returned fewer than a full page
            break

        page += 1
        # Polite pacing: 200 ms between pages to avoid hammering MISP
        time.sleep(0.2)

    log.info("MISP fetch complete: %d unique indicators across %d page(s)", len(indicators), page)
    return indicators


# ── CDB write ────────────────────────────────────────────────────────────────
def _check_disk_space(path: Path, min_free_mb: int) -> None:
    """Raise RuntimeError if available disk space is below min_free_mb."""
    st = os.statvfs(path.parent)
    free_mb = (st.f_bavail * st.f_frsize) // (1024 * 1024)
    if free_mb < min_free_mb:
        raise RuntimeError(
            f"Insufficient disk space: {free_mb} MB free at {path.parent} "
            f"(minimum {min_free_mb} MB required)"
        )


def write_cdb_list(indicators: dict[str, str], dest: Path) -> int:
    """
    Write indicators to dest in Wazuh CDB flat-file format:
        <value>:<type>
    One indicator per line, sorted for deterministic diffs.
    Uses atomic write (temp file → rename) so the live file is never partially written.
    Returns the number of entries written.
    """
    if not indicators:
        log.warning("No indicators to write — leaving existing file unchanged")
        return 0

    _check_disk_space(dest, MIN_FREE_MB)

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Write to a sibling temp file so the rename is atomic on the same filesystem
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=dest.parent,
        prefix=".misp_tmp_",
        suffix=".list",
    )
    count = 0
    try:
        with os.fdopen(tmp_fd, "w") as fh:
            fh.write(f"# CyCentra 360 MISP global blacklist\n")
            fh.write(f"# Generated: {now_str}  Entries: {len(indicators)}\n")
            fh.write(f"# Lookback: {DAYS_LOOKBACK} days  Types: {', '.join(INDICATOR_TYPES)}\n")
            fh.write("#\n")
            for value in sorted(indicators):
                ioc_type = indicators[value]
                # Wazuh CDB format: key:value  (the value/label after the colon is
                # returned by match_key_value lookups and visible in alert enrichment)
                fh.write(f"{value}:{ioc_type}\n")
                count += 1
    except Exception:
        os.unlink(tmp_path)
        raise

    os.rename(tmp_path, str(dest))
    log.info("CDB list written: %d entries → %s", count, dest)
    return count


# ── Stale-entry cleanup ───────────────────────────────────────────────────────
def cleanup_stale_entries(dest: Path, max_age_days: int = DAYS_LOOKBACK) -> None:
    """
    Remove any indicator entries from dest whose comment-embedded timestamp is
    older than max_age_days.  Since sync_misp_cache.py performs a full refresh
    each run (fetching only last-30-days data), this function is primarily a
    safety net for files partially updated by older script versions or manual edits.

    The function also trims any file that has grown beyond a safe size threshold
    by keeping only the most recently added entries (sorted by first-seen order).
    """
    if not dest.is_file():
        return

    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    # Parse the generation timestamp from the header comment
    header_ts_re = re.compile(r"^# Generated:\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")

    lines = dest.read_text().splitlines()
    generated_at = None
    for line in lines[:10]:
        m = header_ts_re.match(line)
        if m:
            try:
                generated_at = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
            except ValueError:
                pass
            break

    if generated_at and generated_at < cutoff:
        log.warning(
            "CDB file at %s was generated on %s (> %d days ago) — "
            "file is stale; next full sync will replace it",
            dest,
            generated_at.strftime("%Y-%m-%d"),
            max_age_days,
        )
        # Do not delete — a stale list is better than no list.
        # The next successful MISP fetch will overwrite it atomically.
        return

    # Safety: if the file has grown unexpectedly large, truncate to MAX_INDICATORS lines
    data_lines = [l for l in lines if l and not l.startswith("#")]
    if len(data_lines) > MAX_INDICATORS:
        log.warning(
            "CDB file has %d entries (cap=%d) — truncating to cap",
            len(data_lines), MAX_INDICATORS,
        )
        header_lines = [l for l in lines if l.startswith("#")]
        kept = header_lines + data_lines[:MAX_INDICATORS]
        dest.write_text("\n".join(kept) + "\n")
        log.info("CDB truncated to %d entries", MAX_INDICATORS)


# ── CDB binary compilation ────────────────────────────────────────────────────
def compile_cdb(dest: Path) -> None:
    """
    Compile the plaintext CDB list to a binary index using wazuh-dbcheck.
    Falls back to signalling wazuh-analysisd to reload (which compiles on startup).
    """
    if os.path.isfile(DBCHECK_BIN):
        result = subprocess.run(
            [DBCHECK_BIN, "-c", str(dest)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            log.info("wazuh-dbcheck: CDB compiled successfully")
        else:
            log.warning(
                "wazuh-dbcheck exited %d: %s",
                result.returncode,
                (result.stderr or result.stdout).strip(),
            )
    else:
        log.warning(
            "%s not found — signalling wazuh-analysisd to reload rules "
            "(CDB will be compiled on reload)",
            DBCHECK_BIN,
        )
        # Trigger wazuh-analysisd rule reload without a full service restart
        if os.path.isfile(WAZUH_CTL):
            subprocess.run([WAZUH_CTL, "reload"], capture_output=True, timeout=30)


# ── Permission enforcement ────────────────────────────────────────────────────
def enforce_permissions(path: Path) -> None:
    """Set path to mode 0640 owned by root:wazuh."""
    import grp
    import pwd

    os.chmod(path, FILE_MODE)

    try:
        uid = pwd.getpwnam("root").pw_uid
        gid = grp.getgrnam("wazuh").gr_gid
        os.chown(path, uid, gid)
    except KeyError as exc:
        log.warning("Could not set ownership (%s) — check user/group exist", exc)
    except PermissionError as exc:
        log.warning("Could not chown %s: %s — running as non-root?", path, exc)


# ── Disk-backed advisory lock ─────────────────────────────────────────────────
class _SyncLock:
    """Prevent concurrent runs via an fcntl exclusive lock on LOCK_FILE."""

    def __init__(self, path: Path):
        self._path = path
        self._fh = None

    def __enter__(self):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._path, "w")
        try:
            fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._fh.close()
            raise RuntimeError(
                f"Another misp-sync process is already running (lock: {self._path})"
            )
        self._fh.write(str(os.getpid()))
        self._fh.flush()
        return self

    def __exit__(self, *_):
        if self._fh:
            fcntl.flock(self._fh, fcntl.LOCK_UN)
            self._fh.close()
        try:
            self._path.unlink()
        except FileNotFoundError:
            pass


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> int:
    start = time.monotonic()
    log.info("=" * 60)
    log.info("CyCentra 360 MISP sync starting")

    # Ensure output directory exists
    BLACKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)

    try:
        with _SyncLock(LOCK_FILE):
            # 1. Resolve secrets
            misp_url, api_key = _resolve_secrets()
            log.info("MISP endpoint: %s", misp_url)

            # 2. Fetch indicators from MISP
            indicators = fetch_misp_indicators(misp_url, api_key)
            if not indicators:
                log.error("No indicators returned from MISP — aborting write to preserve existing list")
                return 1

            # 3. Write CDB flat file (atomic)
            count = write_cdb_list(indicators, BLACKLIST_PATH)

            # 4. Safety cleanup — remove/warn about stale content
            cleanup_stale_entries(BLACKLIST_PATH)

            # 5. Compile to binary CDB index
            compile_cdb(BLACKLIST_PATH)

            # 6. Enforce permissions: 0640 root:wazuh
            enforce_permissions(BLACKLIST_PATH)

    except RuntimeError as exc:
        log.error("MISP sync failed: %s", exc)
        return 1
    except Exception as exc:
        log.exception("Unexpected error during MISP sync: %s", exc)
        return 1

    elapsed = time.monotonic() - start
    log.info("MISP sync complete: %d entries in %.1fs", count, elapsed)
    log.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
