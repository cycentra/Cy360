# Phase 7 — SIEM-Agnostic Adapter Layer: Detailed Execution Plan

**Document Status:** DRAFT — Pending Review & Approval Before Implementation  
**Prepared by:** g-cyra-360  
**Date:** 2026-07-08  
**Refs:** `docs/INVESTIGATION_ENGINE_PLAN.md` §5.7, `docs/WAZUH_INTEGRATION_AUDIT.md`  
**Prerequisite:** Phases 1–6 stable in production

---

## 0. Executive Summary

Phase 7 decouples all hardcoded Wazuh REST API calls from the platform layer and routes them
through a `SIEMAdapter` protocol. The adapter's active instance is determined at runtime by
reading the `cy_comp_siem_connections` table — the same table already exposed in
**Settings > Security Compliance > SIEM Sources > Add SIEM Source**.

**What this means for Internal Exposure:**
The Internal Exposure dashboard (`InternalExposureDashboard.jsx`) currently fetches incident
counts, entity risk, UEBA data, and threat hunt activity from the CySIEM correlation engine DB
tables — these are already SIEM-agnostic (they are the normalised output of the correlation
pipeline). However, two subsystems it depends on **call Wazuh directly**:
1. `_refresh_host_cache_sync()` in `siem_proxy.py` — fetches agent list, SCA scores, and
   vulnerability data from Wazuh REST API to populate `host_posture_cache`
2. `benchmark/routes.py` — fetches SCA policy results and vulnerability counts from Wazuh REST
   API to compute the Detection Posture Score displayed in the Internal Exposure header widget

After Phase 7, both of these will route through `get_active_adapter()`, using whichever SIEM
source is marked `is_active = TRUE` in Settings > Security Compliance > SIEM Sources.

**Zero-disruption guarantee:** Existing `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`
env vars remain fully operative as the fallback path. No operator action is required on
deployment — the platform auto-seeds a Wazuh adapter row from env vars if no active connection
exists in the DB.

---

## 1. Scope Definition

### 1.1 In Scope

| Area | Wazuh Calls Being Abstracted |
|------|------------------------------|
| `backend/siem_proxy.py` | `_wazuh_auth_token()`, `_wz()`, `_refresh_host_cache_sync()` (agents/SCA/vulnerabilities), 5 evidence-collector routes (process tree, DNS, SCA checks, packages, vuln detail) |
| `backend/blueprints/benchmark/routes.py` | `_wazuh_get()`, `/agents`, `/sca/<id>`, `/vulnerability/<id>` calls in `_collect_*()` functions |
| `backend/cysiemstack/host_service.py` | `_wazuh_token()`, `_wazuh_get()`, `_fetch_wazuh_agents()` |
| `backend/blueprints/comp/routes.py` | Fix credential encryption writing; add activate + test-connection routes |
| `backend/cy_comp/models.py` | Add missing columns to `cy_comp_siem_connections`; auto-seed from env |
| `portal/src/pages/settings/SystemSettingsPage.jsx` | Enhance `CompSIEMSourcesTab` — credentials, activate, test, health dot |
| `portal/src/siem/InternalExposureDashboard.jsx` | Active SIEM adapter badge; adapter-aware status messages |

### 1.2 Explicitly Out of Scope (Phase 7)

| Area | Why Excluded |
|------|-------------|
| Correlation engine normaliser (`normaliser.py`) | Structural Wazuh schema dependency — tracked in Wazuh Audit Layer 1/2; separate initiative |
| All 55 correlator rules (`correlator.py`) | Rule ID decoupling — separate initiative (Wazuh Audit Layer 2) |
| UEBA detectors (`ueba.py`) | `wazuh_id` FK coupling — separate initiative |
| `CYSIEM-Config/` — Wazuh manager config | Not a Python change; operational config |
| Active Response (`POST /active-response`) | Wazuh-specific endpoint; addressed in Wazuh Audit Layer 5 |
| `systemctl restart wazuh-manager` in `system/routes.py` | Wazuh Audit Layer 6; separate |
| Splunk / Sentinel / Elastic adapter implementations | Declared stubs only in Phase 7; full implementations in future phases |

> **Note:** The above exclusions mean the platform remains Wazuh-dependent for alert ingestion
> and correlation rule firing after Phase 7. Phase 7 achieves SIEM-agnostic **API access**
> (host posture, benchmark, evidence collection). Full ingestion abstraction is a later initiative.

---

## 2. Files to Create

```
backend/
  siem_adapters/
    __init__.py     ← get_active_adapter() factory
    base.py         ← SIEMAdapter Protocol + NullAdapter
    wazuh.py        ← WazuhAdapter (absorbs all existing inline Wazuh helpers)
```

---

## 3. Files to Modify

| File | Nature of Change |
|------|-----------------|
| `backend/cy_comp/models.py` | Add 3 columns to `cy_comp_siem_connections`; add auto-seed migration |
| `backend/blueprints/comp/routes.py` | Fix password_enc/api_key_enc writing; add `/activate` + `/test` routes |
| `backend/siem_proxy.py` | Replace 7 inline Wazuh call sites with adapter; new `GET /api/siem/adapter/status` route |
| `backend/blueprints/benchmark/routes.py` | Replace `_wazuh_get()` + auth with adapter |
| `backend/cysiemstack/host_service.py` | Replace `_wazuh_token()`, `_fetch_wazuh_agents()` with adapter |
| `portal/src/pages/settings/SystemSettingsPage.jsx` | Enhance `CompSIEMSourcesTab` (password, API key, activate, test, health dot) |
| `portal/src/siem/InternalExposureDashboard.jsx` | Adapter status badge; adapter-aware offline message |

---

## 4. Database Changes

All changes use `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` (never `create_all()`).

```sql
-- In cy_comp/models.py → ensure_tables() — 3 new columns on existing table
ALTER TABLE cy_comp_siem_connections
    ADD COLUMN IF NOT EXISTS capabilities  JSONB   DEFAULT '[]';

ALTER TABLE cy_comp_siem_connections
    ADD COLUMN IF NOT EXISTS last_tested   TIMESTAMPTZ;

ALTER TABLE cy_comp_siem_connections
    ADD COLUMN IF NOT EXISTS last_test_ok  BOOLEAN;
```

### 4.1 Auto-Seed Migration (zero operator action required)

On startup, `ensure_tables()` runs the following after schema migrations:

```python
# If WAZUH_API_URL env var is set AND no active connection exists →
# insert a "Wazuh (migrated from config)" row with is_active=TRUE.
# This ensures existing deployments are unaffected by Phase 7.
# If a row already exists (matching host), skip insertion.
```

Precise logic:
1. Check `SELECT COUNT(*) FROM cy_comp_siem_connections WHERE is_active = TRUE`
2. If count == 0 AND `WAZUH_API_URL` env var is set:
   - Upsert (on conflict `host`) a row: `{name: "Wazuh", siem_type: "wazuh", host: WAZUH_API_URL, port: 55000, username: WAZUH_API_USER, is_active: TRUE}`
3. If count > 0: skip — operator has already configured a connection

---

## 5. New Files — Detailed Specification

### 5.1 `backend/siem_adapters/base.py`

**SIEMAdapter Protocol** — 9 method signatures:

```python
class SIEMAdapter(Protocol):
    def get_agents(self) -> list[dict]: ...
    def get_agent_sca(self, agent_id: str) -> dict: ...
    def get_agent_vulnerabilities(self, agent_id: str) -> dict: ...
    def get_agent_packages(self, agent_id: str) -> dict: ...
    def get_process_tree(self, agent_id: str, pid: str) -> dict: ...
    def get_dns_history(self, agent_id: str) -> dict: ...
    def get_auth_token(self) -> str | None: ...
    def test_connection(self) -> dict: ...
    def get_capabilities(self) -> list[str]: ...
```

**NullAdapter** — All methods return `{}` or `[]`. Used when no adapter is configured and no
env var fallback exists. Prevents crashes; returns empty data gracefully.

### 5.2 `backend/siem_adapters/wazuh.py` — `WazuhAdapter`

Absorbs the following from `siem_proxy.py` with **identical logic, no behavior change**:

| Existing function/code | Moves to WazuhAdapter method |
|------------------------|------------------------------|
| `_wazuh_auth_token()` (siem_proxy line ~1793) | `get_auth_token()` |
| `_wz(path, method, **kwargs)` (siem_proxy line ~1819) | `_request(path, method, **kwargs)` (private) |
| Agent fetch block in `_refresh_host_cache_sync()` lines ~1457–1550 | `get_agents()` |
| SCA fetch in `_refresh_host_cache_sync()` lines ~1567–1595 | `get_agent_sca(agent_id)` |
| Vulnerability fetch in `_refresh_host_cache_sync()` lines ~1596–1630 | `get_agent_vulnerabilities(agent_id)` |
| Packages fetch | `get_agent_packages(agent_id)` |
| Evidence collector routes lines ~2935–3048 (process tree, DNS, etc.) | `get_process_tree()`, `get_dns_history()` |
| `test_connection()` | Returns `{ok, latency_ms, wazuh_version, agent_count}` |
| `get_capabilities()` | Returns `["sca", "vulnerabilities", "packages", "process_tree", "dns_history", "agents"]` |

Constructor signature:
```python
class WazuhAdapter:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = False):
        ...
```

### 5.3 `backend/siem_adapters/__init__.py` — `get_active_adapter()`

**Resolution order** (first match wins):

```
1. DB: SELECT * FROM cy_comp_siem_connections WHERE is_active=TRUE LIMIT 1
       → decrypt password_enc / api_key_enc → instantiate adapter by siem_type
2. ENV fallback: if WAZUH_API_URL + WAZUH_API_PASSWORD set
       → WazuhAdapter(WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD)
3. NullAdapter (returns empty data, logs warning once per process start)
```

The adapter instance is **cached per process** (module-level singleton with a 5-minute TTL).
A cache invalidation signal is sent whenever `POST /api/comp/settings/siem-connections/<id>/activate`
is called, ensuring the new adapter is picked up within one request cycle.

### 5.4 Adapter Inventory — Phase 7 Delivery Tiers

The existing `cy_comp_siem_connections.siem_type` column and the Settings UI dropdown already
enumerate the full intended set ([SystemSettingsPage.jsx line 2971](../portal/src/pages/settings/SystemSettingsPage.jsx)):

```js
["wazuh", "splunk", "elastic", "sentinel", "qradar", "correlation_engine"]
```

Phase 7 ships them in two tiers:

| Adapter file | `siem_type` | Phase 7 Status | Capabilities delivered |
|---|---|---|---|
| `siem_adapters/wazuh.py` | `wazuh` | **Full implementation** | `agents`, `sca`, `vulnerabilities`, `packages`, `process_tree`, `dns_history` |
| `siem_adapters/splunk.py` | `splunk` | Declared stub | `get_capabilities()` returns `[]`; all data methods return `{}`/`[]`; logs warning |
| `siem_adapters/elastic.py` | `elastic` | Declared stub | Same as Splunk stub |
| `siem_adapters/sentinel.py` | `sentinel` | Declared stub | Same |
| `siem_adapters/qradar.py` | `qradar` | Declared stub | Same |
| `siem_adapters/null.py` | *(fallback)* | **NullAdapter** | Used when no adapter configured — silent empty data, no crash |

**Stub behaviour rationale:** If a user activates Splunk in the UI before a full
`SplunkAdapter` is implemented, the platform degrades gracefully: benchmark returns `0` for
SCA/vuln subscores, host posture shows no agents. No crash, no 500 error. Full
Splunk / Elastic / Sentinel / QRadar implementations are future phases.

---

### 5.5 Adding a New SIEM Adapter (Future Extension Process)

The Protocol-based design makes adding a new SIEM a **self-contained 3-step process that
touches no existing code**. This section is the reference guide for whoever implements
Splunk, Elastic, Sentinel, or QRadar.

#### Step 1 — Create `backend/siem_adapters/<name>.py`

Implement every method defined in `SIEMAdapter` (base.py). The only hard contract is that
each data method returns the same dict shape as `WazuhAdapter`. Example for Splunk:

```python
# backend/siem_adapters/splunk.py

import requests
from .base import SIEMAdapter

class SplunkAdapter:
    siem_type = "splunk"

    def __init__(self, base_url: str, username: str, password: str, api_key: str = ""):
        self._base    = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.verify = False
        # Prefer token auth; fall back to username/password
        if api_key:
            self._session.headers["Authorization"] = f"Bearer {api_key}"
        else:
            self._authenticate(username, password)

    def _authenticate(self, username: str, password: str):
        r = self._session.post(
            f"{self._base}/services/auth/login",
            data={"username": username, "password": password},
        )
        r.raise_for_status()
        token = r.json()["sessionKey"]
        self._session.headers["Authorization"] = f"Splunk {token}"

    def get_agents(self) -> list[dict]:
        # Query the endpoint index for unique hosts active in the last 24h.
        # Return list in same shape WazuhAdapter uses:
        # [{agent_id, name, ip, os_type, os_version, status, last_seen}]
        ...

    def get_agent_sca(self, agent_id: str) -> dict:
        # Splunk Enterprise Security: query compliance checks for this host.
        # If Splunk ES not licensed, return {} — caller checks get_capabilities().
        ...

    def get_agent_vulnerabilities(self, agent_id: str) -> dict:
        # Query vulnerability scan results from the Splunk index.
        # Shape: {agent_id, items: [{cve, severity, package, ...}]}
        ...

    def get_agent_packages(self, agent_id: str) -> dict: ...
    def get_process_tree(self, agent_id: str, pid: str) -> dict: ...
    def get_dns_history(self, agent_id: str) -> dict: ...

    def get_auth_token(self) -> str | None:
        return self._session.headers.get("Authorization")

    def test_connection(self) -> dict:
        # GET /services/server/info  →  check HTTP 200 + parse build/version
        try:
            r = self._session.get(f"{self._base}/services/server/info", timeout=5)
            ok = r.status_code == 200
            info = r.json().get("entry", [{}])[0].get("content", {})
            return {"ok": ok, "version": info.get("version"), "build": info.get("build")}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def get_capabilities(self) -> list[str]:
        # Declare ONLY the methods that return real data in this implementation.
        # Callers skip subscores for any capability not listed here.
        return ["agents", "vulnerabilities"]   # SCA requires Splunk ES licence
```

#### Step 2 — Register in `backend/siem_adapters/__init__.py`

Add one import and one dict entry. No other file changes:

```python
from .wazuh    import WazuhAdapter
from .splunk   import SplunkAdapter   # ← add
from .elastic  import ElasticAdapter  # ← add
from .null     import NullAdapter

_ADAPTER_MAP = {
    "wazuh":               WazuhAdapter,
    "splunk":              SplunkAdapter,   # ← add
    "elastic":             ElasticAdapter,  # ← add
    "sentinel":            SentinelAdapter,
    "qradar":              QRadarAdapter,
    "correlation_engine":  NullAdapter,
}

def get_active_adapter() -> SIEMAdapter:
    row = _get_active_db_row()          # reads cy_comp_siem_connections WHERE is_active=TRUE
    cls = _ADAPTER_MAP.get(row["siem_type"], NullAdapter)
    return cls(
        base_url = row["host"],
        username = row["username"],
        password = decrypt_value(row["password_enc"]),
        api_key  = decrypt_value(row["api_key_enc"]),
    )
```

#### Step 3 — (Optional) `test_connection()` response format

`POST /api/comp/settings/siem-connections/<id>/test` calls `adapter.test_connection()` and
forwards the result dict directly to the UI. The UI renders it as a status message. The
shape is flexible — no route change required. The only convention: include an `"ok": bool`
key so the UI knows whether to show green or red.

#### What the adapter developer does NOT touch

This is the point of the protocol design. Adding a new SIEM adapter requires **zero changes** to:

| File | Why untouched |
|------|--------------|
| `siem_proxy.py` | Already calls `get_active_adapter()` after Phase 7 |
| `benchmark/routes.py` | Already calls `adapter.get_agent_sca()` etc. after Phase 7 |
| `host_service.py` | Already calls `adapter.get_agents()` after Phase 7 |
| `InternalExposureDashboard.jsx` | Reads adapter name from `/api/siem/adapter/status` dynamically |
| `CompSIEMSourcesTab` in Settings | Already accepts any `siem_type` string in the form |
| `cy_comp_siem_connections` schema | `siem_type` is a free-text column — no migration needed |
| Any correlation rule or UEBA detector | They read from normalised DB tables, not from the adapter |

The only mandatory discipline: if the new SIEM does not support a capability (e.g. Splunk
has no direct SCA equivalent), omit it from `get_capabilities()`. Callers in
`benchmark/routes.py` already gate on `"sca" not in adapter.get_capabilities()` and return
`0.0` for that subscore cleanly rather than erroring.

#### Capability-to-subscore mapping (for benchmark completeness)

| `get_capabilities()` entry | Which benchmark subscore uses it | Fallback when absent |
|---|---|---|
| `"agents"` | Active agent count subscore | Returns `0` |
| `"sca"` | SCA policy pass-rate subscore | Returns `0` |
| `"vulnerabilities"` | Vulnerability subscore | Returns `0` |
| `"packages"` | Software inventory (ITAM enrichment) | Skipped silently |
| `"process_tree"` | Phase 3 evidence collection | Gap marked MISSING in evidence log |
| `"dns_history"` | Phase 3 evidence collection | Gap marked MISSING in evidence log |

---

## 6. Modified Files — Detailed Specification

### 6.1 `backend/blueprints/comp/routes.py`

**Fix credential writing in `create_siem_connection()` and `update_siem_connection()`:**

Currently, the `POST` and `PUT` handlers accept `password_enc` and `api_key_enc` field names
in the request body but do NOT write them. The fix:
- Accept `password` and `api_key` as plaintext from the request body
- Encrypt via `kv_secrets.encrypt_value(value)` before writing to `password_enc` / `api_key_enc`
- Never return plaintext credentials in GET response (return `"•STORED•"` sentinel like ITAM)

**New routes to add to comp_bp:**

| Route | Method | RBAC | Purpose |
|-------|--------|------|---------|
| `/settings/siem-connections/<id>/test` | POST | analyst+ | Instantiate adapter with stored creds, call `test_connection()`, write `last_tested` + `last_test_ok`, return result |
| `/settings/siem-connections/<id>/test` | OPTIONS | — | CORS preflight |
| `/settings/siem-connections/<id>/activate` | POST | admin | Set `is_active=TRUE` for this ID, `is_active=FALSE` for all others; invalidate adapter cache |
| `/settings/siem-connections/<id>/activate` | OPTIONS | — | CORS preflight |

### 6.2 `backend/siem_proxy.py`

**Replace inline Wazuh calls — 7 call sites:**

| Call site (current) | Replacement |
|---------------------|-------------|
| `_wazuh_auth_token()` global function (~line 1793) | Remove; route callers to `get_active_adapter().get_auth_token()` |
| `_wz(path, ...)` global function (~line 1819) | Remove; move to WazuhAdapter._request() |
| `_refresh_host_cache_sync()` Wazuh agent/SCA/vuln block | `adapter = get_active_adapter()` at top; use `adapter.get_agents()`, `adapter.get_agent_sca()`, `adapter.get_agent_vulnerabilities()`, `adapter.get_agent_packages()` |
| Evidence collector routes process-tree line ~2935 | `adapter.get_process_tree(agent_id, pid)` |
| Evidence collector routes DNS history line ~2959 | `adapter.get_dns_history(agent_id)` |
| Evidence collector routes SCA checks line ~2981 | `adapter.get_agent_sca(agent_id)` |
| Evidence collector routes packages line ~3003 | `adapter.get_agent_packages(agent_id)` |
| Evidence collector routes vuln detail line ~3024 | `adapter.get_agent_vulnerabilities(agent_id)` |

**`siem_wazuh_launch()` route (line ~636):**
Rename to `siem_siem_launch()`. Only set `siem_launch_url` when `adapter.siem_type == "wazuh"`.
For other adapter types, return a redirect URL based on the connection's `host` field.

**New route: `GET /api/siem/adapter/status`** (viewer+)
```json
{
  "siem_type": "wazuh",
  "name": "Wazuh (from config)",
  "source": "db",          // "db" | "env" | "null"
  "is_connected": true,
  "capabilities": ["sca", "vulnerabilities", "packages", "process_tree", "dns_history", "agents"],
  "last_tested": "2026-07-08T14:30:00Z",
  "last_test_ok": true
}
```
Route also needs OPTIONS handler.

**`WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASS` module-level vars (lines 34–36):**
Keep as-is for backward compatibility. They are read by `get_active_adapter()` env fallback.
Remove only from the inline call sites that are being replaced.

### 6.3 `backend/blueprints/benchmark/routes.py`

**Replace `_wazuh_auth_token()` + `_wazuh_get()` pattern (~lines 642–672) with adapter:**

```python
from siem_adapters import get_active_adapter

def _collect_vuln_subscore():
    adapter = get_active_adapter()
    if "vulnerabilities" not in adapter.get_capabilities():
        return 0.0  # capability not available; skip subscore
    agents = adapter.get_agents()
    ...
    vuln_data = adapter.get_agent_vulnerabilities(agent_id)
    ...

def _collect_sca_subscore():
    adapter = get_active_adapter()
    if "sca" not in adapter.get_capabilities():
        return 0.0
    sca_data = adapter.get_agent_sca(agent_id)
    ...
```

**Impact on Internal Exposure:**  
The Detection Posture Score widget in `InternalExposureDashboard.jsx` calls
`/api/benchmark/score`. After this change, the benchmark SCA and vulnerability subscores
flow through the active adapter — not directly to Wazuh. The widget receives the same
response shape; no frontend change to the widget itself is needed.

### 6.4 `backend/cysiemstack/host_service.py`

Replace `_wazuh_token()` (~line 1, helper function) and `_fetch_wazuh_agents()` with:

```python
from siem_adapters import get_active_adapter

def _fetch_agents():
    return get_active_adapter().get_agents()
```

The callers of `_fetch_wazuh_agents()` receive the same dict structure — WazuhAdapter's
`get_agents()` returns Wazuh's native format, so existing callers are unaffected.

### 6.5 `portal/src/pages/settings/SystemSettingsPage.jsx` — `CompSIEMSourcesTab`

**Add to the "Add SIEM Source" form:**
- Password field (type=password, never pre-filled)
- API Key field (type=password, optional — for Splunk/Elastic token-based auth)

**On each connection card, add three controls:**

1. **Active badge**: "● ACTIVE" green chip if `is_active === true`
2. **Set Active button** (admin only): `POST /api/comp/settings/siem-connections/${id}/activate`
   - Only show when `is_active === false`
   - Reloads connection list on success
3. **Test Connection button** (analyst+): `POST /api/comp/settings/siem-connections/${id}/test`
   - Shows inline result: green "Connected — Wazuh v4.8.1 · 12 agents" or red "Failed: timeout"
   - Updates `last_test_ok` and `last_tested` display on card

**Connection card information to display:**
```
[● ACTIVE / ○ INACTIVE]  Wazuh Production
wazuh — 127.0.0.1:55000  |  Tested: 2026-07-08 14:30  ✓ OK
[Test Connection]  [Set Active]  [Remove]
```

**Header note (informational, non-blocking):**
```
The active SIEM source supplies host telemetry, SCA scores, and vulnerability data to the 
Internal Exposure dashboard and Benchmark scoring. Only one source can be active at a time.
```

### 6.6 `portal/src/siem/InternalExposureDashboard.jsx`

**Two additive changes (no existing functionality removed):**

**Change 1 — Active adapter badge in the page header:**
Fetch `GET /api/siem/adapter/status` on mount (best-effort, non-blocking).
Add a small badge next to the existing "INTERNAL" chip:

```jsx
// Current header chips:
<span>[INTERNAL]</span>

// After Phase 7:
<span>[INTERNAL]</span>
{adapterStatus && (
  <span style={{ /* amber/grey monospace chip */ }}>
    {adapterStatus.siem_type.toUpperCase()} ADAPTER
    {!adapterStatus.is_connected && " · DISCONNECTED"}
  </span>
)}
```

Behavior:
- Connected: `WAZUH ADAPTER` (no extra decoration)
- Disconnected: `WAZUH ADAPTER · DISCONNECTED` (amber)
- Adapter fetch failed: badge absent (no error shown)

**Change 2 — Footer text update:**
```jsx
// Current:
"Dashboard refreshes every 60 s · Data sourced from CySIEM Correlation Engine · UEBA Baseline Engine · Entity Risk Scorer"

// After Phase 7:
`Dashboard refreshes every 60 s · Data sourced from CySIEM Correlation Engine via ${adapterName} · UEBA Baseline Engine · Entity Risk Scorer`
```
Where `adapterName` is `adapterStatus?.name || "CySIEM"` (fallback keeps existing text on fetch failure).

---

## 7. What Stays Identical (Zero-Change Guarantee)

| Component | Why unchanged |
|-----------|--------------|
| `normaliser.py` | Not in scope; alert ingestion coupling is a separate initiative |
| All 55 correlation rules | Not in scope |
| UEBA detectors / `ueba.py` | Not in scope |
| `host_posture_cache` table schema | No schema change; data populates through adapter |
| `InternalExposureDashboard` incident/risk/UEBA charts | These already read from normalised correlation DB tables |
| `SiemEngineStatus.jsx` | Checks correlation engine health (`/api/siem/health`), not Wazuh — already adapter-agnostic |
| `cysoar_connector.py` | SOAR dispatch unaffected |
| All auth / RBAC / OIDC routes | No changes |
| All EDR routes and agent | Not in scope |
| All ITAM routes | Not in scope |
| All existing env vars | Remain as fallback; no operator migration needed |
| `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD` in `.env` | Still read; become the env fallback path in `get_active_adapter()` |

---

## 8. Encryption Strategy for Stored Credentials

Use the existing `kv_secrets.py` infrastructure:

```python
from core.kv_secrets import encrypt_value, decrypt_value

# On POST/PUT siem-connections:
password_enc = encrypt_value(plaintext_password) if plaintext_password else existing_value

# On get_active_adapter() instantiation:
password = decrypt_value(row["password_enc"]) if row.get("password_enc") else ""
```

`encrypt_value()` / `decrypt_value()` already exist in `kv_secrets.py` for ITAM credential
storage. If the function is not yet generic, extend it alongside ITAM's pattern.

GET response for existing password: return `"•STORED•"` sentinel (same as ITAM).
PUT with `"•STORED•"` or empty string: leave stored value unchanged.

---

## 9. Backward Compatibility Matrix

| Deployment State | Phase 7 Behavior |
|-----------------|-----------------|
| Existing deployment — env vars set, no DB connection | Auto-seed migration inserts Wazuh row → adapter resolves from DB → behavior identical |
| New deployment — no env vars, user adds Wazuh via UI | User adds connection in Settings > SIEM Sources → activates it → adapter picks up |
| Mixed — env vars set AND DB connection exists | DB connection takes priority (DB is order 1 in resolution); env vars still valid as manual fallback |
| No env vars, no DB connection | NullAdapter — host posture returns empty; benchmark SCA/vuln subscores return 0; other features unaffected |
| Future — Splunk added via UI, activated | WazuhAdapter deconfigured; `SplunkAdapter` (stub returning capability list + empty data) instantiated |

---

## 10. New API Routes Summary

| Route | Method | RBAC | Blueprint | Status |
|-------|--------|------|-----------|--------|
| `GET /api/siem/adapter/status` | GET | viewer+ | siem_bp (siem_proxy.py) | New |
| `GET /api/siem/adapter/status` | OPTIONS | — | siem_bp | New |
| `POST /api/comp/settings/siem-connections/<id>/test` | POST | analyst+ | comp_bp | New |
| `POST /api/comp/settings/siem-connections/<id>/test` | OPTIONS | — | comp_bp | New |
| `POST /api/comp/settings/siem-connections/<id>/activate` | POST | admin | comp_bp | New |
| `POST /api/comp/settings/siem-connections/<id>/activate` | OPTIONS | — | comp_bp | New |

All existing routes remain unchanged in path, method, and response schema.

---

## 11. Execution Steps (Ordered)

### Step 7.1 — Adapter Infrastructure (Backend, no behavior change)

**Deliverable:** `siem_adapters/` package created and importable.  
`WazuhAdapter` passes all existing Wazuh calls through identically. `get_active_adapter()`
resolves to `WazuhAdapter` from env fallback for all existing deployments. No other files changed.  
**Test:** `python -c "from siem_adapters import get_active_adapter; print(get_active_adapter())"` succeeds.  
**Risk:** Zero — no existing code changed.

---

### Step 7.2 — DB Schema + Credential Encryption + Auto-seed (Backend)

**Deliverable:** `cy_comp/models.py` adds 3 columns + auto-seed migration. `comp/routes.py`
writes `password_enc`/`api_key_enc`. GET returns `"•STORED•"` sentinel.  
**Test:** Add a Wazuh connection via Settings UI → confirm password is NOT returned in GET response.  
Run DB inspection: `SELECT id, name, is_active, password_enc IS NOT NULL FROM cy_comp_siem_connections;`  
**Risk:** Low — additive ALTER TABLE only.

---

### Step 7.3 — siem_proxy.py Refactor (Backend)

**Deliverable:** `_refresh_host_cache_sync()` uses adapter. Evidence collector routes use adapter.
`GET /api/siem/adapter/status` route added. `_wazuh_auth_token()` and `_wz()` global
functions removed from module scope (moved into `WazuhAdapter`).  
**Test (critical path):**
- Host Posture tab still shows agent list — confirms `get_agents()` via adapter works
- SCA scores still populate — confirms `get_agent_sca()` works
- Vulnerability counts still appear — confirms `get_agent_vulnerabilities()` works
- `GET /api/siem/adapter/status` returns `{siem_type: "wazuh", is_connected: true}`  
**Risk:** High — central proxy file. Must run full regression on this step.

---

### Step 7.4 — benchmark/routes.py + host_service.py Refactor (Backend)

**Deliverable:** Benchmark SCA and vulnerability subscores route through adapter.
`host_service.py` host fetch routes through adapter.  
**Test:**
- `GET /api/benchmark/score` returns same breakdown as before
- Detection Posture Score widget in Internal Exposure loads correctly  
**Risk:** Medium — benchmark scoring is complex; verify subscore calculation is identical.

---

### Step 7.5 — Add /activate + /test Routes (Backend)

**Deliverable:** `POST /api/comp/settings/siem-connections/<id>/test` and `/activate` routes
added with RBAC + OPTIONS handlers. Adapter cache invalidated on activate.  
**Test:**
- POST test → returns `{ok: true, latency_ms: 45, details: {...}}`
- POST activate → confirms `is_active` flipped in DB; subsequent `GET /api/siem/adapter/status`
  returns the newly activated connection  
**Risk:** Low — additive new routes.

---

### Step 7.6 — Settings UI Enhancement (Frontend)

**Deliverable:** `CompSIEMSourcesTab` shows password/API-key fields, Active badge,
"Set Active" and "Test Connection" buttons, health dot per card.  
**Test (UI):**
- Add Wazuh connection with password → confirm "•STORED•" shown on next load
- Test Connection button shows inline result
- Set Active button sets the active connection; page reloads showing green "ACTIVE" badge
- Existing connection management (add/remove) still works  
**Risk:** Low — UI only; backend routes validated in Step 7.5.

---

### Step 7.7 — Internal Exposure Adapter Awareness (Frontend)

**Deliverable:** `InternalExposureDashboard.jsx` shows adapter badge in header and
adapter name in footer.  
**Test (UI):**
- Internal Exposure page shows "WAZUH ADAPTER" chip next to "INTERNAL" badge
- Footer reads "CySIEM Correlation Engine via Wazuh · UEBA…"
- If adapter fetch fails: badge absent, footer fallback text shows — no error  
**Risk:** Zero — additive UI only; all existing data sources and refresh logic unchanged.

---

### Step 7.8 — Regression Testing (Full Suite)

Before marking Phase 7 complete, verify all of the following still work identically:

| Feature | Test Method |
|---------|-------------|
| Host Posture tab — agent list | Navigate to Host Intelligence → Hosts tab |
| Host Posture tab — SCA score per agent | Click any agent → SCA tab |
| Vulnerability data | Click any agent → Vulnerabilities tab |
| Benchmark score | Navigate to Benchmark page → confirm all 5 subscores present |
| Internal Exposure — Detection Posture Score widget | Confirm non-zero score in header widget |
| Internal Exposure — incident/UEBA/risk charts | Confirm data populates (correlation DB, unchanged) |
| Evidence Collection tab in incident detail (Phase 3) | Trigger evidence collector; confirm COLLECTED status |
| SIEM Sources UI | Add, test, activate, remove a connection |
| Adapter status API | `GET /api/siem/adapter/status` returns correct source |

---

## 12. Regression Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| `get_active_adapter()` returns `NullAdapter` on existing deployment | Low | Auto-seed migration handles this |
| WazuhAdapter request timeout differs from inline `_wz()` | Medium | Use identical timeout values in WazuhAdapter (copy from siem_proxy.py line ~1445) |
| Adapter cache stale after `activate` | Medium | Cache invalidation call in the activate route |
| `siem_proxy.py` import of `siem_adapters` causes circular import | Low | `siem_adapters` has no imports from `blueprints/`; import only `get_active_adapter` |
| `kv_secrets.encrypt_value()` not generic | Low | Verify it exists in `kv_secrets.py`; if not, implement alongside ITAM pattern |
| benchmark/routes.py capability check returns 0 for SCA | Only if NullAdapter active | Log a warning; UI shows 0 for that subscore with a "Wazuh unreachable" callout |

---

## 13. UI Verification Checklist

- [ ] Settings > Security Compliance > SIEM Sources: Add form has Password and API Key fields
- [ ] Password field returns `"•STORED•"` on page reload (not plaintext)
- [ ] "Test Connection" button shows inline result (green or red) within 5 seconds
- [ ] "Set Active" button makes the selected connection show "● ACTIVE" badge
- [ ] Only one connection shows "● ACTIVE" at any time
- [ ] After activating a new connection, `GET /api/siem/adapter/status` returns the new adapter
- [ ] Internal Exposure page shows "WAZUH ADAPTER" badge next to "INTERNAL"
- [ ] Badge is absent (not broken) if adapter status API call fails
- [ ] Footer shows "CySIEM Correlation Engine via Wazuh" when Wazuh is active adapter
- [ ] Detection Posture Score widget still loads (benchmark still functional via adapter)
- [ ] All existing incident/risk/UEBA/kill-chain charts continue to load normally
- [ ] Host Posture agent list loads correctly
- [ ] SCA scores load on agent detail page
- [ ] Vulnerability data loads on agent detail page
- [ ] `GET /api/siem/adapter/status` returns `200` with correct fields

---

## 14. New Env Vars

**None.** All existing env vars remain unchanged and retain their role as the env fallback
path in `get_active_adapter()`.

---

## 15. RBAC Summary

| Route | GET | POST/PUT | DELETE |
|-------|-----|----------|--------|
| `/api/siem/adapter/status` | viewer+ | — | — |
| `/api/comp/settings/siem-connections` | analyst+ | admin | — |
| `/api/comp/settings/siem-connections/<id>` | analyst+ | admin | admin |
| `/api/comp/settings/siem-connections/<id>/test` | — | analyst+ | — |
| `/api/comp/settings/siem-connections/<id>/activate` | — | admin | — |

---

## 16. Archive After Phase 7

| Code | Location | Action |
|------|----------|--------|
| `_wazuh_auth_token()` global function | `siem_proxy.py` | Remove (replaced by `WazuhAdapter.get_auth_token()`) |
| `_wz()` global function | `siem_proxy.py` | Remove (replaced by `WazuhAdapter._request()`) |
| `_WAZUH_ADMIN_BASIC`, `_WAZUH_RO_BASIC` constants | `siem_proxy.py` | Remove (moved to WazuhAdapter) |
| `_wazuh_auth_token()` + `_wazuh_get()` in benchmark | `benchmark/routes.py` | Remove |
| `_wazuh_token()`, `_fetch_wazuh_agents()` | `host_service.py` | Remove |

Module-level `WAZUH_API_URL` / `WAZUH_API_USER` / `WAZUH_API_PASS` in `siem_proxy.py`
remain for now (read by `get_active_adapter()` env fallback via import from `core/config.py`).

---

## 17. Agents to Notify on Approval

- **@g-cyra-siem** — host posture, UEBA, correlation engine unaffected but siem_proxy.py changes touch their domain
- **@g-cyra-devops** — no infra changes; notify for awareness of new `siem_adapters/` package in deploy path
- **@g-cyra-test** — this phase requires a full regression run (Step 7.8); update test inventory

---

## 18. Open Questions (Resolve Before Implementation Begins)

1. **`kv_secrets.encrypt_value()` / `decrypt_value()`** — Do these generic functions exist in
   `kv_secrets.py`, or does only the ITAM-specific pattern exist? If the latter, we implement
   a generic helper alongside Step 7.2.

2. **Adapter cache TTL** — Is 5 minutes acceptable for the `get_active_adapter()` singleton TTL,
   or should it be shorter? Short TTL = more DB hits; long TTL = slower activation propagation.
   Recommended: 5 minutes with explicit invalidation on `/activate`.

3. **SplunkAdapter / ElasticAdapter stubs** — Phase 7 plan declares stub classes that satisfy
   the SIEMAdapter Protocol but return empty data (with a log warning). Confirm this is the
   right approach, or should they raise `NotImplementedError` instead?

4. **Wazuh SSO launch route** — After Phase 7, `GET /api/siem/wazuh-launch` should only be
   accessible when the Wazuh adapter is active. Confirm: should the route return `404` when
   a non-Wazuh adapter is active, or redirect to the configured SIEM's own UI URL?

---

*This document is a plan only. No code has been written. Implementation begins only after
explicit approval of this plan by the product owner.*
