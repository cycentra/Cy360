# CyTIM Centralization & Dark Web Endpoint — Change Log
**Date:** 2026-07-05  
**Scope:** CyTIM v1.2.4 + Cy360 backend  
**Type:** Architecture / Integration

---

## Summary

This change eliminates scattered, per-module TI source calls across Cy360 and replaces them with a single centralized gateway. All modules (ASM, SIEM, GRC, Cases, dark web) now check one place to determine whether TI enrichment is enabled. A dedicated dark web endpoint has been added to CyTIM, controlled by a toggle in the admin UI that gates the dark web scan across all modules.

---

## Problem Statements Addressed

| # | Problem | Resolution |
|---|---------|------------|
| 1 | ASM `cycentra_scan.py` called MISP directly (bypassing CyTIM) | Replaced with `cytim_bulk_enrich(profile="asm")` gateway call |
| 2 | `passive_osint.py` called Shodan and MISP directly | Routes through `cytim_bulk_enrich(profile="asm")` when CyTIM enabled |
| 3 | No centralized CyTIM on/off switch for Cy360 | Added `CYTIM_ENABLED` env var + `is_cytim_enabled()` gateway function |
| 4 | Dark web enrichment had no dedicated endpoint or toggle | Added `POST /api/cytim/darkweb-enrich`, `GET /api/cytim/darkweb-status`, and toggle in admin UI |
| 5 | Dark web module ran unconditionally regardless of TI config | `gather_dark_web()` now gate-checks `is_darkweb_enabled()` before running |
| 6 | Bulk enrichment queried all 7 sources for every call | Added `profile` param — ASM and SIEM profiles query only relevant sources, preserving rate limits |
| 7 | No persistent runtime toggle for dark web on/off | Added `cytim_settings` DB table; toggle persists across CyTIM restarts |

---

## Architecture After This Change

```
Cy360 Modules                    CyTIM Broker
──────────────────────────────   ────────────────────────────────────────

ASM (cycentra_scan.py)    ──┐
ASM (passive_osint.py)    ──┤    POST /api/cytim/bulk-enrich
SIEM (cytim_enricher.py)  ──┼──► { iocs: [...], profile: "asm"|"siem" }
GRC (enrichment.py)       ──┤         │
Cases                     ──┘         └── registry.enrich_all(profile)
                                           ├── MISP
ASM (dark_web.py)         ─────► GET /api/cytim/darkweb-status (gate-check)
                                      │
                          ─────► POST /api/cytim/darkweb-enrich
                                      └── (enterprise DW source when added)

All modules              ──────► is_cytim_enabled()  ← helpers.py gateway
                                 is_darkweb_enabled() ← darkweb-status endpoint
```

**Single control point:** Set `CYTIM_ENABLED=false` in `/opt/cycentra/.env` → all modules fall back to direct calls or skip TI enrichment. No per-module config changes needed.

---

## Files Changed

### CyTIM (`cytim/`)

| File | Change |
|------|--------|
| `cytim/db.py` | Added `cytim_settings` table (idempotent); `get_setting()`, `set_setting()` helpers |
| `cytim/config.py` | Added `CYTIM_DARKWEB_ENABLED` env var (boot default for dark web toggle) |
| `cytim/sources/registry.py` | Added `_PROFILE_SOURCES` dict; `enrich_all()` now accepts `profile` param |
| `cytim/api/enrich.py` | `POST /bulk-enrich` accepts `profile` field; validates against `VALID_PROFILES` |
| `cytim/api/darkweb.py` | **NEW** — `GET /api/cytim/darkweb-status` (no auth), `POST /api/cytim/darkweb-enrich` (API key) |
| `cytim/api/admin.py` | Added `GET/POST /api/cytim/admin/settings`; `/health` now includes `darkweb_enabled` |
| `cytim/app.py` | Registers `darkweb_bp` |
| `cytim/static/index.html` | Dark web toggle card in Sources tab (toggle reads/writes admin/settings) |
| `cytim.env.example` | Added `CYTIM_DARKWEB_ENABLED=true` with documentation |

### Cy360 (`Cy360/backend/`)

| File | Change |
|------|--------|
| `core/config.py` | Added `CYTIM_ENABLED` env var (master on/off; default `true`) |
| `core/helpers.py` | Added 4 gateway functions: `is_cytim_enabled()`, `cytim_bulk_enrich()`, `cytim_darkweb_enrich()`, `is_darkweb_enabled()` |
| `cy_asm/cycentra_scan.py` | TI IOC block (line ~1122): routes through `cytim_bulk_enrich(profile="asm")`; MISP direct call is fallback only |
| `cy_asm/modules/dark_web.py` | `gather_dark_web()` gate-checks `is_darkweb_enabled()` at start; returns `{skipped: "dark_web_enrichment_disabled"}` if off |
| `cy_asm/modules/passive_osint.py` | `gather_passive_osint()` routes domain TI through CyTIM when enabled; direct MISP+Shodan only as fallback |

---

## New API Endpoints (CyTIM)

### `GET /api/cytim/darkweb-status`
No authentication required. Called by any Cy360 module before running dark web scans.

```json
{
  "enabled": true,
  "sources_active": [],
  "coverage": "limited",
  "note": "Dark web enrichment is active (Ahmia/HIBP clearnet proxies only). Add RecordedFuture, DarkOwl, or Flashpoint for full dark web indexing."
}
```

### `POST /api/cytim/darkweb-enrich`
Requires `X-CyTIM-Key`. Body: `{"iocs": [{"type": "domain", "value": "example.com"}]}`

```json
{
  "enabled": true,
  "results": [
    {
      "ioc_type": "domain",
      "ioc_value": "example.com",
      "coverage": "none",
      "score": 0,
      "findings": [],
      "note": "No dark web sources configured. Add RecordedFuture, DarkOwl, or Flashpoint for coverage."
    }
  ]
}
```
Returns `{"enabled": false}` immediately when dark web toggle is off.

### `GET /api/cytim/admin/settings`
Requires `X-CyTIM-Admin-Secret`.
```json
{"settings": {"darkweb_enabled": "true"}}
```

### `POST /api/cytim/admin/settings`
Requires `X-CyTIM-Admin-Secret`. Body: `{"darkweb_enabled": "false"}`
```json
{"updated": {"darkweb_enabled": "false"}}
```

### Updated: `POST /api/cytim/bulk-enrich`
Now accepts optional `profile` field:
```json
{
  "iocs": [{"type": "ip", "value": "1.2.3.4"}],
  "profile": "asm"
}
```

---

## Source Profiles

| Profile | Sources Queried | Use Case |
|---------|----------------|----------|
| `default` | All registered (up to 7) | General enrichment |
| `asm` | shodan, virustotal, greynoise, misp, alienvault | ASM scans — exposure + community TI |
| `siem` | virustotal, abuseipdb, greynoise, misp, ciscotalos, alienvault | SIEM enrichment — reputation-focused |

**Rationale:** The `asm` profile drops AbuseIPDB (IP-only, limited value for domain/subdomain scanning) and CiscoTalos (commercial quota, prioritized for SIEM). The `siem` profile drops Shodan (exposure context not useful for alert enrichment). Profiles gate source queries only — the cache is source-keyed, not profile-keyed, so cached results are shared across profiles.

---

## Centralized Gateway (Cy360)

All Cy360 modules must use these functions from `core.helpers` — never call CyTIM directly:

```python
from core.helpers import (
    is_cytim_enabled,      # gate-check: returns bool
    cytim_bulk_enrich,     # IOC enrichment: returns {ioc_value → result_dict}
    cytim_darkweb_enrich,  # dark web: returns full response dict
    is_darkweb_enabled,    # dark web gate-check: returns bool
)

# Pattern for any module:
if is_cytim_enabled():
    results = cytim_bulk_enrich(ioc_list, profile="asm")
else:
    # existing direct-call fallback
```

### `cytim_bulk_enrich()` return shape

```python
{
    "1.2.3.4": {
        "ioc_type": "ip",
        "ioc_value": "1.2.3.4",
        "score": 72,
        "confidence": 0.87,
        "tags": ["malware", "c2"],
        "sources": {
            "virustotal": {"score": 85, "confidence": 0.95, ...},
            "greynoise":  {"score": 60, "confidence": 0.80, ...},
        },
        "cache_hit": true
    },
    ...
}
```

---

## Dark Web Toggle Behaviour

```
CyTIM Admin UI (Sources tab)
  └── Dark Web Enrichment toggle
        │
        ├── ON  → POST /api/cytim/admin/settings {"darkweb_enabled": "true"}
        │         → persisted in cytim_settings table
        │         → darkweb-status returns {"enabled": true}
        │         → gather_dark_web() proceeds (Ahmia + HIBP)
        │
        └── OFF → POST /api/cytim/admin/settings {"darkweb_enabled": "false"}
                  → darkweb-status returns {"enabled": false}
                  → gather_dark_web() returns {skipped: "dark_web_enrichment_disabled"}
                  → POST /darkweb-enrich returns {"enabled": false} immediately
```

The toggle defaults to `true` (enabled) from env var `CYTIM_DARKWEB_ENABLED`. The DB value takes precedence once set via UI. To disable at boot without UI access: `CYTIM_DARKWEB_ENABLED=false` in `cytim.env`.

---

## New Database Table (`cytim_settings`)

```sql
CREATE TABLE IF NOT EXISTS cytim_settings (
    key        VARCHAR(100) PRIMARY KEY,
    value      TEXT         NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ  DEFAULT NOW()
);
```

Created automatically by `ensure_tables()` on first startup. No manual migration needed.

**Current settings key:** `darkweb_enabled` — `"true"` or `"false"`.

---

## Subdomain Enumeration (NOT Changed — By Design)

`cy_asm/modules/subdomain_enum.py` VT, OTX, and MISP calls were assessed and intentionally left unchanged. These use different API endpoints for **asset discovery** (find subdomains), not IOC reputation scoring:
- `GET /api/v3/domains/{domain}/subdomains` — enumerate known subdomains in VT
- `GET /indicators/domain/{domain}/passive_dns` — OTX passive DNS
- MISP hostname attribute search

These are complementary to CyTIM enrichment and use a different API surface. Routing them through CyTIM would require adding enumeration capabilities to CyTIM, which is outside CyTIM's scope as a **reputation broker**.

---

## Deployment Steps Required

### 1. CyTIM — Release and Deploy

CyTIM must be released and deployed before Cy360 changes are activated.

```bash
# From local Mac
cd CyRepo/cytim
./scripts/git-push.sh          # bumps patch version, creates GitHub Release
                               # GitHub Actions builds and pushes new Docker image

# After image build completes (~5 min):
./scripts/server-deploy.sh     # SSH to CyMind server, git pull, docker compose up -d
```

**OR** use the Update App button in the CyTIM admin UI (Overview tab → Update App) after pushing code.

**After deploy, verify:**
```bash
curl http://204.168.193.23:7443/health
# Expect: {"status": "ok", ..., "darkweb_enabled": true}

curl http://204.168.193.23:7443/api/cytim/darkweb-status
# Expect: {"enabled": true, "coverage": "limited", ...}
```

### 2. Cy360 — Deploy Backend

```bash
# On the Cy360 server
ssh -p 2026 root@77.42.75.20

cd /path/to/Cy360   # or git pull if tracking remote
systemctl restart cycentra-backend.service
systemctl status cycentra-backend.service
```

### 3. Verify `.env` on Cy360 Server

Ensure `/opt/cycentra/.env` has the CyTIM connection **and** the new `CYTIM_ENABLED` flag:

```bash
# /opt/cycentra/.env
CYTIM_URL=http://204.168.193.23:7443
CYTIM_API_KEY=cytim-<your-key>
CYTIM_ENABLED=true          # ← new; defaults to true if absent
```

No restart needed if `CYTIM_ENABLED` is omitted — it defaults to `true`.

### 4. Commit Cy360 Changes

```bash
cd CyRepo/Cy360
git add backend/core/config.py \
        backend/core/helpers.py \
        backend/cy_asm/cycentra_scan.py \
        backend/cy_asm/modules/dark_web.py \
        backend/cy_asm/modules/passive_osint.py
git commit -m "feat: centralize CyTIM gateway; add dark web gate-check; ASM routes through CyTIM"
git push origin main
```

---

## Testing Checklist

### CyTIM Health

- [ ] `GET /health` returns `{"status": "ok", ..., "darkweb_enabled": true}`
- [ ] `GET /api/cytim/darkweb-status` returns `{"enabled": true, "coverage": "limited"}`
- [ ] `POST /api/cytim/bulk-enrich` with `{"iocs": [...], "profile": "asm"}` returns results
- [ ] `POST /api/cytim/bulk-enrich` with `{"iocs": [...], "profile": "siem"}` returns results
- [ ] `POST /api/cytim/darkweb-enrich` with valid IOC list returns `{"enabled": true, "results": [...]}`
- [ ] `GET /api/cytim/admin/settings` returns `{"settings": {"darkweb_enabled": "true"}}`
- [ ] `POST /api/cytim/admin/settings` with `{"darkweb_enabled": "false"}` persists across restart

### CyTIM Admin UI

- [ ] Sources tab loads without JS errors
- [ ] Dark web toggle card visible at bottom of Sources tab
- [ ] Toggle off → label shows "Disabled" (red)
- [ ] Toggle on → label shows "Enabled" (green)
- [ ] Toggle state persists after page reload

### ASM Integration

- [ ] Run a standard ASM scan — logs show `[CyTIM/ASM]` instead of `[MISP]` for IOC lookup
- [ ] Run a scan against a domain with known IPs — `misp_hit_map` populated from CyTIM results
- [ ] Set `CYTIM_ENABLED=false` → scan falls back to direct MISP call (log shows `[MISP]`)
- [ ] passive_osint returns CyTIM enrichment result for domain TI

### Dark Web Gate-Check

- [ ] With dark web toggle ON: ASM scan proceeds with Ahmia + HIBP dark web module
- [ ] With dark web toggle OFF: `gather_dark_web()` returns `{skipped: "dark_web_enrichment_disabled"}`, scan completes without error
- [ ] ASM scan report still generates correctly when dark web is skipped

### Fallback Behaviour

- [ ] With `CYTIM_URL` blank: `is_cytim_enabled()` returns `False`; direct MISP fallback used
- [ ] With CyTIM unreachable: `cytim_bulk_enrich()` returns `{}`; scan completes (never blocks)
- [ ] With `is_darkweb_enabled()` failing (CyTIM unreachable): returns `False`; dark web skipped silently

---

## Future Work

| Item | Priority | Notes |
|------|----------|-------|
| Add RecordedFuture source to CyTIM | High | Enables real dark web IOC coverage; requires enterprise licence |
| Add DarkOwl source to CyTIM | High | Dedicated dark web indexer; REST API available |
| Expose `cytim_darkweb_enrich()` from Cases module | Medium | Enrich case IOCs with dark web findings |
| Add `darkweb` profile to `_PROFILE_SOURCES` | Low | After first DW source is added; currently no DW-specific sources exist |
| GRC compliance enrichment via CyTIM | Low | `cy_comp/services/enrichment.py` still calls legacy paths |

---

*Generated by CyCentra Engineering — 2026-07-05*
