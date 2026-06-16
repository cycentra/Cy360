# Marketplace — Configuration Reference & Agent Packages Extension Plan

## Part 1 — How the Marketplace Is Configured Today

### Architecture (3-tier, cloud-pull)

```
CyAdmin (internal, localhost:7070)
  ├─ Manages working catalog: CyAdmin/data/catalog.json
  ├─ Publish button → writes to cycentra.com/public/marketplace/catalog.json
  └─ git-push.sh → CI deploys live

cycentra.com (nginx, static)
  └─ /marketplace/catalog.json
       Token-gated via X-CyCentra-Token header
       CORS locked to ${FRONTEND_URL}

CyCentra 360 Flask backend
  └─ GET /api/marketplace/catalog
       _fetch_cloud_catalog() → sends X-CyCentra-Token server-side
       Merges cloud items + per-server custom items
       Never exposes cycentra.com URL to the browser

CyCentra 360 Portal (React)
  └─ MarketplacePage.jsx
       Fetches /api/marketplace/catalog (session required)
       Renders catalog grid, config modals, Platform Extensions section
```

**Key principle:** the browser never calls CyAdmin or cycentra.com directly. All catalog traffic is proxied through the Flask backend.

---

### Token Gating — Two Layers

**Layer 1 — cycentra.com nginx** (`CyCentra.com/nginx.conf.template:24-30`):

```nginx
set $ct_required "${MARKETPLACE_CATALOG_TOKEN}";
set $ct_fail 0;
if ($ct_required != "") { set $ct_fail 1; }
if ($http_x_cycentra_token = "${MARKETPLACE_CATALOG_TOKEN}") { set $ct_fail 0; }
if ($ct_fail = 1) { return 403; }
```

- Flask sends `X-CyCentra-Token` server-side on every catalog fetch.
- `MARKETPLACE_CATALOG_TOKEN` empty on both sides = open access (backwards compat).
- CORS is locked to `${FRONTEND_URL}` — browser cross-origin access is blocked regardless.

**Layer 2 — Portal session auth** (`blueprints/marketplace/routes.py:61-74`):

- All `/api/marketplace/*` endpoints call `_require_auth()` → 401 if no session.
- Pull / configure / remove call `_require_admin()` → 403 if not `admin` role.
- The portal itself is only reachable after Google/Microsoft OAuth login.

---

### Key File Locations

| File | Role |
|------|------|
| `CyCentra.com/public/marketplace/catalog.json` | Live static catalog served by nginx |
| `CyCentra.com/nginx.conf.template` | Token gate + CORS for `/marketplace/` |
| `Cy360/backend/blueprints/marketplace/routes.py` | All catalog / install / custom-item Flask routes |
| `Cy360/portal/src/pages/marketplace/MarketplacePage.jsx` | React UI — catalog grid, modals, Platform Extensions |
| `Cy360/backend/core/config.py:167-171` | `MARKETPLACE_CATALOG_TOKEN`, `MARKETPLACE_CATALOG_URL` |
| `CyAdmin/data/catalog.json` | Working copy — all edits happen here via CyAdmin UI |
| `/opt/cycentra/marketplace_custom.json` | Per-server custom catalog items |
| `/var/ossec/etc/cycentra_marketplace.json` | Per-server install state |

---

### catalog.json Item Schema

```json
{
  "version": "1.0",
  "updated": "ISO-8601",
  "items": [{
    "id":               "kebab-case (immutable once published)",
    "name":             "Display name",
    "type":             "integration | playbook",
    "category":         "Cloud | Active Response | etc.",
    "vendor":           "CyCentra",
    "icon":             "emoji",
    "color":            "#hex",
    "description":      "...",
    "modules_required": ["CySIEM", "CySOAR", "CyIRIS"],
    "estimated_time":   "~N min",
    "tags":             ["lowercase"],
    "config_type":      "o365 | gcloud | github | null",
    "cysoar_flow":      "file.py",
    "steps":            ["step 1", "..."]
  }]
}
```

`config_type` is set only for integrations that have a dedicated configuration modal (O365, GCloud, GitHub). Omit for items needing no guided setup.

---

### Backend Route Summary

| Method | Route | Auth |
|--------|-------|------|
| GET | `/api/marketplace/catalog` | Session required |
| POST | `/api/marketplace/catalog/custom` | Admin |
| PUT | `/api/marketplace/catalog/custom/<id>` | Admin |
| DELETE | `/api/marketplace/catalog/custom/<id>` | Admin |
| POST | `/api/marketplace/catalog/custom/<id>/submit` | Admin |
| POST | `/api/marketplace/catalog/custom/<id>/approve` | CyCentra admin only |
| POST | `/api/marketplace/catalog/custom/<id>/reject` | CyCentra admin only |
| GET | `/api/marketplace/submissions` | CyCentra admin only |
| GET | `/api/marketplace/installed` | Session required |
| POST | `/api/marketplace/install` | Admin |
| DELETE | `/api/marketplace/install/<item_id>` | Admin |

---

### Portal Page Structure (MarketplacePage.jsx)

```
MarketplacePage
  ├─ Header — title, item count badge, "Contribute" button (admin only)
  ├─ ReviewQueueSection — approve/reject submissions (CyCentra admin only)
  ├─ Search bar + type filter tabs (All / Integrations / Playbooks)
  ├─ Cloud status banner (shown when cycentra.com is unreachable)
  ├─ "Installed on this Server" grid — MarketplaceCard × n
  ├─ "Available from Cloud" grid — MarketplaceCard × n
  ├─ CySOAR Playbooks info box (when playbooks are visible)
  ├─ Config modals: O365ConfigModal | GCloudConfigModal | GitHubConfigModal
  ├─ Detail modal: PlaybookModal
  └─ CatalogItemFormModal (admin: create / edit custom items)

AddonModulesSection (rendered separately — not catalog items)
  └─ PLATFORM_MODULES with tier === "addon" (e.g. CySOAR)
       Uses /api/platform/install and /api/platform/status, not marketplace routes
```

---

### Role Matrix

| Action | Required |
|--------|---------|
| Browse catalog | Any authenticated session |
| Pull / configure / remove integration | `admin` role |
| Create / edit per-server custom item | `admin` role |
| Submit item for cloud review | `admin` role |
| Approve / reject submitted items | `CYCENTRA_ADMIN_EMAIL` account |

---

---

## Part 2 — Extension Plan: Agent Install Packages *(Planned — Not Yet Implemented)*

> **Status:** The features described in Part 2 are a planned extension. None of the routes, components, or catalog files listed below currently exist in the codebase. Do not treat this section as current documentation — it is a design specification for future implementation.



Add a new `agents` catalog on cycentra.com served under the **same token gate** as the marketplace, and a new **"Agent Packages" tab** inside `MarketplacePage.jsx`. No new token, no new auth concept — the existing session + `MARKETPLACE_CATALOG_TOKEN` covers everything.

### What Changes — Summary

| Layer | Change |
|-------|--------|
| `cycentra.com` static | New `/agents/catalog.json` + nginx location block |
| `cycentra.com` nginx | Copy `/marketplace/` block, change path to `/agents/` |
| `CyAdmin` | New "Agents" tab to manage the agents catalog + Publish writes second target |
| Flask backend | `AGENTS_CATALOG_URL` config var + `GET /api/marketplace/agents` route |
| Portal | New "Agent Packages" tab in `MarketplacePage.jsx` + `AgentCatalogSection` + `AgentCard` |

---

### Step 1 — cycentra.com: New Static Catalog + Nginx Block

**New file:** `CyCentra.com/public/agents/catalog.json`

Schema (packages, not config items):

```json
{
  "version": "1.0",
  "updated": "ISO-8601",
  "items": [{
    "id":               "wazuh-agent-linux-x64",
    "name":             "Wazuh Agent",
    "version":          "4.9.1",
    "platform":         "linux",
    "arch":             "x86_64",
    "category":         "SIEM Agent",
    "icon":             "🛡️",
    "color":            "#00e5a0",
    "description":      "...",
    "install_cmd":      "bash <(curl -s ...)",
    "checksum_sha256":  "abc123...",
    "modules_required": ["CySIEM"],
    "tags":             ["wazuh", "siem", "linux"],
    "added_at":         "ISO-8601"
  }]
}
```

**`CyCentra.com/nginx.conf.template`** — add a `/agents/` location block directly below the `/marketplace/` block. Copy it verbatim and change the path:

```nginx
location /agents/ {
    if ($request_method = OPTIONS) {
        add_header Access-Control-Allow-Origin "${FRONTEND_URL}";
        add_header Access-Control-Allow-Methods "GET, OPTIONS";
        add_header Access-Control-Allow-Headers "X-CyCentra-Token";
        return 204;
    }

    set $ct_required "${MARKETPLACE_CATALOG_TOKEN}";
    set $ct_fail 0;
    if ($ct_required != "") { set $ct_fail 1; }
    if ($http_x_cycentra_token = "${MARKETPLACE_CATALOG_TOKEN}") { set $ct_fail 0; }
    if ($ct_fail = 1) { return 403; }

    add_header Access-Control-Allow-Origin "${FRONTEND_URL}" always;
    add_header Access-Control-Allow-Methods "GET, OPTIONS" always;
    add_header Access-Control-Allow-Headers "X-CyCentra-Token" always;
    add_header Cache-Control "no-store" always;
}
```

The same `MARKETPLACE_CATALOG_TOKEN` env var covers both endpoints — no new secret needed.

---

### Step 2 — Flask Backend: New Route + Config

**`Cy360/backend/core/config.py`** — add after `MARKETPLACE_CATALOG_URL`:

```python
AGENTS_CATALOG_URL = os.environ.get(
    "AGENTS_CATALOG_URL",
    "https://cycentra.com/agents/catalog.json",
)
```

**`Cy360/backend/blueprints/marketplace/routes.py`** — add import, fetch helper, and route:

```python
from core.config import MARKETPLACE_CATALOG_TOKEN, MARKETPLACE_CATALOG_URL, \
                        AGENTS_CATALOG_URL, CYCENTRA_ADMIN_EMAIL


def _fetch_agents_catalog():
    """Proxy the agents catalog from cycentra.com — same token as marketplace."""
    try:
        headers = {}
        if MARKETPLACE_CATALOG_TOKEN:
            headers["X-CyCentra-Token"] = MARKETPLACE_CATALOG_TOKEN
        resp = http_requests.get(AGENTS_CATALOG_URL, headers=headers, timeout=6)
        if resp.ok:
            return resp.json().get("items", []), "ok"
        log.warning("agents catalog fetch failed — HTTP %s", resp.status_code)
    except Exception as exc:
        log.warning("agents catalog fetch error — %s: %s", type(exc).__name__, exc)
    return [], "fetch_error"


@marketplace_bp.route("/api/marketplace/agents", methods=["GET"])
def marketplace_agents():
    err = _require_auth()
    if err:
        return add_cors_headers(err[0]), err[1]
    items, status = _fetch_agents_catalog()
    resp = jsonify({"ok": True, "items": items, "cloud_status": status})
    return add_cors_headers(resp)
```

Also add `/api/marketplace/agents` to `_PREFLIGHT_ROUTES` so the OPTIONS handler is registered.

---

### Step 3 — Portal: "Agent Packages" Tab in MarketplacePage

Add a top-level tab strip to the existing page header — two tabs:
- **Integrations & Playbooks** (existing catalog grid)
- **Agent Packages** (new `AgentCatalogSection`)

**State addition** in `MarketplacePage`:

```jsx
const [activeTab, setActiveTab] = useState("catalog");
```

**Tab strip** (add in header row, same visual style as existing filter pills):

```jsx
<div style={{ display:"flex", gap:6 }}>
  {[
    { id:"catalog", label:"Integrations & Playbooks" },
    { id:"agents",  label:"Agent Packages" },
  ].map(t => (
    <button key={t.id} onClick={() => setActiveTab(t.id)}
      style={{
        background: activeTab===t.id ? "rgba(0,229,160,0.12)" : "rgba(255,255,255,0.04)",
        color:      activeTab===t.id ? "#00e5a0" : "rgba(255,255,255,0.45)",
        border:     `1px solid ${activeTab===t.id ? "rgba(0,229,160,0.3)" : "rgba(255,255,255,0.08)"}`,
        borderRadius:20, padding:"7px 14px", fontSize:11, fontFamily:"monospace", cursor:"pointer"
      }}>
      {t.label}
    </button>
  ))}
</div>
```

**`AgentCatalogSection` component** (new, inside `MarketplacePage.jsx`):

```jsx
function AgentCatalogSection() {
  const [agents,      setAgents]      = useState([]);
  const [loading,     setLoading]     = useState(true);
  const [cloudStatus, setCloudStatus] = useState(null);
  const [platform,    setPlatform]    = useState("all");

  useEffect(() => {
    fetch(`${API_BASE}/api/marketplace/agents`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { setAgents(d.items || []); setCloudStatus(d.cloud_status); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const platforms = ["all", ...new Set(agents.map(a => a.platform))];
  const filtered  = platform === "all" ? agents : agents.filter(a => a.platform === platform);

  // ... platform filter pills, AgentCard grid
}
```

**`AgentCard` component** — shows: name, version, platform/arch badge, description, copy-to-clipboard install command, SHA-256 checksum, required modules.

**Conditional render** in `MarketplacePage` return:

```jsx
{activeTab === "catalog" && (
  <>
    {/* existing catalog grid, installed section, available section */}
  </>
)}
{activeTab === "agents" && (
  <AgentCatalogSection />
)}
```

No separate route needed — the tab lives inside the same authenticated page component.

---

### Step 4 — CyAdmin: Agents Tab

Add an "Agents" tab to `CyAdmin/templates/marketplace.html` with the same table + form modal pattern as the existing Integrations/Playbooks tab.

Extend `CyAdmin/app.py` to manage a second working catalog file `CyAdmin/data/agents.json` and a second write target in the Publish endpoint:

```python
AGENTS_CATALOG_PATH = os.environ.get(
    "AGENTS_CATALOG_PATH",
    "../CyCentra/cycentra.com/public/agents/catalog.json"
)
```

The Publish button writes both `CYCENTRA_CATALOG_PATH` and `AGENTS_CATALOG_PATH` in a single action. The same `git-push.sh` deploys both files.

---

### What Does NOT Need to Change

- `MARKETPLACE_CATALOG_TOKEN` — reused as-is across both endpoints; no new secret
- Auth / RBAC — session auth + admin-role gating applies automatically via `_require_auth()`
- Custom-item submission workflow — agents catalog is cloud-managed only (no per-server custom agents)
- `cycentra-setup.sh` — add `AGENTS_CATALOG_URL` as a new optional env var with the same pattern as `MARKETPLACE_CATALOG_URL`

---

### Implementation Order

| # | Work | Owner | Notes |
|---|------|-------|-------|
| 1 | `nginx.conf.template` — add `/agents/` location block | g-cyra-web / g-cyra-devops | 5 min, copy-paste from `/marketplace/` block |
| 2 | `public/agents/catalog.json` — seed initial entries | g-cyra-web | Define schema, add first agent packages |
| 3 | `core/config.py` — add `AGENTS_CATALOG_URL` | g-cyra-360 | One line after `MARKETPLACE_CATALOG_URL` |
| 4 | `marketplace/routes.py` — add fetch helper + GET route | g-cyra-360 | Mirror of `_fetch_cloud_catalog()` |
| 5 | `MarketplacePage.jsx` — tab state + `AgentCatalogSection` + `AgentCard` | g-cyra-360 | Requires Docker rebuild after JSX change |
| 6 | `CyAdmin` — agents tab + Publish extension | g-cyra-360 / g-cyra-mgr | Independent of steps 1–5 |
| 7 | `cycentra-setup.sh` — add `AGENTS_CATALOG_URL` env var | g-cyra-devops | Document in `docs/MARKETPLACE.md` env table |

Steps 1–2 can be deployed independently (new static path, no portal change). Steps 3–5 are a single coordinated backend+frontend change. Step 6 is fully independent.
