# Integration Marketplace — Architecture & Contribution Guide

## Overview

The CyCentra 360 Integration Marketplace is a **three-tier, cloud-pull system**. No integrations or playbooks are bundled with the platform at ship time. Everything visible in the Marketplace tab is fetched on demand from the cloud catalog hosted on `cycentra.com`.

**The catalog is managed exclusively through the CyAdmin Marketplace Manager UI — never by editing files directly.**

---

## The Three UIs

| UI | URL | Who uses it | Purpose |
|----|-----|-------------|---------|
| **CyAdmin Marketplace Manager** | `http://localhost:7070/marketplace` | CyCentra team (internal) | Add/edit/delete items, review and approve/reject contributor submissions, publish to cycentra.com |
| **CyAdmin Contributor Form** | `http://localhost:7070/marketplace/contribute` | Authorized contributors | Submit new integrations or playbooks for review |
| **CyCentra 360 Marketplace Tab** | Portal → Marketplace | End users (SOC analysts, admins) | Browse the live catalog, pull integrations, configure credentials |

---

## Architecture & Data Flow

```
┌──────────────────────────────────────────────────────────────────────┐
│  CyAdmin (internal, localhost:7070)                                  │
│  /marketplace             — admin catalog manager UI                │
│  /marketplace/contribute  — contributor submission form             │
│  data/catalog.json        — working copy (bind-mounted ./data/)     │
│                                                                      │
│  [Publish to cycentra.com] button                                    │
│   → POST /api/marketplace/publish                                    │
│   → writes approved items to cycentra.com repo on disk              │
└──────────────────────────────┬───────────────────────────────────────┘
                               │  file write
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  CyCentra/cycentra.com/public/marketplace/catalog.json              │
│  (local repo file — git tracked)                                     │
│                                                                      │
│  bash git-push.sh   →   CI builds + deploys to cycentra.com server  │
└──────────────────────────────┬───────────────────────────────────────┘
                               │  HTTPS GET on each portal page load
                               │  (MARKETPLACE_CATALOG_URL default)
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  https://cycentra.com/marketplace/catalog.json                      │
│  nginx serves the static file; CORS locked to ${FRONTEND_URL}       │
└──────────────────────────────┬───────────────────────────────────────┘
                               │  fetched by Flask backend
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  CyCentra 360 Backend (Flask)                                        │
│  GET /api/marketplace/catalog                                        │
│  • _fetch_cloud_catalog() fetches MARKETPLACE_CATALOG_URL           │
│  • Merges with any approved custom items on this server             │
│  • Returns merged list to portal — cycentra.com URL never exposed   │
└──────────────────────────────┬───────────────────────────────────────┘
                               │  JSON response
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  CyCentra 360 Portal (React)                                         │
│  portal/src/pages/marketplace/MarketplacePage.jsx                   │
│  • Search bar, type tabs (All / Integrations / Playbooks)           │
│  • "Available from Cloud" and "Installed on this Server"            │
│  • Admin: Pull, Configure, Remove buttons                           │
│  • Non-admin: read-only view with locked action buttons             │
└──────────────────────────────────────────────────────────────────────┘
```

**Key principle:** the browser never calls CyAdmin or cycentra.com directly. All catalog traffic is proxied through the CyCentra 360 Flask backend.

---

## The Standard Workflow — Adding or Updating an Item

This is the **only** correct process. Do not edit catalog files directly.

### Step 1 — Open CyAdmin Marketplace Manager

```
http://localhost:7070/marketplace
```

### Step 2 — Add or edit the item

- Click **+ Add Item** to create a new entry, or the edit icon on an existing row.
- Fill in all required fields (see Field Reference below).
- Item `id` must be unique, lowercase alphanumeric + hyphens, 3–50 chars.
- The ID is **immutable once published** — changing it breaks install state on all existing servers.

### Step 3 — Publish to cycentra.com

Click the **"Publish to cycentra.com"** button in the toolbar.

This writes all approved items to:
```
CyCentra/cycentra.com/public/marketplace/catalog.json
```

A toast confirms: *"Published N item(s) to cycentra.com catalog."*

### Step 4 — Deploy live

```bash
cd /path/to/CyCentra/cycentra.com
bash git-push.sh
```

CI builds and deploys the updated container to `cycentra.com`. Once deployed, **all connected CyCentra 360 instances see the new item immediately** on the next page load — no server-side action required on any connected server.

---

## CyAdmin Marketplace Manager — Details

### Admin capabilities

- View all catalog items in a searchable, filterable table (All / Integrations / Playbooks)
- Add new items via a full-form modal — validates all fields, checks ID uniqueness
- Edit any existing item — ID is locked once created to protect install state on live servers
- Delete items
- View all contributor submissions (Submissions tab with red dot when pending reviews exist)
- Approve a submission → item immediately added to the working catalog
- Reject a submission with a mandatory written reason
- **Publish to cycentra.com** — syncs approved working catalog to the live static file

### Auth

If `CYADMIN_TOKEN` is set in `docker-compose.yml`, the page prompts for the token on first load (stored in `localStorage`). If not set, the portal is open.

### Working catalog vs. live catalog

| Location | Purpose |
|----------|---------|
| `CyAdmin/data/catalog.json` | Working copy — all edits happen here |
| `CyCentra/cycentra.com/public/marketplace/catalog.json` | Live static file served to all CyCentra 360 instances |

The **Publish** button syncs the working copy to the live file. Until you publish and run `git-push.sh`, changes in CyAdmin are not visible to any CyCentra 360 instance.

---

## Contributor Workflow

Anyone with a `CONTRIBUTOR_TOKEN` can submit items for review without admin access.

### Submitting

```
http://localhost:7070/marketplace/contribute
```

The form collects all catalog fields, has a playbook-specific section shown when "Playbook" is selected, and requires the contributor token. **Submissions never publish directly** — they land in the Submissions queue for admin review.

### Review

CyAdmin admins see pending submissions in the Submissions tab. They can:
- **Approve** — item moves to the working catalog; Publish + `git-push.sh` to go live
- **Reject** — mandatory reason is recorded

### Setting up contributor tokens

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Set in `CyAdmin/docker-compose.yml`:
```yaml
- CONTRIBUTOR_TOKEN=<generated-token>
```

Share the token only with trusted contributors. It is separate from `CYADMIN_TOKEN` — contributors cannot access admin functions.

---

## Field Reference

| Field | Required | Notes |
|-------|----------|-------|
| `id` | ✅ | Lowercase alphanumeric + hyphens, 3–50 chars. **Immutable once published** — changing it breaks install state on every connected server. |
| `name` | ✅ | Display name in the portal |
| `type` | ✅ | `"integration"` or `"playbook"` |
| `description` | ✅ | Shown in the detail panel |
| `category` | | Grouping label (e.g. `"Cloud"`, `"Active Response"`, `"Threat Intelligence"`) |
| `vendor` | | Defaults to `"CyCentra"` if omitted |
| `icon` | | Emoji or short string shown in the card |
| `color` | | Hex accent color for the card border |
| `modules_required` | | Array of CyCentra module names the item depends on (`"CySIEM"`, `"CySOAR"`) |
| `estimated_time` | | Rough config/deploy estimate shown in the card |
| `tags` | | Lowercase strings used by the search filter |
| `config_type` | | `"o365"` or `"gcloud"` — opens the dedicated config modal on install. Omit for items needing no guided setup. |
| `cysoar_flow` | | Playbooks only — the CySOAR flow filename to reference |
| `steps` | | Playbooks only — ordered list of automation steps shown in the detail panel |

---

## Access Control

### CyAdmin (management layer)

| Action | Requirement |
|--------|-------------|
| Browse/edit catalog items | `CYADMIN_TOKEN` (or open if not set) |
| Approve/reject submissions | `CYADMIN_TOKEN` |
| Submit new item for review | `CONTRIBUTOR_TOKEN` (or `CYADMIN_TOKEN`) |
| Publish to cycentra.com | `CYADMIN_TOKEN` |

### CyCentra 360 Portal (consumer layer)

| Action | Required role |
|--------|--------------|
| Browse catalog / view items | Any authenticated user (viewer, analyst, admin) |
| Pull / Install an item | `admin` only |
| Configure credentials (O365, GCloud) | `admin` only |
| Remove installed item | `admin` only |
| Create / edit per-server custom items | `admin` only |
| Submit per-server item for cloud review | `admin` only |

Unauthenticated requests to any `/api/marketplace/*` route return `401`. Insufficient-role requests return `403`.

### cycentra.com CORS lock

`nginx.conf.template` restricts `/marketplace/` to a single allowed origin:

```nginx
location /marketplace/ {
    add_header Access-Control-Allow-Origin "${FRONTEND_URL}" always;
    add_header Access-Control-Allow-Methods "GET, OPTIONS" always;
    add_header Cache-Control "no-store" always;
}
```

`FRONTEND_URL` is injected at container startup (e.g. `https://cy360.cycentra.com`). The CyCentra 360 Flask backend fetches the catalog server-side, so this CORS lock does not affect normal operation.

---

## File Locations

| File | Purpose |
|------|---------|
| `CyAdmin/data/catalog.json` | Working catalog — managed via CyAdmin UI |
| `CyAdmin/app.py` | All marketplace API routes and Publish endpoint |
| `CyAdmin/templates/marketplace.html` | Admin manager UI |
| `CyAdmin/templates/marketplace_contribute.html` | Contributor submission form |
| `CyCentra/cycentra.com/public/marketplace/catalog.json` | **Live static catalog** — written by Publish, deployed by `git-push.sh` |
| `CyCentra/cycentra.com/nginx.conf.template` | nginx CORS config for `/marketplace/` |
| `cycentra360/backend/blueprints/marketplace/routes.py` | All CyCentra 360 marketplace API endpoints |
| `cycentra360/portal/src/pages/marketplace/MarketplacePage.jsx` | CyCentra 360 consumer-side Marketplace UI |
| `/opt/cycentra/marketplace_custom.json` | Per-server custom items (local to each server) |
| `/var/ossec/etc/cycentra_marketplace.json` | Per-server install state |
| `cycentra360/backend/core/config.py` (lines 141–150) | `MARKETPLACE_CATALOG_TOKEN`, `MARKETPLACE_CATALOG_URL`, `CYCENTRA_ADMIN_EMAIL` |

---

## Adding a Config Modal for a New Integration

If your integration requires credentials (like O365 or Google Cloud), add a `config_type` and a portal modal.

### Step 1 — Register the `config_type`

In `backend/blueprints/marketplace/routes.py`:

```python
_VALID_CONFIG_TYPES = {"o365", "gcloud", "your_type", None}
```

### Step 2 — Add backend config endpoints

```python
@system_bp.route("/api/system/yourconfig", methods=["OPTIONS"])
def options_yourconfig():
    return add_cors_headers(make_response('', 204))

@system_bp.route("/api/system/yourconfig", methods=["GET"])
def get_yourconfig():
    ...

@system_bp.route("/api/system/yourconfig", methods=["POST"])
def post_yourconfig():
    # admin only
    ...
```

### Step 3 — Create the config modal in the portal

Following the pattern of `O365ConfigModal` and `GCloudConfigModal` in `MarketplacePage.jsx`:

```jsx
function YourConfigModal({ item, onClose, onSaved }) {
  // form state, useEffect to load existing config
  // handleSave → POST /api/system/yourconfig
  return ( /* modal JSX */ );
}
```

Wire it into `renderConfigModal`:

```jsx
if (item.config_type === "your_type") return <YourConfigModal ... />;
```

### Step 4 — Register the new env var

Add any new secrets/config keys to `core/config.py` and `cycentra-setup.sh`. Notify `@cyra-devops`.

---

## Per-Server Custom Item Workflow

Admins on a CyCentra 360 server can create items **local to their installation** and optionally submit them for inclusion in the global catalog.

```
Admin creates draft item
  → visible only on that server
  → editable freely while in draft or rejected state

Admin submits for cloud review
  → status becomes "submitted"
  → visible to the CyCentra platform admin (CYCENTRA_ADMIN_EMAIL)
  → cannot be edited while under review (recall first to edit)

CyCentra admin approves in CyAdmin
  → adds item to working catalog → Publish → git-push.sh → visible globally

CyCentra admin rejects (with reason)
  → status becomes "rejected"
  → admin sees the reason; can revise and resubmit
```

Per-server custom items are **never** sent to cycentra.com automatically. The submission workflow is a notification mechanism only.

---

## Environment Variables

### CyAdmin (`CyAdmin/docker-compose.yml`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `CYADMIN_TOKEN` | *(unset — open)* | Bearer token protecting all admin API routes |
| `CONTRIBUTOR_TOKEN` | *(unset — open)* | Separate token for contributor submissions |
| `CATALOG_FILE` | `./data/catalog.json` | Path to the working catalog inside the container |
| `CYCENTRA_CATALOG_PATH` | `../CyCentra/cycentra.com/public/marketplace/catalog.json` | Destination written by the Publish action |

### CyCentra 360 (`/opt/cycentra/.env`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `MARKETPLACE_CATALOG_URL` | `https://cycentra.com/marketplace/catalog.json` | URL of the live cloud catalog fetched by Flask |
| `MARKETPLACE_CATALOG_TOKEN` | *(empty)* | Pre-shared token for future gated catalog access. Currently unused. |
| `CYCENTRA_ADMIN_EMAIL` | `cyadmin@cycentra.com` | Account that can approve/reject per-server submitted items |

---

## What NOT to Do

- **Never edit `catalog.json` files directly in any text editor.** Use the CyAdmin Marketplace Manager UI.
- **Never add or modify catalog items directly on a live server via SSH.** All catalog changes go through CyAdmin → Publish → `git-push.sh`.
- **Never hard-code an integration into the portal or backend.** The catalog is the single source of truth.
- **Never commit real secrets into any catalog file.** Catalog files contain metadata only. Credentials go in `/opt/cycentra/.env` on the server.
- **Never change an existing item's `id`.** The ID is the primary key for install state on every connected server. Renaming it breaks tracking silently and permanently.
- **Never skip `git-push.sh` after Publish.** The Publish button writes to the local repo file only. The live cycentra.com server is only updated after CI deploys.

---

## Adding a New Item — Quick Checklist

- [ ] Opened CyAdmin at `http://localhost:7070/marketplace`
- [ ] Item `id` is lowercase alphanumeric + hyphens, 3–50 chars, unique across all existing items
- [ ] `type` is `"integration"` or `"playbook"`
- [ ] `description` is non-empty
- [ ] `modules_required` lists only real CyCentra modules
- [ ] Tags are lowercase with no spaces
- [ ] If `config_type` is set, a backend endpoint and portal modal exist for it
- [ ] If `cysoar_flow` is set, the flow file exists in CySOAR
- [ ] Clicked **"Publish to cycentra.com"** button — toast confirms success
- [ ] `bash git-push.sh` run from `CyCentra/cycentra.com/`
- [ ] Verified new item appears in the CyCentra 360 portal Marketplace tab
