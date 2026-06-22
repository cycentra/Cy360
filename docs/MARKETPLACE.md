# Integration Marketplace — Architecture & Contribution Guide

## Overview

The CyCentra 360 Integration Marketplace is a **three-tier, live-API system**. No integrations or playbooks are bundled with the platform at ship time. Everything visible in the Marketplace tab is fetched on demand from the cloud catalog hosted on `cycentra.com`.

**The catalog is managed exclusively through the CyAdmin Marketplace Manager UI — never by editing files directly.**

---

## The Three UIs

| UI | URL | Who uses it | Purpose |
|----|-----|-------------|---------|
| **CyAdmin Marketplace Manager** | `http://localhost:7070/marketplace` | CyCentra team (internal, dev machine only) | Add/edit/delete items, review remote submissions from Cy360 instances, publish live to cycentra.com |
| **CyAdmin Contributor Form** | `http://localhost:7070/marketplace/contribute` | Authorized contributors | Submit new integrations or playbooks for review |
| **CyCentra 360 Marketplace Tab** | Portal → Marketplace | End users (SOC analysts, admins) | Browse the live catalog, pull integrations, configure credentials, contribute items |

> **Important:** CyAdmin lives only on the developer's local machine — it is never exposed to client Cy360 instances. All live traffic passes through `cycentra.com`.

---

## Architecture & Data Flow

### Publication path (CyAdmin → cycentra.com → Cy360 — immediate, no CI)

```
┌──────────────────────────────────────────────────────────────────────┐
│  CyAdmin (developer laptop only — localhost:7070)                    │
│  /marketplace           — admin catalog manager UI                   │
│  data/catalog.json      — working copy (bind-mounted ./data/)        │
│                                                                      │
│  [Publish to cycentra.com] button                                    │
│   → POST /api/marketplace/publish                                    │
│   → HTTP POST to cycentra.com/marketplace/api/publish               │
│     (Authorization: Bearer MARKETPLACE_ADMIN_TOKEN)                  │
└──────────────────────────────┬───────────────────────────────────────┘
                               │  HTTPS POST
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  cycentra.com — marketplace-api (Flask, port 5050, Docker)           │
│  POST /marketplace/api/publish                                        │
│   → validates MARKETPLACE_ADMIN_TOKEN                                │
│   → writes catalog.json to shared Docker volume (/data/)             │
│                                                                      │
│  cycentra-web (nginx)                                                 │
│   → serves /marketplace/catalog.json from same shared volume         │
│   → LIVE immediately — zero CI rebuild, zero restart                 │
└──────────────────────────────┬───────────────────────────────────────┘
                               │  HTTPS GET — MARKETPLACE_CATALOG_URL
                               │  X-CyCentra-Token header (if token set)
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  CyCentra 360 Backend (Flask)  _fetch_cloud_catalog()                │
│  GET /api/marketplace/catalog                                         │
│  • Fetches MARKETPLACE_CATALOG_URL with X-CyCentra-Token            │
│  • Merges with approved custom items local to this server            │
│  • Returns merged list — cycentra.com URL never exposed to browser   │
└──────────────────────────────┬───────────────────────────────────────┘
                               │  JSON response
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  CyCentra 360 Portal (React)                                          │
│  portal/src/pages/marketplace/MarketplacePage.jsx                    │
└──────────────────────────────────────────────────────────────────────┘
```

### Contribution path (Cy360 portal → cycentra.com → CyAdmin review — immediate)

```
┌──────────────────────────────────────────────────────────────────────┐
│  Cy360 Portal — "+ Contribute to Marketplace"                         │
│  Admin fills form → clicks "Submit for Review"                        │
│  POST /api/marketplace/catalog/custom          (create draft)         │
│  POST /api/marketplace/catalog/custom/<id>/submit                     │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Cy360 Backend  catalog_custom_submit()                               │
│  • Saves status="submitted" to /opt/cycentra/marketplace_custom.json │
│  • Sends email notification to MARKETPLACE_ADMIN_EMAIL               │
│  • Fire-and-forget: POST MARKETPLACE_SUBMIT_URL                      │
│    (defaults to cycentra.com/marketplace/api/submissions)            │
│    X-CyCentra-Token: MARKETPLACE_CATALOG_TOKEN                       │
└──────────────────────────────┬───────────────────────────────────────┘
                               │  HTTPS POST (async background thread)
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  cycentra.com marketplace-api                                         │
│  POST /marketplace/api/submissions                                    │
│   → validates X-CyCentra-Token                                       │
│   → appends to submissions.json on shared volume                     │
│   → persisted immediately, visible to CyAdmin                        │
└──────────────────────────────┬───────────────────────────────────────┘
                               │  HTTPS GET (CyAdmin polls on load)
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  CyAdmin — Remote Submissions tab                                     │
│  GET /api/marketplace/remote-submissions                              │
│   → proxies GET cycentra.com/marketplace/api/submissions             │
│                                                                      │
│  Approve → POST cycentra.com/marketplace/api/submissions/<id>/approve│
│   → item promoted to live catalog.json immediately (no Publish step) │
│                                                                      │
│  Reject → POST cycentra.com/marketplace/api/submissions/<id>/reject  │
│   → reason stored; item stays off live catalog                       │
└──────────────────────────────────────────────────────────────────────┘
```

**Key principles:**
- The browser never calls CyAdmin or cycentra.com directly — all catalog traffic is proxied through the Cy360 Flask backend.
- Publishing from CyAdmin goes live immediately — no `git-push.sh` required.
- Contributions from Cy360 instances land on cycentra.com; CyAdmin pulls them from there for review.

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

This POSTs all approved items to `cycentra.com/marketplace/api/publish` via the admin API. The live `catalog.json` is updated immediately on the shared Docker volume.

A toast confirms: *"Published N item(s)."*

**That's it — no `git-push.sh` needed. All connected Cy360 instances see the new item on the next page load.**

---

## CyAdmin Marketplace Manager — Details

### Admin capabilities

- View all catalog items in a searchable, filterable table (All / Integrations / Playbooks)
- Add new items via a full-form modal — validates all fields, checks ID uniqueness
- Edit any existing item — ID is locked once created to protect install state on live servers
- Delete items
- View **Local Submissions** (items submitted from the CyAdmin contributor form)
- View **Remote Submissions** (items submitted from Cy360 portal instances via cycentra.com)
- Approve a submission → item published live immediately to cycentra.com catalog
- Reject a submission with a mandatory written reason
- **Publish to cycentra.com** — syncs approved working catalog to the live API

### Auth

If `CYADMIN_TOKEN` is set in `docker-compose.yml`, the page prompts for the token on first load (stored in `localStorage`). If not set, the portal is open.

---

## Contributor Workflow

### From the CyAdmin contributor form

```
http://localhost:7070/marketplace/contribute
```

The form collects all catalog fields and requires the contributor token. **Submissions never publish directly** — they land in the Local Submissions queue for admin review.

### From the Cy360 portal (recommended for client submissions)

Admins on a Cy360 server can create items local to their installation and submit them for inclusion in the global catalog.

1. Portal → Marketplace → "+ Contribute to Marketplace"
2. Fill the form → click "Submit for Review"
3. The item is saved locally (status = "submitted") and forwarded to cycentra.com's submissions queue
4. CyAdmin team sees it in the **Remote Submissions** tab
5. Approve → item goes live in the catalog immediately; all Cy360 instances see it
6. Reject → admin sees the reason in the portal and can edit + resubmit

### Review in CyAdmin

| Tab | Source |
|-----|--------|
| **Local Submissions** | Submissions via `http://localhost:7070/marketplace/contribute` |
| **Remote Submissions** | Submissions from Cy360 portal instances, stored on cycentra.com |

### Setting up contributor tokens

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Set in `CyAdmin/docker-compose.yml`:
```yaml
- CONTRIBUTOR_TOKEN=<generated-token>
```

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
| `config_type` | | `"o365"`, `"gcloud"`, or `"github"` — opens the dedicated config modal on install. Omit for items needing no guided setup. |
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
| Publish to cycentra.com live API | `CYADMIN_TOKEN` + `MARKETPLACE_ADMIN_TOKEN` |

### cycentra.com marketplace-api

| Action | Requirement |
|--------|-------------|
| Publish catalog (write) | `Authorization: Bearer MARKETPLACE_ADMIN_TOKEN` |
| Fetch submissions list | `Authorization: Bearer MARKETPLACE_ADMIN_TOKEN` |
| Approve / reject submission | `Authorization: Bearer MARKETPLACE_ADMIN_TOKEN` |
| Submit a contribution | `X-CyCentra-Token: MARKETPLACE_CATALOG_TOKEN` |
| Read catalog.json | `X-CyCentra-Token: MARKETPLACE_CATALOG_TOKEN` |

### CyCentra 360 Portal (consumer layer)

| Action | Required role |
|--------|--------------|
| Browse catalog / view items | Any authenticated user (viewer, analyst, admin) |
| Pull / Install an item | `admin` only |
| Configure credentials (O365, GCloud) | `admin` only |
| Remove installed item | `admin` only |
| Create / edit per-server custom items | `admin` only |
| Submit per-server item for cloud review | `admin` only |

---

## File Locations

| File | Purpose |
|------|---------|
| `CyAdmin/data/catalog.json` | Working catalog — managed via CyAdmin UI |
| `CyAdmin/app.py` | All marketplace API routes; publish calls cycentra.com API |
| `CyAdmin/templates/marketplace.html` | Admin manager UI (Local + Remote Submissions tabs) |
| `CyAdmin/templates/marketplace_contribute.html` | Local contributor submission form |
| `CyCentra.com/marketplace-api/app.py` | Live Flask API: publish, submissions, approve/reject |
| `CyCentra.com/marketplace-api/Dockerfile` | python:3.12-slim, port 5050 |
| `CyCentra.com/docker-compose.yml` | Shared `marketplace-data` volume; nginx + marketplace-api services |
| `CyCentra.com/nginx.conf.template` | Routes `/marketplace/api/` → marketplace-api; `/marketplace/` serves catalog.json |
| `Cy360/backend/blueprints/marketplace/routes.py` | All CyCentra 360 marketplace API endpoints |
| `Cy360/portal/src/pages/marketplace/MarketplacePage.jsx` | CyCentra 360 consumer-side Marketplace UI |
| `/opt/cycentra/marketplace_custom.json` | Per-server custom items (local to each server) |
| `/var/ossec/etc/cycentra_marketplace.json` | Per-server install state |
| `Cy360/backend/core/config.py` | `MARKETPLACE_CATALOG_TOKEN`, `MARKETPLACE_CATALOG_URL`, `MARKETPLACE_SUBMIT_URL` |

---

## Environment Variables

### CyAdmin (`CyAdmin/docker-compose.yml`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `CYADMIN_TOKEN` | *(unset — open)* | Bearer token protecting all admin API routes |
| `CONTRIBUTOR_TOKEN` | *(unset — open)* | Separate token for local contributor submissions |
| `CATALOG_FILE` | `./data/catalog.json` | Path to the working catalog inside the container |
| `CYCENTRA_COM_URL` | `https://cycentra.com` | Base URL of the live cycentra.com marketplace API |
| `MARKETPLACE_ADMIN_TOKEN` | *(required for Publish)* | Admin secret shared with cycentra.com; gates publish and remote submission review |
| `NOTIFY_EMAIL` | `marketplace@cycentra.com` | Destination for local contributor submission email notifications |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` | *(unset)* | SMTP config for email notifications |

### cycentra.com (`CyCentra.com/.env`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `MARKETPLACE_ADMIN_TOKEN` | *(required)* | Secret known only to CyAdmin; gates publish and submission review |
| `MARKETPLACE_CATALOG_TOKEN` | *(empty)* | Pre-shared token for Cy360 instances; gates catalog read and contribution submit. Leave empty for open access. |
| `FRONTEND_URL` | `https://cy360.cycentra.com` | CORS allowed origin for nginx catalog endpoint |

### CyCentra 360 (`/opt/cycentra/.env`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `MARKETPLACE_CATALOG_URL` | `https://cycentra.com/marketplace/catalog.json` | URL Cy360 fetches the live catalog from |
| `MARKETPLACE_CATALOG_TOKEN` | *(empty)* | Pre-shared token sent as `X-CyCentra-Token`; must match `MARKETPLACE_CATALOG_TOKEN` on cycentra.com |
| `MARKETPLACE_SUBMIT_URL` | derived from `MARKETPLACE_CATALOG_URL` | URL to POST contributions to (auto-derived as `{base}/marketplace/api/submissions`) |
| `CYCENTRA_ADMIN_EMAIL` | `cyadmin@cycentra.com` | Account that can approve/reject per-server submitted items in the Cy360 portal |
| `MARKETPLACE_ADMIN_EMAIL` | `marketplace@cycentra.com` | Destination for submission notification emails; can be a shared team inbox |

---

## Adding a Config Modal for a New Integration

If your integration requires credentials, add a `config_type` and a portal modal.
Three `config_type` values are already implemented end-to-end: `o365`, `gcloud`, and `github`.
Use one of these as a reference implementation before adding a new type.

### Step 1 — Register the `config_type`

In `backend/blueprints/marketplace/routes.py`:

```python
_VALID_CONFIG_TYPES = {"o365", "gcloud", "github", "your_type", None}
```

### Step 2 — Add backend config endpoints

```python
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

---

## What NOT to Do

- **Never edit `catalog.json` files directly in any text editor.** Use the CyAdmin Marketplace Manager UI.
- **Never configure Cy360 to call CyAdmin directly.** CyAdmin is on a developer machine — it cannot be reached by client instances. All traffic goes through cycentra.com.
- **Never hard-code an integration into the portal or backend.** The catalog is the single source of truth.
- **Never commit real secrets into any catalog file.** Catalog files contain metadata only. Credentials go in `/opt/cycentra/.env` on the server.
- **Never change an existing item's `id`.** The ID is the primary key for install state on every connected server. Renaming it breaks tracking silently and permanently.

---

## Adding a New Item — Quick Checklist

- [ ] Opened CyAdmin at `http://localhost:7070/marketplace`
- [ ] `CYCENTRA_COM_URL` and `MARKETPLACE_ADMIN_TOKEN` are set in `CyAdmin/docker-compose.yml`
- [ ] Item `id` is lowercase alphanumeric + hyphens, 3–50 chars, unique across all existing items
- [ ] `type` is `"integration"` or `"playbook"`
- [ ] `description` is non-empty
- [ ] `modules_required` lists only real CyCentra modules
- [ ] Tags are lowercase with no spaces
- [ ] If `config_type` is set, a backend endpoint and portal modal exist for it
- [ ] If `cysoar_flow` is set, the flow file exists in CySOAR
- [ ] Clicked **"Publish to cycentra.com"** button — toast confirms success
- [ ] Verified new item appears in the CyCentra 360 portal Marketplace tab (no deploy step needed)
