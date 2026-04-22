# CyMind × CyCentra 360 Integration Guide

Connects CyMind's on-prem RAG-chat platform to the CyCentra 360 Security MCP bridge so that analysts can query live SIEM data (incidents, alerts, UEBA, risk scores) directly from the CyMind chat interface, embedded as an overlay inside the CyCentra 360 portal.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser (analyst)                                              │
│                                                                 │
│  ┌─────────────────────────────────┐                            │
│  │   CyCentra 360 Portal (React)   │                            │
│  │   + CyMind Chat Overlay         │                            │
│  └──────────────┬──────────────────┘                            │
└─────────────────┼───────────────────────────────────────────────┘
                  │ HTTPS
      ┌───────────▼──────────────┐
      │  CyCentra 360 Backend    │     ┌──────────────────────────┐
      │  Flask :5252             │     │  CyMind Backend          │
      │  • /api/system/cymind    │     │  FastAPI :8000           │
      │    (config + key mgmt)   │     │  • /api/v1/chat/stream   │
      │                          │     │  • /api/v1/apikeys       │
      │  FastAPI Correlation     │     │  • /api/v1/users         │
      │  Engine :8100            ◄─────┤  mcp_client.py           │
      │  • /mcp/sse  (MCP SSE)   │ SSE │    (SSE connection)      │
      │    + CYMIND_API_KEY guard│     └──────────────────────────┘
      └──────────────────────────┘
```

**Two separate keys are used — do not confuse them:**

| Key prefix | Direction | Purpose |
|---|---|---|
| `cymk_…` | CyMind → CyCentra | M2M key: CyMind calls CyCentra's MCP bridge to fetch live SIEM data |
| `pak_…`  | CyCentra overlay → CyMind | Chat key: the browser overlay authenticates to CyMind's chat API |

**Data flow for a live SIEM query:**

1. Analyst types a security question in the CyMind chat overlay embedded in CyCentra.
2. The overlay POSTs to CyMind `/api/v1/chat/stream` using the `pak_…` chat key.
3. CyMind chat router detects SIEM keywords and calls `mcp_client.fetch_context()`.
4. CyMind opens an MCP SSE session to CyCentra's `/mcp/sse` using the `cymk_…` M2M key.
5. CyCentra correlation engine executes tools (e.g. `list_incidents`) and returns JSON.
6. CyMind injects the JSON as context into the system prompt → LLM answers with live data.

---

## Prerequisites

| Requirement | Details |
|---|---|
| CyCentra 360 | v1.0.233+ |
| CyMind | Commit `cymind-mcp-integration` or later |
| Network | CyMind host must reach CyCentra 360 on port 8100 (or via nginx reverse-proxy) |
| `mcp[cli]` | Must be installed in CyCentra's correlation engine venv: `pip install 'mcp[cli]'` |

---

## Step-by-Step Setup

### Step 1 — Enter the CyMind URL in CyCentra

1. Log in to **CyCentra 360** as **admin**.
2. Go to **System Settings → CyMind** tab.
3. Enter the CyMind base URL (e.g. `https://cymind.corp.example.com`) and click **Save**.
   - This injects the nginx reverse-proxy block so the overlay can reach CyMind.

---

### Step 2 — Generate the M2M key and configure CyMind's environment

This key lets CyMind read live SIEM data from CyCentra's MCP bridge.

**In CyCentra 360 (System Settings → CyMind):**

1. Click **Generate M2M Key**.
2. **Copy the displayed key** (`cymk_…`) — it is shown only once.

**In CyMind's `.env` file:**

```dotenv
CYCENTRA_URL=https://cysoc.YOUR_DOMAIN    # CyCentra 360 base URL
CYCENTRA_API_KEY=cymk_YOUR_KEY_HERE        # M2M key from step above
```

Restart CyMind after saving:

```bash
docker compose restart cymind
# or: sudo systemctl restart cymind
```

**Verify the MCP bridge (optional):**

```bash
# No key → should return 401
curl -s http://127.0.0.1:8100/mcp/sse

# With key → should open an SSE stream (Ctrl-C to close)
curl -s -H "Authorization: Bearer cymk_YOUR_KEY" http://127.0.0.1:8100/mcp/sse
```

---

### Step 3 — Create a CyMind service account and get the Chat API key

The browser overlay authenticates to CyMind using a `pak_…` API key. This key **must be generated inside CyMind** and then pasted into CyCentra — CyCentra cannot generate a key that CyMind will recognise.

**3a — Create a dedicated service account in CyMind:**

1. Log in to **CyMind** as **admin**.
2. Go to **Users → Create User** (or call `POST /api/v1/users`).
3. Fill in:
   - **Name**: `cycentra-portal` (or any descriptive name)
   - **Email**: `cycentra-portal@internal` (does not need to be a real address)
   - **Password**: a strong random password (stored but never used interactively)
   - **Role**: `analyst`
4. Save the user.

> **Why analyst role?**  
> CyMind's chat router only injects live MCP/SIEM context for requests from users with the `analyst` or `admin` role. A `viewer` account can chat but will not receive live SIEM data even if `use_mcp: true` is sent.

**3b — Generate an API key for that service account:**

You need to be logged in as the service account user (or use the admin user-management API).

_Option A — Via the CyMind UI (log in as the service account):_

1. Log in to CyMind as `cycentra-portal@internal`.
2. Go to **API Keys → Generate API Key**.
3. Give it a descriptive name (e.g. `CyCentra overlay`).
4. **Copy the displayed key** (`pak_…`) — it is shown only once.

_Option B — Via the CyMind admin API (stay logged in as admin):_

```bash
# 1. Get the service account's user ID
curl -s -H "Authorization: Bearer <ADMIN_JWT>" \
     https://cymind.corp.example.com/api/v1/users \
  | jq '.users[] | select(.email=="cycentra-portal@internal") | .id'

# 2. Generate the key (admin generates for another user is not directly supported in
#    the current API — log in as the service account and use the UI, or use Option A).
```

**3c — Paste the key into CyCentra:**

1. Go back to **CyCentra 360 → System Settings → CyMind**.
2. In the **Chat API Key** section, paste the `pak_…` key into the input field.
3. Click **Save Chat Key**.

The overlay will now use this key when analysts open the chat.

---

### Step 4 — Allow CyCentra 360 to embed CyMind in an iframe

In CyMind's `.env`, add the CyCentra origin so that CORS headers allow the iframe:

```dotenv
CYCENTRA_ORIGIN=https://cysoc.YOUR_DOMAIN
```

Restart CyMind after saving:

```bash
docker compose restart cymind
```

---

### Step 5 — Verify the overlay

1. Log in to CyCentra 360 as an **analyst** or **admin**.
2. A green brain-shaped FAB button appears at the bottom-right of the portal.
3. Click it — the CyMind chat slides up.
4. Ask: *"What open incidents do we have right now?"*
5. CyMind should respond with live incident data pulled from CyCentra.

---

## Rotating the Chat API Key

When you need to rotate the chat key (e.g. security rotation):

1. In CyMind: go to the `cycentra-portal` user's API Keys, revoke the old key, generate a new one.
2. Copy the new `pak_…` key.
3. In CyCentra 360 → System Settings → CyMind → Chat API Key: paste the new key and click **Save Chat Key**.

No restart is required — the overlay picks up the new key immediately on next load.

---

## Rotating the M2M Key (`cymk_…`)

1. In CyCentra 360 → System Settings → CyMind: click **Rotate M2M Key**.
2. Copy the new `cymk_…` key.
3. In CyMind `.env`: update `CYCENTRA_API_KEY` to the new key.
4. Restart CyMind: `docker compose restart cymind`.

---

## Access Control Summary

| Role | Chat overlay visible | Live SIEM data via MCP |
|---|---|---|
| admin | ✓ | ✓ |
| analyst | ✓ | ✓ |
| developer | ✗ | ✗ |
| viewer | ✗ | ✗ (chat only, no SIEM) |

Enforcement is layered:

- **Frontend** (`App.jsx`): FAB only rendered for `role === "analyst" || "admin"`.
- **CyCentra backend** (`/api/system/cymind`): GET requires analyst+; POST requires admin.
- **MCP endpoint** (correlation engine): Rejects requests without valid `CYMIND_API_KEY` (`cymk_…`).
- **CyMind backend** (`routers/chat.py`): `use_mcp` context injection only for analyst/admin roles.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| FAB not visible | User role is `viewer` or `developer` | Log in with an analyst/admin account |
| Overlay shows "CyMind URL not configured" | CyMind URL not saved in CyCentra | System Settings → CyMind → enter URL → Save |
| Overlay shows blank / connection error | CORS blocked or CyMind unreachable | Set `CYCENTRA_ORIGIN` in CyMind `.env`, restart CyMind |
| CyMind chat returns generic answers, no SIEM data | MCP not connected or chat key missing | Check `CYCENTRA_API_KEY` in CyMind `.env`; verify chat key is set in CyCentra |
| `401 Unauthorized` on CyMind chat | Chat API key not registered / wrong key | Re-generate key in CyMind (Step 3), paste new key in CyCentra |
| `401 Unauthorized` on `/mcp/sse` | M2M key wrong or missing | Rotate M2M key (CyCentra), update `CYCENTRA_API_KEY` in CyMind `.env`, restart |
| MCP connect times out | Firewall between CyMind and CyCentra | Ensure CyMind host can reach CyCentra port 8100 (or nginx proxy port) |
| "Chat API key must start with pak_" error | Wrong key pasted | Generate the key from **CyMind** API Keys, not from CyCentra |

---

## API Reference

### CyCentra 360

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/system/cymind` | analyst+ | Read integration config; `chatApiKey` returned raw (used by overlay) |
| `POST` | `/api/system/cymind` | admin | Save URL, generate M2M key, save/clear chat key, toggle enabled |

`POST` body fields (all optional):

```json
{
  "cymindUrl":   "https://cymind.corp.example.com",
  "generateKey": true,
  "chatApiKey":  "pak_…key from CyMind…",
  "clearChatKey": false,
  "enabled":     true
}
```

### CyMind

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/users` | admin | Create a user (set role: "analyst") |
| `GET` | `/api/v1/users` | admin | List users (find service account ID) |
| `POST` | `/api/v1/apikeys` | current user | Generate API key for the authenticated user |
| `GET` | `/api/v1/apikeys` | current user | List API keys |
| `DELETE` | `/api/v1/apikeys/{id}` | current user | Revoke API key |

Chat request with MCP context:

```json
POST /api/v1/chat/stream
Authorization: Bearer pak_…

{
  "messages": [{ "role": "user", "content": "Show me today's open incidents" }],
  "use_mcp": true,
  "use_rag": true
}
```

### Available MCP Tools (from CyCentra 360 `/mcp/sse`)

| Tool | Description |
|---|---|
| `get_stats` | High-level SIEM statistics |
| `list_incidents` | Filter incidents by status / severity |
| `get_incident` | Full incident detail by ID |
| `list_alerts` | Raw alerts, optionally by incident |
| `list_risk_scores` | Entity risk leaderboard |
| `list_ueba_users` | UEBA profiles with anomaly counts |
| `get_ueba_anomalies` | Detailed anomaly history for a user |
| `wazuh_list_agents` | Enumerate Wazuh-monitored endpoints |
| `wazuh_active_response` | Trigger containment action on endpoint |
| `wazuh_get_agent_vulnerabilities` | CVEs on a monitored endpoint |
