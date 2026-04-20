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
│  │   + CyMind Chat Overlay (iframe)│                            │
│  └──────────────┬──────────────────┘                            │
└─────────────────┼───────────────────────────────────────────────┘
                  │ HTTPS
      ┌───────────▼──────────────┐
      │  CyCentra 360 Backend    │     ┌──────────────────────────┐
      │  Flask :5252             │     │  CyMind Backend          │
      │  • /api/system/cymind    │     │  FastAPI :8000           │
      │    (config + key mgmt)   │     │  • /api/v1/chat          │
      │                          │     │  • /api/v1/mcp/*         │
      │  FastAPI Correlation     │     │    (status, tools, call) │
      │  Engine :8100            ◄─────┤  mcp_client.py           │
      │  • /mcp/sse  (MCP SSE)   │ SSE │    (SSE connection)      │
      │    + CYMIND_API_KEY guard│     └──────────────────────────┘
      └──────────────────────────┘
```

**Data flow for a live SIEM query:**

1. Analyst types a security question in the CyMind chat overlay.
2. CyMind chat router detects SIEM keywords (`incident`, `risk`, `ueba`, …).
3. CyMind calls `mcp_client.call_tool()` → POST to CyCentra MCP session endpoint.
4. CyCentra correlation engine executes the tool (e.g. `list_incidents`) and returns JSON over SSE.
5. CyMind injects the JSON as context into the system prompt → LLM answers with grounded data.

---

## Prerequisites

| Requirement | Details |
|---|---|
| CyCentra 360 | v1.0.230+ (this integration ships with v1.0.233) |
| CyMind | Commit `cymind-mcp-integration` or later |
| Network | CyMind host must reach CyCentra 360 on port 8100 (or via nginx reverse-proxy) |
| `mcp[cli]` | Must be installed in CyCentra's correlation engine venv: `pip install 'mcp[cli]'` |

---

## Step-by-Step Setup (minimum effort)

### 1 — Generate the API key in CyCentra 360

1. Log in as **admin**.
2. Go to **System Settings → CyMind** tab.
3. Enter the CyMind base URL (e.g. `https://cymind.corp.example.com`).
4. Click **Generate API Key**.
5. **Copy the displayed key** (`cymk_…`) — it is shown once.

### 2 — Set the API key in CyCentra's correlation engine

The portal writes `CYMIND_API_KEY` into `/opt/cycentra/cysiemstack.env` automatically.
Restart the engine service to activate it:

```bash
sudo systemctl restart cysiemstack-engine
# or, for Docker installs:
docker compose -f /opt/cycentra/docker-compose.yml restart cysiemstack-engine
```

Verify the key is active:

```bash
curl -s http://127.0.0.1:8100/mcp/sse   # should return 401 Unauthorized (key guard active)
curl -s -H "Authorization: Bearer cymk_YOUR_KEY" http://127.0.0.1:8100/mcp/sse   # should open SSE stream
```

### 3 — Configure CyMind to connect to the MCP bridge

In CyMind, either:

**Option A — Admin UI** (CyMind → System Settings → MCP Connection):
1. Set **MCP Endpoint** to `http://127.0.0.1:8100/mcp/sse`
   (or `https://cysoc.YOUR_DOMAIN/mcp/sse` if behind nginx).
2. Set **API Key** to the `cymk_…` key from Step 1.
3. Click **Save & Connect**.

**Option B — Environment variable** (`.env` in CyMind):
```dotenv
MCP_ENDPOINT=http://127.0.0.1:8100/mcp/sse
MCP_API_KEY=cymk_YOUR_KEY_HERE
```
Then restart CyMind: `docker compose restart cymind`.

### 4 — Allow CyCentra 360 to embed CyMind in an iframe

In CyMind's `.env`, set the CyCentra origin so CORS allows the iframe:

```dotenv
CYCENTRA_ORIGIN=https://cysoc.YOUR_DOMAIN
```

Restart CyMind after saving.

### 5 — Verify the overlay

1. Log in to CyCentra 360 as an **analyst** or **admin**.
2. A green brain-shaped FAB button appears at the bottom-right of the portal.
3. Click it — the CyMind chat slides up.
4. Ask: *"What open incidents do we have right now?"*
5. CyMind should respond with live incident data from CyCentra.

---

## Access Control Summary

| Role | Chat overlay visible | MCP tools accessible |
|---|---|---|
| admin | ✓ | ✓ |
| analyst | ✓ | ✓ |
| viewer | ✗ | ✗ |
| cyiris / cysoar | ✗ | ✗ |

Enforcement is layered:

- **Frontend** (`App.jsx`): FAB only rendered for `role === "analyst" || "admin"`.
- **CyCentra backend** (`/api/system/cymind`): GET requires analyst+; POST requires admin.
- **MCP endpoint** (correlation engine `main.py`): Rejects requests without valid `CYMIND_API_KEY`.
- **CyMind backend** (`routers/mcp.py`): `/api/v1/mcp/call` requires analyst+ role check.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| FAB not visible | User role is `viewer` | Log in with analyst/admin account |
| Overlay shows "CyMind URL not configured" | CyMind URL not saved | System Settings → CyMind → Save URL |
| Overlay shows blank iframe | CORS blocked | Set `CYCENTRA_ORIGIN` in CyMind `.env` |
| CyMind chat returns no SIEM data | MCP not connected | CyMind → MCP Settings → Connect, check API key |
| `401 Unauthorized` on `/mcp/sse` | Wrong or missing API key | Re-generate key, restart engine |
| MCP connect times out | Network / firewall | Ensure CyMind host can reach port 8100 |

---

## API Reference (new endpoints)

### CyCentra 360

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/system/cymind` | analyst+ | Read integration config (key masked) |
| `POST` | `/api/system/cymind` | admin | Save URL, generate key, toggle enabled |

`POST` body:
```json
{
  "cymindUrl":   "https://cymind.corp.example.com",
  "generateKey": true,
  "enabled":     true
}
```

### CyMind

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/mcp/status` | any auth | Connection state + tool list |
| `GET` | `/api/v1/mcp/tools` | analyst+ | List available SIEM tools |
| `POST` | `/api/v1/mcp/call` | analyst+ | Call a specific tool |
| `GET` | `/api/v1/mcp/settings` | admin | Read endpoint config |
| `PATCH` | `/api/v1/mcp/settings` | admin | Update endpoint / key, auto-reconnect |
| `POST` | `/api/v1/mcp/connect` | admin | Force reconnect |
| `POST` | `/api/v1/mcp/disconnect` | admin | Disconnect |

`POST /api/v1/mcp/call` body:
```json
{
  "name": "list_incidents",
  "arguments": { "status": "open", "severity": "critical", "limit": 10 }
}
```

Chat requests with MCP context (add `use_mcp: true`):
```json
{
  "messages": [{ "role": "user", "content": "Show me today's open incidents" }],
  "use_mcp": true,
  "use_rag": true
}
```

### Available MCP Tools (from CyCentra 360)

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
