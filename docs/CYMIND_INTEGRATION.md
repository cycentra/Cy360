# CyMind × CyCentra 360 Integration Guide

Connects CyMind's on-prem RAG-chat platform to CyCentra 360 so analysts can query live SIEM data (incidents, alerts, UEBA, risk scores, endpoints) directly from a chat overlay embedded inside the CyCentra 360 portal.

Default network addresses used throughout this guide:

| Host | Default IP | Port |
|---|---|---|
| CyCentra 360 | 172.16.0.3 | 443 / 5252 |
| CyMind | 172.16.0.2 | 8080 |

---

## Architecture

```
Browser (analyst)
    │  HTTPS
    ▼
CyCentra 360  (172.16.0.3)
  Flask :5252
  • /api/cymind/chat/stream  ←── overlay sends chat here (same-origin proxy)
  • /api/system/cymind       ←── admin configure / enable
  • /mcp/sse                 ←── CyMind reads live SIEM data (cymk_... key)
    │                                              ▲
    │  HTTP  (server-to-server)                    │ SSE  (cymk_... key)
    ▼                                              │
CyMind  (172.16.0.2:8080)
  FastAPI :8000
  • /api/v1/chat/stream      ←── Flask proxy forwards analyst questions
  • /api/v1/admin/activate-cycentra  ←── auto-provision during Enable
```

**Two keys (auto-managed by the Enable flow):**

| Key | Direction | Purpose |
|---|---|---|
| `cymk_…` | CyMind → CyCentra `/mcp/sse` | M2M: CyMind fetches live SIEM data |
| `pak_…`  | CyCentra proxy → CyMind | Chat auth: proxy authenticates the overlay |

---

## Setup — One-Click Enable (Recommended)

This is the recommended path. No manual steps in CyMind are needed.

### Prerequisites

| Requirement | Notes |
|---|---|
| CyCentra 360 v1.0.241+ | This integration ships with that release |
| CyMind running at 172.16.0.2:8080 | Check with `curl http://172.16.0.2:8080/health` |
| `mcp[cli]` in CyCentra correlation engine | `pip install 'mcp[cli]'` in the engine venv |
| CyMind admin credentials | You need the email + password of a CyMind admin user |

### Steps

**1.** Log in to **CyCentra 360** as admin.

**2.** Go to **System Settings → CyMind** tab.

**3.** Fill in the enable form:
- **CyMind URL**: `http://172.16.0.2:8080`
- **CyMind Admin Email**: your CyMind admin email (e.g. `admin@cymind.local`)
- **CyMind Admin Password**: your CyMind admin password

**4.** Click **Enable Integration**.

CyCentra will automatically:
- Generate the `cymk_…` M2M key and save it
- Log in to CyMind using the provided credentials
- Create a `cycentra-portal@internal` analyst service account in CyMind (idempotent)
- Generate a `pak_…` API key for that account and save it
- Configure CyMind's CYCENTRA_URL and CYCENTRA_API_KEY at runtime (no restart needed)
- Inject the nginx reverse-proxy block for `/cymind/`

**5.** Click **Test Connection** to verify all three checks pass (CyMind reachable, MCP engine, chat key set).

**6.** Log in as an **analyst** or **admin** — the green brain FAB button appears at the bottom-right.

**7.** Click the FAB and try one of the [suggested test questions](#suggested-test-questions) below.

---

## Manual Setup (Fallback)

Use this if the one-click enable fails (e.g. network restrictions between CyCentra and CyMind admin API).

### Step 1 — CyCentra: generate the M2M key

1. Log in to **CyCentra 360** as admin → System Settings → CyMind.
2. Enter CyMind URL: `http://172.16.0.2:8080`
3. Expand **Advanced / Manual Key Management**.
4. Click **Generate M2M Key** → copy the `cymk_…` key (shown once).

### Step 2 — CyMind: configure CYCENTRA connection

In CyMind's `.env`:
```dotenv
CYCENTRA_URL=http://172.16.0.3
CYCENTRA_API_KEY=cymk_YOUR_KEY_HERE
```

Restart CyMind:
```bash
docker compose restart cymind
```

Verify MCP bridge:
```bash
# Should return 401 (key guard active, not open)
curl -s http://172.16.0.2:8080/mcp/sse

# Should open an SSE stream
curl -s -H "Authorization: Bearer cymk_YOUR_KEY" http://172.16.0.2:8080/mcp/sse
```

### Step 3 — CyMind: create portal service account and get chat key

1. Log in to CyMind as admin.
2. Create a user:
   - **Email**: `cycentra-portal@internal`
   - **Role**: `analyst`
3. Log in as that user → **API Keys → Generate API Key** → copy the `pak_…` key.

### Step 4 — CyCentra: paste the chat key

1. System Settings → CyMind → Advanced / Manual Key Management.
2. Paste the `pak_…` key into the Manual Chat Key field → **Save**.

---

## Key Rotation

### Rotate the chat key (`pak_…`)

1. In CyMind: go to the `cycentra-portal@internal` user → API Keys → revoke old key → generate new.
2. Copy the new `pak_…` key.
3. In CyCentra: System Settings → CyMind → Advanced → Manual Chat Key → paste → Save.

OR: re-run **Enable Integration** — it revokes the old key and issues a fresh one automatically.

### Rotate the M2M key (`cymk_…`)

1. In CyCentra: System Settings → CyMind → Advanced → Rotate M2M Key → copy the new `cymk_…`.
2. Update `CYCENTRA_API_KEY` in CyMind `.env` → `docker compose restart cymind`.

OR: re-run **Enable Integration** — it generates a new M2M key and calls CyMind to update it.

---

## Suggested Test Questions

Use these in the CyMind chat overlay after enabling the integration to verify each data source:

**General SIEM health**
```
How many open incidents do we have? Give me a quick summary.
```

**Incident investigation**
```
Show me the most critical open incidents with their MITRE ATT&CK tactics.
```
```
What happened with incident INC-0042? Give me the full timeline.
```

**Alert analysis**
```
List the latest alerts from the last hour and group them by severity.
```

**Risk scoring**
```
Which entities have the highest risk scores right now? Why are they high risk?
```

**UEBA / insider threat**
```
Are there any users with anomalous behaviour this week? What did they do?
```

**Endpoint / Wazuh**
```
Which Wazuh agents are currently disconnected or unhealthy?
```
```
What are the top vulnerabilities on host LAPTOP-JOHN? Include CVE numbers and CVSS scores.
```

**Containment (analyst-requested only)**
```
I want to isolate host LAPTOP-JOHN from the network. Walk me through the steps.
```

---

## Access Control

| Role | Chat FAB visible | Live SIEM data |
|---|---|---|
| admin | ✓ | ✓ |
| analyst | ✓ | ✓ |
| developer | ✗ | ✗ |
| viewer | ✗ | ✗ |

Enforcement layers:
- **Frontend**: FAB only rendered for `role === "analyst" || "admin"`.
- **CyCentra proxy** (`/api/cymind/chat/stream`): requires analyst+ CyCentra session.
- **MCP bridge** (correlation engine): rejects requests without valid `cymk_…` key.
- **CyMind chat router**: `use_mcp` only honoured for analyst/admin roles.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| "Enable Integration" → "Cannot reach CyMind" | Wrong URL or port | Check `http://172.16.0.2:8080/health` from CyCentra server |
| "Enable Integration" → CyMind login failed | Wrong admin credentials | Verify CyMind admin email/password |
| FAB not visible after enable | User role is viewer/developer | Log in with an analyst or admin account |
| Chat opens but returns "not fully set up" | Chat key missing | Re-run Enable Integration or paste manually in Advanced |
| Chat replies but no live SIEM data | MCP not connected | Click Test Connection — check MCP Engine row; verify cymk_… key in CyMind |
| Test Connection: MCP Engine ✗ | Correlation engine not running | `sudo systemctl status cysiemstack-engine` |
| "CyMind returned HTTP 401" in proxy logs | Chat key invalid or expired | Re-run Enable Integration to refresh keys |
| Chat works but containment tools fail | Wazuh active-response not configured | Check Wazuh manager AR settings |

---

## API Reference

### CyCentra 360

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/system/cymind/enable` | admin | One-click enable: logs into CyMind, provisions portal user, saves keys |
| `GET` | `/api/system/cymind` | analyst+ | Read config; `hasChatKey` / `hasKey` flags |
| `POST` | `/api/system/cymind` | admin | Save URL, generate M2M key, paste/clear chat key |
| `GET` | `/api/system/cymind/test` | analyst+ | Test CyMind + MCP engine + chat key |
| `POST` | `/api/cymind/chat/stream` | analyst+ | SSE proxy to CyMind chat endpoint |

### CyMind

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/admin/activate-cycentra` | admin JWT | Auto-provision portal user, configure CYCENTRA connection, return pak_… |
| `GET` | `/api/v1/admin/activate-cycentra/status` | admin JWT | Check activation status |
| `POST` | `/api/v1/chat/stream` | pak_… or JWT | SSE streaming chat (called via CyCentra proxy) |

### Available MCP Tools

| Tool | Keywords that trigger it |
|---|---|
| `get_stats` | always included |
| `list_incidents` | incident, breach, attack, mitre, kill chain, malware, ransomware |
| `get_incident` | specific incident ID |
| `list_alerts` | alert, event, log |
| `list_risk_scores` | risk, score, entity, high-risk |
| `list_ueba_users` | ueba, user, anomaly, insider, behaviour |
| `get_ueba_anomalies` | specific user anomaly detail |
| `wazuh_list_agents` | agent, endpoint, host, wazuh, sensor |
| `wazuh_active_response` | containment, isolate, block, respond |
| `wazuh_get_agent_vulnerabilities` | vulnerability, cve, cvss, patch, exploit |
