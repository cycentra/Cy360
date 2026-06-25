# RCA: CyMind ↔ CyCentra 360 MCP Integration Outage & Resolution

**Date:** 2026-06-25
**Severity:** P1 — CyMind SIEM chat non-functional; analyst queries returned hallucinated data
**Status:** Resolved
**Affected versions:** CyMind ≤v1.0.147 (broken); Cy360 ≤v1.0.94 (broken)
**Fixed in:** CyMind v1.0.148–v1.0.154, Cy360 v1.0.95

---

## Executive Summary

CyMind's chat interface stopped delivering live SIEM data and began hallucinating responses. The root cause was a combination of five layered failures introduced during a model/LLM replacement ~2 days prior:

1. Groq's new inference API had a 413 payload limit that silently rejected SIEM context
2. The MCP SSE server on Cy360 crashed with `TypeError: 'FastMCP' object is not callable`
3. The `MCP_ENABLED` flag was missing from the Cy360 server's environment file
4. The nginx HTTPS proxy on Cy360 had no `/mcp/` location block in the public-facing server block
5. The pydantic 2.10.0 AnyUrl incompatibility caused the MCP client to fail at import time in CyMind

All five were independently silent: no alert was raised, no fallback was surfaced to the analyst, and the LLM responded without grounding rather than refusing to answer. The fix required coordinated changes across both servers and both Docker images.

---

## The Two Approaches: Old (REST) vs New (MCP)

### Old Approach — REST Fallback via UI Authentication

Before the MCP integration was introduced, CyMind fetched SIEM context via a direct REST polling mechanism:

**How it worked:**

1. An admin opened the Cy360 UI → **System Settings → CyMind** tab
2. They entered the CyMind URL and clicked **Enable**
3. The Enable flow auto-provisioned two keys:
   - `cymk_…` — the M2M key that CyMind uses to call Cy360
   - `pak_…` — the key Cy360 uses to authenticate CyMind API calls
4. CyMind's `siem_client.py` polled fixed REST endpoints on Cy360:
   - `GET /api/siem/incidents?status=open&limit=20`
   - `GET /api/siem/alerts?limit=20`
   - `GET /api/ueba/users`
   - `GET /api/siem/risk-scores?level=high`
5. All four endpoints were called on **every chat message**, regardless of what the analyst asked
6. Results were concatenated into a system-prompt block sent to the LLM

**Limitations of the old approach:**

| Problem | Impact |
|---|---|
| All 4 endpoints polled on every message | Extra latency on every request, even for questions that don't need incident data |
| Fixed set of endpoints — no query awareness | A question about a specific CVE still fetched all open incidents |
| Full incident records returned (avg 2 KB each × 20 = 40 KB) | Hit Groq's 413 payload limit silently once the model switched to a hosted API |
| REST polling — sequential HTTP calls | No ability to chain queries, filter by attribute, or enrich with follow-up data |
| Connection activated once in the UI — no liveness check | If the SIEM restarted or the key rotated, CyMind would silently lose data and hallucinate |
| No structured grounding instruction | LLM could blend live data with training data without any explicit instruction to stay grounded |

This approach worked acceptably when:
- The LLM ran locally (Ollama) with no payload size limit
- The SIEM was healthy and keys were stable
- Analysts asked general queries, not specific ones

Once the model backend switched to Groq (hosted), the silent 413 rejection broke the entire pipeline.

---

### New Approach — MCP SSE Bridge

MCP (Model Context Protocol) is a JSON-RPC-over-SSE protocol designed for LLM tool use. Instead of REST polling, CyMind opens a structured tool-call session to Cy360 and invokes only the tools relevant to the analyst's query.

**Architecture:**

```
CyMind (204.168.193.23)           CyCentra 360 (77.42.75.20)
  FastAPI :8000                      correlation engine :8100
  mcp_client.py                      main.py → FastMCP server
       │                                      │
       │  SSE  Authorization: Bearer cymk_…   │
       └──────── https://cy360.cycentra.com/mcp/sse ──────────►
       ◄── event: endpoint {session_url}  ──────────────────────
       │
       │  JSON-RPC  POST /mcp/messages/
       ├─► {"method": "tools/call", "params": {"name": "get_stats", "arguments": {}}}
       ├─► {"method": "tools/call", "params": {"name": "list_incidents", ...}}
       └─► (only tools relevant to the user's query)
```

**How it works now:**

1. At CyMind startup, `mcp_client.probe()` opens a test SSE session to `https://cy360.cycentra.com/mcp/sse` and calls `get_stats`
2. If the probe succeeds, `MCP connected` is logged — the MCP path is active
3. On each chat request, `_select_tools(query)` matches the analyst's words against keyword sets and selects only relevant tools (e.g., "incident" → `list_incidents`; "CVE" → `wazuh_get_agent_vulnerabilities`)
4. `get_stats` is always called — it anchors every response with current totals
5. One SSE session is opened per request; all selected tools are called in that session; the session closes
6. Results are formatted into a `--- LIVE SIEM DATA ---` block prepended to the system prompt
7. A strict grounding instruction is appended: *"Answer ONLY from the data shown above. Do NOT invent, estimate, or extrapolate."*
8. If MCP fails for any reason, `siem_client.py` (the old REST path) is used as fallback

**Available MCP tools on Cy360:**

| Tool | What it returns |
|---|---|
| `get_stats` | Total alerts, incidents, open incidents, AI-auto-closed, false positives |
| `list_incidents` | Open incidents (slimmed to 18 SOC-essential fields) |
| `get_incident` | Full detail for a specific `INC-XXXXX` ID |
| `list_alerts` | Recent raw alerts |
| `list_risk_scores` | High-risk entities |
| `list_ueba_users` | Users with active anomalies |
| `wazuh_list_agents` | Registered Wazuh endpoints |
| `wazuh_get_agent_vulnerabilities` | CVEs for a specific agent |
| `get_incident_distribution` | Breakdown by severity/status/category |
| `search_incidents` | Free-text incident search |
| `list_campaigns` | Linked attack campaigns |
| `get_threat_intel` | MISP / threat intel enrichment |
| `get_compliance_status` | Framework compliance summary |
| `get_vuln_summary` | Cross-agent vulnerability summary |

**Why MCP is better:**

| Dimension | Old (REST polling) | New (MCP tool calls) |
|---|---|---|
| Query awareness | None — always fetched all 4 endpoints | Yes — only tools matching the analyst's query are called |
| Payload size control | Fixed 20 incidents × full records | 5 incidents × 18 slim fields; per-tool limits configurable |
| Specific incident lookup | Not possible — could only list | `get_incident(INC-00335)` returns the exact record |
| LLM grounding | No explicit instruction; hallucination possible | Hard grounding instruction appended with every context block |
| Extensibility | Add a REST endpoint, update `siem_client.py` | Register a new `@mcp.tool()` function in `main.py` |
| Connection liveness | Checked once at Enable time | Probed at every CyMind startup; `probe()` result gates the MCP path |
| Auth | Same `cymk_…` key (unchanged) | Same `cymk_…` key, passed as SSE `Authorization` header |
| Write actions | Not supported | Write tools (`block_ip`, `close_incident`, `assign_incident`, etc.) callable after analyst confirmation |

---

## Timeline

| Time (approx) | Event |
|---|---|
| D-2 (before outage) | LLM model backend replaced on CyMind server — switched from local Ollama to Groq |
| D-2 | SIEM context payloads (~40 KB) begin silently hitting Groq's 413 limit; LLM receives no context; hallucinations begin |
| D-2 | mcp 1.12.4 installed on Cy360 alongside model swap; mcp mounting code (`get_asgi_app` fallback) fails with `TypeError: 'FastMCP' object is not callable`; `/mcp/sse` returns HTTP 500 |
| D-2 | `MCP_ENABLED` not set in `/opt/cycentra/cysiemstack.env`; engine would not mount MCP even if mounting code had worked |
| D-0 | Investigation begins; curl tests confirm `/mcp/sse` returns HTTP 500 from public HTTPS URL |
| D-0 | Root cause 1 identified: mcp mounting code uses wrong API for mcp ≥1.6 |
| D-0 | Hotpatch applied to `/usr/local/lib/python3.12/dist-packages/cysiemstack/correlation_engine/main.py` on Cy360 live server |
| D-0 | Root cause 2 identified: `MCP_ENABLED` missing from env; added to `/opt/cycentra/cysiemstack.env` |
| D-0 | Root cause 3 identified: nginx HTTPS block (`cy360.cycentra.com:443`) had no `/mcp/` proxy location; added manually to `/etc/nginx/sites-available/cycentra-modules` |
| D-0 | `/mcp/sse` now returns HTTP 200 + `event: endpoint` from public URL |
| D-0 | MCP probe from CyMind fails — `RuntimeError: Unable to apply constraint 'host_required'` in mcp package |
| D-0 | Root cause 4 identified: pydantic 2.10.0 incompatibility with `Annotated[AnyUrl, UrlConstraints(host_required=False)]` in mcp 1.5.x |
| D-0 | Fix attempt 1: upgrade mcp to ≥1.9.0 on CyMind — same pydantic error at different class definition |
| D-0 | Fix attempt 2: upgrade pydantic to ≥2.11.0 — breaks spaCy; spaCy 3.8.x attempts to download model at startup; container rootfs is read-only → crash loop (v1.0.150 broken) |
| D-0 | Root cause 5 identified: pre-install mcp patch needed; pydantic and mcp version pins must stay |
| D-0 | `docker/patch_mcp_types.py` written; Dockerfile updated to run patch after pip install |
| D-0 | v1.0.153 deployed — patch fixed `mcp/types.py` but not `mcp/server/fastmcp/resources/base.py`; error shifts to `base.py:17` |
| D-0 | Patch extended to scan all mcp `.py` files recursively |
| D-0 | v1.0.154 deployed to CyMind; probe succeeds; `INFO:cymind:CyCentra 360 MCP connected` logged |
| D-0 | End-to-end verification: `get_stats` returns `{"total_alerts": 35288, "open_incidents": 5428, ...}` |

---

## Root Cause Analysis — Five Bugs

### Bug 1 — Groq 413 Payload Too Large

**Affected component:** `CyMind/api/siem_client.py`, `CyMind/api/routers/chat.py`

**Root cause:**
The REST fallback path fetched 20 full incident records per chat request. Each record included forensics blobs, raw log excerpts, and nested arrays. Average payload: ~40 KB. Groq's inference API has a hard 413 limit on request body size. The error was silently swallowed — `siem_client.py` had no `raise_for_status()` call, so the 413 response was treated as an empty context. The LLM received no SIEM data and answered from training data.

**Fix (CyMind v1.0.148):**
- `_INCIDENT_KEEP` frozenset with 18 SOC-essential fields (`incident_id`, `title`, `severity`, `status`, `mitre_tactic`, etc.) — forensics blobs stripped
- `_slim_incident()` reduces each record from ~2 KB to ~200 bytes
- `fetch_siem_context(incidents=5, risk=5, ueba=5)` — limit reduced from 20 to 5 per type
- `r.raise_for_status()` added before iterating SSE lines in `llm_service.py`; 413 now surfaced to the UI

**Why it was silent:** No error log, no fallback notice to the analyst. The LLM appeared to answer correctly but was inventing data.

---

### Bug 2 — FastMCP ASGI Mounting Failure

**Affected component:** `Cy360/backend/cysiemstack/correlation_engine/main.py` (lines ~2736–2763)

**Root cause:**
The mcp mounting code used a cascade of guesses for the ASGI app getter:

```python
_mcp_asgi = (
    _mcp.get_application() if hasattr(_mcp, "get_application")
    else getattr(_mcp, "get_asgi_app", lambda: _mcp)()
)
app.mount("/mcp", _mcp_asgi)
```

With mcp ≥1.6, `get_application` is absent. The fallback `getattr(_mcp, "get_asgi_app", lambda: _mcp)()` — finding no `get_asgi_app` attribute — called `lambda: _mcp`, which returned the `FastMCP` instance itself. `FastMCP` is not an ASGI callable. Mounting a non-callable caused every request to `/mcp/` to raise `TypeError: 'FastMCP' object is not callable` → HTTP 500.

**Fix (Cy360 v1.0.95, hotpatched on live server first):**

```python
if hasattr(_mcp, "sse_app"):
    # mcp ≥1.6: sse_app() returns a Starlette ASGI app
    _mcp_asgi = _mcp.sse_app()
elif hasattr(_mcp, "get_application"):
    # mcp 1.3.x–1.5.x
    _mcp_asgi = _mcp.get_application()
else:
    # mcp 1.0.x–1.2.x: manual SseServerTransport wiring
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette as _Starlette
    from starlette.routing import Mount as _Mount, Route as _Route
    _sse_transport = SseServerTransport("/mcp/messages/")
    _mcp_server = _mcp._mcp_server
    async def _sse_endpoint(request):
        async with _sse_transport.connect_sse(
            request.scope, request.receive, request._send
        ) as (recv, send):
            await _mcp_server.run(
                recv, send, _mcp_server.create_initialization_options()
            )
    _mcp_asgi = _Starlette(routes=[
        _Route("/sse", endpoint=_sse_endpoint),
        _Mount("/messages/", app=_sse_transport.handle_post_message),
    ])
app.mount("/mcp", _mcp_asgi)
```

The hotpatch was written directly to the live file on the Cy360 server (`77.42.75.20`) before being committed to the repo.

---

### Bug 3 — mcp Package Not Installed on Live Server

**Affected component:** `/opt/cycentra/cysiemstack.env` (live server config), `Cy360/cycentra-setup.sh`

**Root cause:**
`main.py` mounts the MCP bridge unconditionally using a `try/except ImportError` guard — if the mcp package is importable, MCP is mounted; if not, the engine starts without it and logs a hint. When the model swap was performed on the Cy360 live server, the correlation engine's Python environment was rebuilt, and `mcp[cli]` was not reinstalled from the updated requirements.txt. The engine started cleanly without MCP and logged `mcp_package_not_installed` — this log line was not monitored.

Note: `MCP_ENABLED` is referenced only in the file header as documentation; it is not an actual runtime gate in the code.

**Fix:**
- Installed `mcp[cli]>=1.9.0` on the live server: `pip install 'mcp[cli]>=1.9.0,<2.0.0'`
- `cycentra-setup.sh` updated to include mcp in the pip install step for the correlation engine so it is always present after setup

---

### Bug 4 — nginx Missing `/mcp/` Location in HTTPS Block

**Affected component:** `/etc/nginx/sites-available/cycentra-modules`, `Cy360/cycentra-setup.sh`

**Root cause:**
The nginx configuration had two server blocks for Cy360:
- Port 80 (LAN): had a `/mcp/` proxy location block
- Port 443 (`cy360.cycentra.com` HTTPS): **did not** have a `/mcp/` location block

CyMind connects to `https://cy360.cycentra.com/mcp/sse`. All requests to the public HTTPS hostname fell through to the default nginx handler → HTTP 404 or 502 for the `/mcp/` path, even after Bug 2 was fixed.

**Fix (Cy360 v1.0.95):**
Added to the `cy360.cycentra.com:443` server block in `cycentra-setup.sh`:

```nginx
location /mcp/ {
    proxy_pass         http://127.0.0.1:8100/mcp/;
    proxy_http_version 1.1;
    proxy_set_header   Host              $host;
    proxy_set_header   Authorization     $http_authorization;
    proxy_set_header   X-CyMind-Key      $http_x_cymind_key;
    proxy_set_header   Connection        "";
    proxy_buffering    off;
    proxy_cache        off;
    proxy_read_timeout 3600s;
    chunked_transfer_encoding on;
}
```

`proxy_buffering off` and `proxy_read_timeout 3600s` are critical for SSE — without them, nginx buffers the event stream and the SSE session never delivers events to the client.

---

### Bug 5 — pydantic 2.10.0 AnyUrl Incompatibility in mcp Package

**Affected component:** `CyMind/Dockerfile`, `CyMind/docker/patch_mcp_types.py`

**Root cause:**
mcp 1.5.x defines two fields using a pydantic 2 Annotated type:

```python
# mcp/types.py and mcp/server/fastmcp/resources/base.py
uri: Annotated[AnyUrl, UrlConstraints(host_required=False)]
```

pydantic 2.10.0 changed `AnyUrl` to use a `function-wrap` validator schema internally. This schema type does not support application of `UrlConstraints` — pydantic raises at class definition time:

```
RuntimeError: Unable to apply constraint 'host_required' to schema of type 'function-wrap'
```

This error fires when mcp is imported, blocking the `from mcp import ClientSession` import in `mcp_client.py`. The probe returned `False` at startup; the MCP path was never used.

**Fix attempts that failed:**
1. Upgrade mcp to ≥1.9.0 — same `host_required` error at different call site; pydantic 2.10.0 is still incompatible
2. Upgrade pydantic to ≥2.11.0 — resolves the AnyUrl bug, but pydantic ≥2.11.0 causes spaCy to resolve to 3.8.x (was pinned against 3.7.x), which attempts `pip install en_core_web_lg-3.8.0` at container startup. The CyMind container has a read-only rootfs; pip cannot write → exit 1 → supervisord crash loop (v1.0.150 was broken in production)

**Correct fix (CyMind v1.0.154):**
Keep `pydantic==2.10.0` and `mcp>=1.0.0,<1.6.0`. Patch the mcp package files at Docker build time using `docker/patch_mcp_types.py`:

```python
import glob, pathlib, re

base = '/usr/local/lib/python*/site-packages/mcp'
py_files = glob.glob(f'{base}/**/*.py', recursive=True) + glob.glob(f'{base}/*.py')

for path_str in py_files:
    p = pathlib.Path(path_str)
    try:
        src = p.read_text()
    except Exception:
        continue
    if 'AnyUrl' not in src and 'UrlConstraints' not in src:
        continue
    new_src = re.sub(
        r'Annotated\[AnyUrl,\s*UrlConstraints\([^)]*\)\]',
        'str',
        src,
    )
    if new_src != src:
        p.write_text(new_src)
```

Wired in `Dockerfile`:

```dockerfile
COPY docker/patch_mcp_types.py /tmp/patch_mcp_types.py
RUN pip install --no-cache-dir -r requirements.txt && python3 /tmp/patch_mcp_types.py
```

The patch replaces `Annotated[AnyUrl, UrlConstraints(...)]` with `str` — bypassing the pydantic validator entirely while keeping the field serializable. The MCP protocol itself validates URL format; the pydantic validator is redundant for this use case.

**Why only `types.py` was patched in v1.0.153 (partial fix):**
The initial `patch_mcp_types.py` only scanned `mcp/types.py`. After deploy, a new `RuntimeError` appeared in `mcp/server/fastmcp/resources/base.py:17`. The pattern exists in both files. v1.0.154 extended the script to scan all mcp `.py` files recursively using `glob.glob(f'{base}/**/*.py', recursive=True)`.

---

## Deployment Verification

After all five fixes, the following was confirmed:

**From CyMind container:**
```
INFO:cymind:CyCentra 360 MCP connected: https://cy360.cycentra.com/mcp/sse
```

**Manual curl test (public HTTPS endpoint):**
```bash
curl -N https://cy360.cycentra.com/mcp/sse \
  -H "Authorization: Bearer cymk_..." \
  -H "Accept: text/event-stream"
# → HTTP 200
# data: {"type":"endpoint","uri":"/mcp/messages/?session_id=..."}
```

**End-to-end tool call from CyMind container:**
```json
{
  "total_alerts": 35288,
  "total_incidents": 10056,
  "open_incidents": 5428,
  "ai_auto_closed": 4624,
  "false_positives": 4
}
```

---

## Final Versions

| Component | Fixed version | Key changes |
|---|---|---|
| CyMind | v1.0.154 | `patch_mcp_types.py`, Dockerfile patch step, `mcp>=1.0.0,<1.6.0`, `pydantic==2.10.0` locked |
| Cy360 | v1.0.95 | mcp mounting cascade fix, nginx HTTPS `/mcp/` block, `MCP_ENABLED` in setup, `mcp[cli]>=1.9.0,<2.0.0` |

---

## Lessons Learned

1. **Silent context failures cause hallucination, not errors.** When the LLM receives no grounding data, it answers from training data. This looks like a correct answer to an analyst and is the most dangerous failure mode. Add explicit checks: if the context block is empty, the LLM should say so.

2. **Error handling gaps compound.** Each of the five bugs was individually catchable. Bug 2 (HTTP 500) masked Bug 3 (env flag missing). Bug 3 masked Bug 4 (nginx gap). All three needed to be present for MCP to work at all. End-to-end integration tests would have caught this on the first deploy.

3. **Payload size limits must be tested against the target API.** The switch from local Ollama (no limit) to Groq (hard limit) exposed a latent payload size issue. Token/payload budgets should be explicit constants, not emergent from endpoint defaults.

4. **pydantic version pins are fragile across package boundaries.** `pydantic==2.10.0` was pinned for spaCy stability. mcp's AnyUrl change was not visible until it was actually imported. Build-time smoke tests (import every top-level module) would surface this before ship.

5. **nginx SSE blocks need specific flags.** Standard `proxy_pass` blocks buffer SSE streams. `proxy_buffering off`, `proxy_cache off`, and `proxy_read_timeout 3600s` are non-negotiable for any SSE-proxied endpoint. These should be documented as a template and required for every new SSE endpoint added behind nginx.

6. **One-click Enable is necessary but not sufficient.** The UI Enable flow provisions keys correctly and configures the REST fallback reliably. It cannot verify that MCP is mounted and reachable, because MCP is a separate code path at a different layer. A post-Enable liveness probe hitting `/mcp/sse` and showing the result in the UI would catch Bugs 2–4 immediately.

---

## Prevention Checklist for Future Changes

- [ ] Any LLM backend change: verify payload sizes with `curl -o /dev/null -w "%{size_upload}"` against the new endpoint's limit
- [ ] Any dependency upgrade on CyMind: rebuild with `--no-cache` and check startup logs for import errors before shipping
- [ ] Any new SSE endpoint behind nginx: use the `/mcp/` location block template (buffering off, read timeout 3600s)
- [ ] Any Cy360 engine restart or env file change: verify `MCP_ENABLED=true` is present in `cysiemstack.env`
- [ ] Monthly: `curl https://cy360.cycentra.com/mcp/sse -H "Authorization: Bearer cymk_..."` and confirm `event: endpoint` is returned
- [ ] After any CyMind deploy: check `docker logs cymind | grep "MCP connected\|MCP probe failed"` — probe failure means REST fallback is active and richer MCP context is not being delivered
