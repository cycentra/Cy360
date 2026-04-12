"""
mcp_server/server.py — CySIEM Security MCP Server

Exposes a Model Context Protocol (MCP) server over HTTP/SSE on port 8101.
External AI clients (Claude Desktop, OpenAI, etc.) connect to this server
and gain structured access to CyCentra 360's security data and Wazuh
active-response capabilities — no custom glue code required.

Config is sourced automatically from /opt/cycentra/cysiemstack.env.

Exposed tools
─────────────
Correlation engine (via http://127.0.0.1:8100):
  get_stats                   — SIEM overview statistics
  list_incidents              — Security incidents with optional filters
  get_incident                — Full incident details (MITRE, UEBA, LLM summary)
  list_alerts                 — Raw ingested Wazuh alerts
  list_risk_scores            — Entity risk scores
  list_ueba_users             — Users tracked by UEBA
  get_ueba_anomalies          — Baseline + anomaly history for one user

Wazuh Manager API (direct, credentials from cysiemstack.env):
  wazuh_list_agents           — Enumerate registered endpoints
  wazuh_active_response       — Trigger AR action on an agent
  wazuh_get_agent_vulnerabilities — Known CVEs on an agent
"""
from __future__ import annotations

import base64
import json
import os
from typing import Optional

import httpx
import structlog
from mcp.server.fastmcp import FastMCP

from config import get_settings

log = structlog.get_logger()
settings = get_settings()

# ── MCP server instance ────────────────────────────────────────────────────────
mcp = FastMCP(
    "CySIEM Security MCP",
    instructions=(
        "You are a security operations assistant with live access to CyCentra 360. "
        "Use the provided tools to investigate incidents, inspect UEBA behavioural "
        "anomalies, query entity risk scores, enumerate Wazuh endpoints, and trigger "
        "active-response containment actions. Always confirm agent IDs before running "
        "active-response commands."
    ),
)


# ── Internal helpers ───────────────────────────────────────────────────────────

async def _engine_get(path: str, params: dict | None = None) -> dict:
    """Perform a GET request to the correlation engine."""
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{settings.engine_url}{path}", params=params or {})
        r.raise_for_status()
        return r.json()


async def _wazuh_token() -> str:
    """Authenticate with the Wazuh Manager API and return a JWT token."""
    creds = base64.b64encode(
        f"{settings.wazuh_api_user}:{settings.wazuh_api_password}".encode()
    ).decode()
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        r = await client.get(
            f"{settings.wazuh_api_url}/security/user/authenticate",
            headers={"Authorization": f"Basic {creds}"},
        )
        r.raise_for_status()
        return r.json()["data"]["token"]


async def _wazuh_get(path: str, params: dict | None = None) -> dict:
    """Authenticated GET to the Wazuh Manager API."""
    token = await _wazuh_token()
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        r = await client.get(
            f"{settings.wazuh_api_url}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params or {},
        )
        r.raise_for_status()
        return r.json()


async def _wazuh_put(path: str, body: dict | None = None, params: dict | None = None) -> dict:
    """Authenticated PUT to the Wazuh Manager API."""
    token = await _wazuh_token()
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        r = await client.put(
            f"{settings.wazuh_api_url}{path}",
            headers={"Authorization": f"Bearer {token}"},
            json=body or {},
            params=params or {},
        )
        r.raise_for_status()
        return r.json()


# ── Correlation engine tools ───────────────────────────────────────────────────

@mcp.tool()
async def get_stats() -> str:
    """Return high-level SIEM statistics: total incidents, alerts processed,
    active anomalies, and engine uptime."""
    data = await _engine_get("/stats")
    return json.dumps(data, indent=2)


@mcp.tool()
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 20,
) -> str:
    """List security incidents from the correlation engine.

    Args:
        status:   Filter by lifecycle status.
                  Values: open | investigating | resolved | false_positive
        severity: Filter by severity level.
                  Values: low | medium | high | critical
        limit:    Maximum number of incidents to return (1–100, default 20).
    """
    limit = max(1, min(limit, 100))
    params: dict = {"limit": limit}
    if status:
        params["status"] = status
    if severity:
        params["severity"] = severity
    data = await _engine_get("/incidents", params=params)
    return json.dumps(data, indent=2)


@mcp.tool()
async def get_incident(incident_id: str) -> str:
    """Get full details for a specific security incident.

    Returns correlated rules, UEBA flags, MITRE ATT&CK tactic/kill-chain
    mapping, LLM-generated summary, and recommended remediation steps.

    Args:
        incident_id: Incident identifier (e.g. INC-0042).
    """
    data = await _engine_get(f"/incidents/{incident_id}")
    return json.dumps(data, indent=2)


@mcp.tool()
async def list_alerts(
    incident_id: Optional[str] = None,
    limit: int = 50,
) -> str:
    """List raw Wazuh alerts ingested by the correlation engine.

    Args:
        incident_id: Restrict to alerts belonging to a specific incident.
        limit:       Maximum number of alerts to return (1–200, default 50).
    """
    limit = max(1, min(limit, 200))
    params: dict = {"limit": limit}
    if incident_id:
        params["incident_id"] = incident_id
    data = await _engine_get("/alerts", params=params)
    return json.dumps(data, indent=2)


@mcp.tool()
async def list_risk_scores(
    entity_type: Optional[str] = None,
    level: Optional[str] = None,
    limit: int = 20,
) -> str:
    """Return entity risk scores ranked by current threat level.

    Args:
        entity_type: Filter by entity type. Values: user | host | ip
        level:       Filter by risk band. Values: low | medium | high | critical
        limit:       Maximum number of results (1–100, default 20).
    """
    limit = max(1, min(limit, 100))
    params: dict = {"limit": limit}
    if entity_type:
        params["entity_type"] = entity_type
    if level:
        params["level"] = level
    data = await _engine_get("/risk-scores", params=params)
    return json.dumps(data, indent=2)


@mcp.tool()
async def list_ueba_users(
    category: Optional[str] = None,
    has_anomaly: Optional[bool] = None,
    top_activity: Optional[int] = None,
) -> str:
    """List users tracked by UEBA with their behavioural baseline profiles.

    Args:
        category:     Filter by account type. Values: system | service | human
        has_anomaly:  If true, return only users with at least one active anomaly.
        top_activity: If set, return the top N users by average daily event count.
    """
    params: dict = {}
    if category:
        params["category"] = category
    if has_anomaly is not None:
        params["has_anomaly"] = str(has_anomaly).lower()
    if top_activity is not None:
        params["top_activity"] = top_activity
    data = await _engine_get("/ueba/users", params=params)
    return json.dumps(data, indent=2)


@mcp.tool()
async def get_ueba_anomalies(username: str) -> str:
    """Get the UEBA baseline and full anomaly history for a specific user.

    Returns the behavioural baseline (typical hours, agents, fail rates) and
    a list of detected anomalies with severity, type, and triggering alert context.

    Args:
        username: Exact username to investigate (case-sensitive).
    """
    data = await _engine_get(f"/ueba/{username}")
    return json.dumps(data, indent=2)


# ── Wazuh Manager API tools ────────────────────────────────────────────────────

@mcp.tool()
async def wazuh_list_agents(
    status: Optional[str] = None,
    limit: int = 25,
) -> str:
    """List Wazuh agents (monitored endpoints) registered with the manager.

    Args:
        status: Filter by connection status.
                Values: active | disconnected | never_connected | pending
        limit:  Maximum number of agents to return (1–500, default 25).
    """
    limit = max(1, min(limit, 500))
    params: dict = {
        "limit": limit,
        "select": "id,name,ip,status,os,version,lastKeepAlive",
    }
    if status:
        params["status"] = status
    data = await _wazuh_get("/agents", params=params)
    agents = data.get("data", {}).get("affected_items", [])
    return json.dumps({"agents": agents, "total": len(agents)}, indent=2)


@mcp.tool()
async def wazuh_active_response(
    agent_id: str,
    command: str,
    arguments: Optional[list[str]] = None,
) -> str:
    """Trigger a Wazuh active-response action on a specific endpoint.

    Use this to contain threats — for example block a source IP, disable a
    compromised account, or restart the Wazuh agent process. Active-response
    commands must be defined in ossec.conf on the manager.

    Common commands: firewall-drop, disable-account, restart-wazuh

    Args:
        agent_id:  Wazuh agent ID (e.g. "001"). Use wazuh_list_agents to look up IDs.
        command:   Active-response command name (must match ossec.conf definition).
        arguments: Optional list of command arguments (e.g. ["192.168.1.100"]).
    """
    body: dict = {"command": command, "arguments": arguments or []}
    data = await _wazuh_put(
        "/active-response",
        body=body,
        params={"agents_list": agent_id},
    )
    log.info(
        "wazuh_active_response_triggered",
        agent_id=agent_id,
        command=command,
        arguments=arguments,
    )
    return json.dumps(data, indent=2)


@mcp.tool()
async def wazuh_get_agent_vulnerabilities(
    agent_id: str,
    severity: Optional[str] = None,
    limit: int = 25,
) -> str:
    """Get known vulnerabilities detected on a specific Wazuh-monitored endpoint.

    Args:
        agent_id: Wazuh agent ID (e.g. "001").
        severity: Filter by severity. Values: Critical | High | Medium | Low
        limit:    Maximum number of results (1–100, default 25).
    """
    limit = max(1, min(limit, 100))
    params: dict = {"limit": limit}
    if severity:
        params["severity"] = severity
    data = await _wazuh_get(f"/vulnerability/{agent_id}", params=params)
    return json.dumps(data.get("data", {}), indent=2)


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info(
        "cysiemstack_mcp_starting",
        host=settings.mcp_host,
        port=settings.mcp_port,
        engine=settings.engine_url,
        wazuh=settings.wazuh_api_url,
    )
    mcp.run(transport="sse", host=settings.mcp_host, port=settings.mcp_port)
