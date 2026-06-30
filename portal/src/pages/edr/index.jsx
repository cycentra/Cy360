/**
 * pages/edr/index.jsx — CyEDR Endpoint Fleet (main EDR landing page)
 *
 * Displays enrolled agents with real-time status: online/offline, isolation
 * state, open detection count, and quick-action buttons for analyst+.
 */
import React, { useEffect, useState, useCallback } from "react";

const CARD_BG     = "rgba(255,255,255,0.03)";
const CARD_BORDER = "1px solid rgba(255,255,255,0.07)";
const ACCENT      = "#00e5a0";

const OS_ICONS = { WINDOWS: "🪟", LINUX: "🐧", MACOS: "🍎", UNKNOWN: "💻" };

const ASSET_COLORS = {
  domain_controller: "#ff3b3b",
  database:          "#ff8c00",
  server:            "#f5c518",
  api_gateway:       "#b06eff",
  jump_server:       "#ff3b3b",
  workstation:       "#4d9eff",
  laptop:            "#4d9eff",
  unknown:           "#888",
};

const SEV_COLOR = { critical: "#ff3b3b", high: "#ff8c00", medium: "#f5c518", low: "#00e5a0" };

function Badge({ label, color, bg }) {
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, letterSpacing: 1,
      padding: "2px 7px", borderRadius: 4,
      color, background: bg || `${color}22`,
    }}>{label}</span>
  );
}

function AgentCard({ agent, onAction }) {
  const isOnline   = agent.last_seen && (Date.now() - new Date(agent.last_seen).getTime()) < 5 * 60 * 1000;
  const isIsolated = agent.isolation_state === "isolated";

  return (
    <div style={{
      background: CARD_BG, border: CARD_BORDER, borderRadius: 10,
      padding: "16px 20px", display: "flex", flexDirection: "column", gap: 10,
      borderLeft: isIsolated ? "3px solid #ff3b3b" : `3px solid ${ASSET_COLORS[agent.asset_type] || "#4d9eff"}`,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 18 }}>{OS_ICONS[agent.os_type] || "💻"}</span>
          <div>
            <div style={{ fontWeight: 700, color: "#e8eaf0", fontSize: 14 }}>{agent.hostname}</div>
            <div style={{ fontSize: 11, color: "#666", fontFamily: "monospace" }}>{agent.agent_id.slice(0, 8)}…</div>
          </div>
        </div>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <Badge
            label={isOnline ? "ONLINE" : "OFFLINE"}
            color={isOnline ? "#00e5a0" : "#888"}
          />
          {isIsolated && <Badge label="ISOLATED" color="#ff3b3b" />}
        </div>
      </div>

      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
        <StatItem label="Asset Type"    value={agent.asset_type?.replace("_", " ").toUpperCase()} />
        <StatItem label="IP"            value={agent.agent_ip || "—"} />
        <StatItem label="Open Detections" value={agent.open_detections ?? 0}
          color={agent.open_detections > 0 ? SEV_COLOR.high : ACCENT} />
        <StatItem label="Pending Cmds"  value={agent.pending_commands ?? 0}
          color={agent.pending_commands > 0 ? "#f5c518" : "#888"} />
        <StatItem label="Version"       value={agent.version || "—"} />
        <StatItem label="Last Seen"     value={agent.last_seen ? new Date(agent.last_seen).toLocaleString() : "Never"} />
        <StatItem
          label="Network Zone"
          value={agent.current_network_zone || "Unknown / Roaming"}
          color={agent.current_network_zone ? ACCENT : "#888"}
        />
        <div style={{ minWidth: 80 }}>
          <div style={{ fontSize: 10, color: "#555", marginBottom: 2 }}>ARP Discovery</div>
          <span style={{
            fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 4,
            background: agent.arp_enabled ? "rgba(0,229,160,0.12)" : "rgba(255,59,59,0.12)",
            color: agent.arp_enabled ? "#00e5a0" : "#ff3b3b",
          }}>
            {agent.arp_enabled ? "ACTIVE" : "BLOCKED"}
          </span>
        </div>
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 4 }}>
        <ActionBtn label="Details" color={ACCENT} onClick={() => onAction("detail", agent)} />
        {!isIsolated
          ? <ActionBtn label="Isolate"   color="#ff3b3b" onClick={() => onAction("isolate", agent)} />
          : <ActionBtn label="Unisolate" color="#00e5a0" onClick={() => onAction("unisolate", agent)} />
        }
        <ActionBtn label="Collect Forensics" color="#b06eff" onClick={() => onAction("forensics", agent)} />
        <ActionBtn label="Run Scan"    color="#f5c518" onClick={() => onAction("scan", agent)} />
      </div>
    </div>
  );
}

function StatItem({ label, value, color }) {
  return (
    <div style={{ minWidth: 80 }}>
      <div style={{ fontSize: 10, color: "#555", marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 12, color: color || "#b0b8c8", fontWeight: 600 }}>{value}</div>
    </div>
  );
}

function ActionBtn({ label, color, onClick }) {
  const [hover, setHover] = useState(false);
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        border: `1px solid ${color}44`, borderRadius: 6,
        background: hover ? `${color}22` : "transparent",
        color, fontSize: 11, fontWeight: 600, padding: "4px 10px",
        cursor: "pointer", transition: "all 0.15s",
      }}
    >{label}</button>
  );
}

function StatsBar({ stats }) {
  if (!stats) return null;
  const items = [
    { label: "Total Agents",      value: stats.total_agents ?? 0,      color: ACCENT      },
    { label: "Online",            value: stats.online_agents ?? 0,     color: "#00e5a0"   },
    { label: "Isolated",          value: stats.isolated_agents ?? 0,   color: "#ff3b3b"   },
    { label: "Open Detections",   value: stats.open_detections ?? 0,   color: "#ff8c00"   },
    { label: "Critical Open",     value: stats.critical_open ?? 0,     color: "#ff3b3b"   },
    { label: "Detections (24h)",  value: stats.detections_24h ?? 0,    color: "#f5c518"   },
    { label: "Auto Responses",    value: stats.auto_responses_24h ?? 0, color: "#b06eff"  },
  ];
  return (
    <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
      {items.map(({ label, value, color }) => (
        <div key={label} style={{
          background: CARD_BG, border: CARD_BORDER, borderRadius: 10,
          padding: "12px 18px", minWidth: 100, flex: "1 1 100px",
        }}>
          <div style={{ fontSize: 22, fontWeight: 800, color }}>{value}</div>
          <div style={{ fontSize: 11, color: "#666", marginTop: 2 }}>{label}</div>
        </div>
      ))}
    </div>
  );
}

function ConfirmModal({ title, message, onConfirm, onCancel, confirmLabel = "Confirm", confirmColor = "#ff3b3b" }) {
  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 9999,
    }}>
      <div style={{
        background: "#12182b", border: CARD_BORDER, borderRadius: 12,
        padding: 28, maxWidth: 420, width: "90%",
      }}>
        <div style={{ fontSize: 16, fontWeight: 700, color: "#e8eaf0", marginBottom: 12 }}>{title}</div>
        <div style={{ fontSize: 13, color: "#9aa0b0", marginBottom: 24 }}>{message}</div>
        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
          <button onClick={onCancel} style={{
            border: "1px solid #333", borderRadius: 6, background: "transparent",
            color: "#9aa0b0", padding: "6px 16px", cursor: "pointer",
          }}>Cancel</button>
          <button onClick={onConfirm} style={{
            border: "none", borderRadius: 6,
            background: confirmColor, color: "#0a0e1a",
            padding: "6px 16px", fontWeight: 700, cursor: "pointer",
          }}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}

export default function EdrFleetPage({ onViewDetail }) {
  const [agents, setAgents]     = useState([]);
  const [stats, setStats]       = useState(null);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [filter, setFilter]     = useState("active");
  const [search, setSearch]     = useState("");
  const [confirm, setConfirm]   = useState(null); // { action, agent }

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [agentsRes, statsRes] = await Promise.all([
        fetch(`/api/edr/agents?status=${filter}`),
        fetch("/api/edr/stats"),
      ]);
      if (!agentsRes.ok) throw new Error(`Agents: ${agentsRes.status}`);
      const agentsData = await agentsRes.json();
      const statsData  = statsRes.ok ? await statsRes.json() : null;
      setAgents(agentsData.agents || []);
      setStats(statsData);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => { load(); }, [load]);

  const handleAction = async (action, agent) => {
    if (action === "detail") {
      onViewDetail?.(agent.agent_id);
      return;
    }
    if (action === "isolate") {
      setConfirm({ action, agent,
        title: "Isolate Endpoint",
        message: `Isolate ${agent.hostname}? The endpoint will lose all network access except the EDR management channel.`,
        label: "Isolate", color: "#ff3b3b",
      });
      return;
    }
    if (action === "unisolate") {
      setConfirm({ action, agent,
        title: "Restore Network Access",
        message: `Restore full network connectivity to ${agent.hostname}?`,
        label: "Unisolate", color: "#00e5a0",
      });
      return;
    }
    await issueCommand(action, agent);
  };

  const issueCommand = async (action, agent) => {
    const endpoints = {
      isolate:   `/api/edr/response/${agent.agent_id}/isolate`,
      unisolate: `/api/edr/response/${agent.agent_id}/unisolate`,
      forensics: `/api/edr/response/${agent.agent_id}/collect-forensics`,
      scan:      `/api/edr/response/${agent.agent_id}/run-scan`,
    };
    const url = endpoints[action];
    if (!url) return;
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: `Issued from CyEDR Fleet Console` }),
      });
      if (!res.ok) throw new Error(`${res.status}`);
      await load();
    } catch (e) {
      setError(`Command failed: ${e.message}`);
    }
  };

  const filtered = agents.filter(a =>
    !search || a.hostname?.toLowerCase().includes(search.toLowerCase()) ||
    a.agent_ip?.includes(search) || a.asset_type?.includes(search.toLowerCase())
  );

  return (
    <div style={{ padding: "28px 32px", minHeight: "100vh", background: "#0a0e1a" }}>
      {confirm && (
        <ConfirmModal
          title={confirm.title}
          message={confirm.message}
          confirmLabel={confirm.label}
          confirmColor={confirm.color}
          onConfirm={() => { setConfirm(null); issueCommand(confirm.action, confirm.agent); }}
          onCancel={() => setConfirm(null)}
        />
      )}

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800, color: "#e8eaf0" }}>
            Endpoint Fleet
          </h1>
          <div style={{ fontSize: 12, color: "#555", marginTop: 4 }}>
            CyEDR — Deployed agents, isolation state, and response console
          </div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <select value={filter} onChange={e => setFilter(e.target.value)} style={{
            background: CARD_BG, border: CARD_BORDER, borderRadius: 6, color: "#e8eaf0",
            padding: "6px 10px", fontSize: 12, cursor: "pointer",
          }}>
            <option value="active">Active</option>
            <option value="all">All</option>
          </select>
          <input
            placeholder="Search hostname / IP…"
            value={search} onChange={e => setSearch(e.target.value)}
            style={{
              background: CARD_BG, border: CARD_BORDER, borderRadius: 6, color: "#e8eaf0",
              padding: "6px 12px", fontSize: 12, width: 200, outline: "none",
            }}
          />
          <button onClick={load} style={{
            border: `1px solid ${ACCENT}44`, borderRadius: 6, background: "transparent",
            color: ACCENT, padding: "6px 14px", fontWeight: 600, cursor: "pointer", fontSize: 12,
          }}>Refresh</button>
        </div>
      </div>

      <StatsBar stats={stats} />

      {loading && (
        <div style={{ textAlign: "center", color: "#555", padding: 40, fontSize: 13 }}>
          Loading endpoint fleet…
        </div>
      )}
      {error && (
        <div style={{
          background: "#ff3b3b22", border: "1px solid #ff3b3b44", borderRadius: 8,
          padding: "12px 16px", color: "#ff7070", fontSize: 13, marginBottom: 16,
        }}>{error}</div>
      )}

      {!loading && filtered.length === 0 && (
        <div style={{ textAlign: "center", color: "#555", padding: 60, fontSize: 13 }}>
          No agents found. Enroll your first endpoint via{" "}
          <span style={{ color: ACCENT, fontFamily: "monospace" }}>
            POST /api/edr/agents/enroll
          </span>
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(480px, 1fr))", gap: 14 }}>
        {filtered.map(agent => (
          <AgentCard key={agent.agent_id} agent={agent} onAction={handleAction} />
        ))}
      </div>
    </div>
  );
}
