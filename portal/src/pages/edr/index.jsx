/**
 * pages/edr/index.jsx — CyEDR Endpoint Fleet
 *
 * Paginated sortable table view of enrolled agents.
 * Click any row to open AgentDetailModal with Overview + Command History tabs.
 * Run Scan / Collect Forensics / Isolate queue async commands and show a banner
 * with the command ID; results appear in Command History once the agent executes.
 */
import React, { useEffect, useState, useCallback, useRef } from "react";
import { AppleLogo, WindowsLogo, LinuxLogo } from "../../components/OsLogo.jsx";

const CARD_BG     = "rgba(255,255,255,0.03)";
const CARD_BORDER = "1px solid rgba(255,255,255,0.07)";
const ACCENT      = "#00e5a0";
const PAGE_SIZE   = 25;

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

function isOnline(agent) {
  return agent.last_seen && (Date.now() - new Date(agent.last_seen).getTime()) < 5 * 60 * 1000;
}

function OsIcon({ os_type, size = 16 }) {
  const props = { size };
  if (os_type === "MACOS")   return <AppleLogo   {...props} color="#b0b8c8" />;
  if (os_type === "WINDOWS") return <WindowsLogo {...props} />;
  if (os_type === "LINUX")   return <LinuxLogo   {...props} />;
  return <span style={{ fontSize: size }}>💻</span>;
}

function StatusDot({ online, isolated }) {
  const color = isolated ? "#ff3b3b" : online ? "#00e5a0" : "#555";
  const label = isolated ? "Isolated" : online ? "Online" : "Offline";
  return (
    <span title={label} style={{
      display: "inline-block", width: 8, height: 8, borderRadius: "50%",
      background: color, boxShadow: `0 0 4px ${color}`,
    }} />
  );
}

function Badge({ label, color, small }) {
  return (
    <span style={{
      fontSize: small ? 9 : 10, fontWeight: 700, letterSpacing: 0.8,
      padding: small ? "1px 5px" : "2px 7px", borderRadius: 4,
      color, background: `${color}22`,
    }}>{label}</span>
  );
}

// ─── Stats bar ───────────────────────────────────────────────────────────────

function StatsBar({ stats }) {
  if (!stats) return null;
  const items = [
    { label: "Total Agents",     value: stats.total_agents ?? 0,       color: ACCENT     },
    { label: "Online",           value: stats.online_agents ?? 0,      color: "#00e5a0"  },
    { label: "Isolated",         value: stats.isolated_agents ?? 0,    color: "#ff3b3b"  },
    { label: "Open Detections",  value: stats.open_detections ?? 0,    color: "#ff8c00"  },
    { label: "Critical Open",    value: stats.critical_open ?? 0,      color: "#ff3b3b"  },
    { label: "Detections (24h)", value: stats.detections_24h ?? 0,     color: "#f5c518"  },
    { label: "Auto Responses",   value: stats.auto_responses_24h ?? 0, color: "#b06eff"  },
  ];
  return (
    <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 20 }}>
      {items.map(({ label, value, color }) => (
        <div key={label} style={{
          background: CARD_BG, border: CARD_BORDER, borderRadius: 10,
          padding: "10px 16px", minWidth: 90, flex: "1 1 90px",
        }}>
          <div style={{ fontSize: 20, fontWeight: 800, color }}>{value}</div>
          <div style={{ fontSize: 10, color: "#666", marginTop: 2 }}>{label}</div>
        </div>
      ))}
    </div>
  );
}

// ─── Command feedback banner ──────────────────────────────────────────────────

function CmdBanner({ msg, onDismiss }) {
  useEffect(() => {
    const t = setTimeout(onDismiss, 8000);
    return () => clearTimeout(t);
  }, [onDismiss]);
  return (
    <div style={{
      background: "rgba(0,229,160,0.08)", border: "1px solid rgba(0,229,160,0.3)",
      borderRadius: 8, padding: "10px 16px", marginBottom: 16,
      display: "flex", justifyContent: "space-between", alignItems: "flex-start",
      fontSize: 12, color: "#b0ffdf",
    }}>
      <span>{msg}</span>
      <button onClick={onDismiss} style={{
        background: "none", border: "none", color: "#555", cursor: "pointer",
        fontSize: 14, lineHeight: 1, marginLeft: 12,
      }}>✕</button>
    </div>
  );
}

// ─── Action icon buttons (table row) ─────────────────────────────────────────

function IconBtn({ title, color, onClick, children, disabled }) {
  const [hov, setHov] = useState(false);
  return (
    <button
      title={title}
      disabled={disabled}
      onClick={e => { e.stopPropagation(); onClick(); }}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        border: `1px solid ${color}44`, borderRadius: 5,
        background: hov ? `${color}22` : "transparent",
        color, fontSize: 10, fontWeight: 700, padding: "3px 8px",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.4 : 1,
        transition: "all 0.15s", whiteSpace: "nowrap",
      }}
    >{children}</button>
  );
}

// ─── Confirm modal ────────────────────────────────────────────────────────────

function ConfirmModal({ title, message, onConfirm, onCancel, confirmLabel = "Confirm", confirmColor = "#ff3b3b" }) {
  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 10000,
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
            color: "#9aa0b0", padding: "6px 16px", cursor: "pointer", fontSize: 12,
          }}>Cancel</button>
          <button onClick={onConfirm} style={{
            border: "none", borderRadius: 6, background: confirmColor, color: "#0a0e1a",
            padding: "6px 16px", fontWeight: 700, cursor: "pointer", fontSize: 12,
          }}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}

// ─── Command history list (inside modal) ─────────────────────────────────────

const CMD_STATUS_COLOR = {
  pending:      "#f5c518",
  acknowledged: "#4d9eff",
  completed:    "#00e5a0",
  failed:       "#ff3b3b",
};

function CommandHistoryTab({ agentId }) {
  const [cmds, setCmds]     = useState([]);
  const [loading, setLoad]  = useState(true);
  const [error, setError]   = useState(null);
  const [expanded, setExpanded] = useState(null);
  const intervalRef = useRef(null);

  const fetch_ = useCallback(async () => {
    try {
      const r = await fetch(`/api/edr/response/${agentId}/commands?limit=50`);
      if (!r.ok) throw new Error(r.status);
      const d = await r.json();
      setCmds(d.commands || []);
      setError(null);
    } catch (e) {
      setError(`Failed to load: ${e.message}`);
    } finally {
      setLoad(false);
    }
  }, [agentId]);

  useEffect(() => {
    fetch_();
    intervalRef.current = setInterval(fetch_, 15000); // auto-refresh every 15s
    return () => clearInterval(intervalRef.current);
  }, [fetch_]);

  if (loading) return <div style={{ color: "#555", fontSize: 12, padding: 20 }}>Loading command history…</div>;
  if (error)   return <div style={{ color: "#ff7070", fontSize: 12, padding: 20 }}>{error}</div>;
  if (!cmds.length) return (
    <div style={{ color: "#555", fontSize: 12, padding: 24, textAlign: "center" }}>
      No commands issued for this agent yet.
    </div>
  );

  return (
    <div style={{ overflowY: "auto", maxHeight: 420 }}>
      <div style={{ fontSize: 11, color: "#555", marginBottom: 8 }}>
        Showing last {cmds.length} commands · auto-refreshes every 15s
      </div>
      {cmds.map(cmd => {
        const sc = CMD_STATUS_COLOR[cmd.status] || "#888";
        const isOpen = expanded === cmd.id;
        const resultStr = cmd.result
          ? (typeof cmd.result === "string" ? cmd.result : JSON.stringify(cmd.result, null, 2))
          : null;
        return (
          <div key={cmd.id} style={{
            borderBottom: "1px solid rgba(255,255,255,0.05)",
            padding: "10px 0",
          }}>
            <div
              style={{ display: "flex", alignItems: "center", gap: 10, cursor: "pointer" }}
              onClick={() => setExpanded(isOpen ? null : cmd.id)}
            >
              <span style={{
                fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 4,
                background: `${sc}22`, color: sc, minWidth: 80, textAlign: "center",
              }}>{cmd.status.toUpperCase()}</span>
              <span style={{ fontSize: 12, fontWeight: 600, color: "#e8eaf0", flex: 1 }}>
                {cmd.action}
              </span>
              {cmd.auto_triggered && (
                <span style={{ fontSize: 9, color: "#b06eff", background: "#b06eff22", padding: "1px 5px", borderRadius: 3 }}>
                  AUTO
                </span>
              )}
              <span style={{ fontSize: 10, color: "#555" }}>
                {cmd.issued_at ? new Date(cmd.issued_at).toLocaleString() : "—"}
              </span>
              <span style={{ fontSize: 10, color: "#444" }}>
                {isOpen ? "▲" : "▼"}
              </span>
            </div>

            {isOpen && (
              <div style={{
                marginTop: 8, padding: "10px 12px",
                background: "rgba(0,0,0,0.3)", borderRadius: 6,
                fontSize: 11, color: "#9aa0b0",
              }}>
                <div style={{ marginBottom: 4 }}>
                  <strong style={{ color: "#555" }}>Command ID:</strong>{" "}
                  <span style={{ fontFamily: "monospace", color: "#e8eaf0" }}>{cmd.id}</span>
                </div>
                <div style={{ marginBottom: 4 }}>
                  <strong style={{ color: "#555" }}>Issued by:</strong>{" "}
                  {cmd.issued_by || "system"}
                </div>
                {cmd.parameters && Object.keys(cmd.parameters).length > 0 && (
                  <div style={{ marginBottom: 4 }}>
                    <strong style={{ color: "#555" }}>Parameters:</strong>{" "}
                    {Object.entries(cmd.parameters)
                      .filter(([, v]) => v != null)
                      .map(([k, v]) => `${k}=${v}`)
                      .join(", ")}
                  </div>
                )}
                {cmd.completed_at && (
                  <div style={{ marginBottom: 4 }}>
                    <strong style={{ color: "#555" }}>Completed:</strong>{" "}
                    {new Date(cmd.completed_at).toLocaleString()}
                  </div>
                )}
                {resultStr ? (
                  <div style={{ marginTop: 8 }}>
                    <strong style={{ color: "#555" }}>Result:</strong>
                    <pre style={{
                      marginTop: 4, padding: "8px 10px", background: "#0a0e1a",
                      borderRadius: 4, overflowX: "auto", whiteSpace: "pre-wrap",
                      color: cmd.status === "failed" ? "#ff7070" : "#00e5a0",
                      fontSize: 10, maxHeight: 200, overflowY: "auto",
                    }}>{resultStr}</pre>
                  </div>
                ) : (
                  cmd.status === "pending" || cmd.status === "acknowledged" ? (
                    <div style={{ marginTop: 6, color: "#f5c518", fontSize: 11 }}>
                      ⏳ Waiting for agent to execute (polls every ~60s)
                    </div>
                  ) : null
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Tamper Log Tab ────────────────────────────────────────────────────────────
// Audit trail of the local system-tray app's scan/stop requests and password
// outcomes for this agent — see blueprints/edr/routes.py's tamper-events
// routes. The password check itself happens locally on the endpoint
// (cyedr_agent.py's IPCListener); this is the record of what it decided.

function TamperLogTab({ agentId }) {
  const [events, setEvents] = useState([]);
  const [loading, setLoad]  = useState(true);
  const [error, setError]   = useState(null);
  const intervalRef = useRef(null);

  const fetch_ = useCallback(async () => {
    try {
      const r = await fetch(`/api/edr/tamper-events?agent_id=${agentId}&limit=50`);
      if (!r.ok) throw new Error(r.status);
      const d = await r.json();
      setEvents(d.events || []);
      setError(null);
    } catch (e) {
      setError(`Failed to load: ${e.message}`);
    } finally {
      setLoad(false);
    }
  }, [agentId]);

  useEffect(() => {
    fetch_();
    intervalRef.current = setInterval(fetch_, 15000); // auto-refresh every 15s
    return () => clearInterval(intervalRef.current);
  }, [fetch_]);

  if (loading) return <div style={{ color: "#555", fontSize: 12, padding: 20 }}>Loading tamper log…</div>;
  if (error)   return <div style={{ color: "#ff7070", fontSize: 12, padding: 20 }}>{error}</div>;
  if (!events.length) return (
    <div style={{ color: "#555", fontSize: 12, padding: 24, textAlign: "center" }}>
      No tray scan/stop activity recorded for this agent yet.
    </div>
  );

  const ACTION_LABEL = {
    scan_requested:   "On-Demand Scan Requested",
    stop_requested:   "Stop/Exit Requested",
    stop_denied:      "Stop/Exit Denied (wrong password)",
    stop_authorized:  "Stop/Exit Authorized",
  };
  const ACTION_COLOR = {
    scan_requested:  "#4d9eff",
    stop_requested:  "#f5c518",
    stop_denied:     "#ff3b3b",
    stop_authorized: "#00e5a0",
  };

  return (
    <div style={{ overflowY: "auto", maxHeight: 420 }}>
      <div style={{ fontSize: 11, color: "#555", marginBottom: 8 }}>
        Showing last {events.length} events · auto-refreshes every 15s
      </div>
      {events.map(ev => {
        const c = ACTION_COLOR[ev.action] || "#888";
        return (
          <div key={ev.id} style={{
            display: "flex", alignItems: "flex-start", gap: 10,
            borderBottom: "1px solid rgba(255,255,255,0.05)", padding: "10px 0",
          }}>
            <span style={{
              fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 4,
              background: `${c}22`, color: c, minWidth: 170, textAlign: "center", flexShrink: 0,
            }}>{(ACTION_LABEL[ev.action] || ev.action).toUpperCase()}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              {ev.detail && <div style={{ fontSize: 12, color: "#9aa0b0" }}>{ev.detail}</div>}
            </div>
            <span style={{ fontSize: 11, color: "#555", flexShrink: 0 }}>
              {ev.created_at ? new Date(ev.created_at).toLocaleString() : ""}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ─── Agent Detail Modal ───────────────────────────────────────────────────────

function AgentDetailModal({ agent, onClose, onAction }) {
  const [tab, setTab]         = useState("overview");
  const [cmdBanner, setBanner] = useState(null);
  const [confirm, setConfirm]  = useState(null);
  const [busy, setBusy]        = useState(false);
  const online   = isOnline(agent);
  const isolated = agent.isolation_state === "isolated";

  const issueCommand = async (action) => {
    const endpoints = {
      isolate:   `/api/edr/response/${agent.agent_id}/isolate`,
      unisolate: `/api/edr/response/${agent.agent_id}/unisolate`,
      forensics: `/api/edr/response/${agent.agent_id}/collect-forensics`,
      scan:      `/api/edr/response/${agent.agent_id}/run-scan`,
    };
    setBusy(true);
    try {
      const res = await fetch(endpoints[action], {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: "Issued from CyEDR Fleet Console" }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const friendly = {
        isolate:   "ISOLATE queued",
        unisolate: "UNISOLATE queued",
        forensics: "COLLECT_FORENSICS queued",
        scan:      "RUN_SCAN queued",
      }[action];
      setBanner(
        `✓ ${friendly} — Command ID: ${data.command_id}. ` +
        `The agent will execute on its next poll cycle (~60s). ` +
        `Switch to the Command History tab to track progress; ` +
        (action === "scan" ? "CyScan matches will appear in EDR Detections." : "results appear in Command History.")
      );
      setTab("history");
    } catch (e) {
      setBanner(`✗ Command failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  const handleAction = (action) => {
    if (action === "isolate") {
      setConfirm({
        action,
        title: "Isolate Endpoint",
        message: `Isolate ${agent.hostname}? The endpoint will lose all network access except the EDR management channel.`,
        label: "Isolate", color: "#ff3b3b",
      });
    } else if (action === "unisolate") {
      setConfirm({
        action,
        title: "Restore Network Access",
        message: `Restore full network connectivity to ${agent.hostname}?`,
        label: "Unisolate", color: "#00e5a0",
      });
    } else {
      issueCommand(action);
    }
  };

  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 9999,
    }} onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      {confirm && (
        <ConfirmModal
          title={confirm.title}
          message={confirm.message}
          confirmLabel={confirm.label}
          confirmColor={confirm.color}
          onConfirm={() => { setConfirm(null); issueCommand(confirm.action); }}
          onCancel={() => setConfirm(null)}
        />
      )}

      <div style={{
        background: "#0d1220", border: "1px solid rgba(255,255,255,0.1)",
        borderRadius: 14, width: "min(800px, 95vw)", maxHeight: "85vh",
        display: "flex", flexDirection: "column", overflow: "hidden",
      }}>
        {/* Header */}
        <div style={{
          padding: "18px 24px", borderBottom: "1px solid rgba(255,255,255,0.07)",
          display: "flex", alignItems: "center", justifyContent: "space-between",
          flexShrink: 0,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <OsIcon os_type={agent.os_type} size={22} />
            <div>
              <div style={{ fontWeight: 700, color: "#e8eaf0", fontSize: 16 }}>{agent.hostname}</div>
              <div style={{ fontSize: 11, color: "#555", fontFamily: "monospace" }}>{agent.agent_id}</div>
            </div>
            <StatusDot online={online} isolated={isolated} />
            {isolated && <Badge label="ISOLATED" color="#ff3b3b" />}
          </div>
          <button onClick={onClose} style={{
            background: "none", border: "none", color: "#555", cursor: "pointer",
            fontSize: 20, lineHeight: 1,
          }}>✕</button>
        </div>

        {/* Tabs */}
        <div style={{
          display: "flex", gap: 0,
          borderBottom: "1px solid rgba(255,255,255,0.07)", flexShrink: 0,
        }}>
          {[["overview", "Overview"], ["history", "Command History"], ["tamper", "Tamper Log"]].map(([id, label]) => (
            <button key={id} onClick={() => setTab(id)} style={{
              padding: "10px 20px", background: "none", border: "none",
              borderBottom: tab === id ? `2px solid ${ACCENT}` : "2px solid transparent",
              color: tab === id ? ACCENT : "#666",
              fontSize: 12, fontWeight: 600, cursor: "pointer",
            }}>{label}</button>
          ))}
        </div>

        {/* Body */}
        <div style={{ padding: "16px 24px", overflowY: "auto", flex: 1 }}>
          {cmdBanner && (
            <div style={{
              background: cmdBanner.startsWith("✓") ? "rgba(0,229,160,0.08)" : "rgba(255,59,59,0.08)",
              border: `1px solid ${cmdBanner.startsWith("✓") ? "rgba(0,229,160,0.3)" : "rgba(255,59,59,0.3)"}`,
              borderRadius: 8, padding: "10px 14px", marginBottom: 14,
              fontSize: 12, color: cmdBanner.startsWith("✓") ? "#b0ffdf" : "#ff9090",
              display: "flex", justifyContent: "space-between",
            }}>
              <span>{cmdBanner}</span>
              <button onClick={() => setBanner(null)} style={{
                background: "none", border: "none", color: "#555", cursor: "pointer",
                fontSize: 13, marginLeft: 10,
              }}>✕</button>
            </div>
          )}

          {tab === "overview" && (
            <div>
              <div style={{
                display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px 24px",
                marginBottom: 20,
              }}>
                {[
                  ["Asset Type",      agent.asset_type?.replace(/_/g, " ").toUpperCase() || "—"],
                  ["IP Address",      agent.agent_ip || "—"],
                  ["OS",              agent.os_type || "—"],
                  ["Version",         agent.version || "—"],
                  ["Open Detections", agent.open_detections ?? 0],
                  ["Pending Commands", agent.pending_commands ?? 0],
                  ["Network Zone",    agent.current_network_zone || "Unknown / Roaming"],
                  ["ARP Discovery",   agent.arp_enabled ? "ACTIVE" : "BLOCKED"],
                  ["Last Seen",       agent.last_seen ? new Date(agent.last_seen).toLocaleString() : "Never"],
                  ["Isolation State", agent.isolation_state || "normal"],
                ].map(([label, value]) => (
                  <div key={label}>
                    <div style={{ fontSize: 10, color: "#555", marginBottom: 3 }}>{label}</div>
                    <div style={{ fontSize: 13, color: "#b0b8c8", fontWeight: 600 }}>{String(value)}</div>
                  </div>
                ))}
              </div>

              <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: 16 }}>
                <div style={{ fontSize: 11, color: "#555", marginBottom: 10, fontWeight: 600 }}>
                  RESPONSE ACTIONS
                </div>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                  {!isolated
                    ? <ActionModalBtn label="Isolate"           color="#ff3b3b" disabled={busy} onClick={() => handleAction("isolate")} />
                    : <ActionModalBtn label="Unisolate"         color="#00e5a0" disabled={busy} onClick={() => handleAction("unisolate")} />
                  }
                  <ActionModalBtn label="Collect Forensics" color="#b06eff" disabled={busy} onClick={() => handleAction("forensics")} />
                  <ActionModalBtn label="Run CyScan"        color="#f5c518" disabled={busy} onClick={() => handleAction("scan")} />
                  <ActionModalBtn label="View Full Detail"  color={ACCENT}   disabled={false} onClick={() => onAction("detail", agent)} />
                </div>
                {!online && (
                  <div style={{ marginTop: 10, fontSize: 11, color: "#888" }}>
                    ⚠ Agent appears offline. Commands will be queued and executed when it reconnects.
                  </div>
                )}
              </div>
            </div>
          )}

          {tab === "history" && <CommandHistoryTab agentId={agent.agent_id} />}
          {tab === "tamper" && <TamperLogTab agentId={agent.agent_id} />}
        </div>
      </div>
    </div>
  );
}

function ActionModalBtn({ label, color, onClick, disabled }) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        border: `1px solid ${color}44`, borderRadius: 7,
        background: hov ? `${color}22` : "transparent",
        color, fontSize: 12, fontWeight: 600, padding: "7px 14px",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1, transition: "all 0.15s",
      }}
    >{label}</button>
  );
}

// ─── Sortable table header cell ───────────────────────────────────────────────

function TH({ label, col, sort, onSort, style }) {
  const active = sort.col === col;
  return (
    <th
      onClick={() => onSort(col)}
      style={{
        padding: "9px 12px", textAlign: "left", fontSize: 10,
        fontWeight: 700, color: active ? ACCENT : "#555",
        cursor: "pointer", userSelect: "none", whiteSpace: "nowrap",
        borderBottom: "1px solid rgba(255,255,255,0.07)",
        background: "rgba(255,255,255,0.02)",
        ...style,
      }}
    >
      {label} {active ? (sort.dir === "asc" ? "↑" : "↓") : ""}
    </th>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function EdrFleetPage({ onViewDetail }) {
  const [agents, setAgents]   = useState([]);
  const [stats, setStats]     = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [filter, setFilter]   = useState("active");
  const [search, setSearch]   = useState("");
  const [sort, setSort]       = useState({ col: "hostname", dir: "asc" });
  const [page, setPage]       = useState(0);
  const [selected, setSelected] = useState(null);
  const [banner, setBanner]   = useState(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [ar, sr] = await Promise.all([
        fetch(`/api/edr/agents?status=${filter}`),
        fetch("/api/edr/stats"),
      ]);
      if (!ar.ok) throw new Error(`Agents: ${ar.status}`);
      const ad = await ar.json();
      const sd = sr.ok ? await sr.json() : null;
      setAgents(ad.agents || []);
      setStats(sd);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => { load(); setPage(0); }, [load]);

  const handleSort = (col) => {
    setSort(s => ({ col, dir: s.col === col && s.dir === "asc" ? "desc" : "asc" }));
    setPage(0);
  };

  // Filter + sort
  const filtered = agents.filter(a =>
    !search ||
    a.hostname?.toLowerCase().includes(search.toLowerCase()) ||
    a.agent_ip?.includes(search) ||
    a.asset_type?.includes(search.toLowerCase())
  );

  const sorted = [...filtered].sort((a, b) => {
    const { col, dir } = sort;
    let va = a[col] ?? ""; let vb = b[col] ?? "";
    if (col === "last_seen") { va = va ? new Date(va).getTime() : 0; vb = vb ? new Date(vb).getTime() : 0; }
    if (col === "open_detections" || col === "pending_commands") { va = Number(va); vb = Number(vb); }
    const cmp = typeof va === "number" ? va - vb : String(va).localeCompare(String(vb));
    return dir === "asc" ? cmp : -cmp;
  });

  const pages = Math.ceil(sorted.length / PAGE_SIZE);
  const paged = sorted.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const handleRowAction = async (action, agent) => {
    if (action === "detail") { onViewDetail?.(agent.agent_id); return; }
    setSelected(agent);
  };

  // Refresh selected agent data after actions inside modal
  const refreshSelected = () => {
    load();
    if (selected) {
      setSelected(prev => agents.find(a => a.agent_id === prev?.agent_id) ?? prev);
    }
  };

  return (
    <div style={{ padding: "28px 32px", minHeight: "100vh", background: "#0a0e1a" }}>
      {selected && (
        <AgentDetailModal
          agent={selected}
          onClose={() => { setSelected(null); load(); }}
          onAction={(action, agent) => { setSelected(null); onViewDetail?.(agent.agent_id); }}
        />
      )}

      {/* Page header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800, color: "#e8eaf0" }}>Endpoint Fleet</h1>
          <div style={{ fontSize: 12, color: "#555", marginTop: 4 }}>
            CyEDR — Deployed agents, isolation state, and response console
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <select value={filter} onChange={e => { setFilter(e.target.value); setPage(0); }} style={{
            background: CARD_BG, border: CARD_BORDER, borderRadius: 6, color: "#e8eaf0",
            padding: "6px 10px", fontSize: 12, cursor: "pointer",
          }}>
            <option value="active">Active</option>
            <option value="all">All</option>
          </select>
          <input
            placeholder="Search hostname / IP…"
            value={search} onChange={e => { setSearch(e.target.value); setPage(0); }}
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

      {banner && <CmdBanner msg={banner} onDismiss={() => setBanner(null)} />}

      {error && (
        <div style={{
          background: "#ff3b3b22", border: "1px solid #ff3b3b44", borderRadius: 8,
          padding: "10px 16px", color: "#ff7070", fontSize: 13, marginBottom: 16,
        }}>{error}</div>
      )}

      {/* Agent table */}
      <div style={{
        background: CARD_BG, border: CARD_BORDER, borderRadius: 12, overflow: "hidden",
      }}>
        {loading ? (
          <div style={{ textAlign: "center", color: "#555", padding: 40, fontSize: 13 }}>
            Loading endpoint fleet…
          </div>
        ) : sorted.length === 0 ? (
          <div style={{ textAlign: "center", color: "#555", padding: 60, fontSize: 13 }}>
            No agents found. Enroll your first endpoint via{" "}
            <span style={{ color: ACCENT, fontFamily: "monospace" }}>POST /api/edr/agents/enroll</span>
          </div>
        ) : (
          <>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    <th style={{ width: 28, padding: "9px 0 9px 14px", borderBottom: "1px solid rgba(255,255,255,0.07)", background: "rgba(255,255,255,0.02)" }} />
                    <TH label="Hostname"    col="hostname"         sort={sort} onSort={handleSort} />
                    <TH label="OS"          col="os_type"          sort={sort} onSort={handleSort} style={{ width: 40 }} />
                    <TH label="Asset Type"  col="asset_type"       sort={sort} onSort={handleSort} />
                    <TH label="IP"          col="agent_ip"         sort={sort} onSort={handleSort} />
                    <TH label="Zone"        col="current_network_zone" sort={sort} onSort={handleSort} />
                    <TH label="Detections"  col="open_detections"  sort={sort} onSort={handleSort} style={{ textAlign: "center" }} />
                    <TH label="Last Seen"   col="last_seen"        sort={sort} onSort={handleSort} />
                    <th style={{ padding: "9px 12px", fontSize: 10, fontWeight: 700, color: "#555", borderBottom: "1px solid rgba(255,255,255,0.07)", background: "rgba(255,255,255,0.02)" }}>
                      ACTIONS
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {paged.map((agent, i) => {
                    const online   = isOnline(agent);
                    const isolated = agent.isolation_state === "isolated";
                    const assetColor = ASSET_COLORS[agent.asset_type] || "#4d9eff";
                    return (
                      <tr
                        key={agent.agent_id}
                        onClick={() => setSelected(agent)}
                        style={{
                          borderBottom: "1px solid rgba(255,255,255,0.04)",
                          background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)",
                          cursor: "pointer",
                          transition: "background 0.1s",
                        }}
                        onMouseEnter={e => e.currentTarget.style.background = "rgba(0,229,160,0.04)"}
                        onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)"}
                      >
                        {/* Status dot */}
                        <td style={{ paddingLeft: 14, width: 28 }}>
                          <StatusDot online={online} isolated={isolated} />
                        </td>

                        {/* Hostname + isolation badge */}
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <div style={{
                              width: 3, height: 20, borderRadius: 2, flexShrink: 0,
                              background: isolated ? "#ff3b3b" : assetColor,
                            }} />
                            <div>
                              <div style={{ fontWeight: 600, color: "#e8eaf0", fontSize: 13 }}>
                                {agent.hostname}
                              </div>
                              <div style={{ fontFamily: "monospace", fontSize: 10, color: "#444" }}>
                                {agent.agent_id.slice(0, 10)}…
                              </div>
                            </div>
                            {isolated && <Badge label="ISOLATED" color="#ff3b3b" small />}
                          </div>
                        </td>

                        {/* OS icon */}
                        <td style={{ padding: "10px 12px" }}>
                          <OsIcon os_type={agent.os_type} size={16} />
                        </td>

                        {/* Asset type */}
                        <td style={{ padding: "10px 12px", fontSize: 11, color: assetColor, fontWeight: 600, whiteSpace: "nowrap" }}>
                          {agent.asset_type?.replace(/_/g, " ").toUpperCase() || "—"}
                        </td>

                        {/* IP */}
                        <td style={{ padding: "10px 12px", fontFamily: "monospace", fontSize: 11, color: "#9aa0b0" }}>
                          {agent.agent_ip || "—"}
                        </td>

                        {/* Zone */}
                        <td style={{ padding: "10px 12px", fontSize: 11, color: agent.current_network_zone ? ACCENT : "#444" }}>
                          {agent.current_network_zone || "Unknown"}
                        </td>

                        {/* Open detections */}
                        <td style={{ padding: "10px 12px", textAlign: "center" }}>
                          <span style={{
                            fontSize: 12, fontWeight: 700,
                            color: (agent.open_detections ?? 0) > 0 ? "#ff8c00" : "#555",
                          }}>
                            {agent.open_detections ?? 0}
                          </span>
                        </td>

                        {/* Last seen */}
                        <td style={{ padding: "10px 12px", fontSize: 11, color: "#666", whiteSpace: "nowrap" }}>
                          {agent.last_seen ? new Date(agent.last_seen).toLocaleString() : "Never"}
                        </td>

                        {/* Actions */}
                        <td style={{ padding: "10px 12px" }} onClick={e => e.stopPropagation()}>
                          <div style={{ display: "flex", gap: 6 }}>
                            {!isolated
                              ? <IconBtn title="Isolate endpoint" color="#ff3b3b" onClick={() => { setSelected(agent); }}>
                                  Isolate
                                </IconBtn>
                              : <IconBtn title="Lift isolation" color="#00e5a0" onClick={() => { setSelected(agent); }}>
                                  Unisolate
                                </IconBtn>
                            }
                            <IconBtn title="Queue CyScan" color="#f5c518" onClick={() => { setSelected(agent); }}>
                              Scan
                            </IconBtn>
                            <IconBtn title="Collect forensics" color="#b06eff" onClick={() => { setSelected(agent); }}>
                              Forensics
                            </IconBtn>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {pages > 1 && (
              <div style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "10px 16px", borderTop: "1px solid rgba(255,255,255,0.06)",
              }}>
                <div style={{ fontSize: 11, color: "#555" }}>
                  {sorted.length} agent{sorted.length !== 1 ? "s" : ""} ·{" "}
                  showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, sorted.length)}
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} style={{
                    border: "1px solid #333", borderRadius: 5, background: "transparent",
                    color: page === 0 ? "#333" : "#9aa0b0", padding: "4px 12px",
                    cursor: page === 0 ? "not-allowed" : "pointer", fontSize: 12,
                  }}>← Prev</button>
                  <span style={{ fontSize: 12, color: "#555", padding: "4px 8px" }}>
                    {page + 1} / {pages}
                  </span>
                  <button onClick={() => setPage(p => Math.min(pages - 1, p + 1))} disabled={page === pages - 1} style={{
                    border: "1px solid #333", borderRadius: 5, background: "transparent",
                    color: page === pages - 1 ? "#333" : "#9aa0b0", padding: "4px 12px",
                    cursor: page === pages - 1 ? "not-allowed" : "pointer", fontSize: 12,
                  }}>Next →</button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
