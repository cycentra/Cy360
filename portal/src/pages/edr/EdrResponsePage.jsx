/**
 * pages/edr/EdrResponsePage.jsx — Response Command Console
 *
 * Central view for analysts to issue and track response actions across
 * the endpoint fleet: isolation, process kill, forensic collection, rollback.
 */
import React, { useEffect, useState, useCallback } from "react";

const CARD_BG     = "rgba(255,255,255,0.03)";
const CARD_BORDER = "1px solid rgba(255,255,255,0.07)";
const ACCENT      = "#00e5a0";

const ACTION_META = {
  ISOLATE:           { color: "#ff3b3b", icon: "🔒", label: "Isolate" },
  UNISOLATE:         { color: "#00e5a0", icon: "🔓", label: "Unisolate" },
  KILL_PROCESS:      { color: "#ff8c00", icon: "⚡", label: "Kill Process" },
  BLOCK_HASH:        { color: "#ff8c00", icon: "🚫", label: "Block Hash" },
  COLLECT_FORENSICS: { color: "#b06eff", icon: "🔬", label: "Collect Forensics" },
  ROLLBACK:          { color: "#4d9eff", icon: "↩️", label: "Rollback" },
  QUARANTINE_FILE:   { color: "#f5c518", icon: "📦", label: "Quarantine File" },
  RUN_SCAN:          { color: "#f5c518", icon: "🔍", label: "Run Scan" },
};

const STATUS_META = {
  pending:      { color: "#f5c518", label: "Pending" },
  acknowledged: { color: "#4d9eff", label: "Acknowledged" },
  completed:    { color: "#00e5a0", label: "Completed" },
  failed:       { color: "#ff3b3b", label: "Failed" },
};

function Badge({ label, color }) {
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, letterSpacing: 1,
      padding: "2px 7px", borderRadius: 4,
      color, background: `${color}22`,
    }}>{label}</span>
  );
}

function CommandRow({ cmd }) {
  const actionMeta = ACTION_META[cmd.action] || { color: "#888", icon: "▶", label: cmd.action };
  const statusMeta = STATUS_META[cmd.status] || { color: "#888", label: cmd.status };

  return (
    <div style={{
      background: CARD_BG, border: CARD_BORDER, borderRadius: 8, marginBottom: 6,
      padding: "12px 16px",
      display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
      borderLeft: `3px solid ${actionMeta.color}`,
    }}>
      <span style={{ fontSize: 18 }}>{actionMeta.icon}</span>
      <div style={{ flex: 1, minWidth: 160 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "#e8eaf0" }}>{actionMeta.label}</div>
        <div style={{ fontSize: 11, color: "#666", marginTop: 2, fontFamily: "monospace" }}>
          {cmd.agent_id?.slice(0, 8)}… · cmd {cmd.id?.slice(0, 8)}…
        </div>
      </div>
      <Badge label={statusMeta.label} color={statusMeta.color} />
      {cmd.auto_triggered && <Badge label="AUTO" color="#b06eff" />}
      <div style={{ fontSize: 11, color: "#555" }}>
        {cmd.issued_at ? new Date(cmd.issued_at).toLocaleString() : "—"}
      </div>
      {cmd.parameters && Object.keys(cmd.parameters).length > 0 && (
        <div style={{ fontSize: 11, color: "#9aa0b0", maxWidth: 300, wordBreak: "break-all" }}>
          {JSON.stringify(cmd.parameters)}
        </div>
      )}
    </div>
  );
}

function IssueActionPanel({ agents, onIssued }) {
  const [agentId,   setAgentId]  = useState("");
  const [action,    setAction]   = useState("ISOLATE");
  const [reason,    setReason]   = useState("");
  const [pid,       setPid]      = useState("");
  const [imageName, setImageName] = useState("");
  const [sha256,    setSha256]   = useState("");
  const [filePath,  setFilePath] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [err,       setErr]      = useState("");

  const endpointMap = {
    ISOLATE:           "isolate",
    UNISOLATE:         "unisolate",
    KILL_PROCESS:      "kill-process",
    BLOCK_HASH:        "block-hash",
    COLLECT_FORENSICS: "collect-forensics",
    ROLLBACK:          "rollback",
    QUARANTINE_FILE:   "quarantine-file",
    RUN_SCAN:          "run-scan",
  };

  const buildBody = () => {
    const base = { reason: reason || "Manual action from response console" };
    if (action === "KILL_PROCESS") {
      if (!pid && !imageName) { setErr("PID or image name required"); return null; }
      return { ...base, pid: pid ? parseInt(pid) : undefined, image_name: imageName };
    }
    if (action === "BLOCK_HASH") {
      if (!sha256) { setErr("SHA-256 hash required"); return null; }
      return { ...base, sha256 };
    }
    if (action === "QUARANTINE_FILE") {
      if (!filePath) { setErr("File path required"); return null; }
      return { ...base, file_path: filePath };
    }
    return base;
  };

  const submit = async () => {
    if (!agentId) { setErr("Select an agent"); return; }
    setErr("");
    const body = buildBody();
    if (!body) return;

    setSubmitting(true);
    try {
      const path = endpointMap[action] || "run-scan";
      const res = await fetch(`/api/edr/response/${agentId}/${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || res.status);
      }
      setReason(""); setPid(""); setImageName(""); setSha256(""); setFilePath("");
      onIssued();
    } catch (e) {
      setErr(`Failed: ${e.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const inputStyle = {
    background: "rgba(255,255,255,0.05)", border: CARD_BORDER, borderRadius: 6,
    color: "#e8eaf0", padding: "7px 12px", fontSize: 12, width: "100%", outline: "none",
    boxSizing: "border-box",
  };
  const labelStyle = { fontSize: 11, color: "#555", display: "block", marginBottom: 4 };

  return (
    <div style={{
      background: CARD_BG, border: CARD_BORDER, borderRadius: 12, padding: "20px 24px", marginBottom: 28,
    }}>
      <div style={{ fontSize: 14, fontWeight: 700, color: "#e8eaf0", marginBottom: 16 }}>
        Issue Response Action
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
        <div>
          <label style={labelStyle}>Target Agent</label>
          <select value={agentId} onChange={e => setAgentId(e.target.value)} style={inputStyle}>
            <option value="">Select agent…</option>
            {agents.map(a => (
              <option key={a.agent_id} value={a.agent_id}>
                {a.hostname} ({a.agent_id?.slice(0, 8)}…) — {a.isolation_state}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label style={labelStyle}>Action</label>
          <select value={action} onChange={e => { setAction(e.target.value); setErr(""); }} style={inputStyle}>
            {Object.entries(ACTION_META).map(([k, v]) => (
              <option key={k} value={k}>{v.icon} {v.label}</option>
            ))}
          </select>
        </div>
      </div>

      {action === "KILL_PROCESS" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
          <div>
            <label style={labelStyle}>PID</label>
            <input type="number" placeholder="1234" value={pid} onChange={e => setPid(e.target.value)} style={inputStyle} />
          </div>
          <div>
            <label style={labelStyle}>Image Name (alternative)</label>
            <input placeholder="malware.exe" value={imageName} onChange={e => setImageName(e.target.value)} style={inputStyle} />
          </div>
        </div>
      )}

      {action === "BLOCK_HASH" && (
        <div style={{ marginBottom: 16 }}>
          <label style={labelStyle}>SHA-256 Hash</label>
          <input placeholder="a3f4b…" value={sha256} onChange={e => setSha256(e.target.value)} style={{ ...inputStyle, fontFamily: "monospace" }} />
        </div>
      )}

      {action === "QUARANTINE_FILE" && (
        <div style={{ marginBottom: 16 }}>
          <label style={labelStyle}>File Path</label>
          <input placeholder="/tmp/malware or C:\Users\…" value={filePath} onChange={e => setFilePath(e.target.value)} style={{ ...inputStyle, fontFamily: "monospace" }} />
        </div>
      )}

      <div style={{ marginBottom: 16 }}>
        <label style={labelStyle}>Reason / Note</label>
        <input placeholder="e.g. Escalation from incident INC-0042" value={reason} onChange={e => setReason(e.target.value)} style={inputStyle} />
      </div>

      {err && <div style={{ color: "#ff7070", fontSize: 12, marginBottom: 12 }}>{err}</div>}

      <button
        onClick={submit}
        disabled={submitting}
        style={{
          border: "none", borderRadius: 7, background: ACCENT,
          color: "#0a0e1a", fontWeight: 700, padding: "9px 22px",
          cursor: submitting ? "default" : "pointer", fontSize: 13,
          opacity: submitting ? 0.6 : 1,
        }}
      >{submitting ? "Issuing…" : "Issue Action"}</button>
    </div>
  );
}

const RESPONSE_TABS = [
  { id: "console", label: "Response Console", icon: "⚡" },
  { id: "history", label: "Command History",  icon: "📋" },
];

export default function EdrResponsePage() {
  const [activeTab,    setActiveTab]    = useState("console");
  const [commands, setCommands] = useState([]);
  const [agents,   setAgents]   = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState(null);
  const [statusFilter, setStatusFilter] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const agRes = await fetch("/api/edr/agents?status=all");
      if (!agRes.ok) throw new Error(`Agents: ${agRes.status}`);
      const agData = await agRes.json();
      const agentList = agData.agents || [];
      setAgents(agentList.filter(a => a.status === "active"));

      // Fetch command history from each agent's detail endpoint (EDR-native, not SIEM policies)
      const allCmds = [];
      await Promise.all(
        agentList.slice(0, 20).map(async ag => {
          try {
            const r = await fetch(`/api/edr/agents/${ag.agent_id}`);
            if (r.ok) {
              const d = await r.json();
              (d.commands || []).forEach(c => allCmds.push({ ...c, hostname: ag.hostname }));
            }
          } catch {}
        })
      );
      allCmds.sort((a, b) => new Date(b.issued_at) - new Date(a.issued_at));
      setCommands(allCmds);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const filtered = statusFilter
    ? commands.filter(c => c.status === statusFilter)
    : commands;

  return (
    <div style={{ padding: "28px 32px", minHeight: "100vh", background: "#0a0e1a" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800, color: "#e8eaf0" }}>Response Console</h1>
          <div style={{ fontSize: 12, color: "#555", marginTop: 4 }}>Issue containment actions and track command execution across the fleet</div>
        </div>
        <button onClick={load} style={{ border: `1px solid ${ACCENT}44`, borderRadius: 6, background: "transparent", color: ACCENT, padding: "6px 14px", fontWeight: 600, cursor: "pointer", fontSize: 12 }}>Refresh</button>
      </div>

      <div style={{ display: "flex", gap: 0, marginBottom: 28, borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
        {RESPONSE_TABS.map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)} style={{
            border: "none", borderBottom: activeTab === tab.id ? `2px solid ${ACCENT}` : "2px solid transparent",
            background: "transparent", color: activeTab === tab.id ? ACCENT : "#666",
            padding: "10px 20px", fontSize: 13, fontWeight: activeTab === tab.id ? 700 : 400,
            cursor: "pointer", marginBottom: -1, transition: "color 0.15s",
          }}>{tab.icon} {tab.label}</button>
        ))}
      </div>

      {activeTab === "console" && (
        <IssueActionPanel agents={agents} onIssued={() => { load(); setActiveTab("history"); }} />
      )}

      {activeTab === "history" && (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
            <div style={{ fontSize: 13, color: "#9aa0b0" }}>{commands.length} command{commands.length !== 1 ? "s" : ""} across the fleet</div>
            <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} style={{ background: CARD_BG, border: CARD_BORDER, borderRadius: 6, color: "#e8eaf0", padding: "4px 10px", fontSize: 11, cursor: "pointer" }}>
              <option value="">All Statuses</option>
              <option value="pending">Pending</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>
          </div>
          {error && <div style={{ background: "#ff3b3b22", border: "1px solid #ff3b3b44", borderRadius: 8, padding: "12px 16px", color: "#ff7070", fontSize: 13, marginBottom: 16 }}>{error}</div>}
          {loading ? (
            <div style={{ textAlign: "center", color: "#555", padding: 40, fontSize: 13 }}>Loading commands…</div>
          ) : filtered.length === 0 ? (
            <div style={{ textAlign: "center", color: "#555", padding: 60, fontSize: 13 }}>No response commands yet. Issue an action from the Response Console tab.</div>
          ) : (
            filtered.map(cmd => <CommandRow key={cmd.id} cmd={cmd} />)
          )}
        </>
      )}
    </div>
  );
}
