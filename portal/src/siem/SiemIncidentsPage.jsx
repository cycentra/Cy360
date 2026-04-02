/**
 * SiemIncidentsPage.jsx
 * Correlated incident list from the CySIEM Correlation Engine.
 * Connects to WebSocket for real-time updates, polls every 30s as fallback.
 */

import { useState, useEffect, useRef, useCallback } from "react";
import { siemApi, siemFetch } from "./siemApi";
import { SiemEngineStatus } from "./SiemEngineStatus";
import { RISK_CONFIG, STATUS_CONFIG } from "../core/constants";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// ── Severity badge ─────────────────────────────────────────────────────────────
function SevBadge({ severity }) {
  const cfg = RISK_CONFIG[severity] || RISK_CONFIG.low;
  return (
    <span style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40`,
      fontSize: 10, fontWeight: 700, letterSpacing: "1.5px", fontFamily: "monospace",
      padding: "2px 8px", borderRadius: 2 }}>
      {cfg.label}
    </span>
  );
}

// ── Status badge ───────────────────────────────────────────────────────────────
function StatBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || { color: "#888", label: status?.toUpperCase() || "?" };
  return (
    <span style={{ color: cfg.color, fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
      {cfg.label}
    </span>
  );
}

// ── Live indicator ─────────────────────────────────────────────────────────────
function LiveDot({ connected }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5,
      color: connected ? "#00e5a0" : "rgba(255,255,255,0.25)", fontSize: 10,
      fontFamily: "monospace" }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%",
        background: connected ? "#00e5a0" : "rgba(255,255,255,0.2)",
        animation: connected ? "pulse 2s infinite" : "none", display: "inline-block" }} />
      {connected ? "LIVE" : "POLLING"}
    </span>
  );
}

// ── Helpers ─────────────────────────────────────────────────────────────────
function fmtTs(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" })
    + " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function SectionLabel({ children }) {
  return (
    <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace",
      letterSpacing: "1px", marginBottom: 6, marginTop: 18 }}>{children}</div>
  );
}

const KILL_CHAIN_NAMES = [
  "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
  "Installation", "Command & Control", "Actions on Objectives",
];

const CAT_COLORS = {
  authentication: "#ff8c00", brute_force: "#ff3b3b", malware: "#ff3b3b",
  fim: "#f5c518", web: "#4d9eff", scan: "#b36bff", vulnerability: "#ff8c00",
  system: "rgba(255,255,255,0.4)",
};

// ── Incident drawer ────────────────────────────────────────────────────────────
function IncidentDrawer({ incident: initialIncident, onClose, onPatched }) {
  const [inc, setInc]           = useState(initialIncident);
  const [loadingDetail, setLoadingDetail] = useState(true);
  const [status, setStatus]     = useState(initialIncident.status || "open");
  const [notes, setNotes]       = useState(initialIncident.notes || "");
  const [assignee, setAssignee] = useState(initialIncident.assigned_to || "");
  const [saving, setSaving]     = useState(false);
  const [saved, setSaved]       = useState(false);
  const [alertsExpanded, setAlertsExpanded] = useState(false);

  // Fetch full incident detail (includes alerts array) on mount
  useEffect(() => {
    (async () => {
      const data = await siemFetch(siemApi.getIncident(initialIncident.id));
      if (!data._error && !data._offline) {
        setInc(data);
        setStatus(data.status || "open");
        setNotes(data.notes || "");
        setAssignee(data.assigned_to || "");
      }
      setLoadingDetail(false);
    })();
  }, [initialIncident.id]);

  const handleSave = async () => {
    setSaving(true);
    const data = await siemFetch(
      siemApi.patchIncident(inc.id, { status, notes, assigned_to: assignee })
    );
    setSaving(false);
    if (!data._error && !data._offline) {
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
      const updated = { ...inc, status, notes, assigned_to: assignee };
      setInc(updated);
      onPatched?.(updated);
    }
  };

  // Derive Wazuh Dashboard URL from current hostname
  const host = window.location.hostname;
  const wazuhHost = host.startsWith("cy360.")
    ? host.replace("cy360.", "cysiem.")
    : `${host}:5601`;
  const wazuhUrl = `https://${wazuhHost}/app/wazuh`;

  const misp       = inc.misp_enrichment || {};
  const corrRules  = inc.correlated_rules || [];
  const uebaFlags  = inc.ueba_flags || [];
  const alerts     = inc.alerts || [];
  const categories = inc.categories || [];
  const srcIps     = inc.src_ips || [];
  const users      = inc.affected_users || [];
  const agents     = inc.affected_agents || [];
  const killStage  = inc.kill_chain_stage;

  return (
    <div style={{ position: "fixed", top: 0, right: 0, width: "min(640px, 96vw)", height: "100vh",
      background: "#0d1117", borderLeft: "1px solid rgba(255,255,255,0.08)", zIndex: 200,
      display: "flex", flexDirection: "column", overflowY: "auto" }}>

      {/* Header */}
      <div style={{ padding: "18px 24px", borderBottom: "1px solid rgba(255,255,255,0.07)",
        display: "flex", justifyContent: "space-between", alignItems: "flex-start",
        position: "sticky", top: 0, background: "#0d1117", zIndex: 10 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <span style={{ color: "#4d9eff", fontSize: 12, fontFamily: "monospace", fontWeight: 700 }}>
              {inc.id}
            </span>
            <SevBadge severity={inc.severity} />
            <StatBadge status={inc.status} />
            {categories.slice(0, 2).map(cat => (
              <span key={cat} style={{ background: "rgba(255,255,255,0.06)",
                color: CAT_COLORS[cat] || "rgba(255,255,255,0.5)",
                fontSize: 10, fontFamily: "monospace", padding: "2px 8px",
                borderRadius: 2, textTransform: "uppercase" }}>{cat.replace(/_/g, " ")}</span>
            ))}
            {killStage > 0 && (
              <span style={{ background: "rgba(179,107,255,0.1)", color: "#b36bff",
                fontSize: 10, fontFamily: "monospace", padding: "2px 8px", borderRadius: 2 }}>
                KC-{killStage} {KILL_CHAIN_NAMES[killStage - 1] || ""}
              </span>
            )}
          </div>
          <div style={{ display: "flex", gap: 16, marginTop: 6, flexWrap: "wrap" }}>
            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 11 }}>
              First seen: <span style={{ color: "rgba(255,255,255,0.6)" }}>{fmtTs(inc.first_seen)}</span>
            </span>
            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 11 }}>
              Last seen: <span style={{ color: "rgba(255,255,255,0.6)" }}>{fmtTs(inc.last_seen)}</span>
            </span>
            {inc.risk_score > 0 && (
              <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 11 }}>
                Risk: <span style={{ color: inc.risk_score >= 8 ? "#ff3b3b" : inc.risk_score >= 5 ? "#ff8c00" : "#f5c518",
                  fontWeight: 700 }}>{inc.risk_score?.toFixed(1)}</span>
              </span>
            )}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0, marginLeft: 12 }}>
          <a href={wazuhUrl} target="_blank" rel="noopener noreferrer"
            style={{ background: "rgba(77,158,255,0.1)", border: "1px solid rgba(77,158,255,0.3)",
              color: "#4d9eff", padding: "6px 12px", borderRadius: 4, cursor: "pointer",
              fontSize: 11, fontFamily: "monospace", textDecoration: "none", whiteSpace: "nowrap" }}>
            ↗ Investigate in Wazuh
          </a>
          <button onClick={onClose}
            style={{ background: "none", border: "none", color: "rgba(255,255,255,0.4)",
              cursor: "pointer", fontSize: 20, padding: 4, flexShrink: 0 }}>✕</button>
        </div>
      </div>

      <div style={{ padding: "18px 24px", flex: 1 }}>

        {loadingDetail && (
          <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 12, fontFamily: "monospace",
            marginBottom: 16 }}>Loading full incident detail…</div>
        )}

        {/* Stats row */}
        <div style={{ display: "flex", gap: 10, marginBottom: 4, flexWrap: "wrap" }}>
          {[
            { label: "Alerts",   value: inc.alert_count },
            { label: "Agents",   value: agents.length },
            { label: "Users",    value: users.length },
            { label: "Src IPs",  value: srcIps.length },
          ].map(s => (
            <div key={s.label} style={{ background: "rgba(255,255,255,0.03)",
              border: "1px solid rgba(255,255,255,0.07)", borderRadius: 4, padding: "10px 14px" }}>
              <div style={{ color: "#00e5a0", fontSize: 20, fontWeight: 700, fontFamily: "monospace" }}>{s.value}</div>
              <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace" }}>{s.label}</div>
            </div>
          ))}
        </div>

        {/* Agents */}
        {agents.length > 0 && (
          <>
            <SectionLabel>AFFECTED HOSTS</SectionLabel>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {agents.map(a => (
                <span key={a} style={{ background: "rgba(255,255,255,0.05)",
                  color: "rgba(255,255,255,0.7)", fontSize: 11, fontFamily: "monospace",
                  padding: "3px 10px", borderRadius: 2, border: "1px solid rgba(255,255,255,0.1)" }}>{a}</span>
              ))}
            </div>
          </>
        )}

        {/* Source IPs */}
        {srcIps.length > 0 && (
          <>
            <SectionLabel>SOURCE IPs ({srcIps.length})</SectionLabel>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {srcIps.map(ip => (
                <span key={ip} style={{ background: "rgba(255,59,59,0.07)",
                  color: "#ff8c00", fontSize: 11, fontFamily: "monospace",
                  padding: "3px 10px", borderRadius: 2, border: "1px solid rgba(255,140,0,0.25)" }}>{ip}</span>
              ))}
            </div>
          </>
        )}

        {/* Users */}
        {users.length > 0 && (
          <>
            <SectionLabel>AFFECTED USERS ({users.length})</SectionLabel>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {users.map(u => (
                <span key={u} style={{ background: "rgba(245,197,24,0.07)",
                  color: "#f5c518", fontSize: 11, fontFamily: "monospace",
                  padding: "3px 10px", borderRadius: 2, border: "1px solid rgba(245,197,24,0.2)" }}>{u}</span>
              ))}
            </div>
          </>
        )}

        {/* MITRE ATT&CK */}
        {(inc.mitre_ids || []).length > 0 && (
          <>
            <SectionLabel>MITRE ATT&CK</SectionLabel>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {(inc.mitre_ids || []).map((id, idx) => {
                const tactic = (inc.mitre_tactics || [])[idx];
                return (
                  <a key={id} href={`https://attack.mitre.org/techniques/${id.replace(".", "/")}`}
                    target="_blank" rel="noopener noreferrer"
                    style={{ background: "rgba(77,158,255,0.08)", color: "#4d9eff",
                      border: "1px solid rgba(77,158,255,0.25)", fontSize: 10,
                      fontFamily: "monospace", padding: "3px 10px", borderRadius: 2,
                      textDecoration: "none", display: "inline-flex", flexDirection: "column", gap: 1 }}>
                    <span style={{ fontWeight: 700 }}>{id}</span>
                    {tactic && <span style={{ color: "rgba(77,158,255,0.6)", fontSize: 9 }}>{tactic}</span>}
                  </a>
                );
              })}
            </div>
          </>
        )}

        {/* Correlation rules */}
        {corrRules.length > 0 && (
          <>
            <SectionLabel>CORRELATION RULES TRIGGERED</SectionLabel>
            {corrRules.map((r, i) => (
              <div key={i} style={{ display: "flex", gap: 8, marginBottom: 4, alignItems: "flex-start" }}>
                <span style={{ color: "#f5c518", fontSize: 10, fontFamily: "monospace",
                  flexShrink: 0, marginTop: 2 }}>[{r.rule_id}]</span>
                <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 12 }}>{r.name || r.description}</span>
              </div>
            ))}
          </>
        )}

        {/* UEBA flags */}
        {uebaFlags.length > 0 && (
          <>
            <SectionLabel>UEBA FLAGS</SectionLabel>
            {uebaFlags.map((f, i) => (
              <div key={i} style={{ display: "flex", gap: 8, marginBottom: 4, alignItems: "center" }}>
                <span style={{ color: "#ff8c00", fontSize: 10 }}>⚡</span>
                <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 12 }}>{f}</span>
              </div>
            ))}
          </>
        )}

        {/* MISP hits */}
        {(misp.ioc_hits || []).length > 0 && (
          <>
            <SectionLabel>🔴 THREAT INTEL MATCHES (MISP)</SectionLabel>
            <div style={{ background: "rgba(255,59,59,0.05)", border: "1px solid rgba(255,59,59,0.2)",
              borderRadius: 4, padding: "12px 14px" }}>
              {(misp.ioc_hits || []).map((hit, i) => (
                <div key={i} style={{ color: "rgba(255,255,255,0.6)", fontSize: 12, marginBottom: 4 }}>
                  <span style={{ color: "#ff3b3b", fontFamily: "monospace" }}>{hit.ioc}</span>
                  {" — "}{hit.threat_level} threat · MISP events: {(hit.events || []).join(", ")}
                </div>
              ))}
            </div>
          </>
        )}

        {/* LLM narrative */}
        {inc.llm_summary && (
          <>
            <SectionLabel>🤖 AI NARRATIVE</SectionLabel>
            <div style={{ background: "rgba(0,229,160,0.03)", border: "1px solid rgba(0,229,160,0.15)",
              borderRadius: 4, padding: "14px 16px" }}>
              <div style={{ color: "rgba(255,255,255,0.7)", fontSize: 13, lineHeight: 1.7 }}>
                {inc.llm_summary}
              </div>
              {inc.llm_remediation && (
                <div style={{ marginTop: 10, color: "rgba(255,255,255,0.5)", fontSize: 12,
                  lineHeight: 1.7, whiteSpace: "pre-wrap", borderTop: "1px solid rgba(0,229,160,0.1)",
                  paddingTop: 10 }}>
                  {inc.llm_remediation}
                </div>
              )}
            </div>
          </>
        )}

        {/* Alerts table */}
        {alerts.length > 0 && (
          <>
            <SectionLabel>
              ALERTS ({alerts.length}{inc.alert_count > alerts.length ? ` of ${inc.alert_count}` : ""})
              <button onClick={() => setAlertsExpanded(v => !v)}
                style={{ background: "none", border: "none", color: "#4d9eff",
                  cursor: "pointer", fontSize: 10, fontFamily: "monospace",
                  marginLeft: 12, padding: 0 }}>
                {alertsExpanded ? "▲ collapse" : "▼ expand"}
              </button>
            </SectionLabel>
            {alertsExpanded && (
              <div style={{ overflowX: "auto", borderRadius: 4,
                border: "1px solid rgba(255,255,255,0.07)" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11,
                  fontFamily: "monospace" }}>
                  <thead>
                    <tr style={{ background: "rgba(255,255,255,0.04)" }}>
                      {["Time", "Rule ID", "Level", "Description", "Src IP", "User"].map(h => (
                        <th key={h} style={{ padding: "7px 10px", textAlign: "left",
                          color: "rgba(255,255,255,0.3)", fontWeight: 600,
                          borderBottom: "1px solid rgba(255,255,255,0.07)", whiteSpace: "nowrap" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.map((a, i) => {
                      const lvlColor = a.rule_level >= 12 ? "#ff3b3b" : a.rule_level >= 8 ? "#ff8c00" : "#f5c518";
                      return (
                        <tr key={a.id || i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}
                          onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.025)"}
                          onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                          <td style={{ padding: "6px 10px", color: "rgba(255,255,255,0.35)", whiteSpace: "nowrap" }}>
                            {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : "—"}
                          </td>
                          <td style={{ padding: "6px 10px", color: "#4d9eff" }}>{a.rule_id}</td>
                          <td style={{ padding: "6px 10px", color: lvlColor, fontWeight: 700 }}>{a.rule_level}</td>
                          <td style={{ padding: "6px 10px", color: "rgba(255,255,255,0.65)",
                            maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {a.rule_desc || "—"}
                          </td>
                          <td style={{ padding: "6px 10px", color: "#ff8c00" }}>{a.src_ip || "—"}</td>
                          <td style={{ padding: "6px 10px", color: "#f5c518" }}>{a.username || "—"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            {!alertsExpanded && (
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 11, fontFamily: "monospace",
                padding: "8px 0" }}>
                Click ▼ expand to view individual alerts
              </div>
            )}
          </>
        )}

        {/* Update controls */}
        <SectionLabel>UPDATE INCIDENT</SectionLabel>
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 4, padding: "16px 18px" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
            <div>
              <label style={{ color: "rgba(255,255,255,0.4)", fontSize: 11, fontFamily: "monospace" }}>Status</label>
              <select value={status} onChange={e => setStatus(e.target.value)}
                style={{ width: "100%", background: "rgba(255,255,255,0.05)",
                  border: "1px solid rgba(255,255,255,0.12)", color: "white",
                  padding: "8px 10px", borderRadius: 4, fontSize: 12, marginTop: 4 }}>
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="in-review">In Review</option>
                <option value="resolved">Resolved</option>
                <option value="false_positive">False Positive</option>
              </select>
            </div>
            <div>
              <label style={{ color: "rgba(255,255,255,0.4)", fontSize: 11, fontFamily: "monospace" }}>Assigned To</label>
              <input value={assignee} onChange={e => setAssignee(e.target.value)}
                placeholder="analyst email…"
                style={{ width: "100%", background: "rgba(255,255,255,0.05)",
                  border: "1px solid rgba(255,255,255,0.12)", color: "white",
                  padding: "8px 10px", borderRadius: 4, fontSize: 12, marginTop: 4, boxSizing: "border-box" }} />
            </div>
          </div>
          <div style={{ marginBottom: 10 }}>
            <label style={{ color: "rgba(255,255,255,0.4)", fontSize: 11, fontFamily: "monospace" }}>Notes</label>
            <textarea value={notes} onChange={e => setNotes(e.target.value)}
              rows={3} placeholder="Investigation notes…"
              style={{ width: "100%", background: "rgba(255,255,255,0.05)",
                border: "1px solid rgba(255,255,255,0.12)", color: "white",
                padding: "8px 10px", borderRadius: 4, fontSize: 12, marginTop: 4,
                resize: "vertical", fontFamily: "monospace", boxSizing: "border-box" }} />
          </div>
          <button onClick={handleSave} disabled={saving}
            style={{ background: saved ? "rgba(0,229,160,0.2)" : "rgba(0,229,160,0.12)",
              border: `1px solid rgba(0,229,160,${saved ? 0.6 : 0.4})`,
              color: "#00e5a0", padding: "9px 20px", borderRadius: 4, cursor: "pointer",
              fontSize: 13, fontFamily: "monospace", fontWeight: 700 }}>
            {saving ? "Saving…" : saved ? "✓ Saved" : "Save Changes"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────
export function SiemIncidentsPage() {
  const [incidents, setIncidents]   = useState([]);
  const [total, setTotal]           = useState(0);
  const [loading, setLoading]       = useState(true);
  const [filters, setFilters]       = useState({ status: "", severity: "" });
  const [selected, setSelected]     = useState(null);
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef(null);

  const fetchIncidents = useCallback(async () => {
    const data = await siemFetch(siemApi.getIncidents({ ...filters, limit: 100 }));
    if (data._offline || data._error) return;
    setIncidents(data.incidents || []);
    setTotal(data.total || 0);
    setLoading(false);
  }, [filters]);

  // Initial load + polling fallback (30s)
  useEffect(() => {
    setLoading(true);
    fetchIncidents();
    const timer = setInterval(fetchIncidents, 30_000);
    return () => clearInterval(timer);
  }, [fetchIncidents]);

  // WebSocket live feed
  useEffect(() => {
    const ws = siemApi.connectLive();
    wsRef.current = ws;
    ws.onopen  = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onerror = () => setWsConnected(false);
    ws.onmessage = (evt) => {
      try {
        const e = JSON.parse(evt.data);
        if (e.type === "alert_processed") {
          // Refresh incident list on new event
          fetchIncidents();
        }
      } catch {}
    };
    return () => { ws.close(); };
  }, [fetchIncidents]);

  const handlePatched = (updated) => {
    setIncidents(prev => prev.map(inc => inc.id === updated.id ? { ...inc, ...updated } : inc));
    setSelected(prev => prev?.id === updated.id ? { ...prev, ...updated } : prev);
  };

  const sortedIncidents = [...incidents].sort((a, b) =>
    (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4) ||
    new Date(b.last_seen) - new Date(a.last_seen)
  );

  return (
    <SiemEngineStatus>
      <div style={{ position: "relative" }}>
        {/* Header */}
        <div style={{ marginBottom: 22 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: "white" }}>Incidents</h1>
            <span style={{ background: "rgba(255,59,59,0.12)", color: "#ff3b3b", fontSize: 10,
              fontFamily: "monospace", padding: "3px 10px", borderRadius: 2, fontWeight: 700,
              letterSpacing: "1px" }}>CORRELATION ENGINE</span>
            <LiveDot connected={wsConnected} />
          </div>
          <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13 }}>
            {total} incident{total !== 1 ? "s" : ""} — grouped by temporal + entity correlation across Wazuh alerts.
          </p>
        </div>

        {/* Filters */}
        <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
          {[
            { key: "status", opts: ["", "open", "investigating", "in-review", "resolved", "false_positive"],
              labels: ["All Statuses", "Open", "Investigating", "In Review", "Resolved", "False Positive"] },
            { key: "severity", opts: ["", "critical", "high", "medium", "low"],
              labels: ["All Severities", "Critical", "High", "Medium", "Low"] },
          ].map(({ key, opts, labels }) => (
            <select key={key} value={filters[key]}
              onChange={e => setFilters(prev => ({ ...prev, [key]: e.target.value }))}
              style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
                color: "white", padding: "8px 12px", borderRadius: 4, fontSize: 12, fontFamily: "monospace" }}>
              {opts.map((o, i) => <option key={o} value={o}>{labels[i]}</option>)}
            </select>
          ))}
          <button onClick={fetchIncidents}
            style={{ background: "rgba(0,229,160,0.08)", border: "1px solid rgba(0,229,160,0.3)",
              color: "#00e5a0", padding: "8px 16px", borderRadius: 4, cursor: "pointer",
              fontSize: 12, fontFamily: "monospace" }}>
            ↻ Refresh
          </button>
        </div>

        {loading ? (
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 13, padding: "40px 0" }}>
            Loading incidents…
          </div>
        ) : sortedIncidents.length === 0 ? (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, padding: "40px 0", textAlign: "center" }}>
            No incidents match the current filters.
          </div>
        ) : (
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 4, overflow: "hidden" }}>
            {/* Table header */}
            <div style={{ display: "grid",
              gridTemplateColumns: "130px 75px 1fr 110px 60px 75px 100px",
              gap: 10, padding: "10px 16px",
              background: "rgba(255,255,255,0.03)", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
              {["ID", "SEVERITY", "AFFECTED HOSTS", "TYPE / CATEGORY", "ALERTS", "STATUS", "LAST SEEN"].map(h => (
                <div key={h} style={{ color: "rgba(255,255,255,0.3)", fontSize: 10,
                  fontFamily: "monospace", letterSpacing: "1px" }}>{h}</div>
              ))}
            </div>

            {/* Rows */}
            {sortedIncidents.map(inc => (
              <div key={inc.id}
                onClick={() => setSelected(inc)}
                style={{ display: "grid",
                  gridTemplateColumns: "130px 75px 1fr 110px 60px 75px 100px",
                  gap: 10, padding: "12px 16px", cursor: "pointer",
                  borderBottom: "1px solid rgba(255,255,255,0.04)",
                  background: selected?.id === inc.id ? "rgba(0,229,160,0.04)" : "transparent",
                  transition: "background 0.15s" }}
                onMouseEnter={e => { if (selected?.id !== inc.id) e.currentTarget.style.background = "rgba(255,255,255,0.025)"; }}
                onMouseLeave={e => { if (selected?.id !== inc.id) e.currentTarget.style.background = "transparent"; }}>
                <div style={{ color: "#4d9eff", fontSize: 11, fontFamily: "monospace",
                  fontWeight: 700 }}>{inc.id}</div>
                <div><SevBadge severity={inc.severity} /></div>
                <div style={{ color: "rgba(255,255,255,0.7)", fontSize: 12, overflow: "hidden",
                  textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {(inc.affected_agents || []).join(", ") || "—"}
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                  {(inc.categories || []).slice(0, 2).map(cat => (
                    <span key={cat} style={{ background: "rgba(255,255,255,0.05)",
                      color: CAT_COLORS[cat] || "rgba(255,255,255,0.4)",
                      fontSize: 9, fontFamily: "monospace", padding: "1px 5px",
                      borderRadius: 2, textTransform: "uppercase" }}>
                      {cat.replace(/_/g, " ")}
                    </span>
                  ))}
                  {!(inc.categories || []).length && (
                    <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 11 }}>—</span>
                  )}
                </div>
                <div style={{ color: "rgba(255,255,255,0.6)", fontSize: 12,
                  fontFamily: "monospace" }}>{inc.alert_count}</div>
                <div><StatBadge status={inc.status} /></div>
                <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace" }}>
                  {fmtTs(inc.last_seen)}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Incident drawer */}
        {selected && (
          <>
            <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 199 }}
              onClick={() => setSelected(null)} />
            <IncidentDrawer
              incident={selected}
              onClose={() => setSelected(null)}
              onPatched={handlePatched}
            />
          </>
        )}
      </div>
    </SiemEngineStatus>
  );
}
