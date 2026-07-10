/**
 * pages/itam/ShadowAiPage.jsx — Shadow AI Monitor
 *
 * Tracks unauthorized AI tools found on endpoints by CyEDR process scanning
 * and Wazuh Sysmon DNS/network event correlation.
 */
import React, { useEffect, useState, useCallback } from "react";

const CARD_BG = "rgba(255,255,255,0.03)";
const BORDER  = "1px solid rgba(255,255,255,0.07)";
const ACCENT  = "#00e5a0";

const SEV_COLOR = { critical: "#ff3b3b", high: "#ff8c00", medium: "#f5c518", low: ACCENT, info: "#6aa9ff" };

const STATUS_STYLES = {
  open:       { color: "#ff8c00", bg: "rgba(255,140,0,0.1)",     border: "rgba(255,140,0,0.3)"     },
  approved:   { color: ACCENT,    bg: "rgba(0,229,160,0.1)",     border: "rgba(0,229,160,0.3)"     },
  suppressed: { color: "#555",    bg: "rgba(255,255,255,0.04)",  border: "rgba(255,255,255,0.1)"   },
  escalated:  { color: "#ff3b3b", bg: "rgba(255,59,59,0.1)",     border: "rgba(255,59,59,0.3)"     },
};

function SevBadge({ sev }) {
  const c = SEV_COLOR[sev] || SEV_COLOR.info;
  return (
    <span style={{ fontSize: 9, fontWeight: 700, color: c, border: `1px solid ${c}44`,
      padding: "2px 7px", borderRadius: 4, letterSpacing: 0.5, textTransform: "uppercase" }}>
      {sev || "info"}
    </span>
  );
}

function StatusBadge({ status }) {
  const s = STATUS_STYLES[status] || STATUS_STYLES.open;
  return (
    <span style={{ fontSize: 9, fontWeight: 700, color: s.color,
      background: s.bg, border: `1px solid ${s.border}`,
      padding: "2px 7px", borderRadius: 4, letterSpacing: 0.5, textTransform: "uppercase" }}>
      {status || "open"}
    </span>
  );
}

function KpiCard({ label, value, sub, color }) {
  return (
    <div style={{ background: CARD_BG, border: BORDER, borderRadius: 10, padding: "14px 18px",
      flex: "1 1 100px", minWidth: 100, borderTop: `3px solid ${color}` }}>
      <div style={{ fontSize: 24, fontWeight: 800, color }}>{value}</div>
      <div style={{ fontSize: 11, color: "#555", marginTop: 2 }}>{label}</div>
      {sub && <div style={{ fontSize: 10, color: "#444", marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

export default function ShadowAiPage() {
  const [findings,    setFindings]    = useState([]);
  const [summary,     setSummary]     = useState(null);
  const [whitelist,   setWhitelist]   = useState([]);
  const [total,       setTotal]       = useState(0);
  const [page,        setPage]        = useState(1);
  const [statusFlt,   setStatusFlt]   = useState("open");
  const [loading,     setLoading]     = useState(true);
  const [tab,         setTab]         = useState("findings");
  const [newTool,     setNewTool]     = useState({ ai_tool: "", vendor: "", rationale: "" });
  const [adding,      setAdding]      = useState(false);
  const [addMsg,      setAddMsg]      = useState("");
  const [refreshing,  setRefreshing]  = useState(false);
  const [clearing,    setClearing]    = useState(false);

  const PER_PAGE = 50;

  const loadSummary = async () => {
    try { const r = await fetch("/api/itam/shadow-ai/summary"); if (r.ok) setSummary(await r.json()); } catch {}
  };

  const loadFindings = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams({ page, per_page: PER_PAGE });
    if (statusFlt && statusFlt !== "all") params.set("status", statusFlt);
    try {
      const r = await fetch(`/api/itam/shadow-ai?${params}`);
      if (r.ok) { const d = await r.json(); setFindings(d.findings || []); setTotal(d.total || 0); }
    } catch {}
    setLoading(false);
  }, [page, statusFlt]);

  const loadWhitelist = async () => {
    try { const r = await fetch("/api/itam/ai-whitelist"); if (r.ok) setWhitelist((await r.json()).tools || []); } catch {}
  };

  useEffect(() => { loadSummary(); loadWhitelist(); }, []);
  useEffect(() => { if (tab === "findings") loadFindings(); }, [loadFindings, tab]);

  const setStatus = async (id, status) => {
    try {
      await fetch(`/api/itam/shadow-ai/${id}/status`, {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      setFindings(f => f.map(x => x.id === id ? { ...x, status } : x));
      loadSummary();
    } catch {}
  };

  const addWhitelist = async () => {
    if (!newTool.ai_tool) return;
    setAdding(true); setAddMsg("");
    try {
      const r = await fetch("/api/itam/ai-whitelist", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newTool),
      });
      if (r.ok) {
        setAddMsg(`${newTool.ai_tool} added to approved AI list.`);
        setNewTool({ ai_tool: "", vendor: "", rationale: "" });
        loadWhitelist();
      } else { const d = await r.json(); setAddMsg(d.error || "Failed to add."); }
    } catch { setAddMsg("Network error."); }
    setAdding(false);
  };

  const removeWhitelist = async (id) => {
    try {
      await fetch(`/api/itam/ai-whitelist/${id}`, { method: "DELETE" });
      setWhitelist(w => w.filter(x => x.id !== id));
    } catch {}
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await Promise.all([loadFindings(), loadSummary()]);
    setRefreshing(false);
  };

  const handleClearAll = async () => {
    if (!window.confirm("Delete ALL Shadow AI findings? This cannot be undone.")) return;
    setClearing(true);
    try {
      const r = await fetch("/api/itam/shadow-ai", { method: "DELETE" });
      if (r.ok) {
        setFindings([]);
        setTotal(0);
        await loadSummary();
      }
    } catch {}
    setClearing(false);
  };

  return (
    <div style={{ color: "#e8eaf0" }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: 20 }}>🤖</span>
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 700 }}>Shadow AI Monitor</h2>
          <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: 1.5, color: "#ff8c00",
            border: "1px solid #ff8c0044", padding: "2px 8px", borderRadius: 4 }}>GOVERNANCE</span>
          <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
            <button onClick={handleRefresh} disabled={refreshing} style={{
              border: `1px solid ${ACCENT}55`, borderRadius: 6, padding: "5px 14px",
              fontSize: 11, fontWeight: 600, color: refreshing ? "#444" : ACCENT,
              background: refreshing ? "transparent" : "rgba(0,229,160,0.06)",
              cursor: refreshing ? "not-allowed" : "pointer" }}>
              {refreshing ? "Refreshing…" : "↻ Refresh"}
            </button>
            <button onClick={handleClearAll} disabled={clearing} style={{
              border: "1px solid rgba(255,59,59,0.35)", borderRadius: 6, padding: "5px 14px",
              fontSize: 11, fontWeight: 600, color: clearing ? "#444" : "#ff3b3b",
              background: "transparent", cursor: clearing ? "not-allowed" : "pointer" }}>
              {clearing ? "Clearing…" : "Clear All"}
            </button>
          </div>
        </div>
        <div style={{ fontSize: 12, color: "#555", marginTop: 4 }}>
          Unauthorized AI tools detected via CyEDR process scan, Sysmon DNS, and network telemetry
        </div>
      </div>

      {/* KPI row */}
      {summary && (
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
          <KpiCard label="Open Findings"  value={summary.open || 0}       color="#ff8c00" sub={`${summary.total_7d || 0} new (7d)`}/>
          <KpiCard label="Escalated"      value={summary.escalated || 0}  color="#ff3b3b"/>
          <KpiCard label="Approved Tools" value={summary.approved || 0}   color={ACCENT}/>
          <KpiCard label="Suppressed"     value={summary.suppressed || 0} color="#555"/>
          <KpiCard label="Unique AI Tools" value={summary.unique_tools || 0} color="#6aa9ff"/>
        </div>
      )}

      {/* Tool breakdown */}
      {summary?.by_tool && Object.keys(summary.by_tool).length > 0 && (
        <div style={{ background: CARD_BG, border: BORDER, borderRadius: 12, padding: "14px 18px", marginBottom: 24 }}>
          <div style={{ fontSize: 10, color: "#555", fontWeight: 600, letterSpacing: 0.5, marginBottom: 10 }}>
            TOOLS DETECTED (OPEN FINDINGS)
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {Object.entries(summary.by_tool).sort(([,a],[,b]) => b - a).map(([tool, n]) => (
              <div key={tool} style={{ background: "rgba(255,140,0,0.08)", border: "1px solid rgba(255,140,0,0.2)",
                borderRadius: 8, padding: "6px 12px", display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontSize: 12, color: "#c0c8d8" }}>{tool}</span>
                <span style={{ fontSize: 13, fontWeight: 700, color: "#ff8c00" }}>{n}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: "flex", gap: 0, marginBottom: 16, border: BORDER, borderRadius: 8, overflow: "hidden", width: "fit-content" }}>
        {[["findings", "Findings"], ["whitelist", "Approved AI Tools"]].map(([id, label]) => (
          <button key={id} onClick={() => setTab(id)} style={{
            padding: "7px 18px", fontSize: 11, fontWeight: 600,
            background: tab === id ? "rgba(0,229,160,0.1)" : "transparent",
            color: tab === id ? ACCENT : "#555", cursor: "pointer",
            border: "none", borderRight: id === "findings" ? BORDER : "none",
          }}>{label}</button>
        ))}
      </div>

      {tab === "findings" && (
        <>
          {/* Status filter */}
          <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
            {["open", "escalated", "approved", "suppressed", "all"].map(s => (
              <button key={s} onClick={() => { setStatusFlt(s); setPage(1); }} style={{
                border: statusFlt === s ? `1px solid ${SEV_COLOR[s] || "#555"}` : BORDER,
                borderRadius: 6, padding: "4px 12px", fontSize: 11, fontWeight: 600,
                background: statusFlt === s ? `${(SEV_COLOR[s] || "#555")}18` : "transparent",
                color: statusFlt === s ? (SEV_COLOR[s] || "#aaa") : "#555", cursor: "pointer",
                textTransform: "capitalize",
              }}>{s}</button>
            ))}
          </div>

          <div style={{ background: CARD_BG, border: BORDER, borderRadius: 12, overflow: "hidden" }}>
            {loading
              ? <div style={{ padding: 32, textAlign: "center", color: "#555" }}>Loading…</div>
              : findings.length === 0
              ? <div style={{ padding: 32, textAlign: "center", color: "#555" }}>
                  {statusFlt === "open"
                    ? "No open Shadow AI findings — your endpoints are clean or CyEDR hasn't reported in yet."
                    : `No ${statusFlt} findings.`}
                </div>
              : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
                        {["AI Tool", "Hostname", "Process", "Severity", "Status", "Detection", "First Seen", "Actions"].map(h => (
                          <th key={h} style={{ padding: "8px 12px", textAlign: "left", color: "#555", fontSize: 10, fontWeight: 600, letterSpacing: 0.5 }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {findings.map((f, i) => (
                        <tr key={f.id || i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}
                          onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.025)"}
                          onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                          <td style={{ padding: "9px 12px", fontWeight: 700, color: "#ff8c00" }}>{f.ai_tool}</td>
                          <td style={{ padding: "9px 12px", fontFamily: "monospace", color: "#9aa0b0", fontSize: 11 }}>{f.hostname || "Unknown"}</td>
                          <td style={{ padding: "9px 12px", color: "#666", fontSize: 11, fontFamily: "monospace" }}>{f.process_name || "—"}</td>
                          <td style={{ padding: "9px 12px" }}><SevBadge sev={f.severity}/></td>
                          <td style={{ padding: "9px 12px" }}><StatusBadge status={f.status}/></td>
                          <td style={{ padding: "9px 12px", color: "#555", fontSize: 10 }}>
                            {f.detection_method === "process" ? "🖥 Process" : f.detection_method === "dns" ? "🌐 DNS" : f.detection_method === "network" ? "🔌 Network" : "—"}
                          </td>
                          <td style={{ padding: "9px 12px", color: "#555", fontSize: 11 }}>
                            {f.first_seen ? new Date(f.first_seen).toLocaleDateString() : "—"}
                          </td>
                          <td style={{ padding: "9px 12px" }}>
                            {f.status === "open" && (
                              <div style={{ display: "flex", gap: 4 }}>
                                <button onClick={() => setStatus(f.id, "approved")} style={{
                                  border: `1px solid ${ACCENT}44`, borderRadius: 4, padding: "2px 8px",
                                  fontSize: 9, fontWeight: 700, color: ACCENT, background: "transparent", cursor: "pointer" }}>
                                  Approve
                                </button>
                                <button onClick={() => setStatus(f.id, "escalated")} style={{
                                  border: "1px solid #ff3b3b44", borderRadius: 4, padding: "2px 8px",
                                  fontSize: 9, fontWeight: 700, color: "#ff3b3b", background: "transparent", cursor: "pointer" }}>
                                  Escalate
                                </button>
                                <button onClick={() => setStatus(f.id, "suppressed")} style={{
                                  border: BORDER, borderRadius: 4, padding: "2px 8px",
                                  fontSize: 9, fontWeight: 700, color: "#555", background: "transparent", cursor: "pointer" }}>
                                  Suppress
                                </button>
                              </div>
                            )}
                            {f.status !== "open" && (
                              <button onClick={() => setStatus(f.id, "open")} style={{
                                border: BORDER, borderRadius: 4, padding: "2px 8px",
                                fontSize: 9, color: "#555", background: "transparent", cursor: "pointer" }}>
                                Reopen
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )
            }
          </div>

          {total > PER_PAGE && (
            <div style={{ display: "flex", justifyContent: "center", gap: 8, padding: 16 }}>
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                style={{ border: BORDER, borderRadius: 6, padding: "4px 12px", background: "transparent",
                  color: page === 1 ? "#333" : "#9aa0b0", cursor: page === 1 ? "not-allowed" : "pointer" }}>← Prev</button>
              <span style={{ color: "#555", fontSize: 11, alignSelf: "center" }}>Page {page} of {Math.ceil(total / PER_PAGE)}</span>
              <button onClick={() => setPage(p => p + 1)} disabled={page >= Math.ceil(total / PER_PAGE)}
                style={{ border: BORDER, borderRadius: 6, padding: "4px 12px", background: "transparent",
                  color: page >= Math.ceil(total / PER_PAGE) ? "#333" : "#9aa0b0",
                  cursor: page >= Math.ceil(total / PER_PAGE) ? "not-allowed" : "pointer" }}>Next →</button>
            </div>
          )}
        </>
      )}

      {tab === "whitelist" && (
        <>
          {/* Add new tool */}
          <div style={{ background: CARD_BG, border: BORDER, borderRadius: 12, padding: "16px 20px", marginBottom: 20 }}>
            <div style={{ fontSize: 11, color: "#555", fontWeight: 600, marginBottom: 12 }}>ADD APPROVED AI TOOL</div>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <label style={{ fontSize: 10, color: "#555" }}>Tool Name *</label>
                <input value={newTool.ai_tool} onChange={e => setNewTool(t => ({ ...t, ai_tool: e.target.value }))}
                  placeholder="e.g. github-copilot" style={{
                    background: "rgba(255,255,255,0.04)", border: BORDER, borderRadius: 6,
                    padding: "6px 10px", color: "#e8eaf0", fontSize: 12, width: 180 }}/>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <label style={{ fontSize: 10, color: "#555" }}>Vendor</label>
                <input value={newTool.vendor} onChange={e => setNewTool(t => ({ ...t, vendor: e.target.value }))}
                  placeholder="e.g. GitHub / Microsoft" style={{
                    background: "rgba(255,255,255,0.04)", border: BORDER, borderRadius: 6,
                    padding: "6px 10px", color: "#e8eaf0", fontSize: 12, width: 180 }}/>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <label style={{ fontSize: 10, color: "#555" }}>Rationale</label>
                <input value={newTool.rationale} onChange={e => setNewTool(t => ({ ...t, rationale: e.target.value }))}
                  placeholder="Approved by IT security on 2026-06-01" style={{
                    background: "rgba(255,255,255,0.04)", border: BORDER, borderRadius: 6,
                    padding: "6px 10px", color: "#e8eaf0", fontSize: 12, width: 260 }}/>
              </div>
              <button onClick={addWhitelist} disabled={adding || !newTool.ai_tool} style={{
                border: `1px solid ${ACCENT}66`, borderRadius: 6, padding: "6px 16px", fontSize: 11,
                fontWeight: 700, color: ACCENT, background: "rgba(0,229,160,0.06)",
                cursor: adding || !newTool.ai_tool ? "not-allowed" : "pointer" }}>
                {adding ? "Adding…" : "+ Add"}
              </button>
            </div>
            {addMsg && <div style={{ marginTop: 10, fontSize: 12, color: ACCENT }}>{addMsg}</div>}
          </div>

          {/* Whitelist table */}
          <div style={{ background: CARD_BG, border: BORDER, borderRadius: 12, overflow: "hidden" }}>
            {whitelist.length === 0
              ? <div style={{ padding: 32, textAlign: "center", color: "#555" }}>
                  No approved AI tools yet. Add tools that are sanctioned by IT Security.
                </div>
              : (
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
                      {["Tool", "Vendor", "Approved By", "Rationale", "Added", ""].map(h => (
                        <th key={h} style={{ padding: "8px 12px", textAlign: "left", color: "#555", fontSize: 10, fontWeight: 600, letterSpacing: 0.5 }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {whitelist.map((w, i) => (
                      <tr key={w.id || i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}
                        onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.025)"}
                        onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                        <td style={{ padding: "9px 12px", fontWeight: 700, color: ACCENT }}>{w.ai_tool}</td>
                        <td style={{ padding: "9px 12px", color: "#9aa0b0" }}>{w.vendor || "—"}</td>
                        <td style={{ padding: "9px 12px", color: "#666", fontSize: 11 }}>{w.approved_by || "—"}</td>
                        <td style={{ padding: "9px 12px", color: "#666", fontSize: 11, maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{w.rationale || "—"}</td>
                        <td style={{ padding: "9px 12px", color: "#555", fontSize: 11 }}>
                          {w.created_at ? new Date(w.created_at).toLocaleDateString() : "—"}
                        </td>
                        <td style={{ padding: "9px 12px" }}>
                          <button onClick={() => removeWhitelist(w.id)} style={{
                            border: "1px solid #ff3b3b44", borderRadius: 4, padding: "2px 8px",
                            fontSize: 9, fontWeight: 700, color: "#ff3b3b", background: "transparent", cursor: "pointer" }}>
                            Remove
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            }
          </div>

          <div style={{ marginTop: 12, padding: "10px 14px", borderRadius: 8,
            background: "rgba(0,229,160,0.06)", border: "1px solid rgba(0,229,160,0.15)", fontSize: 11, color: "#666" }}>
            Tools on this list will not generate Shadow AI findings. CyEDR agents refresh the approved list hourly.
          </div>
        </>
      )}
    </div>
  );
}
