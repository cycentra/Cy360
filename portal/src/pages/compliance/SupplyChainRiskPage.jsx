/**
 * SupplyChainRiskPage.jsx — Supply Chain Cyber Risk (#12)
 * =========================================================
 * Visualises supply chain risks from the exposure register (exposure_type=supply_chain).
 * Sources: ASM scan imports + manual entries.
 * Actions: import from latest ASM scan, resolve/accept items.
 */

import { useState, useEffect, useCallback } from "react";
import { API_BASE } from "../../core/constants.js";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};
const CARD = {
  background: "rgba(255,255,255,0.02)", border: `1px solid ${C.border}`,
  borderRadius: 8, padding: "20px 24px",
};

const SEV_COLORS = { critical: C.red, high: C.orange, medium: C.blue, low: C.muted };
const SEV_ORDER  = { critical: 0, high: 1, medium: 2, low: 3 };

function SevBadge({ sev }) {
  const color = SEV_COLORS[sev] || C.muted;
  return (
    <span style={{
      background: `${color}22`, color, border: `1px solid ${color}44`,
      borderRadius: 4, padding: "2px 8px", fontSize: 11, fontWeight: 600,
      textTransform: "uppercase", letterSpacing: 1,
    }}>{sev || "—"}</span>
  );
}

function StatusBadge({ status }) {
  const map = { open: C.orange, in_progress: C.blue, resolved: C.accent, accepted: C.muted };
  const c = map[status] || C.muted;
  return (
    <span style={{
      color: c, fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5,
    }}>{status?.replace(/_/g, " ") || "—"}</span>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div style={{ ...CARD, textAlign: "center", minWidth: 110 }}>
      <div style={{ fontSize: 28, fontWeight: 700, color: color || C.text, fontFamily: "monospace" }}>
        {value ?? "—"}
      </div>
      <div style={{ fontSize: 11, color: C.muted, marginTop: 4, textTransform: "uppercase", letterSpacing: 0.8 }}>
        {label}
      </div>
    </div>
  );
}

export default function SupplyChainRiskPage() {
  const [items, setItems]     = useState([]);
  const [loading, setLoading] = useState(true);
  const [importing, setImp]   = useState(false);
  const [msg, setMsg]         = useState(null);
  const [filter, setFilter]   = useState({ sev: "all", status: "all", search: "" });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(
        `${API_BASE}/api/comp/exposure?exposure_type=supply_chain&limit=200`,
        { credentials: "include" }
      );
      const d = await r.json();
      const sorted = (d.items || []).sort(
        (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
      );
      setItems(sorted);
    } catch (e) {
      setMsg({ type: "error", text: "Failed to load supply chain risks." });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const importASM = async () => {
    setImp(true);
    setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/comp/exposure/import-asm`,
        { method: "POST", credentials: "include" });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Import failed");
      setMsg({ type: "ok", text: `Imported ${d.imported} items (${d.skipped} already existed)` });
      await load();
    } catch (e) {
      setMsg({ type: "error", text: e.message });
    } finally {
      setImp(false);
    }
  };

  const updateStatus = async (id, status) => {
    try {
      const r = await fetch(`${API_BASE}/api/comp/exposure/${id}`,
        {
          method: "PUT", credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status }),
        });
      if (!r.ok) throw new Error("Update failed");
      setItems(prev => prev.map(i => i.id === id ? { ...i, status } : i));
    } catch (e) {
      setMsg({ type: "error", text: e.message });
    }
  };

  // Stats
  const total    = items.length;
  const critical = items.filter(i => i.severity === "critical").length;
  const high     = items.filter(i => i.severity === "high").length;
  const resolved = items.filter(i => i.status === "resolved" || i.status === "accepted").length;

  // Filter
  const visible = items.filter(i => {
    if (filter.sev !== "all" && i.severity !== filter.sev) return false;
    if (filter.status !== "all" && i.status !== filter.status) return false;
    if (filter.search) {
      const q = filter.search.toLowerCase();
      return (i.asset || "").toLowerCase().includes(q)
        || (i.title || "").toLowerCase().includes(q)
        || (i.cves || []).join(" ").toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div style={{ padding: "28px 32px", background: C.bg, minHeight: "100vh", color: C.text, fontFamily: "system-ui, sans-serif" }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <div style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>Supply Chain Risk</div>
          <div style={{ color: C.muted, fontSize: 13 }}>
            Third-party and dependency risks imported from ASM scans and manual entries.
          </div>
        </div>
        <button
          onClick={importASM}
          disabled={importing}
          style={{
            background: importing ? "rgba(255,255,255,0.05)" : C.accent,
            color: importing ? C.muted : "#000",
            border: "none", borderRadius: 6, padding: "9px 18px",
            fontSize: 13, fontWeight: 600, cursor: importing ? "not-allowed" : "pointer",
          }}
        >
          {importing ? "Importing…" : "Import from ASM Scan"}
        </button>
      </div>

      {/* Message */}
      {msg && (
        <div style={{
          ...CARD, marginBottom: 20,
          borderColor: msg.type === "error" ? C.red : C.accent,
          color: msg.type === "error" ? C.red : C.accent,
          padding: "10px 18px", fontSize: 13,
        }}>
          {msg.text}
        </div>
      )}

      {/* Stats */}
      <div style={{ display: "flex", gap: 12, marginBottom: 24, flexWrap: "wrap" }}>
        <StatCard label="Total Dependencies" value={total} color={C.text} />
        <StatCard label="Critical"           value={critical} color={C.red} />
        <StatCard label="High"               value={high} color={C.orange} />
        <StatCard label="Resolved / Accepted" value={resolved} color={C.accent} />
      </div>

      {/* Empty state */}
      {!loading && items.length === 0 && (
        <div style={{ ...CARD, textAlign: "center", padding: "40px 24px" }}>
          <div style={{ fontSize: 36, marginBottom: 12 }}>📦</div>
          <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>No supply chain risks found</div>
          <div style={{ color: C.muted, fontSize: 13, marginBottom: 20 }}>
            Click "Import from ASM Scan" to pull supply chain risks from your latest ASM scan,
            or add items manually via the Exposure Register.
          </div>
          <button
            onClick={importASM}
            style={{ background: C.accent, color: "#000", border: "none", borderRadius: 6,
              padding: "9px 18px", fontSize: 13, fontWeight: 600, cursor: "pointer" }}
          >
            Import from ASM Scan
          </button>
        </div>
      )}

      {/* Filters + table */}
      {items.length > 0 && (
        <div style={CARD}>
          {/* Filters */}
          <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
            <input
              placeholder="Search asset, title, CVE…"
              value={filter.search}
              onChange={e => setFilter(f => ({ ...f, search: e.target.value }))}
              style={{
                flex: 1, minWidth: 200, background: "rgba(255,255,255,0.04)",
                border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 12px",
                color: C.text, fontSize: 13, outline: "none",
              }}
            />
            {[
              { key: "sev", opts: ["all", "critical", "high", "medium", "low"], label: "Severity" },
              { key: "status", opts: ["all", "open", "in_progress", "resolved", "accepted"], label: "Status" },
            ].map(({ key, opts, label }) => (
              <select key={key} value={filter[key]}
                onChange={e => setFilter(f => ({ ...f, [key]: e.target.value }))}
                style={{
                  background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
                  borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 13,
                }}
              >
                {opts.map(o => <option key={o} value={o}>{o === "all" ? `All ${label}` : o.replace(/_/g," ")}</option>)}
              </select>
            ))}
          </div>

          {/* Table */}
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}`, color: C.muted, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.8 }}>
                  {["Asset / Library", "Risk", "CVEs", "CVSS", "Severity", "Status", "Actions"].map(h => (
                    <th key={h} style={{ padding: "8px 12px", textAlign: "left", whiteSpace: "nowrap" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visible.map(item => (
                  <tr key={item.id} style={{ borderBottom: `1px solid rgba(255,255,255,0.04)` }}>
                    <td style={{ padding: "10px 12px", color: C.accent, fontFamily: "monospace", fontSize: 12 }}>
                      {item.asset || "—"}
                    </td>
                    <td style={{ padding: "10px 12px", maxWidth: 260, color: C.text }}>
                      <div style={{ fontWeight: 500, marginBottom: 2 }}>{item.title}</div>
                      {item.description && (
                        <div style={{ color: C.muted, fontSize: 11, overflow: "hidden",
                          display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>
                          {item.description}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: "10px 12px", fontFamily: "monospace", fontSize: 11 }}>
                      {(item.cves || []).slice(0, 3).map(c => (
                        <div key={c} style={{ color: C.red, marginBottom: 1 }}>{c}</div>
                      ))}
                      {(item.cves || []).length > 3 && (
                        <div style={{ color: C.muted }}>+{item.cves.length - 3} more</div>
                      )}
                    </td>
                    <td style={{ padding: "10px 12px", color: C.muted, fontFamily: "monospace" }}>
                      {item.cvss_score ?? "—"}
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      <SevBadge sev={item.severity} />
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      <StatusBadge status={item.status} />
                    </td>
                    <td style={{ padding: "10px 12px", whiteSpace: "nowrap" }}>
                      {item.status === "open" || item.status === "in_progress" ? (
                        <div style={{ display: "flex", gap: 6 }}>
                          <button onClick={() => updateStatus(item.id, "resolved")}
                            style={{ background: `${C.accent}22`, color: C.accent, border: `1px solid ${C.accent}44`,
                              borderRadius: 4, padding: "3px 8px", fontSize: 11, cursor: "pointer" }}>
                            Resolve
                          </button>
                          <button onClick={() => updateStatus(item.id, "accepted")}
                            style={{ background: `${C.muted}22`, color: C.muted, border: `1px solid ${C.border}`,
                              borderRadius: 4, padding: "3px 8px", fontSize: 11, cursor: "pointer" }}>
                            Accept Risk
                          </button>
                        </div>
                      ) : (
                        <button onClick={() => updateStatus(item.id, "open")}
                          style={{ background: "rgba(255,255,255,0.04)", color: C.muted, border: `1px solid ${C.border}`,
                            borderRadius: 4, padding: "3px 8px", fontSize: 11, cursor: "pointer" }}>
                          Reopen
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div style={{ marginTop: 12, color: C.muted, fontSize: 12 }}>
            Showing {visible.length} of {total} supply chain risks
          </div>
        </div>
      )}

      {loading && (
        <div style={{ color: C.muted, textAlign: "center", padding: 40, fontSize: 13 }}>
          Loading supply chain risks…
        </div>
      )}
    </div>
  );
}
