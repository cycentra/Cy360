/**
 * ComplianceLiveAlertsPage.jsx
 * ==============================
 * Compliance-relevant alerts from the correlation engine.
 * Data source: alerts table (is_compliance_relevant = TRUE) — no duplication.
 * Uses compliance_frameworks[], compliance_controls{} columns enriched by siem_bridge.
 */

import { useState, useEffect, useCallback } from "react";
import { API_BASE } from "../../core/constants.js";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};

const SEV_COLORS = { critical: C.red, high: C.orange, medium: C.blue, low: C.muted, info: C.muted };

const FW_COLORS = {
  nis2: "#6378ff", iso27001: "#00e5c0", dora: "#ffd166",
  soc2: "#ff6b6b", avg: "#a78bfa", nist_csf: "#38bdf8", pci_dss: "#f97316", hipaa: "#84cc16",
};

const FRAMEWORKS = ["", "nis2", "dora", "iso27001", "soc2", "nist_csf", "pci_dss", "avg"];
const SEVERITIES = ["", "critical", "high", "medium", "low"];

function FrameworkBadge({ fw }) {
  const color = FW_COLORS[fw] || "#6378ff";
  return (
    <span style={{
      fontSize: 9, padding: "1px 5px", borderRadius: 3, fontFamily: "monospace",
      fontWeight: 700, background: `${color}18`, color,
      border: `1px solid ${color}40`, whiteSpace: "nowrap",
    }}>
      {fw.toUpperCase()}
    </span>
  );
}

function ControlBadges({ controls }) {
  if (!controls || !Object.keys(controls).length) return null;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 3, marginTop: 4 }}>
      {Object.entries(controls).map(([fw, ids]) =>
        Array.isArray(ids) && ids.length > 0 ? (
          <span key={fw} title={ids.join(", ")}
            style={{
              fontSize: 9, padding: "1px 5px", borderRadius: 3, fontFamily: "monospace",
              fontWeight: 700, background: `${FW_COLORS[fw] || "#6378ff"}18`,
              color: FW_COLORS[fw] || "#6378ff",
              border: `1px solid ${FW_COLORS[fw] || "#6378ff"}40`,
            }}>
            {fw.toUpperCase()}: {ids.slice(0, 2).join(", ")}{ids.length > 2 ? ` +${ids.length - 2}` : ""}
          </span>
        ) : null
      )}
    </div>
  );
}

function SevBadge({ sev }) {
  const c = SEV_COLORS[sev] || C.muted;
  return (
    <span style={{
      background: `${c}18`, color: c, border: `1px solid ${c}30`,
      fontSize: 9, fontFamily: "monospace", fontWeight: 700,
      padding: "2px 6px", borderRadius: 3, textTransform: "uppercase",
    }}>
      {sev}
    </span>
  );
}

function ConfidencePill({ score }) {
  if (!score) return null;
  const pct = Math.round(score * 100);
  const color = pct >= 80 ? C.red : pct >= 60 ? C.orange : C.blue;
  return (
    <span style={{
      fontSize: 9, fontFamily: "monospace", color,
      background: `${color}12`, border: `1px solid ${color}30`,
      padding: "1px 5px", borderRadius: 3, marginLeft: 4,
    }}>
      {pct}% conf
    </span>
  );
}

function fmtTs(ts) {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString("en-US", {
      month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
    });
  } catch { return ts; }
}

export function ComplianceLiveAlertsPage() {
  const [alerts, setAlerts]     = useState([]);
  const [total, setTotal]       = useState(0);
  const [loading, setLoading]   = useState(true);
  const [syncing, setSyncing]   = useState(false);
  const [syncMsg, setSyncMsg]   = useState(null);
  const [severity, setSeverity] = useState("");
  const [framework, setFramework] = useState("");
  const [page, setPage]         = useState(1);

  const PER_PAGE = 50;

  const load = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams({ page, per_page: PER_PAGE });
    if (severity)  params.set("severity",  severity);
    if (framework) params.set("framework", framework);
    fetch(`${API_BASE}/api/comp/alerts?${params}`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setAlerts(d.alerts || []); setTotal(d.total || 0); setLoading(false); })
      .catch(() => setLoading(false));
  }, [page, severity, framework]);

  useEffect(() => { load(); }, [load]);

  const handleSync = () => {
    setSyncing(true); setSyncMsg(null);
    fetch(`${API_BASE}/api/comp/alerts/sync`, { method: "POST", credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        const a = d.result?.alerts || {};
        setSyncMsg(`Enriched ${a.enriched || 0} alerts — ${a.relevant || 0} compliance-relevant`);
        load();
      })
      .catch(e => setSyncMsg(`Enrichment failed (${e})`))
      .finally(() => setSyncing(false));
  };

  const totalPages = Math.ceil(total / PER_PAGE);

  return (
    <div>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px", fontFamily: "monospace", textTransform: "uppercase", marginBottom: 4 }}>
            SECURITY COMPLIANCE
          </div>
          <h1 style={{ color: C.text, fontSize: 20, fontWeight: 700, margin: 0 }}>Live Compliance Alerts</h1>
          <div style={{ color: C.muted, fontSize: 11, marginTop: 4, fontFamily: "monospace" }}>
            {total} compliance-relevant alerts from correlation engine
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8, alignItems: "flex-end" }}>
          <button onClick={handleSync} disabled={syncing}
            style={{
              background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
              color: C.accent, padding: "8px 18px", borderRadius: 4,
              fontFamily: "monospace", fontSize: 11, fontWeight: 700,
              cursor: "pointer", opacity: syncing ? 0.6 : 1,
            }}>
            {syncing ? "Enriching..." : "Run Compliance Enrichment"}
          </button>
          {syncMsg && (
            <div style={{ color: syncMsg.includes("failed") ? C.red : C.accent, fontSize: 10, fontFamily: "monospace" }}>
              {syncMsg}
            </div>
          )}
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
        {[
          { label: "Severity",  value: severity,  setValue: setSeverity,  options: SEVERITIES },
          { label: "Framework", value: framework, setValue: setFramework, options: FRAMEWORKS },
        ].map(({ label, value, setValue, options }) => (
          <select key={label} value={value} onChange={e => { setValue(e.target.value); setPage(1); }}
            style={{
              background: "#0d1117", border: `1px solid ${C.border}`, color: C.text,
              borderRadius: 4, padding: "6px 10px", fontFamily: "monospace", fontSize: 11, cursor: "pointer",
            }}>
            <option value="">{label}: All</option>
            {options.filter(Boolean).map(o => <option key={o} value={o}>{o.toUpperCase()}</option>)}
          </select>
        ))}
      </div>

      {/* Alert table */}
      <div style={{ background: "#0d1117", border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {["Sev / Level", "Rule & Description", "MITRE", "Frameworks & Controls", "Agent", "Incident", "Time"].map(h => (
                <th key={h} style={{
                  padding: "10px 14px", textAlign: "left",
                  color: C.muted, fontSize: 9, fontFamily: "monospace",
                  letterSpacing: "1px", textTransform: "uppercase",
                }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} style={{ padding: 32, textAlign: "center", color: C.muted, fontFamily: "monospace", fontSize: 12 }}>Loading...</td></tr>
            ) : alerts.length === 0 ? (
              <tr><td colSpan={7} style={{ padding: 32, textAlign: "center", color: C.muted, fontFamily: "monospace", fontSize: 12 }}>
                {total === 0
                  ? "No compliance-relevant alerts found. Click \"Run Compliance Enrichment\" to tag existing alerts."
                  : "No alerts match the current filters."}
              </td></tr>
            ) : alerts.map((a, i) => (
              <tr key={a.id} style={{
                borderBottom: `1px solid rgba(255,255,255,0.03)`,
                background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)",
                verticalAlign: "top",
              }}>
                {/* Severity + level */}
                <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                  <SevBadge sev={a.severity} />
                  <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace", marginTop: 3 }}>
                    Lvl {a.rule_level} · Score {a.base_score.toFixed(1)}
                  </div>
                </td>
                {/* Rule + description */}
                <td style={{ padding: "10px 14px", color: C.text, fontSize: 11, maxWidth: 320 }}>
                  <div style={{ fontWeight: 600, marginBottom: 2 }}>{a.title}</div>
                  <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>
                    Rule {a.rule_id} · {a.category || "—"}
                    {a.src_ip && <span> · {a.src_ip}</span>}
                    {a.username && <span> · {a.username}</span>}
                  </div>
                  <ConfidencePill score={a.compliance_confidence} />
                </td>
                {/* MITRE */}
                <td style={{ padding: "10px 14px", color: C.purple, fontSize: 10, fontFamily: "monospace", whiteSpace: "nowrap" }}>
                  {a.mitre_technique || "—"}
                  {a.mitre_tactic && (
                    <div style={{ color: "rgba(176,110,255,0.55)", fontSize: 9, marginTop: 2 }}>
                      {a.mitre_tactic}
                    </div>
                  )}
                </td>
                {/* Frameworks + controls */}
                <td style={{ padding: "10px 14px", maxWidth: 280 }}>
                  {(a.compliance_frameworks || []).length > 0 ? (
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 3, marginBottom: 4 }}>
                      {(a.compliance_frameworks || []).map(fw => <FrameworkBadge key={fw} fw={fw} />)}
                    </div>
                  ) : (
                    <span style={{ color: "rgba(255,255,255,0.15)", fontSize: 9, fontFamily: "monospace" }}>no mapping</span>
                  )}
                  <ControlBadges controls={a.controls} />
                </td>
                {/* Agent */}
                <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                  {a.agent_name || "—"}
                  {a.agent_ip && <div style={{ fontSize: 9, color: "rgba(255,255,255,0.2)" }}>{a.agent_ip}</div>}
                </td>
                {/* Incident link */}
                <td style={{ padding: "10px 14px", fontSize: 10, fontFamily: "monospace" }}>
                  {a.incident_id ? (
                    <span style={{ color: C.orange }}>{a.incident_id}</span>
                  ) : (
                    <span style={{ color: "rgba(255,255,255,0.15)" }}>—</span>
                  )}
                </td>
                {/* Time */}
                <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10, fontFamily: "monospace", whiteSpace: "nowrap" }}>
                  {fmtTs(a.timestamp)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 16 }}>
          <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
            style={{
              background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
              color: C.text, padding: "6px 14px", borderRadius: 4,
              fontFamily: "monospace", fontSize: 11, cursor: "pointer",
              opacity: page === 1 ? 0.4 : 1,
            }}>
            Previous
          </button>
          <span style={{ color: C.muted, fontSize: 11, fontFamily: "monospace", display: "flex", alignItems: "center" }}>
            {page} / {totalPages}
          </span>
          <button disabled={page === totalPages} onClick={() => setPage(p => p + 1)}
            style={{
              background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
              color: C.text, padding: "6px 14px", borderRadius: 4,
              fontFamily: "monospace", fontSize: 11, cursor: "pointer",
              opacity: page === totalPages ? 0.4 : 1,
            }}>
            Next
          </button>
        </div>
      )}
    </div>
  );
}
