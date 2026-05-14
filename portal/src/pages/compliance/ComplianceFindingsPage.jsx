/**
 * ComplianceFindingsPage.jsx
 * ===========================
 * Filterable compliance findings table with AI analyze button.
 */

import { useState, useEffect, useCallback } from "react";
import { API_BASE } from "../../core/constants.js";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};

const SEV_COLORS = { critical: C.red, high: C.orange, medium: C.blue, low: C.muted, info: C.muted };
const FRAMEWORKS = ["", "nis2", "dora", "iso27001", "soc2", "nist_csf", "pci_dss"];
const SEVERITIES = ["", "critical", "high", "medium", "low"];
const STATUSES   = ["", "open", "in_progress", "resolved", "accepted"];

function SevBadge({ sev }) {
  const c = SEV_COLORS[sev] || C.muted;
  return (
    <span style={{ background: `${c}18`, color: c, border: `1px solid ${c}30`,
      fontSize: 9, fontFamily: "monospace", fontWeight: 700,
      padding: "2px 6px", borderRadius: 3, textTransform: "uppercase" }}>{sev}</span>
  );
}

function fmtTs(ts) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" }); }
  catch { return ts; }
}

export function ComplianceFindingsPage() {
  const [findings, setFindings] = useState([]);
  const [total, setTotal]       = useState(0);
  const [loading, setLoading]   = useState(true);
  const [framework, setFramework] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus]     = useState("open");
  const [page, setPage]         = useState(1);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm]         = useState({ title: "", framework: "iso27001", severity: "medium", description: "" });
  const [aiMap, setAiMap]       = useState({});
  const [aiLoading, setAiLoading] = useState({});
  const PER_PAGE = 50;

  const load = useCallback(() => {
    setLoading(true);
    const p = new URLSearchParams({ page, per_page: PER_PAGE });
    if (framework) p.set("framework", framework);
    if (severity)  p.set("severity", severity);
    if (status)    p.set("status", status);
    fetch(`${API_BASE}/api/comp/findings?${p}`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setFindings(d.findings || []); setTotal(d.total || 0); setLoading(false); })
      .catch(() => setLoading(false));
  }, [page, framework, severity, status]);

  useEffect(() => { load(); }, [load]);

  const handleCreate = () => {
    fetch(`${API_BASE}/api/comp/findings`, { method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(form) })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(() => { setShowForm(false); setForm({ title: "", framework: "iso27001", severity: "medium", description: "" }); load(); })
      .catch(e => alert(`Create failed: ${e}`));
  };

  const handleStatusUpdate = (id, newStatus) => {
    fetch(`${API_BASE}/api/comp/findings/${id}`, { method: "PUT", credentials: "include",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: newStatus }) })
      .then(r => r.ok ? load() : alert("Update failed"));
  };

  const handleAnalyze = (finding) => {
    setAiLoading(m => ({ ...m, [finding.id]: true }));
    fetch(`${API_BASE}/api/comp/findings/${finding.id}/analyze`, { method: "POST", credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setAiMap(m => ({ ...m, [finding.id]: d.analysis })); })
      .catch(() => {})
      .finally(() => setAiLoading(m => ({ ...m, [finding.id]: false })));
  };

  const inp = { background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
    borderRadius: 4, color: C.text, fontFamily: "monospace", fontSize: 12,
    padding: "7px 10px", width: "100%", outline: "none", boxSizing: "border-box" };

  const totalPages = Math.ceil(total / PER_PAGE);

  return (
    <div>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px", fontFamily: "monospace",
            textTransform: "uppercase", marginBottom: 4 }}>SECURITY COMPLIANCE</div>
          <h1 style={{ color: C.text, fontSize: 20, fontWeight: 700, margin: 0 }}>Compliance Findings</h1>
          <div style={{ color: C.muted, fontSize: 11, marginTop: 4, fontFamily: "monospace" }}>
            {total} findings
          </div>
        </div>
        <button onClick={() => setShowForm(s => !s)}
          style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
            color: C.accent, padding: "8px 18px", borderRadius: 4, fontFamily: "monospace",
            fontSize: 11, fontWeight: 700, cursor: "pointer" }}>
          {showForm ? "Close" : "+ Add Finding"}
        </button>
      </div>

      {showForm && (
        <div style={{ background: "#0d1117", border: `1px solid ${C.border}`, borderRadius: 8,
          padding: 20, marginBottom: 20, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <div style={{ gridColumn: "1/-1" }}>
            <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px",
              textTransform: "uppercase", marginBottom: 5 }}>Title *</div>
            <input style={inp} value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
          </div>
          {[
            { key: "framework", opts: FRAMEWORKS.filter(Boolean), label: "Framework" },
            { key: "severity", opts: SEVERITIES.filter(Boolean), label: "Severity" },
          ].map(({ key, opts, label }) => (
            <div key={key}>
              <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px",
                textTransform: "uppercase", marginBottom: 5 }}>{label}</div>
              <select style={{ ...inp, cursor: "pointer" }} value={form[key]}
                onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}>
                {opts.map(o => <option key={o} value={o}>{o.toUpperCase()}</option>)}
              </select>
            </div>
          ))}
          <div style={{ gridColumn: "1/-1" }}>
            <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px",
              textTransform: "uppercase", marginBottom: 5 }}>Description</div>
            <textarea style={{ ...inp, height: 64, resize: "vertical" }}
              value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          </div>
          <div style={{ gridColumn: "1/-1", display: "flex", gap: 10, justifyContent: "flex-end" }}>
            <button onClick={() => setShowForm(false)} style={{ background: "rgba(255,255,255,0.04)",
              border: `1px solid ${C.border}`, color: C.muted, padding: "8px 18px",
              borderRadius: 4, fontFamily: "monospace", fontSize: 11, cursor: "pointer" }}>Cancel</button>
            <button onClick={handleCreate} style={{ background: `${C.accent}10`,
              border: `1px solid ${C.accent}40`, color: C.accent, padding: "8px 18px",
              borderRadius: 4, fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer" }}>
              Create Finding
            </button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
        {[
          { label: "Framework", value: framework, setValue: setFramework, options: FRAMEWORKS },
          { label: "Severity",  value: severity,  setValue: setSeverity,  options: SEVERITIES },
          { label: "Status",    value: status,    setValue: setStatus,    options: STATUSES },
        ].map(({ label, value, setValue, options }) => (
          <select key={label} value={value} onChange={e => { setValue(e.target.value); setPage(1); }}
            style={{ background: "#0d1117", border: `1px solid ${C.border}`, color: C.text,
              borderRadius: 4, padding: "6px 10px", fontFamily: "monospace", fontSize: 11, cursor: "pointer" }}>
            <option value="">{label}: All</option>
            {options.filter(Boolean).map(o => <option key={o} value={o}>{o.toUpperCase()}</option>)}
          </select>
        ))}
      </div>

      {/* Findings table */}
      <div style={{ background: "#0d1117", border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {["Severity", "Framework", "Control", "Title", "Status", "Date", "Actions"].map(h => (
                <th key={h} style={{ padding: "10px 14px", textAlign: "left",
                  color: C.muted, fontSize: 9, fontFamily: "monospace",
                  letterSpacing: "1px", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} style={{ padding: 32, textAlign: "center",
                color: C.muted, fontFamily: "monospace" }}>Loading...</td></tr>
            ) : findings.length === 0 ? (
              <tr><td colSpan={7} style={{ padding: 32, textAlign: "center",
                color: C.muted, fontFamily: "monospace" }}>No findings match the selected filters.</td></tr>
            ) : findings.map((f, i) => [
              <tr key={f.id} style={{ borderBottom: `1px solid rgba(255,255,255,0.03)`,
                background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)" }}>
                <td style={{ padding: "10px 14px" }}><SevBadge sev={f.severity} /></td>
                <td style={{ padding: "10px 14px", color: C.blue, fontSize: 9, fontFamily: "monospace",
                  textTransform: "uppercase" }}>{f.framework}</td>
                <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                  {f.control_id || "—"}
                </td>
                <td style={{ padding: "10px 14px", color: C.text, fontSize: 11, maxWidth: 300 }}>
                  <div style={{ fontWeight: 600, marginBottom: 2 }}>{f.title}</div>
                  {f.description && (
                    <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace",
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 280 }}>
                      {f.description}
                    </div>
                  )}
                </td>
                <td style={{ padding: "10px 14px" }}>
                  <select value={f.status}
                    onChange={e => handleStatusUpdate(f.id, e.target.value)}
                    style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
                      color: f.status === "open" ? C.orange : f.status === "resolved" ? C.accent : C.muted,
                      borderRadius: 3, padding: "3px 6px", fontFamily: "monospace", fontSize: 9,
                      cursor: "pointer", textTransform: "uppercase" }}>
                    {STATUSES.filter(Boolean).map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
                  </select>
                </td>
                <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                  {fmtTs(f.created_at)}
                </td>
                <td style={{ padding: "10px 14px" }}>
                  <button onClick={() => handleAnalyze(f)} disabled={aiLoading[f.id]}
                    style={{ background: "rgba(176,110,255,0.1)", border: `1px solid ${C.purple}30`,
                      color: C.purple, padding: "4px 10px", borderRadius: 3, fontFamily: "monospace",
                      fontSize: 9, cursor: "pointer", fontWeight: 700, opacity: aiLoading[f.id] ? 0.6 : 1 }}>
                    {aiLoading[f.id] ? "AI..." : "Analyze"}
                  </button>
                </td>
              </tr>,
              (aiMap[f.id] || f.ai_analysis) && (
                <tr key={`${f.id}-ai`} style={{ background: "rgba(176,110,255,0.04)",
                  borderBottom: `1px solid rgba(255,255,255,0.03)` }}>
                  <td colSpan={7} style={{ padding: "10px 14px" }}>
                    <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                      letterSpacing: "1px", textTransform: "uppercase", marginBottom: 6 }}>AI Analysis</div>
                    <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 11,
                      fontFamily: "monospace", lineHeight: 1.6, whiteSpace: "pre-wrap", maxWidth: 900 }}>
                      {aiMap[f.id] || f.ai_analysis}
                    </div>
                  </td>
                </tr>
              ),
            ].filter(Boolean))}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 16 }}>
          <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
            style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
              color: C.text, padding: "6px 14px", borderRadius: 4, fontFamily: "monospace",
              fontSize: 11, cursor: "pointer", opacity: page === 1 ? 0.4 : 1 }}>Previous</button>
          <span style={{ color: C.muted, fontSize: 11, fontFamily: "monospace", alignSelf: "center" }}>
            {page} / {totalPages}
          </span>
          <button disabled={page === totalPages} onClick={() => setPage(p => p + 1)}
            style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
              color: C.text, padding: "6px 14px", borderRadius: 4, fontFamily: "monospace",
              fontSize: 11, cursor: "pointer", opacity: page === totalPages ? 0.4 : 1 }}>Next</button>
        </div>
      )}
    </div>
  );
}
