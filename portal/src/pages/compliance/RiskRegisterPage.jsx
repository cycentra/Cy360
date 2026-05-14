/**
 * RiskRegisterPage.jsx
 * =====================
 * Risk register table with CRUD + AI analyze + heatmap toggle.
 */

import { useState, useEffect, useCallback } from "react";
import { API_BASE } from "../../core/constants.js";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};

const SEVERITY_COLORS = { critical: C.red, high: C.orange, medium: C.blue, low: C.muted };
const CATEGORIES = ["IT", "Operational", "Financial", "Legal", "Reputational"];
const TREATMENTS = ["mitigate", "avoid", "transfer", "accept"];
const APPETITES  = ["low", "medium", "high"];

function SevBadge({ score }) {
  const sev = score >= 20 ? "critical" : score >= 12 ? "high" : score >= 6 ? "medium" : "low";
  const c   = SEVERITY_COLORS[sev] || C.muted;
  return (
    <span style={{ background: `${c}18`, color: c, border: `1px solid ${c}30`,
      fontSize: 9, fontFamily: "monospace", fontWeight: 700,
      padding: "2px 6px", borderRadius: 3, textTransform: "uppercase" }}>
      {sev} ({score})
    </span>
  );
}

function RiskForm({ initial, onSave, onCancel }) {
  const [form, setForm] = useState(initial || {
    title: "", description: "", category: "IT", owner: "",
    likelihood: 3, impact: 3, appetite: "medium", treatment: "mitigate",
  });
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));
  const score = (form.likelihood || 3) * (form.impact || 3);

  const inp = {
    background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
    borderRadius: 4, color: C.text, fontFamily: "monospace", fontSize: 12,
    padding: "7px 10px", width: "100%", outline: "none", boxSizing: "border-box",
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, padding: 20,
      background: "#0d1117", border: `1px solid ${C.border}`, borderRadius: 8, marginBottom: 20 }}>
      <div style={{ gridColumn: "1/-1" }}>
        <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px",
          textTransform: "uppercase", marginBottom: 5 }}>Title *</div>
        <input style={inp} value={form.title} onChange={e => set("title", e.target.value)} />
      </div>
      <div style={{ gridColumn: "1/-1" }}>
        <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px",
          textTransform: "uppercase", marginBottom: 5 }}>Description</div>
        <textarea style={{ ...inp, height: 72, resize: "vertical" }}
          value={form.description} onChange={e => set("description", e.target.value)} />
      </div>
      {[
        { label: "Category", key: "category", opts: CATEGORIES },
        { label: "Treatment", key: "treatment", opts: TREATMENTS },
        { label: "Appetite", key: "appetite", opts: APPETITES },
      ].map(({ label, key, opts }) => (
        <div key={key}>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px",
            textTransform: "uppercase", marginBottom: 5 }}>{label}</div>
          <select style={{ ...inp, cursor: "pointer" }} value={form[key]}
            onChange={e => set(key, e.target.value)}>
            {opts.map(o => <option key={o} value={o}>{o.charAt(0).toUpperCase() + o.slice(1)}</option>)}
          </select>
        </div>
      ))}
      <div>
        <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px",
          textTransform: "uppercase", marginBottom: 5 }}>Owner</div>
        <input style={inp} value={form.owner} onChange={e => set("owner", e.target.value)} />
      </div>
      <div>
        <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px",
          textTransform: "uppercase", marginBottom: 5 }}>
          Likelihood (1-5): <span style={{ color: C.accent }}>{form.likelihood}</span>
        </div>
        <input type="range" min={1} max={5} value={form.likelihood}
          onChange={e => set("likelihood", +e.target.value)}
          style={{ width: "100%", accentColor: C.accent }} />
      </div>
      <div>
        <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px",
          textTransform: "uppercase", marginBottom: 5 }}>
          Impact (1-5): <span style={{ color: C.orange }}>{form.impact}</span>
        </div>
        <input type="range" min={1} max={5} value={form.impact}
          onChange={e => set("impact", +e.target.value)}
          style={{ width: "100%", accentColor: C.orange }} />
      </div>
      <div style={{ gridColumn: "1/-1" }}>
        <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
          Risk Score: <span style={{ color: score >= 20 ? C.red : score >= 12 ? C.orange : C.blue,
            fontWeight: 700, fontSize: 14 }}>{score}/25</span>
        </div>
      </div>
      <div style={{ gridColumn: "1/-1", display: "flex", gap: 10, justifyContent: "flex-end" }}>
        <button onClick={onCancel} style={{ background: "rgba(255,255,255,0.04)",
          border: `1px solid ${C.border}`, color: C.muted, padding: "8px 18px",
          borderRadius: 4, fontFamily: "monospace", fontSize: 11, cursor: "pointer" }}>
          Cancel
        </button>
        <button onClick={() => onSave(form)} style={{ background: `${C.accent}10`,
          border: `1px solid ${C.accent}40`, color: C.accent, padding: "8px 18px",
          borderRadius: 4, fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer" }}>
          Save Risk
        </button>
      </div>
    </div>
  );
}

export function RiskRegisterPage({ setActiveTab }) {
  const [risks, setRisks]       = useState([]);
  const [loading, setLoading]   = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing]   = useState(null);
  const [aiMap, setAiMap]       = useState({});
  const [aiLoading, setAiLoading] = useState({});

  const load = useCallback(() => {
    setLoading(true);
    fetch(`${API_BASE}/api/comp/risks`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setRisks(d.risks || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleSave = (form) => {
    const method = editing ? "PUT" : "POST";
    const url    = editing ? `${API_BASE}/api/comp/risks/${editing.id}` : `${API_BASE}/api/comp/risks`;
    fetch(url, { method, credentials: "include",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(form) })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(() => { setShowForm(false); setEditing(null); load(); })
      .catch(e => alert(`Save failed: ${e}`));
  };

  const handleDelete = (id) => {
    if (!confirm("Delete this risk?")) return;
    fetch(`${API_BASE}/api/comp/risks/${id}`, { method: "DELETE", credentials: "include" })
      .then(r => r.ok ? load() : alert("Delete failed"));
  };

  const handleAnalyze = (id) => {
    setAiLoading(m => ({ ...m, [id]: true }));
    fetch(`${API_BASE}/api/comp/risks/${id}/analyze`, { method: "POST", credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        setAiMap(m => ({ ...m, [id]: d.analysis }));
        setAiLoading(m => ({ ...m, [id]: false }));
      })
      .catch(() => setAiLoading(m => ({ ...m, [id]: false })));
  };

  return (
    <div>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px", fontFamily: "monospace",
            textTransform: "uppercase", marginBottom: 4 }}>SECURITY COMPLIANCE</div>
          <h1 style={{ color: C.text, fontSize: 20, fontWeight: 700, margin: 0 }}>Risk Register</h1>
          <div style={{ color: C.muted, fontSize: 11, marginTop: 4, fontFamily: "monospace" }}>
            {risks.length} risks tracked
          </div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button onClick={() => setActiveTab && setActiveTab("comp-heatmap")}
            style={{ background: "rgba(176,110,255,0.1)", border: `1px solid ${C.purple}40`,
              color: C.purple, padding: "8px 18px", borderRadius: 4, fontFamily: "monospace",
              fontSize: 11, fontWeight: 700, cursor: "pointer" }}>
            Risk Heatmap
          </button>
          <button onClick={() => { setEditing(null); setShowForm(true); }}
            style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
              color: C.accent, padding: "8px 18px", borderRadius: 4, fontFamily: "monospace",
              fontSize: 11, fontWeight: 700, cursor: "pointer" }}>
            + Add Risk
          </button>
        </div>
      </div>

      {(showForm || editing) && (
        <RiskForm initial={editing} onSave={handleSave}
          onCancel={() => { setShowForm(false); setEditing(null); }} />
      )}

      <div style={{ background: "#0d1117", border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {["Risk", "Category", "Score", "Appetite", "Status", "Owner", "Actions"].map(h => (
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
            ) : risks.length === 0 ? (
              <tr><td colSpan={7} style={{ padding: 32, textAlign: "center",
                color: C.muted, fontFamily: "monospace" }}>No risks registered. Click "Add Risk" to begin.</td></tr>
            ) : risks.map((r, i) => [
              <tr key={r.id} style={{ borderBottom: `1px solid rgba(255,255,255,0.03)`,
                background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)" }}>
                <td style={{ padding: "10px 14px", maxWidth: 280 }}>
                  <div style={{ color: C.text, fontSize: 12, fontWeight: 600 }}>{r.title}</div>
                  {r.description && (
                    <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace",
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                      maxWidth: 260, marginTop: 2 }}>{r.description}</div>
                  )}
                </td>
                <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                  {r.category}
                </td>
                <td style={{ padding: "10px 14px" }}>
                  <SevBadge score={r.risk_score || 0} />
                </td>
                <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10, fontFamily: "monospace",
                  textTransform: "uppercase" }}>{r.appetite}</td>
                <td style={{ padding: "10px 14px" }}>
                  <span style={{ color: r.status === "open" ? C.orange : r.status === "mitigated" ? C.accent : C.muted,
                    fontSize: 10, fontFamily: "monospace", textTransform: "uppercase" }}>{r.status}</span>
                </td>
                <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                  {r.owner || "—"}
                </td>
                <td style={{ padding: "10px 14px" }}>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button onClick={() => { setEditing(r); setShowForm(false); }}
                      style={{ background: "rgba(77,158,255,0.1)", border: `1px solid ${C.blue}30`,
                        color: C.blue, padding: "4px 10px", borderRadius: 3, fontFamily: "monospace",
                        fontSize: 9, cursor: "pointer", fontWeight: 700 }}>Edit</button>
                    <button onClick={() => handleAnalyze(r.id)} disabled={aiLoading[r.id]}
                      style={{ background: "rgba(176,110,255,0.1)", border: `1px solid ${C.purple}30`,
                        color: C.purple, padding: "4px 10px", borderRadius: 3, fontFamily: "monospace",
                        fontSize: 9, cursor: "pointer", fontWeight: 700,
                        opacity: aiLoading[r.id] ? 0.6 : 1 }}>
                      {aiLoading[r.id] ? "AI..." : "AI"}
                    </button>
                    <button onClick={() => handleDelete(r.id)}
                      style={{ background: "rgba(255,59,59,0.1)", border: `1px solid ${C.red}30`,
                        color: C.red, padding: "4px 10px", borderRadius: 3, fontFamily: "monospace",
                        fontSize: 9, cursor: "pointer", fontWeight: 700 }}>Del</button>
                  </div>
                </td>
              </tr>,
              (aiMap[r.id] || r.ai_analysis) && (
                <tr key={`${r.id}-ai`} style={{ background: "rgba(176,110,255,0.04)",
                  borderBottom: `1px solid rgba(255,255,255,0.03)` }}>
                  <td colSpan={7} style={{ padding: "10px 14px" }}>
                    <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                      letterSpacing: "1px", textTransform: "uppercase", marginBottom: 6 }}>
                      AI Analysis
                    </div>
                    <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 11,
                      fontFamily: "monospace", lineHeight: 1.6,
                      whiteSpace: "pre-wrap", maxWidth: 900 }}>
                      {aiMap[r.id] || r.ai_analysis}
                    </div>
                  </td>
                </tr>
              ),
            ].filter(Boolean))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
