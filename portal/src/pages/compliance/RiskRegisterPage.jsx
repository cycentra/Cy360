/**
 * RiskRegisterPage.jsx
 * ====================
 * Combined Risk Management page with three tabs:
 *   Heatmap | Register | Appetite
 *
 * Mirrors the original CyComp RiskRegister.jsx single-page approach.
 * Accepts optional `initialView` prop ("heatmap"|"list"|"appetite").
 */

import { useState, useEffect, useCallback } from "react";
import { API_BASE } from "../../core/constants.js";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff",
  purple: "#b06eff", yellow: "#ffd166", teal: "#4ecdc4",
};

// Score → severity mapping (Likelihood × Impact, range 1-25)
// Critical ≥20 | High 12-19 | Medium 6-11 | Low 1-5
const SCORE_SEV = s => s >= 20 ? "critical" : s >= 12 ? "high" : s >= 6 ? "medium" : "low";
const SEV_COLOR = { critical: C.red, high: C.orange, medium: C.yellow, low: C.teal };
const SEV_BG    = { critical: `${C.red}18`, high: `${C.orange}18`, medium: `${C.yellow}18`, low: `${C.teal}18` };

// Heatmap cell color (L × I score)
const CELL_COLOR = (l, i) => {
  const s = l * i;
  if (s >= 20) return C.red;
  if (s >= 12) return C.orange;
  if (s >= 6)  return C.yellow;
  return C.teal;
};

const CATEGORIES = ["IT", "Operational", "Financial", "Legal", "Reputational"];
const TREATMENTS = ["mitigate", "avoid", "transfer", "accept"];
const STATUSES   = ["open", "mitigated", "accepted", "closed"];
const APPETITES  = ["low", "medium", "high"];
const FRAMEWORKS = ["NIS2", "DORA", "ISO27001", "SOC2", "AVG", "NIST"];

const EMPTY_FORM = {
  title: "", description: "", category: "IT", owner: "",
  likelihood: 3, impact: 3, appetite: "medium",
  status: "open", treatment: "mitigate", frameworks: [],
};

// ── Subcomponents ─────────────────────────────────────────────────────────────

function SevBadge({ score }) {
  const sev = SCORE_SEV(score);
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <div style={{ width: 34, height: 34, borderRadius: "50%", display: "flex",
        alignItems: "center", justifyContent: "center", fontWeight: 800, fontSize: 12,
        background: SEV_BG[sev], color: SEV_COLOR[sev], border: `2px solid ${SEV_COLOR[sev]}40` }}>
        {score}
      </div>
      <span style={{ fontSize: 9, color: SEV_COLOR[sev], fontWeight: 700,
        fontFamily: "monospace", textTransform: "uppercase" }}>{sev}</span>
    </div>
  );
}

function ScoreLegend() {
  return (
    <div style={{ display: "flex", gap: 16, flexWrap: "wrap", fontSize: 10,
      fontFamily: "monospace", color: C.muted, alignItems: "center" }}>
      <span style={{ color: "rgba(255,255,255,0.3)", letterSpacing: "1px" }}>SCORE = Likelihood × Impact (1–5 each)</span>
      {[
        { label: "Critical", range: "20–25", color: C.red },
        { label: "High",     range: "12–19", color: C.orange },
        { label: "Medium",   range: "6–11",  color: C.yellow },
        { label: "Low",      range: "1–5",   color: C.teal },
      ].map(({ label, range, color }) => (
        <span key={label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <span style={{ width: 8, height: 8, borderRadius: 2, background: color, display: "inline-block" }} />
          <span style={{ color }}>{label}</span>
          <span style={{ color: "rgba(255,255,255,0.3)" }}>({range})</span>
        </span>
      ))}
    </div>
  );
}

function Heatmap({ grid, onCellClick }) {
  const [hovered, setHovered] = useState(null);
  return (
    <div>
      <div style={{ display: "flex", gap: 4, marginBottom: 4, paddingLeft: 28 }}>
        {[1,2,3,4,5].map(l => (
          <div key={l} style={{ width: 60, textAlign: "center", fontSize: 10, color: C.muted,
            fontFamily: "monospace" }}>L{l}</div>
        ))}
      </div>
      {[4,3,2,1,0].map(im => (
        <div key={im} style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 4 }}>
          <div style={{ width: 24, fontSize: 10, color: C.muted, textAlign: "right",
            fontFamily: "monospace" }}>I{im+1}</div>
          {[0,1,2,3,4].map(li => {
            const cell = (grid && grid[im] && grid[im][li]) || [];
            const color = CELL_COLOR(li+1, im+1);
            const isHov = hovered === `${im}-${li}`;
            return (
              <div key={li}
                onClick={() => cell.length && onCellClick && onCellClick(cell)}
                onMouseEnter={() => setHovered(`${im}-${li}`)}
                onMouseLeave={() => setHovered(null)}
                style={{ width: 60, height: 44, borderRadius: 6,
                  cursor: cell.length ? "pointer" : "default",
                  background: color, border: isHov ? "2px solid rgba(255,255,255,0.4)" : "2px solid transparent",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  transition: "all 0.15s", transform: isHov ? "scale(1.06)" : "scale(1)" }}>
                {cell.length > 0 && (
                  <div style={{ width: 20, height: 20, borderRadius: "50%",
                    background: "rgba(0,0,0,0.5)", color: "#fff",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 10, fontWeight: 700 }}>{cell.length}</div>
                )}
              </div>
            );
          })}
        </div>
      ))}
      <div style={{ display: "flex", gap: 12, marginTop: 12, paddingLeft: 28, flexWrap: "wrap" }}>
        {[
          { label: "Critical ≥20", color: C.red },
          { label: "High 12–19",   color: C.orange },
          { label: "Medium 6–11",  color: C.yellow },
          { label: "Low 1–5",      color: C.teal },
        ].map(b => (
          <div key={b.label} style={{ display: "flex", alignItems: "center", gap: 4,
            fontSize: 10, color: C.muted, fontFamily: "monospace" }}>
            <div style={{ width: 10, height: 10, borderRadius: 2, background: b.color }} />
            {b.label}
          </div>
        ))}
      </div>
    </div>
  );
}

function RiskForm({ initial, onSave, onCancel }) {
  const [form, setForm] = useState(initial ? { ...EMPTY_FORM, ...initial } : EMPTY_FORM);
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));
  const score = (form.likelihood || 3) * (form.impact || 3);
  const sev = SCORE_SEV(score);

  const inp = {
    background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
    borderRadius: 4, color: C.text, fontFamily: "monospace", fontSize: 12,
    padding: "7px 10px", width: "100%", outline: "none", boxSizing: "border-box",
  };

  const toggleFw = fw => setForm(f => ({
    ...f, frameworks: f.frameworks.includes(fw)
      ? f.frameworks.filter(x => x !== fw) : [...f.frameworks, fw],
  }));

  return (
    <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8,
      padding: 20, marginBottom: 20 }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <div style={{ gridColumn: "1/-1" }}>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
            letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 5 }}>Title *</div>
          <input style={inp} value={form.title} onChange={e => set("title", e.target.value)} />
        </div>
        <div style={{ gridColumn: "1/-1" }}>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
            letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 5 }}>Description</div>
          <textarea style={{ ...inp, height: 72, resize: "vertical" }}
            value={form.description} onChange={e => set("description", e.target.value)} />
        </div>
        {[
          { label: "Category",  key: "category",  opts: CATEGORIES },
          { label: "Owner",     key: "owner",      opts: null },
          { label: "Treatment", key: "treatment",  opts: TREATMENTS },
          { label: "Status",    key: "status",     opts: STATUSES },
          { label: "Appetite",  key: "appetite",   opts: APPETITES },
        ].map(({ label, key, opts }) => (
          <div key={key}>
            <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
              letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 5 }}>{label}</div>
            {opts
              ? <select style={{ ...inp, cursor: "pointer" }} value={form[key]}
                  onChange={e => set(key, e.target.value)}>
                  {opts.map(o => <option key={o} value={o}>{o.charAt(0).toUpperCase() + o.slice(1)}</option>)}
                </select>
              : <input style={inp} value={form[key]} onChange={e => set(key, e.target.value)} />
            }
          </div>
        ))}

        {[
          { key: "likelihood", label: "Likelihood", color: C.accent },
          { key: "impact",     label: "Impact",     color: C.orange },
        ].map(({ key, label, color }) => (
          <div key={key}>
            <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
              letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 5 }}>
              {label}: <span style={{ color }}>{form[key]}</span>
            </div>
            <input type="range" min={1} max={5} value={form[key]}
              onChange={e => set(key, +e.target.value)}
              style={{ width: "100%", accentColor: color }} />
            <div style={{ display: "flex", justifyContent: "space-between",
              fontSize: 9, color: "rgba(255,255,255,0.25)", fontFamily: "monospace" }}>
              <span>1 Very Low</span><span>5 Very High</span>
            </div>
          </div>
        ))}

        {/* Live score preview */}
        <div style={{ gridColumn: "1/-1", padding: "10px 14px", borderRadius: 6,
          background: SEV_BG[sev], border: `1px solid ${SEV_COLOR[sev]}30`,
          display: "flex", alignItems: "center", gap: 12 }}>
          <SevBadge score={score} />
          <div style={{ fontSize: 11, color: C.muted, fontFamily: "monospace" }}>
            Inherent risk score (L{form.likelihood} × I{form.impact} = {score}/25) — updates in real time
          </div>
        </div>

        <div style={{ gridColumn: "1/-1" }}>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
            letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 6 }}>Frameworks</div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {FRAMEWORKS.map(fw => (
              <button key={fw} type="button" onClick={() => toggleFw(fw)}
                style={{ fontSize: 11, padding: "3px 10px", borderRadius: 4, cursor: "pointer",
                  background: form.frameworks.includes(fw) ? `${C.blue}20` : "transparent",
                  border: `1px solid ${form.frameworks.includes(fw) ? `${C.blue}60` : C.border}`,
                  color: form.frameworks.includes(fw) ? C.blue : C.muted,
                  fontFamily: "monospace" }}>
                {fw}
              </button>
            ))}
          </div>
        </div>

        <div style={{ gridColumn: "1/-1", display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 4 }}>
          <button onClick={onCancel}
            style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
              color: C.muted, padding: "8px 18px", borderRadius: 4,
              fontFamily: "monospace", fontSize: 11, cursor: "pointer" }}>Cancel</button>
          <button onClick={() => onSave(form)} disabled={!form.title.trim()}
            style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
              color: C.accent, padding: "8px 18px", borderRadius: 4,
              fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer" }}>
            Save Risk
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

export function RiskRegisterPage({ initialView = "heatmap" }) {
  const [view, setView]           = useState(initialView);
  const [risks, setRisks]         = useState([]);
  const [heatmap, setHeatmap]     = useState(null);
  const [appetite, setAppetite]   = useState(null);
  const [loading, setLoading]     = useState(true);
  const [showForm, setShowForm]   = useState(false);
  const [editing, setEditing]     = useState(null);
  const [expanded, setExpanded]   = useState(null);
  const [cellRisks, setCellRisks] = useState(null);
  const [aiMap, setAiMap]         = useState({});
  const [aiLoading, setAiLoading] = useState({});
  const [msg, setMsg]             = useState("");
  const [populating, setPopulating] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      fetch(`${API_BASE}/api/comp/risks`, { credentials: "include" }).then(r => r.ok ? r.json() : {}),
      fetch(`${API_BASE}/api/comp/risks/heatmap`, { credentials: "include" }).then(r => r.ok ? r.json() : null),
      fetch(`${API_BASE}/api/comp/appetite`, { credentials: "include" }).then(r => r.ok ? r.json() : null),
    ]).then(([rd, hd, ad]) => {
      setRisks(rd.risks || []);
      setHeatmap(hd);
      setAppetite(ad);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleSave = (form) => {
    const method = editing ? "PUT" : "POST";
    const url    = editing ? `${API_BASE}/api/comp/risks/${editing.id}` : `${API_BASE}/api/comp/risks`;
    fetch(url, { method, credentials: "include",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(form) })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(() => { setShowForm(false); setEditing(null); setMsg("Saved"); load(); })
      .catch(e => setMsg(`Save failed: ${e}`));
  };

  const handleDelete = (id) => {
    if (!confirm("Delete this risk?")) return;
    fetch(`${API_BASE}/api/comp/risks/${id}`, { method: "DELETE", credentials: "include" })
      .then(r => r.ok ? load() : setMsg("Delete failed"));
  };

  const handleAnalyze = (id) => {
    setAiLoading(m => ({ ...m, [id]: true }));
    fetch(`${API_BASE}/api/comp/risks/${id}/analyze`, { method: "POST", credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setAiMap(m => ({ ...m, [id]: d.analysis })); setAiLoading(m => ({ ...m, [id]: false })); })
      .catch(() => setAiLoading(m => ({ ...m, [id]: false })));
  };

  const tabs = [
    { id: "heatmap",  label: "Risk Heatmap" },
    { id: "list",     label: "Risk Register" },
    { id: "appetite", label: "Risk Appetite" },
  ];

  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px",
            fontFamily: "monospace", textTransform: "uppercase", marginBottom: 4 }}>SECURITY COMPLIANCE</div>
          <h1 style={{ color: C.text, fontSize: 20, fontWeight: 700, margin: 0 }}>Risk Management</h1>
          <div style={{ color: C.muted, fontSize: 11, marginTop: 4, fontFamily: "monospace" }}>
            {risks.length} risks tracked
            {heatmap?.summary && ` · ${heatmap.summary.critical || 0} critical · ${heatmap.summary.high || 0} high`}
          </div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button onClick={() => {
            setPopulating(true); setMsg("");
            fetch(`${API_BASE}/api/comp/risks/auto-populate`, { method: "POST", credentials: "include" })
              .then(r => r.ok ? r.json() : Promise.reject(r.status))
              .then(d => { setMsg(`Auto-populated: ${d.result?.created || 0} risks added`); load(); })
              .catch(e => setMsg(`Failed: ${e}`))
              .finally(() => setPopulating(false));
          }} disabled={populating}
            style={{ background: `${C.blue}10`, border: `1px solid ${C.blue}40`,
              color: C.blue, padding: "8px 16px", borderRadius: 4, fontFamily: "monospace",
              fontSize: 11, fontWeight: 700, cursor: "pointer", opacity: populating ? 0.6 : 1 }}>
            {populating ? "Populating…" : "Auto-Populate from Findings"}
          </button>
          <button onClick={() => { setEditing(null); setShowForm(s => !s); }}
            style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
              color: C.accent, padding: "8px 18px", borderRadius: 4, fontFamily: "monospace",
              fontSize: 11, fontWeight: 700, cursor: "pointer" }}>
            + Add Risk
          </button>
        </div>
      </div>

      {/* Score legend */}
      <div style={{ marginBottom: 16 }}><ScoreLegend /></div>

      {/* Inline form */}
      {(showForm || editing) && (
        <RiskForm initial={editing} onSave={handleSave}
          onCancel={() => { setShowForm(false); setEditing(null); }} />
      )}

      {/* Tab switcher */}
      <div style={{ display: "flex", gap: 4, marginBottom: 20 }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setView(t.id)}
            style={{ padding: "7px 16px", borderRadius: 6, cursor: "pointer",
              fontFamily: "monospace", fontSize: 11, fontWeight: 600,
              background: view === t.id ? `${C.blue}20` : "transparent",
              border: `1px solid ${view === t.id ? `${C.blue}60` : C.border}`,
              color: view === t.id ? C.blue : C.muted }}>
            {t.label}
          </button>
        ))}
      </div>

      {loading && <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12, padding: 24 }}>Loading...</div>}

      {/* ── HEATMAP ── */}
      {!loading && view === "heatmap" && (
        <div>
          {/* Summary cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 20 }}>
            {[
              { label: "Critical", key: "critical", color: C.red },
              { label: "High",     key: "high",     color: C.orange },
              { label: "Medium",   key: "medium",   color: C.yellow },
              { label: "Low",      key: "low",      color: C.teal },
            ].map(({ label, key, color }) => (
              <div key={key} style={{ background: C.surface, border: `1px solid ${C.border}`,
                borderRadius: 8, padding: "14px 16px", textAlign: "center" }}>
                <div style={{ fontSize: 28, fontWeight: 800, color }}>{heatmap?.summary?.[key] || 0}</div>
                <div style={{ fontSize: 11, color: C.muted, marginTop: 2, fontFamily: "monospace" }}>{label}</div>
              </div>
            ))}
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 20 }}>
              <div style={{ fontFamily: "monospace", fontSize: 9, letterSpacing: "1.5px",
                color: C.muted, textTransform: "uppercase", marginBottom: 16 }}>RISK HEATMAP</div>
              <Heatmap grid={heatmap?.grid || []} onCellClick={setCellRisks} />
              <div style={{ marginTop: 10, fontSize: 10, color: "rgba(255,255,255,0.25)",
                fontFamily: "monospace" }}>Click a cell to see risks at that position</div>
            </div>

            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 20 }}>
              <div style={{ fontFamily: "monospace", fontSize: 9, letterSpacing: "1.5px",
                color: C.muted, textTransform: "uppercase", marginBottom: 16 }}>BY CATEGORY</div>
              {Object.entries(heatmap?.summary?.by_category || {}).map(([cat, count]) => (
                <div key={cat} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                  <div style={{ fontSize: 11, color: C.text, width: 110, fontFamily: "monospace" }}>{cat}</div>
                  <div style={{ flex: 1, height: 6, background: "rgba(255,255,255,0.06)", borderRadius: 3, overflow: "hidden" }}>
                    <div style={{ height: "100%", borderRadius: 3, background: C.blue,
                      width: `${((count / (heatmap?.summary?.total || 1)) * 100)}%` }} />
                  </div>
                  <div style={{ fontSize: 11, color: C.muted, width: 20, textAlign: "right",
                    fontFamily: "monospace" }}>{count}</div>
                </div>
              ))}
              {!Object.keys(heatmap?.summary?.by_category || {}).length && (
                <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace",
                  lineHeight: 1.6 }}>
                  No risks yet.
                  <br />To populate: go to <strong style={{ color: C.blue }}>Findings</strong> →
                  generate findings from alerts, then click
                  <strong style={{ color: C.blue }}> "Auto-Populate from Findings"</strong> above.
                </div>
              )}
            </div>
          </div>

          {/* Cell drill-down */}
          {cellRisks && (
            <div style={{ background: C.surface, border: `1px solid ${C.border}`,
              borderRadius: 8, padding: 16, marginTop: 16 }}>
              <div style={{ display: "flex", justifyContent: "space-between",
                alignItems: "center", marginBottom: 12 }}>
                <div style={{ fontFamily: "monospace", fontSize: 9, letterSpacing: "1px",
                  color: C.muted, textTransform: "uppercase" }}>
                  Risks at this position ({cellRisks.length})
                </div>
                <button onClick={() => setCellRisks(null)}
                  style={{ background: "none", border: "none", cursor: "pointer",
                    color: C.muted, fontSize: 16 }}>×</button>
              </div>
              {cellRisks.map(cr => {
                const full = risks.find(r => r.id === cr.id);
                return full ? (
                  <div key={cr.id} style={{ padding: "8px 0",
                    borderBottom: `1px solid rgba(255,255,255,0.05)` }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: C.text }}>{full.title}</div>
                    <div style={{ fontSize: 10, color: C.muted, fontFamily: "monospace", marginTop: 2 }}>
                      {full.category} · Score {full.risk_score} · {full.treatment}
                    </div>
                  </div>
                ) : null;
              })}
            </div>
          )}
        </div>
      )}

      {/* ── REGISTER (LIST) ── */}
      {!loading && view === "list" && (
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Risk", "Category", "Score", "L × I", "Appetite", "Status", "Owner", "Actions"].map(h => (
                  <th key={h} style={{ padding: "10px 14px", textAlign: "left",
                    color: C.muted, fontSize: 9, fontFamily: "monospace",
                    letterSpacing: "1px", textTransform: "uppercase" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {risks.length === 0 ? (
                <tr><td colSpan={8} style={{ padding: 32, textAlign: "center",
                  color: C.muted, fontFamily: "monospace" }}>
                  No risks registered. Click "+ Add Risk" to begin.
                </td></tr>
              ) : risks.map((r, i) => [
                <tr key={r.id} style={{ borderBottom: `1px solid rgba(255,255,255,0.03)`,
                  background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)" }}>
                  <td style={{ padding: "10px 14px", maxWidth: 260 }}>
                    <div style={{ color: C.text, fontSize: 12, fontWeight: 600 }}>{r.title}</div>
                    {r.description && (
                      <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace",
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                        maxWidth: 240, marginTop: 2 }}>{r.description}</div>
                    )}
                  </td>
                  <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                    {r.category}
                  </td>
                  <td style={{ padding: "10px 14px" }}><SevBadge score={r.risk_score || 0} /></td>
                  <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                    L{r.likelihood} × I{r.impact}
                  </td>
                  <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10,
                    fontFamily: "monospace", textTransform: "uppercase" }}>{r.appetite}</td>
                  <td style={{ padding: "10px 14px" }}>
                    <span style={{ fontSize: 10, fontFamily: "monospace", textTransform: "uppercase",
                      color: r.status === "open" ? C.orange : r.status === "mitigated" ? C.accent : C.muted }}>
                      {r.status}
                    </span>
                  </td>
                  <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                    {r.owner || "—"}
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    <div style={{ display: "flex", gap: 5 }}>
                      <button onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                        style={{ background: `${C.purple}10`, border: `1px solid ${C.purple}30`,
                          color: C.purple, padding: "4px 8px", borderRadius: 3,
                          fontFamily: "monospace", fontSize: 9, cursor: "pointer", fontWeight: 700 }}>
                        {expanded === r.id ? "▲" : "▼"}
                      </button>
                      <button onClick={() => { setEditing(r); setShowForm(false); }}
                        style={{ background: `${C.blue}10`, border: `1px solid ${C.blue}30`,
                          color: C.blue, padding: "4px 8px", borderRadius: 3,
                          fontFamily: "monospace", fontSize: 9, cursor: "pointer", fontWeight: 700 }}>Edit</button>
                      <button onClick={() => handleAnalyze(r.id)} disabled={aiLoading[r.id]}
                        style={{ background: `${C.purple}10`, border: `1px solid ${C.purple}30`,
                          color: C.purple, padding: "4px 8px", borderRadius: 3,
                          fontFamily: "monospace", fontSize: 9, cursor: "pointer",
                          opacity: aiLoading[r.id] ? 0.6 : 1, fontWeight: 700 }}>
                        {aiLoading[r.id] ? "…" : "AI"}
                      </button>
                      <button onClick={() => handleDelete(r.id)}
                        style={{ background: `${C.red}10`, border: `1px solid ${C.red}30`,
                          color: C.red, padding: "4px 8px", borderRadius: 3,
                          fontFamily: "monospace", fontSize: 9, cursor: "pointer", fontWeight: 700 }}>Del</button>
                    </div>
                  </td>
                </tr>,
                expanded === r.id && (
                  <tr key={`${r.id}-exp`} style={{ background: "rgba(176,110,255,0.04)",
                    borderBottom: `1px solid rgba(255,255,255,0.03)` }}>
                    <td colSpan={8} style={{ padding: "12px 14px" }}>
                      {r.description && (
                        <p style={{ color: "rgba(255,255,255,0.6)", fontSize: 12, margin: "0 0 10px",
                          lineHeight: 1.6 }}>{r.description}</p>
                      )}
                      {r.frameworks?.length > 0 && (
                        <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
                          {r.frameworks.map(fw => (
                            <span key={fw} style={{ fontSize: 10, padding: "2px 8px", borderRadius: 3,
                              background: `${C.blue}10`, color: C.blue, border: `1px solid ${C.blue}30`,
                              fontFamily: "monospace" }}>{fw}</span>
                          ))}
                        </div>
                      )}
                      {(aiMap[r.id] || r.ai_analysis) && (
                        <div>
                          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                            letterSpacing: "1px", textTransform: "uppercase", marginBottom: 6 }}>AI Analysis</div>
                          <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 11,
                            fontFamily: "monospace", lineHeight: 1.7, whiteSpace: "pre-wrap" }}>
                            {aiMap[r.id] || r.ai_analysis}
                          </div>
                        </div>
                      )}
                    </td>
                  </tr>
                ),
              ].filter(Boolean))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── APPETITE ── */}
      {!loading && view === "appetite" && (
        <div>
          {/* Appetite thresholds reference */}
          <div style={{ background: C.surface, border: `1px solid ${C.border}`,
            borderRadius: 8, padding: 20, marginBottom: 16 }}>
            <div style={{ fontFamily: "monospace", fontSize: 9, letterSpacing: "1.5px",
              color: C.muted, textTransform: "uppercase", marginBottom: 14 }}>
              TOLERANCE THRESHOLDS — HOW RISK SCORES MAP TO APPETITE
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginBottom: 16 }}>
              {[
                { label: "Low Appetite",    threshold: "≤ 4",  color: C.teal,   sev: "Low scores only (1–5)",     desc: "Minimal tolerance. Only Low-severity risks accepted." },
                { label: "Medium Appetite", threshold: "≤ 11", color: C.yellow, sev: "Low + Medium (1–11)",        desc: "Standard tolerance. Medium and below accepted." },
                { label: "High Appetite",   threshold: "≤ 19", color: C.orange, sev: "Low + Medium + High (1–19)", desc: "Higher tolerance. High and below accepted." },
              ].map(a => (
                <div key={a.label} style={{ borderRadius: 6, padding: 14,
                  background: `${a.color}08`, borderLeft: `3px solid ${a.color}` }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: a.color, marginBottom: 4 }}>{a.label}</div>
                  <div style={{ fontSize: 11, color: C.muted, fontFamily: "monospace", marginBottom: 4 }}>
                    Max score: {a.threshold}
                  </div>
                  <div style={{ fontSize: 10, color: a.color, fontFamily: "monospace", marginBottom: 4 }}>
                    {a.sev}
                  </div>
                  <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)" }}>{a.desc}</div>
                </div>
              ))}
            </div>

            {/* Score ↔ Severity reference table */}
            <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 14 }}>
              <div style={{ fontFamily: "monospace", fontSize: 9, letterSpacing: "1px",
                color: "rgba(255,255,255,0.25)", textTransform: "uppercase", marginBottom: 10 }}>
                SCORE → SEVERITY REFERENCE (Score = Likelihood 1–5 × Impact 1–5)
              </div>
              <div style={{ display: "flex", gap: 10 }}>
                {[
                  { range: "1–5",   sev: "Low",      color: C.teal,   detail: "L1×I1 to L1×I5 / L5×I1" },
                  { range: "6–11",  sev: "Medium",   color: C.yellow, detail: "L2×I3 to L3×I3" },
                  { range: "12–19", sev: "High",     color: C.orange, detail: "L3×I4 to L4×I4" },
                  { range: "20–25", sev: "Critical", color: C.red,    detail: "L4×I5 to L5×I5" },
                ].map(({ range, sev, color, detail }) => (
                  <div key={sev} style={{ flex: 1, background: `${color}08`,
                    border: `1px solid ${color}30`, borderRadius: 6, padding: "10px 12px" }}>
                    <div style={{ fontSize: 18, fontWeight: 800, color, fontFamily: "monospace" }}>{range}</div>
                    <div style={{ fontSize: 11, fontWeight: 700, color, marginTop: 2 }}>{sev}</div>
                    <div style={{ fontSize: 9, color: "rgba(255,255,255,0.3)",
                      fontFamily: "monospace", marginTop: 4 }}>{detail}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Exceeding appetite */}
          <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 20 }}>
            <div style={{ display: "flex", justifyContent: "space-between",
              alignItems: "center", marginBottom: 14 }}>
              <div style={{ fontFamily: "monospace", fontSize: 9, letterSpacing: "1px",
                color: C.muted, textTransform: "uppercase" }}>RISKS EXCEEDING APPETITE</div>
              <div style={{ fontSize: 12, padding: "4px 12px", borderRadius: 16, fontFamily: "monospace",
                background: (appetite?.exceeding_appetite || 0) > 0 ? `${C.red}12` : `${C.accent}12`,
                color: (appetite?.exceeding_appetite || 0) > 0 ? C.red : C.accent, fontWeight: 700 }}>
                {appetite?.exceeding_appetite || 0} / {appetite?.total_risks || 0}
              </div>
            </div>

            {!appetite?.risks_exceeding?.length
              ? <div style={{ color: C.accent, fontSize: 12, fontFamily: "monospace" }}>
                  ✓ All risks are within configured appetite thresholds
                </div>
              : appetite.risks_exceeding.map(r => (
                <div key={r.id} style={{ padding: "10px 0",
                  borderBottom: `1px solid rgba(255,255,255,0.05)`,
                  display: "flex", alignItems: "center", gap: 12 }}>
                  <SevBadge score={r.risk_score} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: C.text }}>{r.title}</div>
                    <div style={{ fontSize: 10, color: C.muted, fontFamily: "monospace", marginTop: 2 }}>
                      Appetite: <span style={{ color: C.yellow }}>{r.appetite}</span>
                      {appetite.appetite_thresholds?.[r.appetite] !== undefined
                        ? ` (threshold ≤ ${appetite.appetite_thresholds[r.appetite]})`
                        : ""}
                      {" "}· Score: <span style={{ color: SCORE_SEV(r.risk_score) === "critical" ? C.red
                        : SCORE_SEV(r.risk_score) === "high" ? C.orange : C.yellow }}>{r.risk_score}</span>
                    </div>
                  </div>
                  <div style={{ fontSize: 11, padding: "3px 10px", borderRadius: 4,
                    background: `${C.red}10`, color: C.red, border: `1px solid ${C.red}30`,
                    fontFamily: "monospace" }}>
                    Exceeds by {r.risk_score - (appetite.appetite_thresholds?.[r.appetite] || 0)}
                  </div>
                </div>
              ))
            }
          </div>
        </div>
      )}

      {msg && (
        <div style={{ marginTop: 12, padding: "8px 14px", borderRadius: 6, fontSize: 11,
          fontFamily: "monospace",
          background: msg.includes("fail") ? `${C.red}08` : `${C.accent}08`,
          border: `1px solid ${msg.includes("fail") ? `${C.red}30` : `${C.accent}30`}`,
          color: msg.includes("fail") ? C.red : C.accent }}>
          {msg}
        </div>
      )}
    </div>
  );
}

// Aliases so existing comp-heatmap and comp-appetite routes still resolve
export function RiskHeatmapPage()  { return <RiskRegisterPage initialView="heatmap" />; }
export function RiskAppetitePage() { return <RiskRegisterPage initialView="appetite" />; }
