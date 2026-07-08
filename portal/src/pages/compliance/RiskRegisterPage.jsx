/**
 * RiskRegisterPage.jsx
 * ====================
 * Combined Risk Management page with three tabs:
 *   Heatmap | Register | Appetite
 *
 * Mirrors the original CyComp RiskRegister.jsx single-page approach.
 * Accepts optional `initialView` prop ("heatmap"|"list"|"appetite").
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { API_BASE } from "../../core/constants.js";
import { CY_FW_FILTER_KEY } from "./ComplianceDashboardPage.jsx";

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
const FRAMEWORKS = ["NIS2", "DORA", "ISO27001", "SOC2", "NIST_CSF", "PCI_DSS", "GDPR", "EU_AI_ACT"];

function _getEnabledFws() {
  try {
    const s = JSON.parse(localStorage.getItem(CY_FW_FILTER_KEY));
    if (Array.isArray(s) && s.length) return s;
  } catch { /* ignore */ }
  return null;
}

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

// ── Exposure Tab Component ────────────────────────────────────────────────────

const EXP_SEV_COLORS = { critical: C.red, high: C.orange, medium: C.blue, low: C.muted };
const EXP_SEV_ORDER  = { critical: 0, high: 1, medium: 2, low: 3 };

const EXP_TYPE_LABELS = {
  vulnerability: { label: "Vulnerability", color: C.blue },
  supply_chain:  { label: "Supply Chain",  color: C.orange },
  configuration: { label: "Config",        color: C.purple },
  manual:        { label: "Manual",        color: C.muted },
};

const EXP_TABS = [
  { id: "all",           label: "All" },
  { id: "vulnerability", label: "Vulnerabilities" },
  { id: "supply_chain",  label: "Supply Chain" },
  { id: "other",         label: "Other" },
];

function ExposureTab() {
  const [items, setItems]       = useState([]);
  const [loading, setLoading]   = useState(true);
  const [activeType, setType]   = useState("all");
  const [filter, setFilter]     = useState({ sev: "all", status: "all", search: "" });
  const [showCreate, setCreate] = useState(false);
  const [createForm, setCreateForm] = useState({
    asset: "", asset_type: "host", exposure_type: "vulnerability",
    severity: "medium", title: "", description: "", cvss_score: "",
  });
  const [saving, setSaving]   = useState(false);
  const [msg, setMsg]         = useState(null);
  const abortRef              = useRef(null);

  const load = useCallback(async () => {
    if (abortRef.current) abortRef.current.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: 300 });
      if (activeType !== "all" && activeType !== "other") params.set("exposure_type", activeType);
      const r = await fetch(`${API_BASE}/api/comp/exposure?${params}`, {
        credentials: "include", signal: ctrl.signal,
      });
      const d = await r.json();
      const sorted = (d.items || []).sort(
        (a, b) => (EXP_SEV_ORDER[a.severity] ?? 9) - (EXP_SEV_ORDER[b.severity] ?? 9)
      );
      setItems(sorted);
    } catch (e) {
      if (e.name !== "AbortError") setMsg({ type: "error", text: "Failed to load exposure items." });
    } finally {
      setLoading(false);
    }
  }, [activeType]);

  useEffect(() => { load(); }, [load]);

  const updateStatus = async (id, status) => {
    try {
      const r = await fetch(`${API_BASE}/api/comp/exposure/${id}`, {
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

  const submitCreate = async () => {
    if (!createForm.asset || !createForm.title) {
      setMsg({ type: "error", text: "Asset and title are required." }); return;
    }
    setSaving(true); setMsg(null);
    try {
      const body = { ...createForm };
      if (createForm.cvss_score) body.cvss_score = parseFloat(createForm.cvss_score);
      else delete body.cvss_score;
      const r = await fetch(`${API_BASE}/api/comp/exposure`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Create failed");
      setItems(prev => [d.exposure, ...prev]);
      setCreate(false);
      setCreateForm({ asset: "", asset_type: "host", exposure_type: "vulnerability",
        severity: "medium", title: "", description: "", cvss_score: "" });
    } catch (e) {
      setMsg({ type: "error", text: e.message });
    } finally {
      setSaving(false);
    }
  };

  const total    = items.length;
  const critical = items.filter(i => i.severity === "critical").length;
  const open     = items.filter(i => i.status === "open").length;
  const resolved = items.filter(i => i.status === "resolved" || i.status === "accepted").length;

  const visible = items.filter(i => {
    if (activeType === "other"
      && (i.exposure_type === "vulnerability" || i.exposure_type === "supply_chain")) return false;
    if (filter.sev !== "all" && i.severity !== filter.sev) return false;
    if (filter.status !== "all" && i.status !== filter.status) return false;
    if (filter.search) {
      const q = filter.search.toLowerCase();
      return (i.asset || "").toLowerCase().includes(q)
        || (i.title || "").toLowerCase().includes(q);
    }
    return true;
  });

  const inp = {
    width: "100%", background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
    borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12,
    boxSizing: "border-box", outline: "none",
  };

  return (
    <div>
      {/* Stats row */}
      <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        {[
          { label: "Total",    value: total,    color: C.text },
          { label: "Critical", value: critical, color: C.red },
          { label: "Open",     value: open,     color: C.orange },
          { label: "Resolved", value: resolved, color: C.teal },
        ].map(({ label, value, color }) => (
          <div key={label} style={{ background: C.surface, border: `1px solid ${C.border}`,
            borderRadius: 8, padding: "12px 18px", textAlign: "center", minWidth: 90 }}>
            <div style={{ fontSize: 24, fontWeight: 800, color, fontFamily: "monospace" }}>{value}</div>
            <div style={{ fontSize: 10, color: C.muted, marginTop: 2, fontFamily: "monospace" }}>{label}</div>
          </div>
        ))}
        <div style={{ marginLeft: "auto", alignSelf: "center" }}>
          <button onClick={() => setCreate(c => !c)}
            style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
              color: C.accent, padding: "8px 16px", borderRadius: 4,
              fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer" }}>
            + Add Item
          </button>
        </div>
      </div>

      {/* Inline create form */}
      {showCreate && (
        <div style={{ background: C.surface, border: `1px solid ${C.border}`,
          borderRadius: 8, padding: 18, marginBottom: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 14 }}>New Exposure Item</div>
          {msg?.type === "error" && (
            <div style={{ color: C.red, fontSize: 11, marginBottom: 10 }}>{msg.text}</div>
          )}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            {[
              { key: "asset",       label: "Asset / Library",       placeholder: "e.g. acme.example.com" },
              { key: "title",       label: "Title",                  placeholder: "Short description" },
            ].map(f => (
              <div key={f.key}>
                <div style={{ fontSize: 9, color: C.muted, fontFamily: "monospace",
                  textTransform: "uppercase", letterSpacing: "1px", marginBottom: 4 }}>{f.label}</div>
                <input style={inp} placeholder={f.placeholder} value={createForm[f.key]}
                  onChange={e => setCreateForm(p => ({ ...p, [f.key]: e.target.value }))} />
              </div>
            ))}
            <div style={{ gridColumn: "1/-1" }}>
              <div style={{ fontSize: 9, color: C.muted, fontFamily: "monospace",
                textTransform: "uppercase", letterSpacing: "1px", marginBottom: 4 }}>Description</div>
              <textarea style={{ ...inp, height: 60, resize: "vertical" }}
                value={createForm.description}
                onChange={e => setCreateForm(p => ({ ...p, description: e.target.value }))} />
            </div>
            {[
              { key: "exposure_type", label: "Type",      opts: ["vulnerability","supply_chain","configuration","manual"] },
              { key: "asset_type",    label: "Asset Type", opts: ["host","web_asset","api","service","dependency"] },
              { key: "severity",      label: "Severity",   opts: ["critical","high","medium","low"] },
            ].map(f => (
              <div key={f.key}>
                <div style={{ fontSize: 9, color: C.muted, fontFamily: "monospace",
                  textTransform: "uppercase", letterSpacing: "1px", marginBottom: 4 }}>{f.label}</div>
                <select style={{ ...inp, cursor: "pointer" }} value={createForm[f.key]}
                  onChange={e => setCreateForm(p => ({ ...p, [f.key]: e.target.value }))}>
                  {f.opts.map(o => <option key={o} value={o}>{o.replace(/_/g," ")}</option>)}
                </select>
              </div>
            ))}
            <div>
              <div style={{ fontSize: 9, color: C.muted, fontFamily: "monospace",
                textTransform: "uppercase", letterSpacing: "1px", marginBottom: 4 }}>CVSS Score (optional)</div>
              <input style={inp} type="number" placeholder="0.0 – 10.0"
                value={createForm.cvss_score}
                onChange={e => setCreateForm(p => ({ ...p, cvss_score: e.target.value }))} />
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 14 }}>
            <button onClick={() => setCreate(false)}
              style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
                color: C.muted, padding: "7px 16px", borderRadius: 4,
                fontFamily: "monospace", fontSize: 11, cursor: "pointer" }}>Cancel</button>
            <button onClick={submitCreate} disabled={saving}
              style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
                color: C.accent, padding: "7px 16px", borderRadius: 4,
                fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer",
                opacity: saving ? 0.6 : 1 }}>
              {saving ? "Saving…" : "Save"}
            </button>
          </div>
        </div>
      )}

      {/* Message banner */}
      {msg && !showCreate && (
        <div style={{ marginBottom: 12, padding: "8px 14px", borderRadius: 6, fontSize: 11,
          fontFamily: "monospace",
          background: msg.type === "error" ? `${C.red}08` : `${C.teal}08`,
          border: `1px solid ${msg.type === "error" ? `${C.red}30` : `${C.teal}30`}`,
          color: msg.type === "error" ? C.red : C.teal }}>
          {msg.text}
          <button onClick={() => setMsg(null)}
            style={{ float: "right", background: "none", border: "none", cursor: "pointer",
              color: C.muted, fontSize: 13 }}>×</button>
        </div>
      )}

      {/* Type tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 14,
        borderBottom: `1px solid ${C.border}`, paddingBottom: 0 }}>
        {EXP_TABS.map(t => (
          <button key={t.id} onClick={() => setType(t.id)}
            style={{ background: "none", border: "none", padding: "7px 14px", cursor: "pointer",
              fontFamily: "monospace", fontSize: 11, fontWeight: 500,
              color: activeType === t.id ? C.accent : C.muted,
              borderBottom: activeType === t.id ? `2px solid ${C.accent}` : "2px solid transparent" }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
        <input placeholder="Search asset, title…"
          value={filter.search} onChange={e => setFilter(f => ({ ...f, search: e.target.value }))}
          style={{ flex: 1, minWidth: 180, background: "rgba(255,255,255,0.04)",
            border: `1px solid ${C.border}`, borderRadius: 6, padding: "6px 10px",
            color: C.text, fontSize: 12, outline: "none" }} />
        {[
          { key: "sev",    opts: ["all","critical","high","medium","low"],                             label: "Severity" },
          { key: "status", opts: ["all","open","in_progress","resolved","accepted","false_positive"],  label: "Status" },
        ].map(({ key, opts, label }) => (
          <select key={key} value={filter[key]}
            onChange={e => setFilter(f => ({ ...f, [key]: e.target.value }))}
            style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
              borderRadius: 6, padding: "6px 10px", color: C.text, fontSize: 12 }}>
            {opts.map(o => <option key={o} value={o}>{o === "all" ? `All ${label}` : o.replace(/_/g," ")}</option>)}
          </select>
        ))}
      </div>

      {/* Table */}
      {loading ? (
        <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12, padding: 24 }}>Loading…</div>
      ) : visible.length === 0 ? (
        <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12, padding: 24 }}>
          No exposure items match the current filter.
        </div>
      ) : (
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}`, color: C.muted,
                  fontSize: 9, textTransform: "uppercase", letterSpacing: 0.8 }}>
                  {["Asset","Type","Title","Sev","CVSS","Source","Status","Age",""].map(h => (
                    <th key={h} style={{ padding: "8px 12px", textAlign: "left", whiteSpace: "nowrap",
                      fontFamily: "monospace" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visible.map(item => {
                  const sevC = EXP_SEV_COLORS[item.severity] || C.muted;
                  const typM = EXP_TYPE_LABELS[item.exposure_type] || { label: item.exposure_type || "Other", color: C.muted };
                  const ageDays = item.created_at
                    ? Math.floor((Date.now() - new Date(item.created_at)) / 86400000) : null;
                  return (
                    <tr key={item.id} style={{ borderBottom: `1px solid rgba(255,255,255,0.04)` }}>
                      <td style={{ padding: "9px 12px", color: C.accent, fontFamily: "monospace", fontSize: 11 }}>
                        {item.asset || "—"}
                      </td>
                      <td style={{ padding: "9px 12px" }}>
                        <span style={{ color: typM.color, fontSize: 11, fontFamily: "monospace" }}>{typM.label}</span>
                      </td>
                      <td style={{ padding: "9px 12px", color: C.text, maxWidth: 220 }}>
                        <div style={{ fontWeight: 500 }}>{item.title}</div>
                      </td>
                      <td style={{ padding: "9px 12px" }}>
                        <span style={{ background: `${sevC}22`, color: sevC, border: `1px solid ${sevC}44`,
                          borderRadius: 4, padding: "2px 7px", fontSize: 10, fontWeight: 600,
                          textTransform: "uppercase", letterSpacing: 0.8 }}>{item.severity || "—"}</span>
                      </td>
                      <td style={{ padding: "9px 12px", color: C.muted, fontFamily: "monospace", fontSize: 11 }}>
                        {item.cvss_score ?? "—"}
                      </td>
                      <td style={{ padding: "9px 12px", color: C.muted, fontSize: 11 }}>
                        {item.source || "manual"}
                      </td>
                      <td style={{ padding: "9px 12px" }}>
                        <select value={item.status}
                          onChange={e => updateStatus(item.id, e.target.value)}
                          style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
                            borderRadius: 4, padding: "3px 6px", color: C.text, fontSize: 11 }}>
                          {["open","in_progress","resolved","accepted","false_positive"].map(s => (
                            <option key={s} value={s}>{s.replace(/_/g," ")}</option>
                          ))}
                        </select>
                      </td>
                      <td style={{ padding: "9px 12px", color: ageDays > 30 ? C.orange : C.muted,
                        fontFamily: "monospace", fontSize: 11, whiteSpace: "nowrap" }}>
                        {ageDays !== null ? `${ageDays}d` : "—"}
                      </td>
                      <td style={{ padding: "9px 12px" }}>
                        {(item.status === "open" || item.status === "in_progress") && (
                          <button onClick={() => updateStatus(item.id, "resolved")}
                            style={{ background: `${C.teal}22`, color: C.teal, border: `1px solid ${C.teal}44`,
                              borderRadius: 4, padding: "3px 8px", fontSize: 10, cursor: "pointer" }}>
                            Resolve
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div style={{ padding: "8px 12px", color: C.muted, fontSize: 11, fontFamily: "monospace" }}>
            Showing {visible.length} of {total} items
          </div>
        </div>
      )}
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
  const [enabledFws, setEnabledFws] = useState(_getEnabledFws);

  // Stay in sync when the user changes the framework selector on the dashboard
  useEffect(() => {
    const onStorage = e => {
      if (e.key === CY_FW_FILTER_KEY) setEnabledFws(_getEnabledFws());
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  // Client-side filter: a risk is shown when at least one of its frameworks matches
  // the global selection. Comparison is case-insensitive (DB stores mixed case).
  const filteredRisks = enabledFws
    ? risks.filter(r =>
        !r.frameworks?.length ||
        r.frameworks.some(fw => enabledFws.includes(fw.toLowerCase()))
      )
    : risks;

  // Derive heatmap grid + summary from filteredRisks so the heatmap responds to
  // the global framework selector without a separate API call.
  const filteredGrid = (() => {
    const g = Array.from({ length: 5 }, () => Array.from({ length: 5 }, () => []));
    filteredRisks.forEach(r => {
      const li = (r.likelihood || 1) - 1;
      const im = (r.impact || 1) - 1;
      if (li >= 0 && li < 5 && im >= 0 && im < 5) g[im][li].push(r);
    });
    return g;
  })();

  const filteredHeatmapSummary = (() => {
    const by_category = {};
    filteredRisks.forEach(r => {
      const cat = r.category || "Unknown";
      by_category[cat] = (by_category[cat] || 0) + 1;
    });
    const score = r => r.risk_score ?? ((r.likelihood || 1) * (r.impact || 1));
    return {
      total:    filteredRisks.length,
      critical: filteredRisks.filter(r => score(r) >= 20).length,
      high:     filteredRisks.filter(r => score(r) >= 12 && score(r) < 20).length,
      medium:   filteredRisks.filter(r => score(r) >= 6  && score(r) < 12).length,
      low:      filteredRisks.filter(r => score(r) <  6).length,
      by_category,
    };
  })();

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
    { id: "exposure", label: "Exposure" },
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
          {/* Summary cards — derived from filteredRisks so they respond to global framework selector */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 20 }}>
            {[
              { label: "Critical", key: "critical", color: C.red },
              { label: "High",     key: "high",     color: C.orange },
              { label: "Medium",   key: "medium",   color: C.yellow },
              { label: "Low",      key: "low",      color: C.teal },
            ].map(({ label, key, color }) => (
              <div key={key} style={{ background: C.surface, border: `1px solid ${C.border}`,
                borderRadius: 8, padding: "14px 16px", textAlign: "center" }}>
                <div style={{ fontSize: 28, fontWeight: 800, color }}>{filteredHeatmapSummary[key] || 0}</div>
                <div style={{ fontSize: 11, color: C.muted, marginTop: 2, fontFamily: "monospace" }}>{label}</div>
              </div>
            ))}
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 20 }}>
              <div style={{ fontFamily: "monospace", fontSize: 9, letterSpacing: "1.5px",
                color: C.muted, textTransform: "uppercase", marginBottom: 16 }}>RISK HEATMAP</div>
              <Heatmap grid={filteredGrid} onCellClick={setCellRisks} />
              <div style={{ marginTop: 10, fontSize: 10, color: "rgba(255,255,255,0.25)",
                fontFamily: "monospace" }}>Click a cell to see risks at that position</div>
            </div>

            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 20 }}>
              <div style={{ fontFamily: "monospace", fontSize: 9, letterSpacing: "1.5px",
                color: C.muted, textTransform: "uppercase", marginBottom: 16 }}>BY CATEGORY</div>
              {Object.entries(filteredHeatmapSummary.by_category || {}).map(([cat, count]) => (
                <div key={cat} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                  <div style={{ fontSize: 11, color: C.text, width: 110, fontFamily: "monospace" }}>{cat}</div>
                  <div style={{ flex: 1, height: 6, background: "rgba(255,255,255,0.06)", borderRadius: 3, overflow: "hidden" }}>
                    <div style={{ height: "100%", borderRadius: 3, background: C.blue,
                      width: `${((count / (filteredHeatmapSummary.total || 1)) * 100)}%` }} />
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
              {filteredRisks.length === 0 ? (
                <tr><td colSpan={8} style={{ padding: 32, textAlign: "center",
                  color: C.muted, fontFamily: "monospace" }}>
                  {risks.length === 0
                    ? "No risks registered. Click \"+ Add Risk\" to begin."
                    : "No risks match the selected frameworks."}
                </td></tr>
              ) : filteredRisks.map((r, i) => [
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

          {/* Severity breakdown + explanation */}
          <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 20 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <div style={{ fontFamily: "monospace", fontSize: 9, letterSpacing: "1px",
                color: C.muted, textTransform: "uppercase" }}>SEVERITY BREAKDOWN</div>
              <div style={{ fontSize: 9, color: "rgba(255,255,255,0.25)", fontFamily: "monospace" }}>
                open + mitigated risks only
              </div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 12 }}>
              {[
                { label: "Critical", key: "critical", color: C.red },
                { label: "High",     key: "high",     color: C.orange },
                { label: "Medium",   key: "medium",   color: C.yellow },
                { label: "Low",      key: "low",      color: C.teal },
              ].map(({ label, key, color }) => (
                <div key={key} style={{ textAlign: "center", padding: "10px 8px",
                  background: `${color}08`, border: `1px solid ${color}20`, borderRadius: 6 }}>
                  <div style={{ fontSize: 22, fontWeight: 800, color, fontFamily: "monospace" }}>
                    {appetite?.severity_summary?.[key] ?? 0}
                  </div>
                  <div style={{ fontSize: 9, color: C.muted, fontFamily: "monospace", marginTop: 2 }}>{label}</div>
                </div>
              ))}
            </div>
            <div style={{ fontSize: 9, color: "rgba(255,255,255,0.25)", fontFamily: "monospace",
              padding: "8px 10px", background: "rgba(255,255,255,0.02)", borderRadius: 4,
              borderLeft: `2px solid rgba(255,255,255,0.08)` }}>
              ℹ️ Why these counts differ from the Heatmap: the Heatmap includes risks with status
              "accepted" — this view excludes them (accepted risks are intentionally outside the
              normal mitigation cycle). Closed risks are excluded from both.
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

      {/* ── EXPOSURE ── */}
      {view === "exposure" && <ExposureTab />}

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
