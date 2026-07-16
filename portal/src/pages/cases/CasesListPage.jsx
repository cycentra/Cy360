/**
 * CasesListPage.jsx
 * Dashboard widgets + sortable/filterable case table with inline actions.
 */

import { useState, useEffect, useCallback, useRef } from "react";

// ── Palette ───────────────────────────────────────────────────────────────────
const C = {
  bg:      "#090b10",
  surface: "#0d1117",
  border:  "rgba(255,255,255,0.07)",
  text:    "rgba(255,255,255,0.82)",
  muted:   "rgba(255,255,255,0.38)",
  accent:  "#00e5a0",
  red:     "#ff3b3b",
  orange:  "#ff8c00",
  blue:    "#4d9eff",
  purple:  "#b06eff",
  yellow:  "#f5c518",
};

const SEV_CFG = {
  critical: { color: "#ff3b3b", bg: "rgba(255,59,59,0.12)",   label: "CRITICAL" },
  high:     { color: "#ff8c00", bg: "rgba(255,140,0,0.12)",   label: "HIGH"     },
  medium:   { color: "#4d9eff", bg: "rgba(77,158,255,0.12)",  label: "MEDIUM"   },
  low:      { color: "#888888", bg: "rgba(136,136,136,0.12)", label: "LOW"      },
};

const STATUS_CFG = {
  open:          { color: "#00e5a0", label: "OPEN"          },
  investigating: { color: "#f5c518", label: "INVESTIGATING" },
  in_review:     { color: "#4d9eff", label: "IN REVIEW"     },
  resolved:      { color: "#888888", label: "RESOLVED"      },
  closed:        { color: "#555555", label: "CLOSED"        },
  held:          { color: "#b06eff", label: "HELD"          },
};

const TYPE_CFG = {
  ransomware:       { color: "#ff3b3b", label: "RANSOMWARE"       },
  phishing:         { color: "#ff8c00", label: "PHISHING"         },
  brute_force:      { color: "#f5c518", label: "BRUTE FORCE"      },
  data_exfil:       { color: "#b06eff", label: "DATA EXFIL"       },
  lateral_movement: { color: "#4d9eff", label: "LATERAL MOVEMENT" },
  generic:          { color: "#888888", label: "GENERIC"          },
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtAge(iso) {
  if (!iso) return "—";
  const h = Math.floor((Date.now() - new Date(iso).getTime()) / 3_600_000);
  return h < 48 ? `${h}h` : `${Math.floor(h / 24)}d`;
}
function fmtH(h) {
  if (h == null) return "—";
  if (h < 1)  return `${Math.round(h * 60)}m`;
  if (h < 48) return `${h.toFixed(1)}h`;
  return `${(h / 24).toFixed(1)}d`;
}

// ── Badge components ──────────────────────────────────────────────────────────
function SevBadge({ severity }) {
  const cfg = SEV_CFG[severity] || SEV_CFG.low;
  return (
    <span style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40`,
      fontSize: 9, fontWeight: 700, fontFamily: "monospace",
      padding: "2px 7px", borderRadius: 2, letterSpacing: "0.8px" }}>
      {cfg.label}
    </span>
  );
}
function StatusBadge({ status }) {
  const cfg = STATUS_CFG[status] || { color: C.muted, label: (status || "—").toUpperCase() };
  return <span style={{ color: cfg.color, fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>{cfg.label}</span>;
}
function TypeBadge({ type }) {
  const cfg = TYPE_CFG[type] || { color: C.muted, label: (type || "—").replace(/_/g, " ").toUpperCase() };
  return (
    <span style={{ background: `${cfg.color}12`, color: cfg.color, border: `1px solid ${cfg.color}28`,
      fontSize: 9, fontFamily: "monospace", fontWeight: 700, padding: "2px 6px", borderRadius: 2 }}>
      {cfg.label}
    </span>
  );
}

// ── Dashboard widgets ─────────────────────────────────────────────────────────
function MiniDonut({ slices, cx = 44, cy = 44, r = 34, ri = 18 }) {
  let angle = -90;
  const total = slices.reduce((s, x) => s + (x.value || 0), 0);
  if (total === 0) return <circle cx={cx} cy={cy} r={r} fill="rgba(255,255,255,0.04)" />;
  const arcs = slices.filter(s => s.value > 0).map(s => {
    const sweep = (s.value / total) * 360;
    const startR = (angle * Math.PI) / 180;
    const endR   = ((angle + sweep - 0.5) * Math.PI) / 180;
    const x1 = cx + r * Math.cos(startR), y1 = cy + r * Math.sin(startR);
    const x2 = cx + r * Math.cos(endR),   y2 = cy + r * Math.sin(endR);
    const xi1 = cx + ri * Math.cos(startR), yi1 = cy + ri * Math.sin(startR);
    const xi2 = cx + ri * Math.cos(endR),   yi2 = cy + ri * Math.sin(endR);
    const large = sweep > 180 ? 1 : 0;
    const path = `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} L ${xi2} ${yi2} A ${ri} ${ri} 0 ${large} 0 ${xi1} ${yi1} Z`;
    angle += sweep;
    return { ...s, path };
  });
  return (
    <>
      {arcs.map((a, i) => <path key={i} d={a.path} fill={a.color} opacity={0.88} />)}
      <circle cx={cx} cy={cy} r={ri} fill="#090b10" />
    </>
  );
}

function CasesMetrics({ metrics }) {
  if (!metrics) return null;
  const {
    total_cases = 0, open_cases = 0,
    cases_by_status = {}, cases_by_severity = {}, asm_vs_siem = {},
    avg_mtta_hours, avg_mttr_hours, avg_age_hours,
    trend_30d = [], by_analyst = [],
  } = metrics;

  const critHigh = (cases_by_severity.critical || 0) + (cases_by_severity.high || 0);

  const statusSlices = Object.entries(cases_by_status).map(([k, v]) => ({
    label: (STATUS_CFG[k] || { label: k }).label,
    color: (STATUS_CFG[k] || { color: C.muted }).color,
    value: v,
  }));

  const sevSlices = Object.entries(cases_by_severity).map(([k, v]) => ({
    label: (SEV_CFG[k] || { label: k }).label,
    color: (SEV_CFG[k] || { color: C.muted }).color,
    value: v,
  }));

  // Trend sparkline
  const trendMax = Math.max(...trend_30d.map(t => t.count), 1);
  const W = 140, H = 36;
  const pts = trend_30d.map((t, i) => {
    const x = (i / Math.max(trend_30d.length - 1, 1)) * W;
    const y = H - (t.count / trendMax) * H * 0.9;
    return `${x},${y}`;
  }).join(" ");

  const kpiStyle = (accent) => ({
    background: "rgba(255,255,255,0.025)",
    border: `1px solid rgba(255,255,255,0.06)`,
    borderTop: `2px solid ${accent}`,
    borderRadius: 4, padding: "14px 18px", flex: "1 1 120px", minWidth: 110,
  });

  return (
    <div style={{ marginBottom: 20 }}>
      {/* KPI row */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 12 }}>
        {[
          { label: "Total Cases",      value: total_cases, accent: C.blue   },
          { label: "Active",           value: open_cases,  accent: C.orange },
          { label: "Critical / High",  value: critHigh,    accent: C.red    },
          { label: "Avg Age",          value: fmtH(avg_age_hours), accent: C.yellow, raw: true },
          { label: "Avg MTTA",         value: fmtH(avg_mtta_hours), accent: C.purple, raw: true },
          { label: "Avg MTTR",         value: fmtH(avg_mttr_hours), accent: C.accent, raw: true },
        ].map(k => (
          <div key={k.label} style={kpiStyle(k.accent)}>
            <div style={{ color: k.accent, fontSize: 24, fontWeight: 800, fontFamily: "monospace", lineHeight: 1 }}>
              {k.raw ? k.value : k.value}
            </div>
            <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", marginTop: 4, letterSpacing: "0.5px" }}>
              {k.label.toUpperCase()}
            </div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10 }}>

        {/* Status donut */}
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, padding: "14px 16px" }}>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1px", marginBottom: 10 }}>BY STATUS</div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <svg width="88" height="88" viewBox="0 0 88 88" style={{ flexShrink: 0 }}>
              <MiniDonut slices={statusSlices} />
              <text x="44" y="47" textAnchor="middle" fill="white" fontSize="13" fontFamily="monospace" fontWeight="700">{total_cases}</text>
            </svg>
            <div style={{ display: "flex", flexDirection: "column", gap: 4, flex: 1, minWidth: 0 }}>
              {statusSlices.map(s => (
                <div key={s.label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ color: s.color, fontSize: 9, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.label}</span>
                  <span style={{ color: s.color, fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>{s.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Severity donut */}
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, padding: "14px 16px" }}>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1px", marginBottom: 10 }}>BY SEVERITY</div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <svg width="88" height="88" viewBox="0 0 88 88" style={{ flexShrink: 0 }}>
              <MiniDonut slices={sevSlices} />
              <text x="44" y="47" textAnchor="middle" fill="white" fontSize="13" fontFamily="monospace" fontWeight="700">{total_cases}</text>
            </svg>
            <div style={{ display: "flex", flexDirection: "column", gap: 4, flex: 1, minWidth: 0 }}>
              {sevSlices.map(s => (
                <div key={s.label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ color: s.color, fontSize: 9, fontFamily: "monospace" }}>{s.label}</span>
                  <span style={{ color: s.color, fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>{s.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* 30-day trend */}
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, padding: "14px 16px" }}>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1px", marginBottom: 10 }}>30-DAY TREND</div>
          {trend_30d.length > 1 ? (
            <svg width="100%" viewBox={`0 0 ${W} ${H + 4}`} style={{ display: "block" }}>
              <defs>
                <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.blue} stopOpacity="0.3" />
                  <stop offset="100%" stopColor={C.blue} stopOpacity="0.01" />
                </linearGradient>
              </defs>
              <polygon points={`0,${H} ${pts} ${W},${H}`} fill="url(#trendGrad)" />
              <polyline points={pts} fill="none" stroke={C.blue} strokeWidth="1.5" strokeLinejoin="round" />
            </svg>
          ) : (
            <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace", textAlign: "center", paddingTop: 8 }}>No trend data</div>
          )}
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", marginTop: 6, textAlign: "right" }}>
            {trend_30d.reduce((s, t) => s + t.count, 0)} cases opened
          </div>
        </div>

        {/* Source + analyst */}
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, padding: "14px 16px" }}>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1px", marginBottom: 10 }}>SOURCE & WORKLOAD</div>
          <div style={{ display: "flex", gap: 10, marginBottom: 10 }}>
            {[
              { label: "External (ASM)", value: asm_vs_siem.asm || 0,  color: C.orange },
              { label: "Internal (SIEM)", value: asm_vs_siem.siem || 0, color: C.blue   },
            ].map(s => (
              <div key={s.label} style={{ flex: 1, textAlign: "center" }}>
                <div style={{ color: s.color, fontSize: 18, fontWeight: 700, fontFamily: "monospace" }}>{s.value}</div>
                <div style={{ color: C.muted, fontSize: 8, fontFamily: "monospace" }}>{s.label}</div>
              </div>
            ))}
          </div>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "0.5px", marginBottom: 6 }}>TOP ANALYSTS</div>
          {by_analyst.slice(0, 4).map((a, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3 }}>
              <div style={{ flex: 1, height: 4, background: "rgba(255,255,255,0.05)", borderRadius: 2, overflow: "hidden" }}>
                <div style={{ width: `${(a.count / (by_analyst[0]?.count || 1)) * 100}%`, height: "100%",
                  background: C.blue, borderRadius: 2 }} />
              </div>
              <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", minWidth: 16, textAlign: "right" }}>{a.count}</span>
            </div>
          ))}
          {by_analyst.length === 0 && (
            <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>No assignments yet</div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Assign inline (dropdown popup) ───────────────────────────────────────────
function AssignDropdown({ caseId, currentAssignee, analysts, onAssigned, onClose }) {
  const [selected, setSelected] = useState(currentAssignee || "");
  const [saving, setSaving]     = useState(false);
  const [err, setErr]           = useState("");

  const save = async () => {
    setSaving(true); setErr("");
    try {
      const r = await fetch(`/api/cases/${caseId}`, {
        method: "PATCH", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ assigned_to: selected || null }),
      });
      if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.error || `HTTP ${r.status}`); }
      onAssigned(selected || null);
    } catch (e) { setErr(e.message); }
    setSaving(false);
  };

  return (
    <div onClick={e => e.stopPropagation()}
      style={{ position: "absolute", right: 0, top: "100%", zIndex: 500,
        background: "#0d1117", border: "1px solid rgba(255,255,255,0.12)",
        borderRadius: 4, padding: "10px 12px", width: 260,
        boxShadow: "0 8px 24px rgba(0,0,0,0.6)" }}>
      <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 9, fontFamily: "monospace", marginBottom: 6 }}>ASSIGN TO ANALYST</div>
      <select value={selected} onChange={e => setSelected(e.target.value)}
        style={{ width: "100%", background: "#090b10", border: "1px solid rgba(255,255,255,0.12)",
          color: "white", padding: "6px 8px", borderRadius: 3, fontSize: 11, fontFamily: "monospace",
          marginBottom: 8 }}>
        <option value="">— Unassigned —</option>
        {analysts.map(a => (
          <option key={a.email} value={a.email}>
            {a.name !== a.email ? `${a.name} (${a.role})` : a.email}
          </option>
        ))}
      </select>
      {err && <div style={{ color: "#ff6464", fontSize: 10, fontFamily: "monospace", marginBottom: 6 }}>✗ {err}</div>}
      <div style={{ display: "flex", gap: 6 }}>
        <button onClick={onClose}
          style={{ flex: 1, background: "none", border: "1px solid rgba(255,255,255,0.1)",
            color: "rgba(255,255,255,0.5)", padding: "5px", borderRadius: 3,
            fontFamily: "monospace", fontSize: 10, cursor: "pointer" }}>Cancel</button>
        <button onClick={save} disabled={saving}
          style={{ flex: 1, background: "rgba(0,229,160,0.1)", border: "1px solid rgba(0,229,160,0.3)",
            color: "#00e5a0", padding: "5px", borderRadius: 3,
            fontFamily: "monospace", fontSize: 10, fontWeight: 700, cursor: "pointer" }}>
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </div>
  );
}

// ── Filter select helper ──────────────────────────────────────────────────────
function FilterSelect({ value, onChange, options, placeholder }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)}
      style={{ background: C.surface, border: `1px solid ${C.border}`,
        color: value ? C.text : C.muted, fontSize: 11, fontFamily: "monospace",
        padding: "5px 10px", borderRadius: 3, cursor: "pointer", outline: "none" }}>
      <option value="">{placeholder}</option>
      {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  );
}

// ── New Case Modal ────────────────────────────────────────────────────────────
function NewCaseModal({ onClose, onCreated }) {
  const [query, setQuery]       = useState("");
  const [results, setResults]   = useState([]);
  const [searching, setSearch]  = useState(false);
  const [selected, setSelected] = useState(null);
  const [saving, setSaving]     = useState(false);
  const [err, setErr]           = useState("");
  const inputRef  = useRef(null);
  const searchRef = useRef(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  useEffect(() => {
    if (!query.trim()) { setResults([]); return; }
    clearTimeout(searchRef.current);
    searchRef.current = setTimeout(async () => {
      setSearch(true);
      try {
        const r = await fetch(`/api/siem/incidents?limit=12`, { credentials: "include" });
        const d = r.ok ? await r.json() : { incidents: [] };
        const q = query.trim().toLowerCase();
        setResults((d.incidents || []).filter(i =>
          i.id?.toLowerCase().includes(q) ||
          (i.categories || []).some(c => c.toLowerCase().includes(q))
        ).slice(0, 8));
      } catch { setResults([]); }
      setSearch(false);
    }, 300);
  }, [query]);

  const submit = async () => {
    const id = (selected?.id || query).trim();
    if (!id) { setErr("Select or enter an incident ID."); return; }
    setSaving(true); setErr("");
    try {
      const r = await fetch("/api/cases", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ incident_id: id }),
      });
      if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.error || `HTTP ${r.status}`); }
      onCreated(await r.json());
    } catch (e) { setErr(e.message); }
    setSaving(false);
  };

  return (
    <div onKeyDown={e => e.key === "Escape" && onClose()}
      onClick={e => e.target === e.currentTarget && onClose()}
      style={{ position: "fixed", inset: 0, zIndex: 900, background: "rgba(0,0,0,0.65)",
        display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: C.surface, border: "1px solid rgba(255,255,255,0.1)",
        borderRadius: 6, padding: 28, width: 460, boxShadow: "0 20px 60px rgba(0,0,0,0.6)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <div style={{ color: C.text, fontSize: 13, fontWeight: 600 }}>Open New Case</div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 16 }}>✕</button>
        </div>
        <div style={{ marginBottom: 6, color: C.muted, fontSize: 10, fontFamily: "monospace" }}>SEARCH INCIDENT</div>
        <div style={{ position: "relative" }}>
          <input ref={inputRef} value={selected ? selected.id : query}
            onChange={e => { setSelected(null); setQuery(e.target.value); setErr(""); }}
            onKeyDown={e => e.key === "Enter" && !results.length && submit()}
            placeholder="Type incident ID or category…"
            style={{ width: "100%", boxSizing: "border-box", background: C.bg,
              border: `1px solid ${err ? C.red : "rgba(255,255,255,0.12)"}`,
              color: C.text, padding: "9px 12px", borderRadius: 3,
              fontFamily: "monospace", fontSize: 12, outline: "none" }} />
          {searching && <span style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", color: C.muted, fontSize: 10 }}>…</span>}
        </div>
        {results.length > 0 && !selected && (
          <div style={{ background: C.bg, border: "1px solid rgba(255,255,255,0.1)", borderRadius: 3, marginTop: 4, maxHeight: 200, overflowY: "auto" }}>
            {results.map(inc => (
              <div key={inc.id} onClick={() => { setSelected(inc); setResults([]); setErr(""); }}
                style={{ padding: "8px 12px", cursor: "pointer", borderBottom: "1px solid rgba(255,255,255,0.04)",
                  display: "flex", alignItems: "center", gap: 10 }}
                onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                <span style={{ color: (SEV_CFG[inc.severity] || SEV_CFG.low).color, fontSize: 9, fontFamily: "monospace", fontWeight: 700, minWidth: 52 }}>{(inc.severity || "").toUpperCase()}</span>
                <span style={{ color: C.text, fontFamily: "monospace", fontSize: 11, flex: 1 }}>{inc.id}</span>
                <span style={{ color: C.muted, fontSize: 10 }}>{(inc.categories || []).slice(0,2).join(", ")}</span>
              </div>
            ))}
          </div>
        )}
        {selected && (
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 8,
            background: "rgba(0,229,160,0.06)", border: "1px solid rgba(0,229,160,0.2)",
            borderRadius: 3, padding: "6px 10px" }}>
            <span style={{ color: C.accent, fontFamily: "monospace", fontSize: 11, fontWeight: 700 }}>{selected.id}</span>
            <span style={{ color: C.muted, fontSize: 10 }}>{selected.severity} · {selected.status}</span>
            <button onClick={() => { setSelected(null); setQuery(""); }}
              style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 12, marginLeft: "auto", padding: 0 }}>✕</button>
          </div>
        )}
        {err && <div style={{ color: C.red, fontSize: 10, fontFamily: "monospace", marginTop: 8 }}>✗ {err}</div>}
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 20 }}>
          <button onClick={onClose} style={{ background: "none", border: "1px solid rgba(255,255,255,0.12)",
            color: C.muted, padding: "7px 18px", borderRadius: 3, fontFamily: "monospace", fontSize: 11, cursor: "pointer" }}>Cancel</button>
          <button onClick={submit} disabled={saving} style={{ background: saving ? "rgba(0,229,160,0.08)" : "rgba(0,229,160,0.12)",
            border: `1px solid ${C.accent}40`, color: C.accent,
            padding: "7px 18px", borderRadius: 3, fontFamily: "monospace", fontSize: 11, cursor: saving ? "not-allowed" : "pointer", fontWeight: 700 }}>
            {saving ? "Opening…" : "Open Case"}
          </button>
        </div>
      </div>
    </div>
  );
}

function Spinner() {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "60px 0" }}>
      <div style={{ width: 28, height: 28, borderRadius: "50%",
        border: `2px solid rgba(255,255,255,0.08)`, borderTop: `2px solid ${C.accent}`,
        animation: "spin 0.8s linear infinite" }} />
    </div>
  );
}

// ── Sort header ───────────────────────────────────────────────────────────────
function SortTh({ label, field, sortField, sortDir, onSort }) {
  const active = sortField === field;
  return (
    <div onClick={() => onSort(field)} style={{ cursor: "pointer", display: "flex", alignItems: "center", gap: 3,
      color: active ? "rgba(255,255,255,0.7)" : C.muted, fontSize: 9, fontFamily: "monospace",
      fontWeight: 700, letterSpacing: "1px", userSelect: "none" }}>
      {label}
      {field && <span style={{ fontSize: 11, opacity: active ? 1 : 0.35 }}>{active ? (sortDir === "asc" ? "↑" : "↓") : "↕"}</span>}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function CasesListPage({ onOpenCase }) {
  const [cases,      setCases]      = useState([]);
  const [total,      setTotal]      = useState(0);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState("");
  const [showModal,  setShowModal]  = useState(false);
  const [metrics,    setMetrics]    = useState(null);
  const [analysts,   setAnalysts]   = useState([]);
  const [assignOpen, setAssignOpen] = useState(null); // incident_id of row with dropdown open

  // Filters
  const [filterStatus,   setFilterStatus]   = useState("");
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterType,     setFilterType]     = useState("");
  const [filterSource,   setFilterSource]   = useState("");
  const [filterAssigned, setFilterAssigned] = useState("");
  const [filterDateFrom, setFilterDateFrom] = useState("");
  const [filterDateTo,   setFilterDateTo]   = useState("");
  const [page,           setPage]           = useState(1);
  const PER_PAGE = 50;

  // Sort (server-side)
  const [sortField, setSortField] = useState("case_opened_at");
  const [sortDir,   setSortDir]   = useState("desc");

  const handleSort = (field) => {
    if (sortField === field) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortField(field); setSortDir("desc"); }
    setPage(1);
  };

  const load = useCallback(() => {
    setLoading(true); setError("");
    const p = new URLSearchParams({ page, per_page: PER_PAGE, sort_by: sortField, sort_dir: sortDir });
    if (filterStatus)   p.set("status",      filterStatus);
    if (filterSeverity) p.set("severity",     filterSeverity);
    if (filterType)     p.set("type",         filterType);
    if (filterSource)   p.set("source",       filterSource);
    if (filterAssigned) p.set("assigned_to",  filterAssigned);
    if (filterDateFrom) p.set("date_from",    filterDateFrom);
    if (filterDateTo)   p.set("date_to",      filterDateTo);
    fetch(`/api/cases?${p}`, { credentials: "include" })
      .then(r => r.ok ? r.json() : r.json().then(d => Promise.reject(d.error || `HTTP ${r.status}`)))
      .then(d => { setCases(d.cases || []); setTotal(d.total || 0); setLoading(false); })
      .catch(e => { setError(String(e)); setLoading(false); });
  }, [page, sortField, sortDir, filterStatus, filterSeverity, filterType, filterSource, filterAssigned, filterDateFrom, filterDateTo]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    fetch("/api/cases/metrics", { credentials: "include" })
      .then(r => r.ok ? r.json() : null).then(d => d && setMetrics(d)).catch(() => {});
    fetch("/api/cases/assignable-users", { credentials: "include" })
      .then(r => r.ok ? r.json() : []).then(d => setAnalysts(Array.isArray(d) ? d : [])).catch(() => {});
  }, []);

  const handleCreated  = () => { setShowModal(false); load(); setMetrics(null); fetch("/api/cases/metrics", { credentials: "include" }).then(r => r.ok ? r.json() : null).then(d => d && setMetrics(d)).catch(() => {}); };
  const handleRowClick = (c) => { if (onOpenCase) onOpenCase(c.incident_id || c.id); };

  const handleDelete = async (e, caseId) => {
    e.stopPropagation();
    if (!window.confirm(`Remove case ${caseId}? The incident is kept but the case record is cleared.`)) return;
    const r = await fetch(`/api/cases/${caseId}`, { method: "DELETE", credentials: "include" });
    if (r.ok) { load(); setMetrics(null); fetch("/api/cases/metrics", { credentials: "include" }).then(rr => rr.ok ? rr.json() : null).then(d => d && setMetrics(d)).catch(() => {}); }
    else { const d = await r.json().catch(() => ({})); alert(d.error || "Delete failed"); }
  };

  const clearFilters = () => { setFilterStatus(""); setFilterSeverity(""); setFilterType(""); setFilterSource(""); setFilterAssigned(""); setFilterDateFrom(""); setFilterDateTo(""); setPage(1); };
  const anyFilter = filterStatus || filterSeverity || filterType || filterSource || filterAssigned || filterDateFrom || filterDateTo;

  const inputStyle = { background: C.surface, border: `1px solid ${C.border}`,
    color: C.text, fontSize: 11, fontFamily: "monospace", padding: "5px 10px", borderRadius: 3, outline: "none" };

  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));

  const COLS = "140px 90px 110px 130px 1fr 90px 60px 60px 60px";

  return (
    <>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        .cy-case-row:hover { background: rgba(255,255,255,0.03) !important; cursor: pointer; }
        select option { background: #0d1117; }
      `}</style>

      <div style={{ background: C.bg, minHeight: "100%", padding: "24px 28px" }}>

        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 18 }}>
          <div>
            <div style={{ color: C.text, fontSize: 16, fontWeight: 600 }}>CyCases</div>
            <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace", marginTop: 3 }}>
              {loading ? "Loading…" : `${total} case${total !== 1 ? "s" : ""}`}
            </div>
          </div>
          <button onClick={() => setShowModal(true)}
            style={{ background: "rgba(0,229,160,0.1)", border: `1px solid ${C.accent}35`,
              color: C.accent, padding: "8px 16px", borderRadius: 3,
              fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer" }}>
            + New Case
          </button>
        </div>

        {/* Dashboard widgets */}
        <CasesMetrics metrics={metrics} />

        {/* Filter bar */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center",
          padding: "10px 14px", background: C.surface, border: `1px solid ${C.border}`,
          borderRadius: 4, marginBottom: 14 }}>
          <FilterSelect value={filterStatus} onChange={v => { setFilterStatus(v); setPage(1); }} placeholder="All Statuses"
            options={[{ value: "open", label: "Open" }, { value: "investigating", label: "Investigating" },
              { value: "in_review", label: "In Review" }, { value: "resolved", label: "Resolved" },
              { value: "closed", label: "Closed" }]} />
          <FilterSelect value={filterSeverity} onChange={v => { setFilterSeverity(v); setPage(1); }} placeholder="All Severities"
            options={[{ value: "critical", label: "Critical" }, { value: "high", label: "High" },
              { value: "medium", label: "Medium" }, { value: "low", label: "Low" }]} />
          <FilterSelect value={filterType} onChange={v => { setFilterType(v); setPage(1); }} placeholder="All Types"
            options={[{ value: "ransomware", label: "Ransomware" }, { value: "phishing", label: "Phishing" },
              { value: "brute_force", label: "Brute Force" }, { value: "data_exfil", label: "Data Exfil" },
              { value: "lateral_movement", label: "Lateral Movement" }, { value: "generic", label: "Generic" }]} />
          <FilterSelect value={filterSource} onChange={v => { setFilterSource(v); setPage(1); }} placeholder="All Sources"
            options={[{ value: "asm", label: "External (ASM)" }, { value: "siem", label: "Internal (SIEM)" }]} />
          {analysts.length > 0 && (
            <select value={filterAssigned} onChange={e => { setFilterAssigned(e.target.value); setPage(1); }}
              style={inputStyle}>
              <option value="">All Analysts</option>
              {analysts.map(a => <option key={a.email} value={a.email}>{a.name !== a.email ? a.name : a.email}</option>)}
            </select>
          )}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>FROM</span>
            <input type="date" value={filterDateFrom} onChange={e => { setFilterDateFrom(e.target.value); setPage(1); }} style={inputStyle} />
            <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>TO</span>
            <input type="date" value={filterDateTo}   onChange={e => { setFilterDateTo(e.target.value);   setPage(1); }} style={inputStyle} />
          </div>
          {anyFilter && (
            <button onClick={clearFilters}
              style={{ background: "none", border: "none", color: C.muted, fontSize: 10, fontFamily: "monospace", cursor: "pointer" }}>
              ✕ Clear
            </button>
          )}
        </div>

        {/* Table */}
        {loading ? <Spinner /> : error ? (
          <div style={{ padding: "32px 20px", textAlign: "center", color: C.red, fontFamily: "monospace", fontSize: 12 }}>
            <div style={{ marginBottom: 8 }}>Failed to load cases</div>
            <div style={{ color: C.muted, fontSize: 10, marginBottom: 14 }}>{error}</div>
            <button onClick={load} style={{ background: "rgba(255,59,59,0.1)", border: `1px solid ${C.red}40`,
              color: C.red, padding: "6px 16px", borderRadius: 3, fontFamily: "monospace", fontSize: 11, cursor: "pointer" }}>Retry</button>
          </div>
        ) : cases.length === 0 ? (
          <div style={{ padding: "60px 20px", textAlign: "center", color: C.muted, fontFamily: "monospace", fontSize: 12 }}>
            <div style={{ fontSize: 28, marginBottom: 12, opacity: 0.3 }}>⚑</div>
            No cases match the current filters
          </div>
        ) : (
          <>
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, overflow: "hidden" }}>
              {/* Header */}
              <div style={{ display: "grid", gridTemplateColumns: COLS,
                padding: "8px 16px", background: "rgba(255,255,255,0.02)", borderBottom: `1px solid ${C.border}`, gap: 8 }}>
                {[
                  { label: "CASE ID",     field: null              },
                  { label: "SEVERITY",    field: "severity"        },
                  { label: "STATUS",      field: "status"          },
                  { label: "TYPE",        field: "case_type"       },
                  { label: "ASSIGNED TO", field: "assigned_to"     },
                  { label: "MTTD",        field: "case_mttd_seconds" },
                  { label: "AGE",         field: "case_opened_at"  },
                  { label: "DELETE",      field: null              },
                  { label: "ASSIGN",      field: null              },
                ].map(h => (
                  <SortTh key={h.label} label={h.label} field={h.field}
                    sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                ))}
              </div>

              {/* Rows */}
              {cases.map((c, i) => {
                const cid = c.incident_id || c.id;
                return (
                  <div key={cid} className="cy-case-row"
                    onClick={() => handleRowClick(c)}
                    style={{ display: "grid", gridTemplateColumns: COLS, gap: 8,
                      padding: "11px 16px", alignItems: "center",
                      borderBottom: i < cases.length - 1 ? `1px solid rgba(255,255,255,0.03)` : "none",
                      background: i % 2 === 1 ? "rgba(255,255,255,0.01)" : "transparent",
                      transition: "background 0.12s", position: "relative" }}>
                    {/* Case ID */}
                    <div style={{ color: C.accent, fontFamily: "monospace", fontSize: 11, fontWeight: 600,
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {cid}
                      {c.case_restricted && <span title="Restricted" style={{ marginLeft: 5, fontSize: 11, opacity: 0.5 }}>🔒</span>}
                    </div>
                    <div><SevBadge severity={c.severity} /></div>
                    <div><StatusBadge status={c.status} /></div>
                    <div><TypeBadge type={c.case_type} /></div>
                    {/* Assigned To */}
                    <div style={{ color: c.assigned_to ? C.text : C.muted, fontSize: 11, fontFamily: "monospace",
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {c.assigned_to || "Unassigned"}
                    </div>
                    {/* MTTD */}
                    <div style={{ color: C.muted, fontSize: 11, fontFamily: "monospace" }}>
                      {c.case_mttd_seconds != null ? fmtH(c.case_mttd_seconds / 3600) : "—"}
                    </div>
                    {/* Age */}
                    <div style={{ color: C.muted, fontSize: 11, fontFamily: "monospace" }}>
                      {fmtAge(c.case_opened_at)}
                    </div>
                    {/* Delete */}
                    <div onClick={e => handleDelete(e, cid)} title="Remove case"
                      style={{ color: "rgba(255,59,59,0.5)", fontSize: 14, textAlign: "center", cursor: "pointer" }}
                      onMouseEnter={e => e.currentTarget.style.color = "#ff3b3b"}
                      onMouseLeave={e => e.currentTarget.style.color = "rgba(255,59,59,0.5)"}>
                      🗑
                    </div>
                    {/* Assign */}
                    <div style={{ position: "relative" }}>
                      <div onClick={e => { e.stopPropagation(); setAssignOpen(assignOpen === cid ? null : cid); }}
                        title="Assign to analyst"
                        style={{ color: "rgba(77,158,255,0.5)", fontSize: 14, textAlign: "center", cursor: "pointer" }}
                        onMouseEnter={e => e.currentTarget.style.color = "#4d9eff"}
                        onMouseLeave={e => e.currentTarget.style.color = "rgba(77,158,255,0.5)"}>
                        👤
                      </div>
                      {assignOpen === cid && (
                        <AssignDropdown
                          caseId={cid}
                          currentAssignee={c.assigned_to || ""}
                          analysts={analysts}
                          onAssigned={(email) => {
                            setCases(prev => prev.map(x => (x.incident_id || x.id) === cid ? { ...x, assigned_to: email } : x));
                            setAssignOpen(null);
                          }}
                          onClose={() => setAssignOpen(null)}
                        />
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
                marginTop: 12, padding: "0 4px" }}>
                <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                  {(page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, total)} of {total}
                </span>
                <div style={{ display: "flex", gap: 4 }}>
                  <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                    style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
                      color: page === 1 ? "rgba(255,255,255,0.45)" : C.muted,
                      padding: "3px 10px", borderRadius: 3, cursor: page === 1 ? "default" : "pointer",
                      fontFamily: "monospace", fontSize: 11 }}>‹ Prev</button>
                  <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                    style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
                      color: page === totalPages ? "rgba(255,255,255,0.45)" : C.muted,
                      padding: "3px 10px", borderRadius: 3, cursor: page === totalPages ? "default" : "pointer",
                      fontFamily: "monospace", fontSize: 11 }}>Next ›</button>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {showModal && <NewCaseModal onClose={() => setShowModal(false)} onCreated={handleCreated} />}
    </>
  );
}
