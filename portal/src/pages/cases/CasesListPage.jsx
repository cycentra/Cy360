/**
 * CasesListPage.jsx
 * =================
 * Table-based list of all cases. Supports filtering by status, severity,
 * type, and date range. Inline "New Case" modal. Navigates to detail via
 * the onOpenCase prop (matches App.jsx activeTab pattern).
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

// ── Severity config ───────────────────────────────────────────────────────────
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
  const diffMs = Date.now() - new Date(iso).getTime();
  const h = Math.floor(diffMs / 3_600_000);
  if (h < 48) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}

function fmtMttd(seconds) {
  if (!seconds && seconds !== 0) return "—";
  return `${Math.round(seconds / 3600)}h`;
}

// ── Small badge components ────────────────────────────────────────────────────
function SevBadge({ severity }) {
  const cfg = SEV_CFG[severity] || SEV_CFG.low;
  return (
    <span style={{
      background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40`,
      fontSize: 9, fontWeight: 700, fontFamily: "monospace",
      padding: "2px 7px", borderRadius: 2, letterSpacing: "0.8px",
    }}>{cfg.label}</span>
  );
}

function StatusBadge({ status }) {
  const cfg = STATUS_CFG[status] || { color: C.muted, label: (status || "—").toUpperCase() };
  return (
    <span style={{ color: cfg.color, fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
      {cfg.label}
    </span>
  );
}

function TypeBadge({ type }) {
  const cfg = TYPE_CFG[type] || { color: C.muted, label: (type || "—").replace(/_/g, " ").toUpperCase() };
  return (
    <span style={{
      background: `${cfg.color}12`, color: cfg.color, border: `1px solid ${cfg.color}28`,
      fontSize: 9, fontFamily: "monospace", fontWeight: 700,
      padding: "2px 6px", borderRadius: 2,
    }}>{cfg.label}</span>
  );
}

// ── Filter select helper ──────────────────────────────────────────────────────
function FilterSelect({ value, onChange, options, placeholder }) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      style={{
        background: C.surface, border: `1px solid ${C.border}`,
        color: value ? C.text : C.muted,
        fontSize: 11, fontFamily: "monospace",
        padding: "5px 10px", borderRadius: 3, cursor: "pointer",
        outline: "none",
      }}
    >
      <option value="">{placeholder}</option>
      {options.map(o => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  );
}

// ── New Case Modal ────────────────────────────────────────────────────────────
function NewCaseModal({ onClose, onCreated }) {
  const [query,      setQuery]      = useState("");
  const [results,    setResults]    = useState([]);
  const [searching,  setSearching]  = useState(false);
  const [selected,   setSelected]   = useState(null);  // { id, severity, status, categories }
  const [saving,     setSaving]     = useState(false);
  const [err,        setErr]        = useState("");
  const inputRef = useRef(null);
  const searchRef = useRef(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  // Debounced incident search
  useEffect(() => {
    if (!query.trim()) { setResults([]); return; }
    clearTimeout(searchRef.current);
    searchRef.current = setTimeout(async () => {
      setSearching(true);
      try {
        const qs = new URLSearchParams({ limit: 12 });
        // Try as ID prefix first, then as free-text
        const r = await fetch(`/api/siem/incidents?${qs}`, { credentials: "include" });
        const d = r.ok ? await r.json() : { incidents: [] };
        const q = query.trim().toLowerCase();
        const filtered = (d.incidents || []).filter(i =>
          i.id?.toLowerCase().includes(q) ||
          (i.categories || []).some(c => c.toLowerCase().includes(q)) ||
          (i.mitre_tactics || []).some(t => t.toLowerCase().includes(q))
        );
        setResults(filtered.slice(0, 8));
      } catch { setResults([]); }
      finally { setSearching(false); }
    }, 300);
  }, [query]);

  const handleSubmit = async () => {
    const id = (selected?.id || query).trim();
    if (!id) { setErr("Select or enter an incident ID."); return; }
    setSaving(true); setErr("");
    try {
      const r = await fetch("/api/cases", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ incident_id: id }),
      });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        throw new Error(d.error || `HTTP ${r.status}`);
      }
      onCreated(await r.json());
    } catch (e) { setErr(e.message); }
    finally { setSaving(false); }
  };

  const SEV_COLOR = { critical: "#ff3b3b", high: "#ff8c00", medium: "#4d9eff", low: "#888" };
  const inputS = {
    width: "100%", boxSizing: "border-box",
    background: C.bg, border: `1px solid ${err ? C.red : "rgba(255,255,255,0.12)"}`,
    color: C.text, padding: "9px 12px", borderRadius: 3,
    fontFamily: "monospace", fontSize: 12, outline: "none",
  };

  return (
    <div
      onKeyDown={e => e.key === "Escape" && onClose()}
      onClick={e => e.target === e.currentTarget && onClose()}
      style={{ position: "fixed", inset: 0, zIndex: 900, background: "rgba(0,0,0,0.65)",
        display: "flex", alignItems: "center", justifyContent: "center" }}
    >
      <div style={{ background: C.surface, border: "1px solid rgba(255,255,255,0.1)",
        borderRadius: 6, padding: 28, width: 460, boxShadow: "0 20px 60px rgba(0,0,0,0.6)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <div style={{ color: C.text, fontSize: 13, fontWeight: 600 }}>Open New Case</div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 16 }}>✕</button>
        </div>

        {/* Search / type incident ID */}
        <div style={{ marginBottom: 6, color: C.muted, fontSize: 10, fontFamily: "monospace", letterSpacing: "1px" }}>
          SEARCH INCIDENT
        </div>
        <div style={{ position: "relative" }}>
          <input
            ref={inputRef}
            value={selected ? selected.id : query}
            onChange={e => { setSelected(null); setQuery(e.target.value); setErr(""); }}
            onKeyDown={e => e.key === "Enter" && !results.length && handleSubmit()}
            placeholder="Type incident ID or category (e.g. INC-001, phishing, brute_force)"
            style={{ ...inputS, paddingRight: searching ? 36 : 12 }}
          />
          {searching && (
            <span style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)",
              color: C.muted, fontSize: 10 }}>…</span>
          )}
        </div>

        {/* Results dropdown */}
        {results.length > 0 && !selected && (
          <div style={{ background: C.bg, border: "1px solid rgba(255,255,255,0.1)",
            borderRadius: 3, marginTop: 4, maxHeight: 220, overflowY: "auto" }}>
            {results.map(inc => (
              <div key={inc.id} onClick={() => { setSelected(inc); setResults([]); setErr(""); }}
                style={{ padding: "8px 12px", cursor: "pointer", borderBottom: "1px solid rgba(255,255,255,0.04)",
                  display: "flex", alignItems: "center", gap: 10 }}
                onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                <span style={{ color: SEV_COLOR[inc.severity] || "#888", fontSize: 9, fontFamily: "monospace",
                  fontWeight: 700, minWidth: 52 }}>{(inc.severity || "").toUpperCase()}</span>
                <span style={{ color: C.text, fontFamily: "monospace", fontSize: 11, flex: 1 }}>{inc.id}</span>
                <span style={{ color: C.muted, fontSize: 10 }}>{(inc.categories || []).slice(0,2).join(", ")}</span>
              </div>
            ))}
          </div>
        )}

        {/* Selected incident pill */}
        {selected && (
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 8,
            background: "rgba(0,229,160,0.06)", border: "1px solid rgba(0,229,160,0.2)",
            borderRadius: 3, padding: "6px 10px" }}>
            <span style={{ color: "#00e5a0", fontFamily: "monospace", fontSize: 11, fontWeight: 700 }}>{selected.id}</span>
            <span style={{ color: C.muted, fontSize: 10 }}>{selected.severity} · {selected.status}</span>
            <button onClick={() => { setSelected(null); setQuery(""); }}
              style={{ background: "none", border: "none", color: C.muted, cursor: "pointer",
                fontSize: 12, marginLeft: "auto", padding: 0 }}>✕</button>
          </div>
        )}

        {err && <div style={{ color: C.red, fontSize: 10, fontFamily: "monospace", marginTop: 8 }}>✗ {err}</div>}

        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 20 }}>
          <button onClick={onClose}
            style={{ background: "none", border: "1px solid rgba(255,255,255,0.12)",
              color: C.muted, padding: "7px 18px", borderRadius: 3,
              fontFamily: "monospace", fontSize: 11, cursor: "pointer" }}>Cancel</button>
          <button onClick={handleSubmit} disabled={saving}
            style={{ background: saving ? "rgba(0,229,160,0.08)" : "rgba(0,229,160,0.12)",
              border: `1px solid ${C.accent}40`, color: C.accent,
              padding: "7px 18px", borderRadius: 3, fontFamily: "monospace",
              fontSize: 11, cursor: saving ? "not-allowed" : "pointer", fontWeight: 700 }}>
            {saving ? "Opening…" : "Open Case"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Spinner ───────────────────────────────────────────────────────────────────
function Spinner() {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "60px 0" }}>
      <div style={{
        width: 28, height: 28, borderRadius: "50%",
        border: `2px solid rgba(255,255,255,0.08)`,
        borderTop: `2px solid ${C.accent}`,
        animation: "spin 0.8s linear infinite",
      }} />
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function CasesListPage({ onOpenCase }) {
  const [cases, setCases]         = useState([]);
  const [total, setTotal]         = useState(0);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState("");
  const [showModal, setShowModal] = useState(false);

  // Filters
  const [filterStatus,   setFilterStatus]   = useState("");
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterType,     setFilterType]     = useState("");
  const [filterDateFrom, setFilterDateFrom] = useState("");
  const [filterDateTo,   setFilterDateTo]   = useState("");
  const [page]                              = useState(1);

  const load = useCallback(() => {
    setLoading(true); setError("");
    const p = new URLSearchParams({ page, per_page: 50 });
    if (filterStatus)   p.set("status",   filterStatus);
    if (filterSeverity) p.set("severity", filterSeverity);
    if (filterType)     p.set("type",     filterType);
    if (filterDateFrom) p.set("date_from", filterDateFrom);
    if (filterDateTo)   p.set("date_to",   filterDateTo);

    fetch(`/api/cases?${p}`, { credentials: "include" })
      .then(r => r.ok ? r.json() : r.json().then(d => Promise.reject(d.error || `HTTP ${r.status}`)))
      .then(d => {
        setCases(d.cases || []);
        setTotal(d.total || 0);
        setLoading(false);
      })
      .catch(e => { setError(String(e)); setLoading(false); });
  }, [page, filterStatus, filterSeverity, filterType, filterDateFrom, filterDateTo]);

  useEffect(() => { load(); }, [load]);

  const handleCreated = () => { setShowModal(false); load(); };

  const handleRowClick = (c) => {
    if (onOpenCase) onOpenCase(c.incident_id || c.id);
  };

  const inputStyle = {
    background: C.surface, border: `1px solid ${C.border}`,
    color: C.text, fontSize: 11, fontFamily: "monospace",
    padding: "5px 10px", borderRadius: 3, outline: "none",
  };

  return (
    <>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        .cy-case-row:hover { background: rgba(255,255,255,0.03) !important; cursor: pointer; }
      `}</style>

      <div style={{ background: C.bg, minHeight: "100%", padding: "24px 28px" }}>

        {/* ── Header ────────────────────────────────────────────────────── */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
          <div>
            <div style={{ color: C.text, fontSize: 16, fontWeight: 600, letterSpacing: "-0.3px" }}>
              CyCases
            </div>
            <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace", marginTop: 3 }}>
              {loading ? "Loading…" : `${total} case${total !== 1 ? "s" : ""}`}
            </div>
          </div>
          <button
            onClick={() => setShowModal(true)}
            style={{
              background: "rgba(0,229,160,0.1)", border: `1px solid ${C.accent}35`,
              color: C.accent, padding: "8px 16px", borderRadius: 3,
              fontFamily: "monospace", fontSize: 11, fontWeight: 700,
              cursor: "pointer", letterSpacing: "0.5px",
            }}
          >+ New Case</button>
        </div>

        {/* ── Filter bar ────────────────────────────────────────────────── */}
        <div style={{
          display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center",
          padding: "12px 16px", background: C.surface,
          border: `1px solid ${C.border}`, borderRadius: 4, marginBottom: 16,
        }}>
          <FilterSelect
            value={filterStatus} onChange={setFilterStatus}
            placeholder="All Statuses"
            options={[
              { value: "open",          label: "Open"          },
              { value: "investigating", label: "Investigating" },
              { value: "in_review",     label: "In Review"     },
              { value: "resolved",      label: "Resolved"      },
              { value: "closed",        label: "Closed"        },
            ]}
          />
          <FilterSelect
            value={filterSeverity} onChange={setFilterSeverity}
            placeholder="All Severities"
            options={[
              { value: "critical", label: "Critical" },
              { value: "high",     label: "High"     },
              { value: "medium",   label: "Medium"   },
              { value: "low",      label: "Low"      },
            ]}
          />
          <FilterSelect
            value={filterType} onChange={setFilterType}
            placeholder="All Types"
            options={[
              { value: "ransomware",       label: "Ransomware"       },
              { value: "phishing",         label: "Phishing"         },
              { value: "brute_force",      label: "Brute Force"      },
              { value: "data_exfil",       label: "Data Exfil"       },
              { value: "lateral_movement", label: "Lateral Movement" },
              { value: "generic",          label: "Generic"          },
            ]}
          />
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>FROM</span>
            <input
              type="date" value={filterDateFrom} onChange={e => setFilterDateFrom(e.target.value)}
              style={inputStyle}
            />
            <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>TO</span>
            <input
              type="date" value={filterDateTo} onChange={e => setFilterDateTo(e.target.value)}
              style={inputStyle}
            />
          </div>
          {(filterStatus || filterSeverity || filterType || filterDateFrom || filterDateTo) && (
            <button
              onClick={() => { setFilterStatus(""); setFilterSeverity(""); setFilterType(""); setFilterDateFrom(""); setFilterDateTo(""); }}
              style={{ background: "none", border: "none", color: C.muted, fontSize: 10, fontFamily: "monospace", cursor: "pointer" }}
            >✕ Clear</button>
          )}
        </div>

        {/* ── Content ───────────────────────────────────────────────────── */}
        {loading ? (
          <Spinner />
        ) : error ? (
          <div style={{
            padding: "32px 20px", textAlign: "center",
            color: C.red, fontFamily: "monospace", fontSize: 12,
          }}>
            <div style={{ marginBottom: 10 }}>Failed to load cases</div>
            <div style={{ color: C.muted, fontSize: 10, marginBottom: 16 }}>{error}</div>
            <button onClick={load} style={{
              background: "rgba(255,59,59,0.1)", border: `1px solid ${C.red}40`,
              color: C.red, padding: "6px 16px", borderRadius: 3,
              fontFamily: "monospace", fontSize: 11, cursor: "pointer",
            }}>Retry</button>
          </div>
        ) : cases.length === 0 ? (
          <div style={{
            padding: "60px 20px", textAlign: "center",
            color: C.muted, fontFamily: "monospace", fontSize: 12,
          }}>
            <div style={{ fontSize: 28, marginBottom: 12, opacity: 0.3 }}>⚑</div>
            No open cases
          </div>
        ) : (
          <div style={{
            background: C.surface, border: `1px solid ${C.border}`,
            borderRadius: 4, overflow: "hidden",
          }}>
            {/* Table header */}
            <div style={{
              display: "grid",
              gridTemplateColumns: "140px 90px 110px 130px 1fr 70px 60px 30px",
              padding: "8px 16px",
              background: "rgba(255,255,255,0.02)",
              borderBottom: `1px solid ${C.border}`,
            }}>
              {["CASE ID", "SEVERITY", "STATUS", "TYPE", "ASSIGNED TO", "MTTD", "AGE", ""].map(h => (
                <div key={h} style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px" }}>{h}</div>
              ))}
            </div>

            {/* Table rows */}
            {cases.map((c, i) => (
              <div
                key={c.id || c.incident_id}
                className="cy-case-row"
                onClick={() => handleRowClick(c)}
                style={{
                  display: "grid",
                  gridTemplateColumns: "140px 90px 110px 130px 1fr 70px 60px 30px",
                  padding: "11px 16px", alignItems: "center",
                  borderBottom: i < cases.length - 1 ? `1px solid rgba(255,255,255,0.03)` : "none",
                  background: i % 2 === 1 ? "rgba(255,255,255,0.01)" : "transparent",
                  transition: "background 0.12s",
                }}
              >
                {/* Case ID */}
                <div style={{ color: C.accent, fontFamily: "monospace", fontSize: 11, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {c.incident_id || c.id}
                </div>
                {/* Severity */}
                <div><SevBadge severity={c.severity} /></div>
                {/* Status */}
                <div><StatusBadge status={c.status} /></div>
                {/* Type */}
                <div><TypeBadge type={c.incident_type} /></div>
                {/* Assigned To */}
                <div style={{ color: c.assigned_to ? C.text : C.muted, fontSize: 11, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {c.assigned_to || "Unassigned"}
                </div>
                {/* MTTD */}
                <div style={{ color: C.muted, fontSize: 11, fontFamily: "monospace" }}>
                  {fmtMttd(c.case_mttd_seconds)}
                </div>
                {/* Age */}
                <div style={{ color: C.muted, fontSize: 11, fontFamily: "monospace" }}>
                  {fmtAge(c.case_opened_at)}
                </div>
                {/* Restricted icon */}
                <div style={{ textAlign: "center" }}>
                  {c.case_restricted && (
                    <span title="Restricted" style={{ fontSize: 12, opacity: 0.6 }}>🔒</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {showModal && <NewCaseModal onClose={() => setShowModal(false)} onCreated={handleCreated} />}
    </>
  );
}
