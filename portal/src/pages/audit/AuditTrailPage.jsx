/**
 * AuditTrailPage.jsx
 * ==================
 * Searchable, filterable, timestamped audit log viewer.
 * Covers user activities (login/logout, config changes) and system events
 * (scan triggers, scheduled job execution, service lifecycle).
 */

import { useState, useEffect, useCallback, useRef } from "react";

// ── Colour palette ────────────────────────────────────────────────────────────
const C = {
  bg:      "#090b10",
  surface: "#0d1117",
  border:  "rgba(255,255,255,0.07)",
  text:    "rgba(255,255,255,0.82)",
  muted:   "rgba(255,255,255,0.35)",
  accent:  "#00e5a0",
  red:     "#ff3b3b",
  orange:  "#ff8c00",
  blue:    "#4d9eff",
  purple:  "#b06eff",
  yellow:  "#f5a623",
};

const CATEGORY_COLORS = {
  authentication: C.blue,
  configuration:  C.purple,
  scan:           C.accent,
  system:         C.orange,
  data:           C.yellow,
  security:       C.red,
  other:          C.muted,
};

const RESULT_COLORS = {
  success: C.accent,
  failure: C.red,
  error:   C.red,
  denied:  C.orange,
  warning: C.orange,
};

// ── Small helpers ─────────────────────────────────────────────────────────────

function fmtTs(ts) {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    return d.toLocaleString("en-US", {
      month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hour12: false,
    });
  } catch { return ts; }
}

function CategoryBadge({ category }) {
  const color = CATEGORY_COLORS[category] || C.muted;
  return (
    <span style={{
      background: `${color}18`, color, border: `1px solid ${color}30`,
      fontSize: 9, fontFamily: "monospace", fontWeight: 700,
      padding: "2px 6px", borderRadius: 3, textTransform: "uppercase",
      letterSpacing: "0.8px", whiteSpace: "nowrap",
    }}>
      {category}
    </span>
  );
}

function ResultDot({ result }) {
  const color = RESULT_COLORS[result] || C.muted;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
      <span style={{
        width: 6, height: 6, borderRadius: "50%", background: color,
        boxShadow: `0 0 5px ${color}88`, flexShrink: 0,
      }} />
      <span style={{ color, fontSize: 10, fontFamily: "monospace" }}>
        {(result || "ok").toUpperCase()}
      </span>
    </span>
  );
}

// ── Filter bar ────────────────────────────────────────────────────────────────

function FilterBar({ filters, onChange, onExport, stats }) {
  const inputStyle = {
    background: "#0d1117", border: "1px solid rgba(255,255,255,0.1)",
    color: C.text, borderRadius: 4, padding: "6px 10px",
    fontSize: 11, fontFamily: "monospace", outline: "none",
  };

  const categories = ["", "authentication", "configuration", "scan", "system", "data", "security", "other"];
  const results    = ["", "success", "failure", "error", "denied"];

  return (
    <div style={{
      background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 6, padding: "14px 18px", marginBottom: 16,
      display: "flex", flexWrap: "wrap", gap: 10, alignItems: "flex-end",
    }}>
      {/* Search */}
      <div style={{ flex: "1 1 220px" }}>
        <div style={{ color: C.muted, fontSize: 9, marginBottom: 4, fontFamily: "monospace", letterSpacing: "1px" }}>SEARCH</div>
        <input
          style={{ ...inputStyle, width: "100%", boxSizing: "border-box" }}
          placeholder="Search event, email, detail..."
          value={filters.q}
          onChange={e => onChange({ ...filters, q: e.target.value })}
        />
      </div>

      {/* Category */}
      <div style={{ flex: "0 0 160px" }}>
        <div style={{ color: C.muted, fontSize: 9, marginBottom: 4, fontFamily: "monospace", letterSpacing: "1px" }}>CATEGORY</div>
        <select style={{ ...inputStyle, width: "100%" }}
          value={filters.category}
          onChange={e => onChange({ ...filters, category: e.target.value })}>
          {categories.map(c => <option key={c} value={c}>{c || "All categories"}</option>)}
        </select>
      </div>

      {/* Result */}
      <div style={{ flex: "0 0 140px" }}>
        <div style={{ color: C.muted, fontSize: 9, marginBottom: 4, fontFamily: "monospace", letterSpacing: "1px" }}>RESULT</div>
        <select style={{ ...inputStyle, width: "100%" }}
          value={filters.result}
          onChange={e => onChange({ ...filters, result: e.target.value })}>
          {results.map(r => <option key={r} value={r}>{r || "All results"}</option>)}
        </select>
      </div>

      {/* Email */}
      <div style={{ flex: "0 0 180px" }}>
        <div style={{ color: C.muted, fontSize: 9, marginBottom: 4, fontFamily: "monospace", letterSpacing: "1px" }}>USER / EMAIL</div>
        <input
          style={{ ...inputStyle, width: "100%", boxSizing: "border-box" }}
          placeholder="Filter by email..."
          value={filters.email}
          onChange={e => onChange({ ...filters, email: e.target.value })}
        />
      </div>

      {/* Date range */}
      <div style={{ flex: "0 0 160px" }}>
        <div style={{ color: C.muted, fontSize: 9, marginBottom: 4, fontFamily: "monospace", letterSpacing: "1px" }}>FROM</div>
        <input type="date" style={{ ...inputStyle, width: "100%", boxSizing: "border-box" }}
          value={filters.from}
          onChange={e => onChange({ ...filters, from: e.target.value })} />
      </div>
      <div style={{ flex: "0 0 160px" }}>
        <div style={{ color: C.muted, fontSize: 9, marginBottom: 4, fontFamily: "monospace", letterSpacing: "1px" }}>TO</div>
        <input type="date" style={{ ...inputStyle, width: "100%", boxSizing: "border-box" }}
          value={filters.to}
          onChange={e => onChange({ ...filters, to: e.target.value })} />
      </div>

      {/* Export + clear */}
      <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 2 }}>
        <button onClick={() => onExport("csv")}
          style={{ background: "rgba(77,158,255,0.08)", border: "1px solid rgba(77,158,255,0.25)",
            color: C.blue, padding: "6px 14px", borderRadius: 4, fontSize: 10,
            fontFamily: "monospace", cursor: "pointer", fontWeight: 700 }}>
          ↓ CSV
        </button>
        <button onClick={() => onExport("json")}
          style={{ background: "rgba(77,158,255,0.08)", border: "1px solid rgba(77,158,255,0.25)",
            color: C.blue, padding: "6px 14px", borderRadius: 4, fontSize: 10,
            fontFamily: "monospace", cursor: "pointer", fontWeight: 700 }}>
          ↓ JSON
        </button>
        <button onClick={() => onChange({ q: "", category: "", result: "", email: "", from: "", to: "" })}
          style={{ background: "transparent", border: "1px solid rgba(255,255,255,0.1)",
            color: C.muted, padding: "6px 12px", borderRadius: 4, fontSize: 10,
            fontFamily: "monospace", cursor: "pointer" }}>
          Clear
        </button>
      </div>

      {/* Quick stats */}
      {stats && (
        <div style={{ flex: "1 1 100%", display: "flex", gap: 16, flexWrap: "wrap", marginTop: 4 }}>
          {Object.entries(stats.by_category || {}).map(([cat, n]) => (
            <span key={cat} style={{ color: CATEGORY_COLORS[cat] || C.muted, fontSize: 10, fontFamily: "monospace" }}>
              {cat}: <b>{n}</b>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Entry row ─────────────────────────────────────────────────────────────────

function EntryRow({ entry, expanded, onToggle }) {
  const meta = entry.metadata && Object.keys(entry.metadata).length > 0
    ? entry.metadata : null;

  return (
    <div style={{
      borderBottom: `1px solid ${C.border}`,
      cursor: "pointer",
      background: expanded ? "rgba(0,229,160,0.03)" : "transparent",
      transition: "background 0.12s",
    }}
      onMouseEnter={e => !expanded && (e.currentTarget.style.background = "rgba(255,255,255,0.02)")}
      onMouseLeave={e => !expanded && (e.currentTarget.style.background = "transparent")}
      onClick={onToggle}
    >
      {/* Main row */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "168px 120px 110px 200px 1fr 80px 22px",
        alignItems: "center",
        padding: "9px 14px",
        gap: 12,
      }}>
        {/* Timestamp */}
        <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace", whiteSpace: "nowrap" }}>
          {fmtTs(entry.timestamp)}
        </span>

        {/* Category */}
        <span><CategoryBadge category={entry.category} /></span>

        {/* Event type */}
        <span style={{ color: C.text, fontSize: 10, fontFamily: "monospace", overflow: "hidden",
          textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={entry.type}>
          {entry.type}
        </span>

        {/* Email */}
        <span style={{ color: C.blue, fontSize: 10, fontFamily: "monospace", overflow: "hidden",
          textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {entry.email || <span style={{ color: C.muted }}>—</span>}
        </span>

        {/* Detail */}
        <span style={{ color: C.muted, fontSize: 10, overflow: "hidden",
          textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {entry.detail || entry.resource || ""}
        </span>

        {/* Result */}
        <span><ResultDot result={entry.result} /></span>

        {/* Expand arrow */}
        <span style={{ color: C.muted, fontSize: 11, textAlign: "center" }}>
          {expanded ? "▾" : "▸"}
        </span>
      </div>

      {/* Expanded detail panel */}
      {expanded && (
        <div style={{
          padding: "10px 18px 14px 18px",
          background: "rgba(0,0,0,0.25)",
          borderTop: `1px solid ${C.border}`,
          display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px 24px",
        }}>
          {[
            ["Timestamp",   entry.timestamp],
            ["Type",        entry.type],
            ["Category",    entry.category],
            ["Result",      entry.result],
            ["Email",       entry.email],
            ["Resource",    entry.resource],
            ["IP Address",  entry.ip],
            ["Source",      entry._source],
          ].map(([label, val]) => val ? (
            <div key={label}>
              <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                letterSpacing: "1px", textTransform: "uppercase" }}>{label}: </span>
              <span style={{ color: C.text, fontSize: 10, fontFamily: "monospace" }}>{val}</span>
            </div>
          ) : null)}

          {entry.detail && (
            <div style={{ gridColumn: "1 / -1" }}>
              <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                letterSpacing: "1px", textTransform: "uppercase" }}>Detail: </span>
              <span style={{ color: C.text, fontSize: 10 }}>{entry.detail}</span>
            </div>
          )}

          {meta && (
            <div style={{ gridColumn: "1 / -1",
              background: "rgba(255,255,255,0.03)",
              border: `1px solid ${C.border}`,
              borderRadius: 4, padding: "8px 12px", marginTop: 4,
            }}>
              <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                letterSpacing: "1px", marginBottom: 6, textTransform: "uppercase" }}>
                Metadata
              </div>
              <pre style={{ margin: 0, color: C.accent, fontSize: 9,
                fontFamily: "monospace", overflowX: "auto" }}>
                {JSON.stringify(meta, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Stats strip ───────────────────────────────────────────────────────────────

function StatsStrip({ stats }) {
  if (!stats) return null;
  const cards = [
    { label: "Total Events (30d)", value: stats.total_events, color: C.accent },
    { label: "Successful",  value: stats.by_result?.success || 0,  color: C.accent },
    { label: "Failures",    value: (stats.by_result?.failure || 0) + (stats.by_result?.error || 0), color: C.red },
    { label: "Auth Events", value: stats.by_category?.authentication || 0, color: C.blue },
    { label: "Config Changes", value: stats.by_category?.configuration || 0, color: C.purple },
    { label: "Scan Events", value: stats.by_category?.scan || 0, color: C.accent },
  ];

  return (
    <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 16 }}>
      {cards.map(({ label, value, color }) => (
        <div key={label} style={{
          flex: "1 1 130px", background: C.surface,
          border: `1px solid ${C.border}`,
          borderTop: `2px solid ${color}`,
          borderRadius: 6, padding: "10px 14px",
        }}>
          <div style={{ color, fontSize: 22, fontWeight: 700, fontFamily: "monospace" }}>{value}</div>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
            letterSpacing: "0.8px", textTransform: "uppercase", marginTop: 2 }}>{label}</div>
        </div>
      ))}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function AuditTrailPage() {
  const [entries,  setEntries]  = useState([]);
  const [stats,    setStats]    = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState(null);
  const [expanded, setExpanded] = useState(null);
  const [page,     setPage]     = useState(1);
  const [total,    setTotal]    = useState(0);
  const [pages,    setPages]    = useState(1);
  const PER_PAGE = 50;

  const [filters, setFilters] = useState({
    q: "", category: "", result: "", email: "", from: "", to: "",
  });

  const buildQuery = useCallback((f, pg) => {
    const params = new URLSearchParams({ page: pg, per_page: PER_PAGE });
    if (f.q)        params.set("q",        f.q);
    if (f.category) params.set("category", f.category);
    if (f.result)   params.set("result",   f.result);
    if (f.email)    params.set("email",    f.email);
    if (f.from)     params.set("from",     f.from);
    if (f.to)       params.set("to",       f.to);
    return params.toString();
  }, []);

  const fetchLogs = useCallback(async (f, pg) => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch(`/api/audit/logs?${buildQuery(f, pg)}`);
      if (!r.ok) throw new Error(`Server error ${r.status}`);
      const d = await r.json();
      setEntries(d.entries || []);
      setTotal(d.total || 0);
      setPages(d.pages || 1);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [buildQuery]);

  const fetchStats = useCallback(async () => {
    try {
      const r = await fetch("/api/audit/stats");
      if (r.ok) setStats(await r.json());
    } catch {}
  }, []);

  // Debounced filter effect
  const debounceRef = useRef(null);
  useEffect(() => {
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      setPage(1);
      setExpanded(null);
      fetchLogs(filters, 1);
    }, 280);
    return () => clearTimeout(debounceRef.current);
  }, [filters, fetchLogs]);

  useEffect(() => {
    fetchLogs(filters, page);
  }, [page]);  // eslint-disable-line

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  const handleExport = (fmt) => {
    const q = buildQuery(filters, 1);
    window.open(`/api/audit/export?format=${fmt}&${q}`, "_blank");
  };

  const handleFilterChange = (newF) => {
    setFilters(newF);
  };

  // Table column headers
  const COL_HEADERS = ["Timestamp", "Category", "Event Type", "User / Email", "Detail", "Result", ""];

  return (
    <div style={{ color: C.text, fontFamily: "system-ui, sans-serif" }}>

      {/* Page header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
            stroke={C.accent} strokeWidth="1.8">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
            <line x1="16" y1="13" x2="8" y2="13"/>
            <line x1="16" y1="17" x2="8" y2="17"/>
            <polyline points="10 9 9 9 8 9"/>
          </svg>
          <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: "white",
            letterSpacing: "0.5px" }}>
            Audit Trail
          </h1>
        </div>
        <p style={{ margin: 0, color: C.muted, fontSize: 12 }}>
          User activities, system events, and configuration changes — searchable,
          filterable, and timestamped for monitoring and compliance.
        </p>
      </div>

      {/* Stats strip */}
      <StatsStrip stats={stats} />

      {/* Filters */}
      <FilterBar filters={filters} onChange={handleFilterChange}
        onExport={handleExport} stats={stats} />

      {/* Log table */}
      <div style={{
        background: C.surface, border: `1px solid ${C.border}`,
        borderRadius: 6, overflow: "hidden",
      }}>

        {/* Table header */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "168px 120px 110px 200px 1fr 80px 22px",
          padding: "8px 14px", gap: 12,
          background: "rgba(0,0,0,0.3)",
          borderBottom: `1px solid ${C.border}`,
        }}>
          {COL_HEADERS.map(h => (
            <span key={h} style={{
              color: C.muted, fontSize: 9, fontFamily: "monospace",
              letterSpacing: "1.2px", textTransform: "uppercase",
            }}>{h}</span>
          ))}
        </div>

        {/* Loading */}
        {loading && (
          <div style={{ padding: "32px 0", textAlign: "center", color: C.muted, fontSize: 12 }}>
            <div style={{ display: "inline-block", animation: "spin 1s linear infinite",
              width: 18, height: 18, border: `2px solid ${C.border}`,
              borderTop: `2px solid ${C.accent}`, borderRadius: "50%", marginBottom: 8 }} />
            <div>Loading audit events…</div>
          </div>
        )}

        {/* Error */}
        {error && !loading && (
          <div style={{ padding: "24px", color: C.red, fontSize: 12, textAlign: "center" }}>
            ⚠ Could not load audit logs: {error}
          </div>
        )}

        {/* Empty state */}
        {!loading && !error && entries.length === 0 && (
          <div style={{ padding: "40px 24px", textAlign: "center" }}>
            <div style={{ color: C.muted, fontSize: 30, marginBottom: 10 }}>📋</div>
            <div style={{ color: C.muted, fontSize: 13 }}>No audit events found for the current filters.</div>
            <div style={{ color: "rgba(255,255,255,0.15)", fontSize: 11, marginTop: 4 }}>
              Events are written as logins occur, scans run, and configuration changes are made.
            </div>
          </div>
        )}

        {/* Rows */}
        {!loading && !error && entries.map((entry, i) => (
          <EntryRow
            key={`${entry.timestamp}_${i}`}
            entry={entry}
            expanded={expanded === i}
            onToggle={() => setExpanded(expanded === i ? null : i)}
          />
        ))}
      </div>

      {/* Pagination */}
      {pages > 1 && (
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          marginTop: 12, padding: "8px 4px",
        }}>
          <span style={{ color: C.muted, fontSize: 11, fontFamily: "monospace" }}>
            {total} events · page {page} of {pages}
          </span>
          <div style={{ display: "flex", gap: 6 }}>
            <button onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              style={{ background: C.surface, border: `1px solid ${C.border}`,
                color: page === 1 ? C.muted : C.text, padding: "5px 12px",
                borderRadius: 4, fontSize: 11, cursor: page === 1 ? "default" : "pointer",
                fontFamily: "monospace" }}>
              ← Prev
            </button>

            {/* Page number pills */}
            {Array.from({ length: Math.min(7, pages) }, (_, i) => {
              const pg = page <= 4
                ? i + 1
                : page >= pages - 3
                  ? pages - 6 + i
                  : page - 3 + i;
              if (pg < 1 || pg > pages) return null;
              return (
                <button key={pg} onClick={() => setPage(pg)}
                  style={{
                    background: pg === page ? `${C.accent}18` : C.surface,
                    border: pg === page ? `1px solid ${C.accent}50` : `1px solid ${C.border}`,
                    color: pg === page ? C.accent : C.muted,
                    padding: "5px 10px", borderRadius: 4, fontSize: 11,
                    cursor: "pointer", fontFamily: "monospace",
                  }}>
                  {pg}
                </button>
              );
            })}

            <button onClick={() => setPage(p => Math.min(pages, p + 1))}
              disabled={page === pages}
              style={{ background: C.surface, border: `1px solid ${C.border}`,
                color: page === pages ? C.muted : C.text, padding: "5px 12px",
                borderRadius: 4, fontSize: 11, cursor: page === pages ? "default" : "pointer",
                fontFamily: "monospace" }}>
              Next →
            </button>
          </div>
        </div>
      )}

      {/* Spin keyframe */}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
