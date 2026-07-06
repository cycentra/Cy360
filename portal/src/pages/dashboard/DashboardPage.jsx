/**
 * src/pages/dashboard/DashboardPage.jsx
 * External Attack Posture — full redesign with balanced widget grid,
 * chart visualizations, and integrated SIEM operational widgets.
 */

import { useState, useEffect } from "react";
import { RISK_CONFIG } from '../../core/constants.js';
import { getModuleUrl } from '../../core/constants.js';
import {
  getEmailSecData, getWebSecStats, getInfraStats,
  getSupplyChainRisk, getBrandData, getSSLData,
  getOsintData, getSocialEngData, formatDate,
} from '../../core/adapter.js';
import { PLATFORM_MODULES } from '../../registry/platformModules.js';

// ─────────────────────────────────────────────────────────────────────────────
// Shared visual primitives
// ─────────────────────────────────────────────────────────────────────────────

function AnimCounter({ value, duration = 1200 }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let start = 0;
    const step  = Math.max(1, Math.ceil(value / (duration / 16)));
    const timer = setInterval(() => {
      start += step;
      if (start >= value) { setDisplay(value); clearInterval(timer); }
      else setDisplay(start);
    }, 16);
    return () => clearInterval(timer);
  }, [value, duration]);
  return <>{display}</>;
}

function Badge({ risk }) {
  const cfg = RISK_CONFIG[risk] || RISK_CONFIG.low;
  return (
    <span style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40`,
      fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px", fontFamily: "monospace",
      padding: "2px 8px", borderRadius: "2px", whiteSpace: "nowrap" }}>
      {cfg.label}
    </span>
  );
}

/** Horizontal stacked bar — pass segments=[{value, color, label}] */
function MiniStackedBar({ segments, height = 7, style = {} }) {
  const total = segments.reduce((a, b) => a + (b.value || 0), 0) || 1;
  return (
    <div style={{ height, background: "rgba(255,255,255,0.05)", borderRadius: 3,
      overflow: "hidden", display: "flex", ...style }}>
      {segments.filter(s => s.value > 0).map((s, i) => (
        <div key={i} title={`${s.label}: ${s.value}`}
          style={{ width: `${(s.value / total) * 100}%`, height: "100%",
            background: s.color, transition: "width 0.8s ease" }} />
      ))}
    </div>
  );
}

/** Single labeled bar row with value on right */
function BarRow({ label, value, max, color, labelWidth = 110 }) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
      <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 11,
        fontFamily: "monospace", width: labelWidth, flexShrink: 0,
        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{label}</span>
      <div style={{ flex: 1, height: 6, background: "rgba(255,255,255,0.05)",
        borderRadius: 2, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color,
          borderRadius: 2, transition: "width 0.8s ease", minWidth: value > 0 ? 3 : 0 }} />
      </div>
      <span style={{ color, fontSize: 11, fontFamily: "monospace",
        fontWeight: 700, width: 26, textAlign: "right", flexShrink: 0 }}>{value}</span>
    </div>
  );
}

/** Section divider — thin line with centered label */
function SectionDivider({ label }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10, marginTop: 4 }}>
      <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.06)" }} />
      <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace",
        letterSpacing: "2px", textTransform: "uppercase", flexShrink: 0 }}>{label}</span>
      <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.06)" }} />
    </div>
  );
}

/** Widget shell — consistent card styling */
function ASMWidget({ title, children, accent = "#00e5a0", onViewAll, badge, minHeight }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.07)",
      borderTop: `2px solid ${accent}`, borderRadius: 5, padding: "16px 20px",
      display: "flex", flexDirection: "column", minHeight: minHeight || "auto" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, letterSpacing: "1.5px",
          textTransform: "uppercase", fontFamily: "monospace" }}>{title}</div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {badge != null && (
            <span style={{ background: `${accent}18`, color: accent, fontSize: 10,
              fontFamily: "monospace", padding: "2px 8px", borderRadius: 2, fontWeight: 700 }}>{badge}</span>
          )}
          {onViewAll && (
            <button onClick={onViewAll}
              style={{ background: "none", border: "none", color: accent, fontSize: 10,
                fontFamily: "monospace", cursor: "pointer", opacity: 0.7 }}>
              View All ↗
            </button>
          )}
        </div>
      </div>
      <div style={{ flex: 1 }}>{children}</div>
    </div>
  );
}

function statKV(label, val, color) {
  return (
    <div key={label} style={{ display: "flex", justifyContent: "space-between",
      padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
      <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 12 }}>{label}</span>
      <span style={{ color, fontFamily: "monospace", fontSize: 13, fontWeight: 700 }}>{val}</span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ASM Posture Banner
// ─────────────────────────────────────────────────────────────────────────────

function ASMPostureWidget({ score, grade, scanType, domain, lastScan, onViewScan }) {
  const gradeColor = { "A+": "#00e5a0", A: "#00e5a0", B: "#4d9eff",
    C: "#f5c518", D: "#ff8c00", F: "#ff3b3b" }[grade] || "#00e5a0";
  const scanTypeColor = { deep: "#b06eff", standard: "#00e5a0", passive: "#4d9eff" };
  const stColor = scanTypeColor[scanType] || "#00e5a0";
  const pct = Math.min(100, Math.max(0, score ?? 0));

  return (
    <div style={{ background: `${gradeColor}09`, border: `1px solid ${gradeColor}30`,
      borderTop: `2px solid ${gradeColor}`, borderRadius: 6, padding: "14px 22px",
      marginBottom: 14, display: "flex", alignItems: "center", gap: 22 }}>
      <div style={{ textAlign: "center", flexShrink: 0, minWidth: 72 }}>
        <div style={{ color: gradeColor, fontSize: 42, fontWeight: 800,
          fontFamily: "'Space Mono',monospace", lineHeight: 1 }}>
          {score != null ? score : "—"}
        </div>
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 9,
          fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "1px", marginTop: 3 }}>
          / 100
        </div>
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 7 }}>
          <span style={{ color: "rgba(255,255,255,0.75)", fontSize: 13,
            fontWeight: 700, fontFamily: "monospace" }}>Overall ASM Security Posture</span>
          <span style={{ background: `${gradeColor}18`, color: gradeColor,
            border: `1px solid ${gradeColor}40`, borderRadius: 3, padding: "1px 7px",
            fontSize: 10, fontFamily: "monospace", fontWeight: 700, letterSpacing: "0.5px" }}>
            {grade || "—"}
          </span>
        </div>
        <div style={{ background: "rgba(255,255,255,0.06)", borderRadius: 3, height: 7,
          marginBottom: 8, overflow: "hidden" }}>
          <div style={{ height: "100%", width: `${pct}%`, background: gradeColor,
            borderRadius: 3, transition: "width 0.8s ease" }} />
        </div>
        <div style={{ color: "rgba(255,255,255,0.32)", fontSize: 10,
          fontFamily: "monospace", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
          {domain || ""}{domain && lastScan ? " · " : ""}
          {lastScan ? `Last scan: ${lastScan}` : ""}
          {!domain && !lastScan ? "External attack surface · ASM score" : ""}
        </div>
        {(scanType || (score != null && score < 60)) && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginTop: 7 }}>
            {scanType && (
              <span style={{ background: `${stColor}15`, color: stColor,
                border: `1px solid ${stColor}40`, borderRadius: 3, padding: "1px 7px",
                fontSize: 9, fontFamily: "monospace", fontWeight: 700 }}>
                {scanType.toUpperCase()}
              </span>
            )}
            {score != null && score < 60 && (
              <span style={{ background: "rgba(255,59,59,0.1)", border: "1px solid rgba(255,59,59,0.35)",
                color: "#ff3b3b", borderRadius: 3, padding: "1px 7px", fontSize: 9,
                fontFamily: "monospace", fontWeight: 700 }}>⚠ BELOW THRESHOLD</span>
            )}
          </div>
        )}
      </div>
      {onViewScan && (
        <button onClick={onViewScan} style={{ background: `${gradeColor}10`,
          border: `1px solid ${gradeColor}35`, color: gradeColor, borderRadius: 4,
          padding: "8px 14px", fontSize: 10, fontFamily: "monospace", fontWeight: 700,
          cursor: "pointer", whiteSpace: "nowrap", flexShrink: 0, letterSpacing: "0.5px" }}>
          Full Scan ↗
        </button>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Stat cards strip
// ─────────────────────────────────────────────────────────────────────────────

function StatCard({ label, value, accent, sub }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
      borderTop: `2px solid ${accent}`, padding: "16px 18px", borderRadius: 4,
      flex: 1, minWidth: 110 }}>
      <div style={{ color: accent, fontSize: 28, fontWeight: 800,
        fontFamily: "'Space Mono',monospace", lineHeight: 1 }}>
        <AnimCounter value={value} />
      </div>
      <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10,
        letterSpacing: "1.5px", marginTop: 5, textTransform: "uppercase" }}>{label}</div>
      {sub && <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 10, marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Risk Donut
// ─────────────────────────────────────────────────────────────────────────────

function RiskDonut({ assets, onSevClick }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  assets.forEach(a => (a.vulnerabilities || []).forEach(v => {
    const sev = v.severity?.toLowerCase();
    if (counts[sev] !== undefined) counts[sev]++;
  }));
  const total      = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  const colors     = ["#ff3b3b", "#ff8c00", "#f5c518", "#00e5a0"];
  const keys       = ["critical", "high", "medium", "low"];
  const totalVulns = Object.values(counts).reduce((a, b) => a + b, 0);
  let cumulative   = 0;
  const segments   = keys.map((k, i) => {
    const pct = counts[k] / total;
    const s   = cumulative * 360;
    const e   = (cumulative + pct) * 360;
    cumulative += pct;
    const r = 58, cx = 76, cy = 76;
    const toR = deg => (deg - 90) * Math.PI / 180;
    const x1 = cx + r * Math.cos(toR(s)); const y1 = cy + r * Math.sin(toR(s));
    const x2 = cx + r * Math.cos(toR(e)); const y2 = cy + r * Math.sin(toR(e));
    const d  = pct === 0 ? "" : `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${pct > 0.5 ? 1 : 0} 1 ${x2} ${y2} Z`;
    return { d, color: colors[i], key: k, count: counts[k] };
  });

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
      <svg width="152" height="152" style={{ flexShrink: 0, cursor: onSevClick ? "pointer" : "default" }}
        onClick={onSevClick}>
        <circle cx="76" cy="76" r="58" fill="rgba(255,255,255,0.03)"
          stroke="rgba(255,255,255,0.05)" strokeWidth="1" />
        {segments.map(s => s.d && <path key={s.key} d={s.d} fill={s.color} opacity="0.87" />)}
        <circle cx="76" cy="76" r="36" fill="#0d1117" />
        <text x="76" y="72" textAnchor="middle" fill="white" fontSize="20"
          fontWeight="800" fontFamily="'Space Mono',monospace">{totalVulns}</text>
        <text x="76" y="88" textAnchor="middle" fill="rgba(255,255,255,0.35)"
          fontSize="8" fontFamily="monospace">FINDINGS</text>
      </svg>
      <div style={{ flex: 1 }}>
        {keys.map((k, i) => (
          <BarRow key={k} label={k.charAt(0).toUpperCase() + k.slice(1)}
            value={counts[k]} max={totalVulns || 1} color={colors[i]} labelWidth={58} />
        ))}
        <div style={{ marginTop: 10 }}>
          <MiniStackedBar segments={keys.map((k, i) => ({ value: counts[k], color: colors[i], label: k }))} height={8} />
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Cert timeline
// ─────────────────────────────────────────────────────────────────────────────

function CertTimeline({ assets }) {
  const withCerts = assets.filter(a => a.cert_days != null).slice(0, 5);
  if (!withCerts.length) return null;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
      {withCerts.map(a => {
        const days  = a.cert_days;
        const color = days < 0 ? "#ff3b3b" : days < 30 ? "#ff8c00" : days < 90 ? "#f5c518" : "#00e5a0";
        const pct   = Math.min(100, Math.max(0, (days / 365) * 100));
        return (
          <div key={a.id}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
              <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 10, fontFamily: "monospace",
                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 150 }}>{a.host}</span>
              <span style={{ color, fontSize: 10, fontFamily: "monospace", fontWeight: 700,
                flexShrink: 0 }}>{days < 0 ? "EXPIRED" : `${days}d`}</span>
            </div>
            <div style={{ height: 3, background: "rgba(255,255,255,0.07)", borderRadius: 2 }}>
              <div style={{ height: "100%", width: `${pct}%`, background: color,
                borderRadius: 2, boxShadow: `0 0 4px ${color}60` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Email security row
// ─────────────────────────────────────────────────────────────────────────────

function ESecRow({ label, value, pass }) {
  const color = pass === null ? "rgba(255,255,255,0.35)" : pass ? "#00e5a0" : "#ff3b3b";
  const icon  = pass === null ? "—" : pass ? "✓" : "✗";
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
      padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
      <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>{label}</span>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <span style={{ color: "rgba(255,255,255,0.28)", fontSize: 10, maxWidth: 160,
          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value || "—"}</span>
        <span style={{ color, fontWeight: 700, fontSize: 12, flexShrink: 0 }}>{icon}</span>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Incident State (SIEM live widget)
// ─────────────────────────────────────────────────────────────────────────────

const _STATE_DEFS = [
  { key: "open",           label: "Open",           color: "#ff3b3b" },
  { key: "investigating",  label: "Investigating",  color: "#ff8c00" },
  { key: "in_review",      label: "In Review",      color: "#f5c518" },
  { key: "held",           label: "Held",           color: "#b36bff" },
  { key: "resolved",       label: "Resolved",       color: "#00e5a0" },
  { key: "false_positive", label: "False +ve",      color: "#888888" },
  { key: "closed",         label: "Closed",         color: "#444444" },
];

function IncidentStateWidget({ onViewAll }) {
  const [counts, setCounts]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);

  const fetchStats = async () => {
    try {
      const r = await fetch("/api/siem/stats", { credentials: "include" });
      if (!r.ok) { setOffline(true); setLoading(false); return; }
      const d = await r.json();
      setCounts(d.status_counts || {});
      setOffline(false);
    } catch { setOffline(true); }
    setLoading(false);
  };

  useEffect(() => {
    fetchStats();
    const t = setInterval(fetchStats, 60_000);
    return () => clearInterval(t);
  }, []);

  const total  = counts ? Object.values(counts).reduce((a, b) => a + b, 0) : 0;
  const maxVal = counts ? Math.max(...Object.values(counts), 1) : 1;

  return (
    <div style={{ background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.07)",
      borderTop: "2px solid #4d9eff", borderRadius: 5, padding: "16px 20px",
      display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10,
          letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace" }}>
          Incident State
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {!loading && !offline && (
            <span style={{ background: "rgba(77,158,255,0.12)", color: "#4d9eff", fontSize: 10,
              fontFamily: "monospace", padding: "2px 8px", borderRadius: 2, fontWeight: 700 }}>
              {total} TOTAL
            </span>
          )}
          {onViewAll && (
            <button onClick={onViewAll}
              style={{ background: "none", border: "none", color: "#4d9eff",
                fontSize: 10, fontFamily: "monospace", cursor: "pointer", opacity: 0.7 }}>
              View ↗
            </button>
          )}
        </div>
      </div>

      {loading && <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12,
        fontFamily: "monospace", padding: "10px 0" }}>Loading…</div>}
      {!loading && offline && <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12,
        fontFamily: "monospace", padding: "10px 0" }}>CySIEM engine offline</div>}
      {!loading && !offline && counts && (
        <>
          <div style={{ display: "flex", flexDirection: "column", gap: 6, flex: 1 }}>
            {_STATE_DEFS.map(({ key, label, color }) => {
              const val = counts[key] || 0;
              const pct = total > 0 ? (val / maxVal) * 100 : 0;
              return (
                <div key={key} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <div style={{ width: 80, color: "rgba(255,255,255,0.45)", fontSize: 10,
                    fontFamily: "monospace", flexShrink: 0 }}>{label}</div>
                  <div style={{ flex: 1, height: 10, background: "rgba(255,255,255,0.05)",
                    borderRadius: 2, overflow: "hidden" }}>
                    <div style={{ width: `${pct}%`, height: "100%", background: color,
                      borderRadius: 2, transition: "width 0.6s ease", minWidth: val > 0 ? 4 : 0 }} />
                  </div>
                  <div style={{ width: 24, color: val > 0 ? color : "rgba(255,255,255,0.2)",
                    fontSize: 11, fontFamily: "monospace", fontWeight: 700,
                    textAlign: "right", flexShrink: 0 }}>{val}</div>
                </div>
              );
            })}
          </div>
          {/* Mini stacked summary bar */}
          <div style={{ marginTop: 10 }}>
            <MiniStackedBar
              segments={_STATE_DEFS.map(d => ({ value: counts[d.key] || 0, color: d.color, label: d.label }))}
              height={6} />
          </div>
        </>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// High Confidence Incidents (SIEM)
// ─────────────────────────────────────────────────────────────────────────────

function HighConfidenceWidget({ onViewAll }) {
  const [rows, setRows]       = useState([]);
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const r = await fetch(
          "/api/siem/incidents?limit=200&status=active&sort_by=confidence_score&sort_dir=desc",
          { credentials: "include" }
        );
        if (!r.ok) { if (!cancelled) { setOffline(true); setLoading(false); } return; }
        const d = await r.json();
        if (!cancelled) {
          const highConf = (d.incidents || [])
            .filter(i => i.confidence_score != null && i.confidence_score >= 0.85)
            .sort((a, b) => b.confidence_score - a.confidence_score)
            .slice(0, 5);
          setRows(highConf);
          setOffline(false);
          setLoading(false);
        }
      } catch { if (!cancelled) { setOffline(true); setLoading(false); } }
    };
    load();
    const t = setInterval(load, 120_000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  const sevColor = s => ({ critical: "#ff3b3b", high: "#ff8c00", medium: "#f5c518", low: "#00e5a0" }[s] || "#888");

  return (
    <div style={{ background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.07)",
      borderTop: "2px solid #00e5a0", borderRadius: 5, padding: "16px 20px",
      display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10,
          letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace" }}>
          High Confidence Incidents
          <span style={{ background: "rgba(0,229,160,0.1)", color: "#00e5a0", fontSize: 9,
            fontFamily: "monospace", padding: "1px 6px", borderRadius: 2, fontWeight: 700,
            marginLeft: 8 }}>≥85%</span>
        </div>
        {onViewAll && !loading && !offline && rows.length > 0 && (
          <button onClick={onViewAll}
            style={{ background: "none", border: "none", color: "#00e5a0",
              fontSize: 10, fontFamily: "monospace", cursor: "pointer", opacity: 0.7 }}>
            View All ↗
          </button>
        )}
      </div>

      {loading && <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12,
        fontFamily: "monospace", padding: "10px 0" }}>Loading…</div>}
      {!loading && offline && <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12,
        fontFamily: "monospace", padding: "10px 0" }}>CySIEM engine offline</div>}
      {!loading && !offline && rows.length === 0 && (
        <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12,
          fontFamily: "monospace", padding: "10px 0" }}>
          No high-confidence incidents — AI analysis still running or no active incidents.
        </div>
      )}
      {!loading && !offline && rows.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 7, flex: 1 }}>
          {rows.map(inc => {
            const pct = Math.round(inc.confidence_score * 100);
            const sc  = sevColor(inc.severity);
            const h1  = (inc.hypotheses || [])[0];
            const barW = pct;
            return (
              <div key={inc.id} onClick={() => onViewAll?.()}
                style={{ padding: "9px 11px", background: "rgba(0,229,160,0.03)",
                  borderRadius: 3, border: "1px solid rgba(0,229,160,0.1)",
                  borderLeft: `3px solid ${sc}`, cursor: onViewAll ? "pointer" : "default" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                  <span style={{ color: "white", fontSize: 11, fontWeight: 600,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }}>
                    {h1 ? h1.label : `Incident ${inc.id.slice(0, 8)}`}
                  </span>
                  <span style={{ color: sc, fontSize: 10, fontFamily: "monospace",
                    fontWeight: 700, flexShrink: 0, marginLeft: 8 }}>
                    {(inc.severity || "").toUpperCase()}
                  </span>
                </div>
                {/* Confidence bar */}
                <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                  <div style={{ flex: 1, height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2, overflow: "hidden" }}>
                    <div style={{ width: `${barW}%`, height: "100%", background: "#00e5a0",
                      borderRadius: 2, transition: "width 0.6s ease" }} />
                  </div>
                  <span style={{ color: "#00e5a0", fontSize: 10, fontFamily: "monospace",
                    fontWeight: 700, flexShrink: 0 }}>{pct}%</span>
                </div>
                <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace", marginTop: 3 }}>
                  {inc.id.slice(0, 12)} · {inc.alert_count} alerts
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SOAR Activity
// ─────────────────────────────────────────────────────────────────────────────

function SoarActivityWidget() {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const r = await fetch("/api/siem/soar/status", { credentials: "include" });
        if (!r.ok) { if (!cancelled) setLoading(false); return; }
        const d = await r.json();
        if (!cancelled) { setData(d); setLoading(false); }
      } catch { if (!cancelled) setLoading(false); }
    };
    load();
    const t = setInterval(load, 120_000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  const dotColor = data?.running ? "#00e5a0" : data?.installed ? "#f5c518" : "rgba(255,255,255,0.2)";
  const dotTitle = data?.running ? "CySOAR running"
    : data?.installed ? "CySOAR installed, not running" : "CySOAR not installed";

  const kpis = [
    { label: "Auto-Dispatched", value: data?.auto_dispatched_24h ?? 0, color: "#00e5a0" },
    { label: "Pending Approval", value: data?.pending_approval ?? 0,  color: "#f5c518" },
    { label: "Needs Review",     value: data?.needs_review ?? 0,      color: "#ff6b6b" },
  ];

  return (
    <div style={{ background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.07)",
      borderTop: "2px solid #b36bff", borderRadius: 5, padding: "16px 20px",
      display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10,
          letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace" }}>
          SOAR Activity
          <span title={dotTitle} style={{ display: "inline-block", width: 7, height: 7,
            borderRadius: "50%", background: dotColor, marginLeft: 8, verticalAlign: "middle" }} />
        </div>
        <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace" }}>Last 24h</span>
      </div>

      {loading ? (
        <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace",
          padding: "10px 0" }}>Loading…</div>
      ) : !data ? (
        <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace",
          padding: "10px 0" }}>CySOAR status unavailable</div>
      ) : (
        <>
          <div style={{ display: "flex", gap: 10, flex: 1 }}>
            {kpis.map(({ label, value, color }) => (
              <div key={label} style={{ flex: 1, textAlign: "center",
                background: `${color}08`, border: `1px solid ${color}25`,
                borderRadius: 4, padding: "12px 6px" }}>
                <div style={{ color, fontSize: 26, fontFamily: "monospace",
                  fontWeight: 800, lineHeight: 1 }}>{value}</div>
                <div style={{ color: "rgba(255,255,255,0.32)", fontSize: 9,
                  fontFamily: "monospace", marginTop: 5, textTransform: "uppercase",
                  letterSpacing: "0.5px", lineHeight: 1.3 }}>{label}</div>
              </div>
            ))}
          </div>
          {/* Proportion bar */}
          <div style={{ marginTop: 10 }}>
            <MiniStackedBar segments={kpis.map(k => ({ value: k.value, color: k.color, label: k.label }))} height={5} />
          </div>
        </>
      )}
      {!data?.running && !loading && (
        <div style={{ marginTop: 10, color: "rgba(255,255,255,0.22)", fontSize: 10,
          fontFamily: "monospace", lineHeight: 1.5 }}>
          {data?.installed
            ? "CySOAR installed but not running — start from Extensions"
            : "Install CySOAR from Extensions to enable automated response"}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────

export function DashboardPage({ assets, data, stats, installedModules, setActiveTab, setSelectedAsset, setShowImport }) {
  const emailSec        = getEmailSecData(assets);
  const webSec          = getWebSecStats(assets);
  const infra           = getInfraStats(assets);
  const supply          = getSupplyChainRisk(assets);
  const brand           = getBrandData(assets);
  const sslData         = getSSLData(assets);
  const osint           = getOsintData(assets);
  const social          = getSocialEngData(assets);
  const installedAddons = Object.entries(installedModules).filter(([id]) => PLATFORM_MODULES[id]?.tier === "addon");
  const scanType        = data?.meta?.scan_type;
  const scanTypeColor   = { deep: "#b06eff", standard: "#00e5a0", passive: "#4d9eff" };
  const primaryAsset    = assets.find(a => a.tags?.includes("primary"));
  const newSubCount     = data?.subdomain_summary?.new ?? assets.filter(a => a.tags?.includes("new")).length;

  const critHighVulns = assets.flatMap(a =>
    (a.vulnerabilities || []).filter(v => v.severity === "Critical" || v.severity === "High")
      .map(v => ({ ...v, asset: a.host, assetId: a.id, assetObj: a }))
  ).sort((a, b) => (a.severity === "Critical" ? 0 : 1) - (b.severity === "Critical" ? 0 : 1));

  const webVulns = assets.flatMap(a =>
    (a.vulnerabilities || []).filter(v => {
      const m = (v.module || "").toLowerCase();
      return m === "web" || m === "crypto" || m === "web_analysis" || m === "vuln_scanner" || m === "nuclei" ||
        v.source === "port_banner" || v.source === "exposed_path" || v.source === "js_secret";
    })
  );

  // Web vuln severity breakdown for chart
  const webVulnCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  webVulns.forEach(v => { const s = v.severity?.toLowerCase(); if (webVulnCounts[s] !== undefined) webVulnCounts[s]++; });

  // Attack surface counts for bar visualization
  const asmCounts = [
    { label: "Primary Domains", count: assets.filter(a => a.tags?.includes("primary")).length, color: "#00e5a0" },
    { label: "Subdomains",      count: assets.filter(a => a.type === "Subdomain").length,          color: "rgba(0,229,160,0.55)" },
    { label: "New Subdomains",  count: newSubCount,                                                 color: "#4d9eff" },
    { label: "IP Addresses",    count: assets.filter(a => a.tags?.includes("ip")).length,           color: "#4d9eff" },
    { label: "Typosquats",      count: assets.filter(a => a.type?.includes("Typosquat")).length,    color: "#ff8c00" },
    { label: "Critical Risk",   count: assets.filter(a => a.risk === "critical").length,            color: "#ff3b3b" },
    { label: "High Risk",       count: assets.filter(a => a.risk === "high").length,                color: "#ff8c00" },
    { label: "DNS Takeovers",   count: primaryAsset?.dns_takeovers?.length ?? 0,
      color: (primaryAsset?.dns_takeovers?.length ?? 0) > 0 ? "#ff3b3b" : "rgba(0,229,160,0.4)" },
  ];
  const asmMax = Math.max(...asmCounts.map(r => r.count), 1);

  // Supply chain risk breakdown
  const supplyBreakdown = ["critical", "high", "medium", "low"].map(k => ({
    label: k, color: { critical: "#ff3b3b", high: "#ff8c00", medium: "#f5c518", low: "#00e5a0" }[k],
    value: supply.risks?.filter(r => r.severity?.toLowerCase() === k).length ?? 0,
  }));

  // Open ports for infra visualization (top 8)
  const uniquePorts = [...new Set(assets.flatMap(a => a.ports || []))].slice(0, 8);

  return (
    <div>
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div style={{ marginBottom: 18 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: "white" }}>External Attack Posture</h1>
          {scanType && (
            <span style={{
              background: `${scanTypeColor[scanType] || "#00e5a0"}15`,
              color: scanTypeColor[scanType] || "#00e5a0",
              border: `1px solid ${scanTypeColor[scanType] || "#00e5a0"}40`,
              fontSize: 10, fontFamily: "monospace", fontWeight: 700,
              padding: "2px 8px", borderRadius: 2, letterSpacing: "1px",
            }}>{scanType.toUpperCase()} SCAN</span>
          )}
        </div>
        <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13, marginTop: 4 }}>
          {data?.meta?.domain || data?.meta?.org || "No scan loaded"} · Scan ID: {data?.meta?.scan_id || "—"}
        </p>
      </div>

      {/* ── KPI Strip ───────────────────────────────────────────────────────── */}
      <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
        <StatCard label="Assets"         value={stats.total}            accent="#00e5a0" />
        <StatCard label="Open Issues"    value={stats.open}             accent="#ff3b3b" sub="Requires remediation" />
        <StatCard label="Findings"       value={stats.totalVulns}       accent="#ff8c00" sub="All modules" />
        <StatCard label="Exposed Paths"  value={stats.exposedPaths}     accent="#f5c518" sub="Web surface" />
        <StatCard label="New Subdomains" value={newSubCount}            accent="#4d9eff" sub="Since last scan" />
        <StatCard label="Add-ons Active" value={installedAddons.length} accent="#b06eff" sub="Modules" />
      </div>

      {/* ── ASM Posture Banner ──────────────────────────────────────────────── */}
      <ASMPostureWidget
        score={data?.meta?.posture_score ?? null}
        grade={data?.meta?.posture_grade ?? null}
        scanType={scanType}
        domain={data?.meta?.domain || data?.meta?.org}
        lastScan={data?.meta?.last_scan ? new Date(data.meta.last_scan).toLocaleString() : null}
        onViewScan={() => setActiveTab("scan")}
      />

      {/* ═══════════════════════════════════════════════════════════════════════
          SECTION: LIVE THREAT PICTURE — Incident state, SOAR, high-conf
          ═══════════════════════════════════════════════════════════════════ */}
      <SectionDivider label="Live Threat Picture" />
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1.3fr", gap: 14, marginBottom: 14 }}>
        <IncidentStateWidget onViewAll={() => setActiveTab("siem-incidents")} />
        <SoarActivityWidget />
        <HighConfidenceWidget onViewAll={() => setActiveTab("siem-incidents")} />
      </div>

      {/* ═══════════════════════════════════════════════════════════════════════
          SECTION: ASM RISK — Risk breakdown, SSL, Email
          ═══════════════════════════════════════════════════════════════════ */}
      <SectionDivider label="Attack Surface Risk" />
      <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1fr 1fr", gap: 14, marginBottom: 14 }}>

        {/* Widget 1 — Overall Risk (donut + bars) */}
        <ASMWidget title="1. Overall Risk Overview" accent="#ff3b3b"
          onViewAll={() => setActiveTab("vulns")} minHeight={220}>
          <RiskDonut assets={assets} onSevClick={() => setActiveTab("vulns")} />
        </ASMWidget>

        {/* Widget 2 — SSL / Crypto Health */}
        <ASMWidget title="2. SSL / Crypto Health" accent="#f5c518"
          badge={sslData.expired > 0 ? `${sslData.expired} EXPIRED` : null} minHeight={220}>
          <div style={{ display: "flex", flexDirection: "column", gap: 7, marginBottom: 10 }}>
            {[
              { label: "Monitored",    val: sslData.total,    color: "rgba(255,255,255,0.7)" },
              { label: "Expired",      val: sslData.expired,  color: sslData.expired > 0 ? "#ff3b3b" : "#00e5a0" },
              { label: "Expiring <30d",val: sslData.critical, color: sslData.critical > 0 ? "#ff8c00" : "#00e5a0" },
              { label: "Weak TLS ≤1.0",val: sslData.weakTLS,  color: sslData.weakTLS > 0 ? "#f5c518" : "#00e5a0" },
            ].map(r => statKV(r.label, r.val, r.color))}
          </div>
          {primaryAsset?.pqc_data && (
            <div style={{ padding: "5px 0", borderTop: "1px solid rgba(255,255,255,0.06)", marginBottom: 8 }}>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace", marginBottom: 3 }}>POST-QUANTUM CRYPTO</div>
              <div style={{ color: primaryAsset.pqc_data?.supported ? "#00e5a0" : "#ff8c00", fontSize: 11, fontFamily: "monospace" }}>
                {primaryAsset.pqc_data?.supported ? "✓ PQC Ready" : "⚠ Not PQC Ready"}
                {primaryAsset.pqc_data?.algorithm && ` · ${primaryAsset.pqc_data.algorithm}`}
              </div>
            </div>
          )}
          <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace", marginBottom: 6 }}>CERT EXPIRY TIMELINE</div>
          <CertTimeline assets={assets} />
        </ASMWidget>

        {/* Widget 4 — Email Security (moved up for grouping) */}
        <ASMWidget title="3. Email Security" accent="#b06eff"
          badge={emailSec?.spoofing_risk && emailSec.spoofing_risk !== "Low" ? `${emailSec.spoofing_risk} SPOOFING` : null}
          minHeight={220}>
          {emailSec ? (
            <div style={{ display: "flex", flexDirection: "column" }}>
              <ESecRow label="SPF"     value={emailSec.spf.value}      pass={emailSec.spf.pass} />
              <ESecRow label="DKIM"    value={emailSec.dkim.value}     pass={emailSec.dkim.pass} />
              <ESecRow label="DMARC"   value={emailSec.dmarc.value}    pass={emailSec.dmarc.pass} />
              <ESecRow label="DNSSEC"  value={emailSec.dnssec?.value}  pass={emailSec.dnssec?.pass ?? null} />
              <ESecRow label="BIMI"    value={emailSec.bimi.value}     pass={emailSec.bimi.pass} />
              <ESecRow label="MTA-STS" value={emailSec.mta_sts.value}  pass={emailSec.mta_sts.pass} />
              <ESecRow label="TLS-RPT" value={emailSec.tls_rpt?.value} pass={emailSec.tls_rpt?.pass ?? null} />
              {emailSec.elite_score != null && (
                <div style={{ marginTop: 8, display: "flex", justifyContent: "space-between",
                  padding: "6px 0", borderTop: "1px solid rgba(255,255,255,0.06)" }}>
                  <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>Elite Score</span>
                  <span style={{ color: emailSec.elite_score >= 80 ? "#00e5a0" : emailSec.elite_score >= 50 ? "#f5c518" : "#ff3b3b",
                    fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>
                    {emailSec.elite_score}/100 · {emailSec.elite_status || ""}
                  </span>
                </div>
              )}
            </div>
          ) : (
            <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 12, fontFamily: "monospace", padding: "16px 0" }}>
              No email security data in scan.<br />Run a scan with the Email Security module enabled.
            </div>
          )}
        </ASMWidget>
      </div>

      {/* ═══════════════════════════════════════════════════════════════════════
          SECTION: SURFACE & WEB — Infra, Web vulns, Attack Surface map
          ═══════════════════════════════════════════════════════════════════ */}
      <SectionDivider label="Surface & Web Posture" />
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.2fr 1fr", gap: 14, marginBottom: 14 }}>

        {/* Widget 3 — Infrastructure & Cloud */}
        <ASMWidget title="4. Infrastructure & Cloud" accent="#4d9eff">
          <div style={{ display: "flex", flexDirection: "column", gap: 7, marginBottom: 12 }}>
            {[
              { label: "IPs",        val: infra.ips,   color: "#4d9eff" },
              { label: "Open Ports", val: infra.ports, color: "#ff8c00" },
              { label: "Cloud",      val: infra.cloud, color: "#00e5a0" },
              { label: "Subdomains", val: assets.filter(a => a.type === "Subdomain").length, color: "rgba(255,255,255,0.6)" },
            ].map(r => statKV(r.label, r.val, r.color))}
          </div>

          {uniquePorts.length > 0 && (
            <>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9,
                fontFamily: "monospace", marginBottom: 7 }}>EXPOSED PORTS</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                {uniquePorts.map(p => (
                  <span key={p} style={{ background: "rgba(77,158,255,0.1)", color: "#4d9eff",
                    border: "1px solid rgba(77,158,255,0.22)", padding: "2px 9px",
                    borderRadius: 3, fontSize: 10, fontFamily: "monospace" }}>:{p}</span>
                ))}
              </div>
            </>
          )}

          {/* WHOIS expiry */}
          {primaryAsset?.whois_full?.expiration_date && (() => {
            const exp      = new Date(primaryAsset.whois_full.expiration_date);
            const daysLeft = Math.round((exp - new Date()) / (1000 * 60 * 60 * 24));
            const expColor = daysLeft < 30 ? "#ff3b3b" : daysLeft < 90 ? "#ff8c00" : "#00e5a0";
            return (
              <div style={{ marginTop: 12, padding: "8px 0", borderTop: "1px solid rgba(255,255,255,0.06)" }}>
                <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace", marginBottom: 4 }}>DOMAIN EXPIRY</div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 11 }}>
                    {primaryAsset.whois_full.registrar || "Unknown registrar"}
                  </span>
                  <span style={{ color: expColor, fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>
                    {daysLeft > 0 ? `${daysLeft}d` : "EXPIRED"}
                  </span>
                </div>
                <div style={{ height: 3, background: "rgba(255,255,255,0.07)", borderRadius: 2, marginTop: 4 }}>
                  <div style={{ height: "100%", background: expColor, borderRadius: 2,
                    width: `${Math.min(100, Math.max(0, (daysLeft / 365) * 100))}%` }} />
                </div>
              </div>
            );
          })()}

          {/* DNS Takeover banner */}
          {primaryAsset?.dns_takeovers?.length > 0 && (
            <div style={{ marginTop: 10, background: "rgba(255,59,59,0.08)",
              border: "1px solid rgba(255,59,59,0.25)", borderRadius: 3, padding: "7px 10px" }}>
              <div style={{ color: "#ff3b3b", fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
                ⚠ {primaryAsset.dns_takeovers.length} DNS TAKEOVER RISK{primaryAsset.dns_takeovers.length > 1 ? "S" : ""}
              </div>
              <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 10, marginTop: 2 }}>
                Dangling DNS records — review subdomains immediately
              </div>
            </div>
          )}

          {/* IP Geo / ASN */}
          {primaryAsset?.dns_ips?.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace", marginBottom: 5 }}>IP GEO / ASN</div>
              {primaryAsset.dns_ips.slice(0, 3).map((ipObj, i) => (
                <div key={i} style={{ display: "flex", justifyContent: "space-between",
                  alignItems: "center", padding: "3px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                  <span style={{ color: "#4d9eff", fontFamily: "monospace", fontSize: 10 }}>{ipObj.ip}</span>
                  <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 10 }}>
                    {ipObj.country || "?"} · {(ipObj.org || "Unknown ASN").slice(0, 20)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </ASMWidget>

        {/* Widget 5 — Web Security */}
        <ASMWidget title="5. Web Security" accent="#ff8c00" onViewAll={() => setActiveTab("vulns")}>
          <div style={{ display: "flex", flexDirection: "column", gap: 7, marginBottom: 10 }}>
            {[
              { label: "Web Vulnerabilities", val: webVulns.length, color: webVulns.length > 0 ? "#ff8c00" : "#00e5a0" },
              { label: "Exposed Paths",        val: webSec.paths,   color: webSec.paths > 0 ? "#f5c518" : "#00e5a0" },
              { label: "JS Secrets",           val: primaryAsset?.js_secrets?.length || 0,
                color: (primaryAsset?.js_secrets?.length || 0) > 0 ? "#ff3b3b" : "#00e5a0" },
              { label: "API Endpoints",        val: primaryAsset?.api_endpoints?.length || 0, color: "rgba(255,255,255,0.6)" },
            ].map(r => statKV(r.label, r.val, r.color))}
          </div>

          {/* Severity distribution bars */}
          {webVulns.length > 0 && (
            <>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9,
                fontFamily: "monospace", marginBottom: 7 }}>SEVERITY BREAKDOWN</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 5, marginBottom: 10 }}>
                {["critical", "high", "medium", "low"].map((s, i) => (
                  <BarRow key={s}
                    label={s.charAt(0).toUpperCase() + s.slice(1)}
                    value={webVulnCounts[s]}
                    max={webVulns.length}
                    color={["#ff3b3b", "#ff8c00", "#f5c518", "#00e5a0"][i]}
                    labelWidth={60}
                  />
                ))}
              </div>
              <MiniStackedBar segments={[
                { value: webVulnCounts.critical, color: "#ff3b3b", label: "Critical" },
                { value: webVulnCounts.high,     color: "#ff8c00", label: "High" },
                { value: webVulnCounts.medium,   color: "#f5c518", label: "Medium" },
                { value: webVulnCounts.low,      color: "#00e5a0", label: "Low" },
              ]} height={6} style={{ marginBottom: 12 }} />
            </>
          )}

          {/* Top vuln list */}
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            {webVulns.slice(0, 4).map((v, i) => {
              const cfg = RISK_CONFIG[v.severity?.toLowerCase()] || RISK_CONFIG.low;
              return (
                <div key={i} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <span style={{ width: 6, height: 6, borderRadius: "50%",
                    background: cfg.color, flexShrink: 0 }} />
                  <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
                    {v.vulnerability}
                  </span>
                  {v.cvss && (
                    <span style={{ color: "rgba(255,140,0,0.55)", fontSize: 9,
                      fontFamily: "monospace", flexShrink: 0 }}>CVSS {v.cvss}</span>
                  )}
                </div>
              );
            })}
            {webVulns.length === 0 && (
              <div style={{ color: "rgba(0,229,160,0.55)", fontSize: 11, fontFamily: "monospace" }}>✓ No web vulnerabilities</div>
            )}
          </div>

          {/* Missing security headers */}
          {primaryAsset?.http_analysis?.http_headers?.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9,
                fontFamily: "monospace", marginBottom: 5 }}>MISSING SECURITY HEADERS</div>
              {primaryAsset.http_analysis.http_headers.slice(0, 4).map((h, i) => (
                <div key={i} style={{ display: "flex", gap: 6, alignItems: "center", padding: "2px 0" }}>
                  <span style={{ color: "#ff3b3b", fontSize: 10, flexShrink: 0 }}>✗</span>
                  <span style={{ color: "rgba(255,255,255,0.4)", fontSize: 10,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {h.replace(/^Header:\s*/, "").replace(/^Missing\s*/, "")}
                  </span>
                </div>
              ))}
              {primaryAsset.http_analysis.http_headers.length > 4 && (
                <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>
                  +{primaryAsset.http_analysis.http_headers.length - 4} more
                </div>
              )}
            </div>
          )}
        </ASMWidget>

        {/* Widget 6 — Attack Surface Inventory */}
        <ASMWidget title="6. Attack Surface Map" accent="#00e5a0" onViewAll={() => setActiveTab("assets")}>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {asmCounts.map(r => (
              <BarRow key={r.label} label={r.label} value={r.count}
                max={asmMax} color={r.color} labelWidth={120} />
            ))}
          </div>
          {/* Cloud bucket summary */}
          {primaryAsset?.cloud_data?.bucket_summary && (
            <div style={{ marginTop: 12, padding: "8px 0", borderTop: "1px solid rgba(255,255,255,0.06)" }}>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace", marginBottom: 5 }}>CLOUD BUCKETS</div>
              {["public", "private", "total"].map(k => primaryAsset.cloud_data.bucket_summary[k] != null && (
                <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "2px 0" }}>
                  <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 10 }}>{k.charAt(0).toUpperCase() + k.slice(1)}</span>
                  <span style={{ color: k === "public" && primaryAsset.cloud_data.bucket_summary[k] > 0 ? "#ff3b3b" : "rgba(255,255,255,0.5)",
                    fontSize: 10, fontFamily: "monospace" }}>
                    {primaryAsset.cloud_data.bucket_summary[k]}
                  </span>
                </div>
              ))}
            </div>
          )}
        </ASMWidget>
      </div>

      {/* ═══════════════════════════════════════════════════════════════════════
          SECTION: EXTERNAL RISK — Supply chain + Brand exposure
          ═══════════════════════════════════════════════════════════════════ */}
      <SectionDivider label="External Risk" />
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>

        {/* Widget 7 — Supply Chain Risk */}
        <ASMWidget title="7. Supply Chain Risk" accent="#f5c518"
          badge={supply.high > 0 ? `${supply.high} HIGH` : null}>
          {supply.count > 0 ? (
            <>
              <div style={{ display: "flex", flexDirection: "column", gap: 7, marginBottom: 12 }}>
                {statKV("Total Risks",   supply.count, "#f5c518")}
                {statKV("Critical/High", supply.high,  supply.high > 0 ? "#ff3b3b" : "#00e5a0")}
              </div>

              {/* Severity distribution stacked bar */}
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9,
                fontFamily: "monospace", marginBottom: 6 }}>SEVERITY DISTRIBUTION</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 5, marginBottom: 8 }}>
                {supplyBreakdown.map(s => (
                  <BarRow key={s.label} label={s.label.charAt(0).toUpperCase() + s.label.slice(1)}
                    value={s.value} max={supply.count || 1} color={s.color} labelWidth={60} />
                ))}
              </div>
              <MiniStackedBar segments={supplyBreakdown} height={7} style={{ marginBottom: 12 }} />

              {/* Top risky libraries */}
              {supply.risks?.length > 0 && (
                <>
                  <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9,
                    fontFamily: "monospace", marginBottom: 6 }}>TOP RISKY LIBRARIES</div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                    {supply.risks.slice(0, 4).map((r, i) => {
                      const sc = RISK_CONFIG[r.severity?.toLowerCase()] || RISK_CONFIG.low;
                      return (
                        <div key={i} style={{ background: "rgba(255,255,255,0.02)",
                          border: `1px solid ${sc.color}20`, borderLeft: `2px solid ${sc.color}`,
                          padding: "6px 8px", borderRadius: 2 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <span style={{ color: "rgba(255,255,255,0.7)", fontSize: 11,
                              fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis",
                              whiteSpace: "nowrap", maxWidth: 200 }}>
                              {r.library || r.url?.split("/").pop() || "Unknown"}
                            </span>
                            <span style={{ color: sc.color, fontSize: 9,
                              fontFamily: "monospace", fontWeight: 700, flexShrink: 0 }}>{r.severity}</span>
                          </div>
                          {r.cve_ids?.length > 0 && (
                            <div style={{ color: "rgba(245,197,24,0.5)", fontSize: 9, fontFamily: "monospace", marginTop: 1 }}>
                              {r.cve_ids.slice(0, 2).join(", ")}
                            </div>
                          )}
                        </div>
                      );
                    })}
                    {supply.risks.length > 4 && (
                      <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10,
                        fontFamily: "monospace" }}>+{supply.risks.length - 4} more</div>
                    )}
                  </div>
                </>
              )}
            </>
          ) : (
            <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 12, fontFamily: "monospace", padding: "16px 0" }}>
              No supply chain data in scan.
            </div>
          )}
        </ASMWidget>

        {/* Widget 8 — Brand & External Exposure */}
        <ASMWidget title="8. Brand & External Exposure" accent="#ff3b3b"
          badge={brand.typos > 0 ? `${brand.typos} TYPOSQUATS` : null}>
          <div style={{ display: "flex", flexDirection: "column", gap: 7, marginBottom: 12 }}>
            {statKV("Registered Typosquats", brand.typos,   brand.typos > 0 ? "#ff3b3b" : "#00e5a0")}
            {statKV("Dark Web Mentions",     brand.darkweb, brand.darkweb > 0 ? "#ff8c00" : "#00e5a0")}
            {statKV("OSINT / TI Hits",       osint.misp.length + osint.cves.length,
              (osint.misp.length + osint.cves.length) > 0 ? "#b06eff" : "#00e5a0")}
            {social && statKV("Exposed Emails", social.emails.length,
              social.emails.length > 0 ? "#ff8c00" : "#00e5a0")}
          </div>

          {/* Dark web breach history */}
          {brand.hibp?.length > 0 && (
            <div style={{ marginBottom: 10 }}>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9,
                fontFamily: "monospace", marginBottom: 6 }}>BREACH HISTORY (HaveIBeenPwned)</div>
              {brand.hibp.slice(0, 3).map((b, i) => (
                <div key={i} style={{ padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ color: "rgba(255,255,255,0.65)", fontSize: 11 }}>
                      {b.title || b.Name || "Breach"}
                    </span>
                    {(b.breach_date || b.BreachDate) && (
                      <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace" }}>
                        {(b.breach_date || b.BreachDate)?.slice(0, 4)}
                      </span>
                    )}
                  </div>
                  {(b.data_classes || b.DataClasses)?.length > 0 && (
                    <div style={{ color: "rgba(255,59,59,0.5)", fontSize: 9, fontFamily: "monospace", marginTop: 1 }}>
                      {(b.data_classes || b.DataClasses).slice(0, 3).join(", ")}
                    </div>
                  )}
                </div>
              ))}
              {brand.hibp.length > 3 && (
                <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace", marginTop: 4 }}>
                  +{brand.hibp.length - 3} more breaches
                </div>
              )}
            </div>
          )}

          {/* Social engineering exposure */}
          {social && (social.emails.length > 0 || social.linkedin.length > 0) && (
            <div style={{ marginBottom: 10 }}>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9,
                fontFamily: "monospace", marginBottom: 6 }}>SOCIAL ENGINEERING EXPOSURE</div>
              {social.emails.slice(0, 3).map((em, i) => (
                <div key={i} style={{ display: "flex", gap: 6, alignItems: "center", padding: "3px 0" }}>
                  <span style={{ color: "#ff8c00", fontSize: 10 }}>@</span>
                  <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>
                    {em.email || em}
                    {em.position && <span style={{ color: "rgba(255,255,255,0.25)", marginLeft: 4 }}>· {em.position}</span>}
                  </span>
                </div>
              ))}
              {social.emails.length > 3 && (
                <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace" }}>
                  +{social.emails.length - 3} more
                </div>
              )}
              {social.risk_assessment && (
                <div style={{ marginTop: 5, color: social.risk_assessment.level === "High" ? "#ff3b3b" :
                  social.risk_assessment.level === "Medium" ? "#ff8c00" : "#00e5a0",
                  fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
                  Social Eng Risk: {social.risk_assessment.level}
                </div>
              )}
            </div>
          )}

          {/* Typosquats list */}
          {brand.typos > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace", marginBottom: 4 }}>
                REGISTERED TYPOSQUATS
              </div>
              {assets.filter(a => a.type?.includes("Typosquat")).slice(0, 3).map(a => (
                <div key={a.id} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <span style={{ color: "#ff3b3b", fontSize: 10 }}>⚠</span>
                  <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>{a.host}</span>
                </div>
              ))}
            </div>
          )}

          {/* Shodan */}
          {osint.shodan?.length > 0 && (
            <div style={{ marginTop: 10, padding: "8px 0", borderTop: "1px solid rgba(255,255,255,0.06)" }}>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9,
                fontFamily: "monospace", marginBottom: 5 }}>SHODAN EXPOSED SERVICES</div>
              {osint.shodan.slice(0, 3).map((s, i) => (
                <div key={i} style={{ display: "flex", gap: 8, alignItems: "center", padding: "2px 0" }}>
                  {s.port && <span style={{ color: "#4d9eff", fontFamily: "monospace", fontSize: 10 }}>:{s.port}</span>}
                  <span style={{ color: "rgba(255,255,255,0.4)", fontSize: 10,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {s.product || s.data?.slice(0, 40) || "Unknown service"}
                  </span>
                </div>
              ))}
            </div>
          )}
        </ASMWidget>
      </div>

      {/* ── Add-on modules strip ────────────────────────────────────────────── */}
      {installedAddons.length > 0 && (
        <div style={{ background: "rgba(176,110,255,0.04)",
          border: "1px solid rgba(176,110,255,0.15)", borderRadius: 4,
          padding: "14px 22px", marginBottom: 14 }}>
          <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, letterSpacing: "1.5px",
            textTransform: "uppercase", fontFamily: "monospace", marginBottom: 10 }}>Add-on Modules</div>
          <div style={{ display: "flex", gap: 10 }}>
            {installedAddons.map(([id]) => {
              const def = PLATFORM_MODULES[id]; if (!def) return null;
              return (
                <button key={id}
                  onClick={() => { window.history.pushState({ from: "portal" }, "", window.location.pathname); window.location.href = getModuleUrl(id); }}
                  style={{ display: "flex", alignItems: "center", gap: 8,
                    background: "rgba(255,255,255,0.03)", border: `1px solid ${def.color}30`,
                    borderRadius: 4, padding: "10px 14px", flex: 1, cursor: "pointer", textAlign: "left" }}>
                  <span style={{ fontSize: 18 }}>{def.icon}</span>
                  <div>
                    <div style={{ color: def.color, fontSize: 12, fontWeight: 700, fontFamily: "monospace" }}>{def.name}</div>
                    <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace" }}>Click to open</div>
                  </div>
                  <span style={{ marginLeft: "auto", width: 5, height: 5,
                    borderRadius: "50%", background: "#00e5a0", animation: "pulse 2s infinite" }} />
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Critical & High Vuln table ──────────────────────────────────────── */}
      <div style={{ background: "rgba(255,255,255,0.025)",
        border: "1px solid rgba(255,255,255,0.07)", borderRadius: 4, padding: "18px 22px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
          <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10,
            letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace" }}>
            Critical & High Vulnerabilities
          </div>
          <button onClick={() => setActiveTab("vulns")}
            style={{ background: "none", border: "none", color: "#00e5a0",
              fontSize: 10, fontFamily: "monospace", cursor: "pointer" }}>
            View All ({critHighVulns.length}) ↗
          </button>
        </div>

        {assets.length === 0 ? (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, textAlign: "center", padding: "20px 0" }}>
            No scan data.{" "}
            <button onClick={() => setShowImport(true)}
              style={{ background: "none", border: "none", color: "#00e5a0", cursor: "pointer", fontSize: 13 }}>
              Import a scan
            </button>{" "}or{" "}
            <button onClick={() => setActiveTab("scan")}
              style={{ background: "none", border: "none", color: "#00e5a0", cursor: "pointer", fontSize: 13 }}>
              start a new scan
            </button>.
          </div>
        ) : critHighVulns.length === 0 ? (
          <div style={{ color: "rgba(0,229,160,0.6)", fontSize: 13, textAlign: "center",
            padding: "20px 0", fontFamily: "monospace" }}>✓ No critical or high vulnerabilities found</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            {critHighVulns.slice(0, 10).map((v, i) => {
              const cfg = RISK_CONFIG[v.severity?.toLowerCase()] || RISK_CONFIG.high;
              return (
                <div key={i} className="asset-row" onClick={() => setSelectedAsset(v.assetObj)}
                  style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 12px",
                    background: "rgba(255,255,255,0.02)", borderRadius: 3,
                    border: `1px solid ${cfg.color}12`, borderLeft: `3px solid ${cfg.color}`, cursor: "pointer" }}>
                  <Badge risk={v.severity?.toLowerCase()} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ color: "white", fontSize: 12, fontWeight: 600,
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.vulnerability}</div>
                    <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, marginTop: 1,
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.description}</div>
                  </div>
                  <div style={{ flexShrink: 0, textAlign: "right" }}>
                    <div style={{ color: cfg.color, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{v.asset}</div>
                    <div style={{ display: "flex", gap: 6, justifyContent: "flex-end", marginTop: 2 }}>
                      {v.module && <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>{v.module}</span>}
                      {v.cvss   && <span style={{ color: "rgba(255,140,0,0.6)", fontSize: 10, fontFamily: "monospace" }}>CVSS {v.cvss}</span>}
                      {v.epss != null && v.epss > 0 && (
                        <span style={{ color: "rgba(255,100,100,0.6)", fontSize: 10, fontFamily: "monospace" }}>
                          EPSS {(v.epss * 100).toFixed(1)}%
                        </span>
                      )}
                    </div>
                  </div>
                  <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 11 }}>↗</span>
                </div>
              );
            })}
            {critHighVulns.length > 10 && (
              <button onClick={() => setActiveTab("vulns")}
                style={{ background: "none", border: "none", color: "#00e5a0",
                  fontSize: 11, fontFamily: "monospace", cursor: "pointer",
                  textAlign: "left", padding: "5px 0" }}>
                + {critHighVulns.length - 10} more → View all in Vulnerability Explorer
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
