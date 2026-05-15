/**
 * ComplianceDashboardPage.jsx  —  GRC Posture Dashboard
 * =======================================================
 * Graphical compliance posture overview:
 *   - Overall score donut
 *   - Per-framework score bars (show/hide toggles)
 *   - Findings severity pie
 *   - Alerts-by-day bar chart (14 days)
 *   - Score trend line chart
 *   - Breach incidents + findings verdict summary
 *   - Getting Started flow guide
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

const FW_META = {
  nis2:     { label: "NIS2",      color: "#6378ff" },
  dora:     { label: "DORA",      color: "#ffd166" },
  iso27001: { label: "ISO 27001", color: "#00e5c0" },
  soc2:     { label: "SOC 2",     color: "#ff6b6b" },
  nist_csf: { label: "NIST CSF",  color: "#38bdf8" },
  pci_dss:  { label: "PCI DSS",   color: "#f97316" },
};

const SEV_COLORS = {
  critical: C.red, high: C.orange, medium: C.blue, low: C.muted,
};
const VERDICT_COLORS = {
  breach: C.red, warning: C.orange, compliant: C.accent, open: C.muted,
};

function scoreColor(s) {
  if (s >= 80) return C.accent;
  if (s >= 60) return C.orange;
  return C.red;
}

// ── SVG Chart Components ───────────────────────────────────────────────────────

function DonutChart({ score, size = 140, stroke = 18 }) {
  const r   = (size - stroke) / 2;
  const cx  = size / 2;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;
  const color = scoreColor(score);
  return (
    <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
      <circle cx={cx} cy={cx} r={r} fill="none"
        stroke="rgba(255,255,255,0.06)" strokeWidth={stroke} />
      <circle cx={cx} cy={cx} r={r} fill="none"
        stroke={color} strokeWidth={stroke}
        strokeDasharray={`${dash} ${circ}`}
        strokeLinecap="round"
        style={{ transition: "stroke-dasharray 1.2s ease" }} />
    </svg>
  );
}

function PieChart({ data, size = 130 }) {
  // data = [{label, value, color}]
  const total = data.reduce((s, d) => s + d.value, 0);
  if (!total) {
    return (
      <svg width={size} height={size}>
        <circle cx={size/2} cy={size/2} r={size/2 - 4}
          fill="rgba(255,255,255,0.04)" stroke="rgba(255,255,255,0.06)" strokeWidth={1}/>
        <text x={size/2} y={size/2 + 4} textAnchor="middle"
          fill="rgba(255,255,255,0.25)" fontSize={9} fontFamily="monospace">no data</text>
      </svg>
    );
  }
  let angle = -Math.PI / 2;
  const cx = size / 2, cy = size / 2, r = size / 2 - 6;
  const paths = data.map(d => {
    if (!d.value) return null;
    const sweep = (d.value / total) * 2 * Math.PI;
    const x1 = cx + r * Math.cos(angle);
    const y1 = cy + r * Math.sin(angle);
    angle += sweep;
    const x2 = cx + r * Math.cos(angle);
    const y2 = cy + r * Math.sin(angle);
    const large = sweep > Math.PI ? 1 : 0;
    return (
      <path key={d.label}
        d={`M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`}
        fill={d.color} opacity={0.85}
        stroke="#090b10" strokeWidth={1.5} />
    );
  });
  return <svg width={size} height={size}>{paths}</svg>;
}

function BarChart({ data, height = 100 }) {
  // data = [{date, total, critical, high, medium, low}]
  if (!data || !data.length) return (
    <div style={{ height, display: "flex", alignItems: "center",
      color: "rgba(255,255,255,0.15)", fontFamily: "monospace", fontSize: 10 }}>
      No alert data yet — run compliance enrichment to populate.
    </div>
  );
  const max = Math.max(...data.map(d => d.total), 1);
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 3, height, width: "100%" }}>
      {data.map((d, i) => {
        const barH = Math.max(2, (d.total / max) * height);
        const date  = d.date ? d.date.slice(5) : "";  // MM-DD
        const color = d.critical > 0 ? C.red : d.high > 0 ? C.orange : d.medium > 0 ? C.blue : C.muted;
        return (
          <div key={i} title={`${d.date}: ${d.total} alerts (crit:${d.critical} high:${d.high})`}
            style={{ flex: 1, display: "flex", flexDirection: "column",
              alignItems: "center", gap: 3, cursor: "default" }}>
            <div style={{ width: "100%", height: barH, background: color,
              borderRadius: "2px 2px 0 0", opacity: 0.8, minHeight: 2 }} />
            {data.length <= 10 && (
              <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 7,
                fontFamily: "monospace", whiteSpace: "nowrap" }}>{date}</div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function LineChart({ history, height = 90 }) {
  // history = [{framework, score, computed_at}]
  if (!history || !history.length) return (
    <div style={{ height, display: "flex", alignItems: "center",
      color: "rgba(255,255,255,0.15)", fontFamily: "monospace", fontSize: 10 }}>
      No score history yet — scores are saved each time you refresh framework scores.
    </div>
  );

  // Group by framework, preserving chronological order
  const byFw = {};
  history.forEach(h => {
    if (!byFw[h.framework]) byFw[h.framework] = [];
    byFw[h.framework].push(h);
  });

  const W = 400, H = height;

  // Find overall time range for x-axis positioning
  const allDates = history.map(h => new Date(h.computed_at).getTime()).filter(Boolean);
  const minT = allDates.length ? Math.min(...allDates) : 0;
  const maxT = allDates.length ? Math.max(...allDates) : 1;
  const timeRange = maxT - minT || 1;

  const elements = Object.entries(byFw).flatMap(([fw, pts]) => {
    const color = FW_META[fw]?.color || C.blue;
    if (pts.length === 1) {
      // Single snapshot — draw a dot at the correct score position
      const x = W / 2;
      const y = H - (pts[0].score / 100) * H;
      return [
        <circle key={`${fw}-dot`} cx={x} cy={y} r={4}
          fill={color} opacity={0.8}>
          <title>{FW_META[fw]?.label || fw}: {pts[0].score}%</title>
        </circle>
      ];
    }
    // Multiple snapshots — draw a line using timestamps for x-position
    const linePoints = pts.map(p => {
      const t = new Date(p.computed_at).getTime();
      const x = ((t - minT) / timeRange) * W;
      const y = H - (p.score / 100) * H;
      return `${x},${y}`;
    }).join(" ");
    // End-point dot
    const last = pts[pts.length - 1];
    const lx   = ((new Date(last.computed_at).getTime() - minT) / timeRange) * W;
    const ly   = H - (last.score / 100) * H;
    return [
      <polyline key={`${fw}-line`} points={linePoints}
        fill="none" stroke={color} strokeWidth={1.5}
        strokeLinecap="round" strokeLinejoin="round" opacity={0.8}>
        <title>{FW_META[fw]?.label || fw}</title>
      </polyline>,
      <circle key={`${fw}-end`} cx={lx} cy={ly} r={3}
        fill={color} opacity={0.9} />
    ];
  });

  return (
    <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
      {[0, 25, 50, 75, 100].map(v => (
        <line key={v} x1={0} y1={H - (v/100)*H} x2={W} y2={H - (v/100)*H}
          stroke="rgba(255,255,255,0.04)" strokeWidth={1}/>
      ))}
      {elements}
    </svg>
  );
}

// ── Framework Score Bar ───────────────────────────────────────────────────────

function FwScoreBar({ fw, visible, onToggle, onClick }) {
  const meta  = FW_META[fw.framework] || { label: fw.framework.toUpperCase(), color: C.blue };
  const color = meta.color;
  const score = Math.round(fw.score || 0);
  const sc    = scoreColor(score);

  return (
    <div style={{ opacity: visible ? 1 : 0.3, transition: "opacity 0.2s" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
        <button onClick={onToggle}
          title={visible ? "Hide" : "Show"}
          style={{ width: 12, height: 12, borderRadius: 2, border: "none", cursor: "pointer",
            background: visible ? color : "rgba(255,255,255,0.1)", flexShrink: 0, padding: 0 }} />
        <span style={{ color: visible ? color : C.muted, fontSize: 10, fontFamily: "monospace",
          fontWeight: 700, width: 80, flexShrink: 0 }}>{meta.label}</span>
        <div style={{ flex: 1, height: 6, background: "rgba(255,255,255,0.05)", borderRadius: 3,
          cursor: "pointer" }} onClick={onClick}>
          <div style={{ height: "100%", width: `${score}%`, background: visible ? color : "rgba(255,255,255,0.1)",
            borderRadius: 3, transition: "width 1s ease" }} />
        </div>
        <div style={{ display: "flex", gap: 12, flexShrink: 0 }}>
          <span style={{ color: sc, fontSize: 12, fontFamily: "monospace", fontWeight: 700, width: 32, textAlign: "right" }}>
            {score}%
          </span>
          <span title="Passing questions / Total questions in this framework's assessment"
            style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", width: 70 }}>
            {fw.passing || 0}/{fw.total_controls || 0} ctl
          </span>
          <span title="Critical gaps: failing controls + high/critical compliance alerts"
            style={{ color: (fw.critical_gaps || 0) > 0 ? C.red : C.muted,
            fontSize: 9, fontFamily: "monospace", width: 48 }}>
            {fw.critical_gaps || 0} crit
          </span>
        </div>
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

const STORAGE_KEY = "grc_hidden_frameworks";

export function ComplianceDashboardPage({ setActiveTab }) {
  const [summary, setSummary]       = useState(null);
  const [loading, setLoading]       = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError]           = useState(null);
  const [hidden, setHidden]         = useState(() => {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"); }
    catch { return []; }
  });

  const load = useCallback((force = false) => {
    if (force) setRefreshing(true); else setLoading(true);

    const fetchDashboard = () =>
      fetch(`${API_BASE}/api/comp/dashboard`, { credentials: "include" })
        .then(r => r.ok ? r.json() : Promise.reject(r.status))
        .then(d => { setSummary(d); setLoading(false); setRefreshing(false); })
        .catch(e => { setError(`Failed to load dashboard (${e})`); setLoading(false); setRefreshing(false); });

    if (force) {
      // Step 1: recompute scores on the server.
      // Step 2: re-fetch the full dashboard payload regardless of step 1's result.
      // Never write the /framework-scores response into summary — it has a different shape.
      fetch(`${API_BASE}/api/comp/framework-scores?refresh=true`, { credentials: "include" })
        .finally(() => fetchDashboard());
    } else {
      fetchDashboard();
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const toggleFw = fw => {
    setHidden(prev => {
      const next = prev.includes(fw) ? prev.filter(x => x !== fw) : [...prev, fw];
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      return next;
    });
  };

  if (loading) return (
    <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12, padding: 40 }}>
      Loading GRC posture…
    </div>
  );
  if (error) return (
    <div style={{ color: C.red, fontFamily: "monospace", fontSize: 12, padding: 40 }}>{error}</div>
  );

  const scores        = summary?.framework_scores    || [];
  const findSumm      = summary?.findings_summary    || {};
  const findVerdict   = summary?.findings_by_verdict || {};
  const activeAlerts  = summary?.active_alerts       || 0;
  const breachInc     = summary?.breach_incidents    || 0;
  const overall       = summary?.overall_score       || 0;
  const recentInc     = summary?.recent_incidents    || [];
  const alertsByDay   = summary?.alerts_by_day       || [];
  const scoreHist     = summary?.score_history       || [];
  const riskSummary   = summary?.risk_summary        || {};
  const qHub          = summary?.questionnaire_hub   || [];

  const visibleScores = scores.filter(fw => !hidden.includes(fw.framework));

  // Pie chart data — findings by severity
  const pieData = [
    { label: "Critical", value: findSumm.critical || 0, color: C.red },
    { label: "High",     value: findSumm.high     || 0, color: C.orange },
    { label: "Medium",   value: findSumm.medium   || 0, color: C.blue },
    { label: "Low",      value: findSumm.low       || 0, color: C.muted },
  ].filter(d => d.value > 0);

  const totalFindings = Object.values(findSumm).reduce((s, v) => s + v, 0);

  return (
    <div>
      {/* ── Header ────────────────────────────────────────────────────────── */}
      <div style={{ display: "flex", alignItems: "flex-start",
        justifyContent: "space-between", marginBottom: 28 }}>
        <div>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px",
            fontFamily: "monospace", textTransform: "uppercase", marginBottom: 6 }}>
            SECURITY COMPLIANCE
          </div>
          <h1 style={{ color: C.text, fontSize: 22, fontWeight: 700, margin: 0 }}>
            GRC Posture Dashboard
          </h1>
          <div style={{ color: C.muted, fontSize: 11, marginTop: 4, fontFamily: "monospace" }}>
            Live posture derived from questionnaire assessments, alerts &amp; incidents
          </div>
        </div>
        <button onClick={() => load(true)} disabled={refreshing}
          style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
            color: C.muted, padding: "7px 16px", borderRadius: 4, fontFamily: "monospace",
            fontSize: 10, cursor: "pointer", opacity: refreshing ? 0.6 : 1 }}>
          {refreshing ? "Refreshing…" : "↻ Refresh Scores"}
        </button>
      </div>

      {/* ── Row 1: Overall donut + Framework bars ─────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: 16, marginBottom: 16 }}>

        {/* Overall donut */}
        <div style={{ ...CARD, display: "flex", flexDirection: "column",
          alignItems: "center", justifyContent: "center", gap: 12 }}>
          <div style={{ position: "relative", width: 140, height: 140 }}>
            <DonutChart score={overall} />
            <div style={{ position: "absolute", inset: 0, display: "flex",
              flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
              <span style={{ color: scoreColor(overall), fontSize: 32,
                fontFamily: "monospace", fontWeight: 800, lineHeight: 1 }}>
                {Math.round(overall)}
              </span>
              <span style={{ color: scoreColor(overall), fontSize: 13,
                fontFamily: "monospace" }}>%</span>
            </div>
          </div>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
            fontFamily: "monospace", textTransform: "uppercase", textAlign: "center" }}>
            Overall Posture
          </div>
          <div style={{ display: "flex", gap: 14, flexWrap: "wrap", justifyContent: "center" }}>
            {[
              { label: "Alerts 7d", val: activeAlerts, color: activeAlerts > 50 ? C.red : C.orange },
              { label: "Incidents", val: breachInc,    color: breachInc > 0 ? C.red : C.muted },
            ].map(({ label, val, color }) => (
              <div key={label} style={{ textAlign: "center" }}>
                <div style={{ color, fontSize: 18, fontFamily: "monospace", fontWeight: 700 }}>{val}</div>
                <div style={{ color: C.muted, fontSize: 8, fontFamily: "monospace" }}>{label}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Framework bars + show/hide */}
        <div style={CARD}>
          <div style={{ display: "flex", justifyContent: "space-between",
            alignItems: "center", marginBottom: 16 }}>
            <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
              fontFamily: "monospace", textTransform: "uppercase" }}>
              Framework Posture Scores
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button onClick={() => { setHidden([]); localStorage.removeItem(STORAGE_KEY); }}
                style={{ background: "none", border: "none", color: C.accent,
                  fontFamily: "monospace", fontSize: 9, cursor: "pointer", padding: 0 }}>
                Show All
              </button>
              <button onClick={() => {
                const all = scores.map(s => s.framework);
                setHidden(all); localStorage.setItem(STORAGE_KEY, JSON.stringify(all));
              }}
                style={{ background: "none", border: "none", color: C.muted,
                  fontFamily: "monospace", fontSize: 9, cursor: "pointer", padding: 0 }}>
                Hide All
              </button>
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {scores.map(fw => (
              <FwScoreBar key={fw.framework}
                fw={fw}
                visible={!hidden.includes(fw.framework)}
                onToggle={() => toggleFw(fw.framework)}
                onClick={() => setActiveTab && setActiveTab("comp-assessment")}
              />
            ))}
          </div>
          {scores.length === 0 && (
            <div style={{ color: "rgba(255,255,255,0.15)", fontSize: 11, fontFamily: "monospace" }}>
              No scores yet. Click ↻ Refresh Scores to compute.
            </div>
          )}
        </div>
      </div>

      {/* ── Row 2: Findings pie + Verdicts + Alerts bar ───────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "200px 1fr 1fr", gap: 16, marginBottom: 16 }}>

        {/* Findings pie */}
        <div style={{ ...CARD, display: "flex", flexDirection: "column",
          alignItems: "center", gap: 12 }}>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
            fontFamily: "monospace", textTransform: "uppercase", alignSelf: "flex-start" }}>
            Findings by Severity
          </div>
          <PieChart data={pieData} size={110} />
          <div style={{ display: "flex", flexDirection: "column", gap: 6, alignSelf: "stretch" }}>
            {[
              { label: "Critical", key: "critical", color: C.red },
              { label: "High",     key: "high",     color: C.orange },
              { label: "Medium",   key: "medium",   color: C.blue },
              { label: "Low",      key: "low",      color: C.muted },
            ].map(({ label, key, color }) => (
              <div key={key} style={{ display: "flex", justifyContent: "space-between",
                alignItems: "center" }}>
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <div style={{ width: 8, height: 8, borderRadius: 2, background: color }} />
                  <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>{label}</span>
                </div>
                <span style={{ color, fontSize: 11, fontFamily: "monospace",
                  fontWeight: 700 }}>{findSumm[key] || 0}</span>
              </div>
            ))}
            <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 6, marginTop: 2,
              display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>Total</span>
              <span style={{ color: C.text, fontSize: 11, fontFamily: "monospace",
                fontWeight: 700 }}>{totalFindings}</span>
            </div>
          </div>
        </div>

        {/* Verdict summary */}
        <div style={CARD}>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
            fontFamily: "monospace", textTransform: "uppercase", marginBottom: 16 }}>
            Findings by Verdict
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {[
              { key: "breach",    label: "Breach",    color: C.red },
              { key: "warning",   label: "Warning",   color: C.orange },
              { key: "compliant", label: "Compliant", color: C.accent },
              { key: "open",      label: "Unscored",  color: C.muted },
            ].map(({ key, label, color }) => {
              const cnt = findVerdict[key] || 0;
              const tot = Object.values(findVerdict).reduce((s, v) => s + v, 0) || 1;
              return (
                <div key={key}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <div style={{ width: 8, height: 8, borderRadius: "50%", background: color }} />
                      <span style={{ color, fontSize: 10, fontFamily: "monospace",
                        fontWeight: 700 }}>{label}</span>
                    </div>
                    <span style={{ color, fontSize: 12, fontFamily: "monospace",
                      fontWeight: 700 }}>{cnt}</span>
                  </div>
                  <div style={{ height: 4, background: "rgba(255,255,255,0.04)", borderRadius: 2 }}>
                    <div style={{ height: "100%", borderRadius: 2,
                      width: `${(cnt / tot) * 100}%`, background: color,
                      transition: "width 1s ease" }} />
                  </div>
                </div>
              );
            })}
          </div>
          <div style={{ marginTop: 16 }}>
            <button onClick={() => setActiveTab && setActiveTab("comp-findings")}
              style={{ background: "none", border: "none", color: C.orange,
                fontFamily: "monospace", fontSize: 9, cursor: "pointer", padding: 0,
                fontWeight: 700, letterSpacing: "0.5px" }}>
              VIEW ALL FINDINGS →
            </button>
          </div>
        </div>

        {/* Alerts-by-day bar chart */}
        <div style={CARD}>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
            fontFamily: "monospace", textTransform: "uppercase", marginBottom: 16 }}>
            Compliance Alerts — Last 14 Days
          </div>
          <BarChart data={alertsByDay} height={100} />
          {alertsByDay.length > 0 && (
            <div style={{ display: "flex", gap: 12, marginTop: 12, flexWrap: "wrap" }}>
              {[
                { label: "Critical", color: C.red },
                { label: "High",     color: C.orange },
                { label: "Medium",   color: C.blue },
                { label: "Low",      color: C.muted },
              ].map(({ label, color }) => (
                <div key={label} style={{ display: "flex", gap: 4, alignItems: "center" }}>
                  <div style={{ width: 8, height: 8, borderRadius: 2, background: color }} />
                  <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>{label}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Row 3: Score trend line chart ─────────────────────────────────── */}
      {scoreHist.length > 0 && (
        <div style={{ ...CARD, marginBottom: 16 }}>
          <div style={{ display: "flex", justifyContent: "space-between",
            alignItems: "center", marginBottom: 16 }}>
            <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
              fontFamily: "monospace", textTransform: "uppercase" }}>
              Score Trend (per framework)
            </div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              {Object.entries(FW_META).map(([fw, m]) => (
                <div key={fw} style={{ display: "flex", gap: 5, alignItems: "center" }}>
                  <div style={{ width: 20, height: 2, borderRadius: 1, background: m.color }} />
                  <span style={{ color: C.muted, fontSize: 8, fontFamily: "monospace" }}>{m.label}</span>
                </div>
              ))}
            </div>
          </div>
          {/* Y axis labels */}
          <div style={{ display: "flex", gap: 12 }}>
            <div style={{ display: "flex", flexDirection: "column", justifyContent: "space-between",
              height: 90, paddingBottom: 0 }}>
              {[100, 75, 50, 25, 0].map(v => (
                <span key={v} style={{ color: "rgba(255,255,255,0.15)", fontSize: 8,
                  fontFamily: "monospace", lineHeight: 1 }}>{v}</span>
              ))}
            </div>
            <div style={{ flex: 1 }}>
              <LineChart history={scoreHist} height={90} />
            </div>
          </div>
        </div>
      )}

      {/* ── Row 4: Recent breach incidents ────────────────────────────────── */}
      {recentInc.length > 0 && (
        <div style={{ ...CARD, marginBottom: 16 }}>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
            fontFamily: "monospace", textTransform: "uppercase", marginBottom: 16 }}>
            Compliance-Breaching Incidents ({recentInc.length})
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {recentInc.slice(0, 6).map(inc => {
              const sevColor = { critical: C.red, high: C.orange, medium: C.blue, low: C.muted }[inc.severity] || C.muted;
              return (
                <div key={inc.id} style={{ display: "flex", alignItems: "center", gap: 10,
                  padding: "8px 10px", borderRadius: 4,
                  background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.04)" }}>
                  <span style={{ color: sevColor, fontFamily: "monospace", fontSize: 9,
                    fontWeight: 700, background: `${sevColor}15`, padding: "1px 5px",
                    borderRadius: 3, textTransform: "uppercase", whiteSpace: "nowrap" }}>
                    {inc.severity}
                  </span>
                  <span style={{ color: C.orange, fontFamily: "monospace",
                    fontSize: 10, fontWeight: 700 }}>{inc.id}</span>
                  <div style={{ display: "flex", gap: 3, flexWrap: "wrap", flex: 1 }}>
                    {(inc.frameworks || []).slice(0, 3).map(fw => (
                      <span key={fw} style={{ fontSize: 8, color: FW_META[fw]?.color || C.blue,
                        background: `${FW_META[fw]?.color || C.blue}15`,
                        border: `1px solid ${FW_META[fw]?.color || C.blue}30`,
                        padding: "1px 4px", borderRadius: 2, fontFamily: "monospace",
                        fontWeight: 700 }}>{fw.toUpperCase()}</span>
                    ))}
                  </div>
                  <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                    whiteSpace: "nowrap" }}>{inc.alert_count} alerts</span>
                  <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 9,
                    fontFamily: "monospace", whiteSpace: "nowrap" }}>{inc.status}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Row 5: Risk Register + Questionnaire Completion ─────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>

        {/* Risk Register Summary */}
        <div style={CARD}>
          <div style={{ display: "flex", justifyContent: "space-between",
            alignItems: "center", marginBottom: 16 }}>
            <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
              fontFamily: "monospace", textTransform: "uppercase" }}>
              Risk Register
            </div>
            <button onClick={() => setActiveTab && setActiveTab("comp-risks")}
              style={{ background: "none", border: "none", color: C.red,
                fontFamily: "monospace", fontSize: 9, cursor: "pointer",
                fontWeight: 700, padding: 0 }}>
              VIEW HEATMAP →
            </button>
          </div>
          {riskSummary.total > 0 ? (
            <div>
              <div style={{ display: "flex", gap: 16, marginBottom: 16, flexWrap: "wrap" }}>
                {[
                  { label: "Total",    val: riskSummary.total,    color: C.text },
                  { label: "Critical", val: riskSummary.critical,  color: C.red },
                  { label: "High",     val: riskSummary.high,      color: C.orange },
                  { label: "Medium",   val: riskSummary.medium,    color: C.blue },
                  { label: "Low",      val: riskSummary.low,       color: C.muted },
                ].map(({ label, val, color }) => (
                  <div key={label} style={{ textAlign: "center" }}>
                    <div style={{ color, fontSize: 22, fontFamily: "monospace",
                      fontWeight: 800 }}>{val || 0}</div>
                    <div style={{ color: C.muted, fontSize: 8,
                      fontFamily: "monospace" }}>{label}</div>
                  </div>
                ))}
              </div>
              {/* Severity bar */}
              <div style={{ height: 6, display: "flex", borderRadius: 3, overflow: "hidden",
                background: "rgba(255,255,255,0.04)" }}>
                {[
                  { key: "critical", color: C.red },
                  { key: "high",     color: C.orange },
                  { key: "medium",   color: C.blue },
                  { key: "low",      color: C.muted },
                ].map(({ key, color }) => {
                  const pct = riskSummary.total
                    ? ((riskSummary[key] || 0) / riskSummary.total) * 100 : 0;
                  return pct > 0
                    ? <div key={key} style={{ width: `${pct}%`, background: color }} />
                    : null;
                })}
              </div>
            </div>
          ) : (
            <div style={{ color: "rgba(255,255,255,0.15)", fontSize: 10,
              fontFamily: "monospace" }}>
              No risks in register. Use Auto Populate on the Risk Heatmap page.
            </div>
          )}
        </div>

        {/* Questionnaire Completion */}
        <div style={CARD}>
          <div style={{ display: "flex", justifyContent: "space-between",
            alignItems: "center", marginBottom: 16 }}>
            <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
              fontFamily: "monospace", textTransform: "uppercase" }}>
              Questionnaire Completion
            </div>
            <button onClick={() => setActiveTab && setActiveTab("comp-assessment")}
              style={{ background: "none", border: "none", color: C.purple,
                fontFamily: "monospace", fontSize: 9, cursor: "pointer",
                fontWeight: 700, padding: 0 }}>
              OPEN ASSESSMENT →
            </button>
          </div>
          {qHub.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {qHub.map(fw => {
                const meta  = FW_META[fw.framework] || { label: fw.framework.toUpperCase(), color: C.blue };
                const pct   = fw.pct || 0;
                return (
                  <div key={fw.framework}>
                    <div style={{ display: "flex", justifyContent: "space-between",
                      marginBottom: 3 }}>
                      <span style={{ color: meta.color, fontSize: 9,
                        fontFamily: "monospace", fontWeight: 700 }}>{meta.label}</span>
                      <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>
                        {fw.answered}/{fw.total} · {pct}%
                      </span>
                    </div>
                    <div style={{ height: 4, background: "rgba(255,255,255,0.05)",
                      borderRadius: 2 }}>
                      <div style={{ height: "100%", width: `${pct}%`,
                        background: pct >= 80 ? C.accent : pct >= 40 ? C.orange : C.red,
                        borderRadius: 2, transition: "width 1s ease" }} />
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ color: "rgba(255,255,255,0.15)", fontSize: 10,
              fontFamily: "monospace" }}>
              No questionnaire data. Complete assessments to populate.
            </div>
          )}
        </div>
      </div>

      {/* ── Getting Started Flow ──────────────────────────────────────────── */}
      <div style={CARD}>
        <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
          fontFamily: "monospace", textTransform: "uppercase", marginBottom: 16 }}>
          Getting Started — GRC Setup Flow
        </div>
        <div style={{ display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(190px, 1fr))", gap: 12 }}>
          {[
            { step: "1", label: "Upload Policy Docs",    tab: "comp-policy",
              desc: "Upload your organisation's operational and business policy documents for RAG indexing.",
              color: C.blue },
            { step: "2", label: "Run Enrichment",        tab: null,
              desc: "Enrichment runs automatically and tags alerts with MITRE → framework controls. Framework reference docs are managed in System Settings → Security Compliance.",
              color: C.muted },
            { step: "3", label: "Complete Assessments",  tab: "comp-assessment",
              desc: "Answer questionnaire for each framework — NO = automatic gap finding.",
              color: C.purple },
            { step: "4", label: "Generate Findings",     tab: "comp-findings",
              desc: "Auto-generate findings from enriched alerts with BREACH / WARNING verdicts.",
              color: C.orange },
            { step: "5", label: "Populate Risk Register", tab: "comp-risks",
              desc: "Auto-populate heatmap from breach findings, set risk appetite per category.",
              color: C.red },
            { step: "6", label: "Generate Report",       tab: "comp-reports",
              desc: "Export compliance report with scores, gaps and remediation roadmap.",
              color: C.accent },
          ].map(({ step, label, tab, desc, color }) => (
            <div key={step}
              onClick={() => tab && setActiveTab && setActiveTab(tab)}
              style={{ padding: "14px 16px", borderRadius: 6,
                background: `${color}06`, border: `1px solid ${color}20`,
                cursor: tab ? "pointer" : "default",
                transition: "background 0.15s" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <span style={{ width: 22, height: 22, borderRadius: "50%",
                  background: `${color}25`, border: `1px solid ${color}50`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 9, fontFamily: "monospace", fontWeight: 700,
                  color, flexShrink: 0 }}>{step}</span>
                <span style={{ color, fontSize: 10, fontFamily: "monospace",
                  fontWeight: 700, letterSpacing: "0.3px" }}>{label}</span>
              </div>
              <div style={{ color: C.muted, fontSize: 10, lineHeight: 1.5 }}>{desc}</div>
              {tab && (
                <div style={{ color, fontSize: 9, fontFamily: "monospace",
                  fontWeight: 700, marginTop: 8 }}>GO →</div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
