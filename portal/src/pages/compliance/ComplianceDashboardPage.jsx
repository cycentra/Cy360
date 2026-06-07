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

import { useState, useEffect, useCallback, useRef } from "react";
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
  nis2:      { label: "NIS2",      color: "#6378ff" },
  dora:      { label: "DORA",      color: "#ffd166" },
  iso27001:  { label: "ISO 27001", color: "#00e5c0" },
  soc2:      { label: "SOC 2",     color: "#ff6b6b" },
  nist_csf:  { label: "NIST CSF",  color: "#38bdf8" },
  pci_dss:   { label: "PCI DSS",   color: "#f97316" },
  gdpr:      { label: "GDPR",      color: "#8b5cf6" },
  eu_ai_act: { label: "EU AI Act", color: "#06b6d4" },
};

// Shared localStorage key — other compliance pages read this to inherit the global filter
export const CY_FW_FILTER_KEY = "cy_fw_filter";
const ALL_FRAMEWORKS = Object.keys(FW_META);

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

function LineChart({ history, height = 90, enabledFws }) {
  // history = [{framework, score, computed_at}]
  const filtered = enabledFws
    ? (history || []).filter(h => enabledFws.includes(h.framework))
    : (history || []);
  if (!filtered.length) return (
    <div style={{ height, display: "flex", alignItems: "center",
      color: "rgba(255,255,255,0.15)", fontFamily: "monospace", fontSize: 10 }}>
      No score history yet — scores are saved each time you refresh framework scores.
    </div>
  );

  // Group by framework, preserving chronological order
  const byFw = {};
  filtered.forEach(h => {
    if (!byFw[h.framework]) byFw[h.framework] = [];
    byFw[h.framework].push(h);
  });

  const W = 400, H = height;
  const fwKeys = Object.keys(byFw);

  // Apply a small y-offset so frameworks at the same score level don't stack invisibly
  const scoreGroups = {};
  fwKeys.forEach(fw => {
    const s = Math.round((byFw[fw][byFw[fw].length - 1]?.score) || 0);
    if (!scoreGroups[s]) scoreGroups[s] = [];
    scoreGroups[s].push(fw);
  });
  const yOffset = {};
  Object.values(scoreGroups).forEach(group => {
    const mid = (group.length - 1) / 2;
    group.forEach((fw, i) => { yOffset[fw] = (i - mid) * 2.5; });
  });

  const lines = fwKeys.map(fw => {
    const pts      = byFw[fw];
    const color    = FW_META[fw]?.color || C.blue;
    const off      = yOffset[fw] || 0;
    const series   = pts.length === 1 ? [pts[0], pts[0]] : pts;
    const n        = series.length;
    const points   = series.map((p, i) => {
      const x = n > 1 ? (i / (n - 1)) * W : W / 2;
      const y = H - (p.score / 100) * H + off;
      return `${x},${y}`;
    }).join(" ");
    const lastScore = series[series.length - 1].score;
    const lastY     = H - (lastScore / 100) * H + off;
    const isSingle  = pts.length === 1;
    return (
      <g key={fw}>
        <polyline points={points}
          fill="none" stroke={color}
          strokeWidth={isSingle ? 1.5 : 2}
          strokeDasharray={isSingle ? "5 3" : undefined}
          strokeLinecap="round" strokeLinejoin="round"
          opacity={isSingle ? 0.65 : 0.9}>
          <title>{FW_META[fw]?.label || fw.toUpperCase()}: {Math.round(lastScore)}%{isSingle ? " — single snapshot (dashed)" : ""}</title>
        </polyline>
        <circle cx={W} cy={lastY} r={isSingle ? 2.5 : 3.5} fill={color} opacity={0.95} />
      </g>
    );
  });

  const hasSingle = fwKeys.some(fw => byFw[fw].length === 1);

  return (
    <div>
      <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
        {[0, 25, 50, 75, 100].map(v => (
          <line key={v} x1={0} y1={H - (v/100)*H} x2={W} y2={H - (v/100)*H}
            stroke="rgba(255,255,255,0.04)" strokeWidth={1}/>
        ))}
        {lines}
      </svg>
      {hasSingle && (
        <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 8,
          fontFamily: "monospace", marginTop: 4 }}>
          Dashed = 1 snapshot · Solid = trend · Frameworks at the same score are offset ±2px for visibility · Click ↻ Refresh Scores after each assessment to grow trend history
        </div>
      )}
    </div>
  );
}

// ── Framework Score Bar ───────────────────────────────────────────────────────

function FwScoreBar({ fw, onClick }) {
  const meta    = FW_META[fw.framework] || { label: fw.framework.toUpperCase(), color: C.blue };
  const color   = meta.color;
  const score   = Math.round(fw.score || 0);
  const sc      = scoreColor(score);
  const qAns    = fw.q_answered     ?? fw.passing ?? 0;
  const qTotal  = fw.total_controls || 0;
  const penalty = fw.alert_penalty  ?? 0;

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
      <div style={{ width: 10, height: 10, borderRadius: 2, flexShrink: 0,
        background: color, opacity: 0.85 }} />
      <span style={{ color, fontSize: 10, fontFamily: "monospace",
        fontWeight: 700, width: 80, flexShrink: 0 }}>{meta.label}</span>
      <div style={{ flex: 1, height: 6, background: "rgba(255,255,255,0.05)", borderRadius: 3,
        cursor: "pointer" }} onClick={onClick}>
        <div style={{ height: "100%", width: `${score}%`, background: color,
          borderRadius: 3, transition: "width 1s ease" }} />
      </div>
      <div style={{ display: "flex", gap: 12, flexShrink: 0 }}>
        <span style={{ color: sc, fontSize: 12, fontFamily: "monospace",
          fontWeight: 700, width: 32, textAlign: "right" }}>
          {score}%
        </span>
        <span title={`${qAns} questionnaire questions answered out of ${qTotal} total. Open Assessment to answer questions and raise this score.`}
          style={{ color: qAns > 0 ? C.muted : "rgba(255,255,255,0.25)", fontSize: 9,
          fontFamily: "monospace", width: 60 }}>
          {qAns}/{qTotal} ans
        </span>
        <span title={`Alert penalty: score is reduced by ${penalty} points due to compliance-relevant alerts in the last 30 days (cap: −40pt).`}
          style={{ color: penalty > 0 ? C.orange : C.muted,
          fontSize: 9, fontFamily: "monospace", width: 52 }}>
          {penalty > 0 ? `−${penalty}pt` : "no pen"}
        </span>
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

function _loadEnabled() {
  try {
    const stored = JSON.parse(localStorage.getItem(CY_FW_FILTER_KEY));
    if (Array.isArray(stored) && stored.length) return stored;
  } catch { /* ignore */ }
  return ALL_FRAMEWORKS.slice();
}

export function ComplianceDashboardPage({ setActiveTab }) {
  const [summary, setSummary]       = useState(null);
  const [loading, setLoading]       = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError]           = useState(null);
  const [enabled, setEnabled]       = useState(_loadEnabled);

  // Ref keeps the current framework list accessible inside stable callbacks without
  // adding `enabled` as a dependency (which would cause double-fetches on toggle).
  const enabledRef = useRef(enabled);

  const saveEnabled = next => {
    enabledRef.current = next;   // update ref before triggering fetch
    setEnabled(next);
    localStorage.setItem(CY_FW_FILTER_KEY, JSON.stringify(next));
    window.dispatchEvent(new StorageEvent("storage", {
      key: CY_FW_FILTER_KEY, newValue: JSON.stringify(next),
    }));
    load(false, true);  // silent re-fetch scoped to new framework selection
  };

  const toggleFw = fw =>
    saveEnabled(enabled.includes(fw) ? enabled.filter(x => x !== fw) : [...enabled, fw]);

  // `silent = true` skips the loading spinner so the current data stays visible while
  // we refetch with a new framework filter (triggered by chip toggles).
  const load = useCallback((force = false, silent = false) => {
    if (force) setRefreshing(true); else if (!silent) setLoading(true);

    const fwParam = enabledRef.current.join(",");
    const fetchDashboard = () =>
      fetch(`${API_BASE}/api/comp/dashboard?frameworks=${fwParam}`, { credentials: "include" })
        .then(r => r.ok ? r.json() : Promise.reject(r.status))
        .then(d => { setSummary(d); setLoading(false); setRefreshing(false); })
        .catch(e => {
          if (!silent) setError(`Failed to load dashboard (${e})`);
          setLoading(false); setRefreshing(false);
        });

    if (force) {
      fetch(`${API_BASE}/api/comp/framework-scores?refresh=true`, { credentials: "include" })
        .finally(() => fetchDashboard());
    } else {
      fetchDashboard();
    }
  }, []); // stable — reads frameworks via ref, not closure

  useEffect(() => { load(); }, [load]);

  if (loading) return (
    <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12, padding: 40 }}>
      Loading GRC posture…
    </div>
  );
  if (error) return (
    <div style={{ color: C.red, fontFamily: "monospace", fontSize: 12, padding: 40 }}>{error}</div>
  );

  const allScores     = summary?.framework_scores    || [];
  const findSumm      = summary?.findings_summary    || {};
  const findVerdict   = summary?.findings_by_verdict || {};
  const activeAlerts  = summary?.active_alerts       || 0;
  const breachInc     = summary?.breach_incidents    || 0;
  const overall       = summary?.overall_score       || 0;
  const recentInc     = summary?.recent_incidents    || [];
  const alertsByDay   = summary?.alerts_by_day       || [];
  const allScoreHist  = summary?.score_history       || [];
  const riskSummary   = summary?.risk_summary        || {};
  const allQHub       = summary?.questionnaire_hub   || [];

  // Apply global framework filter
  const scores    = allScores.filter(fw => enabled.includes(fw.framework));
  const scoreHist = allScoreHist.filter(h => enabled.includes(h.framework));
  const qHub      = allQHub.filter(fw => enabled.includes(fw.framework));

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

        {/* Framework bars + chip selector */}
        <div style={CARD}>
          <div style={{ display: "flex", justifyContent: "space-between",
            alignItems: "center", marginBottom: 12 }}>
            <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
              fontFamily: "monospace", textTransform: "uppercase" }}>
              Framework Posture Scores
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button onClick={() => saveEnabled(ALL_FRAMEWORKS.slice())}
                style={{ background: "none", border: "none", color: C.accent,
                  fontFamily: "monospace", fontSize: 9, cursor: "pointer", padding: 0 }}>
                All
              </button>
              <button onClick={() => saveEnabled([])}
                style={{ background: "none", border: "none", color: C.muted,
                  fontFamily: "monospace", fontSize: 9, cursor: "pointer", padding: 0 }}>
                None
              </button>
            </div>
          </div>

          {/* Framework chip selector — controls global filter for all widgets & pages */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 16,
            paddingBottom: 12, borderBottom: `1px solid ${C.border}` }}>
            {ALL_FRAMEWORKS.map(fw => {
              const meta = FW_META[fw];
              const on   = enabled.includes(fw);
              return (
                <button key={fw} onClick={() => toggleFw(fw)}
                  title={on ? `Hide ${meta.label} from all views` : `Show ${meta.label} in all views`}
                  style={{
                    padding: "3px 10px", borderRadius: 12, fontFamily: "monospace",
                    fontSize: 9, fontWeight: 700, cursor: "pointer", letterSpacing: "0.3px",
                    transition: "all 0.15s",
                    background: on ? `${meta.color}22` : "rgba(255,255,255,0.03)",
                    border: `1px solid ${on ? meta.color : "rgba(255,255,255,0.1)"}`,
                    color: on ? meta.color : "rgba(255,255,255,0.2)",
                  }}>
                  {meta.label}
                </button>
              );
            })}
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {scores.map(fw => (
              <FwScoreBar key={fw.framework}
                fw={fw}
                onClick={() => setActiveTab && setActiveTab("comp-assessment")}
              />
            ))}
          </div>
          {scores.length === 0 && (
            <div style={{ color: "rgba(255,255,255,0.15)", fontSize: 11, fontFamily: "monospace" }}>
              {allScores.length === 0
                ? "No scores yet. Click ↻ Refresh Scores to compute."
                : "No frameworks selected. Use the chips above to show frameworks."}
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
      {allScoreHist.length > 0 && (
        <div style={{ ...CARD, marginBottom: 16 }}>
          <div style={{ display: "flex", justifyContent: "space-between",
            alignItems: "center", marginBottom: 16 }}>
            <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
              fontFamily: "monospace", textTransform: "uppercase" }}>
              Score Trend (per framework)
            </div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              {enabled.map(fw => {
                const m = FW_META[fw];
                if (!m) return null;
                return (
                  <div key={fw} style={{ display: "flex", gap: 5, alignItems: "center" }}>
                    <div style={{ width: 20, height: 2, borderRadius: 1, background: m.color }} />
                    <span style={{ color: C.muted, fontSize: 8, fontFamily: "monospace" }}>{m.label}</span>
                  </div>
                );
              })}
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
              <LineChart history={allScoreHist} height={90} enabledFws={enabled} />
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
