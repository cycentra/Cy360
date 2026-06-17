/**
 * InternalExposureDashboard.jsx
 * Dedicated dashboard for the Internal Exposure section.
 *
 * Visualisations:
 *   • KPI row  — total incidents, open, crit/high, high-risk entities,
 *                AI auto-closed, tickets raised
 *   • Incident State Overview   (bar chart by lifecycle state)
 *   • Severity Donut            (pie by critical/high/medium/low)
 *   • Category Histogram        (incident categories)
 *   • 30-day Incident Trend     (mini line chart from first_seen dates)
 *   • Entity Risk Histogram     (score buckets 0-100)
 *   • UEBA Anomaly Distribution (anomaly-type bar chart)
 *   • AI Disposition Widget     (auto-closed vs manual, ticket rate, %)
 *   • Kill Chain Stage Funnel   (kill-chain stage distribution)
 *   • Top Risky Entities        (leaderboard)
 */

import { useState, useEffect, useCallback } from "react";
import { siemApi, siemFetch } from "./siemApi";
import { SiemEngineStatus } from "./SiemEngineStatus";
import { RISK_CONFIG } from "../core/constants";

// ─────────────────────────────────────────────────────────────────────────────
// Detection Posture Score helpers
// ─────────────────────────────────────────────────────────────────────────────

function siemScoreColor(s) {
  if (s >= 75) return "#00e5a0";
  if (s >= 60) return "#4d9eff";
  if (s >= 45) return "#f5a623";
  if (s >= 30) return "#ff8c00";
  return "#ff3b3b";
}

function DetectionPostureWidget({ data, onViewBenchmark }) {
  if (!data) return null;
  const score = Math.round(data.score ?? 0);
  const color = siemScoreColor(score);
  const pct   = Math.min(100, Math.max(0, score));
  const label = data.label || (score >= 75 ? "STRONG" : score >= 60 ? "MODERATE" : score >= 45 ? "FAIR" : score >= 30 ? "WEAK" : "CRITICAL");
  const detail = data.detail || [
    data.critical_alerts  != null ? `${data.critical_alerts} critical alert${data.critical_alerts  !== 1 ? "s" : ""}` : null,
    data.open_incidents   != null ? `${data.open_incidents} open incident${data.open_incidents   !== 1 ? "s" : ""}` : null,
  ].filter(Boolean).join(" · ") || "Entity risk · UEBA anomalies · Kill-chain coverage";

  return (
    <div style={{
      background: `${color}09`,
      border: `1px solid ${color}30`,
      borderLeft: `4px solid ${color}`,
      borderRadius: 6,
      padding: "16px 22px",
      marginBottom: 18,
      display: "flex",
      alignItems: "center",
      gap: 22,
    }}>
      {/* Score circle */}
      <div style={{ textAlign: "center", flexShrink: 0, minWidth: 76 }}>
        <div style={{ color, fontSize: 44, fontWeight: 800, fontFamily: "'Space Mono',monospace", lineHeight: 1 }}>
          {score}
        </div>
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "1px", marginTop: 3 }}>
          / 100
        </div>
      </div>

      {/* Bar + labels */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 7 }}>
          <span style={{ color: "rgba(255,255,255,0.75)", fontSize: 13, fontWeight: 700, fontFamily: "monospace" }}>
            Internal Detection Posture
          </span>
          <span style={{
            background: `${color}18`, color, border: `1px solid ${color}40`,
            borderRadius: 3, padding: "1px 7px", fontSize: 10,
            fontFamily: "monospace", fontWeight: 700, letterSpacing: "0.5px",
          }}>
            {label}
          </span>
        </div>
        <div style={{ background: "rgba(255,255,255,0.06)", borderRadius: 3, height: 7, marginBottom: 8, overflow: "hidden" }}>
          <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: 3, transition: "width 0.8s ease" }} />
        </div>
        <div style={{ color: "rgba(255,255,255,0.32)", fontSize: 10, fontFamily: "monospace", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
          {detail}
        </div>
        {/* Signal chips — only rendered when relevant */}
        {(data.ueba_active_anomalies > 0 || data.kill_chain_deep > 0 || data.kill_chain_mid > 0 || data.active_agents === 0) && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginTop: 7 }}>
            {data.ueba_active_anomalies > 0 && (
              <span style={{ background: "rgba(251,191,36,0.1)", border: "1px solid rgba(251,191,36,0.35)", color: "#fbbf24", borderRadius: 3, padding: "1px 7px", fontSize: 9, fontFamily: "monospace", fontWeight: 700 }}>
                UEBA {data.ueba_active_anomalies} anomaly{data.ueba_active_anomalies !== 1 ? "s" : ""}
              </span>
            )}
            {data.kill_chain_deep > 0 && (
              <span style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.35)", color: "#ef4444", borderRadius: 3, padding: "1px 7px", fontSize: 9, fontFamily: "monospace", fontWeight: 700 }}>
                ⚠ {data.kill_chain_deep} deep kill-chain
              </span>
            )}
            {data.kill_chain_mid > 0 && (
              <span style={{ background: "rgba(249,115,22,0.1)", border: "1px solid rgba(249,115,22,0.35)", color: "#f97316", borderRadius: 3, padding: "1px 7px", fontSize: 9, fontFamily: "monospace", fontWeight: 700 }}>
                {data.kill_chain_mid} mid kill-chain
              </span>
            )}
            {data.active_agents === 0 && (
              <span style={{ background: "rgba(156,163,175,0.1)", border: "1px solid rgba(156,163,175,0.35)", color: "#9ca3af", borderRadius: 3, padding: "1px 7px", fontSize: 9, fontFamily: "monospace", fontWeight: 700 }}>
                ⚠ no active agents
              </span>
            )}
          </div>
        )}
      </div>

      {/* CTA */}
      {onViewBenchmark && (
        <button onClick={onViewBenchmark} style={{
          background: `${color}10`, border: `1px solid ${color}35`, color,
          borderRadius: 4, padding: "8px 14px", fontSize: 10, fontFamily: "monospace",
          fontWeight: 700, cursor: "pointer", whiteSpace: "nowrap", flexShrink: 0,
          letterSpacing: "0.5px",
        }}>
          Full Benchmark ↗
        </button>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared primitive components (self-contained, no external deps)
// ─────────────────────────────────────────────────────────────────────────────

function AnimCounter({ value = 0, duration = 1000 }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let cur = 0;
    const step  = Math.max(1, Math.ceil(value / (duration / 16)));
    const timer = setInterval(() => {
      cur += step;
      if (cur >= value) { setDisplay(value); clearInterval(timer); }
      else setDisplay(cur);
    }, 16);
    return () => clearInterval(timer);
  }, [value]);
  return <>{display}</>;
}

function KpiCard({ label, value, accent = "#00e5a0", sub, icon }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.03)",
      border: "1px solid rgba(255,255,255,0.07)",
      borderTop: `2px solid ${accent}`,
      padding: "16px 20px",
      borderRadius: 4, flex: "1 1 130px", minWidth: 120,
    }}>
      {icon && <div style={{ fontSize: 18, marginBottom: 6 }}>{icon}</div>}
      <div style={{ color: accent, fontSize: 28, fontWeight: 800, fontFamily: "'Space Mono',monospace", lineHeight: 1 }}>
        <AnimCounter value={value} />
      </div>
      <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 10, letterSpacing: "1.5px", marginTop: 5, textTransform: "uppercase" }}>
        {label}
      </div>
      {sub && <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 10, marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

function Panel({ title, accent = "#00e5a0", badge, onViewAll, children, style = {} }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.025)",
      border: "1px solid rgba(255,255,255,0.07)",
      borderTop: `2px solid ${accent}`,
      borderRadius: 5, padding: "18px 22px",
      ...style,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace" }}>
          {title}
        </span>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {badge != null && (
            <span style={{ background: `${accent}18`, color: accent, fontSize: 10, fontFamily: "monospace", padding: "2px 8px", borderRadius: 2, fontWeight: 700 }}>
              {badge}
            </span>
          )}
          {onViewAll && (
            <button onClick={onViewAll}
              style={{ background: "none", border: "none", color: accent, fontSize: 10, fontFamily: "monospace", cursor: "pointer", opacity: 0.7 }}>
              View All ↗
            </button>
          )}
        </div>
      </div>
      {children}
    </div>
  );
}

function OfflineMsg({ label = "CySIEM engine offline" }) {
  return (
    <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace", padding: "10px 0" }}>
      {label}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Widget: Incident State Overview (bar chart by lifecycle state)
// ─────────────────────────────────────────────────────────────────────────────

const STATE_DEFS = [
  { key: "open",           label: "Open",           color: "#ff3b3b" },
  { key: "investigating",  label: "Investigating",  color: "#ff8c00" },
  { key: "in_review",      label: "In Review",      color: "#f5c518" },
  { key: "held",           label: "Held",           color: "#b36bff" },
  { key: "resolved",       label: "Resolved",       color: "#00e5a0" },
  { key: "false_positive", label: "False Positive", color: "#888888" },
  { key: "closed",         label: "Closed",         color: "#444" },
];

function IncidentStatePanel({ statusCounts, total, loading, offline, onViewAll }) {
  const maxVal = statusCounts ? Math.max(...Object.values(statusCounts), 1) : 1;
  return (
    <Panel title="Incident State Overview" accent="#4d9eff"
      badge={total > 0 ? `${total} TOTAL` : null} onViewAll={onViewAll}>
      {loading  && <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>}
      {!loading && offline  && <OfflineMsg />}
      {!loading && !offline && statusCounts && (
        <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
          {STATE_DEFS.map(({ key, label, color }) => {
            const val = statusCounts[key] || 0;
            const pct = total > 0 ? (val / maxVal) * 100 : 0;
            return (
              <div key={key} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <div style={{ width: 100, color: "rgba(255,255,255,0.45)", fontSize: 11, fontFamily: "monospace", flexShrink: 0 }}>{label}</div>
                <div style={{ flex: 1, height: 12, background: "rgba(255,255,255,0.05)", borderRadius: 2, overflow: "hidden" }}>
                  <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 2, transition: "width 0.6s ease", minWidth: val > 0 ? 4 : 0 }} />
                </div>
                <div style={{ width: 28, color: val > 0 ? color : "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace", fontWeight: 700, textAlign: "right", flexShrink: 0 }}>
                  {val}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Panel>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Widget: Severity Donut
// ─────────────────────────────────────────────────────────────────────────────

function SeverityDonut({ incidents }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  incidents.forEach(inc => { const s = (inc.severity || "low").toLowerCase(); if (counts[s] != null) counts[s]++; });
  const total    = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  const colors   = ["#ff3b3b", "#ff8c00", "#f5c518", "#00e5a0"];
  const keys     = ["critical", "high", "medium", "low"];
  let cumulative = 0;

  const segments = keys.map((k, i) => {
    const pct = counts[k] / total;
    const sAngle = cumulative * 360;
    const eAngle = (cumulative + pct) * 360;
    cumulative += pct;
    const r = 55, cx = 70, cy = 70;
    const toRad = d => (d - 90) * Math.PI / 180;
    const x1 = cx + r * Math.cos(toRad(sAngle)); const y1 = cy + r * Math.sin(toRad(sAngle));
    const x2 = cx + r * Math.cos(toRad(eAngle)); const y2 = cy + r * Math.sin(toRad(eAngle));
    const d  = pct === 0 ? "" : `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${pct > 0.5 ? 1 : 0} 1 ${x2} ${y2} Z`;
    return { d, color: colors[i], key: k, count: counts[k] };
  });

  const totalIncidents = Object.values(counts).reduce((a, b) => a + b, 0);

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
      <svg width="140" height="140" style={{ flexShrink: 0 }}>
        <circle cx="70" cy="70" r="55" fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.05)" strokeWidth="1"/>
        {segments.map(s => s.d && <path key={s.key} d={s.d} fill={s.color} opacity="0.85"/>)}
        <circle cx="70" cy="70" r="34" fill="#0d1117"/>
        <text x="70" y="66" textAnchor="middle" fill="white" fontSize="20" fontWeight="800" fontFamily="'Space Mono',monospace">{totalIncidents}</text>
        <text x="70" y="83" textAnchor="middle" fill="rgba(255,255,255,0.35)" fontSize="8" fontFamily="monospace">INCIDENTS</text>
      </svg>
      <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
        {keys.map((k, i) => (
          <div key={k} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: colors[i], flexShrink: 0 }}/>
            <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, width: 64 }}>{k.charAt(0).toUpperCase() + k.slice(1)}</span>
            <span style={{ color: colors[i], fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>{counts[k]}</span>
            <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>
              ({total > 1 ? Math.round((counts[k] / totalIncidents) * 100) : 0}%)
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Widget: Category Histogram
// ─────────────────────────────────────────────────────────────────────────────

const CAT_COLOR_MAP = {
  authentication: "#ff8c00", brute_force: "#ff3b3b", malware: "#ff3b3b",
  fim: "#f5c518", web: "#4d9eff", scan: "#b36bff", vulnerability: "#ff8c00",
  system: "rgba(255,255,255,0.4)", cloud: "#4d9eff", o365: "#4d9eff",
  azure: "#4d9eff", aws: "#ff8c00", gcp: "#f5c518", github: "#b36bff",
  ueba: "#b36bff", network: "#4d9eff", lateral_movement: "#ff3b3b",
  privilege_escalation: "#ff3b3b", persistence: "#ff8c00",
};

function CategoryHistogram({ incidents }) {
  const tally = {};
  incidents.forEach(inc => {
    (inc.categories || []).forEach(c => {
      const key = c.toLowerCase().replace(/ /g, "_");
      tally[key] = (tally[key] || 0) + 1;
    });
  });
  const sorted = Object.entries(tally).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const maxVal = sorted.length ? sorted[0][1] : 1;

  if (!sorted.length) {
    return <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace" }}>No category data yet</div>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
      {sorted.map(([cat, cnt]) => {
        const color  = CAT_COLOR_MAP[cat] || "#888";
        const label  = cat.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
        const barPct = (cnt / maxVal) * 100;
        return (
          <div key={cat} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 110, color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {label}
            </div>
            <div style={{ flex: 1, height: 10, background: "rgba(255,255,255,0.05)", borderRadius: 2, overflow: "hidden" }}>
              <div style={{ width: `${barPct}%`, height: "100%", background: color, borderRadius: 2, transition: "width 0.5s ease", minWidth: cnt > 0 ? 3 : 0 }} />
            </div>
            <div style={{ width: 24, color: color, fontSize: 11, fontFamily: "monospace", fontWeight: 700, textAlign: "right", flexShrink: 0 }}>{cnt}</div>
          </div>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Widget: 30-day Incident Trend by Severity (4-line chart with spike detection)
// ─────────────────────────────────────────────────────────────────────────────

function IncidentTrendChartSeverity({ incidents }) {
  const DAYS = 30;
  const W = 380, H = 120, PAD = { t: 14, r: 12, b: 28, l: 36 };

  const SEV_COLORS = { critical: "#ff3b3b", high: "#ff8c00", medium: "#f5c518", low: "#00e5a0" };
  const SEV_WIDTHS = { critical: 2.5, high: 2.5, medium: 1.5, low: 1.5 };
  const SEV_KEYS   = ["critical", "high", "medium", "low"];

  const now = Date.now();
  const buckets = Array.from({ length: DAYS }, (_, i) => {
    const d = new Date(now - (DAYS - 1 - i) * 864e5);
    return { day: d.toISOString().slice(0, 10), critical: 0, high: 0, medium: 0, low: 0 };
  });
  const dayMap = Object.fromEntries(buckets.map((b, i) => [b.day, i]));
  incidents.forEach(inc => {
    const day = (inc.first_seen || "").slice(0, 10);
    if (dayMap[day] != null) {
      const sev = (inc.severity || "low").toLowerCase();
      if (buckets[dayMap[day]][sev] != null) buckets[dayMap[day]][sev]++;
    }
  });

  const maxCount = Math.max(...buckets.flatMap(b => SEV_KEYS.map(k => b[k])), 1);
  const xScale   = i => PAD.l + (i / (DAYS - 1)) * (W - PAD.l - PAD.r);
  const yScale   = v => PAD.t + (1 - v / maxCount) * (H - PAD.t - PAD.b);

  // Spike detection: (critical + high) >= 150% of 7-day rolling avg AND abs >= 2
  const critHighSums = buckets.map(b => b.critical + b.high);
  const spikeDays = buckets.map((b, i) => {
    if (i < 7) return false;
    const window7 = critHighSums.slice(i - 7, i);
    const avg = window7.reduce((a, c) => a + c, 0) / window7.length;
    const ch = b.critical + b.high;
    return avg > 0 && ch >= avg * 1.5 && ch >= 2;
  });

  const labelIdx = [0, Math.floor(DAYS / 2), DAYS - 1];
  const now7 = new Date(now - 7 * 864e5).toISOString().slice(0, 10);
  const recentSpike = buckets.find((b, i) => spikeDays[i] && b.day >= now7);

  const sevTotals = Object.fromEntries(SEV_KEYS.map(k => [k, buckets.reduce((s, b) => s + b[k], 0)]));
  const grandTotal = SEV_KEYS.reduce((s, k) => s + sevTotals[k], 0);
  const polyline = (sevKey) => buckets.map((b, i) => `${xScale(i)},${yScale(b[sevKey])}`).join(" ");

  return (
    <div>
      <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ overflow: "visible", display: "block" }}>
        {/* Grid lines */}
        {[0, 0.25, 0.5, 0.75, 1].map(r => {
          const y = PAD.t + (1 - r) * (H - PAD.t - PAD.b);
          return <line key={r} x1={PAD.l} x2={W - PAD.r} y1={y} y2={y} stroke="rgba(255,255,255,0.05)" strokeWidth="1"/>;
        })}
        {/* Y-axis labels */}
        {[0, maxCount].map((v, i) => {
          const y = yScale(v);
          return <text key={i} x={PAD.l - 4} y={y + 4} textAnchor="end" fill="rgba(255,255,255,0.25)" fontSize="8" fontFamily="monospace">{v}</text>;
        })}
        {/* Spike vertical lines */}
        {buckets.map((b, i) => spikeDays[i] && (
          <line key={`spike-${i}`} x1={xScale(i)} x2={xScale(i)} y1={PAD.t} y2={H - PAD.b}
            stroke="rgba(255,59,59,0.4)" strokeWidth="1" strokeDasharray="3 3"/>
        ))}
        {/* Series lines — 4 severities */}
        {SEV_KEYS.map(k => (
          <polyline key={k} points={polyline(k)} fill="none" stroke={SEV_COLORS[k]}
            strokeWidth={SEV_WIDTHS[k]} strokeLinejoin="round" strokeLinecap="round" opacity="0.9"/>
        ))}
        {/* Spike dots on critical line */}
        {buckets.map((b, i) => spikeDays[i] && b.critical > 0 && (
          <circle key={`dot-${i}`} cx={xScale(i)} cy={yScale(b.critical)} r="3" fill="#ff3b3b"/>
        ))}
        {/* X-axis date labels */}
        {labelIdx.map(i => (
          <text key={i} x={xScale(i)} y={H - 4} textAnchor="middle" fill="rgba(255,255,255,0.2)" fontSize="7" fontFamily="monospace">
            {buckets[i].day.slice(5)}
          </text>
        ))}
        {/* X-axis line */}
        <line x1={PAD.l} x2={W - PAD.r} y1={H - PAD.b} y2={H - PAD.b} stroke="rgba(255,255,255,0.07)" strokeWidth="1"/>
      </svg>
      {/* Legend */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 8, alignItems: "center" }}>
        {SEV_KEYS.map(k => (
          <span key={k} style={{ color: SEV_COLORS[k], fontSize: 9, fontFamily: "monospace" }}>
            ■ {k.charAt(0).toUpperCase() + k.slice(1)} {sevTotals[k]}
          </span>
        ))}
        <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace", marginLeft: "auto" }}>
          {grandTotal} total
        </span>
      </div>
      {/* Spike alert banner */}
      {recentSpike && (
        <div style={{
          background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.25)",
          color: "#ff3b3b", fontSize: 11, fontFamily: "monospace", padding: "8px 12px",
          borderRadius: 3, marginTop: 8,
        }}>
          ⚠ Critical/High spike detected on {recentSpike.day} — {recentSpike.critical + recentSpike.high} incidents in 24h
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Widget: Entity Risk Histogram (score buckets 0–100)
// ─────────────────────────────────────────────────────────────────────────────

function EntityRiskHistogram({ riskScores }) {
  const buckets = Array.from({ length: 10 }, (_, i) => ({
    label: `${i * 10}–${i * 10 + 9}`,
    min:   i * 10,
    count: 0,
    color: i >= 7 ? "#ff3b3b" : i >= 5 ? "#ff8c00" : i >= 2 ? "#f5c518" : "#00e5a0",
  }));
  riskScores.forEach(e => {
    const idx = Math.min(9, Math.floor((e.score || 0) / 10));
    buckets[idx].count++;
  });
  const max = Math.max(...buckets.map(b => b.count), 1);

  return (
    <div>
      <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 80, marginBottom: 4 }}>
        {buckets.map((b, i) => (
          <div key={i} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 2 }}>
            <div style={{ width: "100%", background: b.color, borderRadius: "2px 2px 0 0",
              height: `${(b.count / max) * 72}px`, minHeight: b.count > 0 ? 4 : 0,
              transition: "height 0.5s ease", opacity: 0.8 }} />
            {b.count > 0 && (
              <div style={{ color: b.color, fontSize: 8, fontFamily: "monospace", fontWeight: 700 }}>{b.count}</div>
            )}
          </div>
        ))}
      </div>
      <div style={{ display: "flex", gap: 4 }}>
        {buckets.map((b, i) => (
          <div key={i} style={{ flex: 1, color: "rgba(255,255,255,0.18)", fontSize: 7, fontFamily: "monospace", textAlign: "center" }}>
            {i * 10}
          </div>
        ))}
      </div>
      <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace", marginTop: 4, textAlign: "center" }}>
        Risk Score Distribution (0–100)
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Widget: UEBA Anomaly Distribution
// ─────────────────────────────────────────────────────────────────────────────

const ANOMALY_META = {
  privilege_escalation:    { label: "Privilege Escalation",  color: "#ff3b3b" },
  svc_account_interactive: { label: "Service Acct Interactive", color: "#ff3b3b" },
  impossible_travel:       { label: "Impossible Travel",    color: "#ff3b3b" },
  high_auth_fail_rate:     { label: "Auth Failures",        color: "#ff8c00" },
  multi_host_burst:        { label: "Multi-Host Burst",     color: "#ff8c00" },
  off_hours_login:         { label: "Off-Hours Login",      color: "#f5c518" },
  new_agent_access:        { label: "New Host Access",      color: "#4d9eff" },
};

function _resolveAnomalies(u) {
  // The list API returns active_anomalies as an integer count and anomaly_types
  // as an optional string[]. The detail API returns an anomalies[] array of objects.
  // Always return an array of objects with an anomaly_type field.
  if (Array.isArray(u.anomalies) && u.anomalies.length > 0) return u.anomalies;
  if (Array.isArray(u.ueba_anomalies) && u.ueba_anomalies.length > 0) return u.ueba_anomalies;
  // anomaly_types is string[] from the list endpoint
  if (Array.isArray(u.anomaly_types) && u.anomaly_types.length > 0)
    return u.anomaly_types.map(t => ({ anomaly_type: t }));
  // anomaly_type_counts is { type: count } from some response shapes
  if (u.anomaly_type_counts && typeof u.anomaly_type_counts === "object") {
    return Object.entries(u.anomaly_type_counts).flatMap(([t, c]) =>
      Array.from({ length: c }, () => ({ anomaly_type: t }))
    );
  }
  return [];
}

function UebaAnomalyChart({ uebaUsers, totalUebaAlerts = 0 }) {
  const tally = {};
  uebaUsers.forEach(u => {
    _resolveAnomalies(u).forEach(a => {
      const t = a.anomaly_type || a.type || "unknown";
      tally[t] = (tally[t] || 0) + 1;
    });
  });

  const sorted = Object.entries(tally).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const maxVal = sorted.length ? sorted[0][1] : 1;
  const withAnomaly = uebaUsers.filter(u => _resolveAnomalies(u).length > 0 || (u.active_anomalies > 0)).length;

  if (!sorted.length) {
    if (totalUebaAlerts > 0) {
      return (
        <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, fontFamily: "monospace", padding: "6px 0" }}>
          {totalUebaAlerts} UEBA alerts recorded — anomaly breakdown unavailable (entity detail not yet indexed)
        </div>
      );
    }
    return (
      <div style={{ color: "rgba(0,229,160,0.5)", fontSize: 12, fontFamily: "monospace", padding: "6px 0" }}>
        ✓ No active anomalies
      </div>
    );
  }

  return (
    <div>
      <div style={{ marginBottom: 10, display: "flex", gap: 12, flexWrap: "wrap" }}>
        <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace" }}>
          {withAnomaly} of {uebaUsers.length} entities with active anomalies
        </span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
        {sorted.map(([type, cnt]) => {
          const meta  = ANOMALY_META[type] || { label: type.replace(/_/g, " "), color: "#888" };
          const barPct = (cnt / maxVal) * 100;
          return (
            <div key={type} style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{ width: 138, color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {meta.label}
              </div>
              <div style={{ flex: 1, height: 10, background: "rgba(255,255,255,0.05)", borderRadius: 2, overflow: "hidden" }}>
                <div style={{ width: `${barPct}%`, height: "100%", background: meta.color, borderRadius: 2, transition: "width 0.5s ease", minWidth: cnt > 0 ? 3 : 0 }} />
              </div>
              <div style={{ width: 24, color: meta.color, fontSize: 11, fontFamily: "monospace", fontWeight: 700, textAlign: "right", flexShrink: 0 }}>{cnt}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Widget: AI Disposition (auto-closed vs manual, ticket rate)
// ─────────────────────────────────────────────────────────────────────────────

function AiDispositionWidget({ incidents }) {
  const total = incidents.length;

  // Engine auto-closes: status=closed with false_positive_reason set (fp_probability on 0–100 scale)
  const aiClosed = incidents.filter(i =>
    i.status === "closed" && i.false_positive_reason != null
  );
  const manuallyResolved = incidents.filter(i => i.status === "resolved");
  const manuallyClosed = incidents.filter(i =>
    i.status === "closed" && i.false_positive_reason == null
  );
  const falsePositiveManual = incidents.filter(i => i.status === "false_positive");
  const stillOpen = incidents.filter(i =>
    i.status === "open" || i.status === "investigating" || i.status === "in_review" || i.status === "held"
  );
  const casesOpen  = incidents.filter(i => i.case_opened_at);

  const aiCount          = aiClosed.length;
  const manResolvedCount = manuallyResolved.length;
  const manClosedCount   = manuallyClosed.length;
  const fpManualCount    = falsePositiveManual.length;
  const ticketCount      = casesOpen.length;
  const totalClosed      = aiCount + manResolvedCount + manClosedCount + fpManualCount;
  const manualTotalCount = manResolvedCount + manClosedCount + fpManualCount;
  const aiPct     = totalClosed > 0 ? Math.round((aiCount / totalClosed) * 100) : 0;
  const manualPct = totalClosed > 0 ? Math.round((manualTotalCount / totalClosed) * 100) : 0;
  const ticketPct = total > 0 ? Math.round((ticketCount / total) * 100) : 0;

  const rows = [
    { label: "AI Auto-Closed (FP)",     value: aiCount,         color: "#00e5a0", pct: aiPct,                                                                              sub: "Engine auto-closed (FP ≥ 80%)"  },
    { label: "Manually Resolved",       value: manResolvedCount, color: "#4d9eff", pct: totalClosed > 0 ? Math.round((manResolvedCount / totalClosed) * 100) : 0,         sub: "Analyst confirmed resolved" },
    { label: "Manually Closed",         value: manClosedCount,  color: "#888",    pct: totalClosed > 0 ? Math.round((manClosedCount / totalClosed) * 100) : 0,           sub: "Analyst closed"             },
    { label: "False Positive (Manual)", value: fpManualCount,   color: "#888",    pct: totalClosed > 0 ? Math.round((fpManualCount / totalClosed) * 100) : 0,            sub: "Analyst marked FP"          },
    { label: "Still Open / Active",     value: stillOpen.length, color: "#ff8c00", pct: total > 0 ? Math.round((stillOpen.length / total) * 100) : 0,                    sub: "Requires attention"         },
  ];

  return (
    <div>
      {/* Summary row */}
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 18 }}>
        <div style={{ flex: 1, minWidth: 120, background: "rgba(0,229,160,0.06)", border: "1px solid rgba(0,229,160,0.18)", borderRadius: 4, padding: "12px 14px" }}>
          <div style={{ color: "#00e5a0", fontSize: 26, fontFamily: "'Space Mono',monospace", fontWeight: 800 }}>{aiPct}%</div>
          <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, marginTop: 4 }}>Closed without<br/>manual intervention</div>
        </div>
        <div style={{ flex: 1, minWidth: 120, background: "rgba(176,110,255,0.06)", border: "1px solid rgba(176,110,255,0.18)", borderRadius: 4, padding: "12px 14px" }}>
          <div style={{ color: "#b06eff", fontSize: 26, fontFamily: "'Space Mono',monospace", fontWeight: 800 }}>{ticketCount}</div>
          <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, marginTop: 4 }}>Tickets raised where<br/>more insights needed</div>
        </div>
      </div>

      {/* Stacked bar: AI vs Manual */}
      {totalClosed > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace", marginBottom: 5 }}>CLOSURE BREAKDOWN</div>
          <div style={{ height: 14, borderRadius: 3, overflow: "hidden", display: "flex", gap: 1 }}>
            <div style={{ width: `${aiPct}%`, background: "#00e5a0", transition: "width 0.7s ease" }} title={`AI: ${aiCount}`}/>
            <div style={{ flex: 1, background: "#4d9eff", opacity: 0.6 }} title={`Manual: ${manualTotalCount}`}/>
          </div>
          <div style={{ display: "flex", gap: 12, marginTop: 4 }}>
            <span style={{ color: "#00e5a0", fontSize: 9, fontFamily: "monospace" }}>■ AI {aiPct}%</span>
            <span style={{ color: "#4d9eff", fontSize: 9, fontFamily: "monospace" }}>■ Manual {manualPct}%</span>
          </div>
        </div>
      )}

      {/* Detail rows */}
      <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
        {rows.map(({ label, value, color, pct, sub }) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>{label}</span>
                <div style={{ display: "flex", gap: 8 }}>
                  <span style={{ color, fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>{value}</span>
                  <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>({pct}%)</span>
                </div>
              </div>
              <div style={{ height: 4, background: "rgba(255,255,255,0.05)", borderRadius: 2 }}>
                <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 2, transition: "width 0.5s ease", opacity: 0.75 }} />
              </div>
              <div style={{ color: "rgba(255,255,255,0.18)", fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>{sub}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Widget: Kill Chain Stage Distribution
// ─────────────────────────────────────────────────────────────────────────────

const KC_NAMES = [
  "Recon", "Weaponize", "Delivery", "Exploit",
  "Install", "C2", "Actions",
];
const KC_COLORS = ["#4d9eff", "#b36bff", "#ff8c00", "#ff3b3b", "#ff3b3b", "#ff3b3b", "#ff3b3b"];

function KillChainFunnel({ incidents }) {
  const counts = Array(7).fill(0);
  incidents.forEach(i => {
    const stage = i.kill_chain_stage;
    if (stage != null && stage >= 0 && stage < 7) counts[stage]++;
  });
  const maxCount = Math.max(...counts, 1);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
      {KC_NAMES.map((name, i) => {
        const cnt = counts[i];
        const barPct = (cnt / maxCount) * 100;
        return (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: KC_COLORS[i], flexShrink: 0 }}/>
            <div style={{ width: 72, color: "rgba(255,255,255,0.4)", fontSize: 10, fontFamily: "monospace", flexShrink: 0 }}>
              {i + 1}. {name}
            </div>
            <div style={{ flex: 1, height: 8, background: "rgba(255,255,255,0.05)", borderRadius: 2, overflow: "hidden" }}>
              <div style={{ width: `${barPct}%`, height: "100%", background: KC_COLORS[i], borderRadius: 2, transition: "width 0.5s ease", minWidth: cnt > 0 ? 3 : 0 }} />
            </div>
            <div style={{ width: 20, color: cnt > 0 ? KC_COLORS[i] : "rgba(255,255,255,0.15)", fontSize: 11, fontFamily: "monospace", fontWeight: 700, textAlign: "right", flexShrink: 0 }}>
              {cnt}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Widget: Top Risky Entities
// ─────────────────────────────────────────────────────────────────────────────

function entityRiskLevel(score) {
  if (score >= 75) return { label: "CRITICAL", color: "#ff3b3b" };
  if (score >= 50) return { label: "HIGH",     color: "#ff8c00" };
  if (score >= 25) return { label: "MEDIUM",   color: "#f5c518" };
  return               { label: "LOW",      color: "#00e5a0" };
}

function TopRiskyEntities({ riskScores, onView }) {
  const top = riskScores.slice(0, 8);
  if (!top.length) {
    return <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace" }}>No entity risk data yet</div>;
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
      {top.map((e, i) => {
        const lvl = entityRiskLevel(e.score || 0);
        const bar = Math.round(e.score || 0);
        return (
          <div key={e.entity_id || i}
            style={{ display: "flex", alignItems: "center", gap: 10, padding: "7px 10px",
              background: "rgba(255,255,255,0.02)", borderRadius: 3,
              borderLeft: `2px solid ${lvl.color}`, cursor: onView ? "pointer" : "default" }}
            onClick={() => onView && onView(e)}
          >
            <div style={{ width: 18, color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace", textAlign: "right", flexShrink: 0 }}>{i + 1}</div>
            <div style={{ fontSize: 13 }}>{e.entity_type === "user" ? "👤" : "🖥️"}</div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ color: "rgba(255,255,255,0.75)", fontSize: 11, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {e.entity_name || e.entity_id}
              </div>
              <div style={{ height: 3, background: "rgba(255,255,255,0.06)", borderRadius: 2, marginTop: 3 }}>
                <div style={{ width: `${bar}%`, height: "100%", background: lvl.color, borderRadius: 2 }} />
              </div>
            </div>
            <div style={{ flexShrink: 0, textAlign: "right" }}>
              <div style={{ color: lvl.color, fontSize: 12, fontFamily: "monospace", fontWeight: 700 }}>{bar}</div>
              <div style={{ color: lvl.color, fontSize: 8, fontFamily: "monospace", opacity: 0.7 }}>{lvl.label}</div>
            </div>
            {e.trend === "rising"  && <span style={{ color: "#ff3b3b", fontSize: 12 }}>↑</span>}
            {e.trend === "falling" && <span style={{ color: "#00e5a0", fontSize: 12 }}>↓</span>}
            {e.trend === "stable"  && <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 12 }}>→</span>}
          </div>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Widget: Entity Type Donut (human / service / system)
// ─────────────────────────────────────────────────────────────────────────────

const ENTITY_TYPE_META = {
  human:   { label: "Human",   color: "#00e5a0", icon: "👤" },
  user:    { label: "User",    color: "#00e5a0", icon: "👤" },
  service: { label: "Service", color: "#4d9eff", icon: "⚙️"  },
  system:  { label: "System",  color: "#888",    icon: "🖥️" },
  host:    { label: "Host",    color: "#b36bff", icon: "🖥️" },
};

function EntityTypeDonut({ riskScores }) {
  const tally = {};
  riskScores.forEach(e => {
    const t = (e.entity_type || "unknown").toLowerCase();
    tally[t] = (tally[t] || 0) + 1;
  });
  const entries  = Object.entries(tally).sort((a, b) => b[1] - a[1]);
  const totalEnt = entries.reduce((s, [, c]) => s + c, 0) || 1;
  const PALETTE  = ["#00e5a0", "#4d9eff", "#b36bff", "#ff8c00", "#f5c518", "#888"];
  let cum        = 0;

  const segments = entries.map(([type, cnt], i) => {
    const pct = cnt / totalEnt;
    const sA  = cum * 360; const eA = (cum + pct) * 360; cum += pct;
    const r = 45, cx = 55, cy = 55;
    const toRad = d => (d - 90) * Math.PI / 180;
    const x1 = cx + r * Math.cos(toRad(sA)); const y1 = cy + r * Math.sin(toRad(sA));
    const x2 = cx + r * Math.cos(toRad(eA)); const y2 = cy + r * Math.sin(toRad(eA));
    const d  = pct === 0 ? "" : `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${pct > 0.5 ? 1 : 0} 1 ${x2} ${y2} Z`;
    const color = (ENTITY_TYPE_META[type] || {}).color || PALETTE[i % PALETTE.length];
    return { d, color, type, cnt };
  });

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
      <svg width="110" height="110" style={{ flexShrink: 0 }}>
        {segments.map(s => s.d && <path key={s.type} d={s.d} fill={s.color} opacity="0.85"/>)}
        <circle cx="55" cy="55" r="27" fill="#0d1117"/>
        <text x="55" y="51" textAnchor="middle" fill="white" fontSize="16" fontWeight="800" fontFamily="'Space Mono',monospace">{riskScores.length}</text>
        <text x="55" y="65" textAnchor="middle" fill="rgba(255,255,255,0.3)" fontSize="7" fontFamily="monospace">ENTITIES</text>
      </svg>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {entries.map(([type, cnt], i) => {
          const meta  = ENTITY_TYPE_META[type] || {};
          const color = meta.color || PALETTE[i % PALETTE.length];
          return (
            <div key={type} style={{ display: "flex", alignItems: "center", gap: 7 }}>
              <span style={{ fontSize: 12 }}>{meta.icon || "📦"}</span>
              <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, width: 56 }}>
                {(meta.label || type).charAt(0).toUpperCase() + (meta.label || type).slice(1)}
              </span>
              <span style={{ color, fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>{cnt}</span>
              <span style={{ color: "rgba(255,255,255,0.18)", fontSize: 9, fontFamily: "monospace" }}>
                ({Math.round((cnt / totalEnt) * 100)}%)
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────

export function InternalExposureDashboard({ setActiveTab }) {
  const [stats,        setStats]        = useState(null);
  const [incidents,    setIncidents]    = useState([]);
  const [riskScores,   setRiskScores]   = useState([]);
  const [uebaUsers,    setUebaUsers]    = useState([]);
  const [loading,      setLoading]      = useState(true);
  const [offline,      setOffline]      = useState(false);
  const [lastRefresh,  setLastRefresh]  = useState(null);
  const [postureScore, setPostureScore] = useState(null);
  const [caseMetrics,  setCaseMetrics]  = useState(null);

  const fetchAll = useCallback(async () => {
    setLoading(true);

    const [statsData, incData, riskData, uebaData, benchData] = await Promise.all([
      siemFetch(siemApi.getStats()),
      siemFetch(siemApi.getIncidents({ limit: 200 })),
      siemFetch(siemApi.getRiskScores({ limit: 100 })),
      siemFetch(siemApi.getUebaUsers({ limit: 100 })),
      fetch("/api/benchmark/score", { credentials: "include" })
        .then(r => r.ok ? r.json() : null)
        .catch(() => null),
    ]);

    if (statsData._offline || incData._offline) {
      setOffline(true);
      setLoading(false);
      return;
    }
    setOffline(false);
    if (!statsData._error) setStats(statsData);
    if (!incData._error)   setIncidents(incData.incidents || []);
    if (!riskData._error)  setRiskScores((riskData.scores || riskData.entities || riskData || []).sort((a, b) => (b.score || 0) - (a.score || 0)));
    if (!uebaData._error)  setUebaUsers(Array.isArray(uebaData) ? uebaData : (uebaData.users || []));
    if (benchData?.breakdown?.siem) setPostureScore(benchData.breakdown.siem);
    // Case metrics (best-effort — don't block dashboard if cases API is slow)
    fetch("/api/cases/metrics", { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => d && setCaseMetrics(d))
      .catch(() => {});
    setLoading(false);
    setLastRefresh(new Date());
  }, []);

  useEffect(() => {
    fetchAll();
    const t = setInterval(fetchAll, 60_000);
    return () => clearInterval(t);
  }, [fetchAll]);

  // Derived KPIs
  const statusCounts  = stats?.status_counts || {};
  const totalInc      = stats?.total_incidents || 0;
  const openInc       = stats?.open_incidents  || 0;
  const critHighInc   = incidents.filter(i => i.severity === "critical" || i.severity === "high").length;
  const highRiskEnt   = riskScores.filter(e => (e.score || 0) >= 50).length;
  // Use the stats endpoint's ai_auto_closed count (reliable — not limited by the 200-row incident sample)
  const aiAutoClose   = stats?.ai_auto_closed ?? 0;
  // Use caseMetrics.open_cases when available; fall back to incident-list count
  const casesOpen = caseMetrics?.open_cases ?? incidents.filter(i => i.case_opened_at).length;

  return (
    <div>
      {/* ── Header ── */}
      <div style={{ marginBottom: 22 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: "white", margin: 0 }}>
            Internal Attack Posture
          </h1>
          <span style={{ background: "rgba(255,59,59,0.12)", color: "#ff3b3b", border: "1px solid rgba(255,59,59,0.3)", fontSize: 10, fontFamily: "monospace", fontWeight: 700, padding: "2px 8px", borderRadius: 2, letterSpacing: "1px" }}>
            INTERNAL
          </span>
          {!loading && !offline && (
            <span style={{ display: "flex", alignItems: "center", gap: 5, color: "#00e5a0", fontSize: 10, fontFamily: "monospace" }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#00e5a0", display: "inline-block", animation: "pulse 2s infinite" }}/>
              LIVE
            </span>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 14, marginTop: 6, flexWrap: "wrap" }}>
          <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13, margin: 0 }}>
            CySIEM correlation engine · UEBA behavioral analytics · Entity risk intelligence
          </p>
          {lastRefresh && (
            <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button onClick={fetchAll}
            style={{ background: "rgba(0,229,160,0.08)", border: "1px solid rgba(0,229,160,0.2)", color: "#00e5a0", fontSize: 10, fontFamily: "monospace", padding: "3px 10px", borderRadius: 3, cursor: "pointer" }}>
            ↻ Refresh
          </button>
        </div>
      </div>

      <SiemEngineStatus />

      {offline && !loading && (
        <div style={{ background: "rgba(255,59,59,0.06)", border: "1px solid rgba(255,59,59,0.2)", borderRadius: 4, padding: "12px 18px", marginBottom: 18 }}>
          <span style={{ color: "#ff3b3b", fontSize: 11, fontFamily: "monospace" }}>
            ⚠ CySIEM engine is offline — dashboard data unavailable
          </span>
        </div>
      )}

      {/* ── KPI Row ── */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
        <KpiCard label="Total Incidents" value={totalInc}      accent="#4d9eff"  icon="📊" />
        <KpiCard label="Open / Active"   value={openInc}       accent="#ff3b3b"  icon="🔥" sub="Requires attention" />
        <KpiCard label="Critical & High" value={critHighInc}   accent="#ff8c00"  icon="⚡" sub="High-severity incidents" />
        <KpiCard label="High-Risk Entities" value={highRiskEnt} accent="#b06eff" icon="🎯" sub="Score ≥ 50" />
        <KpiCard label="AI Auto-Closed"  value={aiAutoClose}   accent="#00e5a0"  icon="🤖" sub="Engine FP auto-close" />
        <KpiCard label="Cases Open"  value={casesOpen} accent="#b06eff"  icon="🗂️" sub="Active case investigations" />
      </div>

      {/* ── Detection Posture Score ── */}
      <DetectionPostureWidget
        data={postureScore}
        onViewBenchmark={() => setActiveTab?.("benchmark")}
      />

      {/* ── CyCases Summary widget ── */}
      {caseMetrics && (() => {
        const { total_cases = 0, open_cases = 0, cases_by_severity = {}, avg_mtta_hours, asm_vs_siem = {}, cases_by_status = {} } = caseMetrics;
        const critHigh = (cases_by_severity.critical || 0) + (cases_by_severity.high || 0);
        const statusEntries = Object.entries(cases_by_status)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5);
        const STATUS_COLOR = { open: "#00e5a0", investigating: "#f5c518", in_review: "#4d9eff", resolved: "#888", closed: "#555" };
        return (
          <div style={{
            background: "rgba(77,158,255,0.04)", border: "1px solid rgba(77,158,255,0.15)",
            borderLeft: "4px solid rgba(77,158,255,0.5)",
            borderRadius: 6, padding: "14px 20px", marginBottom: 16,
            display: "flex", alignItems: "stretch", gap: 20, flexWrap: "wrap",
          }}>
            {/* Section label */}
            <div style={{ display: "flex", flexDirection: "column", justifyContent: "center", minWidth: 120 }}>
              <div style={{ color: "#4d9eff", fontSize: 10, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginBottom: 4 }}>
                🗂️ CYCASES
              </div>
              <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 9, fontFamily: "monospace" }}>
                Investigation tracking
              </div>
              <button
                onClick={() => setActiveTab?.("cases")}
                style={{ marginTop: 8, background: "rgba(77,158,255,0.1)", border: "1px solid rgba(77,158,255,0.3)",
                  color: "#4d9eff", padding: "4px 10px", borderRadius: 3,
                  fontFamily: "monospace", fontSize: 9, cursor: "pointer", fontWeight: 700 }}>
                View All →
              </button>
            </div>

            {/* KPI tiles */}
            {[
              { label: "Total Cases",     value: total_cases, color: "#4d9eff" },
              { label: "Active",          value: open_cases,  color: "#ff8c00" },
              { label: "Crit / High",     value: critHigh,    color: "#ff3b3b" },
              { label: "Avg MTTA",        value: avg_mtta_hours != null ? (avg_mtta_hours < 1 ? `${Math.round(avg_mtta_hours * 60)}m` : `${avg_mtta_hours.toFixed(1)}h`) : "—", color: "#b06eff", raw: true },
            ].map(k => (
              <div key={k.label} style={{ textAlign: "center", minWidth: 70 }}>
                <div style={{ color: k.color, fontSize: 22, fontWeight: 800, fontFamily: "monospace", lineHeight: 1 }}>
                  {k.raw ? k.value : k.value}
                </div>
                <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 8, fontFamily: "monospace", marginTop: 3 }}>
                  {k.label.toUpperCase()}
                </div>
              </div>
            ))}

            {/* Status mini-bar */}
            {statusEntries.length > 0 && (
              <div style={{ flex: 1, minWidth: 160, display: "flex", flexDirection: "column", justifyContent: "center", gap: 4 }}>
                <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 8, fontFamily: "monospace", letterSpacing: "1px", marginBottom: 2 }}>BY STATUS</div>
                {statusEntries.map(([st, cnt]) => (
                  <div key={st} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <div style={{ flex: 1, height: 4, background: "rgba(255,255,255,0.05)", borderRadius: 2, overflow: "hidden" }}>
                      <div style={{ width: `${(cnt / total_cases) * 100}%`, height: "100%",
                        background: STATUS_COLOR[st] || "#888", borderRadius: 2 }} />
                    </div>
                    <span style={{ color: STATUS_COLOR[st] || "#888", fontSize: 8, fontFamily: "monospace", minWidth: 20, textAlign: "right" }}>{cnt}</span>
                    <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 8, fontFamily: "monospace", minWidth: 64 }}>{st.toUpperCase()}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Source split + note */}
            <div style={{ display: "flex", flexDirection: "column", justifyContent: "center", gap: 6, minWidth: 140 }}>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 8, fontFamily: "monospace", letterSpacing: "1px" }}>SOURCE</div>
              <div style={{ display: "flex", gap: 12 }}>
                <div style={{ textAlign: "center" }}>
                  <div style={{ color: "#ff8c00", fontSize: 16, fontWeight: 700, fontFamily: "monospace" }}>{asm_vs_siem.asm || 0}</div>
                  <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 8, fontFamily: "monospace" }}>EXTERNAL</div>
                </div>
                <div style={{ textAlign: "center" }}>
                  <div style={{ color: "#4d9eff", fontSize: 16, fontWeight: 700, fontFamily: "monospace" }}>{asm_vs_siem.siem || 0}</div>
                  <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 8, fontFamily: "monospace" }}>INTERNAL</div>
                </div>
              </div>
              <div style={{ background: "rgba(245,197,24,0.07)", border: "1px solid rgba(245,197,24,0.2)",
                borderRadius: 3, padding: "4px 8px" }}>
                <div style={{ color: "#f5c518", fontSize: 8, fontFamily: "monospace", fontWeight: 700 }}>ℹ POSTURE NOTE</div>
                <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 8, fontFamily: "monospace", marginTop: 2, lineHeight: 1.4 }}>
                  Case severity is tracked separately from the posture score. Open critical/high cases
                  are a qualitative risk signal — reviewed by analysts alongside the posture grade.
                </div>
              </div>
            </div>
          </div>
        );
      })()}

      {/* ── Row 1: State Overview + Severity Donut + Category Histogram ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14, marginBottom: 14 }}>

        <IncidentStatePanel
          statusCounts={statusCounts}
          total={totalInc}
          loading={loading}
          offline={offline}
          onViewAll={() => setActiveTab?.("siem-incidents")}
        />

        <Panel title="Severity Distribution" accent="#ff3b3b">
          {loading  ? <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>
          : offline ? <OfflineMsg />
          : <SeverityDonut incidents={incidents} />}
        </Panel>

        <Panel title="Incident Categories" accent="#b06eff">
          {loading  ? <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>
          : offline ? <OfflineMsg />
          : <CategoryHistogram incidents={incidents} />}
        </Panel>

      </div>

      {/* ── Row 2: Trend + Risk Histogram + Entity Type Donut ── */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 14, marginBottom: 14 }}>

        <Panel title="30-Day Incident Trend by Severity" accent="#00e5a0">
          {loading  ? <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>
          : offline ? <OfflineMsg />
          : (
            <>
              <IncidentTrendChartSeverity incidents={incidents} />
              <div style={{ marginTop: 8, color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace" }}>
                Each point = incident first seen on that day
              </div>
            </>
          )}
        </Panel>

        <Panel title="Entity Risk Distribution" accent="#ff8c00">
          {loading  ? <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>
          : offline ? <OfflineMsg />
          : riskScores.length === 0 ? <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace" }}>No entity risk data</div>
          : <EntityRiskHistogram riskScores={riskScores} />}
        </Panel>

        <Panel title="Entity Type Breakdown" accent="#4d9eff">
          {loading  ? <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>
          : offline ? <OfflineMsg />
          : riskScores.length === 0 ? <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace" }}>No entity data</div>
          : <EntityTypeDonut riskScores={riskScores} />}
        </Panel>

      </div>

      {/* ── Row 3: AI Disposition + UEBA Anomalies ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>

        <Panel title="AI Disposition — Auto-Closed vs Manual"
          accent="#00e5a0"
          badge={aiAutoClose > 0 ? `${aiAutoClose} AI RESOLVED` : null}>
          {loading  ? <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>
          : offline ? <OfflineMsg />
          : <AiDispositionWidget incidents={incidents} />}
        </Panel>

        <Panel title="UEBA Anomaly Distribution"
          accent="#b06eff"
          onViewAll={() => setActiveTab?.("siem-ueba")}>
          {loading  ? <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>
          : offline ? <OfflineMsg />
          : <UebaAnomalyChart uebaUsers={uebaUsers} totalUebaAlerts={stats?.ueba_alerts || stats?.total_ueba_alerts || 0} />}
        </Panel>

      </div>

      {/* ── Row 4: Kill Chain + Top Entities ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.4fr", gap: 14, marginBottom: 14 }}>

        <Panel title="Kill Chain Stage Distribution" accent="#ff3b3b">
          {loading  ? <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>
          : offline ? <OfflineMsg />
          : <KillChainFunnel incidents={incidents} />}
        </Panel>

        <Panel title="Top Risky Entities"
          accent="#ff8c00"
          onViewAll={() => setActiveTab?.("siem-risk")}>
          {loading  ? <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>
          : offline ? <OfflineMsg />
          : <TopRiskyEntities riskScores={riskScores} onView={() => setActiveTab?.("siem-risk")} />}
        </Panel>

      </div>

      {/* ── Footer note ── */}
      <div style={{ padding: "10px 0", color: "rgba(255,255,255,0.15)", fontSize: 9, fontFamily: "monospace", textAlign: "center" }}>
        Dashboard refreshes every 60 s · Data sourced from CySIEM Correlation Engine · UEBA Baseline Engine · Entity Risk Scorer
      </div>
    </div>
  );
}
