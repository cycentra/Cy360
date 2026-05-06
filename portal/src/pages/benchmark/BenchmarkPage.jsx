/**
 * PATCH 2 of 3 — CyCentra 360 Benchmark Intelligence Engine
 * ==========================================================
 * File to create: portal/src/pages/benchmark/BenchmarkPage.jsx
 *
 * WHAT THIS PAGE SHOWS (in calculation order, top to bottom)
 * ----------------------------------------------------------
 * 1. CSPI gauge + grade + percentile callout            ← composite result first
 * 2. Industry benchmark chart                           ← where customer sits vs cohort
 * 3. Per-dimension score breakdown (6 source cards)     ← what drives the score
 * 4. Source weight configurator (toggle + slider)       ← customer control
 * 5. Industry / size selector                           ← cohort context control
 *
 * INSTALLATION
 * ------------
 * mkdir -p portal/src/pages/benchmark
 * Save this file as portal/src/pages/benchmark/BenchmarkPage.jsx
 * Then apply PATCH_3 to App.jsx and navConfig.jsx
 */

import { useState, useEffect, useCallback } from "react";

// ── Constants ─────────────────────────────────────────────────────────────────

const API = "/api/benchmark";

const C = {
  bg:       "#090b10",
  surface:  "#0d1117",
  surface2: "#111620",
  border:   "rgba(255,255,255,0.07)",
  border2:  "rgba(255,255,255,0.12)",
  text:     "rgba(255,255,255,0.85)",
  muted:    "rgba(255,255,255,0.35)",
  dim:      "rgba(255,255,255,0.18)",
  accent:   "#00e5a0",
  red:      "#ff3b3b",
  orange:   "#ff8c00",
  blue:     "#4d9eff",
  purple:   "#b06eff",
  amber:    "#f5a623",
};

const GRADE_COLOR = (g) =>
  g === "A+" || g === "A" ? "#00e5a0" :
  g === "B"               ? "#4d9eff" :
  g === "C"               ? "#f5a623" :
  g === "D"               ? "#ff8c00" :
  g === "F"               ? "#ff3b3b" : C.muted;

const SCORE_COLOR = (s) =>
  s === null || s === undefined ? C.muted :
  s >= 75 ? "#00e5a0" :
  s >= 60 ? "#4d9eff" :
  s >= 45 ? "#f5a623" :
  s >= 30 ? "#ff8c00" : "#ff3b3b";

const BAND_LABELS = ["P10", "P25", "P50 (Median)", "P75", "P90"];
const BAND_COLORS = [
  "rgba(255,59,59,0.25)",
  "rgba(255,140,0,0.20)",
  "rgba(245,166,35,0.18)",
  "rgba(77,158,255,0.18)",
  "rgba(0,229,160,0.22)",
];

// ── Small helpers ─────────────────────────────────────────────────────────────

function ScorePill({ score, size = 13 }) {
  const color = SCORE_COLOR(score);
  return (
    <span style={{
      background: `${color}18`, color, border: `1px solid ${color}40`,
      fontSize: size - 2, fontFamily: "monospace", fontWeight: 700,
      padding: "3px 9px", borderRadius: 3, letterSpacing: "0.5px",
    }}>
      {score === null || score === undefined ? "—" : score}
    </span>
  );
}

function StaleBadge() {
  return (
    <span style={{
      background: "rgba(245,166,35,0.12)", color: C.amber,
      border: "1px solid rgba(245,166,35,0.3)", fontSize: 9,
      fontFamily: "monospace", padding: "2px 6px", borderRadius: 2,
      marginLeft: 6, letterSpacing: "0.5px",
    }}>
      STALE
    </span>
  );
}

function Spinner() {
  return (
    <div style={{
      display: "inline-block", width: 16, height: 16,
      border: `2px solid ${C.border}`,
      borderTop: `2px solid ${C.accent}`,
      borderRadius: "50%",
      animation: "spin 0.8s linear infinite",
    }} />
  );
}

// ── 1. CSPI Gauge ─────────────────────────────────────────────────────────────

function CspiGauge({ cspi, grade, percentile, percentileLabel }) {
  const color      = SCORE_COLOR(cspi);
  const gradeColor = GRADE_COLOR(grade);
  const hasScore   = cspi !== null && cspi !== undefined;

  // SVG half-donut gauge
  const R = 80, CX = 110, CY = 100;
  const arcPath = (pct, r) => {
    const a   = Math.PI * (1 - pct);
    const x   = CX + r * Math.cos(a);
    const y   = CY - r * Math.sin(a);
    return `M ${CX - r} ${CY} A ${r} ${r} 0 0 1 ${x} ${y}`;
  };

  const needleAngle = hasScore ? Math.PI * (1 - cspi / 100) : Math.PI * 0.5;
  const nx = CX + 65 * Math.cos(needleAngle);
  const ny = CY - 65 * Math.sin(needleAngle);

  return (
    <div style={{
      background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 10, padding: "28px 24px",
      display: "flex", flexDirection: "column", alignItems: "center",
      minWidth: 240,
    }}>
      <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace",
        letterSpacing: "1.8px", marginBottom: 16 }}>
        CSPI — SECURITY POSTURE INDEX
      </div>

      <svg width="220" height="118" viewBox="0 0 220 118">
        {/* Background arc */}
        <path d={`M ${CX - R} ${CY} A ${R} ${R} 0 0 1 ${CX + R} ${CY}`}
          fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="18" strokeLinecap="round"/>
        {/* Zone arcs: red → orange → yellow → blue → green */}
        {[
          [0.00, 0.30, "#ff3b3b"],
          [0.30, 0.50, "#ff8c00"],
          [0.50, 0.65, "#f5a623"],
          [0.65, 0.80, "#4d9eff"],
          [0.80, 1.00, "#00e5a0"],
        ].map(([lo, hi, col]) => {
          const a0 = Math.PI * (1 - lo), a1 = Math.PI * (1 - hi);
          const x0 = CX + R * Math.cos(a0), y0 = CY - R * Math.sin(a0);
          const x1 = CX + R * Math.cos(a1), y1 = CY - R * Math.sin(a1);
          return (
            <path key={col}
              d={`M ${x0} ${y0} A ${R} ${R} 0 0 1 ${x1} ${y1}`}
              fill="none" stroke={col} strokeWidth="18" strokeLinecap="butt"
              opacity="0.7"
            />
          );
        })}
        {/* Score fill arc */}
        {hasScore && cspi > 0 && (
          <path d={arcPath(cspi / 100, R)}
            fill="none" stroke={color} strokeWidth="18"
            strokeLinecap="round" opacity="0.35"/>
        )}
        {/* Needle */}
        {hasScore && (
          <>
            <line x1={CX} y1={CY} x2={nx} y2={ny}
              stroke={color} strokeWidth="2.5" strokeLinecap="round"/>
            <circle cx={CX} cy={CY} r="5" fill={color}/>
          </>
        )}
        {/* Score text */}
        <text x={CX} y={CY + 8} textAnchor="middle"
          style={{ fontSize: 32, fontWeight: 700, fill: hasScore ? color : C.dim,
            fontFamily: "monospace" }}>
          {hasScore ? cspi : "—"}
        </text>
      </svg>

      {/* Grade badge */}
      <div style={{
        background: `${gradeColor}15`, color: gradeColor,
        border: `1px solid ${gradeColor}40`,
        fontSize: 22, fontWeight: 700, fontFamily: "monospace",
        padding: "4px 18px", borderRadius: 6, marginTop: 8,
      }}>
        Grade {grade || "—"}
      </div>

      {/* Percentile */}
      {percentileLabel && (
        <div style={{ marginTop: 12, textAlign: "center" }}>
          <div style={{ color: C.text, fontSize: 13, fontWeight: 600 }}>
            {percentileLabel}
          </div>
          <div style={{ color: C.muted, fontSize: 11, marginTop: 2 }}>
            vs your selected industry cohort
          </div>
        </div>
      )}
    </div>
  );
}

// ── 2. Industry Benchmark Chart ───────────────────────────────────────────────

function BenchmarkChart({ cspi, cohort, industry, allIndustries, onIndustryChange }) {
  const bands  = cohort?.bands || [30, 44, 58, 69, 80];
  const labels = cohort?.label || "Industry";
  const W      = 600;
  const H      = 68;
  const PAD_L  = 0;
  const PAD_R  = 0;
  const TW     = W - PAD_L - PAD_R;

  // Map score 0-100 to pixel x
  const toX = (s) => PAD_L + (s / 100) * TW;

  const bandSegs = [
    [0,        bands[0], BAND_COLORS[0], "Critical"],
    [bands[0], bands[1], BAND_COLORS[1], "Below Avg"],
    [bands[1], bands[2], BAND_COLORS[2], "Average"],
    [bands[2], bands[3], BAND_COLORS[3], "Above Avg"],
    [bands[3], bands[4], BAND_COLORS[4], "Leader"],
    [bands[4], 100,      "rgba(0,229,160,0.32)", "Top 10%"],
  ];

  const customerX = cspi !== null && cspi !== undefined ? toX(cspi) : null;

  return (
    <div style={{
      background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 10, padding: "24px 28px", flex: 1,
    }}>
      {/* Header row */}
      <div style={{ display: "flex", justifyContent: "space-between",
        alignItems: "flex-start", marginBottom: 20, flexWrap: "wrap", gap: 12 }}>
        <div>
          <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace",
            letterSpacing: "1.8px", marginBottom: 4 }}>
            INDUSTRY BENCHMARK CHART
          </div>
          <div style={{ color: C.text, fontSize: 15, fontWeight: 600 }}>
            {cohort?.label || "Industry"} · {cohort?.region || "Benelux / DACH"}
          </div>
          <div style={{ color: C.muted, fontSize: 11, marginTop: 3 }}>
            n={cohort?.sample_size?.toLocaleString() || "?"} organisations ·{" "}
            Source: {cohort?.source || "ENISA 2024"}
          </div>
        </div>
        {/* Industry selector */}
        <select
          value={industry}
          onChange={(e) => onIndustryChange(e.target.value)}
          style={{
            background: C.surface2, color: C.text, border: `1px solid ${C.border2}`,
            borderRadius: 5, padding: "6px 12px", fontSize: 12,
            fontFamily: "monospace", cursor: "pointer",
          }}>
          {Object.entries(allIndustries || {}).map(([k, v]) => (
            <option key={k} value={k}>{v.icon} {v.label}</option>
          ))}
        </select>
      </div>

      {/* The chart */}
      <div style={{ overflowX: "auto" }}>
        <svg width="100%" viewBox={`0 0 ${W} ${H + 40}`}
          style={{ minWidth: 360, display: "block" }}>

          {/* Band segments */}
          {bandSegs.map(([lo, hi, col, lbl]) => (
            <g key={lbl}>
              <rect x={toX(lo)} y={0}
                width={toX(hi) - toX(lo)} height={H}
                fill={col} rx="2"/>
            </g>
          ))}

          {/* Percentile tick marks + labels */}
          {bands.map((b, i) => (
            <g key={i}>
              <line x1={toX(b)} y1={0} x2={toX(b)} y2={H}
                stroke="rgba(255,255,255,0.25)" strokeWidth="1" strokeDasharray="3 3"/>
              <text x={toX(b)} y={H + 14} textAnchor="middle"
                style={{ fontSize: 9, fill: C.muted, fontFamily: "monospace" }}>
                {BAND_LABELS[i]}
              </text>
              <text x={toX(b)} y={H + 26} textAnchor="middle"
                style={{ fontSize: 9, fill: C.dim, fontFamily: "monospace" }}>
                {b}
              </text>
            </g>
          ))}

          {/* 0 and 100 axis labels */}
          <text x={2} y={H + 26} textAnchor="start"
            style={{ fontSize: 9, fill: C.dim, fontFamily: "monospace" }}>0</text>
          <text x={W - 2} y={H + 26} textAnchor="end"
            style={{ fontSize: 9, fill: C.dim, fontFamily: "monospace" }}>100</text>

          {/* Customer marker */}
          {customerX !== null && (
            <g>
              <line x1={customerX} y1={-6} x2={customerX} y2={H + 6}
                stroke={SCORE_COLOR(cspi)} strokeWidth="2.5"/>
              {/* Triangle pointer at top */}
              <polygon
                points={`${customerX},${-14} ${customerX - 7},${-5} ${customerX + 7},${-5}`}
                fill={SCORE_COLOR(cspi)}/>
              {/* Score label above */}
              <rect x={customerX - 16} y={-28} width={32} height={14}
                fill={SCORE_COLOR(cspi)} rx="3"/>
              <text x={customerX} y={-18} textAnchor="middle"
                style={{ fontSize: 9, fill: "#0d0f14", fontFamily: "monospace",
                  fontWeight: 700 }}>
                {cspi}
              </text>
            </g>
          )}

          {/* No score placeholder */}
          {customerX === null && (
            <text x={W / 2} y={H / 2 + 4} textAnchor="middle"
              style={{ fontSize: 12, fill: C.dim, fontFamily: "monospace" }}>
              Run a scan to place your score
            </text>
          )}
        </svg>
      </div>

      {/* Legend */}
      <div style={{ display: "flex", gap: 16, marginTop: 8, flexWrap: "wrap" }}>
        {bandSegs.map(([,, col, lbl]) => (
          <div key={lbl} style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <div style={{ width: 10, height: 10, borderRadius: 2, background: col }}/>
            <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>{lbl}</span>
          </div>
        ))}
        <div style={{ display: "flex", alignItems: "center", gap: 5, marginLeft: "auto" }}>
          <div style={{ width: 2, height: 14, background: SCORE_COLOR(cspi) }}/>
          <span style={{ color: C.text, fontSize: 10, fontFamily: "monospace",
            fontWeight: 700 }}>
            YOUR SCORE
          </span>
        </div>
      </div>
    </div>
  );
}

// ── 3. Per-Dimension Breakdown Cards ─────────────────────────────────────────

const DIM_ORDER = ["asm", "siem", "compliance", "vuln", "threat_intel", "ext_benchmark"];

const DIM_META = {
  asm:           { icon: "🌐", desc: "External attack surface — SSL, DNS, subdomains, CVEs, email auth, cloud exposure" },
  siem:          { icon: "🔥", desc: "Internal detection posture — entity risk, UEBA anomalies, kill-chain coverage" },
  compliance:    { icon: "📋", desc: "Regulatory coverage — NIS2, DORA, ISO 27001, AVG/GDPR control states" },
  vuln:          { icon: "🔒", desc: "Vulnerability management — CVSS/EPSS weighted open findings, patch velocity" },
  threat_intel:  { icon: "🎯", desc: "Threat intelligence — MISP feed coverage, IOC hit rate, ATT&CK alignment" },
  ext_benchmark: { icon: "📊", desc: "CIS Controls v8 / NIST CSF 2.0 alignment — implementation group scoring" },
};

function DimensionCard({ id, dim }) {
  const meta  = DIM_META[id] || {};
  const color = dim.color || C.muted;
  const s     = dim.score;

  const barW = s !== null && s !== undefined ? `${s}%` : "0%";

  return (
    <div style={{
      background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 8, padding: "16px 18px",
      borderLeft: `3px solid ${dim.enabled ? color : C.dim}`,
      opacity: dim.enabled ? 1 : 0.45,
      transition: "opacity 0.2s",
    }}>
      <div style={{ display: "flex", alignItems: "flex-start",
        justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 15 }}>{meta.icon}</span>
          <div>
            <div style={{ color: C.text, fontSize: 13, fontWeight: 600 }}>
              {dim.label}
            </div>
            <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace",
              marginTop: 1 }}>
              Weight: {dim.weight}%
            </div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {dim.stale && <StaleBadge/>}
          <ScorePill score={s} size={15}/>
        </div>
      </div>

      {/* Score bar */}
      <div style={{
        height: 4, background: "rgba(255,255,255,0.06)",
        borderRadius: 2, overflow: "hidden", marginBottom: 8,
      }}>
        <div style={{
          height: "100%", width: barW,
          background: dim.enabled ? color : C.dim,
          borderRadius: 2, transition: "width 0.6s ease",
        }}/>
      </div>

      <div style={{ color: C.muted, fontSize: 11 }}>{dim.detail || "—"}</div>
      <div style={{ color: "rgba(255,255,255,0.18)", fontSize: 10,
        fontFamily: "monospace", marginTop: 4 }}>
        {meta.desc}
      </div>
    </div>
  );
}

// ── 4. Source Configurator ────────────────────────────────────────────────────

function SourceConfigurator({ config, onSave, saving }) {
  const [local, setLocal] = useState(() =>
    JSON.parse(JSON.stringify(config?.sources || {}))
  );

  useEffect(() => {
    setLocal(JSON.parse(JSON.stringify(config?.sources || {})));
  }, [config]);

  const totalW = Object.values(local).reduce(
    (s, d) => s + (d.enabled ? (d.weight || 0) : 0), 0
  );

  const setEnabled = (id, val) =>
    setLocal(p => ({ ...p, [id]: { ...p[id], enabled: val } }));
  const setWeight  = (id, val) =>
    setLocal(p => ({ ...p, [id]: { ...p[id], weight: Number(val) } }));

  return (
    <div style={{
      background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 10, padding: "24px 28px",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between",
        alignItems: "center", marginBottom: 20 }}>
        <div>
          <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace",
            letterSpacing: "1.8px", marginBottom: 2 }}>
            SCORE SOURCE CONFIGURATION
          </div>
          <div style={{ color: C.text, fontSize: 13 }}>
            Toggle sources and adjust relative weights to customise your CSPI.
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{
            color: totalW === 100 ? C.accent : C.amber,
            fontFamily: "monospace", fontSize: 14, fontWeight: 700,
          }}>
            {totalW}% total
          </div>
          <div style={{ color: C.muted, fontSize: 10 }}>
            {totalW === 100 ? "Balanced ✓" : "Weights need not sum to 100"}
          </div>
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 12, marginBottom: 20 }}>
        {DIM_ORDER.map(id => {
          const dim  = local[id];
          if (!dim) return null;
          const meta = DIM_META[id] || {};
          const color = dim.color || C.muted;
          return (
            <div key={id} style={{
              display: "flex", alignItems: "center", gap: 14,
              padding: "12px 14px",
              background: dim.enabled ? "rgba(255,255,255,0.02)" : "transparent",
              borderRadius: 6, border: `1px solid ${dim.enabled ? C.border : "transparent"}`,
              opacity: dim.enabled ? 1 : 0.5, transition: "all 0.15s",
            }}>
              {/* Toggle */}
              <button
                onClick={() => setEnabled(id, !dim.enabled)}
                style={{
                  width: 34, height: 19, borderRadius: 9, border: "none",
                  background: dim.enabled ? color : "rgba(255,255,255,0.1)",
                  cursor: "pointer", position: "relative", flexShrink: 0,
                  transition: "background 0.2s",
                }}>
                <div style={{
                  position: "absolute", top: 2.5,
                  left: dim.enabled ? 16 : 2.5,
                  width: 14, height: 14, borderRadius: "50%",
                  background: "white",
                  transition: "left 0.2s",
                }}/>
              </button>

              {/* Icon + label */}
              <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 180 }}>
                <span style={{ fontSize: 14 }}>{meta.icon}</span>
                <div>
                  <div style={{ color: C.text, fontSize: 12, fontWeight: 600 }}>
                    {dim.label}
                  </div>
                </div>
              </div>

              {/* Slider */}
              <div style={{ flex: 1, display: "flex", alignItems: "center", gap: 10 }}>
                <input
                  type="range" min={0} max={50} step={5}
                  value={dim.weight}
                  disabled={!dim.enabled}
                  onChange={(e) => setWeight(id, e.target.value)}
                  style={{
                    flex: 1, accentColor: color,
                    opacity: dim.enabled ? 1 : 0.3,
                  }}
                />
                <span style={{
                  color: dim.enabled ? color : C.dim,
                  fontFamily: "monospace", fontSize: 12, fontWeight: 700,
                  minWidth: 36, textAlign: "right",
                }}>
                  {dim.weight}%
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Save + reset buttons */}
      <div style={{ display: "flex", gap: 10 }}>
        <button
          onClick={() => onSave({ sources: local })}
          disabled={saving}
          style={{
            background: saving ? "rgba(0,229,160,0.08)" : "rgba(0,229,160,0.15)",
            color: C.accent, border: `1px solid rgba(0,229,160,0.3)`,
            borderRadius: 5, padding: "8px 22px",
            fontFamily: "monospace", fontSize: 12, fontWeight: 700,
            cursor: saving ? "wait" : "pointer", letterSpacing: "0.5px",
          }}>
          {saving ? "Saving…" : "Save Configuration"}
        </button>
        <button
          onClick={() => setLocal(JSON.parse(JSON.stringify(config?.sources || {})))}
          style={{
            background: "transparent", color: C.muted,
            border: `1px solid ${C.border}`,
            borderRadius: 5, padding: "8px 16px",
            fontFamily: "monospace", fontSize: 12, cursor: "pointer",
          }}>
          Reset
        </button>
      </div>
    </div>
  );
}

// ── 5. Industry & Size Selector ────────────────────────────────────────────────

const SIZE_BANDS = [
  { id: "micro",    label: "Micro",      desc: "< 10 employees" },
  { id: "small",    label: "Small",      desc: "10–50 employees" },
  { id: "mid",      label: "Mid-market", desc: "50–500 employees" },
  { id: "large",    label: "Large",      desc: "500–5,000 employees" },
  { id: "enterprise", label: "Enterprise", desc: "> 5,000 employees" },
];

function CohortSelector({ config, allIndustries, onSave }) {
  const [industry, setIndustry] = useState(config?.industry || "general");
  const [sizeBand, setSizeBand] = useState(config?.size_band || "mid");
  const [optIn,    setOptIn]    = useState(config?.cohort_opt_in || false);

  useEffect(() => {
    setIndustry(config?.industry  || "general");
    setSizeBand(config?.size_band || "mid");
    setOptIn(config?.cohort_opt_in || false);
  }, [config]);

  const dirty = industry !== config?.industry ||
                sizeBand !== config?.size_band ||
                optIn    !== config?.cohort_opt_in;

  return (
    <div style={{
      background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 10, padding: "24px 28px",
    }}>
      <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace",
        letterSpacing: "1.8px", marginBottom: 16 }}>
        COHORT CONTEXT
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20,
        marginBottom: 20 }}>

        {/* Industry */}
        <div>
          <div style={{ color: C.muted, fontSize: 11, marginBottom: 6 }}>
            Industry sector
          </div>
          <select
            value={industry}
            onChange={(e) => setIndustry(e.target.value)}
            style={{
              width: "100%", background: C.surface2, color: C.text,
              border: `1px solid ${C.border2}`, borderRadius: 5,
              padding: "8px 10px", fontSize: 12, fontFamily: "monospace",
              cursor: "pointer",
            }}>
            {Object.entries(allIndustries || {}).map(([k, v]) => (
              <option key={k} value={k}>{v.icon} {v.label}</option>
            ))}
          </select>
          {allIndustries?.[industry] && (
            <div style={{ color: C.muted, fontSize: 10, marginTop: 5 }}>
              {allIndustries[industry].description}
            </div>
          )}
        </div>

        {/* Size band */}
        <div>
          <div style={{ color: C.muted, fontSize: 11, marginBottom: 6 }}>
            Organisation size
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {SIZE_BANDS.map(b => (
              <button
                key={b.id}
                onClick={() => setSizeBand(b.id)}
                style={{
                  background: sizeBand === b.id
                    ? "rgba(77,158,255,0.15)" : "rgba(255,255,255,0.03)",
                  color: sizeBand === b.id ? C.blue : C.muted,
                  border: `1px solid ${sizeBand === b.id
                    ? "rgba(77,158,255,0.4)" : C.border}`,
                  borderRadius: 4, padding: "5px 10px",
                  fontSize: 11, fontFamily: "monospace", cursor: "pointer",
                }}>
                {b.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Cohort opt-in */}
      <div style={{
        display: "flex", alignItems: "flex-start", gap: 12,
        background: "rgba(77,158,255,0.05)", border: "1px solid rgba(77,158,255,0.15)",
        borderRadius: 6, padding: "12px 14px", marginBottom: 18,
      }}>
        <button
          onClick={() => setOptIn(!optIn)}
          style={{
            width: 34, height: 19, borderRadius: 9, border: "none",
            background: optIn ? C.blue : "rgba(255,255,255,0.1)",
            cursor: "pointer", position: "relative", flexShrink: 0,
            transition: "background 0.2s", marginTop: 2,
          }}>
          <div style={{
            position: "absolute", top: 2.5,
            left: optIn ? 16 : 2.5,
            width: 14, height: 14, borderRadius: "50%",
            background: "white", transition: "left 0.2s",
          }}/>
        </button>
        <div>
          <div style={{ color: C.text, fontSize: 12, fontWeight: 600 }}>
            Contribute to anonymised cohort pool
          </div>
          <div style={{ color: C.muted, fontSize: 11, marginTop: 2, lineHeight: 1.5 }}>
            Share your anonymised CSPI snapshot (no identifiable data) to improve
            the industry benchmarks. Your score appears as one anonymous data point
            in the cohort.
          </div>
        </div>
      </div>

      {dirty && (
        <button
          onClick={() => onSave({ industry, size_band: sizeBand, cohort_opt_in: optIn })}
          style={{
            background: "rgba(77,158,255,0.15)", color: C.blue,
            border: `1px solid rgba(77,158,255,0.3)`,
            borderRadius: 5, padding: "8px 22px",
            fontFamily: "monospace", fontSize: 12, fontWeight: 700,
            cursor: "pointer",
          }}>
          Save Cohort Settings
        </button>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function BenchmarkPage() {
  const [scoreData,    setScoreData]    = useState(null);
  const [config,       setConfig]       = useState(null);
  const [industries,   setIndustries]   = useState(null);
  const [loading,      setLoading]      = useState(true);
  const [error,        setError]        = useState(null);
  const [saving,       setSaving]       = useState(false);
  const [lastRefresh,  setLastRefresh]  = useState(null);
  const [industry,     setIndustry]     = useState("general");

  const fetchAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [scoreRes, configRes, indRes] = await Promise.all([
        fetch(`${API}/score`,      { credentials: "include" }),
        fetch(`${API}/config`,     { credentials: "include" }),
        fetch(`${API}/industries`, { credentials: "include" }),
      ]);
      if (!scoreRes.ok)  throw new Error(`Score API error ${scoreRes.status}`);
      if (!configRes.ok) throw new Error(`Config API error ${configRes.status}`);
      if (!indRes.ok)    throw new Error(`Industries API error ${indRes.status}`);
      const [score, cfg, ind] = await Promise.all([
        scoreRes.json(), configRes.json(), indRes.json(),
      ]);
      setScoreData(score);
      setConfig(cfg);
      setIndustries(ind.industries || {});
      setIndustry(score.industry || cfg.industry || "general");
      setLastRefresh(new Date());
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const handleSaveConfig = async (patch) => {
    setSaving(true);
    try {
      const r = await fetch(`${API}/config`, {
        method: "PUT",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
      if (!r.ok) throw new Error(`Save failed: ${r.status}`);
      await fetchAll();
    } catch (e) {
      alert(e.message);
    } finally {
      setSaving(false);
    }
  };

  const handleIndustryChange = (newInd) => {
    setIndustry(newInd);
    handleSaveConfig({ industry: newInd });
  };

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div style={{ color: C.text, fontFamily: "system-ui, sans-serif" }}>

      {/* ── Page header ────────────────────────────────────────────────────── */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12,
          justifyContent: "space-between", flexWrap: "wrap" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10,
              marginBottom: 4 }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none"
                stroke={C.accent} strokeWidth="1.8">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
              </svg>
              <h1 style={{ margin: 0, fontSize: 20, fontWeight: 700,
                color: "white", letterSpacing: "0.3px" }}>
                Security Posture Benchmark
              </h1>
              <span style={{
                background: "rgba(0,229,160,0.1)", color: C.accent,
                border: "1px solid rgba(0,229,160,0.25)", fontSize: 9,
                fontFamily: "monospace", padding: "3px 10px", borderRadius: 2,
                fontWeight: 700, letterSpacing: "1.2px",
              }}>
                CSPI
              </span>
            </div>
            <p style={{ margin: 0, color: C.muted, fontSize: 12, lineHeight: 1.6 }}>
              CyCentra Security Posture Index — composite score across all platform
              modules, benchmarked against your industry cohort.
            </p>
          </div>

          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {lastRefresh && (
              <span style={{ color: C.dim, fontSize: 10, fontFamily: "monospace" }}>
                Refreshed {lastRefresh.toLocaleTimeString()}
              </span>
            )}
            <button
              onClick={fetchAll}
              disabled={loading}
              style={{
                background: "rgba(0,229,160,0.08)", color: C.accent,
                border: "1px solid rgba(0,229,160,0.2)", borderRadius: 5,
                padding: "7px 16px", fontFamily: "monospace", fontSize: 11,
                cursor: loading ? "wait" : "pointer", fontWeight: 700,
                display: "flex", alignItems: "center", gap: 6,
              }}>
              {loading ? <Spinner/> : "↻"} Refresh
            </button>
          </div>
        </div>
      </div>

      {/* ── Error state ─────────────────────────────────────────────────────── */}
      {error && (
        <div style={{
          background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.25)",
          borderRadius: 8, padding: "16px 20px", marginBottom: 24, color: C.red,
          fontSize: 12, fontFamily: "monospace",
        }}>
          ⚠ {error} — check that the backend is running and you are logged in.
        </div>
      )}

      {/* ── Section 1: Composite score + benchmark chart ──────────────────── */}
      <div style={{ display: "flex", gap: 20, marginBottom: 24,
        flexWrap: "wrap", alignItems: "stretch" }}>
        <CspiGauge
          cspi={scoreData?.cspi}
          grade={scoreData?.grade}
          percentile={scoreData?.percentile}
          percentileLabel={scoreData?.percentile_label}
        />
        <BenchmarkChart
          cspi={scoreData?.cspi}
          cohort={scoreData?.cohort || industries?.[industry]}
          industry={industry}
          allIndustries={industries}
          onIndustryChange={handleIndustryChange}
        />
      </div>

      {/* ── Section divider ─────────────────────────────────────────────────── */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace",
          letterSpacing: "1.8px", marginBottom: 12 }}>
          SCORE BREAKDOWN — HOW CSPI IS CALCULATED
        </div>
        <p style={{ margin: 0, color: C.muted, fontSize: 11, lineHeight: 1.6 }}>
          The CSPI is a weighted average of the six source dimensions below,
          calculated in the order shown. Each dimension pulls live data from
          the corresponding CyCentra module. Disabled sources are excluded
          from the composite calculation.
        </p>
      </div>

      {/* ── Section 2: Per-dimension cards (in calculation order) ──────────── */}
      {loading && !scoreData ? (
        <div style={{ display: "flex", alignItems: "center", gap: 10,
          color: C.muted, fontSize: 13, padding: "32px 0" }}>
          <Spinner/> Loading score data…
        </div>
      ) : (
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
          gap: 16, marginBottom: 28,
        }}>
          {DIM_ORDER.map(id => {
            const dim = scoreData?.breakdown?.[id];
            if (!dim) return null;
            return <DimensionCard key={id} id={id} dim={dim}/>;
          })}
        </div>
      )}

      {/* ── Section 3: Source weight configurator ─────────────────────────── */}
      {config && (
        <div style={{ marginBottom: 24 }}>
          <SourceConfigurator
            config={config}
            onSave={handleSaveConfig}
            saving={saving}
          />
        </div>
      )}

      {/* ── Section 4: Cohort selector ─────────────────────────────────────── */}
      {config && (
        <div style={{ marginBottom: 24 }}>
          <CohortSelector
            config={config}
            allIndustries={industries}
            onSave={handleSaveConfig}
          />
        </div>
      )}

      {/* ── Footer note ─────────────────────────────────────────────────────── */}
      <div style={{
        borderTop: `1px solid ${C.border}`,
        paddingTop: 16, color: C.dim, fontSize: 10,
        fontFamily: "monospace", lineHeight: 1.7,
      }}>
        Industry benchmark data sourced from ENISA Threat Landscape 2024, CIS Benchmark
        SecureSuite, NCSC-NL, BSI Lagebericht, and Verizon DBIR 2024.
        Cohort bands represent P10/P25/P50/P75/P90 percentiles of organisations in
        the Benelux / DACH region. Score computed at{" "}
        {scoreData?.computed_at
          ? new Date(scoreData.computed_at).toLocaleString()
          : "—"}.
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}
