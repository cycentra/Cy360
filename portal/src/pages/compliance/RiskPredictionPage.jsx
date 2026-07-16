/**
 * RiskPredictionPage.jsx — Predictive Risk Modeling (#17)
 * =========================================================
 * Linear regression + EWMA predictions for each GRC framework.
 * Chart: solid line = historical, dashed = predicted trajectory.
 * Horizon toggle: 30 / 60 / 90 days.
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
  nis2:      { label: "NIS2",       color: "#6378ff" },
  dora:      { label: "DORA",       color: "#ffd166" },
  iso27001:  { label: "ISO 27001",  color: "#00e5c0" },
  soc2:      { label: "SOC 2",      color: "#ff6b6b" },
  nist_csf:  { label: "NIST CSF",   color: "#38bdf8" },
  pci_dss:   { label: "PCI DSS",    color: "#f97316" },
  gdpr:      { label: "GDPR",       color: "#8b5cf6" },
  eu_ai_act: { label: "EU AI Act",  color: "#06b6d4" },
  iso42001:  { label: "ISO 42001",  color: "#10b981" },
};
const FRAMEWORKS = Object.keys(FW_META);

function scoreColor(s) {
  if (!s && s !== 0) return C.muted;
  if (s >= 80) return C.accent;
  if (s >= 60) return C.orange;
  return C.red;
}

function TrendBadge({ trend }) {
  const map = {
    improving: { icon: "↑", color: C.accent },
    declining: { icon: "↓", color: C.red },
    stable:    { icon: "→", color: C.muted },
  };
  const t = map[trend] || { icon: "?", color: C.muted };
  return (
    <span style={{ color: t.color, fontWeight: 700, fontSize: 14 }}>
      {t.icon} {trend || "—"}
    </span>
  );
}

/** Inline SVG line chart with historical (solid) + predicted (dashed) segments. */
function PredictionChart({ actual, predictions, horizon, fwColor }) {
  if (!actual || actual.length === 0) return (
    <div style={{ height: 140, display: "flex", alignItems: "center", justifyContent: "center",
      color: C.muted, fontSize: 12 }}>
      No score history yet — trigger a refresh to begin collecting data.
    </div>
  );

  const W = 560, H = 140, PAD = { top: 12, right: 20, bottom: 24, left: 36 };
  const innerW = W - PAD.left - PAD.right;
  const innerH = H - PAD.top - PAD.bottom;

  const pred = predictions?.[String(horizon)] || {};
  const lastX = actual[actual.length - 1]?.days ?? 0;
  const futureX = lastX + horizon;
  const allX = actual.map(a => a.days).concat([futureX]);
  const allY = actual.map(a => a.score).concat([pred.score ?? actual[actual.length - 1]?.score ?? 50]);

  const minX = Math.min(...allX);
  const maxX = Math.max(...allX);
  const minY = Math.max(0, Math.min(...allY) - 10);
  const maxY = Math.min(100, Math.max(...allY) + 10);

  const scX = x => PAD.left + ((x - minX) / (maxX - minX || 1)) * innerW;
  const scY = y => PAD.top + (1 - (y - minY) / (maxY - minY || 1)) * innerH;

  // Historical polyline
  const histPts = actual.map(a => `${scX(a.days)},${scY(a.score)}`).join(" ");
  const lastPt  = actual[actual.length - 1];

  // Predicted segment from last actual to horizon
  const predLine = pred.score !== undefined
    ? `M ${scX(lastPt.days)},${scY(lastPt.score)} L ${scX(futureX)},${scY(pred.score)}`
    : null;

  // Confidence band
  const predHigh = pred.high, predLow = pred.low;
  const bandPath = (predHigh !== undefined && predLow !== undefined)
    ? `M ${scX(lastPt.days)},${scY(lastPt.score)}
       L ${scX(futureX)},${scY(predHigh)}
       L ${scX(futureX)},${scY(predLow)} Z`
    : null;

  // Y-axis gridlines at 0, 25, 50, 75, 100
  const gridYs = [0, 25, 50, 75, 100].filter(y => y >= minY && y <= maxY);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: 140, display: "block" }}>
      {/* Grid */}
      {gridYs.map(y => (
        <g key={y}>
          <line x1={PAD.left} y1={scY(y)} x2={W - PAD.right} y2={scY(y)}
            stroke="rgba(255,255,255,0.05)" strokeWidth={1} />
          <text x={PAD.left - 4} y={scY(y) + 3} textAnchor="end"
            fill="rgba(255,255,255,0.45)" fontSize={9} fontFamily="monospace">{y}</text>
        </g>
      ))}

      {/* Confidence band */}
      {bandPath && (
        <path d={bandPath} fill={fwColor} fillOpacity={0.08} />
      )}

      {/* Historical line */}
      <polyline points={histPts} fill="none" stroke={fwColor} strokeWidth={2} strokeLinecap="round" />

      {/* Predicted line (dashed) */}
      {predLine && (
        <path d={predLine} fill="none" stroke={fwColor} strokeWidth={2}
          strokeDasharray="5,4" strokeLinecap="round" opacity={0.7} />
      )}

      {/* Current point */}
      <circle cx={scX(lastPt.days)} cy={scY(lastPt.score)} r={4}
        fill={fwColor} stroke="#090b10" strokeWidth={2} />

      {/* Predicted point */}
      {pred.score !== undefined && (
        <circle cx={scX(futureX)} cy={scY(pred.score)} r={4}
          fill="none" stroke={fwColor} strokeWidth={2} strokeDasharray="3,2" />
      )}

      {/* "NOW" label */}
      <text x={scX(lastPt.days)} y={H - 4} textAnchor="middle"
        fill="rgba(255,255,255,0.45)" fontSize={8} fontFamily="monospace">now</text>

      {/* Horizon label */}
      <text x={scX(futureX)} y={H - 4} textAnchor="middle"
        fill="rgba(255,255,255,0.45)" fontSize={8} fontFamily="monospace">+{horizon}d</text>
    </svg>
  );
}

function PortfolioSummary({ portfolio }) {
  if (!portfolio) return null;
  const { count_improving, count_declining, count_stable, count_no_data, by_framework } = portfolio;
  return (
    <div style={{ ...CARD, marginBottom: 24 }}>
      <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Portfolio Trend Overview</div>
      <div style={{ display: "flex", gap: 20, marginBottom: 16, flexWrap: "wrap" }}>
        {[
          { label: "Improving", value: count_improving, color: C.accent },
          { label: "Declining", value: count_declining, color: C.red },
          { label: "Stable",    value: count_stable,    color: C.muted },
          { label: "No Data",   value: count_no_data,   color: "rgba(255,255,255,0.45)" },
        ].map(({ label, value, color }) => (
          <div key={label} style={{ textAlign: "center", minWidth: 70 }}>
            <div style={{ fontSize: 22, fontWeight: 700, color, fontFamily: "monospace" }}>{value ?? 0}</div>
            <div style={{ fontSize: 11, color: C.muted, textTransform: "uppercase", letterSpacing: 0.7 }}>{label}</div>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
        {(by_framework || []).map(fw => (
          <div key={fw.framework} style={{
            background: "rgba(255,255,255,0.03)", border: `1px solid ${C.border}`,
            borderRadius: 6, padding: "6px 12px", display: "flex", alignItems: "center", gap: 8,
          }}>
            <span style={{ color: FW_META[fw.framework]?.color || C.muted, fontWeight: 600, fontSize: 12 }}>
              {FW_META[fw.framework]?.label || fw.framework}
            </span>
            {fw.data_points > 0 ? (
              <>
                <span style={{ color: scoreColor(fw.current_score), fontFamily: "monospace", fontSize: 12 }}>
                  {fw.current_score?.toFixed(1) ?? "—"}%
                </span>
                <span style={{
                  fontSize: 11,
                  color: fw.trend === "improving" ? C.accent : fw.trend === "declining" ? C.red : C.muted,
                }}>
                  {fw.trend === "improving" ? "↑" : fw.trend === "declining" ? "↓" : "→"}
                  {" "}{fw.score_30d !== undefined && fw.score_30d !== null
                    ? `→ ${fw.score_30d.toFixed(1)}% (+30d)` : ""}
                </span>
              </>
            ) : (
              <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 11 }}>warming up</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function RiskPredictionPage() {
  const [selectedFw, setFw]     = useState("nis2");
  const [horizon, setHorizon]   = useState(30);
  const [fwData, setFwData]     = useState(null);
  const [portfolio, setPort]    = useState(null);
  const [loading, setLoading]   = useState(false);
  const [portLoad, setPortLoad] = useState(true);
  const [refreshing, setRef]    = useState(false);
  const [msg, setMsg]           = useState(null);

  // Load portfolio overview once
  useEffect(() => {
    (async () => {
      setPortLoad(true);
      try {
        const r = await fetch(`${API_BASE}/api/comp/predict`, { credentials: "include" });
        const d = await r.json();
        setPort(d);
      } catch { /* portfolio is optional */ }
      setPortLoad(false);
    })();
  }, []);

  // Load per-framework prediction
  const loadFw = useCallback(async (fw) => {
    setLoading(true); setFwData(null);
    try {
      const r = await fetch(`${API_BASE}/api/comp/predict?framework=${fw}&horizon=30,60,90`,
        { credentials: "include" });
      const d = await r.json();
      setFwData(d);
    } catch (e) {
      setMsg({ type: "error", text: `Failed to load prediction for ${fw}` });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadFw(selectedFw); }, [selectedFw, loadFw]);

  const triggerRefresh = async () => {
    setRef(true); setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/comp/dashboard/refresh`,
        { method: "POST", credentials: "include" });
      if (!r.ok) throw new Error("Refresh failed");
      setMsg({ type: "ok", text: "Score refresh triggered. Prediction history will update shortly." });
      setTimeout(() => loadFw(selectedFw), 2000);
    } catch (e) {
      setMsg({ type: "error", text: e.message });
    } finally {
      setRef(false);
    }
  };

  const fwColor   = FW_META[selectedFw]?.color || C.accent;
  const pred      = fwData?.predictions || {};
  const actual    = fwData?.actual || [];
  const n         = fwData?.data_points || 0;
  const curScore  = fwData?.current_score;

  return (
    <div style={{ padding: "28px 32px", background: C.bg, minHeight: "100vh", color: C.text, fontFamily: "system-ui, sans-serif" }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <div style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>Predictive Risk Modeling</div>
          <div style={{ color: C.muted, fontSize: 13 }}>
            Linear regression + EWMA forecast on compliance score history.
          </div>
        </div>
        <button onClick={triggerRefresh} disabled={refreshing}
          style={{ background: "rgba(255,255,255,0.05)", color: C.text, border: `1px solid ${C.border}`,
            borderRadius: 6, padding: "8px 16px", fontSize: 12, fontWeight: 600, cursor: "pointer" }}>
          {refreshing ? "Refreshing…" : "Refresh Score History"}
        </button>
      </div>

      {/* Message */}
      {msg && (
        <div style={{ ...CARD, marginBottom: 20, padding: "10px 18px", fontSize: 13,
          borderColor: msg.type === "error" ? C.red : C.accent,
          color: msg.type === "error" ? C.red : C.accent }}>
          {msg.text}
        </div>
      )}

      {/* Portfolio summary */}
      {!portLoad && <PortfolioSummary portfolio={portfolio} />}

      {/* Framework selector */}
      <div style={{ ...CARD, marginBottom: 20 }}>
        <div style={{ fontSize: 12, color: C.muted, marginBottom: 10, textTransform: "uppercase", letterSpacing: 0.8 }}>
          Select Framework
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          {FRAMEWORKS.map(fw => {
            const meta = FW_META[fw];
            const active = fw === selectedFw;
            return (
              <button key={fw} onClick={() => setFw(fw)}
                style={{
                  background: active ? `${meta.color}22` : "rgba(255,255,255,0.03)",
                  color: active ? meta.color : C.muted,
                  border: `1px solid ${active ? meta.color + "66" : C.border}`,
                  borderRadius: 6, padding: "6px 14px", fontSize: 12, fontWeight: active ? 700 : 400,
                  cursor: "pointer",
                }}>
                {meta.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Horizon toggle */}
      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        {[30, 60, 90].map(h => (
          <button key={h} onClick={() => setHorizon(h)}
            style={{
              background: horizon === h ? `${C.accent}22` : "rgba(255,255,255,0.03)",
              color: horizon === h ? C.accent : C.muted,
              border: `1px solid ${horizon === h ? C.accent + "66" : C.border}`,
              borderRadius: 6, padding: "6px 14px", fontSize: 12, fontWeight: 600, cursor: "pointer",
            }}>
            +{h}d
          </button>
        ))}
      </div>

      {/* Chart + prediction panel */}
      {loading ? (
        <div style={{ color: C.muted, textAlign: "center", padding: 40, fontSize: 13 }}>Loading prediction…</div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: 20 }}>

          {/* Chart */}
          <div style={CARD}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
              <div>
                <span style={{ color: fwColor, fontWeight: 700, fontSize: 15 }}>
                  {FW_META[selectedFw]?.label}
                </span>
                {curScore !== null && curScore !== undefined && (
                  <span style={{ color: scoreColor(curScore), fontFamily: "monospace",
                    fontSize: 20, fontWeight: 700, marginLeft: 16 }}>
                    {curScore?.toFixed(1)}%
                  </span>
                )}
                {fwData?.trend && (
                  <span style={{ marginLeft: 12, fontSize: 13 }}>
                    <TrendBadge trend={fwData.trend} />
                  </span>
                )}
              </div>
              <div style={{ color: C.muted, fontSize: 11 }}>
                {n} data point{n !== 1 ? "s" : ""} &nbsp;·&nbsp; R²={fwData?.r_squared ?? "—"}
              </div>
            </div>

            <PredictionChart
              actual={actual}
              predictions={pred}
              horizon={horizon}
              fwColor={fwColor}
            />

            <div style={{ display: "flex", gap: 20, marginTop: 12, fontSize: 11, color: C.muted }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <div style={{ width: 24, height: 2, background: fwColor }} />
                Historical
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <div style={{ width: 24, height: 0, border: `1px dashed ${fwColor}` }} />
                Predicted
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <div style={{ width: 10, height: 10, background: fwColor, opacity: 0.15, borderRadius: 2 }} />
                Confidence band
              </div>
            </div>

            {n < 5 && (
              <div style={{ marginTop: 12, padding: "8px 12px", background: `${C.orange}15`,
                border: `1px solid ${C.orange}33`, borderRadius: 6, fontSize: 12, color: C.orange }}>
                ⚠ Low data quality — only {n} score{n !== 1 ? "s" : ""} in history.
                Predictions improve with more data points. Use "Refresh Score History" to add more.
              </div>
            )}
          </div>

          {/* Prediction table */}
          <div>
            <div style={CARD}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 14, color: C.muted }}>
                Score Forecast
              </div>
              {fwData?.data_points === 0 ? (
                <div style={{ color: C.muted, fontSize: 12 }}>
                  No history yet. Click "Refresh Score History" to compute and store the current score.
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                  <tbody>
                    {[
                      { label: "Current", score: curScore, conf: null, horizon: null },
                      ...[30, 60, 90].map(h => {
                        const p = pred[String(h)] || {};
                        return { label: `+${h}d`, score: p.score, conf: p.confidence, low: p.low, high: p.high, horizon: h };
                      }),
                    ].map(row => (
                      <tr key={row.label} style={{ borderBottom: `1px solid rgba(255,255,255,0.04)` }}>
                        <td style={{ padding: "10px 0", color: C.muted, fontSize: 12, width: 60 }}>
                          {row.label}
                        </td>
                        <td style={{ padding: "10px 0", textAlign: "right" }}>
                          {row.score !== undefined && row.score !== null ? (
                            <span style={{ color: scoreColor(row.score), fontFamily: "monospace",
                              fontSize: 16, fontWeight: 700 }}>
                              {row.score.toFixed(1)}%
                            </span>
                          ) : <span style={{ color: C.muted }}>—</span>}
                        </td>
                        <td style={{ padding: "10px 0 10px 8px" }}>
                          {row.conf !== null && row.conf !== undefined && (
                            <div>
                              <div style={{ color: C.muted, fontSize: 10 }}>
                                {row.low?.toFixed(0)}–{row.high?.toFixed(0)}%
                              </div>
                              <div style={{ color: row.conf >= 70 ? C.accent : C.orange, fontSize: 10 }}>
                                {row.conf}% conf
                              </div>
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {/* Slope info */}
            {fwData?.slope_per_day !== undefined && n > 1 && (
              <div style={{ ...CARD, marginTop: 12, fontSize: 12 }}>
                <div style={{ color: C.muted, marginBottom: 6, textTransform: "uppercase", letterSpacing: 0.7, fontSize: 11 }}>
                  Regression Details
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ color: C.muted }}>Slope / day</span>
                  <span style={{
                    color: fwData.slope_per_day > 0 ? C.accent : fwData.slope_per_day < 0 ? C.red : C.muted,
                    fontFamily: "monospace",
                  }}>
                    {fwData.slope_per_day > 0 ? "+" : ""}{fwData.slope_per_day?.toFixed(4)}
                  </span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: C.muted }}>R² (fit quality)</span>
                  <span style={{
                    color: fwData.r_squared >= 0.7 ? C.accent : fwData.r_squared >= 0.4 ? C.orange : C.muted,
                    fontFamily: "monospace",
                  }}>
                    {fwData.r_squared?.toFixed(3)}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
