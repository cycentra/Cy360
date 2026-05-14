/**
 * RiskHeatmapPage.jsx
 * ====================
 * 5x5 risk heatmap grid. Color-coded by risk count per cell.
 * Tooltip shows risk list on hover.
 */

import { useState, useEffect } from "react";
import { API_BASE } from "../../core/constants.js";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};

function cellColor(count, impact, likelihood) {
  const score = (impact + 1) * (likelihood + 1);
  if (count === 0) return "rgba(255,255,255,0.03)";
  if (score >= 20) return count > 0 ? "rgba(255,59,59,0.45)" : "rgba(255,59,59,0.12)";
  if (score >= 12) return count > 0 ? "rgba(255,140,0,0.45)" : "rgba(255,140,0,0.12)";
  if (score >= 6)  return count > 0 ? "rgba(77,158,255,0.35)" : "rgba(77,158,255,0.10)";
  return count > 0 ? "rgba(0,229,160,0.25)" : "rgba(0,229,160,0.06)";
}

const LABELS  = ["1", "2", "3", "4", "5"];
const I_LABELS = ["Very Low", "Low", "Medium", "High", "Very High"];

export function RiskHeatmapPage() {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [tooltip, setTooltip] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/api/comp/risks/heatmap`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  if (loading) return (
    <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12, padding: 40 }}>
      Loading heatmap...
    </div>
  );

  const grid    = data?.grid || Array(5).fill(null).map(() => Array(5).fill([]));
  const summary = data?.summary || {};

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px", fontFamily: "monospace",
          textTransform: "uppercase", marginBottom: 4 }}>SECURITY COMPLIANCE</div>
        <h1 style={{ color: C.text, fontSize: 20, fontWeight: 700, margin: 0 }}>Risk Heatmap</h1>
        <div style={{ color: C.muted, fontSize: 11, marginTop: 4, fontFamily: "monospace" }}>
          {summary.total || 0} active risks
        </div>
      </div>

      {/* Summary stats */}
      <div style={{ display: "flex", gap: 16, marginBottom: 28 }}>
        {[
          { label: "Critical", count: summary.critical, color: C.red },
          { label: "High",     count: summary.high,     color: C.orange },
          { label: "Medium",   count: summary.medium,   color: C.blue },
          { label: "Low",      count: summary.low,      color: C.muted },
        ].map(({ label, count, color }) => (
          <div key={label} style={{ background: "#0d1117", border: `1px solid ${C.border}`,
            borderRadius: 6, padding: "12px 20px", minWidth: 100 }}>
            <div style={{ color, fontSize: 24, fontFamily: "monospace", fontWeight: 700 }}>
              {count || 0}
            </div>
            <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
              textTransform: "uppercase", letterSpacing: "1px" }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Heatmap grid */}
      <div style={{ display: "flex", gap: 24 }}>
        {/* Y axis label */}
        <div style={{ display: "flex", flexDirection: "column", justifyContent: "center",
          alignItems: "center", gap: 8, paddingTop: 32 }}>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
            textTransform: "uppercase", letterSpacing: "1px",
            writingMode: "vertical-rl", transform: "rotate(180deg)" }}>
            Impact
          </div>
        </div>

        <div>
          {/* Grid with Y labels */}
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {[4, 3, 2, 1, 0].map(im => (
              <div key={im} style={{ display: "flex", gap: 4, alignItems: "center" }}>
                <div style={{ width: 72, color: C.muted, fontSize: 9, fontFamily: "monospace",
                  textAlign: "right", paddingRight: 8 }}>
                  {I_LABELS[im]}
                </div>
                {[0, 1, 2, 3, 4].map(li => {
                  const cell = grid[im]?.[li] || [];
                  return (
                    <div key={li}
                      onMouseEnter={e => cell.length > 0 && setTooltip({ im, li, risks: cell, rect: e.currentTarget.getBoundingClientRect() })}
                      onMouseLeave={() => setTooltip(null)}
                      style={{
                        width: 88, height: 72, borderRadius: 6, cursor: cell.length > 0 ? "pointer" : "default",
                        background: cellColor(cell.length, im, li),
                        border: `1px solid rgba(255,255,255,0.06)`,
                        display: "flex", alignItems: "center", justifyContent: "center",
                        flexDirection: "column", gap: 4,
                        transition: "transform 0.15s",
                      }}>
                      {cell.length > 0 && (
                        <>
                          <div style={{ color: "white", fontSize: 22, fontFamily: "monospace",
                            fontWeight: 700, lineHeight: 1 }}>{cell.length}</div>
                          <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 9,
                            fontFamily: "monospace" }}>risk{cell.length > 1 ? "s" : ""}</div>
                        </>
                      )}
                    </div>
                  );
                })}
              </div>
            ))}

            {/* X axis labels */}
            <div style={{ display: "flex", gap: 4, marginTop: 4, paddingLeft: 80 }}>
              {LABELS.map((l, i) => (
                <div key={i} style={{ width: 88, textAlign: "center", color: C.muted,
                  fontSize: 9, fontFamily: "monospace" }}>{l}</div>
              ))}
            </div>
            <div style={{ paddingLeft: 80, textAlign: "center", color: C.muted,
              fontSize: 9, fontFamily: "monospace", textTransform: "uppercase",
              letterSpacing: "1px", marginTop: 4 }}>
              Likelihood
            </div>
          </div>
        </div>

        {/* Legend */}
        <div style={{ display: "flex", flexDirection: "column", gap: 8, paddingTop: 8, paddingLeft: 16 }}>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
            textTransform: "uppercase", letterSpacing: "1px", marginBottom: 6 }}>Legend</div>
          {[
            { label: "Critical (score 20-25)", color: "rgba(255,59,59,0.45)" },
            { label: "High (score 12-19)",     color: "rgba(255,140,0,0.45)" },
            { label: "Medium (score 6-11)",    color: "rgba(77,158,255,0.35)" },
            { label: "Low (score 1-5)",        color: "rgba(0,229,160,0.25)" },
            { label: "Empty",                  color: "rgba(255,255,255,0.03)" },
          ].map(({ label, color }) => (
            <div key={label} style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{ width: 16, height: 16, background: color, borderRadius: 3,
                border: "1px solid rgba(255,255,255,0.06)" }} />
              <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>{label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div style={{
          position: "fixed",
          top: (tooltip.rect?.top || 0) - 10,
          left: (tooltip.rect?.right || 0) + 10,
          background: "#0d1117", border: `1px solid ${C.border}`,
          borderRadius: 6, padding: 14, zIndex: 999, minWidth: 200,
          boxShadow: "0 8px 24px rgba(0,0,0,0.6)",
        }}>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
            textTransform: "uppercase", letterSpacing: "1px", marginBottom: 8 }}>
            {tooltip.risks.length} Risk{tooltip.risks.length > 1 ? "s" : ""}
          </div>
          {tooltip.risks.slice(0, 8).map(r => (
            <div key={r.id} style={{ color: C.text, fontSize: 11, fontFamily: "monospace",
              marginBottom: 4, paddingBottom: 4, borderBottom: `1px solid rgba(255,255,255,0.04)` }}>
              <span style={{ color: C.orange, marginRight: 6 }}>{r.score}/25</span>
              {r.title}
            </div>
          ))}
          {tooltip.risks.length > 8 && (
            <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>
              +{tooltip.risks.length - 8} more
            </div>
          )}
        </div>
      )}
    </div>
  );
}
