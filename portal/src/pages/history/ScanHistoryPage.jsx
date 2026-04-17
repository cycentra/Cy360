/**
 * src/pages/history/ScanHistoryPage.jsx
 * =========================================
 * Scan Timeline — last 15 scans shown as:
 *  1. SVG line graph  (findings: total / critical / high + subdomains)
 *  2. Bar chart       (stacked severity per scan)
 *  3. Scan list table (click any row to load that scan)
 */

import { useState } from "react";

const TYPE_COLOR = { deep: "#b06eff", standard: "#00e5a0", passive: "#4d9eff" };
const TYPE_LABEL = { deep: "DEEP", standard: "STD", passive: "PASS" };

function fmtDate(ts) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString("en-US", {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}
function fmtShort(ts) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString("en-US", { month: "short", day: "numeric" });
}

// ── SVG Line Graph ────────────────────────────────────────────────────────────
function LineGraph({ scans, selectedScanId, onScanSelect }) {
  const [tooltip, setTooltip] = useState(null);

  const W = 820, H = 200, PAD = { top: 20, right: 20, bottom: 36, left: 44 };
  const innerW = W - PAD.left - PAD.right;
  const innerH = H - PAD.top  - PAD.bottom;

  // chronological order (oldest → newest)
  const pts = [...scans].reverse();
  const n   = pts.length;
  if (n === 0) return null;

  const maxFindings = Math.max(...pts.map(s => s.total_findings || 0), 1);
  const maxSubs     = Math.max(...pts.map(s => s.subdomains     || 0), 1);
  const overallMax  = Math.max(maxFindings, maxSubs, 1);

  // map value → y pixel
  const yScale = v => PAD.top + innerH - (v / overallMax) * innerH;
  // map index → x pixel
  const xScale = i => PAD.left + (n === 1 ? innerW / 2 : (i / (n - 1)) * innerW);

  function smoothPath(key) {
    if (n === 1) {
      const x = xScale(0), y = yScale(pts[0][key] || 0);
      return `M ${x} ${y}`;
    }
    const points = pts.map((s, i) => ({ x: xScale(i), y: yScale(s[key] || 0) }));
    let d = `M ${points[0].x} ${points[0].y}`;
    for (let i = 1; i < points.length; i++) {
      const cp1x = (points[i - 1].x + points[i].x) / 2;
      const cp2x = cp1x;
      d += ` C ${cp1x} ${points[i - 1].y} ${cp2x} ${points[i].y} ${points[i].x} ${points[i].y}`;
    }
    return d;
  }

  // Y-axis gridlines (4 ticks)
  const ticks = [0, 0.25, 0.5, 0.75, 1].map(f => ({
    value: Math.round(overallMax * f),
    y: yScale(overallMax * f),
  }));

  const lines = [
    { key: "total_findings", color: "#00e5a0", label: "Total Findings", dashed: false },
    { key: "critical",       color: "#ff3b3b", label: "Critical",       dashed: false },
    { key: "high",           color: "#ff8c00", label: "High",           dashed: false },
    { key: "subdomains",     color: "#4d9eff", label: "Subdomains",     dashed: true  },
  ];

  return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "18px 22px", marginBottom: 18, overflowX: "auto" }}>
      <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px", marginBottom: 10 }}>
        FINDINGS &amp; SUBDOMAINS — TREND LINE GRAPH
      </div>

      <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ display: "block", fontFamily: "monospace" }}>
        {/* Gridlines */}
        {ticks.map(t => (
          <g key={t.value}>
            <line x1={PAD.left} y1={t.y} x2={W - PAD.right} y2={t.y}
              stroke="rgba(255,255,255,0.05)" strokeWidth="1" strokeDasharray="3 4"/>
            <text x={PAD.left - 6} y={t.y + 4} textAnchor="end" fill="rgba(255,255,255,0.2)" fontSize="9">{t.value}</text>
          </g>
        ))}

        {/* Lines */}
        {lines.map(({ key, color, dashed }) => (
          <path key={key}
            d={smoothPath(key)}
            fill="none"
            stroke={color}
            strokeWidth={key === "total_findings" ? 2 : 1.5}
            strokeDasharray={dashed ? "5 3" : undefined}
            opacity={key === "total_findings" ? 1 : 0.7}
          />
        ))}

        {/* Area fill under total_findings */}
        <path
          d={smoothPath("total_findings") + ` L ${xScale(n - 1)} ${PAD.top + innerH} L ${xScale(0)} ${PAD.top + innerH} Z`}
          fill="rgba(0,229,160,0.04)"
        />

        {/* Data points + hover targets */}
        {pts.map((s, i) => {
          const isActive = s.scan_id === selectedScanId;
          const cx = xScale(i);
          const cy = yScale(s.total_findings || 0);
          return (
            <g key={s.scan_id}>
              {/* invisible hit area */}
              <rect
                x={cx - 12} y={PAD.top} width={24} height={innerH}
                fill="transparent"
                style={{ cursor: "pointer" }}
                onMouseEnter={() => setTooltip({ i, x: cx, y: cy, s })}
                onMouseLeave={() => setTooltip(null)}
                onClick={() => onScanSelect(s.scan_id)}
              />
              {/* vertical guide on hover / active */}
              {(isActive || (tooltip && tooltip.i === i)) && (
                <line x1={cx} y1={PAD.top} x2={cx} y2={PAD.top + innerH}
                  stroke="rgba(255,255,255,0.08)" strokeWidth="1" strokeDasharray="3 3"/>
              )}
              {/* dot */}
              <circle cx={cx} cy={cy} r={isActive ? 5 : 3.5}
                fill={isActive ? "#00e5a0" : "#0d1117"}
                stroke={isActive ? "#00e5a0" : "rgba(0,229,160,0.5)"}
                strokeWidth={isActive ? 2 : 1.5}
                style={{ cursor: "pointer" }}
                onMouseEnter={() => setTooltip({ i, x: cx, y: cy, s })}
                onMouseLeave={() => setTooltip(null)}
                onClick={() => onScanSelect(s.scan_id)}
              />
              {/* critical dot */}
              {(s.critical || 0) > 0 && (
                <circle cx={cx} cy={yScale(s.critical)} r={2.5}
                  fill="#ff3b3b" stroke="#0d1117" strokeWidth={1}/>
              )}
              {/* subdomain dot */}
              <circle cx={cx} cy={yScale(s.subdomains || 0)} r={2.5}
                fill="#4d9eff" stroke="#0d1117" strokeWidth={1}/>
            </g>
          );
        })}

        {/* X-axis labels */}
        {pts.map((s, i) => (
          <text key={s.scan_id} x={xScale(i)} y={H - 6}
            textAnchor="middle"
            fill={s.scan_id === selectedScanId ? "#00e5a0" : "rgba(255,255,255,0.18)"}
            fontSize="9">
            {fmtShort(s.last_scan)}
          </text>
        ))}

        {/* Tooltip */}
        {tooltip && (() => {
          const { x, y, s } = tooltip;
          const tx = x + 12 > W - 140 ? x - 142 : x + 12;
          const ty = Math.max(PAD.top + 4, Math.min(y - 50, PAD.top + innerH - 100));
          return (
            <g>
              <rect x={tx} y={ty} width={130} height={90} rx="4"
                fill="#0d1117" stroke="rgba(255,255,255,0.12)" strokeWidth="1"/>
              <text x={tx + 8} y={ty + 15} fill="rgba(255,255,255,0.5)" fontSize="8">{fmtShort(s.last_scan)}</text>
              <text x={tx + 8} y={ty + 27} fill="rgba(255,255,255,0.3)" fontSize="8">{s.domain || ""}</text>
              <text x={tx + 8} y={ty + 44} fill="#00e5a0"   fontSize="9">Findings:   {s.total_findings || 0}</text>
              <text x={tx + 8} y={ty + 57} fill="#ff3b3b"   fontSize="9">Critical:   {s.critical || 0}</text>
              <text x={tx + 8} y={ty + 70} fill="#ff8c00"   fontSize="9">High:       {s.high || 0}</text>
              <text x={tx + 8} y={ty + 83} fill="#4d9eff"   fontSize="9">Subdomains: {s.subdomains || 0}</text>
            </g>
          );
        })()}
      </svg>

      {/* Legend */}
      <div style={{ display: "flex", gap: 16, marginTop: 6 }}>
        {lines.map(({ color, label, dashed }) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <svg width="20" height="8">
              <line x1="0" y1="4" x2="20" y2="4" stroke={color} strokeWidth="2"
                strokeDasharray={dashed ? "4 3" : undefined}/>
            </svg>
            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace" }}>{label}</span>
          </div>
        ))}
        <div style={{ marginLeft: "auto", color: "rgba(255,255,255,0.15)", fontSize: 9, fontFamily: "monospace" }}>
          Click any data point to load that scan
        </div>
      </div>
    </div>
  );
}

// ── Bar chart (stacked severity) ──────────────────────────────────────────────
function BarChart({ scans, selectedScanId, onScanSelect }) {
  const [hoveredId, setHoveredId] = useState(null);
  const maxTotal = Math.max(...scans.map(s => s.total_findings || 0), 1);
  const pts = [...scans].reverse();

  return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "18px 22px", marginBottom: 18 }}>
      <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px", marginBottom: 14 }}>
        FINDINGS PER SCAN — STACKED SEVERITY
      </div>
      <div style={{ display: "flex", alignItems: "flex-end", gap: 6, height: 80 }}>
        {pts.map((s, i) => {
          const total   = s.total_findings || 0;
          const barH    = maxTotal > 0 ? Math.max((total / maxTotal) * 72, total > 0 ? 4 : 0) : 0;
          const crit    = s.critical || 0;
          const high    = s.high     || 0;
          const rest    = total - crit - high;
          const isActive = s.scan_id === selectedScanId;
          const isHover  = s.scan_id === hoveredId;
          return (
            <div key={s.scan_id}
              title={`${fmtShort(s.last_scan)}\n${total} findings (${crit} critical, ${high} high)`}
              onClick={() => onScanSelect(s.scan_id)}
              onMouseEnter={() => setHoveredId(s.scan_id)}
              onMouseLeave={() => setHoveredId(null)}
              style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "flex-end", cursor: "pointer", position: "relative" }}>
              <div style={{ height: barH || 2, borderRadius: "2px 2px 0 0", overflow: "hidden",
                outline: isActive ? "1px solid #00e5a0" : isHover ? "1px solid rgba(255,255,255,0.2)" : "none",
                transition: "all 0.15s" }}>
                {total > 0 ? (
                  <>
                    {crit > 0 && <div style={{ height: `${(crit/total)*100}%`, background: "#ff3b3b" }}/>}
                    {high > 0 && <div style={{ height: `${(high/total)*100}%`, background: "#ff8c00" }}/>}
                    {rest > 0 && <div style={{ height: `${(rest/total)*100}%`, background: "#f5c518" }}/>}
                  </>
                ) : (
                  <div style={{ height: "100%", background: "rgba(0,229,160,0.2)" }}/>
                )}
              </div>
              {isActive && <div style={{ position: "absolute", top: -6, left: "50%", transform: "translateX(-50%)", width: 5, height: 5, borderRadius: "50%", background: "#00e5a0", boxShadow: "0 0 6px #00e5a0" }}/>}
            </div>
          );
        })}
      </div>
      <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
        {pts.map(s => (
          <div key={s.scan_id} style={{ flex: 1, textAlign: "center",
            color: s.scan_id === selectedScanId ? "#00e5a0" : "rgba(255,255,255,0.15)",
            fontSize: 8, fontFamily: "monospace" }}>
            {new Date(s.last_scan).toLocaleDateString("en-US", { month: "numeric", day: "numeric" })}
          </div>
        ))}
      </div>
      <div style={{ display: "flex", gap: 14, marginTop: 10 }}>
        {[["#ff3b3b","Critical"],["#ff8c00","High"],["#f5c518","Other"]].map(([c,l]) => (
          <div key={l} style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <div style={{ width: 8, height: 8, borderRadius: 1, background: c }}/>
            <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace" }}>{l}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Findings bar (for table) ──────────────────────────────────────────────────
function FindingBar({ scan, maxTotal }) {
  const total = scan.total_findings || 0;
  const crit  = scan.critical       || 0;
  const high  = scan.high           || 0;
  const rest  = total - crit - high;
  const pct   = maxTotal > 0 ? (total / maxTotal) * 100 : 0;
  const segs  = [
    { count: crit, color: "#ff3b3b" },
    { count: high, color: "#ff8c00" },
    { count: rest > 0 ? rest : 0, color: "#f5c518" },
  ].filter(s => s.count > 0);
  const barTotal = segs.reduce((a, s) => a + s.count, 0) || 1;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
      <div style={{ display: "flex", height: 8, borderRadius: 2, overflow: "hidden",
        width: `${Math.max(pct, 2)}%`, minWidth: total > 0 ? 8 : 0 }}>
        {segs.map((s, i) => (
          <div key={i} style={{ width: `${(s.count / barTotal) * 100}%`, background: s.color }}/>
        ))}
      </div>
      <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace" }}>{total} findings</div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export function ScanHistoryPage({ scanHistory, selectedScanId, onScanSelect, historyLoading }) {
  const [hoveredId, setHoveredId] = useState(null);

  const maxTotal = Math.max(...(scanHistory || []).map(s => s.total_findings || 0), 1);

  if (historyLoading) {
    return (
      <div style={{ padding: "60px 0", textAlign: "center", color: "rgba(255,255,255,0.25)", fontFamily: "monospace", fontSize: 13 }}>
        Loading scan history…
      </div>
    );
  }

  if (!scanHistory || scanHistory.length === 0) {
    return (
      <div>
        <div style={{ marginBottom: 22 }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: "white" }}>Scan Timeline</h1>
          <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13, marginTop: 4 }}>Historical scan results</p>
        </div>
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "48px 24px", textAlign: "center" }}>
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, fontFamily: "monospace" }}>
            No scan history found. Run your first scan to start tracking changes over time.
          </div>
        </div>
      </div>
    );
  }

  const newest = scanHistory[0];
  const oldest = scanHistory[scanHistory.length - 1];
  const findingDelta = (newest.total_findings || 0) - (oldest.total_findings || 0);
  const subDelta     = (newest.subdomains     || 0) - (oldest.subdomains     || 0);

  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 22 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: "white" }}>Scan Timeline</h1>
          <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13, marginTop: 4 }}>
            {scanHistory.length} scan{scanHistory.length !== 1 ? "s" : ""} · click any point or row to load that scan
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {[
            { label: "FINDINGS TREND",   delta: findingDelta, pos: "#ff3b3b", neg: "#00e5a0" },
            { label: "SUBDOMAIN TREND",  delta: subDelta,     pos: "#ff8c00", neg: "#00e5a0" },
          ].map(({ label, delta, pos, neg }) => (
            <div key={label} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 4, padding: "6px 12px", textAlign: "center" }}>
              <div style={{ color: delta > 0 ? pos : delta < 0 ? neg : "rgba(255,255,255,0.4)", fontSize: 16, fontFamily: "monospace", fontWeight: 700 }}>
                {delta > 0 ? `+${delta}` : delta}
              </div>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* SVG line graph */}
      <LineGraph scans={scanHistory} selectedScanId={selectedScanId} onScanSelect={onScanSelect}/>

      {/* Stacked bar chart */}
      <BarChart scans={scanHistory} selectedScanId={selectedScanId} onScanSelect={onScanSelect}/>

      {/* Scan list table */}
      <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 80px 1fr 80px 80px 100px",
          padding: "10px 18px", borderBottom: "1px solid rgba(255,255,255,0.06)",
          color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace", letterSpacing: "1.2px", textTransform: "uppercase" }}>
          <span>Date / Scan ID</span>
          <span>Type</span>
          <span>Findings</span>
          <span style={{ textAlign: "right" }}>Subdomains</span>
          <span style={{ textAlign: "right" }}>Critical</span>
          <span style={{ textAlign: "right" }}>Status</span>
        </div>

        {scanHistory.map((s) => {
          const isSelected = s.scan_id === selectedScanId;
          const tc   = TYPE_COLOR[s.scan_type] || "#00e5a0";
          const crit = s.critical || 0;
          return (
            <div key={s.scan_id}
              onClick={() => onScanSelect(s.scan_id)}
              onMouseEnter={() => setHoveredId(s.scan_id)}
              onMouseLeave={() => setHoveredId(null)}
              style={{
                display: "grid", gridTemplateColumns: "1fr 80px 1fr 80px 80px 100px",
                padding: "14px 18px", cursor: "pointer", alignItems: "center",
                borderBottom: "1px solid rgba(255,255,255,0.04)",
                background: isSelected
                  ? "rgba(0,229,160,0.05)"
                  : hoveredId === s.scan_id
                    ? "rgba(255,255,255,0.03)"
                    : i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)",
                borderLeft: isSelected ? "2px solid #00e5a0" : "2px solid transparent",
                transition: "background 0.12s",
              }}>
              <div>
                <div style={{ color: isSelected ? "#00e5a0" : "rgba(255,255,255,0.8)", fontSize: 12, fontFamily: "monospace", fontWeight: isSelected ? 700 : 400 }}>
                  {fmtDate(s.last_scan)}
                </div>
                <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>
                  {s.scan_id}
                  {i === 0 && !isSelected && <span style={{ marginLeft: 6, color: "#4d9eff", fontSize: 9 }}>LATEST</span>}
                  {isSelected && <span style={{ marginLeft: 6, color: "#00e5a0", fontSize: 9 }}>● ACTIVE</span>}
                </div>
                <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, marginTop: 2 }}>{s.domain}</div>
              </div>

              <div>
                <span style={{ background: `${tc}15`, color: tc, border: `1px solid ${tc}30`, fontSize: 9, fontFamily: "monospace", fontWeight: 700, padding: "2px 6px", borderRadius: 2 }}>
                  {TYPE_LABEL[s.scan_type] || (s.scan_type || "").toUpperCase().slice(0, 4) || "—"}
                </span>
              </div>

              <FindingBar scan={s} maxTotal={maxTotal}/>

              <div style={{ textAlign: "right" }}>
                <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 12, fontFamily: "monospace" }}>{s.subdomains || 0}</span>
              </div>

              <div style={{ textAlign: "right" }}>
                <span style={{ color: crit > 0 ? "#ff3b3b" : "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace", fontWeight: crit > 0 ? 700 : 400 }}>
                  {crit > 0 ? `▲ ${crit}` : "—"}
                </span>
              </div>

              <div style={{ textAlign: "right" }}>
                {isSelected
                  ? <span style={{ color: "#00e5a0", fontSize: 10, fontFamily: "monospace" }}>● Loaded</span>
                  : <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>Load ↗</span>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
