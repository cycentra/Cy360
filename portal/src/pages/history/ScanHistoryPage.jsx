/**
 * src/pages/history/ScanHistoryPage.jsx
 * =========================================
 * Scan Timeline — SVG line graph + stacked bar chart + scan list table.
 */

import { useState } from "react";

const TYPE_COLOR = { deep: "#b06eff", standard: "#00e5a0", passive: "#4d9eff" };
const TYPE_LABEL = { deep: "DEEP", standard: "STD", passive: "PASS" };

function fmtDate(ts) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" }); }
  catch { return "—"; }
}
function fmtShort(ts) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString("en-US", { month: "short", day: "numeric" }); }
  catch { return "—"; }
}

// ── Tooltip overlay (portal-style, avoids SVG clipping) ──────────────────────
function ScanTooltip({ tooltip }) {
  if (!tooltip) return null;
  const { screenX, screenY, s } = tooltip;
  return (
    <div style={{
      position: "fixed", left: screenX + 14, top: screenY - 10, zIndex: 9999,
      background: "#0d1117", border: "1px solid rgba(255,255,255,0.15)",
      borderRadius: 5, padding: "10px 12px", pointerEvents: "none",
      boxShadow: "0 6px 24px rgba(0,0,0,0.6)", minWidth: 150,
    }}>
      <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, fontFamily: "monospace", marginBottom: 4 }}>{fmtShort(s.last_scan)} · {s.domain || "—"}</div>
      {[
        ["Findings",   s.total_findings || 0, "#00e5a0"],
        ["Critical",   s.critical       || 0, "#ff3b3b"],
        ["High",       s.high           || 0, "#ff8c00"],
        ["Subdomains", s.subdomains     || 0, "#4d9eff"],
      ].map(([label, val, color]) => (
        <div key={label} style={{ display: "flex", justifyContent: "space-between", gap: 14, marginTop: 3 }}>
          <span style={{ color: "rgba(255,255,255,0.62)", fontSize: 11, fontFamily: "monospace" }}>{label}</span>
          <span style={{ color, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{val}</span>
        </div>
      ))}
    </div>
  );
}

// ── SVG Line Graph ────────────────────────────────────────────────────────────
function LineGraph({ scans, selectedScanId, onScanSelect }) {
  const [tooltip, setTooltip] = useState(null);

  if (!scans || scans.length === 0) return null;

  const pts = [...scans].reverse(); // oldest → newest
  const n   = pts.length;

  const W = 760, H = 190;
  const PAD = { top: 18, right: 18, bottom: 32, left: 40 };
  const iW  = W - PAD.left - PAD.right;
  const iH  = H - PAD.top  - PAD.bottom;

  const maxVal = Math.max(
    ...pts.map(s => Math.max(s.total_findings || 0, s.subdomains || 0)), 1
  );

  const xOf = i => PAD.left + (n < 2 ? iW / 2 : (i / (n - 1)) * iW);
  const yOf = v => PAD.top + iH - Math.min((v / maxVal) * iH, iH);

  function buildPath(key) {
    if (n < 2) return `M ${xOf(0)} ${yOf(pts[0][key] || 0)}`;
    return pts.map((s, i) => {
      const x = xOf(i), y = yOf(s[key] || 0);
      if (i === 0) return `M ${x} ${y}`;
      const px = xOf(i - 1), py = yOf(pts[i - 1][key] || 0);
      const cx = (px + x) / 2;
      return `C ${cx} ${py} ${cx} ${y} ${x} ${y}`;
    }).join(" ");
  }

  const totalPath = buildPath("total_findings");
  const areaPath  = totalPath + ` L ${xOf(n - 1)} ${PAD.top + iH} L ${xOf(0)} ${PAD.top + iH} Z`;

  // Y gridlines at 0%, 25%, 50%, 75%, 100%
  const gridTicks = [0, 0.25, 0.5, 0.75, 1].map(f => ({
    y:   yOf(maxVal * f),
    lbl: Math.round(maxVal * f),
  }));

  const SERIES = [
    { key: "total_findings", color: "#00e5a0", label: "Total Findings", width: 2,   dash: null },
    { key: "critical",       color: "#ff3b3b", label: "Critical",       width: 1.5, dash: null },
    { key: "high",           color: "#ff8c00", label: "High",           width: 1.5, dash: null },
    { key: "subdomains",     color: "#4d9eff", label: "Subdomains",     width: 1.5, dash: "5 3" },
  ];

  return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "18px 22px", marginBottom: 18 }}>
      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px", marginBottom: 10 }}>
        FINDINGS & SUBDOMAINS — TREND OVER TIME
      </div>

      <ScanTooltip tooltip={tooltip}/>

      <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", display: "block", overflow: "visible" }}>
        {/* Grid */}
        {gridTicks.map(t => (
          <g key={t.lbl}>
            <line x1={PAD.left} y1={t.y} x2={W - PAD.right} y2={t.y}
              stroke="rgba(255,255,255,0.05)" strokeWidth="1" strokeDasharray="3 4"/>
            <text x={PAD.left - 5} y={t.y + 4} textAnchor="end"
              fill="rgba(255,255,255,0.45)" fontSize="9" fontFamily="monospace">{t.lbl}</text>
          </g>
        ))}

        {/* Area fill under total findings */}
        <path d={areaPath} fill="rgba(0,229,160,0.05)"/>

        {/* Series lines */}
        {SERIES.map(s => (
          <path key={s.key} d={buildPath(s.key)} fill="none"
            stroke={s.color} strokeWidth={s.width}
            strokeDasharray={s.dash || undefined} opacity={s.key === "total_findings" ? 1 : 0.7}/>
        ))}

        {/* Dots + hit areas */}
        {pts.map((s, i) => {
          const cx = xOf(i);
          const active = s.scan_id === selectedScanId;
          return (
            <g key={s.scan_id || i}>
              {/* Vertical guide */}
              {active && (
                <line x1={cx} y1={PAD.top} x2={cx} y2={PAD.top + iH}
                  stroke="rgba(255,255,255,0.08)" strokeWidth="1" strokeDasharray="3 3"/>
              )}

              {/* Total findings dot */}
              <circle cx={cx} cy={yOf(s.total_findings || 0)} r={active ? 5 : 3.5}
                fill={active ? "#00e5a0" : "#0d1117"}
                stroke={active ? "#00e5a0" : "rgba(0,229,160,0.6)"}
                strokeWidth={active ? 2 : 1.5}
                style={{ cursor: "pointer" }}
                onClick={() => onScanSelect(s.scan_id)}/>

              {/* Critical dot */}
              {(s.critical || 0) > 0 && (
                <circle cx={cx} cy={yOf(s.critical)} r={2.5}
                  fill="#ff3b3b" stroke="#0d1117" strokeWidth={1}
                  style={{ pointerEvents: "none" }}/>
              )}

              {/* Subdomains dot */}
              <circle cx={cx} cy={yOf(s.subdomains || 0)} r={2.5}
                fill="#4d9eff" stroke="#0d1117" strokeWidth={1}
                style={{ pointerEvents: "none" }}/>

              {/* Invisible hit area */}
              <rect
                x={cx - 14} y={PAD.top} width={28} height={iH}
                fill="transparent" style={{ cursor: "pointer" }}
                onClick={() => onScanSelect(s.scan_id)}
                onMouseEnter={e => setTooltip({ screenX: e.clientX, screenY: e.clientY, s })}
                onMouseMove={e  => setTooltip(t => t ? { ...t, screenX: e.clientX, screenY: e.clientY } : null)}
                onMouseLeave={() => setTooltip(null)}
              />

              {/* Active scan indicator */}
              {active && (
                <circle cx={cx} cy={PAD.top - 7} r={3}
                  fill="#00e5a0" style={{ filter: "drop-shadow(0 0 4px #00e5a0)" }}/>
              )}
            </g>
          );
        })}

        {/* X-axis date labels */}
        {pts.map((s, i) => (
          <text key={s.scan_id || i} x={xOf(i)} y={H - 4} textAnchor="middle"
            fill={s.scan_id === selectedScanId ? "#00e5a0" : "rgba(255,255,255,0.45)"}
            fontSize="9" fontFamily="monospace">
            {fmtShort(s.last_scan)}
          </text>
        ))}
      </svg>

      {/* Legend */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 14, marginTop: 8 }}>
        {SERIES.map(s => (
          <div key={s.key} style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <svg width="18" height="8" style={{ flexShrink: 0 }}>
              <line x1="0" y1="4" x2="18" y2="4"
                stroke={s.color} strokeWidth="2" strokeDasharray={s.dash || undefined}/>
            </svg>
            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace" }}>{s.label}</span>
          </div>
        ))}
        <span style={{ marginLeft: "auto", color: "rgba(255,255,255,0.42)", fontSize: 9, fontFamily: "monospace" }}>
          click a point to load that scan
        </span>
      </div>
    </div>
  );
}

// ── Stacked bar chart ─────────────────────────────────────────────────────────
function BarChart({ scans, selectedScanId, onScanSelect }) {
  const [hoveredId, setHoveredId] = useState(null);
  const pts      = [...scans].reverse();
  const maxTotal = Math.max(...pts.map(s => s.total_findings || 0), 1);

  return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "18px 22px", marginBottom: 18 }}>
      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px", marginBottom: 14 }}>
        STACKED SEVERITY — FINDINGS PER SCAN
      </div>
      <div style={{ display: "flex", alignItems: "flex-end", gap: 5, height: 80 }}>
        {pts.map((s) => {
          const total    = s.total_findings || 0;
          const barH     = Math.max((total / maxTotal) * 72, total > 0 ? 4 : 2);
          const crit     = s.critical || 0;
          const high     = s.high     || 0;
          const rest     = Math.max(total - crit - high, 0);
          const isActive = s.scan_id === selectedScanId;
          const isHover  = s.scan_id === hoveredId;
          return (
            <div key={s.scan_id}
              onClick={() => onScanSelect(s.scan_id)}
              onMouseEnter={() => setHoveredId(s.scan_id)}
              onMouseLeave={() => setHoveredId(null)}
              title={`${fmtShort(s.last_scan)} · ${total} findings`}
              style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "flex-end", cursor: "pointer", position: "relative" }}>
              <div style={{
                height: barH, borderRadius: "2px 2px 0 0", overflow: "hidden",
                outline: isActive ? "1px solid #00e5a0" : isHover ? "1px solid rgba(255,255,255,0.2)" : "none",
                transition: "all 0.15s",
              }}>
                {total > 0 ? (
                  <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
                    {crit > 0 && <div style={{ flex: crit, background: "#ff3b3b" }}/>}
                    {high > 0 && <div style={{ flex: high, background: "#ff8c00" }}/>}
                    {rest > 0 && <div style={{ flex: rest, background: "#f5c518" }}/>}
                  </div>
                ) : (
                  <div style={{ height: "100%", background: "rgba(0,229,160,0.15)" }}/>
                )}
              </div>
              {isActive && (
                <div style={{ position: "absolute", top: -7, left: "50%", transform: "translateX(-50%)", width: 5, height: 5, borderRadius: "50%", background: "#00e5a0", boxShadow: "0 0 6px #00e5a0" }}/>
              )}
            </div>
          );
        })}
      </div>
      <div style={{ display: "flex", gap: 5, marginTop: 5 }}>
        {pts.map(s => (
          <div key={s.scan_id} style={{ flex: 1, textAlign: "center",
            color: s.scan_id === selectedScanId ? "#00e5a0" : "rgba(255,255,255,0.45)",
            fontSize: 8, fontFamily: "monospace" }}>
            {fmtShort(s.last_scan)}
          </div>
        ))}
      </div>
      <div style={{ display: "flex", gap: 14, marginTop: 10 }}>
        {[["#ff3b3b", "Critical"], ["#ff8c00", "High"], ["#f5c518", "Other"]].map(([c, l]) => (
          <div key={l} style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <div style={{ width: 8, height: 8, borderRadius: 1, background: c }}/>
            <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace" }}>{l}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Proportional finding bar (for table) ─────────────────────────────────────
function FindingBar({ scan, maxTotal }) {
  const total = scan.total_findings || 0;
  const crit  = scan.critical || 0;
  const high  = scan.high     || 0;
  const rest  = Math.max(total - crit - high, 0);
  const pct   = maxTotal > 0 ? (total / maxTotal) * 100 : 0;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
      <div style={{ display: "flex", height: 8, borderRadius: 2, overflow: "hidden", width: `${Math.max(pct, 2)}%`, minWidth: total > 0 ? 8 : 0 }}>
        {crit > 0 && <div style={{ flex: crit, background: "#ff3b3b" }}/>}
        {high > 0 && <div style={{ flex: high, background: "#ff8c00" }}/>}
        {rest > 0 && <div style={{ flex: rest, background: "#f5c518" }}/>}
      </div>
      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace" }}>{total} findings</div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export function ScanHistoryPage({ scanHistory, selectedScanId, onScanSelect, historyLoading }) {
  const [hoveredId, setHoveredId] = useState(null);

  if (historyLoading) {
    return (
      <div style={{ padding: "60px 0", textAlign: "center" }}>
        <div style={{ color: "#00e5a0", fontSize: 13, fontFamily: "monospace" }}>Loading scan history…</div>
      </div>
    );
  }

  if (!scanHistory || scanHistory.length === 0) {
    return (
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: "white", marginBottom: 8 }}>Scan Timeline</h1>
        <p style={{ color: "rgba(255,255,255,0.65)", fontSize: 13, marginBottom: 22 }}>Historical scan results — last 15 scans</p>
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 6, padding: "48px 24px", textAlign: "center" }}>
          <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 13, fontFamily: "monospace" }}>
            No scan history found. Run your first scan to start tracking changes over time.
          </div>
        </div>
      </div>
    );
  }

  const maxTotal     = Math.max(...scanHistory.map(s => s.total_findings || 0), 1);
  const newest       = scanHistory[0];
  const oldest       = scanHistory[scanHistory.length - 1];
  const findingDelta = (newest.total_findings || 0) - (oldest.total_findings || 0);
  const subDelta     = (newest.subdomains     || 0) - (oldest.subdomains     || 0);

  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 22 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: "white" }}>Scan Timeline</h1>
          <p style={{ color: "rgba(255,255,255,0.65)", fontSize: 13, marginTop: 4 }}>
            {scanHistory.length} scan{scanHistory.length !== 1 ? "s" : ""} · click any point or row to load that scan
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {[
            { label: "FINDINGS TREND",  delta: findingDelta, posColor: "#ff3b3b" },
            { label: "SUBDOMAIN TREND", delta: subDelta,     posColor: "#ff8c00" },
          ].map(({ label, delta, posColor }) => (
            <div key={label} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 4, padding: "6px 14px", textAlign: "center" }}>
              <div style={{ color: delta > 0 ? posColor : delta < 0 ? "#00e5a0" : "rgba(255,255,255,0.4)", fontSize: 18, fontFamily: "monospace", fontWeight: 700 }}>
                {delta > 0 ? `+${delta}` : delta}
              </div>
              <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Line graph */}
      <LineGraph scans={scanHistory} selectedScanId={selectedScanId} onScanSelect={onScanSelect}/>

      {/* Bar chart */}
      <BarChart scans={scanHistory} selectedScanId={selectedScanId} onScanSelect={onScanSelect}/>

      {/* Scan list table */}
      <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 70px 1fr 80px 80px 90px", padding: "10px 18px", borderBottom: "1px solid rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace", letterSpacing: "1.2px", textTransform: "uppercase" }}>
          <span>Date / Scan ID</span><span>Type</span><span>Findings</span>
          <span style={{ textAlign: "right" }}>Subdomains</span>
          <span style={{ textAlign: "right" }}>Critical</span>
          <span style={{ textAlign: "right" }}>Status</span>
        </div>

        {scanHistory.map((s, i) => {
          const isSelected = s.scan_id === selectedScanId;
          const tc         = TYPE_COLOR[s.scan_type] || "#00e5a0";
          const crit       = s.critical || 0;
          return (
            <div key={s.scan_id || i}
              onClick={() => onScanSelect(s.scan_id)}
              onMouseEnter={() => setHoveredId(s.scan_id)}
              onMouseLeave={() => setHoveredId(null)}
              style={{
                display: "grid", gridTemplateColumns: "1fr 70px 1fr 80px 80px 90px",
                padding: "13px 18px", cursor: "pointer", alignItems: "center",
                borderBottom: "1px solid rgba(255,255,255,0.04)",
                background: isSelected ? "rgba(0,229,160,0.05)" : hoveredId === s.scan_id ? "rgba(255,255,255,0.03)" : "transparent",
                borderLeft: isSelected ? "2px solid #00e5a0" : "2px solid transparent",
                transition: "background 0.12s",
              }}>
              <div>
                <div style={{ color: isSelected ? "#00e5a0" : "rgba(255,255,255,0.8)", fontSize: 12, fontFamily: "monospace", fontWeight: isSelected ? 700 : 400 }}>
                  {fmtDate(s.last_scan)}
                  {i === 0 && !isSelected && <span style={{ marginLeft: 8, color: "#4d9eff", fontSize: 9 }}>LATEST</span>}
                  {isSelected && <span style={{ marginLeft: 8, color: "#00e5a0", fontSize: 9 }}>● ACTIVE</span>}
                </div>
                <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>{s.scan_id}</div>
                <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, marginTop: 2 }}>{s.domain}</div>
              </div>

              <div>
                <span style={{ background: `${tc}15`, color: tc, border: `1px solid ${tc}30`, fontSize: 9, fontFamily: "monospace", fontWeight: 700, padding: "2px 6px", borderRadius: 2 }}>
                  {TYPE_LABEL[s.scan_type] || (s.scan_type || "").toUpperCase().slice(0, 4) || "—"}
                </span>
              </div>

              <FindingBar scan={s} maxTotal={maxTotal}/>

              <div style={{ textAlign: "right", color: "rgba(255,255,255,0.55)", fontSize: 12, fontFamily: "monospace" }}>{s.subdomains || 0}</div>

              <div style={{ textAlign: "right", color: crit > 0 ? "#ff3b3b" : "rgba(255,255,255,0.45)", fontSize: 12, fontFamily: "monospace", fontWeight: crit > 0 ? 700 : 400 }}>
                {crit > 0 ? `▲ ${crit}` : "—"}
              </div>

              <div style={{ textAlign: "right" }}>
                {isSelected
                  ? <span style={{ color: "#00e5a0", fontSize: 10, fontFamily: "monospace" }}>● Loaded</span>
                  : <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace" }}>Load ↗</span>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
