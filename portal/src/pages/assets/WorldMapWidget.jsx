/**
 * src/pages/assets/WorldMapWidget.jsx
 * =====================================
 * Shows asset IPs as geo-located dots on a simplified SVG world map.
 * Uses /api/system/geoip (backend proxies to ipwho.is, no external key needed).
 * Zero npm dependencies — pure React + SVG + equirectangular projection.
 */

import { useState, useEffect, useCallback } from "react";
import { API_BASE, RISK_CONFIG } from "../../core/constants.js";

// ── Map dimensions (equirectangular / plate carrée projection) ────────────────
const W = 800;
const H = 380;

// Map lon/lat → SVG x/y
function project(lon, lat) {
  const x = ((lon + 180) / 360) * W;
  const y = ((90 - lat) / 180) * H;
  return [x, y];
}

// ── Simplified continent SVG paths (equirectangular projection) ───────────────
// Approximate outlines — sufficient for a geospatial dashboard indicator.
const CONTINENT_PATHS = [
  // North America
  { id: "na", d: "M27,56 L38,67 L100,80 L133,130 L160,155 L202,165 L220,145 L282,96 L222,38 Z" },
  // South America
  { id: "sa", d: "M227,182 L264,176 L322,211 L311,251 L282,278 L256,322 L240,300 L218,211 Z" },
  // Europe
  { id: "eu", d: "M351,58 L456,42 L467,67 L464,109 L458,118 L427,120 L380,118 L389,71 Z" },
  // Africa
  { id: "af", d: "M385,120 L427,115 L476,131 L513,176 L473,260 L440,276 L427,240 L362,153 Z" },
  // Asia
  { id: "as", d: "M458,107 L467,44 L689,40 L778,56 L762,87 L689,131 L631,196 L578,182 L551,149 L507,173 L480,120 Z" },
  // Australia
  { id: "au", d: "M653,249 L691,227 L722,224 L736,276 L704,280 L653,278 Z" },
  // Greenland (approximate)
  { id: "gl", d: "M230,22 L275,18 L285,35 L260,50 L225,42 Z" },
  // UK + Ireland (approximate)
  { id: "uk", d: "M364,72 L374,68 L378,80 L368,86 Z" },
  // Japan (approximate)
  { id: "jp", d: "M720,100 L730,92 L735,108 L724,115 Z" },
  // New Zealand (approximate)
  { id: "nz", d: "M782,310 L790,300 L795,316 L785,322 Z" },
];

// ── Tooltip component ─────────────────────────────────────────────────────────
function Tooltip({ dot, mapWidth }) {
  if (!dot) return null;
  // Keep tooltip inside SVG bounds
  const [bx, by] = dot.xy;
  const tx = bx > mapWidth * 0.7 ? bx - 135 : bx + 12;
  const ty = by < 60 ? by + 12 : by - 52;
  return (
    <g>
      <rect x={tx} y={ty} width={130} height={48} rx={3}
        fill="rgba(10,12,18,0.92)" stroke="rgba(255,255,255,0.12)" strokeWidth={0.8}/>
      <text x={tx + 8} y={ty + 14} fill={RISK_CONFIG[dot.risk]?.color || "#00e5a0"} fontSize={9} fontFamily="monospace" fontWeight={700}>
        {dot.host}
      </text>
      <text x={tx + 8} y={ty + 26} fill="rgba(255,255,255,0.55)" fontSize={8} fontFamily="monospace">
        {dot.ip}
      </text>
      <text x={tx + 8} y={ty + 38} fill="rgba(255,255,255,0.35)" fontSize={8} fontFamily="monospace">
        {dot.flag} {dot.city}{dot.city && dot.country ? ", " : ""}{dot.country}
      </text>
    </g>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// Main component
// ════════════════════════════════════════════════════════════════════════════

export function WorldMapWidget({ assets }) {
  const [geoMap,   setGeoMap]   = useState({});   // ip → {lat,lon,country,city,flag}
  const [loading,  setLoading]  = useState(false);
  const [tooltip,  setTooltip]  = useState(null); // dot being hovered

  // Collect unique non-private IPs from primary assets
  const uniqueIPs = [...new Set(
    assets
      .filter(a => a.tags?.includes("primary") && a.ip && a.ip !== "—")
      .map(a => a.ip)
  )];

  const fetchGeo = useCallback(async () => {
    if (!uniqueIPs.length) return;
    setLoading(true);
    try {
      const r = await fetch(`${API_BASE}/api/system/geoip`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ips: uniqueIPs }),
      });
      const d = await r.json();
      setGeoMap(d.results || {});
    } catch {}
    setLoading(false);
  }, [uniqueIPs.join(",")]);   // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { fetchGeo(); }, [fetchGeo]);

  // Build dot list: one dot per primary asset with known geo
  const dots = assets
    .filter(a => a.tags?.includes("primary") && geoMap[a.ip])
    .map(a => {
      const geo = geoMap[a.ip];
      return {
        id:      a.id,
        host:    a.host,
        ip:      a.ip,
        risk:    a.risk,
        ...geo,
        xy:      project(geo.lon, geo.lat),
      };
    });

  // Group overlapping dots (same IP co-located assets)
  const dotsByIP = {};
  dots.forEach(d => {
    if (!dotsByIP[d.ip]) dotsByIP[d.ip] = [];
    dotsByIP[d.ip].push(d);
  });
  const uniqueDots = Object.values(dotsByIP).map(group => ({
    ...group[0],
    count: group.length,
    hosts: group.map(g => g.host),
  }));

  const riskColor = (risk) => RISK_CONFIG[risk]?.color || "#00e5a0";

  return (
    <div style={{ background: "rgba(255,255,255,0.015)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "16px 20px", marginBottom: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div>
          <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, letterSpacing: "1.5px", fontFamily: "monospace", textTransform: "uppercase" }}>
            Asset Geo-Location
          </div>
          <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, marginTop: 2 }}>
            {uniqueDots.length} location{uniqueDots.length !== 1 ? "s" : ""} discovered
            {loading && <span style={{ color: "rgba(255,255,255,0.25)", marginLeft: 8 }}>resolving IPs…</span>}
          </div>
        </div>
        <button onClick={fetchGeo} disabled={loading}
          style={{ background: "none", border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.3)", borderRadius: 4, padding: "4px 10px", fontFamily: "monospace", fontSize: 10, cursor: "pointer" }}>
          Refresh
        </button>
      </div>

      <div style={{ borderRadius: 4, overflow: "hidden", background: "#060810" }}>
        <svg
          viewBox={`0 0 ${W} ${H}`}
          style={{ width: "100%", height: "auto", display: "block" }}
          onMouseLeave={() => setTooltip(null)}
        >
          {/* Ocean background */}
          <rect width={W} height={H} fill="#060810"/>

          {/* Latitude grid lines */}
          {[-60,-30,0,30,60].map(lat => {
            const [,y] = project(0, lat);
            return (
              <line key={lat} x1={0} y1={y} x2={W} y2={y}
                stroke="rgba(255,255,255,0.04)" strokeWidth={0.5}
                strokeDasharray={lat === 0 ? "3,3" : "1,4"}/>
            );
          })}
          {/* Longitude grid lines */}
          {[-120,-60,0,60,120].map(lon => {
            const [x] = project(lon, 0);
            return <line key={lon} x1={x} y1={0} x2={x} y2={H}
              stroke="rgba(255,255,255,0.04)" strokeWidth={0.5} strokeDasharray="1,4"/>;
          })}

          {/* Continent shapes */}
          {CONTINENT_PATHS.map(c => (
            <path key={c.id} d={c.d}
              fill="rgba(255,255,255,0.055)"
              stroke="rgba(255,255,255,0.12)"
              strokeWidth={0.6}/>
          ))}

          {/* Asset dots */}
          {uniqueDots.map(dot => {
            const [x, y] = dot.xy;
            const color  = riskColor(dot.risk);
            const r      = dot.count > 1 ? 7 : 5;
            const isHover = tooltip?.id === dot.id;
            return (
              <g key={dot.id}
                style={{ cursor: "pointer" }}
                onMouseEnter={() => setTooltip(dot)}
                onMouseLeave={() => setTooltip(null)}>
                {/* Pulse ring */}
                <circle cx={x} cy={y} r={r + 4}
                  fill="none" stroke={color} strokeWidth={0.8} opacity={isHover ? 0.5 : 0.2}/>
                {/* Main dot */}
                <circle cx={x} cy={y} r={r} fill={color} opacity={isHover ? 1 : 0.85}
                  style={{ filter: `drop-shadow(0 0 4px ${color})` }}/>
                {/* Count badge for co-located */}
                {dot.count > 1 && (
                  <text x={x} y={y + 4} textAnchor="middle" fill="#0d0f14"
                    fontSize={6} fontFamily="monospace" fontWeight={700}>{dot.count}</text>
                )}
              </g>
            );
          })}

          {/* Tooltip */}
          {tooltip && <Tooltip dot={tooltip} mapWidth={W}/>}

          {/* Empty state overlay */}
          {!loading && uniqueDots.length === 0 && (
            <text x={W/2} y={H/2} textAnchor="middle" fill="rgba(255,255,255,0.15)"
              fontSize={12} fontFamily="monospace">
              No resolved IPs — scan data needed
            </text>
          )}
        </svg>
      </div>

      {/* Legend */}
      <div style={{ display: "flex", gap: 16, marginTop: 10 }}>
        {["critical","high","medium","low"].map(r => (
          <div key={r} style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: RISK_CONFIG[r].color, display: "inline-block" }}/>
            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", textTransform: "uppercase" }}>{r}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
