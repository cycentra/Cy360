/**
 * src/pages/assets/WorldMapWidget.jsx
 * =====================================
 * Animated SVG world map showing asset geo-locations.
 * Uses /api/system/geoip (backend proxies to ipwho.is).
 * Zero npm dependencies — pure React + SVG.
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { API_BASE, RISK_CONFIG } from "../../core/constants.js";

// ── Projection ──────────────────────────────────────────────────────────────
const W = 820, H = 400;
const project = (lon, lat) => [((lon + 180) / 360) * W, ((90 - lat) / 180) * H];

// ── Continent / landmass path data ──────────────────────────────────────────
// Equirectangular projection, viewBox 0 0 820 400
// More detailed than v1 — realistic continental silhouettes
const LAND = [
  // North America (main)
  { id:"na", d:"M 42,44 L 68,30 L 105,30 L 128,40 L 140,50 L 148,58 L 155,62 L 164,67 L 175,68 L 188,64 L 200,62 L 218,65 L 228,72 L 228,82 L 222,90 L 215,100 L 214,112 L 219,126 L 227,140 L 226,153 L 220,160 L 210,167 L 200,170 L 188,173 L 185,164 L 192,155 L 195,145 L 190,134 L 176,127 L 162,126 L 150,130 L 140,142 L 132,144 L 122,134 L 115,118 L 108,100 L 100,80 L 86,68 L 64,60 Z" },
  // Alaska peninsula (attached)
  { id:"ak", d:"M 42,44 L 64,60 L 55,60 L 42,57 L 28,55 L 22,60 L 28,72 L 38,75 L 42,68 Z" },
  // Central America / Yucatan
  { id:"ca", d:"M 200,170 L 210,167 L 218,168 L 220,178 L 212,182 L 204,182 L 198,178 Z" },
  // Greenland
  { id:"gl", d:"M 240,12 L 272,10 L 290,16 L 295,26 L 288,38 L 272,46 L 255,48 L 242,40 L 236,28 Z" },
  // Iceland
  { id:"ic", d:"M 340,50 L 352,46 L 358,52 L 352,58 L 340,58 Z" },
  // South America
  { id:"sa", d:"M 218,175 L 232,170 L 248,172 L 264,178 L 278,192 L 295,212 L 315,226 L 328,248 L 325,270 L 312,292 L 290,308 L 268,318 L 252,322 L 244,314 L 238,298 L 228,278 L 218,252 L 214,230 L 214,205 L 215,186 Z" },
  // Europe (western)
  { id:"eu", d:"M 358,55 L 370,48 L 384,44 L 396,44 L 405,48 L 404,56 L 398,65 L 390,72 L 383,80 L 383,88 L 390,94 L 405,92 L 420,88 L 435,82 L 445,75 L 452,65 L 456,54 L 462,46 L 470,40 L 458,34 L 442,32 L 424,33 L 408,36 L 394,38 L 382,42 L 370,44 Z" },
  // Scandinavia
  { id:"sc", d:"M 420,33 L 430,24 L 440,20 L 452,22 L 460,30 L 462,38 L 458,34 L 445,32 Z" },
  // UK & Ireland
  { id:"uk", d:"M 358,65 L 366,58 L 374,60 L 375,70 L 368,76 L 358,75 Z" },
  // Africa
  { id:"af", d:"M 365,110 L 382,104 L 405,106 L 428,108 L 448,114 L 466,125 L 480,142 L 495,162 L 510,185 L 516,210 L 514,236 L 505,260 L 490,278 L 468,292 L 448,300 L 430,296 L 415,282 L 406,262 L 398,240 L 390,215 L 380,188 L 370,164 L 362,140 L 360,122 Z" },
  // Madagascar
  { id:"mg", d:"M 525,260 L 530,250 L 536,255 L 535,270 L 528,275 Z" },
  // Middle East / Arabian Peninsula
  { id:"me", d:"M 466,105 L 488,100 L 510,105 L 522,120 L 525,138 L 516,148 L 508,152 L 495,148 L 484,138 L 474,125 Z" },
  // Asia (main continental)
  { id:"as", d:"M 466,105 L 474,88 L 468,72 L 465,55 L 468,42 L 476,36 L 492,32 L 520,28 L 560,26 L 602,26 L 644,28 L 678,32 L 708,36 L 730,40 L 750,44 L 762,50 L 772,56 L 778,65 L 772,76 L 760,83 L 746,88 L 732,93 L 718,100 L 705,112 L 692,126 L 674,138 L 656,148 L 640,158 L 625,165 L 608,170 L 592,168 L 575,160 L 560,150 L 546,148 L 534,152 L 522,162 L 514,170 L 505,162 L 495,148 L 484,138 L 474,125 L 470,112 Z" },
  // Indian Subcontinent
  { id:"in", d:"M 575,160 L 592,168 L 600,182 L 598,200 L 590,214 L 580,218 L 570,205 L 560,188 L 558,172 L 560,160 Z" },
  // Southeast Asia
  { id:"se", d:"M 640,158 L 658,155 L 672,158 L 680,168 L 675,180 L 662,185 L 648,182 L 636,175 Z" },
  // Sri Lanka
  { id:"sl", d:"M 590,218 L 596,215 L 598,225 L 592,228 Z" },
  // Japan
  { id:"jp", d:"M 735,95 L 744,88 L 752,92 L 752,103 L 744,108 L 737,105 Z" },
  // Australia
  { id:"au", d:"M 634,228 L 655,218 L 680,212 L 705,215 L 720,220 L 734,234 L 740,252 L 742,270 L 736,282 L 720,290 L 700,294 L 675,292 L 656,284 L 642,270 L 636,254 L 632,240 Z" },
  // Tasmania
  { id:"ta", d:"M 696,298 L 704,293 L 710,298 L 706,306 L 698,306 Z" },
  // New Zealand (North)
  { id:"nz", d:"M 778,290 L 784,282 L 790,285 L 788,295 L 780,298 Z" },
  // Antarctica (partial band)
  { id:"an", d:"M 0,360 L 820,360 L 820,384 L 0,384 Z" },
];

// ── Risk color map ────────────────────────────────────────────────────────────
const riskColor = r => RISK_CONFIG?.[r]?.color || "#00e5a0";

// ── Tooltip ───────────────────────────────────────────────────────────────────
function Tooltip({ dot }) {
  if (!dot) return null;
  const [bx, by] = dot.xy;
  const tx = bx > W * 0.72 ? bx - 148 : bx + 14;
  const ty = by < 70 ? by + 14 : by - 58;
  const color = riskColor(dot.risk);
  return (
    <g style={{ pointerEvents: "none" }}>
      <rect x={tx} y={ty} width={142} height={54} rx={4}
        fill="rgba(8,10,18,0.95)" stroke={color} strokeWidth={0.7} strokeOpacity={0.4}/>
      <text x={tx+9} y={ty+15} fill={color} fontSize={9.5} fontFamily="monospace" fontWeight={700}>{dot.host?.slice(0,20)}</text>
      <text x={tx+9} y={ty+27} fill="rgba(255,255,255,0.52)" fontSize={8} fontFamily="monospace">{dot.ip}</text>
      <text x={tx+9} y={ty+39} fill="rgba(255,255,255,0.35)" fontSize={8} fontFamily="monospace">
        {dot.flag} {[dot.city, dot.country].filter(Boolean).join(", ")}
      </text>
      <text x={tx+9} y={ty+50} fill={color} fontSize={7.5} fontFamily="monospace" fontWeight={700} opacity={0.7}>
        {dot.risk?.toUpperCase()} RISK · {dot.count > 1 ? `${dot.count} assets` : "1 asset"}
      </text>
    </g>
  );
}

// ════════════════════════════════════════════════════════════════════════════
export function WorldMapWidget({ assets }) {
  const [geoMap,  setGeoMap]  = useState({});
  const [loading, setLoading] = useState(false);
  const [tooltip, setTooltip] = useState(null);
  const sweepRef = useRef(null);

  // Unique non-private IPs from primary assets only
  const uniqueIPs = [...new Set(
    assets.filter(a => a.tags?.includes("primary") && a.ip && a.ip !== "—").map(a => a.ip)
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
  }, [uniqueIPs.join(",")]);  // eslint-disable-line

  useEffect(() => { fetchGeo(); }, [fetchGeo]);

  // Build dot list, group co-located IPs
  const dotsByIP = {};
  assets.filter(a => a.tags?.includes("primary") && geoMap[a.ip]).forEach(a => {
    const geo = geoMap[a.ip];
    if (!dotsByIP[a.ip]) dotsByIP[a.ip] = { ...a, ...geo, xy: project(geo.lon, geo.lat), count: 0, hosts: [] };
    dotsByIP[a.ip].count++;
    dotsByIP[a.ip].hosts.push(a.host);
    // Escalate risk if any co-located asset is worse
    const order = { critical:0, high:1, medium:2, low:3 };
    if ((order[a.risk] ?? 3) < (order[dotsByIP[a.ip].risk] ?? 3)) dotsByIP[a.ip].risk = a.risk;
  });
  const dots = Object.values(dotsByIP);

  // CSS keyframes injected once
  const styleTag = (
    <style>{`
      @keyframes dot-pulse {
        0%,100% { r: 5; opacity: 0.9; }
        50%      { r: 7; opacity: 1;   }
      }
      @keyframes ring-pulse {
        0%   { r: 9;  opacity: 0.55; stroke-width: 1.2; }
        100% { r: 20; opacity: 0;    stroke-width: 0.3; }
      }
      @keyframes scanline {
        0%   { x: -60; }
        100% { x: 880; }
      }
      @keyframes ocean-glow {
        0%,100% { stop-opacity: 0.18; }
        50%      { stop-opacity: 0.28; }
      }
      .dot-circle { animation: dot-pulse 2.4s ease-in-out infinite; }
      .dot-ring   { animation: ring-pulse 2.8s ease-out infinite; }
      .scanline   { animation: scanline 8s linear infinite; }
    `}</style>
  );

  return (
    <div style={{ background:"rgba(255,255,255,0.012)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:6, padding:"16px 20px", marginBottom:24 }}>
      {/* Header */}
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:12 }}>
        <div>
          <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.5px", fontFamily:"monospace", textTransform:"uppercase" }}>Asset Geo-Location</div>
          <div style={{ color:"rgba(255,255,255,0.45)", fontSize:11, marginTop:2 }}>
            {dots.length} location{dots.length !== 1 ? "s" : ""} mapped
            {loading && <span style={{ color:"rgba(255,255,255,0.2)", marginLeft:8, fontFamily:"monospace", fontSize:10 }}>resolving…</span>}
          </div>
        </div>
        <button onClick={fetchGeo} disabled={loading}
          style={{ background:"none", border:"1px solid rgba(255,255,255,0.09)", color:"rgba(255,255,255,0.28)", borderRadius:4, padding:"4px 10px", fontFamily:"monospace", fontSize:10, cursor:"pointer" }}>
          ↺ Refresh
        </button>
      </div>

      {/* Map */}
      <div style={{ borderRadius:5, overflow:"hidden", background:"#04060e", boxShadow:"inset 0 0 40px rgba(0,229,160,0.03)" }}>
        {styleTag}
        <svg viewBox={`0 0 ${W} ${H}`} style={{ width:"100%", height:"auto", display:"block" }}
          onMouseLeave={() => setTooltip(null)}>
          <defs>
            <radialGradient id="ocean-grad" cx="50%" cy="50%" r="70%">
              <stop offset="0%"   stopColor="#0a1628" stopOpacity="1"/>
              <stop offset="100%" stopColor="#04060e" stopOpacity="1"/>
            </radialGradient>
            <radialGradient id="pole-grad" cx="50%" cy="80%" r="60%">
              <stop offset="0%"   stopColor="#00e5a0" stopOpacity="0.06">
                <animate attributeName="stopOpacity" values="0.04;0.10;0.04" dur="6s" repeatCount="indefinite"/>
              </stop>
              <stop offset="100%" stopColor="#04060e" stopOpacity="0"/>
            </radialGradient>
            <filter id="dot-glow" x="-80%" y="-80%" width="260%" height="260%">
              <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="blur"/>
              <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
          </defs>

          {/* Ocean */}
          <rect width={W} height={H} fill="url(#ocean-grad)"/>
          <rect width={W} height={H} fill="url(#pole-grad)"/>

          {/* Animated scan line */}
          <rect className="scanline" y={0} width={55} height={H}
            fill="url(#scan-grad)" opacity={0.025}/>
          <defs>
            <linearGradient id="scan-grad" x1="0" x2="1" y1="0" y2="0">
              <stop offset="0%"   stopColor="#00e5a0" stopOpacity="0"/>
              <stop offset="50%"  stopColor="#00e5a0" stopOpacity="1"/>
              <stop offset="100%" stopColor="#00e5a0" stopOpacity="0"/>
            </linearGradient>
          </defs>

          {/* Graticule */}
          {[-60,-30,0,30,60].map(lat => {
            const [,y] = project(0, lat);
            return <line key={`lat${lat}`} x1={0} y1={y} x2={W} y2={y}
              stroke={lat === 0 ? "rgba(0,229,160,0.12)" : "rgba(255,255,255,0.04)"}
              strokeWidth={lat === 0 ? 0.7 : 0.4}
              strokeDasharray={lat === 0 ? "none" : "2,6"}/>;
          })}
          {[-120,-60,0,60,120].map(lon => {
            const [x] = project(lon, 0);
            return <line key={`lon${lon}`} x1={x} y1={0} x2={x} y2={H}
              stroke="rgba(255,255,255,0.04)" strokeWidth={0.4} strokeDasharray="2,6"/>;
          })}

          {/* Landmasses */}
          {LAND.map(l => (
            <path key={l.id} d={l.d}
              fill="rgba(60,80,65,0.55)"
              stroke="rgba(120,200,160,0.18)"
              strokeWidth={0.5}/>
          ))}

          {/* Asset dots */}
          {dots.map((dot, i) => {
            const [x, y] = dot.xy;
            const color  = riskColor(dot.risk);
            const isHover = tooltip?.ip === dot.ip;
            const delay  = `${(i * 0.4) % 2.4}s`;
            return (
              <g key={dot.ip} style={{ cursor:"pointer" }}
                onMouseEnter={() => setTooltip(dot)}
                onMouseLeave={() => setTooltip(null)}>
                {/* Expanding ring */}
                <circle className="dot-ring" cx={x} cy={y} r={9}
                  fill="none" stroke={color} strokeOpacity={isHover ? 0.7 : 0.4}
                  style={{ animationDelay: delay, animationDuration: isHover ? "1.6s" : "2.8s" }}/>
                {/* Second ring (offset) */}
                <circle className="dot-ring" cx={x} cy={y} r={9}
                  fill="none" stroke={color} strokeOpacity={isHover ? 0.4 : 0.2}
                  style={{ animationDelay: `${parseFloat(delay) + 1.2}s`, animationDuration:"2.8s" }}/>
                {/* Core dot */}
                <circle className="dot-circle" cx={x} cy={y} r={5}
                  fill={color} filter="url(#dot-glow)"
                  style={{ animationDelay: delay }}/>
                {/* Count badge */}
                {dot.count > 1 && (
                  <text x={x} y={y + 3.5} textAnchor="middle" fill="#060810"
                    fontSize={6.5} fontFamily="monospace" fontWeight={700}
                    style={{ pointerEvents:"none" }}>{dot.count}</text>
                )}
              </g>
            );
          })}

          {/* Tooltip */}
          {tooltip && <Tooltip dot={tooltip}/>}

          {/* Empty state */}
          {!loading && dots.length === 0 && (
            <text x={W/2} y={H/2} textAnchor="middle"
              fill="rgba(255,255,255,0.14)" fontSize={12} fontFamily="monospace">
              No resolved IPs — scan assets to populate map
            </text>
          )}

          {/* Corner label */}
          <text x={8} y={H-8} fill="rgba(0,229,160,0.25)" fontSize={8} fontFamily="monospace">ASSET GEO-LOCATION INTELLIGENCE</text>
        </svg>
      </div>

      {/* Legend */}
      <div style={{ display:"flex", gap:20, marginTop:10, flexWrap:"wrap" }}>
        {["critical","high","medium","low"].map(r => (
          <div key={r} style={{ display:"flex", alignItems:"center", gap:5 }}>
            <span style={{ width:7, height:7, borderRadius:"50%", background:riskColor(r), display:"inline-block",
              boxShadow:`0 0 5px ${riskColor(r)}66` }}/>
            <span style={{ color:"rgba(255,255,255,0.28)", fontSize:10, fontFamily:"monospace", textTransform:"uppercase", letterSpacing:"0.8px" }}>{r}</span>
          </div>
        ))}
        <div style={{ marginLeft:"auto", color:"rgba(255,255,255,0.18)", fontSize:10, fontFamily:"monospace" }}>
          {dots.reduce((sum, d) => sum + d.count, 0)} primary assets mapped
        </div>
      </div>
    </div>
  );
}

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
