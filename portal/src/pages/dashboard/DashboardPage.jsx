/**
 * src/pages/dashboard/DashboardPage.jsx
 * External Attack Posture — 8 ASM widgets, no SIEM widgets.
 */

import { useState, useEffect } from "react";
import { RISK_CONFIG } from '../../core/constants.js';
import { getModuleUrl } from '../../core/constants.js';
import {
  getEmailSecData, getWebSecStats, getInfraStats,
  getSupplyChainRisk, getBrandData, getSSLData,
  getOsintData, getSocialEngData,
} from '../../core/adapter.js';
import { PLATFORM_MODULES } from '../../registry/platformModules.js';

// ─────────────────────────────────────────────────────────────────────────────
// Visual primitives
// ─────────────────────────────────────────────────────────────────────────────

function AnimCounter({ value, duration = 1200 }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let start = 0;
    const step = Math.max(1, Math.ceil(value / (duration / 16)));
    const t = setInterval(() => {
      start += step;
      if (start >= value) { setDisplay(value); clearInterval(t); }
      else setDisplay(start);
    }, 16);
    return () => clearInterval(t);
  }, [value, duration]);
  return <>{display}</>;
}

function Badge({ risk }) {
  const cfg = RISK_CONFIG[risk] || RISK_CONFIG.low;
  return (
    <span style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40`,
      fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px", fontFamily: "monospace",
      padding: "2px 8px", borderRadius: "2px", whiteSpace: "nowrap" }}>
      {cfg.label}
    </span>
  );
}

/** Horizontal stacked bar */
function MiniStackedBar({ segs, height = 7, style = {} }) {
  const total = segs.reduce((a, b) => a + (b.value || 0), 0) || 1;
  return (
    <div style={{ height, background: "rgba(255,255,255,0.05)", borderRadius: 3,
      overflow: "hidden", display: "flex", ...style }}>
      {segs.filter(s => s.value > 0).map((s, i) => (
        <div key={i} title={`${s.label}: ${s.value}`}
          style={{ width: `${(s.value / total) * 100}%`, height: "100%",
            background: s.color, transition: "width 0.8s ease" }} />
      ))}
    </div>
  );
}

/** Labeled horizontal bar row */
function BarRow({ label, value, max, color, lw = 90 }) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <span style={{ color: "rgba(255,255,255,0.42)", fontSize: 10, fontFamily: "monospace",
        width: lw, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {label}
      </span>
      <div style={{ flex: 1, height: 6, background: "rgba(255,255,255,0.05)", borderRadius: 2, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color,
          borderRadius: 2, transition: "width 0.8s ease", minWidth: value > 0 ? 3 : 0 }} />
      </div>
      <span style={{ color, fontSize: 11, fontFamily: "monospace", fontWeight: 700,
        width: 26, textAlign: "right", flexShrink: 0 }}>{value}</span>
    </div>
  );
}

/** Reusable donut/ring SVG chart */
function Donut({ segs, size = 104, hole = 0.52, center }) {
  const cx = size / 2, cy = size / 2, r = size * 0.43, ir = r * hole;
  const total = segs.reduce((a, b) => a + (b.value || 0), 0) || 1;
  const toR = d => (d * Math.PI) / 180;
  let angle = -90;
  return (
    <svg width={size} height={size} style={{ flexShrink: 0 }}>
      <circle cx={cx} cy={cy} r={r} fill="rgba(255,255,255,0.03)"
        stroke="rgba(255,255,255,0.06)" strokeWidth={1} />
      {segs.filter(s => s.value > 0).map((s, i) => {
        const sweep = (s.value / total) * 358;
        const x1 = cx + r * Math.cos(toR(angle));
        const y1 = cy + r * Math.sin(toR(angle));
        const x2 = cx + r * Math.cos(toR(angle + sweep));
        const y2 = cy + r * Math.sin(toR(angle + sweep));
        const xi1 = cx + ir * Math.cos(toR(angle));
        const yi1 = cy + ir * Math.sin(toR(angle));
        const xi2 = cx + ir * Math.cos(toR(angle + sweep));
        const yi2 = cy + ir * Math.sin(toR(angle + sweep));
        const large = sweep > 180 ? 1 : 0;
        const d = `M${x1} ${y1} A${r} ${r} 0 ${large} 1 ${x2} ${y2} L${xi2} ${yi2} A${ir} ${ir} 0 ${large} 0 ${xi1} ${yi1}Z`;
        angle += (s.value / total) * 360;
        return <path key={i} d={d} fill={s.color} opacity={0.88} />;
      })}
      <circle cx={cx} cy={cy} r={ir} fill="#0d1117" />
      {center?.v && (
        <text x={cx} y={cy - (center.sub ? 5 : 0)} textAnchor="middle" fill="white"
          fontSize={center.vSize || 18} fontWeight="800" fontFamily="'Space Mono',monospace">
          {center.v}
        </text>
      )}
      {center?.sub && (
        <text x={cx} y={cy + 13} textAnchor="middle" fill="rgba(255,255,255,0.3)"
          fontSize={8} fontFamily="monospace" letterSpacing="0.5">
          {center.sub}
        </text>
      )}
    </svg>
  );
}

/** Vertical legend for a Donut */
function DonutLegend({ segs }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {segs.filter(s => s.value > 0 || s.showZero).map(s => (
        <div key={s.label} style={{ display: "flex", alignItems: "center", gap: 7 }}>
          <div style={{ width: 8, height: 8, borderRadius: 2, background: s.color, flexShrink: 0 }} />
          <span style={{ color: "rgba(255,255,255,0.4)", fontSize: 10, fontFamily: "monospace", flex: 1 }}>
            {s.label}
          </span>
          <span style={{ color: s.color, fontWeight: 700, fontSize: 11, fontFamily: "monospace" }}>
            {s.value}
          </span>
        </div>
      ))}
    </div>
  );
}

/** Section divider */
function SectionDivider({ label }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10, marginTop: 2 }}>
      <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.06)" }} />
      <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace",
        letterSpacing: "2px", textTransform: "uppercase", flexShrink: 0 }}>{label}</span>
      <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.06)" }} />
    </div>
  );
}

/** Widget card shell */
function ASMWidget({ title, children, accent = "#00e5a0", onViewAll, badge }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.07)",
      borderTop: `2px solid ${accent}`, borderRadius: 5, padding: "16px 18px",
      display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div style={{ color: "rgba(255,255,255,0.42)", fontSize: 10, letterSpacing: "1.5px",
          textTransform: "uppercase", fontFamily: "monospace" }}>{title}</div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {badge != null && (
            <span style={{ background: `${accent}18`, color: accent, fontSize: 10,
              fontFamily: "monospace", padding: "2px 8px", borderRadius: 2, fontWeight: 700 }}>{badge}</span>
          )}
          {onViewAll && (
            <button onClick={onViewAll} style={{ background: "none", border: "none", color: accent,
              fontSize: 10, fontFamily: "monospace", cursor: "pointer", opacity: 0.7 }}>
              View All ↗
            </button>
          )}
        </div>
      </div>
      <div style={{ flex: 1 }}>{children}</div>
    </div>
  );
}

/** Donut + legend side-by-side in fixed-height row — keeps all row widgets aligned */
function DonutRow({ donut, legend, height = 116 }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 14, height,
      marginBottom: 14, overflow: "hidden" }}>
      {donut}
      <div style={{ flex: 1, minWidth: 0 }}>{legend}</div>
    </div>
  );
}

function kv(label, val, color) {
  return (
    <div key={label} style={{ display: "flex", justifyContent: "space-between",
      padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
      <span style={{ color: "rgba(255,255,255,0.42)", fontSize: 11 }}>{label}</span>
      <span style={{ color, fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>{val}</span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ASM Posture Banner
// ─────────────────────────────────────────────────────────────────────────────

function ASMPostureWidget({ score, grade, scanType, domain, lastScan, onViewScan }) {
  const gc = { "A+": "#00e5a0", A: "#00e5a0", B: "#4d9eff",
    C: "#f5c518", D: "#ff8c00", F: "#ff3b3b" }[grade] || "#00e5a0";
  const stc = { deep: "#b06eff", standard: "#00e5a0", passive: "#4d9eff" }[scanType] || "#00e5a0";
  const pct = Math.min(100, Math.max(0, score ?? 0));
  return (
    <div style={{ background: `${gc}09`, border: `1px solid ${gc}30`, borderTop: `2px solid ${gc}`,
      borderRadius: 6, padding: "14px 22px", marginBottom: 14, display: "flex", alignItems: "center", gap: 22 }}>
      <div style={{ textAlign: "center", flexShrink: 0, minWidth: 70 }}>
        <div style={{ color: gc, fontSize: 42, fontWeight: 800, fontFamily: "'Space Mono',monospace", lineHeight: 1 }}>
          {score != null ? score : "—"}
        </div>
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace",
          textTransform: "uppercase", letterSpacing: "1px", marginTop: 3 }}>/ 100</div>
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 7 }}>
          <span style={{ color: "rgba(255,255,255,0.75)", fontSize: 13, fontWeight: 700, fontFamily: "monospace" }}>
            Overall ASM Security Posture
          </span>
          <span style={{ background: `${gc}18`, color: gc, border: `1px solid ${gc}40`,
            borderRadius: 3, padding: "1px 7px", fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
            {grade || "—"}
          </span>
        </div>
        <div style={{ background: "rgba(255,255,255,0.06)", borderRadius: 3, height: 7, marginBottom: 8, overflow: "hidden" }}>
          <div style={{ height: "100%", width: `${pct}%`, background: gc, borderRadius: 3, transition: "width 0.8s ease" }} />
        </div>
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace",
          whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
          {domain || ""}{domain && lastScan ? " · " : ""}
          {lastScan ? `Last scan: ${lastScan}` : ""}
          {!domain && !lastScan ? "External attack surface · ASM score" : ""}
        </div>
        {(scanType || (score != null && score < 60)) && (
          <div style={{ display: "flex", gap: 5, marginTop: 7 }}>
            {scanType && (
              <span style={{ background: `${stc}15`, color: stc, border: `1px solid ${stc}40`,
                borderRadius: 3, padding: "1px 7px", fontSize: 9, fontFamily: "monospace", fontWeight: 700 }}>
                {scanType.toUpperCase()}
              </span>
            )}
            {score != null && score < 60 && (
              <span style={{ background: "rgba(255,59,59,0.1)", border: "1px solid rgba(255,59,59,0.35)",
                color: "#ff3b3b", borderRadius: 3, padding: "1px 7px", fontSize: 9, fontFamily: "monospace", fontWeight: 700 }}>
                ⚠ BELOW THRESHOLD
              </span>
            )}
          </div>
        )}
      </div>
      {onViewScan && (
        <button onClick={onViewScan} style={{ background: `${gc}10`, border: `1px solid ${gc}35`,
          color: gc, borderRadius: 4, padding: "8px 14px", fontSize: 10, fontFamily: "monospace",
          fontWeight: 700, cursor: "pointer", whiteSpace: "nowrap", flexShrink: 0 }}>
          Full Scan ↗
        </button>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Stat card
// ─────────────────────────────────────────────────────────────────────────────

function StatCard({ label, value, accent, sub }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
      borderTop: `2px solid ${accent}`, padding: "15px 16px", borderRadius: 4, flex: 1, minWidth: 100 }}>
      <div style={{ color: accent, fontSize: 27, fontWeight: 800,
        fontFamily: "'Space Mono',monospace", lineHeight: 1 }}>
        <AnimCounter value={value} />
      </div>
      <div style={{ color: "rgba(255,255,255,0.42)", fontSize: 10,
        letterSpacing: "1.5px", marginTop: 5, textTransform: "uppercase" }}>{label}</div>
      {sub && <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Widget 1 inner — Risk Donut (ring + bar breakdown)
// ─────────────────────────────────────────────────────────────────────────────

function RiskDonut({ assets, onClick }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  assets.forEach(a => (a.vulnerabilities || []).forEach(v => {
    const s = v.severity?.toLowerCase();
    if (counts[s] !== undefined) counts[s]++;
  }));
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const COLS = ["#ff3b3b", "#ff8c00", "#f5c518", "#00e5a0"];
  const KEYS = ["critical", "high", "medium", "low"];
  const segs = KEYS.map((k, i) => ({ value: counts[k], color: COLS[i], label: k.charAt(0).toUpperCase() + k.slice(1) }));
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
      <div style={{ cursor: onClick ? "pointer" : "default" }} onClick={onClick}>
        <Donut segs={segs} size={116}
          center={{ v: total.toString(), sub: "FINDINGS", vSize: 22 }} />
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
          {KEYS.map((k, i) => (
            <BarRow key={k} label={KEYS[i].charAt(0).toUpperCase() + KEYS[i].slice(1)}
              value={counts[k]} max={total || 1} color={COLS[i]} lw={60} />
          ))}
        </div>
        <div style={{ marginTop: 10 }}>
          <MiniStackedBar segs={segs} height={8} />
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Cert timeline bars
// ─────────────────────────────────────────────────────────────────────────────

function CertTimeline({ assets }) {
  const rows = assets.filter(a => a.cert_days != null).slice(0, 5);
  if (!rows.length) return null;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {rows.map(a => {
        const d = a.cert_days;
        const c = d < 0 ? "#ff3b3b" : d < 30 ? "#ff8c00" : d < 90 ? "#f5c518" : "#00e5a0";
        return (
          <div key={a.id}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
              <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, fontFamily: "monospace",
                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 160 }}>
                {a.host}
              </span>
              <span style={{ color: c, fontSize: 10, fontFamily: "monospace", fontWeight: 700, flexShrink: 0 }}>
                {d < 0 ? "EXPIRED" : `${d}d`}
              </span>
            </div>
            <div style={{ height: 3, background: "rgba(255,255,255,0.07)", borderRadius: 2 }}>
              <div style={{ height: "100%", background: c, borderRadius: 2,
                width: `${Math.min(100, Math.max(0, (d / 365) * 100))}%`,
                boxShadow: `0 0 4px ${c}60` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Email security check row
// ─────────────────────────────────────────────────────────────────────────────

function ESecRow({ label, value, pass }) {
  const color = pass === null ? "rgba(255,255,255,0.3)" : pass ? "#00e5a0" : "#ff3b3b";
  const icon  = pass === null ? "—" : pass ? "✓" : "✗";
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
      padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
      <span style={{ color: "rgba(255,255,255,0.48)", fontSize: 11, fontFamily: "monospace" }}>{label}</span>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, maxWidth: 150,
          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value || "—"}</span>
        <span style={{ color, fontWeight: 700, fontSize: 12, flexShrink: 0, width: 14 }}>{icon}</span>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main export
// ─────────────────────────────────────────────────────────────────────────────

export function DashboardPage({ assets, data, stats, installedModules, setActiveTab, setSelectedAsset, setShowImport }) {
  const emailSec        = getEmailSecData(assets);
  const webSec          = getWebSecStats(assets);
  const infra           = getInfraStats(assets);
  const supply          = getSupplyChainRisk(assets);
  const brand           = getBrandData(assets);
  const sslData         = getSSLData(assets);
  const osint           = getOsintData(assets);
  const social          = getSocialEngData(assets);
  const installedAddons = Object.entries(installedModules).filter(([id]) => PLATFORM_MODULES[id]?.tier === "addon");
  const scanType        = data?.meta?.scan_type;
  const stColor         = { deep: "#b06eff", standard: "#00e5a0", passive: "#4d9eff" };
  const primaryAsset    = assets.find(a => a.tags?.includes("primary"));
  const newSubCount     = data?.subdomain_summary?.new ?? assets.filter(a => a.tags?.includes("new")).length;

  const critHighVulns = assets.flatMap(a =>
    (a.vulnerabilities || []).filter(v => v.severity === "Critical" || v.severity === "High")
      .map(v => ({ ...v, asset: a.host, assetId: a.id, assetObj: a }))
  ).sort((a, b) => (a.severity === "Critical" ? 0 : 1) - (b.severity === "Critical" ? 0 : 1));

  const webVulns = assets.flatMap(a =>
    (a.vulnerabilities || []).filter(v => {
      const m = (v.module || "").toLowerCase();
      return m === "web" || m === "crypto" || m === "web_analysis" || m === "vuln_scanner" || m === "nuclei" ||
        v.source === "port_banner" || v.source === "exposed_path" || v.source === "js_secret";
    })
  );
  const wvc = { critical: 0, high: 0, medium: 0, low: 0 };
  webVulns.forEach(v => { const s = v.severity?.toLowerCase(); if (wvc[s] !== undefined) wvc[s]++; });

  // Web security score 0-100
  const missingHdrs = primaryAsset?.http_analysis?.http_headers?.length || 0;
  const webScore = Math.max(0, Math.min(100,
    100 - wvc.critical * 22 - wvc.high * 11 - wvc.medium * 4 - wvc.low * 1 - missingHdrs * 6));
  const wsColor = webScore >= 80 ? "#00e5a0" : webScore >= 50 ? "#f5c518" : webScore >= 25 ? "#ff8c00" : "#ff3b3b";

  // SSL health donut segments
  const sslHealthy = Math.max(0, sslData.total - sslData.expired - sslData.critical - (sslData.weakTLS || 0));
  const sslSegs = [
    { value: sslHealthy,       color: "#00e5a0", label: "Healthy" },
    { value: sslData.weakTLS || 0, color: "#f5c518", label: "Weak TLS" },
    { value: sslData.critical, color: "#ff8c00", label: "Expiring" },
    { value: sslData.expired,  color: "#ff3b3b", label: "Expired" },
  ];

  // Email score donut
  const emailChecks = emailSec ? [
    emailSec.spf?.pass, emailSec.dkim?.pass, emailSec.dmarc?.pass,
    emailSec.dnssec?.pass ?? null, emailSec.bimi?.pass,
    emailSec.mta_sts?.pass, emailSec.tls_rpt?.pass ?? null,
  ] : [];
  const emailPassed  = emailChecks.filter(v => v === true).length;
  const emailFailed  = emailChecks.filter(v => v === false).length;
  const emailUnknown = emailChecks.filter(v => v === null).length;
  const emailSegs = [
    { value: emailPassed,  color: "#00e5a0", label: "Pass" },
    { value: emailFailed,  color: "#ff3b3b", label: "Fail" },
    { value: emailUnknown, color: "rgba(255,255,255,0.15)", label: "N/A" },
  ];

  // Infrastructure asset-type (solid pie segments)
  const subCount   = assets.filter(a => a.type === "Subdomain").length;
  const cloudCount = infra.cloud;
  const infraSegs = [
    { value: subCount,                                                        color: "#4d9eff",               label: "Subdomains" },
    { value: assets.filter(a => a.type?.startsWith("Web")).length,           color: "#ff8c00",               label: "Web/App"    },
    { value: assets.filter(a => a.tags?.includes("ip")).length,              color: "#00e5a0",               label: "IPs"        },
    { value: cloudCount,                                                      color: "#b06eff",               label: "Cloud"      },
    { value: Math.max(0, assets.length - subCount
        - assets.filter(a => a.type?.startsWith("Web")).length
        - assets.filter(a => a.tags?.includes("ip")).length - cloudCount),   color: "rgba(255,255,255,0.2)", label: "Other"      },
  ];

  // Supply chain breakdown
  const supplySegs = ["critical", "high", "medium", "low"].map(k => ({
    label: k.charAt(0).toUpperCase() + k.slice(1),
    color: { critical: "#ff3b3b", high: "#ff8c00", medium: "#f5c518", low: "#00e5a0" }[k],
    value: supply.risks?.filter(r => r.severity?.toLowerCase() === k).length ?? 0,
  }));

  // Brand exposure donut
  const brandTotal = brand.typos + brand.darkweb + osint.misp.length + osint.cves.length + (social?.emails?.length || 0);
  const brandSegs = [
    { value: brand.typos,                              color: "#ff3b3b", label: "Typosquats" },
    { value: brand.darkweb,                            color: "#ff8c00", label: "Dark Web" },
    { value: osint.misp.length + osint.cves.length,    color: "#b06eff", label: "OSINT / TI" },
    { value: social?.emails?.length || 0,              color: "#f5c518", label: "Exp. Emails" },
  ];

  const uniquePorts = [...new Set(assets.flatMap(a => a.ports || []))].slice(0, 10);

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 18 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: "white" }}>External Attack Posture</h1>
          {scanType && (
            <span style={{ background: `${stColor[scanType] || "#00e5a0"}15`,
              color: stColor[scanType] || "#00e5a0",
              border: `1px solid ${stColor[scanType] || "#00e5a0"}40`,
              fontSize: 10, fontFamily: "monospace", fontWeight: 700,
              padding: "2px 8px", borderRadius: 2, letterSpacing: "1px" }}>
              {scanType.toUpperCase()} SCAN
            </span>
          )}
        </div>
        <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13, marginTop: 4 }}>
          {data?.meta?.domain || data?.meta?.org || "No scan loaded"} · Scan ID: {data?.meta?.scan_id || "—"}
        </p>
      </div>

      {/* KPI strip */}
      <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
        <StatCard label="Assets"         value={stats.total}            accent="#00e5a0" />
        <StatCard label="Open Issues"    value={stats.open}             accent="#ff3b3b" sub="Needs remediation" />
        <StatCard label="Findings"       value={stats.totalVulns}       accent="#ff8c00" sub="All modules" />
        <StatCard label="Exposed Paths"  value={stats.exposedPaths}     accent="#f5c518" sub="Web surface" />
        <StatCard label="New Subdomains" value={newSubCount}            accent="#4d9eff" sub="Since last scan" />
        <StatCard label="Add-ons Active" value={installedAddons.length} accent="#b06eff" sub="Modules" />
      </div>

      {/* Posture banner */}
      <ASMPostureWidget
        score={data?.meta?.posture_score ?? null}
        grade={data?.meta?.posture_grade ?? null}
        scanType={scanType}
        domain={data?.meta?.domain || data?.meta?.org}
        lastScan={data?.meta?.last_scan ? new Date(data.meta.last_scan).toLocaleString() : null}
        onViewScan={() => setActiveTab("scan")}
      />

      {/* ══ ROW 1: Risk, SSL, Email — 3 columns ═════════════════════════════ */}
      <SectionDivider label="Risk & Security Posture" />
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14, marginBottom: 14 }}>

        {/* W1 — Overall Risk — Ring */}
        <ASMWidget title="1. Overall Risk Overview" accent="#ff3b3b" onViewAll={() => setActiveTab("vulns")}>
          <RiskDonut assets={assets} onClick={() => setActiveTab("vulns")} />
        </ASMWidget>

        {/* W2 — SSL / Crypto Health — stacked bar + cert timeline, no ring */}
        <ASMWidget title="2. SSL / Crypto Health" accent="#f5c518"
          badge={sslData.expired > 0 ? `${sslData.expired} EXPIRED` : null}>
          {/* Stat row */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 12 }}>
            {[
              { label: "Monitored",    value: sslData.total,    color: "rgba(255,255,255,0.6)" },
              { label: "Expired",      value: sslData.expired,  color: sslData.expired > 0 ? "#ff3b3b" : "#00e5a0" },
              { label: "Expiring <30d",value: sslData.critical, color: sslData.critical > 0 ? "#ff8c00" : "#00e5a0" },
              { label: "Weak TLS",     value: sslData.weakTLS,  color: sslData.weakTLS > 0 ? "#f5c518" : "#00e5a0" },
            ].map(s => (
              <div key={s.label} style={{ background: `${s.color}0d`,
                border: `1px solid ${s.color}25`, borderRadius: 4, padding: "9px 11px" }}>
                <div style={{ color: s.color, fontSize: 22, fontWeight: 800,
                  fontFamily: "'Space Mono',monospace", lineHeight: 1 }}>
                  <AnimCounter value={s.value} />
                </div>
                <div style={{ color: "rgba(255,255,255,0.32)", fontSize: 9,
                  letterSpacing: "1px", marginTop: 4, textTransform: "uppercase" }}>{s.label}</div>
              </div>
            ))}
          </div>
          {/* Stacked distribution bar */}
          <div style={{ marginBottom: 12 }}>
            <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 9,
              fontFamily: "monospace", marginBottom: 5 }}>CERT HEALTH DISTRIBUTION</div>
            <MiniStackedBar segs={sslSegs} height={8} />
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 6 }}>
              {sslSegs.filter(s => s.value > 0).map(s => (
                <div key={s.label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <div style={{ width: 7, height: 7, borderRadius: 1, background: s.color }} />
                  <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 9, fontFamily: "monospace" }}>
                    {s.label}: <span style={{ color: s.color, fontWeight: 700 }}>{s.value}</span>
                  </span>
                </div>
              ))}
            </div>
          </div>
          {primaryAsset?.pqc_data && (
            <div style={{ padding: "6px 0", borderTop: "1px solid rgba(255,255,255,0.05)", marginBottom: 10 }}>
              <div style={{ color: primaryAsset.pqc_data?.supported ? "#00e5a0" : "#ff8c00",
                fontSize: 11, fontFamily: "monospace" }}>
                {primaryAsset.pqc_data?.supported ? "✓ PQC Ready" : "⚠ Not PQC Ready"}
                {primaryAsset.pqc_data?.algorithm && ` · ${primaryAsset.pqc_data.algorithm}`}
              </div>
            </div>
          )}
          {assets.some(a => a.cert_days != null) && (
            <>
              <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 9,
                fontFamily: "monospace", marginBottom: 7 }}>CERT EXPIRY TIMELINE</div>
              <CertTimeline assets={assets} />
            </>
          )}
        </ASMWidget>

        {/* W3 — Email Security — pass/fail summary + checklist, no chart */}
        <ASMWidget title="3. Email Security" accent="#b06eff"
          badge={emailSec?.spoofing_risk && emailSec.spoofing_risk !== "Low"
            ? `${emailSec.spoofing_risk} SPOOFING` : null}>
          {emailSec ? (
            <>
              {/* Pass/fail summary header */}
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
                <div style={{ textAlign: "center", flexShrink: 0 }}>
                  <div style={{ fontSize: 28, fontWeight: 800, fontFamily: "'Space Mono',monospace",
                    color: emailPassed === emailChecks.filter(v => v !== null).length ? "#00e5a0"
                      : emailFailed > 2 ? "#ff3b3b" : "#f5c518", lineHeight: 1 }}>
                    {emailPassed}<span style={{ fontSize: 14, color: "rgba(255,255,255,0.3)" }}>/{emailChecks.filter(v => v !== null).length}</span>
                  </div>
                  <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 9,
                    fontFamily: "monospace", marginTop: 3, letterSpacing: "1px" }}>PASSED</div>
                </div>
                <div style={{ flex: 1 }}>
                  <MiniStackedBar segs={emailSegs} height={7} />
                  <div style={{ display: "flex", gap: 10, marginTop: 5 }}>
                    {[
                      { label: "Pass", value: emailPassed,  color: "#00e5a0" },
                      { label: "Fail", value: emailFailed,  color: "#ff3b3b" },
                      { label: "N/A",  value: emailUnknown, color: "rgba(255,255,255,0.2)" },
                    ].map(s => (
                      <div key={s.label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                        <div style={{ width: 6, height: 6, borderRadius: 1, background: s.color }} />
                        <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 9, fontFamily: "monospace" }}>
                          {s.label} <span style={{ color: s.color, fontWeight: 700 }}>{s.value}</span>
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              {/* 7-check checklist */}
              <div style={{ display: "flex", flexDirection: "column" }}>
                <ESecRow label="SPF"     value={emailSec.spf?.value}      pass={emailSec.spf?.pass} />
                <ESecRow label="DKIM"    value={emailSec.dkim?.value}     pass={emailSec.dkim?.pass} />
                <ESecRow label="DMARC"   value={emailSec.dmarc?.value}    pass={emailSec.dmarc?.pass} />
                <ESecRow label="DNSSEC"  value={emailSec.dnssec?.value}   pass={emailSec.dnssec?.pass ?? null} />
                <ESecRow label="BIMI"    value={emailSec.bimi?.value}     pass={emailSec.bimi?.pass} />
                <ESecRow label="MTA-STS" value={emailSec.mta_sts?.value}  pass={emailSec.mta_sts?.pass} />
                <ESecRow label="TLS-RPT" value={emailSec.tls_rpt?.value}  pass={emailSec.tls_rpt?.pass ?? null} />
              </div>
              {emailSec.elite_score != null && (
                <div style={{ marginTop: 8, display: "flex", justifyContent: "space-between",
                  padding: "6px 0", borderTop: "1px solid rgba(255,255,255,0.05)" }}>
                  <span style={{ color: "rgba(255,255,255,0.42)", fontSize: 11, fontFamily: "monospace" }}>
                    Elite Score
                  </span>
                  <span style={{ color: emailSec.elite_score >= 80 ? "#00e5a0"
                    : emailSec.elite_score >= 50 ? "#f5c518" : "#ff3b3b",
                    fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>
                    {emailSec.elite_score}/100
                  </span>
                </div>
              )}
            </>
          ) : (
            <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 12,
              fontFamily: "monospace", padding: "16px 0" }}>
              No email security data in scan.
            </div>
          )}
        </ASMWidget>
      </div>

      {/* ══ ROW 2: Infra + Web — 2 columns ══════════════════════════════════ */}
      <SectionDivider label="Attack Surface Inventory" />
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>

        {/* W4 — Infrastructure & Cloud — Solid Pie + IP GEO/ASN */}
        <ASMWidget title="4. Infrastructure & Cloud" accent="#4d9eff">
          <DonutRow
            donut={<Donut segs={infraSegs} size={104} hole={0} center={null} />}
            legend={<DonutLegend segs={infraSegs} />}
          />
          <div style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 10 }}>
            {kv("IP Addresses", infra.ips,   "#4d9eff")}
            {kv("Open Ports",   infra.ports, infra.ports > 0 ? "#ff8c00" : "#00e5a0")}
            {kv("Cloud Assets", infra.cloud, "#b06eff")}
            {kv("Subdomains",   subCount,    "rgba(255,255,255,0.55)")}
          </div>
          {uniquePorts.length > 0 && (
            <>
              <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 9,
                fontFamily: "monospace", marginBottom: 6 }}>EXPOSED PORTS</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginBottom: 10 }}>
                {uniquePorts.map(p => (
                  <span key={p} style={{ background: "rgba(77,158,255,0.1)", color: "#4d9eff",
                    border: "1px solid rgba(77,158,255,0.2)", padding: "2px 8px",
                    borderRadius: 3, fontSize: 10, fontFamily: "monospace" }}>:{p}</span>
                ))}
              </div>
            </>
          )}
          {primaryAsset?.dns_ips?.length > 0 && (
            <div style={{ marginBottom: 10 }}>
              <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 9,
                fontFamily: "monospace", marginBottom: 5 }}>IP GEO / ASN</div>
              {primaryAsset.dns_ips.slice(0, 3).map((ip, i) => (
                <div key={i} style={{ display: "flex", justifyContent: "space-between",
                  padding: "4px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                  <span style={{ color: "#4d9eff", fontFamily: "monospace", fontSize: 10 }}>{ip.ip}</span>
                  <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10 }}>
                    {ip.country || "?"} · {(ip.org || "Unknown ASN").slice(0, 24)}
                  </span>
                </div>
              ))}
            </div>
          )}
          {primaryAsset?.whois_full?.expiration_date && (() => {
            const daysLeft = Math.round(
              (new Date(primaryAsset.whois_full.expiration_date) - new Date()) / 86400000);
            const dc = daysLeft < 30 ? "#ff3b3b" : daysLeft < 90 ? "#ff8c00" : "#00e5a0";
            return (
              <div style={{ padding: "8px 0", borderTop: "1px solid rgba(255,255,255,0.05)" }}>
                <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 9, fontFamily: "monospace", marginBottom: 4 }}>
                  DOMAIN EXPIRY
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ color: "rgba(255,255,255,0.42)", fontSize: 11 }}>
                    {primaryAsset.whois_full.registrar || "Unknown registrar"}
                  </span>
                  <span style={{ color: dc, fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>
                    {daysLeft > 0 ? `${daysLeft}d` : "EXPIRED"}
                  </span>
                </div>
                <div style={{ height: 3, background: "rgba(255,255,255,0.07)", borderRadius: 2, marginTop: 5 }}>
                  <div style={{ height: "100%", background: dc, borderRadius: 2,
                    width: `${Math.min(100, Math.max(0, (daysLeft / 365) * 100))}%` }} />
                </div>
              </div>
            );
          })()}
          {primaryAsset?.dns_takeovers?.length > 0 && (
            <div style={{ marginTop: 10, background: "rgba(255,59,59,0.08)",
              border: "1px solid rgba(255,59,59,0.22)", borderRadius: 3, padding: "7px 10px" }}>
              <div style={{ color: "#ff3b3b", fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
                ⚠ {primaryAsset.dns_takeovers.length} DNS TAKEOVER RISK{primaryAsset.dns_takeovers.length > 1 ? "S" : ""}
              </div>
            </div>
          )}
        </ASMWidget>

        {/* W5 — Web Security — Ring/Donut */}
        <ASMWidget title="5. Web Security" accent="#ff8c00" onViewAll={() => setActiveTab("vulns")}>
          <DonutRow
            donut={<Donut
              segs={[
                { value: webScore,       color: wsColor,                   label: "Secure" },
                { value: 100 - webScore, color: "rgba(255,255,255,0.05)",  label: "At Risk" },
              ]}
              size={104}
              center={{ v: webScore.toString(), sub: "WEB SCORE", vSize: 22 }}
            />}
            legend={
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {[
                  { label: "Critical vulns", val: wvc.critical, color: "#ff3b3b" },
                  { label: "High vulns",     val: wvc.high,     color: "#ff8c00" },
                  { label: "Medium vulns",   val: wvc.medium,   color: "#f5c518" },
                  { label: "Low vulns",      val: wvc.low,      color: "#00e5a0" },
                ].map(r => (
                  <div key={r.label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <div style={{ width: 8, height: 8, borderRadius: 2, background: r.color, flexShrink: 0 }} />
                    <span style={{ color: "rgba(255,255,255,0.38)", fontSize: 10,
                      fontFamily: "monospace", flex: 1 }}>{r.label}</span>
                    <span style={{ color: r.val > 0 ? r.color : "rgba(255,255,255,0.2)",
                      fontWeight: 700, fontSize: 11, fontFamily: "monospace" }}>{r.val}</span>
                  </div>
                ))}
              </div>
            }
          />
          <div style={{ display: "flex", flexDirection: "column", gap: 5, marginBottom: 10 }}>
            {["critical", "high", "medium", "low"].map((s, i) => (
              <BarRow key={s}
                label={s.charAt(0).toUpperCase() + s.slice(1)}
                value={wvc[s]}
                max={webVulns.length || 1}
                color={["#ff3b3b", "#ff8c00", "#f5c518", "#00e5a0"][i]}
                lw={60}
              />
            ))}
          </div>
          <MiniStackedBar segs={[
            { value: wvc.critical, color: "#ff3b3b", label: "Critical" },
            { value: wvc.high,     color: "#ff8c00", label: "High" },
            { value: wvc.medium,   color: "#f5c518", label: "Medium" },
            { value: wvc.low,      color: "#00e5a0", label: "Low" },
          ]} height={6} style={{ marginBottom: 12 }} />
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {kv("Web Vulnerabilities", webVulns.length, webVulns.length > 0 ? "#ff8c00" : "#00e5a0")}
            {kv("Exposed Paths",       webSec.paths,    webSec.paths > 0 ? "#f5c518" : "#00e5a0")}
            {kv("JS Secrets",          primaryAsset?.js_secrets?.length || 0,
              (primaryAsset?.js_secrets?.length || 0) > 0 ? "#ff3b3b" : "#00e5a0")}
            {kv("Missing Sec Headers", missingHdrs, missingHdrs > 0 ? "#ff8c00" : "#00e5a0")}
          </div>
          {webVulns.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 5, marginTop: 10 }}>
              {webVulns.slice(0, 3).map((v, i) => {
                const cfg = RISK_CONFIG[v.severity?.toLowerCase()] || RISK_CONFIG.low;
                return (
                  <div key={i} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <span style={{ width: 6, height: 6, borderRadius: "50%",
                      background: cfg.color, flexShrink: 0 }} />
                    <span style={{ color: "rgba(255,255,255,0.48)", fontSize: 10,
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
                      {v.vulnerability}
                    </span>
                    {v.cvss && (
                      <span style={{ color: "rgba(255,140,0,0.5)", fontSize: 9,
                        fontFamily: "monospace", flexShrink: 0 }}>CVSS {v.cvss}</span>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </ASMWidget>

      </div>

      {/* ══ ROW 3: Supply Chain + Brand Exposure — 2 columns ════════════════ */}
      <SectionDivider label="External Threat Exposure" />
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>

        {/* W7 — Supply Chain Risk — Ring + library list */}
        <ASMWidget title="7. Supply Chain Risk" accent="#f5c518"
          badge={supply.high > 0 ? `${supply.high} HIGH` : null}>
          {supply.count > 0 ? (
            <>
              <DonutRow
                donut={<Donut segs={supplySegs} size={104}
                  center={{ v: supply.count.toString(), sub: "RISKS", vSize: 20 }} />}
                legend={<DonutLegend segs={supplySegs} />}
              />
              <div style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 10 }}>
                {kv("Total Risks",   supply.count, "#f5c518")}
                {kv("Critical/High", supply.high,  supply.high > 0 ? "#ff3b3b" : "#00e5a0")}
              </div>
              <MiniStackedBar segs={supplySegs} height={7} style={{ marginBottom: 12 }} />
              {supply.risks?.length > 0 && (
                <>
                  <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 9,
                    fontFamily: "monospace", marginBottom: 6 }}>TOP RISKY LIBRARIES</div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                    {supply.risks.slice(0, 5).map((r, i) => {
                      const sc = RISK_CONFIG[r.severity?.toLowerCase()] || RISK_CONFIG.low;
                      return (
                        <div key={i} style={{ background: "rgba(255,255,255,0.02)",
                          border: `1px solid ${sc.color}20`, borderLeft: `2px solid ${sc.color}`,
                          padding: "6px 8px", borderRadius: 2 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <span style={{ color: "rgba(255,255,255,0.65)", fontSize: 11,
                              fontFamily: "monospace", overflow: "hidden",
                              textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 280 }}>
                              {r.library || r.url?.split("/").pop() || "Unknown"}
                            </span>
                            <span style={{ color: sc.color, fontSize: 9, fontFamily: "monospace",
                              fontWeight: 700, flexShrink: 0 }}>{r.severity}</span>
                          </div>
                          {r.cve_ids?.length > 0 && (
                            <div style={{ color: "rgba(245,197,24,0.45)", fontSize: 9,
                              fontFamily: "monospace", marginTop: 2 }}>
                              {r.cve_ids.slice(0, 2).join(", ")}
                            </div>
                          )}
                        </div>
                      );
                    })}
                    {supply.risks.length > 5 && (
                      <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>
                        +{supply.risks.length - 5} more
                      </div>
                    )}
                  </div>
                </>
              )}
            </>
          ) : (
            <div style={{ padding: "12px 0" }}>
              <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 12,
                fontFamily: "monospace", marginBottom: 10 }}>No supply chain data in current scan.</div>
              <div style={{ background: "rgba(245,197,24,0.06)", border: "1px solid rgba(245,197,24,0.2)",
                borderRadius: 4, padding: "10px 14px" }}>
                <div style={{ color: "#f5c518", fontSize: 10, fontFamily: "monospace",
                  fontWeight: 700, marginBottom: 4 }}>REQUIRES DEEP SCAN</div>
                <div style={{ color: "rgba(255,255,255,0.38)", fontSize: 11, lineHeight: 1.5 }}>
                  Supply Chain analysis (third-party JS libraries via OSV.dev) only runs during a
                  <strong style={{ color: "#b06eff" }}> Deep scan</strong>. Standard and Passive scans skip this module.
                  To populate: run a new Deep scan from Scan Operations.
                </div>
              </div>
            </div>
          )}
        </ASMWidget>

        {/* W8 — Brand & External Exposure — Stacked bar as primary visual */}
        <ASMWidget title="8. Brand & External Exposure" accent="#ff3b3b"
          badge={brand.typos > 0 ? `${brand.typos} TYPOSQUATS` : null}>
          {/* Primary visual: large stacked bar */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
              <span style={{ color: "rgba(255,255,255,0.28)", fontSize: 9,
                fontFamily: "monospace", letterSpacing: "1.5px" }}>EXPOSURE BREAKDOWN</span>
              <span style={{ color: brandTotal > 0 ? "#ff3b3b" : "rgba(255,255,255,0.2)",
                fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>
                {brandTotal} total
              </span>
            </div>
            <MiniStackedBar segs={brandTotal > 0 ? brandSegs
              : [{ value: 1, color: "rgba(255,255,255,0.06)", label: "Clean" }]}
              height={12} style={{ borderRadius: 4 }} />
            <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 8 }}>
              {brandSegs.map(s => (
                <div key={s.label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                  <div style={{ width: 8, height: 8, borderRadius: 2, background: s.color }} />
                  <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace" }}>
                    {s.label}:{" "}
                    <span style={{ color: s.value > 0 ? s.color : "rgba(255,255,255,0.2)",
                      fontWeight: 700 }}>{s.value}</span>
                  </span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 12 }}>
            {kv("Registered Typosquats", brand.typos,   brand.typos > 0 ? "#ff3b3b" : "#00e5a0")}
            {kv("Dark Web Mentions",     brand.darkweb, brand.darkweb > 0 ? "#ff8c00" : "#00e5a0")}
            {kv("OSINT / TI Hits",       osint.misp.length + osint.cves.length,
              (osint.misp.length + osint.cves.length) > 0 ? "#b06eff" : "#00e5a0")}
            {social && kv("Exposed Emails", social.emails.length,
              social.emails.length > 0 ? "#f5c518" : "#00e5a0")}
          </div>
          {brandTotal === 0 && !social && (
            <div style={{ background: "rgba(255,59,59,0.05)", border: "1px solid rgba(255,59,59,0.18)",
              borderRadius: 4, padding: "10px 14px", marginBottom: 12 }}>
              <div style={{ color: "#ff8c00", fontSize: 10, fontFamily: "monospace",
                fontWeight: 700, marginBottom: 4 }}>PARTIAL DATA — DEEP SCAN NEEDED</div>
              <div style={{ color: "rgba(255,255,255,0.38)", fontSize: 11, lineHeight: 1.5 }}>
                Dark Web monitoring runs on <strong style={{ color: "#4d9eff" }}>Passive+</strong> scans.
                Typosquat detection, Social Engineering intel, and HIBP breach data require a
                <strong style={{ color: "#b06eff" }}> Deep scan</strong>.
              </div>
            </div>
          )}
          {brand.hibp?.length > 0 && (
            <div style={{ marginBottom: 10 }}>
              <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 9,
                fontFamily: "monospace", marginBottom: 6 }}>BREACH HISTORY (HaveIBeenPwned)</div>
              {brand.hibp.slice(0, 4).map((b, i) => (
                <div key={i} style={{ padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 11 }}>
                      {b.title || b.Name || "Breach"}
                    </span>
                    {(b.breach_date || b.BreachDate) && (
                      <span style={{ color: "rgba(255,255,255,0.28)", fontSize: 9, fontFamily: "monospace" }}>
                        {(b.breach_date || b.BreachDate)?.slice(0, 4)}
                      </span>
                    )}
                  </div>
                  {(b.data_classes || b.DataClasses)?.length > 0 && (
                    <div style={{ color: "rgba(255,59,59,0.45)", fontSize: 9, fontFamily: "monospace", marginTop: 1 }}>
                      {(b.data_classes || b.DataClasses).slice(0, 3).join(", ")}
                    </div>
                  )}
                </div>
              ))}
              {brand.hibp.length > 4 && (
                <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace", marginTop: 4 }}>
                  +{brand.hibp.length - 4} more breaches
                </div>
              )}
            </div>
          )}
          {social && (social.emails.length > 0 || social.linkedin?.length > 0) && (
            <div>
              <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 9,
                fontFamily: "monospace", marginBottom: 6 }}>SOCIAL ENGINEERING EXPOSURE</div>
              {social.emails.slice(0, 3).map((em, i) => (
                <div key={i} style={{ display: "flex", gap: 6, alignItems: "center", padding: "3px 0" }}>
                  <span style={{ color: "#ff8c00", fontSize: 10 }}>@</span>
                  <span style={{ color: "rgba(255,255,255,0.48)", fontSize: 11, fontFamily: "monospace" }}>
                    {em.email || em}
                    {em.position && <span style={{ color: "rgba(255,255,255,0.22)", marginLeft: 4 }}>· {em.position}</span>}
                  </span>
                </div>
              ))}
              {social.emails.length > 3 && (
                <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace" }}>
                  +{social.emails.length - 3} more
                </div>
              )}
              {social.risk_assessment && (
                <div style={{ marginTop: 6, color: social.risk_assessment.level === "High" ? "#ff3b3b"
                  : social.risk_assessment.level === "Medium" ? "#ff8c00" : "#00e5a0",
                  fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
                  Social Eng Risk: {social.risk_assessment.level}
                </div>
              )}
            </div>
          )}
          {brand.typos > 0 && (
            <div style={{ marginTop: 10 }}>
              <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 9,
                fontFamily: "monospace", marginBottom: 5 }}>REGISTERED TYPOSQUATS</div>
              {assets.filter(a => a.type?.includes("Typosquat")).slice(0, 4).map(a => (
                <div key={a.id} style={{ display: "flex", gap: 8, alignItems: "center", padding: "2px 0" }}>
                  <span style={{ color: "#ff3b3b", fontSize: 10 }}>⚠</span>
                  <span style={{ color: "rgba(255,255,255,0.48)", fontSize: 11, fontFamily: "monospace" }}>{a.host}</span>
                </div>
              ))}
            </div>
          )}
          {osint.shodan?.length > 0 && (
            <div style={{ marginTop: 10, padding: "8px 0", borderTop: "1px solid rgba(255,255,255,0.05)" }}>
              <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 9,
                fontFamily: "monospace", marginBottom: 5 }}>SHODAN EXPOSED SERVICES</div>
              {osint.shodan.slice(0, 3).map((s, i) => (
                <div key={i} style={{ display: "flex", gap: 8, alignItems: "center", padding: "2px 0" }}>
                  {s.port && <span style={{ color: "#4d9eff", fontFamily: "monospace", fontSize: 10 }}>:{s.port}</span>}
                  <span style={{ color: "rgba(255,255,255,0.38)", fontSize: 10,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {s.product || s.data?.slice(0, 40) || "Unknown service"}
                  </span>
                </div>
              ))}
            </div>
          )}
        </ASMWidget>
      </div>

      {/* Add-on modules */}
      {installedAddons.length > 0 && (
        <div style={{ background: "rgba(176,110,255,0.04)", border: "1px solid rgba(176,110,255,0.14)",
          borderRadius: 4, padding: "14px 22px", marginBottom: 14 }}>
          <div style={{ color: "rgba(255,255,255,0.32)", fontSize: 10, letterSpacing: "1.5px",
            textTransform: "uppercase", fontFamily: "monospace", marginBottom: 10 }}>Add-on Modules</div>
          <div style={{ display: "flex", gap: 10 }}>
            {installedAddons.map(([id]) => {
              const def = PLATFORM_MODULES[id]; if (!def) return null;
              return (
                <button key={id}
                  onClick={() => { window.history.pushState({ from: "portal" }, "", window.location.pathname); window.location.href = getModuleUrl(id); }}
                  style={{ display: "flex", alignItems: "center", gap: 8, background: "rgba(255,255,255,0.03)",
                    border: `1px solid ${def.color}30`, borderRadius: 4, padding: "10px 14px",
                    flex: 1, cursor: "pointer", textAlign: "left" }}>
                  <span style={{ fontSize: 18 }}>{def.icon}</span>
                  <div>
                    <div style={{ color: def.color, fontSize: 12, fontWeight: 700, fontFamily: "monospace" }}>{def.name}</div>
                    <div style={{ color: "rgba(255,255,255,0.28)", fontSize: 10, fontFamily: "monospace" }}>Click to open</div>
                  </div>
                  <span style={{ marginLeft: "auto", width: 5, height: 5, borderRadius: "50%",
                    background: "#00e5a0", animation: "pulse 2s infinite" }} />
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Critical & High vuln table */}
      <div style={{ background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.07)",
        borderRadius: 4, padding: "18px 22px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
          <div style={{ color: "rgba(255,255,255,0.42)", fontSize: 10,
            letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace" }}>
            Critical & High Vulnerabilities
          </div>
          <button onClick={() => setActiveTab("vulns")}
            style={{ background: "none", border: "none", color: "#00e5a0",
              fontSize: 10, fontFamily: "monospace", cursor: "pointer" }}>
            View All ({critHighVulns.length}) ↗
          </button>
        </div>
        {assets.length === 0 ? (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, textAlign: "center", padding: "20px 0" }}>
            No scan data.{" "}
            <button onClick={() => setShowImport(true)}
              style={{ background: "none", border: "none", color: "#00e5a0", cursor: "pointer", fontSize: 13 }}>
              Import a scan
            </button>{" "}or{" "}
            <button onClick={() => setActiveTab("scan")}
              style={{ background: "none", border: "none", color: "#00e5a0", cursor: "pointer", fontSize: 13 }}>
              start a new scan
            </button>.
          </div>
        ) : critHighVulns.length === 0 ? (
          <div style={{ color: "rgba(0,229,160,0.6)", fontSize: 13, textAlign: "center",
            padding: "20px 0", fontFamily: "monospace" }}>✓ No critical or high vulnerabilities found</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            {critHighVulns.slice(0, 10).map((v, i) => {
              const cfg = RISK_CONFIG[v.severity?.toLowerCase()] || RISK_CONFIG.high;
              return (
                <div key={i} className="asset-row" onClick={() => setSelectedAsset(v.assetObj)}
                  style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 12px",
                    background: "rgba(255,255,255,0.02)", borderRadius: 3,
                    border: `1px solid ${cfg.color}12`, borderLeft: `3px solid ${cfg.color}`, cursor: "pointer" }}>
                  <Badge risk={v.severity?.toLowerCase()} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ color: "white", fontSize: 12, fontWeight: 600,
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {v.vulnerability}
                    </div>
                    <div style={{ color: "rgba(255,255,255,0.32)", fontSize: 11, marginTop: 1,
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {v.description}
                    </div>
                  </div>
                  <div style={{ flexShrink: 0, textAlign: "right" }}>
                    <div style={{ color: cfg.color, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>
                      {v.asset}
                    </div>
                    <div style={{ display: "flex", gap: 6, justifyContent: "flex-end", marginTop: 2 }}>
                      {v.module && <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>{v.module}</span>}
                      {v.cvss   && <span style={{ color: "rgba(255,140,0,0.6)", fontSize: 10, fontFamily: "monospace" }}>CVSS {v.cvss}</span>}
                      {v.epss != null && v.epss > 0 && (
                        <span style={{ color: "rgba(255,100,100,0.6)", fontSize: 10, fontFamily: "monospace" }}>
                          EPSS {(v.epss * 100).toFixed(1)}%
                        </span>
                      )}
                    </div>
                  </div>
                  <span style={{ color: "rgba(255,255,255,0.18)", fontSize: 11 }}>↗</span>
                </div>
              );
            })}
            {critHighVulns.length > 10 && (
              <button onClick={() => setActiveTab("vulns")}
                style={{ background: "none", border: "none", color: "#00e5a0", fontSize: 11,
                  fontFamily: "monospace", cursor: "pointer", textAlign: "left", padding: "5px 0" }}>
                + {critHighVulns.length - 10} more → View all in Vulnerability Explorer
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
