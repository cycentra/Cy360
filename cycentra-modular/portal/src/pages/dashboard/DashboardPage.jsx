/**
 * src/pages/dashboard/DashboardPage.jsx
 * =======================================
 * Attack Surface Overview dashboard — 10 ASM widgets.
 * Extracted from DashboardTab in App.jsx.
 *
 * All stat computation is now in src/core/adapter.js.
 */

import { useState } from "react";
import { RISK_CONFIG } from '../../core/constants.js';
import {
  getEmailSecData, getWebSecStats, getInfraStats,
  getSupplyChainRisk, getBrandData, getSSLData, formatDate,
} from '../../core/adapter.js';
import { PLATFORM_MODULES } from '../../registry/platformModules.js';

// ── Local UI sub-components ────────────────────────────────────────────────────

function AnimCounter({ value, duration = 1200 }) {
  const [display, setDisplay] = useState(0);
  useState(() => {
    let start = 0;
    const step  = Math.max(1, Math.ceil(value / (duration / 16)));
    const timer = setInterval(() => {
      start += step;
      if (start >= value) { setDisplay(value); clearInterval(timer); }
      else setDisplay(start);
    }, 16);
    return () => clearInterval(timer);
  });
  return <>{display}</>;
}

function Badge({ risk }) {
  const cfg = RISK_CONFIG[risk] || RISK_CONFIG.low;
  return <span style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40`, fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px", fontFamily: "monospace", padding: "2px 8px", borderRadius: "2px", whiteSpace: "nowrap" }}>{cfg.label}</span>;
}

function StatCard({ label, value, accent, sub, onClick }) {
  return (
    <div onClick={onClick} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderTop: `2px solid ${accent}`, padding: "18px 22px", borderRadius: 4, flex: 1, minWidth: 130, cursor: onClick ? "pointer" : "default" }}>
      <div style={{ color: accent, fontSize: 30, fontWeight: 800, fontFamily: "'Space Mono',monospace", lineHeight: 1 }}><AnimCounter value={value}/></div>
      <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, letterSpacing: "1.5px", marginTop: 5, textTransform: "uppercase" }}>{label}</div>
      {sub && <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

function RiskDonut({ assets, onSevClick }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  assets.forEach(a => (a.vulnerabilities || []).forEach(v => {
    const sev = v.severity?.toLowerCase();
    if (counts[sev] !== undefined) counts[sev]++;
  }));
  const total    = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  const colors   = ["#ff3b3b", "#ff8c00", "#f5c518", "#00e5a0"];
  const keys     = ["critical", "high", "medium", "low"];
  let cumulative = 0;
  const segments = keys.map((k, i) => {
    const pct = counts[k] / total;
    const s   = cumulative * 360;
    const e   = (cumulative + pct) * 360;
    cumulative += pct;
    const r   = 60, cx = 80, cy = 80;
    const toR = deg => (deg - 90) * Math.PI / 180;
    const x1  = cx + r * Math.cos(toR(s)); const y1 = cy + r * Math.sin(toR(s));
    const x2  = cx + r * Math.cos(toR(e)); const y2 = cy + r * Math.sin(toR(e));
    const d   = pct === 0 ? "" : `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${pct > 0.5 ? 1 : 0} 1 ${x2} ${y2} Z`;
    return { d, color: colors[i], key: k, count: counts[k] };
  });
  const totalVulns = Object.values(counts).reduce((a, b) => a + b, 0);
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
      <svg width="160" height="160" style={{ flexShrink: 0, cursor: onSevClick ? "pointer" : "default" }} onClick={onSevClick}>
        <circle cx="80" cy="80" r="60" fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.05)" strokeWidth="1"/>
        {segments.map(s => s.d && <path key={s.key} d={s.d} fill={s.color} opacity="0.85" onClick={onSevClick}/>)}
        <circle cx="80" cy="80" r="38" fill="#0d1117"/>
        <text x="80" y="76" textAnchor="middle" fill="white" fontSize="22" fontWeight="800" fontFamily="'Space Mono',monospace">{totalVulns}</text>
        <text x="80" y="94" textAnchor="middle" fill="rgba(255,255,255,0.35)" fontSize="9" fontFamily="monospace">FINDINGS</text>
      </svg>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {keys.map((k, i) => (
          <div key={k} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: colors[i] }}/>
            <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, width: 60 }}>{k.charAt(0).toUpperCase() + k.slice(1)}</span>
            <span style={{ color: colors[i], fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>{counts[k]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ASMWidget({ title, accent = "#00e5a0", badge, children, onViewAll }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.07)", borderTop: `2px solid ${accent}`, borderRadius: 4, padding: "16px 18px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 11, fontWeight: 600, letterSpacing: "0.5px" }}>{title}</span>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {badge && <span style={{ background: "rgba(255,59,59,0.15)", color: "#ff3b3b", fontSize: 9, fontFamily: "monospace", padding: "2px 8px", borderRadius: 2, fontWeight: 700 }}>{badge}</span>}
          {onViewAll && <button onClick={onViewAll} style={{ background: "none", border: "none", color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", cursor: "pointer" }}>View all →</button>}
        </div>
      </div>
      {children}
    </div>
  );
}

function ESecRow({ label, value, pass }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
      <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, width: 70 }}>{label}</span>
      <span style={{ color: pass === true ? "#00e5a0" : pass === false ? "#ff3b3b" : "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace", flex: 1, textAlign: "center" }}>
        {value || "Not configured"}
      </span>
      <span style={{ fontSize: 11, color: pass === true ? "#00e5a0" : pass === false ? "#ff3b3b" : "rgba(255,255,255,0.2)" }}>
        {pass === true ? "✓" : pass === false ? "✗" : "—"}
      </span>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function DashboardPage({ assets, data, stats, installedModules, setActiveTab, setSelectedAsset, setShowImport }) {
  const emailSec = getEmailSecData(assets);
  const webSec   = getWebSecStats(assets);
  const infra    = getInfraStats(assets);
  const supply   = getSupplyChainRisk(assets);
  const brand    = getBrandData(assets);
  const sslData  = getSSLData(assets);
  const installedAddons = Object.entries(installedModules).filter(([id]) => PLATFORM_MODULES[id]?.tier === "addon");

  const critHighVulns = assets.flatMap(a =>
    (a.vulnerabilities || []).filter(v => v.severity === "Critical" || v.severity === "High")
      .map(v => ({ ...v, asset: a.host, assetId: a.id, assetObj: a }))
  ).sort((a, b) => (a.severity === "Critical" ? 0 : 1) - (b.severity === "Critical" ? 0 : 1));

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 22 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: "white" }}>Attack Surface Overview</h1>
        <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13, marginTop: 4 }}>
          {data?.meta?.domain || data?.meta?.org || "No scan loaded"} · Scan ID: {data?.meta?.scan_id || "—"}
        </p>
      </div>

      {/* Top stat row */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
        <StatCard label="Assets"         value={stats.total}        accent="#00e5a0"/>
        <StatCard label="Open Issues"    value={stats.open}         accent="#ff3b3b" sub="Requires remediation"/>
        <StatCard label="Findings"       value={stats.totalVulns}   accent="#ff8c00" sub="Across all modules"/>
        <StatCard label="Exposed Paths"  value={stats.exposedPaths} accent="#f5c518" sub="Web surface"/>
        <StatCard label="Add-ons Active" value={installedAddons.length} accent="#b06eff" sub="Optional modules"/>
      </div>

      {/* Widget grid row 1 */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14, marginBottom: 14 }}>
        <ASMWidget title="1. Overall Risk Overview" accent="#ff3b3b" onViewAll={() => setActiveTab("vulns")}>
          <RiskDonut assets={assets} onSevClick={() => setActiveTab("vulns")}/>
        </ASMWidget>

        <ASMWidget title="2. SSL / Crypto Health" accent="#f5c518" badge={sslData.expired > 0 ? `${sslData.expired} EXPIRED` : null}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {[
              { label: "Certs Monitored", val: sslData.total,   color: "rgba(255,255,255,0.7)" },
              { label: "Expired",         val: sslData.expired,  color: sslData.expired > 0  ? "#ff3b3b" : "#00e5a0" },
              { label: "Expiring <30d",   val: sslData.critical, color: sslData.critical > 0 ? "#ff8c00" : "#00e5a0" },
              { label: "Weak TLS (≤1.0)", val: sslData.weakTLS,  color: sslData.weakTLS > 0  ? "#ff8c00" : "#00e5a0" },
            ].map(r => (
              <div key={r.label} style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 12 }}>{r.label}</span>
                <span style={{ color: r.color, fontFamily: "monospace", fontSize: 13, fontWeight: 700 }}>{r.val}</span>
              </div>
            ))}
          </div>
        </ASMWidget>

        <ASMWidget title="3. Infrastructure" accent="#4d9eff">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {[
              { label: "IP Assets",    val: infra.ips,   color: "rgba(255,255,255,0.7)" },
              { label: "Open Ports",   val: infra.ports, color: infra.ports > 10 ? "#ff8c00" : "rgba(255,255,255,0.7)" },
              { label: "Cloud Assets", val: infra.cloud, color: "rgba(255,255,255,0.7)" },
            ].map(r => (
              <div key={r.label} style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 12 }}>{r.label}</span>
                <span style={{ color: r.color, fontFamily: "monospace", fontSize: 13, fontWeight: 700 }}>{r.val}</span>
              </div>
            ))}
          </div>
        </ASMWidget>
      </div>

      {/* Widget grid row 2 */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14, marginBottom: 14 }}>
        <ASMWidget title="4. Email Security" accent="#b06eff">
          {emailSec ? (
            <div style={{ display: "flex", flexDirection: "column" }}>
              <ESecRow label="SPF"     value={emailSec.spf.value}    pass={emailSec.spf.pass}/>
              <ESecRow label="DKIM"    value={emailSec.dkim.value}   pass={emailSec.dkim.pass}/>
              <ESecRow label="DMARC"   value={emailSec.dmarc.value}  pass={emailSec.dmarc.pass}/>
              <ESecRow label="BIMI"    value={emailSec.bimi.value}   pass={emailSec.bimi.pass}/>
              <ESecRow label="MTA-STS" value={emailSec.mta_sts.value}pass={emailSec.mta_sts.pass}/>
            </div>
          ) : (
            <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 12, fontFamily: "monospace", padding: "16px 0" }}>No email security data in scan.</div>
          )}
        </ASMWidget>

        <ASMWidget title="5. Web Security" accent="#ff8c00" onViewAll={() => setActiveTab("vulns")}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {[
              { label: "Web Vulnerabilities", val: webSec.vulns, color: webSec.vulns > 0 ? "#ff8c00" : "#00e5a0" },
              { label: "Exposed Paths",       val: webSec.paths, color: webSec.paths > 0 ? "#f5c518" : "#00e5a0" },
            ].map(r => (
              <div key={r.label} style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 12 }}>{r.label}</span>
                <span style={{ color: r.color, fontFamily: "monospace", fontSize: 13, fontWeight: 700 }}>{r.val}</span>
              </div>
            ))}
          </div>
        </ASMWidget>

        <ASMWidget title="6. Brand & Dark Web" accent="#e8a020">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {[
              { label: "Typosquats",    val: brand.typos,   color: brand.typos > 0   ? "#ff8c00" : "#00e5a0" },
              { label: "Dark Web Hits", val: brand.darkweb, color: brand.darkweb > 0 ? "#ff3b3b" : "#00e5a0" },
              { label: "3rd-party Scripts", val: supply.count, color: supply.high > 0 ? "#f5c518" : "rgba(255,255,255,0.7)" },
            ].map(r => (
              <div key={r.label} style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 12 }}>{r.label}</span>
                <span style={{ color: r.color, fontFamily: "monospace", fontSize: 13, fontWeight: 700 }}>{r.val}</span>
              </div>
            ))}
          </div>
        </ASMWidget>
      </div>

      {/* Critical findings widget — full width */}
      <ASMWidget title="Critical & High Findings" accent="#ff3b3b" onViewAll={() => setActiveTab("vulns")}>
        {!data ? (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, textAlign: "center", padding: "20px 0" }}>
            No scan data. <button onClick={() => setShowImport(true)} style={{ background: "none", border: "none", color: "#00e5a0", cursor: "pointer", fontSize: 13 }}>Import a scan</button> or <button onClick={() => setActiveTab("scan")} style={{ background: "none", border: "none", color: "#00e5a0", cursor: "pointer", fontSize: 13 }}>start a new scan</button>.
          </div>
        ) : critHighVulns.length === 0 ? (
          <div style={{ color: "rgba(0,229,160,0.6)", fontSize: 13, textAlign: "center", padding: "20px 0", fontFamily: "monospace" }}>✓ No critical or high vulnerabilities found</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            {critHighVulns.slice(0, 10).map((v, i) => {
              const cfg = RISK_CONFIG[v.severity?.toLowerCase()] || RISK_CONFIG.high;
              return (
                <div key={i} className="asset-row" onClick={() => setSelectedAsset(v.assetObj)}
                  style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 12px", background: "rgba(255,255,255,0.02)", borderRadius: 3, border: `1px solid ${cfg.color}12`, borderLeft: `3px solid ${cfg.color}`, cursor: "pointer" }}>
                  <Badge risk={v.severity?.toLowerCase()}/>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ color: "white", fontSize: 12, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.vulnerability}</div>
                    <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, marginTop: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.description}</div>
                  </div>
                  <div style={{ flexShrink: 0, textAlign: "right" }}>
                    <div style={{ color: cfg.color, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{v.asset}</div>
                    {v.module && <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>{v.module}</div>}
                  </div>
                  <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 11 }}>↗</span>
                </div>
              );
            })}
            {critHighVulns.length > 10 && (
              <button onClick={() => setActiveTab("vulns")} style={{ background: "none", border: "none", color: "#00e5a0", fontSize: 11, fontFamily: "monospace", cursor: "pointer", textAlign: "left", padding: "5px 0" }}>
                + {critHighVulns.length - 10} more → View all in Vulnerability Explorer
              </button>
            )}
          </div>
        )}
      </ASMWidget>
    </div>
  );
}
