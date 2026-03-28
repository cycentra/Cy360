/**
 * src/pages/dashboard/DashboardPage.jsx
 * Full 8-widget ASM Dashboard — exact restoration of original DashboardTab.
 *
 * Fix: AnimCounter used useState in a loop (broken). Replaced with useEffect.
 * Fix: Missing CertTimeline, CySIEMFeed, widgets 5-8, add-on strip, vuln list.
 */

import { useState, useEffect } from "react";
import { RISK_CONFIG } from '../../core/constants.js';
import { getModuleUrl } from '../../core/constants.js';
import {
  getEmailSecData, getWebSecStats, getInfraStats,
  getSupplyChainRisk, getBrandData, getSSLData, formatDate,
} from '../../core/adapter.js';
import { PLATFORM_MODULES } from '../../registry/platformModules.js';

// ── AnimCounter ───────────────────────────────────────────────────────────────
function AnimCounter({ value, duration = 1200 }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let start = 0;
    const step  = Math.max(1, Math.ceil(value / (duration / 16)));
    const timer = setInterval(() => {
      start += step;
      if (start >= value) { setDisplay(value); clearInterval(timer); }
      else setDisplay(start);
    }, 16);
    return () => clearInterval(timer);
  }, [value, duration]);
  return <>{display}</>;
}

// ── Badge ─────────────────────────────────────────────────────────────────────
function Badge({ risk }) {
  const cfg = RISK_CONFIG[risk] || RISK_CONFIG.low;
  return (
    <span style={{ background:cfg.bg, color:cfg.color, border:`1px solid ${cfg.color}40`,
      fontSize:"10px", fontWeight:700, letterSpacing:"1.5px", fontFamily:"monospace",
      padding:"2px 8px", borderRadius:"2px", whiteSpace:"nowrap" }}>
      {cfg.label}
    </span>
  );
}

// ── StatCard ──────────────────────────────────────────────────────────────────
function StatCard({ label, value, accent, sub, onClick }) {
  return (
    <div onClick={onClick}
      style={{ background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.07)",
        borderTop:`2px solid ${accent}`, padding:"18px 22px", borderRadius:4,
        flex:1, minWidth:130, cursor:onClick?"pointer":"default" }}>
      <div style={{ color:accent, fontSize:30, fontWeight:800, fontFamily:"'Space Mono',monospace", lineHeight:1 }}>
        <AnimCounter value={value}/>
      </div>
      <div style={{ color:"rgba(255,255,255,0.45)", fontSize:10, letterSpacing:"1.5px", marginTop:5, textTransform:"uppercase" }}>{label}</div>
      {sub && <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, marginTop:2 }}>{sub}</div>}
    </div>
  );
}

// ── RiskDonut ─────────────────────────────────────────────────────────────────
function RiskDonut({ assets, onSevClick }) {
  const counts = { critical:0, high:0, medium:0, low:0 };
  assets.forEach(a => (a.vulnerabilities||[]).forEach(v => {
    const sev = v.severity?.toLowerCase();
    if (counts[sev] !== undefined) counts[sev]++;
  }));
  const total      = Object.values(counts).reduce((a,b)=>a+b,0)||1;
  const colors     = ["#ff3b3b","#ff8c00","#f5c518","#00e5a0"];
  const keys       = ["critical","high","medium","low"];
  const totalVulns = Object.values(counts).reduce((a,b)=>a+b,0);
  let cumulative   = 0;
  const segments   = keys.map((k,i) => {
    const pct=counts[k]/total; const s=cumulative*360; const e=(cumulative+pct)*360; cumulative+=pct;
    const r=60,cx=80,cy=80; const toR=deg=>(deg-90)*Math.PI/180;
    const x1=cx+r*Math.cos(toR(s)); const y1=cy+r*Math.sin(toR(s));
    const x2=cx+r*Math.cos(toR(e)); const y2=cy+r*Math.sin(toR(e));
    const d=pct===0?"": `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${pct>0.5?1:0} 1 ${x2} ${y2} Z`;
    return { d, color:colors[i], key:k, count:counts[k] };
  });
  return (
    <div style={{ display:"flex", alignItems:"center", gap:20 }}>
      <svg width="160" height="160" style={{ flexShrink:0, cursor:onSevClick?"pointer":"default" }} onClick={onSevClick}>
        <circle cx="80" cy="80" r="60" fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.05)" strokeWidth="1"/>
        {segments.map(s => s.d && <path key={s.key} d={s.d} fill={s.color} opacity="0.85"/>)}
        <circle cx="80" cy="80" r="38" fill="#0d1117"/>
        <text x="80" y="76" textAnchor="middle" fill="white" fontSize="22" fontWeight="800" fontFamily="'Space Mono',monospace">{totalVulns}</text>
        <text x="80" y="94" textAnchor="middle" fill="rgba(255,255,255,0.35)" fontSize="9" fontFamily="monospace">FINDINGS</text>
      </svg>
      <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
        {keys.map((k,i) => (
          <div key={k} style={{ display:"flex", alignItems:"center", gap:8 }}>
            <div style={{ width:8, height:8, borderRadius:"50%", background:colors[i] }}/>
            <span style={{ color:"rgba(255,255,255,0.5)", fontSize:11, width:60 }}>{k.charAt(0).toUpperCase()+k.slice(1)}</span>
            <span style={{ color:colors[i], fontFamily:"monospace", fontSize:12, fontWeight:700 }}>{counts[k]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── ASMWidget ─────────────────────────────────────────────────────────────────
function ASMWidget({ title, children, accent="#00e5a0", onViewAll, badge }) {
  return (
    <div style={{ background:"rgba(255,255,255,0.025)", border:"1px solid rgba(255,255,255,0.07)",
      borderTop:`2px solid ${accent}`, borderRadius:5, padding:"18px 22px" }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
        <div style={{ color:"rgba(255,255,255,0.45)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace" }}>{title}</div>
        <div style={{ display:"flex", gap:8, alignItems:"center" }}>
          {badge!=null && <span style={{ background:`${accent}18`, color:accent, fontSize:10, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, fontWeight:700 }}>{badge}</span>}
          {onViewAll && <button onClick={onViewAll} style={{ background:"none", border:"none", color:accent, fontSize:10, fontFamily:"monospace", cursor:"pointer", opacity:0.7 }}>View All ↗</button>}
        </div>
      </div>
      {children}
    </div>
  );
}

// ── ESecRow ───────────────────────────────────────────────────────────────────
function ESecRow({ label, value, pass }) {
  const color = pass===null?"rgba(255,255,255,0.35)":pass?"#00e5a0":"#ff3b3b";
  const icon  = pass===null?"—":pass?"✓":"✗";
  return (
    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"6px 0", borderBottom:"1px solid rgba(255,255,255,0.04)" }}>
      <span style={{ color:"rgba(255,255,255,0.5)", fontSize:12, fontFamily:"monospace" }}>{label}</span>
      <div style={{ display:"flex", gap:8, alignItems:"center" }}>
        <span style={{ color:"rgba(255,255,255,0.35)", fontSize:10, maxWidth:180, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{value||"—"}</span>
        <span style={{ color, fontWeight:700, fontSize:12 }}>{icon}</span>
      </div>
    </div>
  );
}

// ── CertTimeline ──────────────────────────────────────────────────────────────
function CertTimeline({ assets }) {
  const withCerts = assets.filter(a=>a.cert_days!=null).slice(0,6);
  if (!withCerts.length) return null;
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
      {withCerts.map(a => {
        const days  = a.cert_days;
        const color = days<0?"#ff3b3b":days<30?"#ff8c00":days<90?"#f5c518":"#00e5a0";
        const pct   = Math.min(100, Math.max(0,(days/365)*100));
        return (
          <div key={a.id}>
            <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
              <span style={{ color:"rgba(255,255,255,0.6)", fontSize:11, fontFamily:"monospace", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", maxWidth:160 }}>{a.host}</span>
              <span style={{ color, fontSize:10, fontFamily:"monospace", fontWeight:700, flexShrink:0 }}>{days<0?"EXPIRED":`${days}d`}</span>
            </div>
            <div style={{ height:3, background:"rgba(255,255,255,0.07)", borderRadius:2 }}>
              <div style={{ height:"100%", width:`${pct}%`, background:color, borderRadius:2, boxShadow:`0 0 4px ${color}60` }}/>
            </div>
            <div style={{ display:"flex", justifyContent:"space-between", marginTop:4 }}>
              <span style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace" }}>{a.type}</span>
              {a.cert_expiry && <span style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace" }}>Expires {formatDate(a.cert_expiry)}</span>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── CySIEMFeed ────────────────────────────────────────────────────────────────
function CySIEMFeed({ alerts }) {
  if (!alerts?.length) return <div style={{ color:"rgba(255,255,255,0.3)", fontSize:12, fontFamily:"monospace" }}>No alerts forwarded</div>;
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
      {alerts.map((a,i) => {
        const lvlColor = a.level>=12?"#ff3b3b":a.level>=8?"#ff8c00":"#f5c518";
        return (
          <div key={i} style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.06)",
            borderLeft:`3px solid ${lvlColor}`, padding:"10px 14px", borderRadius:"2px" }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:4 }}>
              <span style={{ color:lvlColor, fontSize:10, fontFamily:"monospace", fontWeight:700 }}>LEVEL {a.level} · {a.rule_id}</span>
              <span style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace" }}>{new Date(a.ts).toLocaleTimeString()}</span>
            </div>
            <div style={{ color:"rgba(255,255,255,0.8)", fontSize:12 }}>{a.description}</div>
            <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, fontFamily:"monospace", marginTop:4 }}>→ {a.asset}</div>
          </div>
        );
      })}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export function DashboardPage({ assets, data, stats, installedModules, setActiveTab, setSelectedAsset, setShowImport }) {
  const emailSec        = getEmailSecData(assets);
  const webSec          = getWebSecStats(assets);
  const infra           = getInfraStats(assets);
  const supply          = getSupplyChainRisk(assets);
  const brand           = getBrandData(assets);
  const sslData         = getSSLData(assets);
  const installedAddons = Object.entries(installedModules).filter(([id])=>PLATFORM_MODULES[id]?.tier==="addon");

  const critHighVulns = assets.flatMap(a =>
    (a.vulnerabilities||[]).filter(v=>v.severity==="Critical"||v.severity==="High")
      .map(v=>({...v, asset:a.host, assetId:a.id, assetObj:a}))
  ).sort((a,b)=>(a.severity==="Critical"?0:1)-(b.severity==="Critical"?0:1));

  const statRow = (items) => items.map(r => (
    <div key={r.label} style={{ display:"flex", justifyContent:"space-between", padding:"5px 0", borderBottom:"1px solid rgba(255,255,255,0.04)" }}>
      <span style={{ color:"rgba(255,255,255,0.45)", fontSize:12 }}>{r.label}</span>
      <span style={{ color:r.color, fontFamily:"monospace", fontSize:13, fontWeight:700 }}>{r.val}</span>
    </div>
  ));

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom:22 }}>
        <h1 style={{ fontSize:22, fontWeight:700, color:"white" }}>Attack Surface Overview</h1>
        <p style={{ color:"rgba(255,255,255,0.35)", fontSize:13, marginTop:4 }}>
          {data?.meta?.domain||data?.meta?.org||"No scan loaded"} · Scan ID: {data?.meta?.scan_id||"—"}
        </p>
      </div>

      {/* Stat cards */}
      <div style={{ display:"flex", gap:10, marginBottom:20, flexWrap:"wrap" }}>
        <StatCard label="Assets"         value={stats.total}          accent="#00e5a0"/>
        <StatCard label="Open Issues"    value={stats.open}           accent="#ff3b3b" sub="Requires remediation"/>
        <StatCard label="Findings"       value={stats.totalVulns}     accent="#ff8c00" sub="Across all modules"/>
        <StatCard label="Exposed Paths"  value={stats.exposedPaths}   accent="#f5c518" sub="Web surface"/>
        <StatCard label="Add-ons Active" value={installedAddons.length} accent="#b06eff" sub="Optional modules"/>
      </div>

      {/* ROW 1 */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:14, marginBottom:14 }}>
        <ASMWidget title="1. Overall Risk Overview" accent="#ff3b3b" onViewAll={()=>setActiveTab("vulns")}>
          <RiskDonut assets={assets} onSevClick={()=>setActiveTab("vulns")}/>
        </ASMWidget>

        <ASMWidget title="2. SSL / Crypto Health" accent="#f5c518" badge={sslData.expired>0?`${sslData.expired} EXPIRED`:null}>
          <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
            {statRow([
              { label:"Certs Monitored", val:sslData.total,   color:"rgba(255,255,255,0.7)" },
              { label:"Expired",         val:sslData.expired,  color:sslData.expired>0?"#ff3b3b":"#00e5a0" },
              { label:"Expiring <30d",   val:sslData.critical, color:sslData.critical>0?"#ff8c00":"#00e5a0" },
              { label:"Weak TLS (≤1.0)", val:sslData.weakTLS,  color:sslData.weakTLS>0?"#f5c518":"#00e5a0" },
            ])}
          </div>
          <div style={{ marginTop:12 }}><CertTimeline assets={assets}/></div>
        </ASMWidget>

        <ASMWidget title="3. Infrastructure & Cloud" accent="#4d9eff">
          <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
            {statRow([
              { label:"IP Addresses", val:infra.ips,   color:"#4d9eff" },
              { label:"Open Ports",   val:infra.ports, color:"#ff8c00" },
              { label:"Cloud Assets", val:infra.cloud, color:"#00e5a0" },
              { label:"Subdomains",   val:assets.filter(a=>a.type==="Subdomain").length, color:"rgba(255,255,255,0.6)" },
            ])}
          </div>
          <div style={{ marginTop:14 }}>
            <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace", marginBottom:6 }}>PORT EXPOSURE</div>
            <div style={{ display:"flex", gap:5, flexWrap:"wrap" }}>
              {[...new Set(assets.flatMap(a=>a.ports||[]))].slice(0,12).map(p=>(
                <span key={p} style={{ background:"rgba(77,158,255,0.1)", color:"#4d9eff", border:"1px solid rgba(77,158,255,0.2)", padding:"2px 8px", borderRadius:2, fontSize:10, fontFamily:"monospace" }}>:{p}</span>
              ))}
            </div>
          </div>
        </ASMWidget>
      </div>

      {/* ROW 2 */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:14, marginBottom:14 }}>
        <ASMWidget title="4. Email Security" accent="#b06eff">
          {emailSec ? (
            <div style={{ display:"flex", flexDirection:"column" }}>
              <ESecRow label="SPF"     value={emailSec.spf.value}     pass={emailSec.spf.pass}/>
              <ESecRow label="DKIM"    value={emailSec.dkim.value}    pass={emailSec.dkim.pass}/>
              <ESecRow label="DMARC"   value={emailSec.dmarc.value}   pass={emailSec.dmarc.pass}/>
              <ESecRow label="BIMI"    value={emailSec.bimi.value}    pass={emailSec.bimi.pass}/>
              <ESecRow label="MTA-STS" value={emailSec.mta_sts.value} pass={emailSec.mta_sts.pass}/>
            </div>
          ) : (
            <div style={{ color:"rgba(255,255,255,0.25)", fontSize:12, fontFamily:"monospace", padding:"16px 0" }}>
              No email security data in scan.<br/>Run a scan with the Email Security module enabled.
            </div>
          )}
        </ASMWidget>

        <ASMWidget title="5. Web Security" accent="#ff8c00" onViewAll={()=>setActiveTab("vulns")}>
          <div style={{ display:"flex", flexDirection:"column", gap:8, marginBottom:12 }}>
            {statRow([
              { label:"Web Vulnerabilities", val:webSec.vulns, color:webSec.vulns>0?"#ff8c00":"#00e5a0" },
              { label:"Exposed Paths",       val:webSec.paths, color:webSec.paths>0?"#f5c518":"#00e5a0" },
              { label:"Assets Scanned",      val:assets.filter(a=>a.type?.startsWith("Web")).length, color:"rgba(255,255,255,0.6)" },
            ])}
          </div>
          <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
            {assets.flatMap(a=>(a.vulnerabilities||[]).filter(v=>v.module==="Web"||v.module==="Crypto")).slice(0,3).map((v,i)=>{
              const cfg=RISK_CONFIG[v.severity?.toLowerCase()]||RISK_CONFIG.low;
              return (
                <div key={i} style={{ display:"flex", gap:8, alignItems:"center" }}>
                  <span style={{ width:6, height:6, borderRadius:"50%", background:cfg.color, flexShrink:0 }}/>
                  <span style={{ color:"rgba(255,255,255,0.5)", fontSize:11, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{v.vulnerability}</span>
                </div>
              );
            })}
          </div>
        </ASMWidget>

        <ASMWidget title="6. Attack Surface Inventory" accent="#00e5a0" onViewAll={()=>setActiveTab("assets")}>
          <div style={{ display:"flex", flexDirection:"column", gap:7 }}>
            {[
              { label:"Primary Domains", count:assets.filter(a=>a.tags?.includes("primary")).length,  color:"#00e5a0" },
              { label:"Subdomains",      count:assets.filter(a=>a.type==="Subdomain").length,          color:"rgba(0,229,160,0.6)" },
              { label:"IP Addresses",    count:assets.filter(a=>a.tags?.includes("ip")).length,        color:"#4d9eff" },
              { label:"Typosquats",      count:assets.filter(a=>a.type?.includes("Typosquat")).length, color:"#ff8c00" },
              { label:"Critical Risk",   count:assets.filter(a=>a.risk==="critical").length,           color:"#ff3b3b" },
              { label:"High Risk",       count:assets.filter(a=>a.risk==="high").length,               color:"#ff8c00" },
            ].map(r=>(
              <div key={r.label} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"4px 0" }}>
                <span style={{ color:"rgba(255,255,255,0.45)", fontSize:12 }}>{r.label}</span>
                <span style={{ color:r.color, fontFamily:"monospace", fontSize:13, fontWeight:700 }}>{r.count}</span>
              </div>
            ))}
          </div>
        </ASMWidget>
      </div>

      {/* ROW 3 */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:14, marginBottom:14 }}>
        <ASMWidget title="7. Supply Chain Risk" accent="#f5c518" badge={supply.high>0?`${supply.high} HIGH`:null}>
          {supply.count>0 ? (
            <div style={{ display:"flex", flexDirection:"column", gap:7 }}>
              {statRow([
                { label:"Total Risks",   val:supply.count, color:"#f5c518" },
                { label:"Critical/High", val:supply.high,  color:"#ff3b3b" },
              ])}
            </div>
          ) : (
            <div style={{ color:"rgba(255,255,255,0.25)", fontSize:12, fontFamily:"monospace", padding:"16px 0" }}>No supply chain data.</div>
          )}
          <div style={{ marginTop:12, background:"rgba(245,197,24,0.05)", border:"1px solid rgba(245,197,24,0.12)", borderRadius:3, padding:"10px 12px" }}>
            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace", lineHeight:1.7 }}>
              Supply chain analysis scans JS dependencies, CDN sources and third-party APIs.
            </div>
          </div>
        </ASMWidget>

        <ASMWidget title="8. Brand & External Exposure" accent="#ff3b3b" badge={brand.typos>0?`${brand.typos} TYPOSQUATS`:null}>
          <div style={{ display:"flex", flexDirection:"column", gap:7, marginBottom:12 }}>
            {statRow([
              { label:"Registered Typosquats", val:brand.typos,   color:brand.typos>0?"#ff3b3b":"#00e5a0" },
              { label:"Dark Web Mentions",     val:brand.darkweb, color:brand.darkweb>0?"#ff8c00":"#00e5a0" },
            ])}
          </div>
          {brand.typos>0 && (
            <div style={{ display:"flex", flexDirection:"column", gap:4 }}>
              <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace", marginBottom:4 }}>REGISTERED TYPOSQUATS</div>
              {assets.filter(a=>a.type?.includes("Typosquat")).slice(0,3).map(a=>(
                <div key={a.id} style={{ display:"flex", gap:8, alignItems:"center" }}>
                  <span style={{ color:"#ff3b3b", fontSize:10 }}>⚠</span>
                  <span style={{ color:"rgba(255,255,255,0.5)", fontSize:11, fontFamily:"monospace" }}>{a.host}</span>
                </div>
              ))}
            </div>
          )}
        </ASMWidget>

        <ASMWidget title="CySIEM Alerts" accent="#ff3b3b"
          onViewAll={()=>setActiveTab("cysiemfeed")}
          badge={`${data?.cysiemAlerts?.length||0} FORWARDED`}>
          <CySIEMFeed alerts={data?.cysiemAlerts?.slice(0,3)||[]}/>
        </ASMWidget>
      </div>

      {/* Add-on modules strip */}
      {installedAddons.length>0 && (
        <div style={{ background:"rgba(176,110,255,0.04)", border:"1px solid rgba(176,110,255,0.15)", borderRadius:4, padding:"14px 22px", marginBottom:14 }}>
          <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:10 }}>Add-on Modules</div>
          <div style={{ display:"flex", gap:10 }}>
            {installedAddons.map(([id])=>{
              const def=PLATFORM_MODULES[id]; if(!def) return null;
              return (
                <button key={id} onClick={()=>{ window.history.pushState({from:"portal"},"",window.location.pathname); window.location.href=getModuleUrl(id); }}
                  style={{ display:"flex", alignItems:"center", gap:8, background:"rgba(255,255,255,0.03)",
                    border:`1px solid ${def.color}30`, borderRadius:4, padding:"10px 14px", flex:1, cursor:"pointer", textAlign:"left" }}>
                  <span style={{ fontSize:18 }}>{def.icon}</span>
                  <div>
                    <div style={{ color:def.color, fontSize:12, fontWeight:700, fontFamily:"monospace" }}>{def.name}</div>
                    <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace" }}>Click to open</div>
                  </div>
                  <span style={{ marginLeft:"auto", width:5, height:5, borderRadius:"50%", background:"#00e5a0", animation:"pulse 2s infinite" }}/>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Critical & High vuln list */}
      <div style={{ background:"rgba(255,255,255,0.025)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:4, padding:"18px 22px" }}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
          <div style={{ color:"rgba(255,255,255,0.45)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace" }}>Critical & High Vulnerabilities</div>
          <button onClick={()=>setActiveTab("vulns")} style={{ background:"none", border:"none", color:"#00e5a0", fontSize:10, fontFamily:"monospace", cursor:"pointer" }}>
            View All ({critHighVulns.length}) ↗
          </button>
        </div>

        {assets.length===0 ? (
          <div style={{ color:"rgba(255,255,255,0.2)", fontSize:13, textAlign:"center", padding:"20px 0" }}>
            No scan data. <button onClick={()=>setShowImport(true)} style={{ background:"none", border:"none", color:"#00e5a0", cursor:"pointer", fontSize:13 }}>Import a scan</button> or <button onClick={()=>setActiveTab("scan")} style={{ background:"none", border:"none", color:"#00e5a0", cursor:"pointer", fontSize:13 }}>start a new scan</button>.
          </div>
        ) : critHighVulns.length===0 ? (
          <div style={{ color:"rgba(0,229,160,0.6)", fontSize:13, textAlign:"center", padding:"20px 0", fontFamily:"monospace" }}>✓ No critical or high vulnerabilities found</div>
        ) : (
          <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
            {critHighVulns.slice(0,10).map((v,i) => {
              const cfg=RISK_CONFIG[v.severity?.toLowerCase()]||RISK_CONFIG.high;
              return (
                <div key={i} className="asset-row" onClick={()=>setSelectedAsset(v.assetObj)}
                  style={{ display:"flex", alignItems:"center", gap:10, padding:"9px 12px",
                    background:"rgba(255,255,255,0.02)", borderRadius:3,
                    border:`1px solid ${cfg.color}12`, borderLeft:`3px solid ${cfg.color}`, cursor:"pointer" }}>
                  <Badge risk={v.severity?.toLowerCase()}/>
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ color:"white", fontSize:12, fontWeight:600, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{v.vulnerability}</div>
                    <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, marginTop:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{v.description}</div>
                  </div>
                  <div style={{ flexShrink:0, textAlign:"right" }}>
                    <div style={{ color:cfg.color, fontSize:11, fontFamily:"monospace", fontWeight:700 }}>{v.asset}</div>
                    {v.module && <div style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace" }}>{v.module}</div>}
                  </div>
                  <span style={{ color:"rgba(255,255,255,0.2)", fontSize:11 }}>↗</span>
                </div>
              );
            })}
            {critHighVulns.length>10 && (
              <button onClick={()=>setActiveTab("vulns")} style={{ background:"none", border:"none", color:"#00e5a0", fontSize:11, fontFamily:"monospace", cursor:"pointer", textAlign:"left", padding:"5px 0" }}>
                + {critHighVulns.length-10} more → View all in Vulnerability Explorer
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
