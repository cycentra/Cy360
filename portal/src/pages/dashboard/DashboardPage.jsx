/**
 * src/pages/dashboard/DashboardPage.jsx
 * Full 8-widget ASM Dashboard.
 *
 * v2: Fixes web-security module filter bug, expands all widgets with previously
 *     ignored data — email DNSSEC/TLS-RPT/spoofing, supply chain risk list,
 *     dark web breach detail, social engineering summary, OSINT/MISP count,
 *     scan type badge, new subdomain count.
 */

import { useState, useEffect } from "react";
import { RISK_CONFIG } from '../../core/constants.js';
import { getModuleUrl } from '../../core/constants.js';
import {
  getEmailSecData, getWebSecStats, getInfraStats,
  getSupplyChainRisk, getBrandData, getSSLData,
  getOsintData, getSocialEngData, formatDate,
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
    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"5px 0", borderBottom:"1px solid rgba(255,255,255,0.04)" }}>
      <span style={{ color:"rgba(255,255,255,0.5)", fontSize:11, fontFamily:"monospace" }}>{label}</span>
      <div style={{ display:"flex", gap:8, alignItems:"center" }}>
        <span style={{ color:"rgba(255,255,255,0.3)", fontSize:10, maxWidth:170, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{value||"—"}</span>
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


// ── Main component ────────────────────────────────────────────────────────────
export function DashboardPage({ assets, data, stats, installedModules, setActiveTab, setSelectedAsset, setShowImport }) {
  const emailSec        = getEmailSecData(assets);
  const webSec          = getWebSecStats(assets);
  const infra           = getInfraStats(assets);
  const supply          = getSupplyChainRisk(assets);
  const brand           = getBrandData(assets);
  const sslData         = getSSLData(assets);
  const osint           = getOsintData(assets);
  const social          = getSocialEngData(assets);
  const installedAddons = Object.entries(installedModules).filter(([id])=>PLATFORM_MODULES[id]?.tier==="addon");
  const scanType        = data?.meta?.scan_type;
  const scanTypeColor   = { deep:"#b06eff", standard:"#00e5a0", passive:"#4d9eff" };

  const primaryAsset    = assets.find(a => a.tags?.includes("primary"));

  const critHighVulns = assets.flatMap(a =>
    (a.vulnerabilities||[]).filter(v=>v.severity==="Critical"||v.severity==="High")
      .map(v=>({...v, asset:a.host, assetId:a.id, assetObj:a}))
  ).sort((a,b)=>(a.severity==="Critical"?0:1)-(b.severity==="Critical"?0:1));

  // Web vulns — use all modules, not just "Web" / "Crypto"
  const webVulns = assets.flatMap(a =>
    (a.vulnerabilities||[]).filter(v => {
      const m = (v.module||"").toLowerCase();
      return m==="web"||m==="crypto"||m==="web_analysis"||m==="vuln_scanner"||m==="nuclei"||
             v.source==="port_banner"||v.source==="exposed_path"||v.source==="js_secret";
    })
  );

  const statRow = (items) => items.map(r => (
    <div key={r.label} style={{ display:"flex", justifyContent:"space-between", padding:"5px 0", borderBottom:"1px solid rgba(255,255,255,0.04)" }}>
      <span style={{ color:"rgba(255,255,255,0.45)", fontSize:12 }}>{r.label}</span>
      <span style={{ color:r.color, fontFamily:"monospace", fontSize:13, fontWeight:700 }}>{r.val}</span>
    </div>
  ));

  // New subdomains count from subdomain_summary or counting assets
  const newSubCount = data?.subdomain_summary?.new
    ?? assets.filter(a => a.tags?.includes("new")).length;

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom:22 }}>
        <div style={{ display:"flex", alignItems:"center", gap:10, flexWrap:"wrap" }}>
          <h1 style={{ fontSize:22, fontWeight:700, color:"white" }}>Attack Surface Overview</h1>
          {scanType && (
            <span style={{ background:`${scanTypeColor[scanType]||"#00e5a0"}15`, color:scanTypeColor[scanType]||"#00e5a0",
              border:`1px solid ${scanTypeColor[scanType]||"#00e5a0"}40`,
              fontSize:10, fontFamily:"monospace", fontWeight:700, padding:"2px 8px", borderRadius:2, letterSpacing:"1px" }}>
              {scanType.toUpperCase()} SCAN
            </span>
          )}
        </div>
        <p style={{ color:"rgba(255,255,255,0.35)", fontSize:13, marginTop:4 }}>
          {data?.meta?.domain||data?.meta?.org||"No scan loaded"} · Scan ID: {data?.meta?.scan_id||"—"}
        </p>
      </div>

      {/* Stat cards */}
      <div style={{ display:"flex", gap:10, marginBottom:20, flexWrap:"wrap" }}>
        <StatCard label="Assets"          value={stats.total}           accent="#00e5a0"/>
        <StatCard label="Open Issues"     value={stats.open}            accent="#ff3b3b" sub="Requires remediation"/>
        <StatCard label="Findings"        value={stats.totalVulns}      accent="#ff8c00" sub="Across all modules"/>
        <StatCard label="Exposed Paths"   value={stats.exposedPaths}    accent="#f5c518" sub="Web surface"/>
        <StatCard label="New Subdomains"  value={newSubCount}           accent="#4d9eff" sub="Since last scan"/>
        <StatCard label="Add-ons Active"  value={installedAddons.length} accent="#b06eff" sub="Optional modules"/>
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
            {/* PQC status if available */}
            {primaryAsset?.pqc_data && (
              <div style={{ marginTop:6, padding:"5px 0", borderTop:"1px solid rgba(255,255,255,0.06)" }}>
                <div style={{ color:"rgba(255,255,255,0.25)", fontSize:9, fontFamily:"monospace", marginBottom:4 }}>POST-QUANTUM CRYPTO</div>
                <div style={{ color:primaryAsset.pqc_data?.supported?"#00e5a0":"#ff8c00", fontSize:11, fontFamily:"monospace" }}>
                  {primaryAsset.pqc_data?.supported?"✓ PQC Ready":"⚠ Not PQC Ready"}
                  {primaryAsset.pqc_data?.algorithm && ` · ${primaryAsset.pqc_data.algorithm}`}
                </div>
              </div>
            )}
          </div>
          <div style={{ marginTop:12 }}><CertTimeline assets={assets}/></div>
        </ASMWidget>

        <ASMWidget title="3. Infrastructure & Cloud" accent="#4d9eff">
          <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
            {statRow([
              { label:"IP Addresses",  val:infra.ips,   color:"#4d9eff" },
              { label:"Open Ports",    val:infra.ports, color:"#ff8c00" },
              { label:"Cloud Assets",  val:infra.cloud, color:"#00e5a0" },
              { label:"Subdomains",    val:assets.filter(a=>a.type==="Subdomain").length, color:"rgba(255,255,255,0.6)" },
            ])}
            {/* Cloud bucket summary if available */}
            {primaryAsset?.cloud_data?.bucket_summary && (
              <div style={{ marginTop:4, padding:"5px 0", borderTop:"1px solid rgba(255,255,255,0.06)" }}>
                <div style={{ color:"rgba(255,255,255,0.25)", fontSize:9, fontFamily:"monospace", marginBottom:4 }}>CLOUD BUCKETS</div>
                {["public","private","total"].map(k => primaryAsset.cloud_data.bucket_summary[k] != null && (
                  <div key={k} style={{ display:"flex", justifyContent:"space-between", padding:"2px 0" }}>
                    <span style={{ color:"rgba(255,255,255,0.35)", fontSize:10 }}>{k.charAt(0).toUpperCase()+k.slice(1)}</span>
                    <span style={{ color: k==="public" && primaryAsset.cloud_data.bucket_summary[k]>0?"#ff3b3b":"rgba(255,255,255,0.5)", fontSize:10, fontFamily:"monospace" }}>
                      {primaryAsset.cloud_data.bucket_summary[k]}
                    </span>
                  </div>
                ))}
              </div>
            )}
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
        {/* Widget 4 — Email Security (expanded) */}
        <ASMWidget title="4. Email Security" accent="#b06eff"
          badge={emailSec?.spoofing_risk && emailSec.spoofing_risk !== "Low" ? `${emailSec.spoofing_risk} SPOOFING RISK` : null}>
          {emailSec ? (
            <div style={{ display:"flex", flexDirection:"column" }}>
              <ESecRow label="SPF"      value={emailSec.spf.value}     pass={emailSec.spf.pass}/>
              <ESecRow label="DKIM"     value={emailSec.dkim.value}    pass={emailSec.dkim.pass}/>
              <ESecRow label="DMARC"    value={emailSec.dmarc.value}   pass={emailSec.dmarc.pass}/>
              <ESecRow label="DNSSEC"   value={emailSec.dnssec?.value} pass={emailSec.dnssec?.pass ?? null}/>
              <ESecRow label="BIMI"     value={emailSec.bimi.value}    pass={emailSec.bimi.pass}/>
              <ESecRow label="MTA-STS"  value={emailSec.mta_sts.value} pass={emailSec.mta_sts.pass}/>
              <ESecRow label="TLS-RPT"  value={emailSec.tls_rpt?.value} pass={emailSec.tls_rpt?.pass ?? null}/>
              {emailSec.elite_score != null && (
                <div style={{ marginTop:6, display:"flex", justifyContent:"space-between", padding:"5px 0" }}>
                  <span style={{ color:"rgba(255,255,255,0.5)", fontSize:11, fontFamily:"monospace" }}>Elite Score</span>
                  <span style={{ color: emailSec.elite_score>=80?"#00e5a0":emailSec.elite_score>=50?"#f5c518":"#ff3b3b",
                    fontFamily:"monospace", fontSize:12, fontWeight:700 }}>
                    {emailSec.elite_score}/100 · {emailSec.elite_status||""}
                  </span>
                </div>
              )}
            </div>
          ) : (
            <div style={{ color:"rgba(255,255,255,0.25)", fontSize:12, fontFamily:"monospace", padding:"16px 0" }}>
              No email security data in scan.<br/>Run a scan with the Email Security module enabled.
            </div>
          )}
        </ASMWidget>

        {/* Widget 5 — Web Security (fixed module filter) */}
        <ASMWidget title="5. Web Security" accent="#ff8c00" onViewAll={()=>setActiveTab("vulns")}>
          <div style={{ display:"flex", flexDirection:"column", gap:8, marginBottom:12 }}>
            {statRow([
              { label:"Web Vulnerabilities", val:webVulns.length,  color:webVulns.length>0?"#ff8c00":"#00e5a0" },
              { label:"Exposed Paths",       val:webSec.paths,     color:webSec.paths>0?"#f5c518":"#00e5a0" },
              { label:"JS Secrets",          val:primaryAsset?.js_secrets?.length||0, color:(primaryAsset?.js_secrets?.length||0)>0?"#ff3b3b":"#00e5a0" },
              { label:"API Endpoints",       val:primaryAsset?.api_endpoints?.length||0, color:"rgba(255,255,255,0.6)" },
              { label:"Assets Scanned",      val:assets.filter(a=>a.type?.startsWith("Web")).length, color:"rgba(255,255,255,0.6)" },
            ])}
          </div>
          <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
            {webVulns.slice(0,4).map((v,i)=>{
              const cfg=RISK_CONFIG[v.severity?.toLowerCase()]||RISK_CONFIG.low;
              return (
                <div key={i} style={{ display:"flex", gap:8, alignItems:"center" }}>
                  <span style={{ width:6, height:6, borderRadius:"50%", background:cfg.color, flexShrink:0 }}/>
                  <span style={{ color:"rgba(255,255,255,0.5)", fontSize:11, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{v.vulnerability}</span>
                  {v.cvss && <span style={{ color:"rgba(255,140,0,0.5)", fontSize:9, fontFamily:"monospace", flexShrink:0 }}>{v.cvss}</span>}
                </div>
              );
            })}
            {webVulns.length === 0 && <div style={{ color:"rgba(0,229,160,0.5)", fontSize:11, fontFamily:"monospace" }}>✓ No web vulnerabilities</div>}
          </div>
        </ASMWidget>

        {/* Widget 6 — Attack Surface Inventory */}
        <ASMWidget title="6. Attack Surface Inventory" accent="#00e5a0" onViewAll={()=>setActiveTab("assets")}>
          <div style={{ display:"flex", flexDirection:"column", gap:7 }}>
            {[
              { label:"Primary Domains",  count:assets.filter(a=>a.tags?.includes("primary")).length,  color:"#00e5a0" },
              { label:"Subdomains",       count:assets.filter(a=>a.type==="Subdomain").length,          color:"rgba(0,229,160,0.6)" },
              { label:"New Subdomains",   count:newSubCount,                                             color:"#4d9eff" },
              { label:"IP Addresses",     count:assets.filter(a=>a.tags?.includes("ip")).length,        color:"#4d9eff" },
              { label:"Typosquats",       count:assets.filter(a=>a.type?.includes("Typosquat")).length, color:"#ff8c00" },
              { label:"Critical Risk",    count:assets.filter(a=>a.risk==="critical").length,           color:"#ff3b3b" },
              { label:"High Risk",        count:assets.filter(a=>a.risk==="high").length,               color:"#ff8c00" },
            ].map(r=>(
              <div key={r.label} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"3px 0" }}>
                <span style={{ color:"rgba(255,255,255,0.45)", fontSize:12 }}>{r.label}</span>
                <span style={{ color:r.color, fontFamily:"monospace", fontSize:13, fontWeight:700 }}>{r.count}</span>
              </div>
            ))}
          </div>
        </ASMWidget>
      </div>

      {/* ROW 3 */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14, marginBottom:14 }}>
        {/* Widget 7 — Supply Chain (expanded with risk list) */}
        <ASMWidget title="7. Supply Chain Risk" accent="#f5c518" badge={supply.high>0?`${supply.high} HIGH`:null}>
          {supply.count>0 ? (
            <div>
              <div style={{ display:"flex", flexDirection:"column", gap:7, marginBottom:10 }}>
                {statRow([
                  { label:"Total Risks",   val:supply.count, color:"#f5c518" },
                  { label:"Critical/High", val:supply.high,  color:"#ff3b3b" },
                ])}
              </div>
              {supply.risks?.length > 0 && (
                <div>
                  <div style={{ color:"rgba(255,255,255,0.25)", fontSize:9, fontFamily:"monospace", marginBottom:6 }}>TOP RISKY LIBRARIES</div>
                  <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
                    {supply.risks.slice(0,4).map((r,i) => {
                      const sc = RISK_CONFIG[r.severity?.toLowerCase()] || RISK_CONFIG.low;
                      return (
                        <div key={i} style={{ background:"rgba(255,255,255,0.02)", border:`1px solid ${sc.color}20`, borderLeft:`2px solid ${sc.color}`, padding:"6px 8px", borderRadius:2 }}>
                          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                            <span style={{ color:"rgba(255,255,255,0.7)", fontSize:11, fontFamily:"monospace", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", maxWidth:140 }}>
                              {r.library || r.url?.split("/").pop() || "Unknown"}
                            </span>
                            <span style={{ color:sc.color, fontSize:9, fontFamily:"monospace", fontWeight:700, flexShrink:0 }}>{r.severity}</span>
                          </div>
                          {r.osv_id && <div style={{ color:"rgba(255,255,255,0.25)", fontSize:9, fontFamily:"monospace", marginTop:2 }}>{r.osv_id}</div>}
                          {r.cve_ids?.length > 0 && <div style={{ color:"rgba(245,197,24,0.5)", fontSize:9, fontFamily:"monospace", marginTop:1 }}>{r.cve_ids.slice(0,2).join(", ")}</div>}
                        </div>
                      );
                    })}
                    {supply.risks.length > 4 && (
                      <div style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace", paddingTop:2 }}>+{supply.risks.length-4} more — see Inventory</div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div style={{ color:"rgba(255,255,255,0.25)", fontSize:12, fontFamily:"monospace", padding:"16px 0" }}>No supply chain data.</div>
          )}
          <div style={{ marginTop:10, background:"rgba(245,197,24,0.05)", border:"1px solid rgba(245,197,24,0.12)", borderRadius:3, padding:"8px 12px" }}>
            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace", lineHeight:1.7 }}>
              Scans JS dependencies, CDN sources and third-party APIs.
            </div>
          </div>
        </ASMWidget>

        {/* Widget 8 — Brand & External Exposure (expanded with breach detail + social eng) */}
        <ASMWidget title="8. Brand & External Exposure" accent="#ff3b3b" badge={brand.typos>0?`${brand.typos} TYPOSQUATS`:null}>
          <div style={{ display:"flex", flexDirection:"column", gap:7, marginBottom:10 }}>
            {statRow([
              { label:"Registered Typosquats", val:brand.typos,   color:brand.typos>0?"#ff3b3b":"#00e5a0" },
              { label:"Dark Web Mentions",     val:brand.darkweb, color:brand.darkweb>0?"#ff8c00":"#00e5a0" },
              { label:"OSINT / MISP Hits",     val:osint.misp.length + osint.cves.length, color:(osint.misp.length + osint.cves.length)>0?"#b06eff":"#00e5a0" },
              ...(social ? [{ label:"Exposed Emails", val:social.emails.length, color:social.emails.length>0?"#ff8c00":"#00e5a0" }] : []),
            ])}
          </div>
          {/* Dark web breach detail */}
          {brand.hibp?.length > 0 && (
            <div style={{ marginBottom:10 }}>
              <div style={{ color:"rgba(255,255,255,0.25)", fontSize:9, fontFamily:"monospace", marginBottom:6 }}>BREACH HISTORY (HaveIBeenPwned)</div>
              {brand.hibp.slice(0,3).map((b,i) => (
                <div key={i} style={{ padding:"4px 0", borderBottom:"1px solid rgba(255,255,255,0.04)" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                    <span style={{ color:"rgba(255,255,255,0.65)", fontSize:11 }}>{b.title || b.Name || "Breach"}</span>
                    {(b.breach_date || b.BreachDate) && (
                      <span style={{ color:"rgba(255,255,255,0.3)", fontSize:9, fontFamily:"monospace" }}>{(b.breach_date||b.BreachDate)?.slice(0,4)}</span>
                    )}
                  </div>
                  {(b.data_classes || b.DataClasses)?.length > 0 && (
                    <div style={{ color:"rgba(255,59,59,0.5)", fontSize:9, fontFamily:"monospace", marginTop:1 }}>
                      {(b.data_classes||b.DataClasses).slice(0,3).join(", ")}
                    </div>
                  )}
                </div>
              ))}
              {brand.hibp.length > 3 && <div style={{ color:"rgba(255,255,255,0.2)", fontSize:9, fontFamily:"monospace", marginTop:4 }}>+{brand.hibp.length-3} more breaches</div>}
            </div>
          )}
          {/* Social engineering summary */}
          {social && (social.emails.length > 0 || social.linkedin.length > 0) && (
            <div style={{ marginBottom:8 }}>
              <div style={{ color:"rgba(255,255,255,0.25)", fontSize:9, fontFamily:"monospace", marginBottom:6 }}>SOCIAL ENGINEERING EXPOSURE</div>
              {social.emails.slice(0,2).map((em,i) => (
                <div key={i} style={{ display:"flex", gap:6, alignItems:"center", padding:"3px 0" }}>
                  <span style={{ color:"#ff8c00", fontSize:10 }}>@</span>
                  <span style={{ color:"rgba(255,255,255,0.5)", fontSize:11, fontFamily:"monospace" }}>
                    {em.email || em}
                    {em.position && <span style={{ color:"rgba(255,255,255,0.25)", marginLeft:4 }}>· {em.position}</span>}
                  </span>
                </div>
              ))}
              {social.emails.length > 2 && (
                <div style={{ color:"rgba(255,255,255,0.2)", fontSize:9, fontFamily:"monospace" }}>+{social.emails.length-2} more exposed emails</div>
              )}
              {social.risk_assessment && (
                <div style={{ marginTop:4, color: social.risk_assessment.level==="High"?"#ff3b3b":social.risk_assessment.level==="Medium"?"#ff8c00":"#00e5a0",
                  fontSize:10, fontFamily:"monospace", fontWeight:700 }}>
                  Social Eng Risk: {social.risk_assessment.level}
                </div>
              )}
            </div>
          )}
          {brand.typos>0 && (
            <div style={{ display:"flex", flexDirection:"column", gap:4 }}>
              <div style={{ color:"rgba(255,255,255,0.25)", fontSize:9, fontFamily:"monospace", marginBottom:4 }}>REGISTERED TYPOSQUATS</div>
              {assets.filter(a=>a.type?.includes("Typosquat")).slice(0,3).map(a=>(
                <div key={a.id} style={{ display:"flex", gap:8, alignItems:"center" }}>
                  <span style={{ color:"#ff3b3b", fontSize:10 }}>⚠</span>
                  <span style={{ color:"rgba(255,255,255,0.5)", fontSize:11, fontFamily:"monospace" }}>{a.host}</span>
                </div>
              ))}
            </div>
          )}
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
                    <div style={{ display:"flex", gap:6, justifyContent:"flex-end", marginTop:2 }}>
                      {v.module && <span style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace" }}>{v.module}</span>}
                      {v.cvss   && <span style={{ color:"rgba(255,140,0,0.6)", fontSize:10, fontFamily:"monospace" }}>CVSS {v.cvss}</span>}
                    </div>
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
