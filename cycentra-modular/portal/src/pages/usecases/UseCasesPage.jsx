/**
 * src/pages/usecases/UseCasesPage.jsx
 * ======================================
 * Use Case Marketplace — pre-built CySOAR automation playbook templates.
 */

import { useState } from "react";

const USE_CASES = [
  {
    id:"phishing-response", title:"Phishing Response", icon:"🎣", color:"#ff3b3b", category:"Incident Response",
    description:"Auto-triage phishing emails. Extract IOCs, create a CyIRIS case, block sender domain in CySIEM, and notify the SOC team — all in under 60 seconds.",
    steps:["Email received → CySOAR webhook trigger","Extract headers, links, attachments","VirusTotal/URLScan enrichment","Auto-create CyIRIS case","Block domain in CySIEM active response","Alert SOC via Slack/Teams"],
    modules:["CySOAR","CyIRIS","CySIEM"], time:"~45 min to deploy", cysoarFlow:"phishing_response.py",
  },
  {
    id:"block-ip", title:"Block IP", icon:"🚫", color:"#ff8c00", category:"Active Response",
    description:"Instantly block a malicious IP across all agents via CySIEM active response. Triggered by alert level, CyIRIS case or manual override.",
    steps:["Trigger: alert level ≥12 or manual","Validate IP is not on allowlist","Execute active-response on all agents","Log block to CyIRIS case","Schedule unblock review in 24h"],
    modules:["CySOAR","CySIEM"], time:"~20 min to deploy", cysoarFlow:"block_ip.py",
  },
  {
    id:"ioc-enrichment", title:"IOC Enrichment", icon:"🔍", color:"#4d9eff", category:"Threat Intelligence",
    description:"Automatically enrich indicators of compromise from CySIEM alerts. Query VirusTotal, Shodan, and AbuseIPDB, then push enriched data to CyIRIS.",
    steps:["Receive IOC from CySIEM alert","Query VirusTotal, Shodan, AbuseIPDB","Score severity based on response","Update CyIRIS case with enrichment","Set ticket priority based on score"],
    modules:["CySOAR","CySIEM","CyIRIS"], time:"~30 min to deploy", cysoarFlow:"ioc_enrichment.py",
  },
  {
    id:"malware-isolation", title:"Malware Isolation", icon:"🦠", color:"#b06eff", category:"Active Response",
    description:"Isolate a compromised endpoint on detection. Quarantine the agent, take a memory snapshot, create a CyIRIS IR case, and alert the on-call analyst.",
    steps:["CySIEM fires malware detection rule","CySOAR validates confidence threshold","Isolate agent via Wazuh active response","Trigger memory acquisition script","Create priority CyIRIS case with evidence","Page on-call analyst"],
    modules:["CySOAR","CySIEM","CyIRIS"], time:"~60 min to deploy", cysoarFlow:"malware_isolation.py",
  },
  {
    id:"vuln-ticket", title:"Vulnerability Ticketing", icon:"📋", color:"#f5c518", category:"Vulnerability Management",
    description:"Automatically create and assign remediation tickets for Critical and High CVEs discovered by CySIEM. Includes SLA tracking and escalation.",
    steps:["CySIEM CVE detection alert","Filter: severity Critical or High","Deduplicate against open CyIRIS cases","Create CyIRIS case with CVE details","Assign to asset owner","Set SLA timer: Critical=24h, High=7d"],
    modules:["CySOAR","CySIEM","CyIRIS"], time:"~45 min to deploy", cysoarFlow:"vuln_ticketing.py",
  },
  {
    id:"brute-force-response", title:"Brute Force Response", icon:"🔐", color:"#00e5a0", category:"Active Response",
    description:"Detect and respond to brute force login attempts. Temporarily block offending IPs, alert the user, and create an investigation case.",
    steps:["CySIEM: 10+ failed logins in 60s","Extract source IP and target account","Block IP for 1 hour via active response","Notify target user via email","Create CyIRIS case for investigation","Auto-close if no further activity in 24h"],
    modules:["CySOAR","CySIEM","CyIRIS"], time:"~30 min to deploy", cysoarFlow:"brute_force.py",
  },
];

function UseCaseCard({ uc, onExpand }) {
  return (
    <div onClick={() => onExpand(uc)}
      style={{ background:"rgba(255,255,255,0.025)", border:`1px solid ${uc.color}20`, borderTop:`2px solid ${uc.color}`, borderRadius:5, padding:"20px 22px", cursor:"pointer" }}>
      <div style={{ display:"flex", gap:12, alignItems:"flex-start", marginBottom:10 }}>
        <span style={{ fontSize:22 }}>{uc.icon}</span>
        <div style={{ flex:1 }}>
          <div style={{ color:"white", fontSize:15, fontWeight:700 }}>{uc.title}</div>
          <div style={{ color:uc.color, fontSize:9, fontFamily:"monospace", letterSpacing:"1px", textTransform:"uppercase", marginTop:3 }}>{uc.category}</div>
        </div>
      </div>
      <div style={{ color:"rgba(255,255,255,0.55)", fontSize:12, lineHeight:1.6, marginBottom:14 }}>{uc.description}</div>
      <div style={{ display:"flex", flexWrap:"wrap", gap:5, marginBottom:14 }}>
        {uc.modules.map(m => (
          <span key={m} style={{ background:"rgba(255,255,255,0.06)", color:"rgba(255,255,255,0.5)", border:"1px solid rgba(255,255,255,0.1)", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2 }}>{m}</span>
        ))}
      </div>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
        <span style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace" }}>{uc.time}</span>
        <span style={{ color:uc.color, fontSize:11, fontFamily:"monospace" }}>View details →</span>
      </div>
    </div>
  );
}

function UseCaseModal({ uc, onClose }) {
  if (!uc) return null;
  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.88)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:150, backdropFilter:"blur(6px)" }} onClick={onClose}>
      <div style={{ background:"#0d0f14", border:`1px solid ${uc.color}40`, borderTop:`2px solid ${uc.color}`, borderRadius:8, padding:36, width:"min(640px,95vw)", maxHeight:"85vh", overflowY:"auto" }} onClick={e => e.stopPropagation()}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:24 }}>
          <div style={{ display:"flex", alignItems:"center", gap:14 }}>
            <span style={{ fontSize:36 }}>{uc.icon}</span>
            <div>
              <div style={{ color:"white", fontSize:20, fontWeight:700 }}>{uc.title}</div>
              <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, fontFamily:"monospace", marginTop:3 }}>{uc.category} · {uc.time}</div>
            </div>
          </div>
          <button onClick={onClose} style={{ background:"none", border:"none", color:"rgba(255,255,255,0.4)", cursor:"pointer", fontSize:22 }}>×</button>
        </div>

        <div style={{ color:"rgba(255,255,255,0.6)", fontSize:13, lineHeight:1.7, marginBottom:24 }}>{uc.description}</div>

        <div style={{ marginBottom:24 }}>
          <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:12 }}>Automation Steps</div>
          {uc.steps.map((step, i) => (
            <div key={i} style={{ display:"flex", gap:12, alignItems:"flex-start", marginBottom:10 }}>
              <div style={{ width:22, height:22, borderRadius:"50%", background:`${uc.color}20`, border:`1px solid ${uc.color}40`, display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0, marginTop:1 }}>
                <span style={{ color:uc.color, fontSize:10, fontWeight:700, fontFamily:"monospace" }}>{i + 1}</span>
              </div>
              <span style={{ color:"rgba(255,255,255,0.65)", fontSize:13, lineHeight:1.5, paddingTop:2 }}>{step}</span>
            </div>
          ))}
        </div>

        <div style={{ background:"rgba(0,0,0,0.4)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:4, padding:"14px 18px", marginBottom:24 }}>
          <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace", marginBottom:6 }}>CYSOAR FLOW</div>
          <code style={{ color:"#00e5a0", fontSize:12, fontFamily:"monospace" }}>
            cysoar import-flow {uc.cysoarFlow} --workspace cycentra
          </code>
        </div>

        <div style={{ display:"flex", gap:10 }}>
          <button onClick={onClose}
            style={{ flex:1, background:uc.color, color:"#0d0f14", border:"none", borderRadius:4, padding:"12px", fontFamily:"monospace", fontSize:12, fontWeight:700, cursor:"pointer", letterSpacing:"1px", textTransform:"uppercase" }}>
            Deploy Template
          </button>
          <button onClick={onClose}
            style={{ padding:"12px 20px", background:"transparent", color:"rgba(255,255,255,0.4)", border:"1px solid rgba(255,255,255,0.12)", borderRadius:4, fontFamily:"monospace", fontSize:12, cursor:"pointer" }}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

export function UseCasesPage() {
  const [expanded,  setExpanded]  = useState(null);
  const [catFilter, setCatFilter] = useState("all");

  const categories = ["all", ...new Set(USE_CASES.map(u => u.category))];
  const filtered   = catFilter === "all" ? USE_CASES : USE_CASES.filter(u => u.category === catFilter);

  return (
    <div>
      <div style={{ marginBottom:28 }}>
        <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:8 }}>
          <h1 style={{ fontSize:22, fontWeight:700, color:"white" }}>Use Case Marketplace</h1>
          <span style={{ background:"rgba(0,229,160,0.12)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.25)", fontSize:9, fontFamily:"monospace", padding:"3px 10px", borderRadius:2, fontWeight:700, letterSpacing:"1px" }}>
            {USE_CASES.length} TEMPLATES
          </span>
        </div>
        <p style={{ color:"rgba(255,255,255,0.4)", fontSize:13 }}>
          Pre-built CySOAR automation playbooks. One-click deploy integrates CySOAR, CyIRIS and CySIEM into battle-tested response workflows.
        </p>
      </div>

      {/* Category filter */}
      <div style={{ display:"flex", gap:6, marginBottom:24, flexWrap:"wrap" }}>
        {categories.map(cat => (
          <button key={cat} onClick={() => setCatFilter(cat)}
            style={{ background:catFilter===cat?"rgba(0,229,160,0.12)":"rgba(255,255,255,0.04)", color:catFilter===cat?"#00e5a0":"rgba(255,255,255,0.45)", border:`1px solid ${catFilter===cat?"rgba(0,229,160,0.3)":"rgba(255,255,255,0.08)"}`, borderRadius:20, padding:"6px 14px", fontSize:11, fontFamily:"monospace", cursor:"pointer", textTransform:"capitalize" }}>
            {cat}
          </button>
        ))}
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(300px, 1fr))", gap:16 }}>
        {filtered.map(uc => <UseCaseCard key={uc.id} uc={uc} onExpand={setExpanded}/>)}
      </div>

      {/* CySOAR note */}
      <div style={{ marginTop:28, background:"rgba(77,158,255,0.04)", border:"1px solid rgba(77,158,255,0.15)", borderRadius:6, padding:"20px 24px" }}>
        <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:12 }}>
          <span style={{ fontSize:20 }}>⚡</span>
          <span style={{ color:"rgba(255,255,255,0.7)", fontSize:14, fontWeight:600 }}>CySOAR Integration</span>
        </div>
        <div style={{ color:"rgba(255,255,255,0.4)", fontSize:12, lineHeight:1.8 }}>
          All templates are CySOAR-native Python scripts with built-in secret management, retry logic and webhook endpoints.
          Deploy via <code style={{ color:"#4d9eff" }}>cysoar CLI</code> or drag-and-drop into your CySOAR workspace.
          OIDC SSO means no separate login — your CyCentra 360 session carries through automatically.
        </div>
      </div>

      {expanded && <UseCaseModal uc={expanded} onClose={() => setExpanded(null)}/>}
    </div>
  );
}
