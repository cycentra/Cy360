/**
 * src/pages/usecases/UseCasesPage.jsx
 * ======================================
 * Use Case Marketplace — pre-built CySOAR automation playbook templates
 * and cloud integration configuration widgets.
 */

import { useState, useEffect } from "react";
import { API_BASE } from "../../core/constants";

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
  {
    id:"office365", title:"Office 365", icon:"☁️", color:"#0078d4", category:"Cloud Management",
    description:"Configure the Wazuh Office 365 audit log integration. Ingest Exchange, SharePoint, Azure AD and General audit events directly into CySIEM for unified cloud visibility.",
    modules:["CySIEM"], time:"~5 min to configure",
    isConfigWidget: true,
  },
  {
    id:"google-cloud", title:"Google Cloud", icon:"🔵", color:"#4285f4", category:"Cloud Management",
    description:"Configure the Wazuh GCP Pub/Sub integration. Upload your Service Account JSON key to ingest Google Cloud audit logs — Admin Activity, Data Access, System Events — directly into CySIEM. Custom security rules are deployed automatically.",
    modules:["CySIEM"], time:"~5 min to configure",
    isConfigWidget: true,
    isGCloudWidget: true,
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

const O365_SUBSCRIPTIONS = [
  { id: "Audit.AzureActiveDirectory", label: "Azure Active Directory" },
  { id: "Audit.Exchange",             label: "Exchange" },
  { id: "Audit.SharePoint",           label: "SharePoint" },
  { id: "Audit.General",              label: "General" },
  { id: "DLP.All",                    label: "DLP (Data Loss Prevention)" },
];

const O365_INTERVALS = ["1m","5m","10m","15m","30m","1h","2h","6h","12h","24h"];

const O365_API_TYPES = [
  { id: "commercial", label: "Commercial (Microsoft 365)" },
  { id: "gcc",        label: "GCC (US Government)" },
  { id: "gcc-high",   label: "GCC High (US DoD / High Security)" },
];

function O365ConfigModal({ uc, onClose }) {
  const [tenantId,          setTenantId]          = useState("");
  const [clientId,          setClientId]          = useState("");
  const [clientSecret,      setClientSecret]      = useState("");
  const [apiType,           setApiType]           = useState("commercial");
  const [interval,          setInterval]          = useState("1m");
  const [onlyFutureEvents,  setOnlyFutureEvents]  = useState(true);
  const [subs,              setSubs]              = useState(O365_SUBSCRIPTIONS.filter(s => s.id !== "DLP.All").map(s => s.id));
  const [enabled,           setEnabled]           = useState(true);
  const [saving,            setSaving]            = useState(false);
  const [result,            setResult]            = useState(null);
  const [loadError,         setLoadError]         = useState(null);
  const [hasExistingSecret, setHasExistingSecret] = useState(false);

  // Load existing config on mount
  useEffect(() => {
    fetch(`${API_BASE}/api/system/o365config`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        if (d.ok) {
          if (d.tenant_id)  setTenantId(d.tenant_id);
          if (d.client_id)  setClientId(d.client_id);
          if (d.interval)   setInterval(d.interval);
          if (d.api_type)   setApiType(d.api_type);
          if (d.subscriptions && d.subscriptions.length) setSubs(d.subscriptions);
          setEnabled(d.enabled !== false);
          setOnlyFutureEvents(d.only_future_events !== false);
          // Secret is never returned — track whether one is already configured
          setHasExistingSecret(!!d.tenant_id && !d.tenant_id.startsWith("PLACEHOLDER"));
        }
      })
      .catch(err => {
        // 404 means ossec.conf not found (CySIEM not installed yet) — not an error
        if (err !== 404) setLoadError("Could not load current config.");
      });
  }, []);

  function toggleSub(id) {
    setSubs(prev => prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]);
  }

  function handleSave(e) {
    e.preventDefault();
    setResult(null);
    setSaving(true);
    fetch(`${API_BASE}/api/system/o365config`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tenant_id: tenantId, client_id: clientId, client_secret: clientSecret, api_type: apiType, interval, only_future_events: onlyFutureEvents, subscriptions: subs, enabled }),
    })
      .then(r => r.json().then(d => ({ ok: r.ok, data: d })))
      .then(({ ok, data }) => setResult({ ok: ok && data.ok, msg: data.message || data.error || (ok ? "Saved" : "Error") }))
      .catch(() => setResult({ ok: false, msg: "Network error" }))
      .finally(() => setSaving(false));
  }

  if (!uc) return null;

  const inputStyle = {
    width: "100%", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
    borderRadius: 4, padding: "9px 12px", color: "white", fontSize: 13, fontFamily: "monospace",
    outline: "none", boxSizing: "border-box",
  };
  const labelStyle = { color: "rgba(255,255,255,0.45)", fontSize: 11, fontFamily: "monospace", letterSpacing: "0.8px", textTransform: "uppercase", marginBottom: 6, display: "block" };

  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.88)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:150, backdropFilter:"blur(6px)" }} onClick={onClose}>
      <div style={{ background:"#0d0f14", border:"1px solid #0078d440", borderTop:"2px solid #0078d4", borderRadius:8, padding:36, width:"min(580px,95vw)", maxHeight:"90vh", overflowY:"auto" }} onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:24 }}>
          <div style={{ display:"flex", alignItems:"center", gap:14 }}>
            <span style={{ fontSize:34 }}>☁️</span>
            <div>
              <div style={{ color:"white", fontSize:19, fontWeight:700 }}>Office 365 Integration</div>
              <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, fontFamily:"monospace", marginTop:3 }}>Cloud Management · Wazuh native office365 module</div>
            </div>
          </div>
          <button onClick={onClose} style={{ background:"none", border:"none", color:"rgba(255,255,255,0.4)", cursor:"pointer", fontSize:22 }}>×</button>
        </div>

        <div style={{ color:"rgba(255,255,255,0.5)", fontSize:12, lineHeight:1.7, marginBottom:24 }}>
          Configure the Wazuh native <code style={{ color:"#0078d4" }}>office365</code> module to ingest Microsoft 365 audit logs into CySIEM.
          Credentials are written directly into <code style={{ color:"rgba(255,255,255,0.6)" }}>/var/ossec/etc/ossec.conf</code> and
          <strong style={{ color:"rgba(255,255,255,0.75)" }}> wazuh-manager is restarted automatically</strong>.
        </div>

        {loadError && (
          <div style={{ background:"rgba(255,59,59,0.08)", border:"1px solid rgba(255,59,59,0.25)", borderRadius:4, padding:"10px 14px", fontSize:12, color:"#ff8080", marginBottom:18 }}>
            {loadError}
          </div>
        )}

        <form onSubmit={handleSave}>
          {/* Azure App Credentials */}
          <div style={{ background:"rgba(0,120,212,0.05)", border:"1px solid rgba(0,120,212,0.15)", borderRadius:6, padding:"18px 20px", marginBottom:20 }}>
            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.5px", fontFamily:"monospace", textTransform:"uppercase", marginBottom:16 }}>Azure App Credentials</div>

            <div style={{ marginBottom:14 }}>
              <label style={labelStyle}>Tenant ID</label>
              <input value={tenantId} onChange={e => setTenantId(e.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" required style={inputStyle} />
            </div>
            <div style={{ marginBottom:14 }}>
              <label style={labelStyle}>Client ID (Application ID)</label>
              <input value={clientId} onChange={e => setClientId(e.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" required style={inputStyle} />
            </div>
            <div style={{ marginBottom:14 }}>
              <label style={labelStyle}>Client Secret</label>
              <input type="password" value={clientSecret} onChange={e => setClientSecret(e.target.value)} placeholder={hasExistingSecret ? "Leave blank to keep existing secret" : "Enter client secret"} required={!hasExistingSecret} style={inputStyle} autoComplete="new-password" />
              <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace", marginTop:5 }}>
                {hasExistingSecret ? "Secret already configured — leave blank to keep it unchanged" : "Secret is write-only — never returned by the API"}
              </div>
            </div>
            <div>
              <label style={labelStyle}>Subscription Plan (api_type)</label>
              <select value={apiType} onChange={e => setApiType(e.target.value)} style={{ ...inputStyle, cursor:"pointer" }}>
                {O365_API_TYPES.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
              </select>
              <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace", marginTop:5 }}>
                commercial — standard Microsoft 365 · gcc / gcc-high — US government plans
              </div>
            </div>
          </div>

          {/* Poll Interval */}
          <div style={{ marginBottom:20 }}>
            <label style={labelStyle}>Poll Interval</label>
            <select value={interval} onChange={e => setInterval(e.target.value)} style={{ ...inputStyle, cursor:"pointer" }}>
              {O365_INTERVALS.map(i => <option key={i} value={i}>{i}</option>)}
            </select>
          </div>

          {/* Subscriptions */}
          <div style={{ marginBottom:20 }}>
            <div style={{ ...labelStyle, marginBottom:12 }}>Audit Log Subscriptions</div>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8 }}>
              {O365_SUBSCRIPTIONS.map(s => (
                <label key={s.id} style={{ display:"flex", alignItems:"center", gap:9, cursor:"pointer", background:"rgba(255,255,255,0.03)", border:`1px solid ${subs.includes(s.id)?"rgba(0,120,212,0.4)":"rgba(255,255,255,0.07)"}`, borderRadius:4, padding:"8px 12px" }}>
                  <input type="checkbox" checked={subs.includes(s.id)} onChange={() => toggleSub(s.id)}
                    style={{ accentColor:"#0078d4", width:14, height:14, cursor:"pointer" }} />
                  <span style={{ color: subs.includes(s.id) ? "rgba(255,255,255,0.8)" : "rgba(255,255,255,0.4)", fontSize:12 }}>{s.label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Enable toggle */}
          <div style={{ display:"flex", flexDirection:"column", gap:10, marginBottom:24 }}>
            <div style={{ display:"flex", alignItems:"center", gap:10 }}>
              <input type="checkbox" id="o365enabled" checked={enabled} onChange={e => setEnabled(e.target.checked)}
                style={{ accentColor:"#0078d4", width:15, height:15, cursor:"pointer" }} />
              <label htmlFor="o365enabled" style={{ color:"rgba(255,255,255,0.6)", fontSize:13, cursor:"pointer" }}>
                Enable integration (<code style={{ color:"#0078d4" }}>enabled=yes</code> in ossec.conf)
              </label>
            </div>
            <div style={{ display:"flex", alignItems:"center", gap:10 }}>
              <input type="checkbox" id="o365future" checked={onlyFutureEvents} onChange={e => setOnlyFutureEvents(e.target.checked)}
                style={{ accentColor:"#0078d4", width:15, height:15, cursor:"pointer" }} />
              <label htmlFor="o365future" style={{ color:"rgba(255,255,255,0.6)", fontSize:13, cursor:"pointer" }}>
                Only future events (<code style={{ color:"#0078d4" }}>only_future_events=yes</code> — skip historical logs)
              </label>
            </div>
          </div>

          {/* Result banner */}
          {result && (
            <div style={{ background: result.ok ? "rgba(0,229,160,0.08)" : "rgba(255,59,59,0.08)", border: `1px solid ${result.ok ? "rgba(0,229,160,0.25)" : "rgba(255,59,59,0.25)"}`, borderRadius:4, padding:"10px 14px", fontSize:12, color: result.ok ? "#00e5a0" : "#ff8080", marginBottom:18 }}>
              {result.ok ? "✓ " : "✗ "}{result.msg}
            </div>
          )}

          {/* Actions */}
          <div style={{ display:"flex", gap:10 }}>
            <button type="submit" disabled={saving}
              style={{ flex:1, background: saving ? "rgba(0,120,212,0.4)" : "#0078d4", color:"white", border:"none", borderRadius:4, padding:"12px", fontFamily:"monospace", fontSize:12, fontWeight:700, cursor: saving ? "not-allowed" : "pointer", letterSpacing:"1px", textTransform:"uppercase" }}>
              {saving ? "Applying…" : "Apply Configuration"}
            </button>
            <button type="button" onClick={onClose}
              style={{ padding:"12px 20px", background:"transparent", color:"rgba(255,255,255,0.4)", border:"1px solid rgba(255,255,255,0.12)", borderRadius:4, fontFamily:"monospace", fontSize:12, cursor:"pointer" }}>
              Close
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

const GCP_INTERVALS = ["1m","5m","10m","15m","30m","1h","2h","6h","12h","24h"];
const GCP_LOG_LEVELS = ["debug","info","warning","error","critical"];

function GCloudConfigModal({ uc, onClose }) {
  const [credentialsJson,   setCredentialsJson]   = useState(null);   // parsed JSON object
  const [credentialsName,   setCredentialsName]   = useState("");      // display filename
  const [projectId,         setProjectId]         = useState("");
  const [subscriptionName,  setSubscriptionName]  = useState("");
  const [interval,          setInterval]          = useState("5m");
  const [maxMessages,       setMaxMessages]       = useState(100);
  const [logLevel,          setLogLevel]          = useState("info");
  const [enabled,           setEnabled]           = useState(true);
  const [dragging,          setDragging]          = useState(false);
  const [saving,            setSaving]            = useState(false);
  const [result,            setResult]            = useState(null);
  const [loadError,         setLoadError]         = useState(null);
  const [hasExistingCreds,  setHasExistingCreds]  = useState(false);

  useEffect(() => {
    fetch(`${API_BASE}/api/system/gcloudconfig`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        if (d.ok) {
          if (d.project_id)        setProjectId(d.project_id);
          if (d.subscription_name) setSubscriptionName(d.subscription_name);
          if (d.interval)          setInterval(d.interval);
          if (d.max_messages)      setMaxMessages(d.max_messages);
          if (d.logging)           setLogLevel(d.logging);
          setEnabled(d.enabled !== false);
          setHasExistingCreds(!!d.has_credentials);
        }
      })
      .catch(err => {
        if (err !== 404) setLoadError("Could not load current config.");
      });
  }, []);

  function handleFileRead(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const parsed = JSON.parse(e.target.result);
        setCredentialsJson(parsed);
        setCredentialsName(file.name);
        // Auto-populate project ID from the key file if not already set
        if (parsed.project_id && !projectId) setProjectId(parsed.project_id);
        setResult(null);
      } catch {
        setResult({ ok: false, msg: "Invalid JSON file — please upload a GCP service account key" });
      }
    };
    reader.readAsText(file);
  }

  function handleDropZoneClick() {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json,application/json";
    input.onchange = e => handleFileRead(e.target.files[0]);
    input.click();
  }

  function handleDrop(e) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileRead(file);
  }

  function handleSave(ev) {
    ev.preventDefault();
    setResult(null);
    setSaving(true);
    fetch(`${API_BASE}/api/system/gcloudconfig`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credentials_json: credentialsJson || null,
        project_id: projectId,
        subscription_name: subscriptionName,
        interval,
        max_messages: maxMessages,
        logging: logLevel,
        enabled,
      }),
    })
      .then(r => r.json().then(d => ({ ok: r.ok, data: d })))
      .then(({ ok, data }) => {
        const success = ok && data.ok;
        let msg = data.message || data.error || (ok ? "Saved" : "Error");
        if (success && data.rules_deployed) msg += " · Custom GCP security rules deployed.";
        setResult({ ok: success, msg });
        if (success) setHasExistingCreds(true);
      })
      .catch(() => setResult({ ok: false, msg: "Network error" }))
      .finally(() => setSaving(false));
  }

  if (!uc) return null;

  const inputStyle = {
    width: "100%", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
    borderRadius: 4, padding: "9px 12px", color: "white", fontSize: 13, fontFamily: "monospace",
    outline: "none", boxSizing: "border-box",
  };
  const labelStyle = { color: "rgba(255,255,255,0.45)", fontSize: 11, fontFamily: "monospace", letterSpacing: "0.8px", textTransform: "uppercase", marginBottom: 6, display: "block" };
  const GCP_BLUE = "#4285f4";

  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.88)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:150, backdropFilter:"blur(6px)" }} onClick={onClose}>
      <div style={{ background:"#0d0f14", border:`1px solid ${GCP_BLUE}40`, borderTop:`2px solid ${GCP_BLUE}`, borderRadius:8, padding:36, width:"min(580px,95vw)", maxHeight:"90vh", overflowY:"auto" }} onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:24 }}>
          <div style={{ display:"flex", alignItems:"center", gap:14 }}>
            <span style={{ fontSize:34 }}>🔵</span>
            <div>
              <div style={{ color:"white", fontSize:19, fontWeight:700 }}>Google Cloud Integration</div>
              <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, fontFamily:"monospace", marginTop:3 }}>Cloud Management · Wazuh gcp-pubsub wodle</div>
            </div>
          </div>
          <button onClick={onClose} style={{ background:"none", border:"none", color:"rgba(255,255,255,0.4)", cursor:"pointer", fontSize:22 }}>×</button>
        </div>

        <div style={{ color:"rgba(255,255,255,0.5)", fontSize:12, lineHeight:1.7, marginBottom:24 }}>
          Upload your GCP Service Account key to configure the Wazuh <code style={{ color:GCP_BLUE }}>gcp-pubsub</code> wodle.
          Credentials are saved to <code style={{ color:"rgba(255,255,255,0.6)" }}>/var/ossec/etc/gcp_credentials.json</code> and
          <strong style={{ color:"rgba(255,255,255,0.75)" }}> wazuh-manager is restarted automatically</strong>.
          Custom GCP security rules are deployed on first save.
        </div>

        {loadError && (
          <div style={{ background:"rgba(255,59,59,0.08)", border:"1px solid rgba(255,59,59,0.25)", borderRadius:4, padding:"10px 14px", fontSize:12, color:"#ff8080", marginBottom:18 }}>
            {loadError}
          </div>
        )}

        <form onSubmit={handleSave}>
          {/* Credentials Upload */}
          <div style={{ background:`rgba(66,133,244,0.05)`, border:`1px solid rgba(66,133,244,0.15)`, borderRadius:6, padding:"18px 20px", marginBottom:20 }}>
            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.5px", fontFamily:"monospace", textTransform:"uppercase", marginBottom:14 }}>Service Account Key</div>

            {/* Drop zone */}
            <div
              onClick={handleDropZoneClick}
              onDragOver={e => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={handleDrop}
              style={{
                border: `2px dashed ${dragging ? GCP_BLUE : (credentialsJson || hasExistingCreds) ? "rgba(0,229,160,0.5)" : "rgba(255,255,255,0.15)"}`,
                borderRadius: 6, padding: "22px 16px", textAlign: "center", cursor: "pointer",
                background: dragging ? `rgba(66,133,244,0.08)` : "rgba(255,255,255,0.02)",
                transition: "border-color 0.15s, background 0.15s",
              }}
            >
              {credentialsJson ? (
                <div>
                  <div style={{ fontSize:22, marginBottom:6 }}>✅</div>
                  <div style={{ color:"#00e5a0", fontSize:13, fontFamily:"monospace" }}>{credentialsName}</div>
                  <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, marginTop:4 }}>Click to replace</div>
                </div>
              ) : hasExistingCreds ? (
                <div>
                  <div style={{ fontSize:22, marginBottom:6 }}>🔑</div>
                  <div style={{ color:"rgba(255,255,255,0.6)", fontSize:12 }}>Credentials already configured</div>
                  <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, marginTop:4 }}>Click or drag a new JSON key to replace</div>
                </div>
              ) : (
                <div>
                  <div style={{ fontSize:28, marginBottom:8 }}>📂</div>
                  <div style={{ color:"rgba(255,255,255,0.6)", fontSize:13 }}>Drag &amp; Drop or <span style={{ color:GCP_BLUE }}>Browse</span></div>
                  <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, marginTop:6 }}>GCP Service Account JSON key file</div>
                </div>
              )}
            </div>

            {!credentialsJson && !hasExistingCreds && (
              <div style={{ color:"rgba(255,59,59,0.7)", fontSize:10, fontFamily:"monospace", marginTop:8 }}>
                ⚠ A service account JSON key is required for initial setup
              </div>
            )}
          </div>

          {/* Project ID */}
          <div style={{ marginBottom:14 }}>
            <label style={labelStyle}>Project ID</label>
            <input value={projectId} onChange={e => setProjectId(e.target.value)}
              placeholder="my-gcp-project-123" required style={inputStyle} />
          </div>

          {/* Subscription Name */}
          <div style={{ marginBottom:14 }}>
            <label style={labelStyle}>Pub/Sub Subscription Name</label>
            <input value={subscriptionName} onChange={e => setSubscriptionName(e.target.value)}
              placeholder="projects/my-project/subscriptions/wazuh-sub" required style={inputStyle} />
            <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace", marginTop:5 }}>
              Full subscription path: <code>projects/&lt;PROJECT&gt;/subscriptions/&lt;NAME&gt;</code>
            </div>
          </div>

          {/* Poll Interval + Max Messages */}
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14, marginBottom:20 }}>
            <div>
              <label style={labelStyle}>Poll Interval</label>
              <select value={interval} onChange={e => setInterval(e.target.value)} style={{ ...inputStyle, cursor:"pointer" }}>
                {GCP_INTERVALS.map(i => <option key={i} value={i}>{i}</option>)}
              </select>
            </div>
            <div>
              <label style={labelStyle}>Max Messages / Pull</label>
              <input type="number" min={1} max={1000} value={maxMessages}
                onChange={e => setMaxMessages(Number(e.target.value))} style={inputStyle} />
            </div>
          </div>

          {/* Log Level */}
          <div style={{ marginBottom:20 }}>
            <label style={labelStyle}>Logging Level</label>
            <select value={logLevel} onChange={e => setLogLevel(e.target.value)} style={{ ...inputStyle, cursor:"pointer" }}>
              {GCP_LOG_LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>

          {/* Enable toggle */}
          <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:24 }}>
            <input type="checkbox" id="gcpenabled" checked={enabled} onChange={e => setEnabled(e.target.checked)}
              style={{ accentColor:GCP_BLUE, width:15, height:15, cursor:"pointer" }} />
            <label htmlFor="gcpenabled" style={{ color:"rgba(255,255,255,0.6)", fontSize:13, cursor:"pointer" }}>
              Enable integration (<code style={{ color:GCP_BLUE }}>disabled=no</code> in ossec.conf)
            </label>
          </div>

          {/* Custom rules note */}
          <div style={{ background:"rgba(0,229,160,0.04)", border:"1px solid rgba(0,229,160,0.12)", borderRadius:4, padding:"10px 14px", fontSize:11, color:"rgba(255,255,255,0.4)", fontFamily:"monospace", marginBottom:20 }}>
            ✦ 5 custom GCP security rules will be deployed to <code>/var/ossec/etc/rules/cycentra_gcp_rules.xml</code> on save —
            covering IAM privilege escalation, firewall changes, storage exposure, and project deletion.
          </div>

          {/* Result banner */}
          {result && (
            <div style={{ background: result.ok ? "rgba(0,229,160,0.08)" : "rgba(255,59,59,0.08)", border: `1px solid ${result.ok ? "rgba(0,229,160,0.25)" : "rgba(255,59,59,0.25)"}`, borderRadius:4, padding:"10px 14px", fontSize:12, color: result.ok ? "#00e5a0" : "#ff8080", marginBottom:18 }}>
              {result.ok ? "✓ " : "✗ "}{result.msg}
            </div>
          )}

          {/* Actions */}
          <div style={{ display:"flex", gap:10 }}>
            <button type="submit" disabled={saving}
              style={{ flex:1, background: saving ? `rgba(66,133,244,0.4)` : GCP_BLUE, color:"white", border:"none", borderRadius:4, padding:"12px", fontFamily:"monospace", fontSize:12, fontWeight:700, cursor: saving ? "not-allowed" : "pointer", letterSpacing:"1px", textTransform:"uppercase" }}>
              {saving ? "Applying…" : "Apply Configuration"}
            </button>
            <button type="button" onClick={onClose}
              style={{ padding:"12px 20px", background:"transparent", color:"rgba(255,255,255,0.4)", border:"1px solid rgba(255,255,255,0.12)", borderRadius:4, fontFamily:"monospace", fontSize:12, cursor:"pointer" }}>
              Close
            </button>
          </div>
        </form>
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
          Pre-built CySOAR automation playbooks and cloud integration configurators.
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

      {expanded && (
        expanded.isGCloudWidget
          ? <GCloudConfigModal uc={expanded} onClose={() => setExpanded(null)}/>
          : expanded.isConfigWidget
            ? <O365ConfigModal uc={expanded} onClose={() => setExpanded(null)}/>
            : <UseCaseModal    uc={expanded} onClose={() => setExpanded(null)}/>
      )}
    </div>
  );
}
