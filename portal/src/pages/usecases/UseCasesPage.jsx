/**
 * src/pages/usecases/UseCasesPage.jsx
 * ======================================
 * My Integrations & Playbooks — shows items the user has pulled from the
 * Integration Marketplace. No items are hardcoded; everything originates
 * from the cloud marketplace via GET /api/marketplace/catalog.
 */

import { useState, useEffect } from "react";
import { API_BASE } from "../../core/constants";

// ── Installed item card ───────────────────────────────────────────────────────

function InstalledCard({ item, isConfigured, onOpen }) {
  const isIntegration = item.type === "integration";
  const hasConfig     = !!item.config_type;
  return (
    <div style={{ background:"rgba(255,255,255,0.025)", border:`1px solid ${item.color}20`, borderTop:`2px solid ${item.color}`, borderRadius:5, padding:"20px 22px", display:"flex", flexDirection:"column" }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:10 }}>
        <span style={{ background:isIntegration?"rgba(0,229,160,0.08)":"rgba(77,158,255,0.08)", color:isIntegration?"#00e5a0":"#4d9eff", border:`1px solid ${isIntegration?"rgba(0,229,160,0.2)":"rgba(77,158,255,0.2)"}`, fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, letterSpacing:"1px", textTransform:"uppercase" }}>
          {isIntegration ? "Integration" : "Playbook"}
        </span>
        {hasConfig ? (
          isConfigured
            ? <span style={{ background:"rgba(0,229,160,0.1)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.25)", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, letterSpacing:"1px" }}>✓ ACTIVE</span>
            : <span style={{ background:"rgba(255,180,0,0.1)", color:"#ffb400", border:"1px solid rgba(255,180,0,0.3)", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, letterSpacing:"1px" }}>⚠ NEEDS SETUP</span>
        ) : (
          <span style={{ background:"rgba(0,229,160,0.1)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.25)", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, letterSpacing:"1px" }}>✓ INSTALLED</span>
        )}
      </div>
      <div style={{ display:"flex", gap:12, alignItems:"flex-start", marginBottom:10 }}>
        <span style={{ fontSize:22 }}>{item.icon}</span>
        <div style={{ flex:1 }}>
          <div style={{ color:"white", fontSize:15, fontWeight:700 }}>{item.name}</div>
          <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace", marginTop:2 }}>{item.vendor} · {item.category}</div>
        </div>
      </div>
      <div style={{ color:"rgba(255,255,255,0.55)", fontSize:12, lineHeight:1.6, marginBottom:14, flex:1 }}>{item.description}</div>
      <div style={{ display:"flex", flexWrap:"wrap", gap:5, marginBottom:14 }}>
        {item.modules_required?.map(m => (
          <span key={m} style={{ background:"rgba(255,255,255,0.06)", color:"rgba(255,255,255,0.5)", border:"1px solid rgba(255,255,255,0.1)", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2 }}>{m}</span>
        ))}
      </div>
      <button onClick={() => onOpen(item)}
        style={{ width:"100%", background:hasConfig?item.color:"rgba(255,255,255,0.04)", color:hasConfig?"#0d0f14":"rgba(255,255,255,0.6)", border:hasConfig?"none":"1px solid rgba(255,255,255,0.1)", borderRadius:4, padding:"9px 12px", fontFamily:"monospace", fontSize:11, fontWeight:700, cursor:"pointer", letterSpacing:"1px", textTransform:"uppercase" }}>
        {isIntegration && hasConfig ? "Configure" : isIntegration ? "View Details" : "View Steps"}
      </button>
    </div>
  );
}

// ── Steps / detail modal (playbooks + unconfigured integrations) ──────────────

function StepsModal({ item, onClose }) {
  if (!item) return null;
  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.88)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:150, backdropFilter:"blur(6px)" }} onClick={onClose}>
      <div style={{ background:"#0d0f14", border:`1px solid ${item.color}40`, borderTop:`2px solid ${item.color}`, borderRadius:8, padding:36, width:"min(640px,95vw)", maxHeight:"85vh", overflowY:"auto" }} onClick={e => e.stopPropagation()}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:24 }}>
          <div style={{ display:"flex", alignItems:"center", gap:14 }}>
            <span style={{ fontSize:36 }}>{item.icon}</span>
            <div>
              <div style={{ color:"white", fontSize:20, fontWeight:700 }}>{item.name}</div>
              <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, fontFamily:"monospace", marginTop:3 }}>{item.category} · {item.estimated_time}</div>
            </div>
          </div>
          <button onClick={onClose} style={{ background:"none", border:"none", color:"rgba(255,255,255,0.4)", cursor:"pointer", fontSize:22 }}>×</button>
        </div>
        <div style={{ color:"rgba(255,255,255,0.6)", fontSize:13, lineHeight:1.7, marginBottom:24 }}>{item.description}</div>
        {item.steps?.length > 0 && (
          <div style={{ marginBottom:24 }}>
            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:12 }}>Automation Steps</div>
            {item.steps.map((step, i) => (
              <div key={i} style={{ display:"flex", gap:12, alignItems:"flex-start", marginBottom:10 }}>
                <div style={{ width:22, height:22, borderRadius:"50%", background:`${item.color}20`, border:`1px solid ${item.color}40`, display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0, marginTop:1 }}>
                  <span style={{ color:item.color, fontSize:10, fontWeight:700, fontFamily:"monospace" }}>{i + 1}</span>
                </div>
                <span style={{ color:"rgba(255,255,255,0.65)", fontSize:13, lineHeight:1.5, paddingTop:2 }}>{step}</span>
              </div>
            ))}
          </div>
        )}
        {item.cysoar_flow && (
          <div style={{ background:"rgba(0,0,0,0.4)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:4, padding:"14px 18px", marginBottom:24 }}>
            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace", marginBottom:6 }}>CYSOAR FLOW</div>
            <code style={{ color:"#00e5a0", fontSize:12, fontFamily:"monospace" }}>cysoar import-flow {item.cysoar_flow} --workspace cycentra</code>
          </div>
        )}
        <button onClick={onClose} style={{ width:"100%", background:"transparent", color:"rgba(255,255,255,0.4)", border:"1px solid rgba(255,255,255,0.12)", borderRadius:4, padding:"12px", fontFamily:"monospace", fontSize:12, cursor:"pointer" }}>Close</button>
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
  const [items,      setItems]      = useState([]);
  const [installed,  setInstalled]  = useState(new Set());
  const [configured, setConfigured] = useState(new Set());
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState(null);
  const [modal,      setModal]      = useState(null); // { type: 'o365'|'gcloud'|'steps', item }

  useEffect(() => {
    Promise.all([
      fetch(`${API_BASE}/api/marketplace/catalog`,   { credentials: "include" }).then(r => r.ok ? r.json() : Promise.reject("catalog")),
      fetch(`${API_BASE}/api/marketplace/installed`, { credentials: "include" }).then(r => r.ok ? r.json() : Promise.reject("installed")),
    ])
      .then(([cat, inst]) => {
        setItems(cat.items || []);
        setInstalled(new Set(inst.installed || []));
        setConfigured(new Set(inst.configured || []));
        setLoading(false);
      })
      .catch(() => { setError("Could not load installed items."); setLoading(false); });
  }, []);

  function openModal(item) {
    if (item.config_type === "o365")    setModal({ type: "o365",   item });
    else if (item.config_type === "gcloud") setModal({ type: "gcloud", item });
    else                                setModal({ type: "steps",  item });
  }

  const myItems = items.filter(i => installed.has(i.id));

  if (loading) return (
    <div style={{ padding:"40px 32px", color:"rgba(255,255,255,0.35)", fontFamily:"monospace", fontSize:13 }}>Loading…</div>
  );
  if (error) return (
    <div style={{ padding:"40px 32px", color:"#ff8080", fontFamily:"monospace", fontSize:13 }}>{error}</div>
  );

  return (
    <div>
      <div style={{ marginBottom:28 }}>
        <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:8 }}>
          <h1 style={{ fontSize:22, fontWeight:700, color:"white", margin:0 }}>My Integrations &amp; Playbooks</h1>
          {myItems.length > 0 && (
            <span style={{ background:"rgba(0,229,160,0.12)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.25)", fontSize:9, fontFamily:"monospace", padding:"3px 10px", borderRadius:2, fontWeight:700, letterSpacing:"1px" }}>
              {myItems.length} INSTALLED
            </span>
          )}
        </div>
        <p style={{ color:"rgba(255,255,255,0.4)", fontSize:13, margin:0 }}>
          Integrations and playbooks you have pulled from the marketplace.
        </p>
      </div>

      {myItems.length === 0 ? (
        <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:8, padding:"48px 32px", textAlign:"center" }}>
          <div style={{ fontSize:40, marginBottom:16 }}>📦</div>
          <div style={{ color:"rgba(255,255,255,0.6)", fontSize:15, fontWeight:600, marginBottom:8 }}>Nothing installed yet</div>
          <div style={{ color:"rgba(255,255,255,0.3)", fontSize:12, lineHeight:1.7, maxWidth:420, margin:"0 auto" }}>
            Browse the <strong style={{ color:"#00e5a0" }}>Integration Marketplace</strong> to discover
            and pull security playbooks and cloud integrations into your portal.
          </div>
        </div>
      ) : (
        <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(300px, 1fr))", gap:16 }}>
          {myItems.map(item => (
            <InstalledCard
              key={item.id}
              item={item}
              isConfigured={configured.has(item.id)}
              onOpen={openModal}
            />
          ))}
        </div>
      )}

      {modal?.type === "o365"   && <O365ConfigModal   uc={modal.item} onClose={() => setModal(null)} />}
      {modal?.type === "gcloud" && <GCloudConfigModal uc={modal.item} onClose={() => setModal(null)} />}
      {modal?.type === "steps"  && <StepsModal        item={modal.item} onClose={() => setModal(null)} />}
    </div>
  );
}
