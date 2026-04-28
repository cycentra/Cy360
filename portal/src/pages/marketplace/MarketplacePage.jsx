/**
 * src/pages/marketplace/MarketplacePage.jsx
 * ==========================================
 * Integration Marketplace — catalog is fetched through the cycentra360
 * backend proxy (/api/marketplace/catalog) so the cycentra.com token never
 * reaches the browser. Admins can add/edit/delete custom catalog items.
 *
 * Roles:
 *   any role  — browse, search, view details
 *   admin     — pull, configure, remove, add/edit/delete custom items
 */

import { useState, useEffect, useCallback } from "react";
import { API_BASE } from "../../core/constants";

// ── O365 config modal ─────────────────────────────────────────────────────────

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

function O365ConfigModal({ item, onClose, onSaved }) {
  const [tenantId,          setTenantId]          = useState("");
  const [clientId,          setClientId]          = useState("");
  const [clientSecret,      setClientSecret]      = useState("");
  const [apiType,           setApiType]           = useState("commercial");
  const [interval,          setIntervalVal]       = useState("1m");
  const [onlyFutureEvents,  setOnlyFutureEvents]  = useState(true);
  const [subs,              setSubs]              = useState(O365_SUBSCRIPTIONS.filter(s => s.id !== "DLP.All").map(s => s.id));
  const [enabled,           setEnabled]           = useState(true);
  const [saving,            setSaving]            = useState(false);
  const [result,            setResult]            = useState(null);
  const [loadError,         setLoadError]         = useState(null);
  const [hasExistingSecret, setHasExistingSecret] = useState(false);

  useEffect(() => {
    fetch(`${API_BASE}/api/system/o365config`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        if (d.ok) {
          if (d.tenant_id)  setTenantId(d.tenant_id);
          if (d.client_id)  setClientId(d.client_id);
          if (d.interval)   setIntervalVal(d.interval);
          if (d.api_type)   setApiType(d.api_type);
          if (d.subscriptions?.length) setSubs(d.subscriptions);
          setEnabled(d.enabled !== false);
          setOnlyFutureEvents(d.only_future_events !== false);
          setHasExistingSecret(!!d.tenant_id && !d.tenant_id.startsWith("PLACEHOLDER"));
        }
      })
      .catch(err => { if (err !== 404) setLoadError("Could not load current config."); });
  }, []);

  function toggleSub(id) {
    setSubs(prev => prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]);
  }

  function handleSave(e) {
    e.preventDefault();
    setResult(null);
    setSaving(true);
    fetch(`${API_BASE}/api/system/o365config`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tenant_id: tenantId, client_id: clientId, client_secret: clientSecret, api_type: apiType, interval, only_future_events: onlyFutureEvents, subscriptions: subs, enabled }),
    })
      .then(r => r.json().then(d => ({ ok: r.ok, data: d })))
      .then(({ ok, data }) => {
        setResult({ ok: ok && data.ok, msg: data.message || data.error || (ok ? "Saved" : "Error") });
        if (ok && data.ok && onSaved) onSaved();
      })
      .catch(() => setResult({ ok: false, msg: "Network error" }))
      .finally(() => setSaving(false));
  }

  const inp = { width:"100%", background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.12)", borderRadius:4, padding:"9px 12px", color:"white", fontSize:13, fontFamily:"monospace", outline:"none", boxSizing:"border-box" };
  const lbl = { color:"rgba(255,255,255,0.45)", fontSize:11, fontFamily:"monospace", letterSpacing:"0.8px", textTransform:"uppercase", marginBottom:6, display:"block" };

  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.88)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:150, backdropFilter:"blur(6px)" }} onClick={onClose}>
      <div style={{ background:"#0d0f14", border:"1px solid #0078d440", borderTop:"2px solid #0078d4", borderRadius:8, padding:36, width:"min(580px,95vw)", maxHeight:"90vh", overflowY:"auto" }} onClick={e => e.stopPropagation()}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:24 }}>
          <div style={{ display:"flex", alignItems:"center", gap:14 }}>
            <span style={{ fontSize:34 }}>☁️</span>
            <div>
              <div style={{ color:"white", fontSize:19, fontWeight:700 }}>Office 365 Integration</div>
              <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, fontFamily:"monospace", marginTop:3 }}>Cloud Integration · Wazuh native office365 module</div>
            </div>
          </div>
          <button onClick={onClose} style={{ background:"none", border:"none", color:"rgba(255,255,255,0.4)", cursor:"pointer", fontSize:22 }}>×</button>
        </div>

        <div style={{ color:"rgba(255,255,255,0.5)", fontSize:12, lineHeight:1.7, marginBottom:24 }}>
          Configure the Wazuh native <code style={{ color:"#0078d4" }}>office365</code> module to ingest Microsoft 365 audit logs into CySIEM.
          Credentials are written into <code style={{ color:"rgba(255,255,255,0.6)" }}>/var/ossec/etc/ossec.conf</code> and
          <strong style={{ color:"rgba(255,255,255,0.75)" }}> wazuh-manager is restarted automatically</strong>.
        </div>

        {loadError && <div style={{ background:"rgba(255,59,59,0.08)", border:"1px solid rgba(255,59,59,0.25)", borderRadius:4, padding:"10px 14px", fontSize:12, color:"#ff8080", marginBottom:18 }}>{loadError}</div>}

        <form onSubmit={handleSave}>
          <div style={{ background:"rgba(0,120,212,0.05)", border:"1px solid rgba(0,120,212,0.15)", borderRadius:6, padding:"18px 20px", marginBottom:20 }}>
            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.5px", fontFamily:"monospace", textTransform:"uppercase", marginBottom:16 }}>Azure App Credentials</div>
            <div style={{ marginBottom:14 }}>
              <label style={lbl}>Tenant ID</label>
              <input value={tenantId} onChange={e => setTenantId(e.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" required style={inp} />
            </div>
            <div style={{ marginBottom:14 }}>
              <label style={lbl}>Client ID (Application ID)</label>
              <input value={clientId} onChange={e => setClientId(e.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" required style={inp} />
            </div>
            <div style={{ marginBottom:14 }}>
              <label style={lbl}>Client Secret</label>
              <input type="password" value={clientSecret} onChange={e => setClientSecret(e.target.value)} placeholder={hasExistingSecret ? "Leave blank to keep existing secret" : "Enter client secret"} required={!hasExistingSecret} style={inp} autoComplete="new-password" />
              <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace", marginTop:5 }}>
                {hasExistingSecret ? "Secret already configured — leave blank to keep unchanged" : "Write-only — never returned by the API"}
              </div>
            </div>
            <div>
              <label style={lbl}>Subscription Plan (api_type)</label>
              <select value={apiType} onChange={e => setApiType(e.target.value)} style={{ ...inp, cursor:"pointer" }}>
                {O365_API_TYPES.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
              </select>
              <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace", marginTop:5 }}>
                commercial — standard Microsoft 365 · gcc / gcc-high — US government plans
              </div>
            </div>
          </div>

          <div style={{ marginBottom:20 }}>
            <label style={lbl}>Poll Interval</label>
            <select value={interval} onChange={e => setIntervalVal(e.target.value)} style={{ ...inp, cursor:"pointer" }}>
              {O365_INTERVALS.map(i => <option key={i} value={i}>{i}</option>)}
            </select>
          </div>

          <div style={{ marginBottom:20 }}>
            <div style={{ ...lbl, marginBottom:12 }}>Audit Log Subscriptions</div>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8 }}>
              {O365_SUBSCRIPTIONS.map(s => (
                <label key={s.id} style={{ display:"flex", alignItems:"center", gap:9, cursor:"pointer", background:"rgba(255,255,255,0.03)", border:`1px solid ${subs.includes(s.id)?"rgba(0,120,212,0.4)":"rgba(255,255,255,0.07)"}`, borderRadius:4, padding:"8px 12px" }}>
                  <input type="checkbox" checked={subs.includes(s.id)} onChange={() => toggleSub(s.id)} style={{ accentColor:"#0078d4", width:14, height:14, cursor:"pointer" }} />
                  <span style={{ color:subs.includes(s.id)?"rgba(255,255,255,0.8)":"rgba(255,255,255,0.4)", fontSize:12 }}>{s.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div style={{ display:"flex", flexDirection:"column", gap:10, marginBottom:24 }}>
            <div style={{ display:"flex", alignItems:"center", gap:10 }}>
              <input type="checkbox" id="o365enabledMkt" checked={enabled} onChange={e => setEnabled(e.target.checked)} style={{ accentColor:"#0078d4", width:15, height:15, cursor:"pointer" }} />
              <label htmlFor="o365enabledMkt" style={{ color:"rgba(255,255,255,0.6)", fontSize:13, cursor:"pointer" }}>
                Enable integration (<code style={{ color:"#0078d4" }}>enabled=yes</code>)
              </label>
            </div>
            <div style={{ display:"flex", alignItems:"center", gap:10 }}>
              <input type="checkbox" id="o365futureMkt" checked={onlyFutureEvents} onChange={e => setOnlyFutureEvents(e.target.checked)} style={{ accentColor:"#0078d4", width:15, height:15, cursor:"pointer" }} />
              <label htmlFor="o365futureMkt" style={{ color:"rgba(255,255,255,0.6)", fontSize:13, cursor:"pointer" }}>
                Only future events (<code style={{ color:"#0078d4" }}>only_future_events=yes</code>)
              </label>
            </div>
          </div>

          {result && (
            <div style={{ background:result.ok?"rgba(0,229,160,0.08)":"rgba(255,59,59,0.08)", border:`1px solid ${result.ok?"rgba(0,229,160,0.25)":"rgba(255,59,59,0.25)"}`, borderRadius:4, padding:"10px 14px", fontSize:12, color:result.ok?"#00e5a0":"#ff8080", marginBottom:18 }}>
              {result.ok ? "✓ " : "✗ "}{result.msg}
            </div>
          )}

          <div style={{ display:"flex", gap:10 }}>
            <button type="submit" disabled={saving} style={{ flex:1, background:saving?"rgba(0,120,212,0.4)":"#0078d4", color:"white", border:"none", borderRadius:4, padding:"12px", fontFamily:"monospace", fontSize:12, fontWeight:700, cursor:saving?"not-allowed":"pointer", letterSpacing:"1px", textTransform:"uppercase" }}>
              {saving ? "Applying…" : "Apply Configuration"}
            </button>
            <button type="button" onClick={onClose} style={{ padding:"12px 20px", background:"transparent", color:"rgba(255,255,255,0.4)", border:"1px solid rgba(255,255,255,0.12)", borderRadius:4, fontFamily:"monospace", fontSize:12, cursor:"pointer" }}>
              Close
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── GCloud config modal ───────────────────────────────────────────────────────

const GCP_INTERVALS  = ["1m","5m","10m","15m","30m","1h","2h","6h","12h","24h"];
const GCP_LOG_LEVELS = ["debug","info","warning","error","critical"];
const GCP_BLUE       = "#4285f4";

function GCloudConfigModal({ item, onClose }) {
  const [credentialsJson,  setCredentialsJson]  = useState(null);
  const [credentialsName,  setCredentialsName]  = useState("");
  const [projectId,        setProjectId]        = useState("");
  const [subscriptionName, setSubscriptionName] = useState("");
  const [interval,         setIntervalVal]      = useState("5m");
  const [maxMessages,      setMaxMessages]      = useState(100);
  const [logLevel,         setLogLevel]         = useState("info");
  const [enabled,          setEnabled]          = useState(true);
  const [dragging,         setDragging]         = useState(false);
  const [saving,           setSaving]           = useState(false);
  const [result,           setResult]           = useState(null);
  const [loadError,        setLoadError]        = useState(null);
  const [hasExistingCreds, setHasExistingCreds] = useState(false);

  useEffect(() => {
    fetch(`${API_BASE}/api/system/gcloudconfig`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        if (d.ok) {
          if (d.project_id)        setProjectId(d.project_id);
          if (d.subscription_name) setSubscriptionName(d.subscription_name);
          if (d.interval)          setIntervalVal(d.interval);
          if (d.max_messages)      setMaxMessages(d.max_messages);
          if (d.logging)           setLogLevel(d.logging);
          setEnabled(d.enabled !== false);
          setHasExistingCreds(!!d.has_credentials);
        }
      })
      .catch(err => { if (err !== 404) setLoadError("Could not load current config."); });
  }, []);

  function handleFileRead(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const parsed = JSON.parse(e.target.result);
        setCredentialsJson(parsed);
        setCredentialsName(file.name);
        if (parsed.project_id && !projectId) setProjectId(parsed.project_id);
        setResult(null);
      } catch {
        setResult({ ok: false, msg: "Invalid JSON file — upload a GCP service account key" });
      }
    };
    reader.readAsText(file);
  }

  function handleDropZoneClick() {
    const input = document.createElement("input");
    input.type = "file"; input.accept = ".json,application/json";
    input.onchange = e => handleFileRead(e.target.files[0]);
    input.click();
  }

  function handleDrop(e) {
    e.preventDefault(); setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileRead(file);
  }

  function handleSave(ev) {
    ev.preventDefault(); setResult(null); setSaving(true);
    fetch(`${API_BASE}/api/system/gcloudconfig`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credentials_json: credentialsJson || null, project_id: projectId, subscription_name: subscriptionName, interval, max_messages: maxMessages, logging: logLevel, enabled }),
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

  const inp = { width:"100%", background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.12)", borderRadius:4, padding:"9px 12px", color:"white", fontSize:13, fontFamily:"monospace", outline:"none", boxSizing:"border-box" };
  const lbl = { color:"rgba(255,255,255,0.45)", fontSize:11, fontFamily:"monospace", letterSpacing:"0.8px", textTransform:"uppercase", marginBottom:6, display:"block" };

  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.88)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:150, backdropFilter:"blur(6px)" }} onClick={onClose}>
      <div style={{ background:"#0d0f14", border:`1px solid ${GCP_BLUE}40`, borderTop:`2px solid ${GCP_BLUE}`, borderRadius:8, padding:36, width:"min(580px,95vw)", maxHeight:"90vh", overflowY:"auto" }} onClick={e => e.stopPropagation()}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:24 }}>
          <div style={{ display:"flex", alignItems:"center", gap:14 }}>
            <span style={{ fontSize:34 }}>🔵</span>
            <div>
              <div style={{ color:"white", fontSize:19, fontWeight:700 }}>Google Cloud Integration</div>
              <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, fontFamily:"monospace", marginTop:3 }}>Cloud Integration · Wazuh gcp-pubsub wodle</div>
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

        {loadError && <div style={{ background:"rgba(255,59,59,0.08)", border:"1px solid rgba(255,59,59,0.25)", borderRadius:4, padding:"10px 14px", fontSize:12, color:"#ff8080", marginBottom:18 }}>{loadError}</div>}

        <form onSubmit={handleSave}>
          <div style={{ background:`rgba(66,133,244,0.05)`, border:`1px solid rgba(66,133,244,0.15)`, borderRadius:6, padding:"18px 20px", marginBottom:20 }}>
            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.5px", fontFamily:"monospace", textTransform:"uppercase", marginBottom:14 }}>Service Account Key</div>
            <div
              onClick={handleDropZoneClick}
              onDragOver={e => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={handleDrop}
              style={{ border:`2px dashed ${dragging ? GCP_BLUE : (credentialsJson || hasExistingCreds) ? "rgba(0,229,160,0.5)" : "rgba(255,255,255,0.15)"}`, borderRadius:6, padding:"22px 16px", textAlign:"center", cursor:"pointer", background:dragging?`rgba(66,133,244,0.08)`:"rgba(255,255,255,0.02)", transition:"border-color 0.15s, background 0.15s" }}
            >
              {credentialsJson ? (
                <div><div style={{ fontSize:22, marginBottom:6 }}>✅</div><div style={{ color:"#00e5a0", fontSize:13, fontFamily:"monospace" }}>{credentialsName}</div><div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, marginTop:4 }}>Click to replace</div></div>
              ) : hasExistingCreds ? (
                <div><div style={{ fontSize:22, marginBottom:6 }}>🔑</div><div style={{ color:"rgba(255,255,255,0.6)", fontSize:12 }}>Credentials already configured</div><div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, marginTop:4 }}>Click or drag a new JSON key to replace</div></div>
              ) : (
                <div><div style={{ fontSize:28, marginBottom:8 }}>📂</div><div style={{ color:"rgba(255,255,255,0.6)", fontSize:13 }}>Drag &amp; Drop or <span style={{ color:GCP_BLUE }}>Browse</span></div><div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, marginTop:6 }}>GCP Service Account JSON key file</div></div>
              )}
            </div>
            {!credentialsJson && !hasExistingCreds && <div style={{ color:"rgba(255,59,59,0.7)", fontSize:10, fontFamily:"monospace", marginTop:8 }}>⚠ A service account JSON key is required for initial setup</div>}
          </div>

          <div style={{ marginBottom:14 }}>
            <label style={lbl}>Project ID</label>
            <input value={projectId} onChange={e => setProjectId(e.target.value)} placeholder="my-gcp-project-123" required style={inp} />
          </div>
          <div style={{ marginBottom:14 }}>
            <label style={lbl}>Pub/Sub Subscription Name</label>
            <input value={subscriptionName} onChange={e => setSubscriptionName(e.target.value)} placeholder="projects/my-project/subscriptions/wazuh-sub" required style={inp} />
            <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace", marginTop:5 }}>Full path: <code>projects/&lt;PROJECT&gt;/subscriptions/&lt;NAME&gt;</code></div>
          </div>

          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14, marginBottom:20 }}>
            <div>
              <label style={lbl}>Poll Interval</label>
              <select value={interval} onChange={e => setIntervalVal(e.target.value)} style={{ ...inp, cursor:"pointer" }}>
                {GCP_INTERVALS.map(i => <option key={i} value={i}>{i}</option>)}
              </select>
            </div>
            <div>
              <label style={lbl}>Max Messages / Pull</label>
              <input type="number" min={1} max={1000} value={maxMessages} onChange={e => setMaxMessages(Number(e.target.value))} style={inp} />
            </div>
          </div>

          <div style={{ marginBottom:20 }}>
            <label style={lbl}>Logging Level</label>
            <select value={logLevel} onChange={e => setLogLevel(e.target.value)} style={{ ...inp, cursor:"pointer" }}>
              {GCP_LOG_LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>

          <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:24 }}>
            <input type="checkbox" id="gcpenabled" checked={enabled} onChange={e => setEnabled(e.target.checked)} style={{ accentColor:GCP_BLUE, width:15, height:15, cursor:"pointer" }} />
            <label htmlFor="gcpenabled" style={{ color:"rgba(255,255,255,0.6)", fontSize:13, cursor:"pointer" }}>
              Enable integration (<code style={{ color:GCP_BLUE }}>disabled=no</code>)
            </label>
          </div>

          <div style={{ background:"rgba(0,229,160,0.04)", border:"1px solid rgba(0,229,160,0.12)", borderRadius:4, padding:"10px 14px", fontSize:11, color:"rgba(255,255,255,0.4)", fontFamily:"monospace", marginBottom:20 }}>
            ✦ 5 custom GCP security rules deployed to <code>/var/ossec/etc/rules/cycentra_gcp_rules.xml</code> on save.
          </div>

          {result && (
            <div style={{ background:result.ok?"rgba(0,229,160,0.08)":"rgba(255,59,59,0.08)", border:`1px solid ${result.ok?"rgba(0,229,160,0.25)":"rgba(255,59,59,0.25)"}`, borderRadius:4, padding:"10px 14px", fontSize:12, color:result.ok?"#00e5a0":"#ff8080", marginBottom:18 }}>
              {result.ok ? "✓ " : "✗ "}{result.msg}
            </div>
          )}

          <div style={{ display:"flex", gap:10 }}>
            <button type="submit" disabled={saving} style={{ flex:1, background:saving?`rgba(66,133,244,0.4)`:GCP_BLUE, color:"white", border:"none", borderRadius:4, padding:"12px", fontFamily:"monospace", fontSize:12, fontWeight:700, cursor:saving?"not-allowed":"pointer", letterSpacing:"1px", textTransform:"uppercase" }}>
              {saving ? "Applying…" : "Apply Configuration"}
            </button>
            <button type="button" onClick={onClose} style={{ padding:"12px 20px", background:"transparent", color:"rgba(255,255,255,0.4)", border:"1px solid rgba(255,255,255,0.12)", borderRadius:4, fontFamily:"monospace", fontSize:12, cursor:"pointer" }}>
              Close
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Playbook detail modal ─────────────────────────────────────────────────────

function PlaybookModal({ item, onClose }) {
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
            <code style={{ color:"#00e5a0", fontSize:12, fontFamily:"monospace" }}>
              cysoar import-flow {item.cysoar_flow} --workspace cycentra
            </code>
          </div>
        )}

        <button onClick={onClose} style={{ width:"100%", background:"transparent", color:"rgba(255,255,255,0.4)", border:"1px solid rgba(255,255,255,0.12)", borderRadius:4, padding:"12px", fontFamily:"monospace", fontSize:12, cursor:"pointer" }}>
          Close
        </button>
      </div>
    </div>
  );
}

// ── Admin: catalog item form modal (create / edit custom items) ───────────────

const EMPTY_ITEM = { id:"", name:"", type:"integration", category:"", vendor:"CyCentra", icon:"🔧", color:"#4d9eff", description:"", modules_required:"", estimated_time:"", tags:"", config_type:"", cysoar_flow:"", steps:"" };

const STATUS_META = {
  draft:     { label:"Draft",          color:"rgba(255,255,255,0.4)",  bg:"rgba(255,255,255,0.06)",  border:"rgba(255,255,255,0.12)" },
  submitted: { label:"Pending Review", color:"rgba(255,140,0,0.9)",    bg:"rgba(255,140,0,0.08)",    border:"rgba(255,140,0,0.25)"   },
  approved:  { label:"Approved",       color:"#00e5a0",                bg:"rgba(0,229,160,0.08)",    border:"rgba(0,229,160,0.25)"   },
  rejected:  { label:"Rejected",       color:"rgba(255,59,59,0.9)",    bg:"rgba(255,59,59,0.08)",    border:"rgba(255,59,59,0.25)"   },
};

function CatalogItemFormModal({ initial, onClose, onSaved }) {
  const isEdit   = !!initial?.id;
  const canEdit  = !isEdit || !["submitted"].includes(initial?.status);
  const [form, setForm] = useState(initial ? {
    ...EMPTY_ITEM,
    ...initial,
    modules_required: (initial.modules_required || []).join(", "),
    tags:             (initial.tags || []).join(", "),
    steps:            (initial.steps || []).join("\n"),
  } : EMPTY_ITEM);
  const [saving,       setSaving]       = useState(false);
  const [submitting,   setSubmitting]   = useState(false);
  const [error,        setError]        = useState(null);
  const [savedItem,    setSavedItem]    = useState(null);

  function set(key, val) { setForm(f => ({ ...f, [key]: val })); }

  function buildPayload() {
    return {
      id:               form.id.trim(),
      name:             form.name.trim(),
      type:             form.type,
      category:         form.category.trim(),
      vendor:           form.vendor.trim(),
      icon:             form.icon.trim(),
      color:            form.color.trim(),
      description:      form.description.trim(),
      modules_required: form.modules_required.split(",").map(s => s.trim()).filter(Boolean),
      estimated_time:   form.estimated_time.trim(),
      tags:             form.tags.split(",").map(s => s.trim().toLowerCase()).filter(Boolean),
      config_type:      form.config_type || undefined,
      cysoar_flow:      form.cysoar_flow.trim() || undefined,
      steps:            form.steps.split("\n").map(s => s.trim()).filter(Boolean),
    };
  }

  async function saveItem() {
    const url    = isEdit ? `${API_BASE}/api/marketplace/catalog/custom/${initial.id}` : `${API_BASE}/api/marketplace/catalog/custom`;
    const method = isEdit ? "PUT" : "POST";
    const r = await fetch(url, { method, credentials: "include", headers: { "Content-Type": "application/json" }, body: JSON.stringify(buildPayload()) });
    const d = await r.json();
    if (!r.ok || !d.ok) throw new Error(d.error || "Save failed");
    return d.item;
  }

  async function handleSaveDraft(e) {
    e.preventDefault();
    setError(null); setSaving(true);
    try {
      const item = await saveItem();
      setSavedItem(item);
      onSaved(item, isEdit);
    } catch(err) { setError(err.message); }
    finally { setSaving(false); }
  }

  async function handleSubmitForReview(e) {
    e.preventDefault();
    setError(null); setSubmitting(true);
    try {
      // Save/update first, then submit
      const item    = await saveItem();
      const r2      = await fetch(`${API_BASE}/api/marketplace/catalog/custom/${item.id}/submit`, { method:"POST", credentials:"include" });
      const d2      = await r2.json();
      if (!r2.ok || !d2.ok) throw new Error(d2.error || "Submit failed");
      setSavedItem(d2.item);
      onSaved(d2.item, isEdit);
    } catch(err) { setError(err.message); }
    finally { setSubmitting(false); }
  }

  const inp = { width:"100%", background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.12)", borderRadius:4, padding:"8px 12px", color:"white", fontSize:13, fontFamily:"monospace", outline:"none", boxSizing:"border-box" };
  const lbl = { color:"rgba(255,255,255,0.4)", fontSize:10, fontFamily:"monospace", letterSpacing:"0.8px", textTransform:"uppercase", marginBottom:5, display:"block" };
  const row = { marginBottom:14 };

  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.88)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:200, backdropFilter:"blur(6px)" }} onClick={onClose}>
      <div style={{ background:"#0d0f14", border:"1px solid rgba(77,158,255,0.3)", borderTop:"2px solid #4d9eff", borderRadius:8, padding:32, width:"min(640px,95vw)", maxHeight:"90vh", overflowY:"auto" }} onClick={e => e.stopPropagation()}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:24 }}>
          <div>
            <div style={{ color:"white", fontSize:17, fontWeight:700 }}>{isEdit ? "Edit Custom Item" : "Contribute to Marketplace"}</div>
            <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, fontFamily:"monospace", marginTop:3 }}>
              {isEdit
                ? `Status: ${STATUS_META[initial?.status]?.label || initial?.status || "draft"}`
                : "Save as draft to review later, or submit directly for CyCentra approval."}
            </div>
            {initial?.status === "submitted" && (
              <div style={{ marginTop:8, background:"rgba(255,140,0,0.08)", border:"1px solid rgba(255,140,0,0.2)", borderRadius:4, padding:"8px 12px", fontSize:11, color:"rgba(255,140,0,0.9)", fontFamily:"monospace" }}>
                ⏳ Under review — editing is locked until approved or rejected.
              </div>
            )}
            {initial?.status === "rejected" && initial?.rejection_reason && (
              <div style={{ marginTop:8, background:"rgba(255,59,59,0.08)", border:"1px solid rgba(255,59,59,0.2)", borderRadius:4, padding:"8px 12px", fontSize:11, color:"#ff8080", fontFamily:"monospace" }}>
                ✗ Rejected: {initial.rejection_reason}
              </div>
            )}
          </div>
          <button onClick={onClose} style={{ background:"none", border:"none", color:"rgba(255,255,255,0.4)", cursor:"pointer", fontSize:22, flexShrink:0 }}>×</button>
        </div>

        <form onSubmit={handleSaveDraft}>
          {/* ID + Name */}
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14, marginBottom:14 }}>
            <div>
              <label style={lbl}>ID <span style={{ color:"rgba(255,59,59,0.7)" }}>*</span></label>
              <input value={form.id} onChange={e => set("id", e.target.value)} placeholder="my-custom-integration" required disabled={isEdit} style={{ ...inp, opacity: isEdit ? 0.5 : 1 }} />
              {!isEdit && <div style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace", marginTop:4 }}>lowercase, hyphens only</div>}
            </div>
            <div>
              <label style={lbl}>Name <span style={{ color:"rgba(255,59,59,0.7)" }}>*</span></label>
              <input value={form.name} onChange={e => set("name", e.target.value)} placeholder="My Integration" required style={inp} />
            </div>
          </div>

          {/* Type + Category + Vendor */}
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:14, ...row }}>
            <div>
              <label style={lbl}>Type <span style={{ color:"rgba(255,59,59,0.7)" }}>*</span></label>
              <select value={form.type} onChange={e => set("type", e.target.value)} style={{ ...inp, cursor:"pointer" }}>
                <option value="integration">Integration</option>
                <option value="playbook">Playbook</option>
              </select>
            </div>
            <div>
              <label style={lbl}>Category</label>
              <input value={form.category} onChange={e => set("category", e.target.value)} placeholder="Cloud, SOAR, …" style={inp} />
            </div>
            <div>
              <label style={lbl}>Vendor</label>
              <input value={form.vendor} onChange={e => set("vendor", e.target.value)} placeholder="CyCentra" style={inp} />
            </div>
          </div>

          {/* Icon + Color + Estimated Time */}
          <div style={{ display:"grid", gridTemplateColumns:"80px 130px 1fr", gap:14, ...row }}>
            <div>
              <label style={lbl}>Icon</label>
              <input value={form.icon} onChange={e => set("icon", e.target.value)} placeholder="🔧" style={inp} />
            </div>
            <div>
              <label style={lbl}>Accent Color</label>
              <div style={{ display:"flex", gap:8, alignItems:"center" }}>
                <input type="color" value={form.color} onChange={e => set("color", e.target.value)} style={{ width:36, height:34, borderRadius:4, border:"1px solid rgba(255,255,255,0.12)", background:"transparent", cursor:"pointer" }} />
                <input value={form.color} onChange={e => set("color", e.target.value)} style={{ ...inp, flex:1 }} />
              </div>
            </div>
            <div>
              <label style={lbl}>Estimated Time</label>
              <input value={form.estimated_time} onChange={e => set("estimated_time", e.target.value)} placeholder="~5 min to configure" style={inp} />
            </div>
          </div>

          {/* Description */}
          <div style={row}>
            <label style={lbl}>Description <span style={{ color:"rgba(255,59,59,0.7)" }}>*</span></label>
            <textarea value={form.description} onChange={e => set("description", e.target.value)} rows={3} required placeholder="What does this integration do?" style={{ ...inp, resize:"vertical" }} />
          </div>

          {/* Modules + Tags */}
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14, ...row }}>
            <div>
              <label style={lbl}>Required Modules</label>
              <input value={form.modules_required} onChange={e => set("modules_required", e.target.value)} placeholder="CySIEM, CySOAR" style={inp} />
              <div style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace", marginTop:4 }}>comma-separated</div>
            </div>
            <div>
              <label style={lbl}>Tags</label>
              <input value={form.tags} onChange={e => set("tags", e.target.value)} placeholder="cloud, azure, audit" style={inp} />
              <div style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace", marginTop:4 }}>comma-separated</div>
            </div>
          </div>

          {/* Integration-specific fields */}
          {form.type === "integration" && (
            <div style={row}>
              <label style={lbl}>Config Type</label>
              <select value={form.config_type} onChange={e => set("config_type", e.target.value)} style={{ ...inp, cursor:"pointer" }}>
                <option value="">— None (manual configuration) —</option>
                <option value="o365">o365 — Office 365 API integration</option>
                <option value="gcloud">gcloud — Google Cloud Pub/Sub integration</option>
              </select>
            </div>
          )}

          {/* Playbook-specific fields */}
          {form.type === "playbook" && (
            <>
              <div style={row}>
                <label style={lbl}>CySOAR Flow File</label>
                <input value={form.cysoar_flow} onChange={e => set("cysoar_flow", e.target.value)} placeholder="my_playbook.py" style={inp} />
              </div>
              <div style={row}>
                <label style={lbl}>Automation Steps</label>
                <textarea value={form.steps} onChange={e => set("steps", e.target.value)} rows={5} placeholder={"Step 1 description\nStep 2 description\nStep 3 description"} style={{ ...inp, resize:"vertical" }} />
                <div style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace", marginTop:4 }}>one step per line</div>
              </div>
            </>
          )}

          {error && (
            <div style={{ background:"rgba(255,59,59,0.08)", border:"1px solid rgba(255,59,59,0.25)", borderRadius:4, padding:"10px 14px", fontSize:12, color:"#ff8080", marginBottom:16 }}>
              ✗ {error}
            </div>
          )}

          {!canEdit ? null : (
            <div style={{ display:"flex", gap:8, marginTop:8, flexWrap:"wrap" }}>
              {/* Save as Draft */}
              <button type="submit" disabled={saving || submitting}
                style={{ flex:1, minWidth:140, background:"rgba(255,255,255,0.06)", color:saving?"rgba(255,255,255,0.3)":"rgba(255,255,255,0.75)", border:"1px solid rgba(255,255,255,0.12)", borderRadius:4, padding:"11px", fontFamily:"monospace", fontSize:11, fontWeight:700, cursor:(saving||submitting)?"not-allowed":"pointer", letterSpacing:"1px", textTransform:"uppercase" }}>
                {saving ? "Saving…" : "Save as Draft"}
              </button>
              {/* Submit for Review */}
              <button type="button" disabled={saving || submitting} onClick={handleSubmitForReview}
                style={{ flex:2, minWidth:180, background:(saving||submitting)?"rgba(0,229,160,0.15)":"rgba(0,229,160,0.12)", color:(saving||submitting)?"rgba(0,229,160,0.4)":"#00e5a0", border:"1px solid rgba(0,229,160,0.3)", borderRadius:4, padding:"11px", fontFamily:"monospace", fontSize:11, fontWeight:700, cursor:(saving||submitting)?"not-allowed":"pointer", letterSpacing:"1px", textTransform:"uppercase" }}>
                {submitting ? "Submitting…" : "Submit for CyCentra Review"}
              </button>
              <button type="button" onClick={onClose}
                style={{ padding:"11px 16px", background:"transparent", color:"rgba(255,255,255,0.35)", border:"1px solid rgba(255,255,255,0.1)", borderRadius:4, fontFamily:"monospace", fontSize:11, cursor:"pointer" }}>
                Cancel
              </button>
            </div>
          )}
          {!canEdit && (
            <button type="button" onClick={onClose}
              style={{ width:"100%", marginTop:8, padding:"11px", background:"transparent", color:"rgba(255,255,255,0.35)", border:"1px solid rgba(255,255,255,0.1)", borderRadius:4, fontFamily:"monospace", fontSize:11, cursor:"pointer" }}>
              Close
            </button>
          )}
        </form>
      </div>
    </div>
  );
}

// ── CyCentra admin: pending review queue ──────────────────────────────────────

function ReviewQueueSection({ onApprove, onReject }) {
  const [submissions,  setSubmissions]  = useState([]);
  const [loading,      setLoading]      = useState(true);
  const [rejectTarget, setRejectTarget] = useState(null);
  const [rejectReason, setRejectReason] = useState("");
  const [acting,       setActing]       = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/api/marketplace/submissions`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { setSubmissions(d.submissions || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  function handleApprove(item) {
    setActing(item.id);
    fetch(`${API_BASE}/api/marketplace/catalog/custom/${item.id}/approve`, { method:"POST", credentials:"include" })
      .then(r => r.json())
      .then(d => {
        if (d.ok) {
          setSubmissions(prev => prev.filter(i => i.id !== item.id));
          onApprove(d.item);
        }
      })
      .finally(() => setActing(null));
  }

  function openReject(item) { setRejectTarget(item); setRejectReason(""); }

  function handleReject() {
    if (!rejectReason.trim() || !rejectTarget) return;
    setActing(rejectTarget.id);
    fetch(`${API_BASE}/api/marketplace/catalog/custom/${rejectTarget.id}/reject`, {
      method:"POST", credentials:"include",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ reason: rejectReason.trim() }),
    })
      .then(r => r.json())
      .then(d => {
        if (d.ok) {
          setSubmissions(prev => prev.filter(i => i.id !== rejectTarget.id));
          onReject(d.item);
        }
      })
      .finally(() => { setActing(null); setRejectTarget(null); });
  }

  if (loading) return null;
  if (submissions.length === 0) return (
    <div style={{ background:"rgba(0,229,160,0.04)", border:"1px solid rgba(0,229,160,0.1)", borderRadius:6, padding:"16px 20px", marginBottom:28, display:"flex", alignItems:"center", gap:12 }}>
      <span style={{ fontSize:16 }}>✓</span>
      <div style={{ color:"rgba(255,255,255,0.4)", fontSize:12, fontFamily:"monospace" }}>No items pending review.</div>
    </div>
  );

  return (
    <div style={{ marginBottom:32 }}>
      <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:16 }}>
        <div style={{ color:"rgba(255,140,0,0.9)", fontSize:10, letterSpacing:"1.5px", fontFamily:"monospace", textTransform:"uppercase", fontWeight:700 }}>
          Pending Your Review
        </div>
        <span style={{ background:"rgba(255,140,0,0.12)", color:"rgba(255,140,0,0.9)", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, border:"1px solid rgba(255,140,0,0.25)" }}>
          {submissions.length} AWAITING APPROVAL
        </span>
      </div>

      <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
        {submissions.map(item => (
          <div key={item.id} style={{ background:"rgba(255,140,0,0.04)", border:"1px solid rgba(255,140,0,0.2)", borderRadius:6, padding:"16px 20px", display:"flex", gap:16, alignItems:"flex-start", flexWrap:"wrap" }}>
            <span style={{ fontSize:24, flexShrink:0 }}>{item.icon}</span>
            <div style={{ flex:1, minWidth:200 }}>
              <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:4, flexWrap:"wrap" }}>
                <div style={{ color:"white", fontSize:14, fontWeight:700 }}>{item.name}</div>
                <span style={{ background:"rgba(77,158,255,0.08)", color:"#4d9eff", border:"1px solid rgba(77,158,255,0.2)", fontSize:9, fontFamily:"monospace", padding:"1px 6px", borderRadius:2 }}>{item.type}</span>
                <span style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace" }}>{item.vendor}</span>
              </div>
              <div style={{ color:"rgba(255,255,255,0.5)", fontSize:12, lineHeight:1.6, marginBottom:6 }}>{item.description}</div>
              <div style={{ color:"rgba(255,140,0,0.6)", fontSize:10, fontFamily:"monospace" }}>
                Submitted by {item.submitted_by || item.created_by} · {item.submitted_at ? new Date(item.submitted_at).toLocaleDateString() : ""}
              </div>
            </div>
            <div style={{ display:"flex", gap:8, flexShrink:0 }}>
              <button onClick={() => handleApprove(item)} disabled={acting === item.id}
                style={{ background:"rgba(0,229,160,0.12)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.3)", borderRadius:4, padding:"8px 16px", fontFamily:"monospace", fontSize:11, fontWeight:700, cursor:acting===item.id?"not-allowed":"pointer", letterSpacing:"0.5px" }}>
                {acting === item.id ? "…" : "✓ Approve"}
              </button>
              <button onClick={() => openReject(item)} disabled={acting === item.id}
                style={{ background:"rgba(255,59,59,0.06)", color:"rgba(255,80,80,0.8)", border:"1px solid rgba(255,59,59,0.2)", borderRadius:4, padding:"8px 16px", fontFamily:"monospace", fontSize:11, fontWeight:700, cursor:acting===item.id?"not-allowed":"pointer", letterSpacing:"0.5px" }}>
                ✕ Reject
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Reject reason modal */}
      {rejectTarget && (
        <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.88)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:250, backdropFilter:"blur(6px)" }} onClick={() => setRejectTarget(null)}>
          <div style={{ background:"#0d0f14", border:"1px solid rgba(255,59,59,0.3)", borderTop:"2px solid rgba(255,59,59,0.8)", borderRadius:8, padding:28, width:"min(480px,92vw)" }} onClick={e => e.stopPropagation()}>
            <div style={{ color:"white", fontSize:15, fontWeight:700, marginBottom:6 }}>Reject: {rejectTarget.name}</div>
            <div style={{ color:"rgba(255,255,255,0.4)", fontSize:12, marginBottom:16 }}>Provide a reason so the submitter can improve and resubmit.</div>
            <textarea value={rejectReason} onChange={e => setRejectReason(e.target.value)} rows={4} placeholder="e.g. Missing configuration schema, duplicate of an existing item, security concern…"
              style={{ width:"100%", background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.12)", borderRadius:4, padding:"9px 12px", color:"white", fontSize:13, fontFamily:"monospace", outline:"none", resize:"vertical", boxSizing:"border-box" }} />
            <div style={{ display:"flex", gap:10, marginTop:14 }}>
              <button onClick={handleReject} disabled={!rejectReason.trim()}
                style={{ flex:1, background:rejectReason.trim()?"rgba(255,59,59,0.15)":"rgba(255,255,255,0.04)", color:rejectReason.trim()?"rgba(255,80,80,0.9)":"rgba(255,255,255,0.25)", border:`1px solid ${rejectReason.trim()?"rgba(255,59,59,0.35)":"rgba(255,255,255,0.08)"}`, borderRadius:4, padding:"10px", fontFamily:"monospace", fontSize:11, fontWeight:700, cursor:rejectReason.trim()?"pointer":"not-allowed", letterSpacing:"1px", textTransform:"uppercase" }}>
                Confirm Rejection
              </button>
              <button onClick={() => setRejectTarget(null)} style={{ padding:"10px 16px", background:"transparent", color:"rgba(255,255,255,0.35)", border:"1px solid rgba(255,255,255,0.1)", borderRadius:4, fontFamily:"monospace", fontSize:11, cursor:"pointer" }}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Marketplace card ──────────────────────────────────────────────────────────

function MarketplaceCard({ item, isInstalled, isConfigured, isAdmin, pulling, onPull, onRemove, onConfigure, onViewDetails, onEdit, onCatalogDelete }) {
  const isIntegration = item.type === "integration";
  const isCustom      = item.source === "custom";
  const isPulling     = pulling === item.id;

  return (
    <div style={{ background:"rgba(255,255,255,0.025)", border:`1px solid ${item.color}20`, borderTop:`2px solid ${item.color}`, borderRadius:5, padding:"20px 22px", display:"flex", flexDirection:"column", gap:0 }}>

      {/* Type + source + installed badge row */}
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:10, flexWrap:"wrap", gap:4 }}>
        <div style={{ display:"flex", gap:5 }}>
          <span style={{ background:isIntegration?"rgba(0,229,160,0.08)":"rgba(77,158,255,0.08)", color:isIntegration?"#00e5a0":"#4d9eff", border:`1px solid ${isIntegration?"rgba(0,229,160,0.2)":"rgba(77,158,255,0.2)"}`, fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, letterSpacing:"1px", textTransform:"uppercase" }}>
            {isIntegration ? "Integration" : "Playbook"}
          </span>
          {isCustom && (
            <span style={{ background:"rgba(176,110,255,0.08)", color:"#b06eff", border:"1px solid rgba(176,110,255,0.2)", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, letterSpacing:"1px" }}>
              Custom
            </span>
          )}
          {isCustom && item.status && item.status !== "approved" && (() => {
            const sm = STATUS_META[item.status] || {};
            return (
              <span style={{ background: sm.bg||"rgba(255,255,255,0.06)", color: sm.color||"rgba(255,255,255,0.5)", border:`1px solid ${sm.border||"rgba(255,255,255,0.12)"}`, fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, letterSpacing:"1px" }}>
                {sm.label || item.status}
              </span>
            );
          })()}
        </div>
        <div style={{ display:"flex", gap:5, alignItems:"center" }}>
          {isInstalled && isConfigured && (
            <span style={{ background:"rgba(0,229,160,0.1)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.25)", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, letterSpacing:"1px" }}>
              ✓ ACTIVE
            </span>
          )}
          {isInstalled && !isConfigured && item.config_type && (
            <span title="Integration installed but credentials not yet configured in Wazuh" style={{ background:"rgba(255,180,0,0.1)", color:"#ffb400", border:"1px solid rgba(255,180,0,0.3)", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, letterSpacing:"1px", cursor:"default" }}>
              ⚠ NEEDS SETUP
            </span>
          )}
          {isInstalled && !item.config_type && (
            <span style={{ background:"rgba(0,229,160,0.1)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.25)", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, letterSpacing:"1px" }}>
              ✓ INSTALLED
            </span>
          )}
          {/* Admin edit/delete for custom items */}
          {isAdmin && isCustom && (
            <div style={{ display:"flex", gap:4 }}>
              <button onClick={() => onEdit(item)} title="Edit this item" style={{ background:"rgba(77,158,255,0.08)", color:"#4d9eff", border:"1px solid rgba(77,158,255,0.2)", borderRadius:3, padding:"2px 8px", fontFamily:"monospace", fontSize:9, cursor:"pointer", letterSpacing:"0.5px" }}>Edit</button>
              <button onClick={() => onCatalogDelete(item)} title="Remove from catalog" style={{ background:"rgba(255,59,59,0.06)", color:"rgba(255,80,80,0.7)", border:"1px solid rgba(255,59,59,0.15)", borderRadius:3, padding:"2px 8px", fontFamily:"monospace", fontSize:9, cursor:"pointer" }}>✕</button>
            </div>
          )}
        </div>
      </div>

      {/* Icon + name */}
      <div style={{ display:"flex", gap:12, alignItems:"flex-start", marginBottom:10 }}>
        <span style={{ fontSize:22 }}>{item.icon}</span>
        <div style={{ flex:1 }}>
          <div style={{ color:"white", fontSize:15, fontWeight:700 }}>{item.name}</div>
          <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace", marginTop:2 }}>{item.vendor} · {item.category}</div>
        </div>
      </div>

      <div style={{ color:"rgba(255,255,255,0.55)", fontSize:12, lineHeight:1.6, marginBottom:14, flex:1 }}>{item.description}</div>

      {/* Required modules */}
      <div style={{ display:"flex", flexWrap:"wrap", gap:5, marginBottom:14 }}>
        {item.modules_required?.map(m => (
          <span key={m} style={{ background:"rgba(255,255,255,0.06)", color:"rgba(255,255,255,0.5)", border:"1px solid rgba(255,255,255,0.1)", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2 }}>{m}</span>
        ))}
      </div>

      <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace", marginBottom:14 }}>{item.estimated_time}</div>

      {/* Actions */}
      {/* Non-approved custom items: show pending notice instead of action buttons */}
      {isCustom && item.status && item.status !== "approved" ? (
        <div style={{ padding:"9px 12px", background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:4, color:"rgba(255,255,255,0.3)", fontFamily:"monospace", fontSize:10, textAlign:"center", letterSpacing:"0.5px" }}>
          {item.status === "submitted" ? "Awaiting CyCentra review" : item.status === "rejected" ? "Submission rejected" : "Saved as draft"}
        </div>
      ) : (
      <div style={{ display:"flex", gap:8 }}>
        {isInstalled ? (
          <>
            {isIntegration ? (
              <button
                onClick={() => isAdmin && onConfigure(item)}
                disabled={!isAdmin}
                title={!isAdmin ? "Admin access required" : "Configure this integration"}
                style={{ flex:1, background:isAdmin?item.color:"rgba(255,255,255,0.05)", color:isAdmin?"#0d0f14":"rgba(255,255,255,0.25)", border:"none", borderRadius:4, padding:"9px 12px", fontFamily:"monospace", fontSize:11, fontWeight:700, cursor:isAdmin?"pointer":"not-allowed", letterSpacing:"1px", textTransform:"uppercase" }}>
                {isAdmin ? "Configure" : "🔒 Configure"}
              </button>
            ) : (
              <button
                onClick={() => onViewDetails(item)}
                style={{ flex:1, background:"rgba(255,255,255,0.04)", color:"rgba(255,255,255,0.6)", border:"1px solid rgba(255,255,255,0.1)", borderRadius:4, padding:"9px 12px", fontFamily:"monospace", fontSize:11, cursor:"pointer", letterSpacing:"1px", textTransform:"uppercase" }}>
                View Steps
              </button>
            )}
            {isAdmin && (
              <button
                onClick={() => onRemove(item)}
                title="Remove from installed"
                style={{ padding:"9px 12px", background:"rgba(255,59,59,0.06)", color:"rgba(255,80,80,0.6)", border:"1px solid rgba(255,59,59,0.15)", borderRadius:4, fontFamily:"monospace", fontSize:11, cursor:"pointer" }}>
                Remove
              </button>
            )}
          </>
        ) : (
          <>
            <button
              onClick={() => isAdmin && onPull(item)}
              disabled={!isAdmin || isPulling}
              title={!isAdmin ? "Admin access required to pull integrations" : `Pull ${item.name} from cloud`}
              style={{ flex:1, background:isAdmin?(isPulling?"rgba(0,229,160,0.15)":"rgba(0,229,160,0.1)"):"rgba(255,255,255,0.03)", color:isAdmin?(isPulling?"rgba(0,229,160,0.5)":"#00e5a0"):"rgba(255,255,255,0.2)", border:`1px solid ${isAdmin?"rgba(0,229,160,0.25)":"rgba(255,255,255,0.07)"}`, borderRadius:4, padding:"9px 12px", fontFamily:"monospace", fontSize:11, fontWeight:700, cursor:isAdmin&&!isPulling?"pointer":"not-allowed", letterSpacing:"1px", textTransform:"uppercase" }}>
              {isPulling ? "Pulling…" : isAdmin ? "↓ Pull" : "🔒 Pull"}
            </button>
            <button
              onClick={() => onViewDetails(item)}
              style={{ padding:"9px 12px", background:"transparent", color:"rgba(255,255,255,0.35)", border:"1px solid rgba(255,255,255,0.08)", borderRadius:4, fontFamily:"monospace", fontSize:11, cursor:"pointer" }}>
              Details
            </button>
          </>
        )}
      </div>
      )}
    </div>
  );
}

// ── Main marketplace page ─────────────────────────────────────────────────────

export function MarketplacePage({ user }) {
  const isAdmin = user?.role === "admin";

  const [catalog,          setCatalog]          = useState([]);
  const [catalogLoading,   setCatalogLoading]   = useState(true);
  const [catalogError,     setCatalogError]     = useState(null);
  const [isCycentraAdmin,  setIsCycentraAdmin]  = useState(false);
  const [pendingCount,     setPendingCount]     = useState(0);
  const [installed,        setInstalled]        = useState(new Set());
  const [configured,       setConfigured]       = useState(new Set());
  const [search,           setSearch]           = useState("");
  const [typeFilter,       setTypeFilter]       = useState("all");
  const [configModal,      setConfigModal]      = useState(null);
  const [detailModal,      setDetailModal]      = useState(null);
  const [pulling,          setPulling]          = useState(null);
  const [pullError,        setPullError]        = useState(null);
  const [catalogFormItem,  setCatalogFormItem]  = useState(null);

  // Fetch catalog via backend proxy — also tells us if this session is cycentra_admin
  useEffect(() => {
    fetch(`${API_BASE}/api/marketplace/catalog`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject("unavailable"))
      .then(d => {
        setCatalog(d.items || []);
        setIsCycentraAdmin(!!d.is_cycentra_admin);
        setPendingCount(d.pending_count || 0);
        setCatalogLoading(false);
      })
      .catch(() => {
        setCatalogError("Could not load the marketplace catalog. Check your connection or contact your administrator.");
        setCatalogLoading(false);
      });
  }, []);

  // Fetch installed + configured items from backend
  useEffect(() => {
    fetch(`${API_BASE}/api/marketplace/installed`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => {
        setInstalled(new Set(d.installed || []));
        setConfigured(new Set(d.configured || []));
      })
      .catch(() => {});
  }, []);

  const handlePull = useCallback((item) => {
    if (!isAdmin) return;
    setPulling(item.id);
    setPullError(null);
    fetch(`${API_BASE}/api/marketplace/install`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: item.id }),
    })
      .then(r => r.json().then(d => ({ ok: r.ok, data: d })))
      .then(({ ok, data }) => {
        if (ok && data.ok) {
          setInstalled(prev => new Set([...prev, item.id]));
          // Auto-open configure for integrations after pull
          if (item.type === "integration") setConfigModal(item);
        } else {
          setPullError(data.error || "Failed to pull item");
        }
      })
      .catch(() => setPullError("Network error"))
      .finally(() => setPulling(null));
  }, [isAdmin]);

  const handleRemove = useCallback((item) => {
    if (!isAdmin) return;
    fetch(`${API_BASE}/api/marketplace/install/${item.id}`, { method: "DELETE", credentials: "include" })
      .then(r => r.json())
      .then(d => { if (d.ok) setInstalled(prev => { const s = new Set(prev); s.delete(item.id); return s; }); })
      .catch(() => {});
  }, [isAdmin]);

  // Catalog management handlers (admin: custom items only)
  const handleCatalogSaved = useCallback((savedItem, isEdit) => {
    savedItem.source = "custom";
    setCatalog(prev =>
      isEdit
        ? prev.map(i => i.id === savedItem.id ? savedItem : i)
        : [...prev, savedItem]
    );
    if (savedItem.status === "submitted") setPendingCount(c => c + 1);
    setCatalogFormItem(null);
  }, []);

  const handleReviewApproved = useCallback((approvedItem) => {
    approvedItem.source = "custom";
    setCatalog(prev => prev.map(i => i.id === approvedItem.id ? approvedItem : i));
    setPendingCount(c => Math.max(0, c - 1));
  }, []);

  const handleReviewRejected = useCallback((rejectedItem) => {
    rejectedItem.source = "custom";
    setCatalog(prev => prev.map(i => i.id === rejectedItem.id ? rejectedItem : i));
    setPendingCount(c => Math.max(0, c - 1));
  }, []);

  const handleCatalogDelete = useCallback((item) => {
    if (!isAdmin) return;
    if (!window.confirm(`Remove "${item.name}" from the marketplace catalog? Installed state will also be cleared.`)) return;
    fetch(`${API_BASE}/api/marketplace/catalog/custom/${item.id}`, { method: "DELETE", credentials: "include" })
      .then(r => r.json())
      .then(d => {
        if (d.ok) {
          setCatalog(prev => prev.filter(i => i.id !== item.id));
          setInstalled(prev => { const s = new Set(prev); s.delete(item.id); return s; });
        }
      })
      .catch(() => {});
  }, [isAdmin]);

  // Filter + split
  const filtered = catalog.filter(item => {
    const q = search.toLowerCase();
    const matchSearch = !q ||
      item.name.toLowerCase().includes(q) ||
      item.vendor?.toLowerCase().includes(q) ||
      item.category?.toLowerCase().includes(q) ||
      item.description?.toLowerCase().includes(q) ||
      item.tags?.some(t => t.includes(q));
    const matchType = typeFilter === "all" || item.type === typeFilter;
    return matchSearch && matchType;
  });

  const installedItems = filtered.filter(i => installed.has(i.id));
  const availableItems = filtered.filter(i => !installed.has(i.id));

  const integrationCount = catalog.filter(i => i.type === "integration").length;
  const playbookCount    = catalog.filter(i => i.type === "playbook").length;

  return (
    <div>
      {/* ── Header ── */}
      <div style={{ marginBottom:28 }}>
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", gap:12, marginBottom:8, flexWrap:"wrap" }}>
          <div style={{ display:"flex", alignItems:"center", gap:12, flexWrap:"wrap" }}>
            <h1 style={{ fontSize:22, fontWeight:700, color:"white", margin:0 }}>Integration Marketplace</h1>
            {!catalogLoading && !catalogError && (
              <span style={{ background:"rgba(0,229,160,0.12)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.25)", fontSize:9, fontFamily:"monospace", padding:"3px 10px", borderRadius:2, fontWeight:700, letterSpacing:"1px" }}>
                {catalog.filter(i => !["draft","submitted","rejected"].includes(i.status)).length} ITEMS
              </span>
            )}
            {isCycentraAdmin && pendingCount > 0 && (
              <span style={{ background:"rgba(255,140,0,0.12)", color:"rgba(255,140,0,0.95)", border:"1px solid rgba(255,140,0,0.3)", fontSize:9, fontFamily:"monospace", padding:"3px 10px", borderRadius:2, fontWeight:700, letterSpacing:"1px", animation:"pulse 2s infinite" }}>
                {pendingCount} PENDING REVIEW ↑
              </span>
            )}
            {!isAdmin && (
              <span style={{ background:"rgba(255,140,0,0.08)", color:"rgba(255,140,0,0.7)", border:"1px solid rgba(255,140,0,0.2)", fontSize:9, fontFamily:"monospace", padding:"3px 10px", borderRadius:2, letterSpacing:"1px" }}>
                🔒 VIEW ONLY — ADMIN REQUIRED TO PULL
              </span>
            )}
          </div>
          {isAdmin && (
            <button onClick={() => setCatalogFormItem(EMPTY_ITEM)}
              style={{ background:"rgba(77,158,255,0.1)", color:"#4d9eff", border:"1px solid rgba(77,158,255,0.25)", borderRadius:4, padding:"8px 16px", fontFamily:"monospace", fontSize:11, fontWeight:700, cursor:"pointer", letterSpacing:"0.5px", whiteSpace:"nowrap" }}>
              + Contribute to Marketplace
            </button>
          )}
        </div>
        <p style={{ color:"rgba(255,255,255,0.4)", fontSize:13, margin:0 }}>
          Browse, pull, and configure security integrations and automation playbooks.
          {isAdmin && !isCycentraAdmin && " Admins can contribute new items — submitted content is reviewed by CyCentra before going live."}
          {isCycentraAdmin && " Approve or reject items submitted for marketplace inclusion."}
        </p>
      </div>

      {/* ── CyCentra admin: review queue ── */}
      {isCycentraAdmin && !catalogLoading && (
        <ReviewQueueSection onApprove={handleReviewApproved} onReject={handleReviewRejected} />
      )}

      {/* ── Search + type filter ── */}
      <div style={{ display:"flex", gap:10, marginBottom:24, flexWrap:"wrap", alignItems:"center" }}>
        <div style={{ position:"relative", flex:"1 1 260px", minWidth:200 }}>
          <span style={{ position:"absolute", left:12, top:"50%", transform:"translateY(-50%)", color:"rgba(255,255,255,0.3)", fontSize:13, pointerEvents:"none" }}>🔍</span>
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by name, vendor, tag…"
            style={{ width:"100%", background:"rgba(255,255,255,0.04)", border:"1px solid rgba(255,255,255,0.1)", borderRadius:4, padding:"9px 12px 9px 34px", color:"white", fontSize:13, fontFamily:"monospace", outline:"none", boxSizing:"border-box" }}
          />
        </div>
        <div style={{ display:"flex", gap:6 }}>
          {[
            { id:"all",         label:`All (${catalog.length})` },
            { id:"integration", label:`Integrations (${integrationCount})` },
            { id:"playbook",    label:`Playbooks (${playbookCount})` },
          ].map(f => (
            <button key={f.id} onClick={() => setTypeFilter(f.id)}
              style={{ background:typeFilter===f.id?"rgba(0,229,160,0.12)":"rgba(255,255,255,0.04)", color:typeFilter===f.id?"#00e5a0":"rgba(255,255,255,0.45)", border:`1px solid ${typeFilter===f.id?"rgba(0,229,160,0.3)":"rgba(255,255,255,0.08)"}`, borderRadius:20, padding:"7px 14px", fontSize:11, fontFamily:"monospace", cursor:"pointer", whiteSpace:"nowrap" }}>
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Pull error banner ── */}
      {pullError && (
        <div style={{ background:"rgba(255,59,59,0.08)", border:"1px solid rgba(255,59,59,0.25)", borderRadius:4, padding:"10px 14px", fontSize:12, color:"#ff8080", marginBottom:18, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          <span>✗ {pullError}</span>
          <button onClick={() => setPullError(null)} style={{ background:"none", border:"none", color:"#ff8080", cursor:"pointer", fontSize:16 }}>×</button>
        </div>
      )}

      {/* ── Loading / error state ── */}
      {catalogLoading && (
        <div style={{ textAlign:"center", padding:"48px 0", color:"rgba(255,255,255,0.3)", fontFamily:"monospace", fontSize:13 }}>
          Fetching catalog from cloud…
        </div>
      )}
      {catalogError && (
        <div style={{ background:"rgba(255,140,0,0.06)", border:"1px solid rgba(255,140,0,0.2)", borderRadius:6, padding:"20px 24px", marginBottom:24 }}>
          <div style={{ color:"rgba(255,140,0,0.8)", fontSize:13, marginBottom:6, fontWeight:600 }}>Cloud Marketplace Unavailable</div>
          <div style={{ color:"rgba(255,255,255,0.4)", fontSize:12 }}>{catalogError}</div>
        </div>
      )}

      {/* ── Installed section ── */}
      {!catalogLoading && installedItems.length > 0 && (
        <div style={{ marginBottom:32 }}>
          <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:16 }}>
            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.5px", fontFamily:"monospace", textTransform:"uppercase" }}>
              Installed on this Server
            </div>
            <span style={{ background:"rgba(0,229,160,0.1)", color:"#00e5a0", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2 }}>
              {installedItems.length}
            </span>
          </div>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(300px, 1fr))", gap:16 }}>
            {installedItems.map(item => (
              <MarketplaceCard
                key={item.id}
                item={item}
                isInstalled={true}
                isConfigured={configured.has(item.id)}
                isAdmin={isAdmin}
                pulling={pulling}
                onPull={handlePull}
                onRemove={handleRemove}
                onConfigure={setConfigModal}
                onViewDetails={setDetailModal}
                onEdit={setCatalogFormItem}
                onCatalogDelete={handleCatalogDelete}
              />
            ))}
          </div>
        </div>
      )}

      {/* ── Available from cloud section ── */}
      {!catalogLoading && availableItems.length > 0 && (
        <div style={{ marginBottom:32 }}>
          <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:16 }}>
            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.5px", fontFamily:"monospace", textTransform:"uppercase" }}>
              Available from Cloud
            </div>
            <span style={{ background:"rgba(255,255,255,0.06)", color:"rgba(255,255,255,0.35)", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2 }}>
              {availableItems.length}
            </span>
          </div>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(300px, 1fr))", gap:16 }}>
            {availableItems.map(item => (
              <MarketplaceCard
                key={item.id}
                item={item}
                isInstalled={false}
                isAdmin={isAdmin}
                pulling={pulling}
                onPull={handlePull}
                onRemove={handleRemove}
                onConfigure={setConfigModal}
                onViewDetails={setDetailModal}
                onEdit={setCatalogFormItem}
                onCatalogDelete={handleCatalogDelete}
              />
            ))}
          </div>
        </div>
      )}

      {/* ── Empty search state ── */}
      {!catalogLoading && !catalogError && filtered.length === 0 && search && (
        <div style={{ textAlign:"center", padding:"48px 0", color:"rgba(255,255,255,0.25)", fontFamily:"monospace", fontSize:13 }}>
          No items match "{search}"
        </div>
      )}

      {/* ── CySOAR note (only when playbooks visible) ── */}
      {!catalogLoading && (typeFilter === "all" || typeFilter === "playbook") && catalog.some(i => i.type === "playbook") && (
        <div style={{ marginTop:8, background:"rgba(77,158,255,0.04)", border:"1px solid rgba(77,158,255,0.15)", borderRadius:6, padding:"20px 24px" }}>
          <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:12 }}>
            <span style={{ fontSize:20 }}>⚡</span>
            <span style={{ color:"rgba(255,255,255,0.7)", fontSize:14, fontWeight:600 }}>CySOAR Playbooks</span>
          </div>
          <div style={{ color:"rgba(255,255,255,0.4)", fontSize:12, lineHeight:1.8 }}>
            All playbooks are CySOAR-native Python scripts with built-in secret management, retry logic and webhook endpoints.
            Deploy via <code style={{ color:"#4d9eff" }}>cysoar CLI</code> or drag-and-drop into your CySOAR workspace.
            OIDC SSO means your CyCentra 360 session carries through automatically.
          </div>
        </div>
      )}

      {/* ── Config / detail modals ── */}
      {configModal?.config_type === "o365"   && <O365ConfigModal   item={configModal}     onClose={() => setConfigModal(null)} onSaved={() => { fetch(`${API_BASE}/api/marketplace/installed`,{credentials:"include"}).then(r=>r.json()).then(d=>{setInstalled(new Set(d.installed||[]));setConfigured(new Set(d.configured||[]));}).catch(()=>{}); }} />}
      {configModal?.config_type === "gcloud" && <GCloudConfigModal item={configModal}     onClose={() => setConfigModal(null)} />}
      {detailModal                           && <PlaybookModal     item={detailModal}     onClose={() => setDetailModal(null)} />}

      {/* ── Admin: add / edit custom catalog item ── */}
      {catalogFormItem !== null && (
        <CatalogItemFormModal
          initial={catalogFormItem?.id ? catalogFormItem : null}
          onClose={() => setCatalogFormItem(null)}
          onSaved={handleCatalogSaved}
        />
      )}
    </div>
  );
}
