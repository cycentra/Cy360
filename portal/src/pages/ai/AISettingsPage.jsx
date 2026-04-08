/**
 * src/pages/ai/AISettingsPage.jsx
 * =================================
 * AI provider configuration — provider selection, API key, model,
 * system prompt templates, and module URL overrides.
 */

import { useState } from "react";
import { API_BASE, _BASE_DOMAIN } from '../../core/constants.js';
import { AI_PROVIDERS, DEFAULT_PROMPTS } from '../../registry/aiProviders.js';

export function AISettingsPage({ aiConfig, onSave }) {
  const [provider,       setProvider]    = useState(aiConfig?.provider || "local");
  const [fields,         setFields]      = useState(aiConfig?.fields   || {});
  const [prompts,        setPrompts]     = useState(aiConfig?.prompts  || DEFAULT_PROMPTS);
  const [cymindMemory,   setCymindMemory] = useState(aiConfig?.cymind_memory || {});
  const [activePromptTab,setActivePTab]  = useState("system");
  const [testStatus,     setTestStatus]  = useState(null);   // null | "testing" | "ok" | "fail"
  const [testMsg,        setTestMsg]     = useState("");
  const [saved,          setSaved]       = useState(false);
  const [moduleUrls,     setModuleUrls]  = useState(() => {
    try {
      return {
        cyiris: localStorage.getItem("cycentra_url_cyiris") || "",
        cysoar: localStorage.getItem("cycentra_url_cysoar") || "",
        cysiem: localStorage.getItem("cycentra_url_cysiem") || "",
      };
    } catch { return { cyiris: "", cysoar: "", cysiem: "" }; }
  });

  const currentProvider = AI_PROVIDERS[provider];
  const updateField     = (k, v) => setFields(prev  => ({ ...prev, [k]: v }));
  const updatePrompt    = (k, v) => setPrompts(prev  => ({ ...prev, [k]: v }));
  const resetPrompt     = (k)    => setPrompts(prev  => ({ ...prev, [k]: DEFAULT_PROMPTS[k] }));

  const testConnection = async () => {
    setTestStatus("testing"); setTestMsg("");
    if (provider === "local" && !fields.baseUrl) { setTestStatus("fail"); setTestMsg("Server URL is required"); return; }
    if (provider !== "local" && !fields.apiKey)  { setTestStatus("fail"); setTestMsg("API key is required");    return; }
    try {
      const res = await fetch(`${API_BASE}/api/ai/test`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ provider, ...fields }),
      });
      const d = await res.json();
      if (d.ok) { setTestStatus("ok");   setTestMsg(d.message || "Connected"); }
      else       { setTestStatus("fail"); setTestMsg(d.error  || "Connection failed"); }
    } catch { setTestStatus("fail"); setTestMsg("Cannot reach backend"); }
  };

  const handleSave = () => {
    onSave({ provider, fields, prompts, cymind_memory: cymindMemory });
    try { Object.entries(moduleUrls).forEach(([id, url]) => localStorage.setItem(`cycentra_url_${id}`, url)); } catch {}
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div>
      <div style={{ marginBottom:28 }}>
        <h1 style={{ fontSize:22, fontWeight:700, color:"white" }}>AI Settings</h1>
        <p style={{ color:"rgba(255,255,255,0.35)", fontSize:13, marginTop:4 }}>Configure AI provider and customise how CyCentra AI interprets security findings.</p>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:24, alignItems:"start" }}>
        {/* Provider selection */}
        <div>
          <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:14 }}>AI Provider</div>
          <div style={{ display:"flex", flexDirection:"column", gap:8, marginBottom:22 }}>
            {Object.values(AI_PROVIDERS).map(p => (
              <div key={p.id} onClick={() => { setProvider(p.id); setFields({}); setTestStatus(null); }}
                style={{ display:"flex", alignItems:"center", gap:12, padding:"12px 16px", background:provider===p.id?"rgba(255,255,255,0.04)":"rgba(255,255,255,0.02)", border:`1px solid ${provider===p.id?p.color+"50":"rgba(255,255,255,0.07)"}`, borderLeft:`3px solid ${provider===p.id?p.color:"transparent"}`, borderRadius:4, cursor:"pointer" }}>
                <span style={{ fontSize:18 }}>{p.icon}</span>
                <div style={{ flex:1 }}>
                  <div style={{ display:"flex", gap:8, alignItems:"center" }}>
                    <span style={{ color:provider===p.id?p.color:"white", fontSize:13, fontWeight:600 }}>{p.name}</span>
                    <span style={{ background:`${p.color}20`, color:p.color, border:`1px solid ${p.color}40`, fontSize:8, fontFamily:"monospace", padding:"1px 6px", borderRadius:2, fontWeight:700 }}>{p.badge}</span>
                  </div>
                  <div style={{ color:"rgba(255,255,255,0.3)", fontSize:11, marginTop:2 }}>{p.description}</div>
                </div>
                {provider === p.id && <span style={{ color:p.color, fontSize:14 }}>◉</span>}
              </div>
            ))}
          </div>

          {/* Provider fields */}
          <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:6, padding:"18px 20px", marginBottom:16 }}>
            <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:14 }}>Connection</div>
            {currentProvider.fields.map(f => (
              <div key={f.key} style={{ marginBottom:14 }}>
                <label style={{ color:"rgba(255,255,255,0.4)", fontSize:10, fontFamily:"monospace", letterSpacing:"1px", display:"block", marginBottom:6 }}>{f.label}</label>
                <input type={f.type} value={fields[f.key] || ""} onChange={e => updateField(f.key, e.target.value)}
                  placeholder={f.placeholder}
                  style={{ width:"100%", background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.12)", color:"white", padding:"9px 12px", borderRadius:4, fontSize:12, fontFamily:"monospace", outline:"none", boxSizing:"border-box" }}/>
              </div>
            ))}
            {currentProvider.models && (
              <div style={{ marginBottom:14 }}>
                <label style={{ color:"rgba(255,255,255,0.4)", fontSize:10, fontFamily:"monospace", letterSpacing:"1px", display:"block", marginBottom:6 }}>SUGGESTED MODELS</label>
                <div style={{ display:"flex", gap:5, flexWrap:"wrap" }}>
                  {currentProvider.models.map(m => (
                    <button key={m} onClick={() => updateField("model", m)}
                      style={{ background: fields.model===m?"rgba(0,229,160,0.12)":"rgba(255,255,255,0.04)", color: fields.model===m?"#00e5a0":"rgba(255,255,255,0.4)", border:`1px solid ${fields.model===m?"rgba(0,229,160,0.3)":"rgba(255,255,255,0.08)"}`, borderRadius:3, padding:"4px 10px", fontSize:10, fontFamily:"monospace", cursor:"pointer" }}>
                      {m}
                    </button>
                  ))}
                </div>
              </div>
            )}
            <div style={{ display:"flex", gap:10, alignItems:"center" }}>
              <button onClick={testConnection} disabled={testStatus==="testing"}
                style={{ background:"rgba(0,229,160,0.1)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.3)", borderRadius:4, padding:"8px 18px", fontFamily:"monospace", fontSize:11, cursor:"pointer", fontWeight:700 }}>
                {testStatus === "testing" ? "Testing…" : "Test Connection"}
              </button>
              {testStatus === "ok"   && <span style={{ color:"#00e5a0", fontSize:11, fontFamily:"monospace" }}>✓ {testMsg}</span>}
              {testStatus === "fail" && <span style={{ color:"#ff3b3b", fontSize:11, fontFamily:"monospace" }}>✗ {testMsg}</span>}
            </div>
          </div>

          {/* Module URL overrides */}
          <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:6, padding:"18px 20px", marginBottom:16 }}>
            <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:12 }}>Module URL Overrides</div>
            {[{ id:"cyiris",label:"CyIRIS URL" },{ id:"cysoar",label:"CySOAR URL" },{ id:"cysiem",label:"CySIEM URL" }].map(({ id, label }) => (
              <div key={id} style={{ display:"flex", gap:8, alignItems:"center", marginBottom:10 }}>
                <label style={{ color:"rgba(255,255,255,0.4)", fontSize:11, fontFamily:"monospace", width:110, flexShrink:0 }}>{label}</label>
                <input value={moduleUrls[id] || ""} onChange={e => setModuleUrls(prev => ({ ...prev, [id]: e.target.value }))}
                  placeholder={`https://${id}.${_BASE_DOMAIN}`}
                  style={{ flex:1, background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.12)", color:"white", padding:"8px 12px", borderRadius:4, fontSize:12, fontFamily:"monospace", outline:"none" }}/>
              </div>
            ))}
          </div>

          {/* CyMind episodic memory — always-on, independent of active LLM provider */}
          <div style={{ background:"rgba(168,85,247,0.04)", border:"1px solid rgba(168,85,247,0.2)", borderRadius:6, padding:"18px 20px" }}>
            <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
              <span style={{ fontSize:14 }}>🧠</span>
              <div style={{ color:"rgba(168,85,247,0.9)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace" }}>CyMind Episodic Memory</div>
            </div>
            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:11, marginBottom:14 }}>Store ASM and correlation engine incidents into CyMind for analyst chat queries. Works regardless of the active AI provider above.</div>
            {[{ key:"baseUrl", label:"CyMind Server URL", placeholder:"http://172.16.0.2:8080", type:"text" },
              { key:"apiKey",  label:"API Key (pak_...)", placeholder:"pak_xxxxxxxxxxxxxxxxxxxx", type:"password" }].map(f => (
              <div key={f.key} style={{ marginBottom:12 }}>
                <label style={{ color:"rgba(255,255,255,0.4)", fontSize:10, fontFamily:"monospace", letterSpacing:"1px", display:"block", marginBottom:5 }}>{f.label}</label>
                <input type={f.type} value={cymindMemory[f.key] || ""}
                  onChange={e => setCymindMemory(prev => ({ ...prev, [f.key]: e.target.value }))}
                  placeholder={f.placeholder}
                  style={{ width:"100%", background:"rgba(255,255,255,0.05)", border:"1px solid rgba(168,85,247,0.25)", color:"white", padding:"9px 12px", borderRadius:4, fontSize:12, fontFamily:"monospace", outline:"none", boxSizing:"border-box" }}/>
              </div>
            ))}
            <div style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace" }}>
              {cymindMemory.baseUrl && cymindMemory.apiKey
                ? <span style={{ color:"#a855f7" }}>✓ Configured — incidents will be indexed automatically</span>
                : "Leave blank to disable episodic memory integration"}
            </div>
          </div>
        </div>

        {/* Prompt configuration */}
        <div>
          <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:14 }}>Prompt Configuration</div>
          <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:6, overflow:"hidden" }}>
            <div style={{ display:"flex", borderBottom:"1px solid rgba(255,255,255,0.07)" }}>
              {[{ id:"system",label:"System" },{ id:"asm_context",label:"ASM Context" },{ id:"vuln_analysis",label:"Vuln Analysis" }].map(t => (
                <button key={t.id} onClick={() => setActivePTab(t.id)}
                  style={{ flex:1, background:activePromptTab===t.id?"rgba(0,229,160,0.08)":"transparent", color:activePromptTab===t.id?"#00e5a0":"rgba(255,255,255,0.4)", border:"none", borderBottom:`2px solid ${activePromptTab===t.id?"#00e5a0":"transparent"}`, padding:"10px 8px", fontFamily:"monospace", fontSize:11, cursor:"pointer" }}>
                  {t.label}
                </button>
              ))}
            </div>
            <div style={{ padding:"16px 18px" }}>
              <textarea value={prompts[activePromptTab] || ""} onChange={e => updatePrompt(activePromptTab, e.target.value)}
                style={{ width:"100%", height:280, background:"transparent", border:"none", color:"rgba(255,255,255,0.7)", fontFamily:"monospace", fontSize:11, lineHeight:1.6, outline:"none", resize:"vertical", boxSizing:"border-box" }}/>
              <button onClick={() => resetPrompt(activePromptTab)}
                style={{ background:"transparent", color:"rgba(255,255,255,0.25)", border:"1px solid rgba(255,255,255,0.1)", borderRadius:3, padding:"4px 12px", fontFamily:"monospace", fontSize:10, cursor:"pointer", marginTop:8 }}>
                Reset to default
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Save button */}
      <div style={{ display:"flex", gap:12, marginTop:28, alignItems:"center" }}>
        <button onClick={handleSave}
          style={{ background:"#00e5a0", color:"#0d0f14", border:"none", borderRadius:4, padding:"12px 32px", fontFamily:"monospace", fontSize:13, fontWeight:700, cursor:"pointer", letterSpacing:"1px", textTransform:"uppercase" }}>
          Save AI Configuration
        </button>
        {saved && <span style={{ color:"#00e5a0", fontSize:12, fontFamily:"monospace" }}>✓ Saved</span>}
        <div style={{ flex:1 }}/>
        <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:4, padding:"8px 14px" }}>
          <span style={{ color:"rgba(255,255,255,0.3)", fontSize:11, fontFamily:"monospace" }}>Active: </span>
          <span style={{ color:currentProvider.color, fontSize:11, fontFamily:"monospace", fontWeight:700 }}>
            {currentProvider.icon} {currentProvider.name} {fields.model ? `· ${fields.model}` : ""}
          </span>
        </div>
      </div>
    </div>
  );
}
