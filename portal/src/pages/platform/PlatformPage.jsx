/**
 * src/pages/platform/PlatformPage.jsx
 * =====================================
 * Platform module management — install, uninstall, SSO config.
 * Extracted from App.jsx MODULE 04 block.
 */

import { useState, useEffect, useRef } from "react";
import { API_BASE, PORTAL_URL, _BASE_DOMAIN } from '../../core/constants.js';
import { PLATFORM_MODULES } from '../../registry/platformModules.js';

// ── Status Pill ───────────────────────────────────────────────────────────────

function StatusPill({ status, tier }) {
  if (tier === "base") return (
    <span style={{ background:"rgba(0,229,160,0.12)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.3)", fontSize:9, fontFamily:"monospace", padding:"3px 10px", borderRadius:2, fontWeight:700, letterSpacing:"1px" }}>
      BASE 360 · ALWAYS ON
    </span>
  );
  const cfg = {
    running:    { color:"#00e5a0", label:"RUNNING"       },
    installing: { color:"#f5c518", label:"INSTALLING"    },
    failed:     { color:"#ff3b3b", label:"FAILED"        },
    stopped:    { color:"rgba(255,255,255,0.3)", label:"STOPPED" },
  }[status] || { color:"rgba(255,255,255,0.45)", label:"NOT INSTALLED" };
  return (
    <span style={{ background:`${cfg.color}15`, color:cfg.color, border:`1px solid ${cfg.color}30`, fontSize:9, fontFamily:"monospace", padding:"3px 10px", borderRadius:2, fontWeight:700, letterSpacing:"1px", display:"flex", alignItems:"center", gap:5 }}>
      {status === "running" && <span style={{ width:5, height:5, borderRadius:"50%", background:cfg.color, animation:"pulse 2s infinite" }}/>}
      {cfg.label}
    </span>
  );
}

// ── Install Form ──────────────────────────────────────────────────────────────

function InstallForm({ mod, onInstall, onCancel }) {
  const [config,   setConfig]   = useState(mod.defaultConfig || {});
  const [stage,    setStage]    = useState("config"); // config | installing | done | error
  const [log,      setLog]      = useState([]);
  const [progress, setProgress] = useState(0);
  const logRef  = useRef(null);
  const pollRef = useRef(null);

  // Cleanup any running poll when the form unmounts (e.g. modal closed mid-install)
  useEffect(() => {
    return () => { clearInterval(pollRef.current); };
  }, []);

  const update = (k, v) => setConfig(prev => ({ ...prev, [k]: v }));

  const startInstall = async () => {
    setStage("installing");
    setLog(["Preparing installation…"]);
    setProgress(5);

    try {
      const res = await fetch(`${API_BASE}/api/platform/install`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ module: mod.id, config }),
      });
      if (!res.ok) {
        const e = await res.json();
        setLog(prev => [...prev, `ERROR: ${e.error || "Install failed"}`]);
        setStage("error");
        return;
      }

      // Poll logs + status every 3 s
      pollRef.current = setInterval(async () => {
        try {
          const lr = await fetch(`${API_BASE}/api/platform/logs/${mod.id}`, { credentials: "include" });
          if (lr.ok) {
            const l = await lr.json();
            if (l.lines?.length) {
              setLog(l.lines);
              const last = l.lines[l.lines.length - 1].toLowerCase();
              if (last.includes("pulling"))                setProgress(p => Math.max(p, 15));
              else if (last.includes("starting"))          setProgress(p => Math.max(p, 40));
              else if (last.includes("waiting"))           setProgress(p => Math.max(p, 50));
              else if (last.includes("live"))              setProgress(p => Math.max(p, 85));
              else if (last.includes("credentials set"))   setProgress(p => Math.max(p, 92));
              else if (last.includes("done — status"))     setProgress(100);
            }
          }
          const sr  = await fetch(`${API_BASE}/api/platform/status`, { credentials: "include" });
          if (!sr.ok) return;
          const all = await sr.json();
          const s   = all[mod.id];
          if (!s) return;
          if (s.status === "running") {
            clearInterval(pollRef.current);
            setStage("done");
            setProgress(100);
            onInstall(mod.id, config);
          } else if (s.status === "failed") {
            clearInterval(pollRef.current);
            setStage("error");
          }
        } catch {}
      }, 3000);
    } catch (e) {
      setLog(prev => [...prev, `Network error: ${e.message}`]);
      setStage("error");
    }
  };

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  if (stage === "config") return (
    <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.08)", borderRadius:4, padding:"20px 24px", marginTop:16 }}>
      <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:16 }}>
        Configure {mod.name}
      </div>
      {(mod.configFields || []).map(f => (
        <div key={f.key} style={{ marginBottom:14 }}>
          <label style={{ color:"rgba(255,255,255,0.45)", fontSize:10, fontFamily:"monospace", letterSpacing:"1px", textTransform:"uppercase", display:"block", marginBottom:6 }}>{f.label}</label>
          <input type={f.type || "text"} value={config[f.key] || ""} onChange={e => update(f.key, e.target.value)}
            style={{ width:"100%", background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.12)", color:"white", padding:"10px 14px", borderRadius:4, fontSize:13, fontFamily:"monospace", outline:"none", boxSizing:"border-box" }}/>
          {f.help && <div style={{ color:"rgba(255,255,255,0.45)", fontSize:10, marginTop:4 }}>{f.help}</div>}
        </div>
      ))}
      <div style={{ display:"flex", gap:10, marginTop:20 }}>
        <button onClick={startInstall}
          style={{ background:mod.color, color:"#0d0f14", border:"none", borderRadius:4, padding:"10px 24px", fontFamily:"monospace", fontSize:12, fontWeight:700, cursor:"pointer", letterSpacing:"1px" }}>
          Install {mod.name} →
        </button>
        <button onClick={onCancel}
          style={{ background:"transparent", color:"rgba(255,255,255,0.4)", border:"1px solid rgba(255,255,255,0.1)", borderRadius:4, padding:"10px 18px", fontFamily:"monospace", fontSize:12, cursor:"pointer" }}>
          Cancel
        </button>
      </div>
    </div>
  );

  return (
    <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.08)", borderRadius:4, padding:"20px 24px", marginTop:16 }}>
      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:12 }}>
        <span style={{ color:"rgba(255,255,255,0.5)", fontSize:12, fontFamily:"monospace" }}>
          {stage === "installing" ? "Installing…" : stage === "done" ? "✓ Complete" : "✗ Failed"}
        </span>
        <span style={{ color: stage==="done" ? "#00e5a0" : stage==="error" ? "#ff3b3b" : "#f5c518", fontFamily:"monospace", fontSize:12, fontWeight:700 }}>{progress}%</span>
      </div>
      <div style={{ height:4, background:"rgba(255,255,255,0.06)", borderRadius:2, marginBottom:14 }}>
        <div style={{ height:"100%", width:`${progress}%`, background: stage==="error" ? "#ff3b3b" : "#00e5a0", borderRadius:2, transition:"width 0.4s ease" }}/>
      </div>
      <div ref={logRef} style={{ height:140, overflowY:"auto", background:"rgba(0,0,0,0.4)", borderRadius:4, padding:"10px 14px", fontFamily:"monospace", fontSize:10, color:"rgba(255,255,255,0.5)" }}>
        {log.map((l, i) => <div key={i}>{l}</div>)}
      </div>
      {(stage === "done" || stage === "error") && (
        <div style={{ marginTop:14, display:"flex", gap:10 }}>
          <button onClick={onCancel}
            style={{ background: stage==="done" ? "rgba(255,255,255,0.08)" : "rgba(255,59,59,0.2)", color: stage==="done" ? "rgba(255,255,255,0.6)" : "#ff3b3b", border:"1px solid rgba(255,255,255,0.1)", borderRadius:4, padding:"10px 24px", fontFamily:"monospace", fontSize:12, fontWeight:700, cursor:"pointer" }}>
            {stage === "done" ? "Done" : "Close"}
          </button>
        </div>
      )}
    </div>
  );
}

// ── SSO Config Panel ──────────────────────────────────────────────────────────

function SSOConfigPanel() {
  const [expanded, setExpanded] = useState(null);

  const ssoGuides = [
    {
      id: "cysoar", name: "CySOAR (Node-RED SOAR)", protocol: "OIDC", color: "#4d9eff", icon: "\u26A1",
      steps: [
        "Install CySOAR via the portal — OIDC is pre-configured automatically.",
        "Click the CySOAR link in the portal. You are redirected to CyCentra for auth.",
        "CyCentra session is recognised — you land in Node-RED with no credentials.",
        `OIDC Discovery: https://cyasm.${_BASE_DOMAIN}/oidc/.well-known/openid-configuration`,
        `Callback URI (auto-set): https://cysoc.${_BASE_DOMAIN}/cysoar/auth/callback`,
      ],
    },
    {
      id: "cysiem", name: "CySIEM (Wazuh)", protocol: "OIDC", color: "#ff8c00", icon: "\uD83D\uDC41\uFE0F",
      steps: [
        "CySIEM OIDC is configured automatically by cycentra-setup.sh on every new server.",
        "Visit the CySIEM link — OpenSearch Dashboards redirects to CyCentra for auth.",
        "CyCentra session is recognised — you land in Wazuh Dashboard with no password.",
        `OIDC Discovery: https://cyasm.${_BASE_DOMAIN}/oidc/.well-known/openid-configuration`,
        "Role mapping: admin \u2192 all_access \u00B7 analyst \u2192 readall_and_monitor",
        "Secret stored in /opt/cycentra/.env as CYSIEM_OIDC_SECRET (auto-generated).",
      ],
    },
  ];

  return (
    <div>
      <div style={{ marginBottom:20 }}>
        <h2 style={{ fontSize:18, fontWeight:700, color:"white", marginBottom:6 }}>SSO Configuration</h2>
        <p style={{ color:"rgba(255,255,255,0.35)", fontSize:13 }}>
          CyCentra 360 acts as the Identity Provider. Follow these guides to enable single sign-on for each module.
        </p>
      </div>
      <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
        {ssoGuides.map(g => (
          <div key={g.id} style={{ background:"rgba(255,255,255,0.025)", border:`1px solid ${g.color}20`, borderLeft:`3px solid ${g.color}`, borderRadius:5, overflow:"hidden" }}>
            <div onClick={() => setExpanded(expanded === g.id ? null : g.id)}
              style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"16px 20px", cursor:"pointer" }}>
              <div style={{ display:"flex", gap:12, alignItems:"center" }}>
                <span style={{ fontSize:18 }}>{g.icon}</span>
                <div>
                  <div style={{ color:"white", fontWeight:600, fontSize:14 }}>{g.name}</div>
                  <div style={{ color:"rgba(255,255,255,0.3)", fontSize:11, fontFamily:"monospace", marginTop:2 }}>Protocol: {g.protocol}</div>
                </div>
              </div>
              <span style={{ color:"rgba(255,255,255,0.3)", fontSize:14 }}>{expanded === g.id ? "▲" : "▼"}</span>
            </div>
            {expanded === g.id && (
              <div style={{ padding:"0 20px 20px" }}>
                <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                  {g.steps.map((step, i) => (
                    <div key={i} style={{ display:"flex", gap:12, alignItems:"flex-start" }}>
                      <div style={{ width:20, height:20, borderRadius:"50%", background:`${g.color}20`, border:`1px solid ${g.color}40`, display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0, marginTop:1 }}>
                        <span style={{ color:g.color, fontSize:9, fontWeight:700, fontFamily:"monospace" }}>{i + 1}</span>
                      </div>
                      <span style={{ color:"rgba(255,255,255,0.65)", fontSize:13, lineHeight:1.5, paddingTop:2 }}>{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Platform Page ─────────────────────────────────────────────────────────────

export function PlatformPage({ installedModules, onInstall, onUninstall }) {
  const [installing,    setInstalling]    = useState(null);
  const [confirmUnins,  setConfirmUnins]  = useState(null);
  const [activeSection, setActiveSection] = useState("modules");
  const [moduleVersions,  setModuleVersions]  = useState({});
  const [moduleUpdating,  setModuleUpdating]  = useState({});
  const [verChecking,     setVerChecking]     = useState({});

  const checkModuleVersion = async (moduleId) => {
    setVerChecking(prev => ({ ...prev, [moduleId]: true }));
    try {
      const r = await fetch(`${API_BASE}/api/platform/version/${moduleId}`, { credentials: "include" });
      if (r.ok) {
        const d = await r.json();
        setModuleVersions(prev => ({ ...prev, [moduleId]: d }));
      }
    } catch {}
    setVerChecking(prev => ({ ...prev, [moduleId]: false }));
  };

  const updateModule = async (moduleId) => {
    if (!confirm(`Pull the latest ${moduleId.toUpperCase()} image and restart the service?\nThe module will be unavailable for ~30 seconds.`)) return;
    setModuleUpdating(prev => ({ ...prev, [moduleId]: true }));
    try {
      const r = await fetch(`${API_BASE}/api/platform/update/${moduleId}`, {
        method: "POST", credentials: "include",
      });
      const d = await r.json();
      alert(d.message || (r.ok ? "Update started." : `Error: ${d.error}`));
      if (r.ok) {
        // clear version cache so user sees fresh info after ~30s
        setTimeout(() => {
          setModuleUpdating(prev => ({ ...prev, [moduleId]: false }));
          setModuleVersions(prev => { const n = { ...prev }; delete n[moduleId]; return n; });
        }, 32000);
      } else {
        setModuleUpdating(prev => ({ ...prev, [moduleId]: false }));
      }
    } catch (e) {
      alert("Update request failed: " + e.message);
      setModuleUpdating(prev => ({ ...prev, [moduleId]: false }));
    }
  };

  const baseModules  = Object.values(PLATFORM_MODULES).filter(m => m.tier === "base");
  const addonModules = Object.values(PLATFORM_MODULES).filter(m => m.tier === "addon");

  const handleInstall = (moduleId, config) => {
    onInstall(moduleId, config);
    setInstalling(null);
  };

  // Auto-refresh module status every 5 s
  useEffect(() => {
    const refresh = async () => {
      try {
        const r = await fetch(`${API_BASE}/api/platform/status`, { credentials: "include" });
        if (!r.ok) return;
        const data = await r.json();
        Object.entries(data).forEach(([id, s]) => {
          if (s.status === "running" && installedModules[id]?.status !== "running") {
            onInstall(id, installedModules[id]?.config || {});
          }
        });
      } catch {}
    };
    const timer = setInterval(refresh, 5000);
    refresh();
    return () => clearInterval(timer);
  }, [installedModules, onInstall]);

  return (
    <div>
      {/* Header + tab switcher */}
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-end", marginBottom:24 }}>
        <div>
          <h1 style={{ fontSize:22, fontWeight:700, color:"white" }}>Platform</h1>
          <p style={{ color:"rgba(255,255,255,0.35)", fontSize:13, marginTop:4 }}>Manage modules and centralized SSO configuration</p>
        </div>
        <div style={{ display:"flex", gap:6 }}>
          {[["modules","Modules"],["sso","SSO Config"]].map(([id,label]) => (
            <button key={id} onClick={() => setActiveSection(id)}
              style={{ background:activeSection===id?"rgba(0,229,160,0.12)":"rgba(255,255,255,0.04)", color:activeSection===id?"#00e5a0":"rgba(255,255,255,0.5)", border:`1px solid ${activeSection===id?"rgba(0,229,160,0.3)":"rgba(255,255,255,0.08)"}`, borderRadius:4, padding:"8px 18px", fontFamily:"monospace", fontSize:11, cursor:"pointer", fontWeight:700 }}>
              {label}
            </button>
          ))}
        </div>
      </div>

      {activeSection === "sso" && <SSOConfigPanel/>}

      {activeSection === "modules" && (
        <div>
          {/* Base modules */}
          <div style={{ marginBottom:32 }}>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:14 }}>
              <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace" }}>Base 360 — Always Installed</div>
              <span style={{ background:"rgba(0,229,160,0.1)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.2)", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, fontWeight:700 }}>CORE · NO INSTALL REQUIRED</span>
            </div>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14 }}>
              {baseModules.map(mod => (
                <div key={mod.id} style={{ background:"rgba(255,255,255,0.025)", border:`1px solid ${mod.color}20`, borderTop:`2px solid ${mod.color}`, borderRadius:5, padding:"22px 24px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:14 }}>
                    <div style={{ display:"flex", gap:12, alignItems:"center" }}>
                      <span style={{ fontSize:26 }}>{mod.icon}</span>
                      <div>
                        <div style={{ color:"white", fontSize:16, fontWeight:700 }}>{mod.name}</div>
                        <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, marginTop:2 }}>{mod.fullName?.split("—")[1]?.trim()}</div>
                      </div>
                    </div>
                    <StatusPill tier="base"/>
                  </div>
                  <div style={{ color:"rgba(255,255,255,0.5)", fontSize:12, lineHeight:1.6, marginBottom:14 }}>{mod.description}</div>
                  <div style={{ display:"flex", gap:5, flexWrap:"wrap", marginBottom:14 }}>
                    {(mod.features || []).map(f => (
                      <span key={f} style={{ background:"rgba(255,255,255,0.05)", color:"rgba(255,255,255,0.4)", border:"1px solid rgba(255,255,255,0.08)", fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2 }}>{f}</span>
                    ))}
                  </div>
                  <div style={{ display:"flex", gap:8, alignItems:"center" }}>
                    <span style={{ color:"rgba(255,255,255,0.3)", fontSize:11, fontFamily:"monospace" }}>SSO: {mod.ssoProtocol}</span>
                    <span style={{ color:"rgba(255,255,255,0.45)", fontSize:11 }}>·</span>
                    <a href={mod.docsUrl} onClick={e => { e.preventDefault(); window.location.href = mod.docsUrl; }} style={{ color:"rgba(255,255,255,0.35)", fontSize:11, textDecoration:"none" }}>Docs ↗</a>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Add-on modules */}
          <div>
            <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:14 }}>Add-on Modules — Optional</div>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14 }}>
              {addonModules.map(mod => {
                const installed    = installedModules[mod.id];
                const isInstalling = installing === mod.id;

                return (
                  <div key={mod.id} style={{ background:"rgba(255,255,255,0.025)", border:`1px solid ${mod.color}20`, borderTop:`2px solid ${mod.color}`, borderRadius:5, padding:"22px 24px" }}>
                    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:14 }}>
                      <div style={{ display:"flex", gap:12, alignItems:"center" }}>
                        <span style={{ fontSize:26 }}>{mod.icon}</span>
                        <div>
                          <div style={{ color:"white", fontSize:16, fontWeight:700 }}>{mod.name}</div>
                          <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, marginTop:2 }}>{mod.fullName?.split("—")[1]?.trim()}</div>
                        </div>
                      </div>
                      <StatusPill status={installed?.status} tier={mod.tier}/>
                    </div>

                    <div style={{ color:"rgba(255,255,255,0.5)", fontSize:12, lineHeight:1.6, marginBottom:14 }}>{mod.description}</div>

                    <div style={{ display:"flex", gap:16, marginBottom:14 }}>
                      {[{ label:"RAM", val:`${mod.ram_gb} GB` },{ label:"Disk", val:`${mod.disk_gb} GB` },{ label:"Time", val:mod.install_time }].map(r => (
                        <div key={r.label}>
                          <div style={{ color:"rgba(255,255,255,0.45)", fontSize:9, fontFamily:"monospace", letterSpacing:"1px" }}>{r.label}</div>
                          <div style={{ color:"rgba(255,255,255,0.6)", fontSize:12, fontFamily:"monospace" }}>{r.val}</div>
                        </div>
                      ))}
                    </div>

                    {!installed && !isInstalling && (
                      <button onClick={() => setInstalling(mod.id)}
                        style={{ background:`${mod.color}20`, color:mod.color, border:`1px solid ${mod.color}50`, borderRadius:4, padding:"9px 18px", fontFamily:"monospace", fontSize:11, cursor:"pointer", fontWeight:700 }}>
                        Install {mod.name}
                      </button>
                    )}

                    {installed && !isInstalling && (
                      <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
                        <div style={{ display:"flex", gap:8, alignItems:"center" }}>
                          {confirmUnins === mod.id ? (
                            <div style={{ display:"flex", gap:6 }}>
                              <button onClick={() => { onUninstall(mod.id); setConfirmUnins(null); }}
                                style={{ background:"rgba(255,59,59,0.15)", color:"#ff3b3b", border:"1px solid rgba(255,59,59,0.3)", borderRadius:4, padding:"9px 16px", fontFamily:"monospace", fontSize:11, cursor:"pointer" }}>
                                Confirm Remove
                              </button>
                              <button onClick={() => setConfirmUnins(null)}
                                style={{ background:"transparent", color:"rgba(255,255,255,0.35)", border:"1px solid rgba(255,255,255,0.1)", borderRadius:4, padding:"9px 12px", fontFamily:"monospace", fontSize:11, cursor:"pointer" }}>
                                Cancel
                              </button>
                            </div>
                          ) : (
                            <button onClick={() => setConfirmUnins(mod.id)}
                              style={{ background:"transparent", color:"rgba(255,59,59,0.5)", border:"1px solid rgba(255,59,59,0.2)", borderRadius:4, padding:"9px 16px", fontFamily:"monospace", fontSize:11, cursor:"pointer" }}>
                              Uninstall
                            </button>
                          )}
                        </div>

                        {/* Version & Update row — only for updateable modules */}
                        {mod.id === "cysoar" && installed.status === "running" && (
                          <div style={{ borderTop:"1px solid rgba(255,255,255,0.06)", paddingTop:10 }}>
                            {moduleVersions[mod.id] && (
                              <div style={{ display:"flex", gap:16, marginBottom:8 }}>
                                <div>
                                  <div style={{ fontSize:9, color:"rgba(255,255,255,0.3)", fontFamily:"monospace", letterSpacing:"1px", textTransform:"uppercase", marginBottom:2 }}>Running</div>
                                  <div style={{ fontSize:12, fontWeight:700, color:"#00e5a0", fontFamily:"monospace" }}>{moduleVersions[mod.id].running || "—"}</div>
                                </div>
                                <div>
                                  <div style={{ fontSize:9, color:"rgba(255,255,255,0.3)", fontFamily:"monospace", letterSpacing:"1px", textTransform:"uppercase", marginBottom:2 }}>Latest</div>
                                  <div style={{ fontSize:12, fontWeight:700, color: moduleVersions[mod.id].update_available ? "#f5c518" : "#00e5a0", fontFamily:"monospace" }}>{moduleVersions[mod.id].latest || "—"}</div>
                                </div>
                              </div>
                            )}
                            {moduleVersions[mod.id]?.update_available && (
                              <div style={{ background:"rgba(245,197,24,0.07)", border:"1px solid rgba(245,197,24,0.2)", borderRadius:3, padding:"6px 10px", marginBottom:8, fontSize:11, color:"rgba(245,197,24,0.85)" }}>
                                ⚠ Update available: {moduleVersions[mod.id].running} → {moduleVersions[mod.id].latest}
                              </div>
                            )}
                            {moduleVersions[mod.id] && !moduleVersions[mod.id].update_available && (
                              <div style={{ background:"rgba(0,229,160,0.05)", border:"1px solid rgba(0,229,160,0.18)", borderRadius:3, padding:"6px 10px", marginBottom:8, fontSize:11, color:"rgba(0,229,160,0.75)" }}>
                                ✓ Up to date
                              </div>
                            )}
                            <div style={{ display:"flex", gap:6 }}>
                              <button
                                onClick={() => checkModuleVersion(mod.id)}
                                disabled={verChecking[mod.id] || moduleUpdating[mod.id]}
                                style={{ background:"rgba(255,255,255,0.05)", color:"rgba(255,255,255,0.55)", border:"1px solid rgba(255,255,255,0.1)", borderRadius:3, padding:"7px 12px", fontFamily:"monospace", fontSize:10, cursor:"pointer", display:"flex", alignItems:"center", gap:5 }}>
                                {verChecking[mod.id] ? "⟳" : "🔍"} Check for Update
                              </button>
                              {moduleVersions[mod.id]?.update_available && (
                                <button
                                  onClick={() => updateModule(mod.id)}
                                  disabled={moduleUpdating[mod.id]}
                                  style={{ background:`${mod.color}18`, color:mod.color, border:`1px solid ${mod.color}40`, borderRadius:3, padding:"7px 12px", fontFamily:"monospace", fontSize:10, cursor:"pointer", fontWeight:700, display:"flex", alignItems:"center", gap:5 }}>
                                  {moduleUpdating[mod.id] ? "⟳ Updating…" : "⬆ Update Now"}
                                </button>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {isInstalling && (
                      <InstallForm mod={mod} onInstall={handleInstall} onCancel={() => setInstalling(null)}/>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
