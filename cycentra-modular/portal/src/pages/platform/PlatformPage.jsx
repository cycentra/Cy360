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
  }[status] || { color:"rgba(255,255,255,0.2)", label:"NOT INSTALLED" };
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
  const logRef = useRef(null);

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
      const poll = setInterval(async () => {
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
            clearInterval(poll);
            setStage("done");
            setProgress(100);
            onInstall(mod.id, config);
          } else if (s.status === "failed") {
            clearInterval(poll);
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
          {f.help && <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, marginTop:4 }}>{f.help}</div>}
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
      id: "cyiris", name: "CyIRIS (DFIR IRIS)", protocol: "OIDC", color: "#b06eff", icon: "🔍",
      steps: [
        "Install CyIRIS module (creates the DFIR IRIS instance)",
        `In IRIS → Settings → Authentication → Enable OpenID Connect`,
        `Set OIDC Discovery URL: ${PORTAL_URL}/oidc/.well-known/openid-configuration`,
        "Client ID: cyiris  ·  Client Secret: CYIRIS_OIDC_SECRET from your .env",
        `Redirect URI: https://cyiris.${_BASE_DOMAIN}/auth/oidc/callback`,
        "Save and restart CyIRIS. Users will see 'Login with CyCentra 360' button.",
      ],
    },
    {
      id: "cysoar", name: "CySOAR (Node-RED SOAR)", protocol: "OIDC", color: "#4d9eff", icon: "⚡",
      steps: [
        "Install CySOAR module",
        `Configure OIDC: Discovery URL: ${PORTAL_URL}/oidc/.well-known/openid-configuration`,
        "Client ID: cysoar  ·  Client Secret: CYSOAR_OIDC_SECRET from your .env",
        `Redirect URI: https://cysoar.${_BASE_DOMAIN}/auth/callback`,
        "Enable SSO in Node-RED settings.js. Restart CySOAR.",
      ],
    },
    {
      id: "cysiem", name: "CySIEM (Wazuh)", protocol: "SAML", color: "#ff8c00", icon: "👁️",
      steps: [
        "CySIEM runs Wazuh with OpenSearch. SSO uses OpenSearch Security → SAML.",
        `IdP Entity ID: ${PORTAL_URL}`,
        `IdP Metadata URL: ${PORTAL_URL}/.well-known/saml-metadata`,
        "SP Entity ID: cysiem",
        "After configuring SAML, restart OpenSearch Dashboards.",
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
                    <span style={{ color:"rgba(255,255,255,0.15)", fontSize:11 }}>·</span>
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
                          <div style={{ color:"rgba(255,255,255,0.25)", fontSize:9, fontFamily:"monospace", letterSpacing:"1px" }}>{r.label}</div>
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
