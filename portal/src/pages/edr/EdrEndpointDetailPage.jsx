/**
 * pages/edr/EdrEndpointDetailPage.jsx — Per-endpoint deep dive
 *
 * Displays full endpoint metadata, isolation controls, forensic timeline
 * (process tree + file events + network connections derived from detections),
 * applied policies, pending/historical commands, and detection history.
 */
import React, { useEffect, useState, useCallback } from "react";

const BG      = "#0a0e1a";
const CARD_BG = "rgba(255,255,255,0.03)";
const BORDER  = "1px solid rgba(255,255,255,0.07)";
const ACCENT  = "#00e5a0";

const OS_ICON = { windows:"🪟", linux:"🐧", macos:"🍎" };

const SEVERITY_COLOR = { critical:"#ff3b3b", high:"#ff8c00", medium:"#f5c518", low:"#4d9eff", info:"#555" };

const ISOLATION_COLOR = { isolated:"#ff3b3b", connected:"#00e5a0", pending_isolation:"#f5c518", pending_unisolation:"#f5c518" };

const STATUS_COLOR = { pending:"#f5c518", acknowledged:"#4d9eff", completed:"#00e5a0", failed:"#ff3b3b" };

const ACTION_ICON = {
  ISOLATE:"🔒", UNISOLATE:"🔓", KILL_PROCESS:"⚡", BLOCK_HASH:"🚫",
  COLLECT_FORENSICS:"🔬", ROLLBACK:"↩️", QUARANTINE_FILE:"📦", RUN_SCAN:"🔍", APPLY_POLICY:"📋",
};

function Badge({ label, color }) {
  return (
    <span style={{ fontSize:10, fontWeight:700, letterSpacing:1, padding:"2px 7px", borderRadius:4, color, background:`${color}22` }}>
      {label}
    </span>
  );
}

function Stat({ label, value, color }) {
  return (
    <div style={{ textAlign:"center" }}>
      <div style={{ fontSize:22, fontWeight:800, color:color||"#e8eaf0" }}>{value}</div>
      <div style={{ fontSize:10, color:"#555", marginTop:2 }}>{label}</div>
    </div>
  );
}

function SectionTitle({ children }) {
  return (
    <div style={{ fontSize:11, fontWeight:700, letterSpacing:1.5, color:"#555", marginBottom:12, marginTop:24, paddingBottom:6, borderBottom:BORDER }}>
      {children}
    </div>
  );
}

// ── Forensic timeline from detections ────────────────────────────────────────
function ForensicTimeline({ detections }) {
  const [expanded, setExpanded] = useState(null);

  if (!detections.length) {
    return <div style={{ color:"#555", fontSize:12, padding:"20px 0" }}>No forensic events recorded yet.</div>;
  }

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:0 }}>
      {detections.slice(0, 30).map((det, i) => {
        const sevColor = SEVERITY_COLOR[det.severity] || "#555";
        const isExp = expanded === det.id;
        return (
          <div key={det.id} style={{ display:"flex", gap:0 }}>
            <div style={{ display:"flex", flexDirection:"column", alignItems:"center", marginRight:12 }}>
              <div style={{ width:10, height:10, borderRadius:"50%", background:sevColor, marginTop:14, flexShrink:0 }}/>
              {i < detections.length-1 && <div style={{ width:1, flex:1, background:"rgba(255,255,255,0.06)", minHeight:20 }}/>}
            </div>
            <div style={{ flex:1, paddingBottom:8 }}>
              <div onClick={()=>setExpanded(isExp?null:det.id)}
                style={{ background:isExp?"rgba(255,255,255,0.05)":CARD_BG, border:BORDER, borderRadius:8, padding:"10px 14px", cursor:"pointer",
                  borderLeft:`2px solid ${sevColor}` }}>
                <div style={{ display:"flex", alignItems:"center", gap:10, flexWrap:"wrap" }}>
                  <Badge label={det.severity?.toUpperCase()} color={sevColor}/>
                  <span style={{ fontSize:12, color:"#e8eaf0", flex:1 }}>{det.rule_desc || det.description}</span>
                  <span style={{ fontSize:10, color:"#555", whiteSpace:"nowrap" }}>
                    {det.detected_at ? new Date(det.detected_at).toLocaleString() : "—"}
                  </span>
                  <span style={{ color:"#444", fontSize:12 }}>{isExp?"▲":"▼"}</span>
                </div>

                {isExp && (
                  <div style={{ marginTop:12, borderTop:BORDER, paddingTop:12 }}>
                    <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:12, marginBottom:12 }}>
                      {det.mitre_id && <div><span style={{ fontSize:10, color:"#555" }}>MITRE</span><div style={{ fontSize:12, color:"#b06eff", fontWeight:700 }}>{det.mitre_id}</div></div>}
                      {det.score !== undefined && <div><span style={{ fontSize:10, color:"#555" }}>Confidence</span><div style={{ fontSize:12, color:sevColor, fontWeight:700 }}>{Math.round(det.score)}%</div></div>}
                      {det.process_name && <div><span style={{ fontSize:10, color:"#555" }}>Process</span><div style={{ fontSize:11, color:"#e8eaf0", fontFamily:"monospace" }}>{det.process_name}</div></div>}
                      {det.username && <div><span style={{ fontSize:10, color:"#555" }}>User</span><div style={{ fontSize:12, color:"#e8eaf0" }}>{det.username}</div></div>}
                      {det.src_ip && <div><span style={{ fontSize:10, color:"#555" }}>Src IP</span><div style={{ fontSize:11, color:"#e8eaf0", fontFamily:"monospace" }}>{det.src_ip}</div></div>}
                      {det.dst_ip && <div><span style={{ fontSize:10, color:"#555" }}>Dst IP</span><div style={{ fontSize:11, color:"#e8eaf0", fontFamily:"monospace" }}>{det.dst_ip}</div></div>}
                    </div>
                    {det.triggers?.length > 0 && (
                      <div>
                        <div style={{ fontSize:10, color:"#555", marginBottom:6 }}>Triggered Heuristics</div>
                        <div style={{ display:"flex", flexWrap:"wrap", gap:5 }}>
                          {det.triggers.map(t => (
                            <span key={t} style={{ fontSize:10, padding:"2px 8px", borderRadius:4, background:"rgba(176,110,255,0.12)", border:"1px solid rgba(176,110,255,0.2)", color:"#b06eff" }}>{t}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {det.file_path && (
                      <div style={{ marginTop:10 }}>
                        <div style={{ fontSize:10, color:"#555", marginBottom:3 }}>File Path</div>
                        <div style={{ fontSize:11, fontFamily:"monospace", color:"#9aa0b0", wordBreak:"break-all" }}>{det.file_path}</div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Command history list ──────────────────────────────────────────────────────
function CommandList({ commands }) {
  if (!commands.length) {
    return <div style={{ color:"#555", fontSize:12, padding:"16px 0" }}>No response commands issued.</div>;
  }
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
      {commands.map(cmd => (
        <div key={cmd.id} style={{
          background:CARD_BG, border:BORDER, borderRadius:8, padding:"10px 14px",
          display:"flex", alignItems:"center", gap:12, flexWrap:"wrap",
          borderLeft:`2px solid ${STATUS_COLOR[cmd.status]||"#888"}`,
        }}>
          <span style={{ fontSize:16 }}>{ACTION_ICON[cmd.action]||"▶"}</span>
          <div style={{ flex:1 }}>
            <div style={{ fontSize:12, color:"#e8eaf0", fontWeight:600 }}>{cmd.action}</div>
            {cmd.parameters && Object.keys(cmd.parameters).length > 0 && (
              <div style={{ fontSize:10, color:"#666", fontFamily:"monospace", marginTop:1, wordBreak:"break-all" }}>
                {JSON.stringify(cmd.parameters)}
              </div>
            )}
          </div>
          <Badge label={cmd.status?.toUpperCase()} color={STATUS_COLOR[cmd.status]||"#888"}/>
          {cmd.auto_triggered && <Badge label="AUTO" color="#b06eff"/>}
          <div style={{ fontSize:10, color:"#555" }}>{cmd.issued_at ? new Date(cmd.issued_at).toLocaleString() : "—"}</div>
        </div>
      ))}
    </div>
  );
}

// ── Applied policies list ─────────────────────────────────────────────────────
function AppliedPolicies({ agentId }) {
  const [policies, setPolicies] = useState([]);
  const [loading,  setLoading]  = useState(true);

  useEffect(() => {
    fetch(`/api/edr/agents/${agentId}/policies`)
      .then(r => r.ok ? r.json() : { policies:[] })
      .then(d => setPolicies(d.policies || []))
      .finally(() => setLoading(false));
  }, [agentId]);

  if (loading) return <div style={{ color:"#555", fontSize:12 }}>Loading policies…</div>;
  if (!policies.length) return <div style={{ color:"#555", fontSize:12 }}>No policies assigned to this endpoint.</div>;

  const TYPE_COLOR = {
    threat_prevention:"#ff3b3b", device_control:"#ff8c00", app_control:"#b06eff",
    network_control:"#4d9eff", exclusions:"#f5c518", update_policy:"#00e5a0", isolation_exceptions:"#888",
    network_probe:"#00d4ff",
  };
  return (
    <div style={{ display:"flex", flexWrap:"wrap", gap:8 }}>
      {policies.map(p => {
        const types = p.policy_types || [p.policy_type];
        const primary = TYPE_COLOR[types[0]] || "#888";
        return (
          <div key={p.id} style={{
            border:`1px solid ${primary}44`,
            borderRadius:7, padding:"8px 14px", background:`${primary}0d`,
          }}>
            <div style={{ fontSize:12, fontWeight:700, color:primary }}>{p.name}</div>
            <div style={{ display:"flex", flexWrap:"wrap", gap:6, marginTop:2 }}>
              {types.map(t => (
                <span key={t} style={{ fontSize:10, color:TYPE_COLOR[t]||"#888" }}>{t?.replace("_"," ")}</span>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Isolation control buttons ─────────────────────────────────────────────────
function IsolationControls({ agent, onRefresh }) {
  const [busy,    setBusy]    = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [error,   setError]   = useState("");

  const isIsolated = agent.isolation_state === "isolated";

  const trigger = async () => {
    setBusy(true); setError(""); setConfirm(false);
    const path = isIsolated ? "unisolate" : "isolate";
    try {
      const res = await fetch(`/api/edr/response/${agent.agent_id}/${path}`, {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ reason: isIsolated ? "Manual unisolation from endpoint detail" : "Manual isolation from endpoint detail" }),
      });
      if (!res.ok) throw new Error((await res.json()).error || res.status);
      onRefresh();
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
      {error && <div style={{ color:"#ff7070", fontSize:11 }}>{error}</div>}
      {!confirm ? (
        <button
          onClick={()=>setConfirm(true)}
          disabled={busy || agent.isolation_state==="pending_isolation" || agent.isolation_state==="pending_unisolation"}
          style={{
            border:`1px solid ${isIsolated?"#00e5a0":"#ff3b3b"}44`,
            borderRadius:6, background:isIsolated?"rgba(0,229,160,0.1)":"rgba(255,59,59,0.1)",
            color:isIsolated?"#00e5a0":"#ff3b3b",
            padding:"6px 16px", cursor:"pointer", fontSize:12, fontWeight:600,
          }}
        >{busy?"Working…": isIsolated?"Remove Isolation":"Isolate Endpoint"}</button>
      ) : (
        <div style={{ display:"flex", gap:8 }}>
          <button onClick={trigger} style={{ border:"none", borderRadius:6, background:isIsolated?"#00e5a0":"#ff3b3b", color:"white", padding:"5px 12px", cursor:"pointer", fontSize:11, fontWeight:700 }}>Confirm</button>
          <button onClick={()=>setConfirm(false)} style={{ border:BORDER, borderRadius:6, background:"transparent", color:"#888", padding:"5px 12px", cursor:"pointer", fontSize:11 }}>Cancel</button>
        </div>
      )}
      <div style={{ fontSize:10, color:"#555" }}>
        {agent.isolation_state === "pending_isolation" && "⏳ Isolation queued — awaiting agent acknowledgement"}
        {agent.isolation_state === "pending_unisolation" && "⏳ Unisolation queued — awaiting agent acknowledgement"}
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function EdrEndpointDetailPage({ agentId }) {
  const [agent,      setAgent]      = useState(null);
  const [detections, setDetections] = useState([]);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState(null);
  const [activeTab,  setActiveTab]  = useState("timeline");

  const load = useCallback(async () => {
    if (!agentId) return;
    setLoading(true); setError(null);
    try {
      const [agRes, detRes] = await Promise.all([
        fetch(`/api/edr/agents/${agentId}`),
        fetch(`/api/edr/detections?agent_id=${agentId}&limit=50`),
      ]);
      if (!agRes.ok) throw new Error(`Agent not found (${agRes.status})`);
      const agData = await agRes.json();
      setAgent(agData.agent || agData);
      if (detRes.ok) {
        const detData = await detRes.json();
        setDetections(detData.detections || []);
      }
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }, [agentId]);

  useEffect(() => { load(); }, [load]);

  if (!agentId) {
    return (
      <div style={{ padding:"28px 32px", minHeight:"100vh", background:BG, display:"flex", alignItems:"center", justifyContent:"center" }}>
        <div style={{ textAlign:"center", color:"#555" }}>
          <div style={{ fontSize:40, marginBottom:12 }}>🖥️</div>
          <div style={{ fontSize:14 }}>Select an endpoint from the Fleet view to see details.</div>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div style={{ padding:"28px 32px", minHeight:"100vh", background:BG, display:"flex", alignItems:"center", justifyContent:"center" }}>
        <div style={{ color:"#555", fontSize:13 }}>Loading endpoint data…</div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding:"28px 32px", minHeight:"100vh", background:BG }}>
        <div style={{ background:"#ff3b3b22", border:"1px solid #ff3b3b44", borderRadius:8, padding:"14px 18px", color:"#ff7070" }}>{error}</div>
      </div>
    );
  }

  const a = agent;
  const isoColor = ISOLATION_COLOR[a.isolation_state] || "#888";
  const commands = a.commands || [];
  const osIcon   = OS_ICON[a.os_type] || "🖥️";

  const criticalCount = detections.filter(d => d.severity === "critical").length;
  const highCount     = detections.filter(d => d.severity === "high").length;
  const openCount     = detections.filter(d => d.status === "open").length;

  const TABS = [
    { id:"timeline", label:"Forensic Timeline" },
    { id:"commands", label:`Response Commands (${commands.length})` },
    { id:"policies", label:"Applied Policies" },
  ];

  return (
    <div style={{ padding:"28px 32px", minHeight:"100vh", background:BG }}>
      {/* ── Header ── */}
      <div style={{ display:"flex", alignItems:"flex-start", gap:16, marginBottom:24, flexWrap:"wrap" }}>
        <div style={{ fontSize:36 }}>{osIcon}</div>
        <div style={{ flex:1, minWidth:200 }}>
          <div style={{ display:"flex", alignItems:"center", gap:10, flexWrap:"wrap" }}>
            <h1 style={{ margin:0, fontSize:22, fontWeight:800, color:"#e8eaf0" }}>{a.hostname}</h1>
            <Badge label={a.isolation_state?.replace("_"," ").toUpperCase()} color={isoColor}/>
            <Badge label={a.status?.toUpperCase()} color={a.status==="active"?"#00e5a0":"#555"}/>
          </div>
          <div style={{ fontSize:12, color:"#555", marginTop:4, display:"flex", gap:16, flexWrap:"wrap" }}>
            <span>{a.os_type} · {a.os_version}</span>
            <span>{a.ip_address}</span>
            <span>{a.asset_type}</span>
            <span style={{ fontFamily:"monospace" }}>ID: {a.agent_id}</span>
          </div>
          <div style={{ fontSize:11, color:"#444", marginTop:4 }}>
            Last seen: {a.last_heartbeat ? new Date(a.last_heartbeat).toLocaleString() : "never"} ·
            Enrolled: {a.enrolled_at ? new Date(a.enrolled_at).toLocaleDateString() : "—"}
            {a.enrolled_by && ` by ${a.enrolled_by}`}
          </div>
        </div>
        <IsolationControls agent={a} onRefresh={load} />
      </div>

      {/* ── Stats ── */}
      <div style={{
        background:CARD_BG, border:BORDER, borderRadius:12, padding:"16px 24px",
        display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(100px,1fr))", gap:20, marginBottom:24,
      }}>
        <Stat label="Total Detections" value={detections.length}/>
        <Stat label="Critical" value={criticalCount} color={criticalCount>0?"#ff3b3b":undefined}/>
        <Stat label="High" value={highCount} color={highCount>0?"#ff8c00":undefined}/>
        <Stat label="Open" value={openCount} color={openCount>0?"#f5c518":undefined}/>
        <Stat label="Commands Issued" value={commands.length}/>
        <Stat label="EDR Version" value={a.agent_version||"—"}/>
      </div>

      {/* ── Metadata card ── */}
      <div style={{ background:CARD_BG, border:BORDER, borderRadius:12, padding:"16px 24px", marginBottom:24 }}>
        <SectionTitle>ENDPOINT METADATA</SectionTitle>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(180px,1fr))", gap:16 }}>
          {[
            ["Hostname", a.hostname],
            ["IP Address", a.ip_address],
            ["OS Type", a.os_type],
            ["OS Version", a.os_version],
            ["Asset Type", a.asset_type],
            ["Domain", a.domain||"—"],
            ["Agent Version", a.agent_version||"—"],
            ["Isolation State", a.isolation_state?.replace("_"," ")],
            ["Status", a.status],
            ["Enrollment Token", a.enrollment_token ? `${a.enrollment_token.slice(0,8)}…` : "—"],
          ].map(([label, val]) => (
            <div key={label}>
              <div style={{ fontSize:10, color:"#555", marginBottom:3 }}>{label}</div>
              <div style={{ fontSize:12, color:"#e8eaf0", fontWeight:600 }}>{val||"—"}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Tabs ── */}
      <div style={{ display:"flex", gap:0, marginBottom:20, borderBottom:BORDER }}>
        {TABS.map(tab => (
          <button key={tab.id} onClick={()=>setActiveTab(tab.id)} style={{
            border:"none", borderBottom:activeTab===tab.id?`2px solid ${ACCENT}`:"2px solid transparent",
            background:"transparent", color:activeTab===tab.id?ACCENT:"#666",
            padding:"8px 18px", cursor:"pointer", fontSize:12, fontWeight:activeTab===tab.id?700:400,
            transition:"all 0.15s",
          }}>{tab.label}</button>
        ))}
      </div>

      {activeTab === "timeline" && (
        <div>
          <div style={{ fontSize:11, color:"#555", marginBottom:14 }}>
            Showing {Math.min(detections.length, 30)} most recent events (newest first)
          </div>
          <ForensicTimeline detections={detections} />
        </div>
      )}

      {activeTab === "commands" && <CommandList commands={commands} />}

      {activeTab === "policies" && <AppliedPolicies agentId={agentId} />}
    </div>
  );
}
