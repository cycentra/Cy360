/**
 * pages/edr/EdrAgentInstallerPage.jsx
 * CyEDR Agent Deployment & Enrollment Console
 *
 * Lets admins generate deployment tokens, select target OS + architecture,
 * copy the correct arch-specific install command, and manage self-enrollment.
 */
import React, { useEffect, useState, useCallback } from "react";
import { WindowsLogo, AppleLogo, LinuxLogo, CyCentraEDRBadge } from "../../components/OsLogo.jsx";

const BG      = "#0a0e1a";
const CARD_BG = "rgba(255,255,255,0.03)";
const BORDER  = "1px solid rgba(255,255,255,0.07)";
const ACCENT  = "#00e5a0";

// ── OS configuration with official logo components ─────────────────────────
const OS_CFG = {
  windows: {
    label:  "Windows",
    color:  "#00a4ef",
    Logo:   () => <WindowsLogo size={20} />,
    archs:  ["x64", "arm64"],
    archLabels: { x64: "x64 (Intel/AMD)", arm64: "ARM64 (Qualcomm/Surface)" },
  },
  linux: {
    label:  "Linux",
    color:  "#fcc624",
    Logo:   () => <LinuxLogo size={20} />,
    archs:  ["amd64", "arm64", "x86_64-rpm", "aarch64-rpm"],
    archLabels: {
      "amd64":       "amd64 DEB (Ubuntu/Debian)",
      "arm64":       "arm64 DEB (Ubuntu ARM)",
      "x86_64-rpm":  "x86_64 RPM (RHEL/CentOS)",
      "aarch64-rpm": "aarch64 RPM (RHEL ARM)",
    },
  },
  macos: {
    label:  "macOS",
    color:  "#b0b8c8",
    Logo:   () => <AppleLogo size={20} color="#b0b8c8" />,
    archs:  ["intel", "apple_silicon"],
    archLabels: { intel: "Intel (x86_64)", apple_silicon: "Apple Silicon (M1/M2/M3)" },
  },
};

// ── Copy box ───────────────────────────────────────────────────────────────
function CopyBox({ value, label }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <div style={{ marginBottom: 12 }}>
      {label && <div style={{ fontSize: 11, color: "#555", marginBottom: 5 }}>{label}</div>}
      <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
        <code style={{
          flex: 1, background: "rgba(0,0,0,0.4)", border: BORDER, borderRadius: 7,
          padding: "10px 14px", fontSize: 11, color: "#a8e6cf", fontFamily: "monospace",
          wordBreak: "break-all", lineHeight: 1.6, display: "block", whiteSpace: "pre-wrap",
        }}>{value}</code>
        <button onClick={copy} style={{
          border: `1px solid ${copied ? ACCENT : "#333"}44`, borderRadius: 6,
          background: copied ? `${ACCENT}22` : "transparent",
          color: copied ? ACCENT : "#666",
          padding: "6px 12px", fontSize: 11, cursor: "pointer",
          whiteSpace: "nowrap", transition: "all 0.2s", flexShrink: 0, marginTop: 2,
        }}>{copied ? "✓ Copied" : "Copy"}</button>
      </div>
    </div>
  );
}

// ── Token card ─────────────────────────────────────────────────────────────
function TokenCard({ token, onRevoke }) {
  const isExpired  = token.expires_at && new Date(token.expires_at) < new Date();
  const statusColor = token.revoked ? "#ff3b3b" : isExpired ? "#ff8c00" : "#00e5a0";
  const statusLabel = token.revoked ? "Revoked" : isExpired ? "Expired" : "Active";
  const usageText   = token.max_uses > 0
    ? `${token.used_count}/${token.max_uses} uses`
    : `${token.used_count} uses (unlimited)`;

  return (
    <div style={{
      background: CARD_BG, border: BORDER, borderRadius: 10, padding: "16px 20px",
      borderLeft: `3px solid ${statusColor}`,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{ fontWeight: 700, color: "#e8eaf0", fontSize: 14 }}>
            {token.label || "Deployment Token"}
          </div>
          <div style={{ fontSize: 11, color: "#666", marginTop: 3 }}>
            {token.os_type !== "any" ? `${token.os_type} only · ` : ""}{usageText}
            {token.expires_at ? ` · Expires ${new Date(token.expires_at).toLocaleDateString()}` : " · No expiry"}
          </div>
          <div style={{ fontSize: 11, color: "#444", marginTop: 2 }}>
            Created by {token.created_by} · {new Date(token.created_at).toLocaleString()}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <span style={{
            fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 4,
            color: statusColor, background: `${statusColor}22`,
          }}>{statusLabel}</span>
          {!token.revoked && (
            <button onClick={() => onRevoke(token.id)} style={{
              border: "1px solid #ff3b3b44", borderRadius: 5,
              background: "transparent", color: "#ff3b3b",
              padding: "3px 10px", fontSize: 11, cursor: "pointer",
            }}>Revoke</button>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Create token modal ─────────────────────────────────────────────────────
function CreateTokenModal({ onClose, onCreate }) {
  const [label,   setLabel]   = useState("Production deployment");
  const [osType,  setOsType]  = useState("any");
  const [maxUses, setMaxUses] = useState(0);
  const [expires, setExpires] = useState(0);
  const [busy,    setBusy]    = useState(false);
  const [err,     setErr]     = useState("");

  const submit = async () => {
    setBusy(true); setErr("");
    try {
      const res = await fetch("/api/edr/installer/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label, os_type: osType, max_uses: maxUses, expires_hours: expires }),
      });
      if (!res.ok) throw new Error((await res.json()).error || res.status);
      const tok = await res.json();
      onCreate(tok);
      onClose();
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  const inp = {
    background: "rgba(255,255,255,0.05)", border: BORDER, borderRadius: 6,
    color: "#e8eaf0", padding: "7px 12px", fontSize: 12, width: "100%",
    outline: "none", boxSizing: "border-box",
  };

  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.75)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:9999 }}>
      <div style={{ background:"#12182b", border:BORDER, borderRadius:12, padding:28, maxWidth:460, width:"90%" }}>
        <div style={{ fontSize:15, fontWeight:700, color:"#e8eaf0", marginBottom:20 }}>New Deployment Token</div>
        <div style={{ marginBottom:14 }}>
          <label style={{ fontSize:11, color:"#555", display:"block", marginBottom:4 }}>Label</label>
          <input value={label} onChange={e=>setLabel(e.target.value)} style={inp} />
        </div>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:14 }}>
          <div>
            <label style={{ fontSize:11, color:"#555", display:"block", marginBottom:4 }}>OS Restriction</label>
            <select value={osType} onChange={e=>setOsType(e.target.value)} style={{ ...inp, cursor:"pointer" }}>
              <option value="any">Any platform</option>
              <option value="WINDOWS">Windows only</option>
              <option value="LINUX">Linux only</option>
              <option value="MACOS">macOS only</option>
            </select>
          </div>
          <div>
            <label style={{ fontSize:11, color:"#555", display:"block", marginBottom:4 }}>Max Uses (0=unlimited)</label>
            <input type="number" min="0" value={maxUses} onChange={e=>setMaxUses(parseInt(e.target.value)||0)} style={inp} />
          </div>
        </div>
        <div style={{ marginBottom:20 }}>
          <label style={{ fontSize:11, color:"#555", display:"block", marginBottom:4 }}>Expires After (hours, 0=never)</label>
          <input type="number" min="0" value={expires} onChange={e=>setExpires(parseInt(e.target.value)||0)} style={inp} />
        </div>
        {err && <div style={{ color:"#ff7070", fontSize:12, marginBottom:12 }}>{err}</div>}
        <div style={{ display:"flex", gap:10, justifyContent:"flex-end" }}>
          <button onClick={onClose} style={{ border:BORDER, borderRadius:6, background:"transparent", color:"#888", padding:"7px 18px", cursor:"pointer" }}>Cancel</button>
          <button onClick={submit} disabled={busy} style={{ border:"none", borderRadius:6, background:ACCENT, color:"#0a0e1a", fontWeight:700, padding:"7px 18px", cursor:"pointer", opacity:busy?0.6:1 }}>{busy?"Creating…":"Create Token"}</button>
        </div>
      </div>
    </div>
  );
}

// ── Arch pill selector ─────────────────────────────────────────────────────
function ArchSelector({ archs, archLabels, selected, onChange, color }) {
  return (
    <div style={{ display:"flex", gap:6, flexWrap:"wrap", marginBottom:14 }}>
      {archs.map(arch => (
        <button key={arch} onClick={() => onChange(arch)} style={{
          border: `1px solid ${selected===arch ? color : "#333"}`,
          borderRadius: 6,
          background: selected===arch ? `${color}22` : "transparent",
          color: selected===arch ? color : "#555",
          padding: "4px 12px", fontSize: 11, cursor: "pointer",
          transition: "all 0.15s",
        }}>{archLabels[arch] || arch}</button>
      ))}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────
export default function EdrAgentInstallerPage() {
  const [tokens,       setTokens]       = useState([]);
  const [loading,      setLoading]      = useState(true);
  const [showCreate,   setShowCreate]   = useState(false);
  const [selectedOs,   setSelectedOs]   = useState("linux");
  const [selectedArch, setSelectedArch] = useState("amd64");
  const [selectedCmd,  setSelectedCmd]  = useState("bash");
  const [activeToken,  setActiveToken]  = useState(null);
  const [cmds,         setCmds]         = useState(null);
  const [withSiem,     setWithSiem]     = useState(false);
  const [error,        setError]        = useState("");

  const loadTokens = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/edr/installer/token");
      if (!res.ok) throw new Error(res.status);
      const data = await res.json();
      setTokens(data.tokens || []);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadTokens(); }, [loadTokens]);

  const loadCommands = useCallback(async (token) => {
    setActiveToken(token);
    try {
      const res = await fetch(`/api/edr/installer/commands?token=${encodeURIComponent(token)}`);
      if (!res.ok) throw new Error(res.status);
      setCmds(await res.json());
    } catch (e) {
      setError(e.message);
    }
  }, []);

  // When OS changes, reset arch to its first available option
  const handleOsChange = (os) => {
    setSelectedOs(os);
    setSelectedArch(OS_CFG[os].archs[0]);
    setSelectedCmd(Object.keys(cmds?.[os]?.[OS_CFG[os].archs[0]] || {})[0] || "bash");
  };

  const handleRevoke = async (tokId) => {
    if (!confirm("Revoke this deployment token? Agents already enrolled will not be affected.")) return;
    try {
      await fetch(`/api/edr/installer/token/${tokId}/revoke`, { method:"POST" });
      loadTokens();
    } catch (e) {
      setError(e.message);
    }
  };

  const activeTokens = tokens.filter(t => !t.revoked && (!t.expires_at || new Date(t.expires_at) > new Date()));
  const osCfg        = OS_CFG[selectedOs];
  const archCmds     = cmds?.[selectedOs]?.[selectedArch] || {};
  const siemKey      = withSiem ? `${selectedCmd}+siem` : selectedCmd;
  const displayCmd   = archCmds[siemKey] || archCmds[selectedCmd] || "";

  return (
    <div style={{ padding:"28px 32px", minHeight:"100vh", background:BG }}>
      {showCreate && (
        <CreateTokenModal
          onClose={() => setShowCreate(false)}
          onCreate={tok => { loadTokens(); loadCommands(tok.token); }}
        />
      )}

      {/* ── Header with CyCentra brand ── */}
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:28 }}>
        <div style={{ display:"flex", alignItems:"center", gap:20 }}>
          <CyCentraEDRBadge width={180} height={50} />
          <div style={{ borderLeft:"1px solid rgba(255,255,255,0.08)", paddingLeft:20 }}>
            <h1 style={{ margin:0, fontSize:20, fontWeight:800, color:"#e8eaf0", lineHeight:1.2 }}>
              Agent Deployment
            </h1>
            <div style={{ fontSize:11, color:"#555", marginTop:3 }}>
              Generate tokens · Select platform + architecture · Deploy
            </div>
          </div>
        </div>
        <button onClick={() => setShowCreate(true)} style={{
          border:"none", borderRadius:7, background:ACCENT, color:"#0a0e1a",
          fontWeight:700, padding:"9px 20px", cursor:"pointer", fontSize:13,
        }}>+ New Deployment Token</button>
      </div>

      {error && (
        <div style={{ background:"#ff3b3b22", border:"1px solid #ff3b3b44", borderRadius:8, padding:"12px 16px", color:"#ff7070", fontSize:13, marginBottom:16 }}>{error}</div>
      )}

      {/* ── Quick Deploy ── */}
      <div style={{ background:CARD_BG, border:BORDER, borderRadius:12, padding:"20px 24px", marginBottom:28 }}>
        <div style={{ fontSize:13, fontWeight:700, color:"#e8eaf0", marginBottom:16 }}>Quick Deploy</div>

        {/* Token selector */}
        <div style={{ marginBottom:16 }}>
          <div style={{ fontSize:10, color:"#555", marginBottom:6, letterSpacing:1 }}>DEPLOYMENT TOKEN</div>
          <select
            value={activeToken || ""}
            onChange={e => { setActiveToken(e.target.value); if(e.target.value) loadCommands(e.target.value); }}
            style={{ background:"rgba(255,255,255,0.05)", border:BORDER, borderRadius:6, color:"#e8eaf0", padding:"7px 12px", fontSize:12, minWidth:260 }}
          >
            <option value="">Select deployment token…</option>
            {activeTokens.map(t => (
              <option key={t.id} value={t.token}>{t.label} ({t.used_count} uses)</option>
            ))}
          </select>
        </div>

        {/* OS tabs with official logos */}
        <div style={{ marginBottom:16 }}>
          <div style={{ fontSize:10, color:"#555", marginBottom:8, letterSpacing:1 }}>TARGET PLATFORM</div>
          <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
            {Object.entries(OS_CFG).map(([os, cfg]) => {
              const { Logo } = cfg;
              const active = selectedOs === os;
              return (
                <button
                  key={os}
                  onClick={() => handleOsChange(os)}
                  style={{
                    border: `1px solid ${active ? cfg.color : "rgba(255,255,255,0.08)"}`,
                    borderRadius: 8,
                    background: active ? `${cfg.color}18` : "transparent",
                    color: active ? cfg.color : "#555",
                    padding: "8px 18px",
                    fontSize: 12, fontWeight: 600, cursor: "pointer",
                    display: "flex", alignItems: "center", gap: 8,
                    transition: "all 0.15s",
                    boxShadow: active ? `0 0 0 1px ${cfg.color}44` : "none",
                  }}
                >
                  <Logo />
                  {cfg.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Architecture selector */}
        <div style={{ marginBottom:16 }}>
          <div style={{ fontSize:10, color:"#555", marginBottom:8, letterSpacing:1 }}>
            ARCHITECTURE — <span style={{ color: osCfg.color }}>{osCfg.label}</span>
          </div>
          <ArchSelector
            archs={osCfg.archs}
            archLabels={osCfg.archLabels}
            selected={selectedArch}
            onChange={arch => {
              setSelectedArch(arch);
              setSelectedCmd(Object.keys(cmds?.[selectedOs]?.[arch] || {})[0] || "bash");
            }}
            color={osCfg.color}
          />
        </div>

        {/* CySIEM toggle */}
        <div style={{
          display:"flex", alignItems:"center", gap:10, marginBottom:16,
          background:"rgba(0,229,160,0.04)", border:"1px solid rgba(0,229,160,0.12)",
          borderRadius:8, padding:"10px 14px",
        }}>
          <div style={{ flex:1 }}>
            <div style={{ fontSize:12, fontWeight:700, color:"#e8eaf0" }}>
              Include CySIEM (Wazuh) agent
            </div>
            <div style={{ fontSize:11, color:"#555", marginTop:2 }}>
              Adds FIM, auth log collection, and compliance aggregation alongside CyEDR
            </div>
          </div>
          <button
            onClick={() => setWithSiem(v => !v)}
            style={{
              border: `1px solid ${withSiem ? ACCENT : "#444"}`,
              borderRadius: 20,
              background: withSiem ? `${ACCENT}22` : "transparent",
              color: withSiem ? ACCENT : "#555",
              padding: "5px 16px", fontSize: 11, fontWeight: 600, cursor: "pointer",
              transition: "all 0.2s", whiteSpace: "nowrap",
            }}
          >{withSiem ? "✓ Included" : "Optional"}</button>
        </div>

        {/* Install command */}
        {cmds && activeToken ? (
          <>
            {/* Method tabs */}
            <div style={{ display:"flex", gap:6, marginBottom:10 }}>
              {Object.keys(archCmds).filter(k => !k.includes("+siem")).map(method => (
                <button key={method} onClick={() => setSelectedCmd(method)} style={{
                  border: `1px solid ${selectedCmd===method ? ACCENT : "#333"}44`,
                  borderRadius: 5,
                  background: selectedCmd===method ? `${ACCENT}22` : "transparent",
                  color: selectedCmd===method ? ACCENT : "#555",
                  padding: "4px 12px", fontSize: 11, cursor: "pointer",
                }}>{method}</button>
              ))}
            </div>
            {displayCmd && (
              <CopyBox
                value={displayCmd}
                label={`${osCfg.label} ${osCfg.archLabels[selectedArch]} — ${selectedCmd}${withSiem ? " + CySIEM" : ""}`}
              />
            )}
            {withSiem && (
              <div style={{ fontSize:11, color: ACCENT, marginTop:4 }}>
                <code style={{ fontFamily:"monospace" }}>--with-cysiem</code> flag active — Wazuh agent will also be installed
              </div>
            )}
            <div style={{ fontSize:11, color:"#444", marginTop:8 }}>
              Platform URL: <code style={{ color:"#7090b0", fontFamily:"monospace" }}>{cmds.collector_url}</code>
            </div>
          </>
        ) : (
          <div style={{ fontSize:12, color:"#444", padding:"12px 0" }}>
            Select a deployment token above to generate the install command for your target platform and architecture.
          </div>
        )}
      </div>

      {/* ── Deployment flow steps ── */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(180px, 1fr))", gap:12, marginBottom:28 }}>
        {[
          { step:"1", title:"Install Agent",    desc:"cyedr-install.sh / .ps1 runs on endpoint",         color:"#4d9eff" },
          { step:"2", title:"Self-Enroll",       desc:"Agent POSTs to /api/edr/agents/self-enroll",       color:ACCENT    },
          { step:"3", title:"Receive Policies",  desc:"Platform pushes policy via APPLY_POLICY command",  color:"#b06eff" },
          { step:"4", title:"Stream Telemetry",  desc:"Agent sends behavioral events → SIEM pipeline",    color:"#f5c518" },
          { step:"5", title:"Respond",           desc:"Platform issues containment commands via poll",     color:"#ff8c00" },
        ].map(s => (
          <div key={s.step} style={{ background:CARD_BG, border:BORDER, borderRadius:10, padding:"14px 16px", borderLeft:`3px solid ${s.color}` }}>
            <div style={{ fontSize:10, color:s.color, fontWeight:700, marginBottom:4 }}>STEP {s.step}</div>
            <div style={{ fontSize:13, fontWeight:700, color:"#e8eaf0", marginBottom:4 }}>{s.title}</div>
            <div style={{ fontSize:11, color:"#555" }}>{s.desc}</div>
          </div>
        ))}
      </div>

      {/* ── Package availability matrix ── */}
      <div style={{ background:CARD_BG, border:BORDER, borderRadius:12, padding:"20px 24px", marginBottom:28 }}>
        <div style={{ fontSize:13, fontWeight:700, color:"#e8eaf0", marginBottom:14 }}>
          Agent Package Matrix
        </div>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(3, 1fr)", gap:10 }}>
          {[
            { Logo: () => <WindowsLogo size={16}/>, label:"Windows x64",        pkg:"cyedr-agent-x64.msi",         color:"#00a4ef" },
            { Logo: () => <WindowsLogo size={16}/>, label:"Windows ARM64",       pkg:"cyedr-agent-arm64.msi",       color:"#00a4ef" },
            { Logo: () => <LinuxLogo size={16}/>,   label:"Ubuntu/Debian amd64", pkg:"cyedr-agent-amd64.deb",       color:"#fcc624" },
            { Logo: () => <LinuxLogo size={16}/>,   label:"Ubuntu/Debian arm64", pkg:"cyedr-agent-arm64.deb",       color:"#fcc624" },
            { Logo: () => <LinuxLogo size={16}/>,   label:"RHEL/CentOS x86_64",  pkg:"cyedr-agent-x86_64.rpm",      color:"#fcc624" },
            { Logo: () => <LinuxLogo size={16}/>,   label:"RHEL/CentOS aarch64", pkg:"cyedr-agent-aarch64.rpm",     color:"#fcc624" },
            { Logo: () => <AppleLogo size={16} color="#b0b8c8"/>, label:"macOS Intel",  pkg:"cyedr-agent-intel64.pkg",     color:"#b0b8c8" },
            { Logo: () => <AppleLogo size={16} color="#b0b8c8"/>, label:"macOS Apple Silicon", pkg:"cyedr-agent-arm64.pkg", color:"#b0b8c8" },
          ].map(p => (
            <div key={p.pkg} style={{
              display:"flex", alignItems:"center", gap:8, padding:"8px 12px",
              background:"rgba(255,255,255,0.02)", borderRadius:6,
              border:`1px solid rgba(255,255,255,0.05)`,
            }}>
              <p.Logo />
              <div>
                <div style={{ fontSize:11, fontWeight:600, color:"#b0b8c8" }}>{p.label}</div>
                <div style={{ fontSize:10, color:"#444", fontFamily:"monospace" }}>{p.pkg}</div>
              </div>
            </div>
          ))}
        </div>
        <div style={{ fontSize:11, color:"#444", marginTop:12 }}>
          All packages are standalone executables (PyInstaller). No Python required on endpoints.
          Built via <code style={{ fontFamily:"monospace", color:"#666" }}>agent-packages/build-edr-packages.sh</code>
        </div>
      </div>

      {/* ── Token list ── */}
      <div style={{ fontSize:13, fontWeight:700, color:"#e8eaf0", marginBottom:14 }}>Deployment Tokens</div>
      {loading ? (
        <div style={{ textAlign:"center", color:"#555", padding:30, fontSize:13 }}>Loading tokens…</div>
      ) : tokens.length === 0 ? (
        <div style={{ textAlign:"center", color:"#555", padding:40, fontSize:13 }}>
          No deployment tokens yet. Create one to start deploying agents.
        </div>
      ) : (
        <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
          {tokens.map(t => <TokenCard key={t.id} token={t} onRevoke={handleRevoke} />)}
        </div>
      )}

      {/* ── Manual enrollment ── */}
      <div style={{ background:CARD_BG, border:BORDER, borderRadius:10, padding:"16px 20px", marginTop:24 }}>
        <div style={{ fontSize:12, fontWeight:700, color:"#e8eaf0", marginBottom:8 }}>Manual Enrollment (API)</div>
        <div style={{ fontSize:11, color:"#555", marginBottom:8 }}>
          Admins can enroll agents directly via REST without a deployment token:
        </div>
        <CopyBox value={`curl -X POST https://cy360.{domain}/api/edr/agents/enroll \\
  -H "Cookie: session=<admin-session>" \\
  -H "Content-Type: application/json" \\
  -d '{"hostname":"WIN-DC01","os_type":"WINDOWS","asset_type":"domain_controller"}'`} />
      </div>
    </div>
  );
}
