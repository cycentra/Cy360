/**
 * pages/edr/EdrAgentInstallerPage.jsx
 * CyEDR Agent Deployment & Enrollment Console
 *
 * Lets admins generate deployment tokens, select target OS, and copy a
 * one-line install command that auto-detects CPU architecture on the
 * endpoint. Native packages (DEB/RPM/PKG/MSI) are arch-specific by nature
 * of the OS package manager, so they live under an optional Advanced
 * section for anyone who explicitly needs a package file instead.
 */
import React, { useEffect, useState, useCallback } from "react";
import { WindowsLogo, AppleLogo, LinuxLogo, CyCentraEDRBadge } from "../../components/OsLogo.jsx";

const BG      = "#0a0e1a";
const CARD_BG = "rgba(255,255,255,0.03)";
const BORDER  = "1px solid rgba(255,255,255,0.07)";
const ACCENT  = "#00e5a0";

// ── OS configuration with official logo components ─────────────────────────
// scriptMethod/scriptArch: the one-line installer is architecture-transparent
// (cyedr-install.sh / cyedr-install.ps1 both self-detect CPU arch on the
// endpoint), so any arch bucket returns the same command — scriptArch just
// picks which bucket to read it from. archs/archLabels are only used by the
// Advanced (native package) section below, since DEB/RPM/PKG/MSI are
// genuinely arch-specific artifacts.
const OS_CFG = {
  windows: {
    label:  "Windows",
    color:  "#00a4ef",
    Logo:   () => <WindowsLogo size={20} />,
    scriptMethod: "powershell",
    scriptArch:   "x64",
    archs:  ["x64", "arm64"],
    archLabels: { x64: "x64 (Intel/AMD)", arm64: "ARM64 (Qualcomm/Surface)" },
  },
  linux: {
    label:  "Linux",
    color:  "#fcc624",
    Logo:   () => <LinuxLogo size={20} />,
    scriptMethod: "bash",
    scriptArch:   "amd64",
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
    scriptMethod: "bash",
    scriptArch:   "intel",
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
  const tokenPreview = token.token ? `${token.token.slice(0, 8)}…${token.token.slice(-4)}` : "••••••••";
  const copyToken = () => {
    if (token.token) navigator.clipboard.writeText(token.token).catch(() => {});
  };

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
          {!token.revoked && token.token && (
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 6 }}>
              <code style={{ fontSize: 11, color: "#888", background: "rgba(255,255,255,0.04)", padding: "2px 7px", borderRadius: 4, letterSpacing: "0.03em" }}>
                {tokenPreview}
              </code>
              <button onClick={copyToken} style={{ border: "1px solid #333", borderRadius: 4, background: "transparent", color: "#00e5a0", fontSize: 10, padding: "2px 8px", cursor: "pointer" }}>
                Copy value
              </button>
            </div>
          )}
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
  const [label,     setLabel]     = useState("Production deployment");
  const [osType,    setOsType]    = useState("any");
  const [maxUses,   setMaxUses]   = useState(0);
  const [expires,   setExpires]   = useState(0);
  const [busy,      setBusy]      = useState(false);
  const [err,       setErr]       = useState("");
  const [createdTok, setCreatedTok] = useState(null);

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
      setCreatedTok(tok);
      onCreate(tok);
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  if (createdTok) {
    return (
      <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.75)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:9999 }}>
        <div style={{ background:"#12182b", border:"1px solid #00e5a066", borderRadius:12, padding:28, maxWidth:520, width:"90%" }}>
          <div style={{ fontSize:15, fontWeight:700, color:"#00e5a0", marginBottom:8 }}>Token Created</div>
          <div style={{ fontSize:12, color:"#888", marginBottom:16 }}>Copy this token value now — it is the secret used in install commands. The portal shows only the first/last characters afterwards.</div>
          <div style={{ background:"rgba(0,229,160,0.06)", border:"1px solid #00e5a033", borderRadius:8, padding:"12px 16px", marginBottom:16 }}>
            <div style={{ fontSize:10, color:"#555", marginBottom:6, letterSpacing:1 }}>TOKEN VALUE — COPY NOW</div>
            <code style={{ fontSize:13, color:"#00e5a0", wordBreak:"break-all", lineHeight:1.6 }}>{createdTok.token}</code>
          </div>
          <button onClick={() => navigator.clipboard.writeText(createdTok.token).catch(()=>{})} style={{ border:"none", borderRadius:6, background:"#00e5a0", color:"#0a0e1a", fontWeight:700, padding:"7px 18px", cursor:"pointer", width:"100%", marginBottom:10 }}>
            Copy Token Value
          </button>
          <button onClick={onClose} style={{ border:"1px solid #333", borderRadius:6, background:"transparent", color:"#888", padding:"7px 18px", cursor:"pointer", width:"100%" }}>
            Done
          </button>
        </div>
      </div>
    );
  }

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

// ── Uninstall tab ────────────────────────────────────────────────────────
// Force-uninstall doesn't need a deployment token or per-arch commands — the
// uninstall scripts are architecture-transparent and never enroll/talk to
// the platform, they only clean up local endpoint state.
function UninstallTab() {
  const [selectedOs, setSelectedOs] = useState("linux");
  const [cmds,        setCmds]      = useState(null);
  const [error,       setError]     = useState("");
  const [loading,     setLoading]   = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch("/api/edr/installer/uninstall-commands");
        if (!res.ok) throw new Error(res.status);
        setCmds(await res.json());
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const osCfg = OS_CFG[selectedOs];
  const method = osCfg.scriptMethod;
  const cmd    = cmds?.[selectedOs]?.[method] || "";

  return (
    <div style={{ background:CARD_BG, border:BORDER, borderRadius:12, padding:"20px 24px", marginBottom:28 }}>
      <div style={{ fontSize:13, fontWeight:700, color:"#e8eaf0", marginBottom:8 }}>Force Uninstall</div>
      <div style={{
        background:"#ff3b3b12", border:"1px solid #ff3b3b44", borderRadius:8,
        padding:"12px 16px", marginBottom:18, fontSize:12, color:"#ff9090", lineHeight:1.6,
      }}>
        <strong>Destructive and irreversible on the target endpoint.</strong> This stops and
        removes the CyEDR agent service, system tray, watchdog, auditd rules (Linux),
        Sysmon + PowerShell logging policy (Windows), and every file/directory CyEDR
        created — so the host is fully clean before a new install. Local logs and
        quarantined files are deleted. Past detections/alerts already stored on the
        platform are not affected. Run this only on the endpoint you intend to clean,
        immediately followed by a fresh install if you're re-enrolling it.
      </div>

      {error && (
        <div style={{ background:"#ff3b3b22", border:"1px solid #ff3b3b44", borderRadius:8, padding:"12px 16px", color:"#ff7070", fontSize:13, marginBottom:16 }}>{error}</div>
      )}

      <div style={{ marginBottom:16 }}>
        <div style={{ fontSize:10, color:"#555", marginBottom:8, letterSpacing:1 }}>TARGET PLATFORM</div>
        <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
          {Object.entries(OS_CFG).map(([os, cfg]) => {
            const { Logo } = cfg;
            const active = selectedOs === os;
            return (
              <button
                key={os}
                onClick={() => setSelectedOs(os)}
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

      {loading ? (
        <div style={{ fontSize:12, color:"#444", padding:"12px 0" }}>Loading uninstall command…</div>
      ) : cmd ? (
        <>
          <div style={{ fontSize:10, color:"#555", marginBottom:8, letterSpacing:1 }}>
            UNINSTALL COMMAND — <span style={{ color: osCfg.color }}>{osCfg.label}</span>, run on the endpoint as admin/root
          </div>
          <CopyBox value={cmd} label={`${osCfg.label} — ${method} (force)`} />
        </>
      ) : (
        <div style={{ fontSize:12, color:"#444", padding:"12px 0" }}>
          Uninstall command unavailable — the uninstaller script may not be staged on this platform server yet.
        </div>
      )}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────
export default function EdrAgentInstallerPage() {
  const [mode,         setMode]         = useState("install"); // "install" | "uninstall"
  const [tokens,       setTokens]       = useState([]);
  const [loading,      setLoading]      = useState(true);
  const [showCreate,   setShowCreate]   = useState(false);
  const [selectedOs,   setSelectedOs]   = useState("linux");
  const [selectedArch, setSelectedArch] = useState("amd64");
  const [selectedCmd,  setSelectedCmd]  = useState("deb");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [activeToken,  setActiveToken]  = useState(null);
  const [cmds,         setCmds]         = useState(null);
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

  // When OS changes, reset the advanced arch/method pickers to their first
  // available option (the quick self-detecting command needs no reset).
  const handleOsChange = (os) => {
    setSelectedOs(os);
    const firstArch = OS_CFG[os].archs[0];
    setSelectedArch(firstArch);
    const pkgMethod = Object.keys(cmds?.[os]?.[firstArch] || {})
      .find(k => k !== OS_CFG[os].scriptMethod);
    setSelectedCmd(pkgMethod || "");
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
  const quickCmd      = cmds?.[selectedOs]?.[osCfg.scriptArch]?.[osCfg.scriptMethod] || "";
  const archCmds       = cmds?.[selectedOs]?.[selectedArch] || {};
  const pkgMethods     = Object.keys(archCmds).filter(k => k !== osCfg.scriptMethod);
  const displayCmd     = archCmds[selectedCmd] || "";

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
              Generate tokens · Select platform · Deploy (auto-detects architecture)
            </div>
          </div>
        </div>
        {mode === "install" && (
          <button onClick={() => setShowCreate(true)} style={{
            border:"none", borderRadius:7, background:ACCENT, color:"#0a0e1a",
            fontWeight:700, padding:"9px 20px", cursor:"pointer", fontSize:13,
          }}>+ New Deployment Token</button>
        )}
      </div>

      {/* ── Install / Uninstall tabs ── */}
      <div style={{ display:"flex", gap:0, marginBottom:24, borderBottom:BORDER }}>
        {[
          { id:"install",   label:"Install" },
          { id:"uninstall", label:"Uninstall" },
        ].map(t => (
          <button key={t.id} onClick={() => setMode(t.id)} style={{
            border:"none", background:"transparent", cursor:"pointer",
            padding:"10px 22px", fontSize:13, fontWeight:700,
            color: mode === t.id ? (t.id === "uninstall" ? "#ff3b3b" : ACCENT) : "#555",
            borderBottom: mode === t.id ? `2px solid ${t.id === "uninstall" ? "#ff3b3b" : ACCENT}` : "2px solid transparent",
            marginBottom:-1,
          }}>{t.label}</button>
        ))}
      </div>

      {error && (
        <div style={{ background:"#ff3b3b22", border:"1px solid #ff3b3b44", borderRadius:8, padding:"12px 16px", color:"#ff7070", fontSize:13, marginBottom:16 }}>{error}</div>
      )}

      {mode === "uninstall" ? (
        <UninstallTab />
      ) : (
      <>
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

        {/* Install command — one line, auto-detects CPU architecture on the endpoint */}
        {cmds && activeToken ? (
          <>
            <div style={{ fontSize:10, color:"#555", marginBottom:8, letterSpacing:1 }}>
              INSTALL COMMAND — <span style={{ color: osCfg.color }}>{osCfg.label}</span>, auto-detects architecture
            </div>
            {quickCmd && (
              <CopyBox value={quickCmd} label={`${osCfg.label} — ${osCfg.scriptMethod}`} />
            )}
            <div style={{ fontSize:11, color:"#444", marginTop:8, marginBottom:16 }}>
              Platform URL: <code style={{ color:"#7090b0", fontFamily:"monospace" }}>{cmds.collector_url}</code>
            </div>

            {/* Advanced: native package installers (arch-specific by nature) */}
            <button onClick={() => setShowAdvanced(v => !v)} style={{
              border:"none", background:"transparent", color:"#666", fontSize:11,
              cursor:"pointer", padding:0, display:"flex", alignItems:"center", gap:5,
            }}>
              {showAdvanced ? "▾" : "▸"} Advanced: native package (DEB / RPM / PKG / MSI)
            </button>

            {showAdvanced && (
              <div style={{ marginTop:14, paddingTop:14, borderTop:"1px solid rgba(255,255,255,0.06)" }}>
                <div style={{ fontSize:10, color:"#555", marginBottom:8, letterSpacing:1 }}>
                  ARCHITECTURE — <span style={{ color: osCfg.color }}>{osCfg.label}</span>
                </div>
                <ArchSelector
                  archs={osCfg.archs}
                  archLabels={osCfg.archLabels}
                  selected={selectedArch}
                  onChange={arch => {
                    setSelectedArch(arch);
                    const pkgMethod = Object.keys(cmds?.[selectedOs]?.[arch] || {})
                      .find(k => k !== osCfg.scriptMethod);
                    setSelectedCmd(pkgMethod || "");
                  }}
                  color={osCfg.color}
                />
                {pkgMethods.length > 1 && (
                  <div style={{ display:"flex", gap:6, marginBottom:10 }}>
                    {pkgMethods.map(method => (
                      <button key={method} onClick={() => setSelectedCmd(method)} style={{
                        border: `1px solid ${selectedCmd===method ? ACCENT : "#333"}44`,
                        borderRadius: 5,
                        background: selectedCmd===method ? `${ACCENT}22` : "transparent",
                        color: selectedCmd===method ? ACCENT : "#555",
                        padding: "4px 12px", fontSize: 11, cursor: "pointer",
                      }}>{method}</button>
                    ))}
                  </div>
                )}
                {displayCmd && (
                  <CopyBox
                    value={displayCmd}
                    label={`${osCfg.label} ${osCfg.archLabels[selectedArch]} — ${selectedCmd}`}
                  />
                )}
              </div>
            )}
          </>
        ) : (
          <div style={{ fontSize:12, color:"#444", padding:"12px 0" }}>
            Select a deployment token above to generate the install command for your target platform.
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
      </>
      )}
    </div>
  );
}
