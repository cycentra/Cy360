/**
 * SensorDeploymentTab.jsx
 * CySIEM Agent Manager — download/install/upgrade/uninstall the CySIEM sensor.
 * Extracted from SystemSettingsPage and placed under Host Intelligence.
 */
import { useState, useEffect } from "react";
import { API_BASE } from "../../core/constants.js";

const CARD  = { background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "20px 24px", marginBottom: 20 };
const LABEL = { color: "rgba(255,255,255,0.62)", fontSize: 10, letterSpacing: "1.5px", fontFamily: "monospace", textTransform: "uppercase", marginBottom: 6 };
const BTN   = (color = "#00e5a0") => ({ background: `rgba(${color === "#00e5a0" ? "0,229,160" : "77,158,255"},0.1)`, color, border: `1px solid ${color}40`, padding: "8px 18px", borderRadius: 4, fontFamily: "monospace", fontSize: 11, fontWeight: 700, letterSpacing: "1px", cursor: "pointer", textTransform: "uppercase" });

const PLATFORM_MATRIX = [
  { os: "Linux",   icon: <span style={{ fontSize: 16 }}>🐧</span>, items: ["RPM x86_64 (amd64)", "RPM aarch64 (ARM64)", "DEB amd64", "DEB aarch64 (ARM64)"] },
  { os: "Windows", icon: <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 88 88" width="16" height="16"><path fill="#f25022" d="M0 0h42v42H0z"/><path fill="#7fba00" d="M46 0h42v42H46z"/><path fill="#00a4ef" d="M0 46h42v42H0z"/><path fill="#ffb900" d="M46 46h42v42H46z"/></svg>, items: ["MSI 32-bit", "MSI 64-bit"] },
  { os: "macOS",   icon: <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 814 1000" width="15" height="15" fill="rgba(255,255,255,0.7)"><path d="M788.1 340.9c-5.8 4.5-108.2 62.2-108.2 190.5 0 148.4 130.3 200.9 134.2 202.2-.6 3.2-20.7 71.9-68.7 141.9-42.8 61.6-87.5 123.1-155.5 123.1s-85.5-39.5-164-39.5c-76 0-103.7 40.8-165.9 40.8s-105-37.6-162.2-103c-82.5-95-166.3-243.7-166.3-384.3 0-179.6 116.5-274.7 230.8-274.7 62 0 113.4 40.8 150.7 40.8 35.7 0 92-43.2 161.2-43.2 25.8 0 108.2 2.6 168.9 80.2zm-198.5-160.8c31.1-36.9 53.1-88.1 53.1-139.3 0-7.1-.6-14.3-1.9-20.1-50.6 1.9-110.8 33.7-147.1 75.8-28.5 32.4-55.1 83.6-55.1 135.5 0 7.8 1.3 15.6 1.9 18.1 3.2.6 8.4 1.3 13.6 1.3 45.4 0 102.5-30.4 135.5-71.3z"/></svg>, items: ["Intel (x86_64)", "Apple Silicon (ARM64)"] },
];

export function SensorDeploymentTab() {
  const [pkgInfo,  setPkgInfo]  = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [loadErr,  setLoadErr]  = useState(null);
  const [dlMsg,    setDlMsg]    = useState(null);
  const [pkgList,  setPkgList]  = useState([]);
  const [pruning,  setPruning]  = useState(false);
  const [pruneMsg, setPruneMsg] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/api/system/agent-packages`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setPkgInfo(d); setPkgList(d.packages || []); setLoading(false); })
      .catch(e => { setLoadErr(String(e)); setLoading(false); });
  }, []);

  const handleDownload = (fmt) => {
    setDlMsg({ ok: null, text: "Preparing script…" });
    const url  = `${API_BASE}/api/system/agent-installer?format=${fmt}`;
    const link = document.createElement("a");
    link.href     = url;
    link.download = fmt === "windows" ? "agent-installer.ps1" : "agent-installer.sh";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => setDlMsg({ ok: true,  text: "Download started — check your downloads folder." }), 400);
    setTimeout(() => setDlMsg(null), 4000);
  };

  const serverUrl     = pkgInfo?.server_url     || "—";
  const cySIEMManager = pkgInfo?.cysiem_manager || "—";
  const version       = pkgInfo?.version        || "—";

  const versionGroups = (() => {
    if (!pkgList.length) return [];
    const map = {};
    pkgList.forEach(pkg => {
      const v = pkg.name.match(/(\d+\.\d+\.\d+(?:\.\d+)?)/)?.[1] || "unknown";
      if (!map[v]) map[v] = { version: v, pkgs: [], maxModified: 0 };
      map[v].pkgs.push(pkg);
      if (pkg.modified > map[v].maxModified) map[v].maxModified = pkg.modified;
    });
    return Object.values(map).sort((a, b) => b.maxModified - a.maxModified);
  })();
  const displayGroups   = versionGroups.slice(0, 3);
  const olderGroupCount = Math.max(0, versionGroups.length - 3);

  return (
    <div style={{ maxWidth: 780 }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
        <span style={{ fontSize: 18 }}>📡</span>
        <div style={{ color: "rgba(0,229,160,0.9)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700 }}>
          CySIEM Sensor Deployment
        </div>
        {!loading && version !== "—" && (
          <span style={{ background: "rgba(0,229,160,0.08)", color: "rgba(0,229,160,0.7)", border: "1px solid rgba(0,229,160,0.2)", borderRadius: 4, padding: "2px 8px", fontSize: 10, fontFamily: "monospace" }}>
            v{version}
          </span>
        )}
      </div>
      <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, marginBottom: 16, lineHeight: 1.7 }}>
        Download the Agent Manager script — it auto-detects your OS and architecture.
        If the CySIEM Agent is <strong style={{ color: "rgba(255,255,255,0.5)" }}>not installed</strong>, it installs it.
        If it is <strong style={{ color: "rgba(255,255,255,0.5)" }}>already installed</strong>, it prompts you to upgrade or uninstall.
        Pass <code style={{ color: "rgba(0,229,160,0.7)", fontFamily: "monospace" }}>--uninstall</code> to remove non-interactively.
      </div>

      {/* EDR callout */}
      <div style={{ background: "rgba(0,229,160,0.04)", border: "1px solid rgba(0,229,160,0.2)", borderRadius: 5, padding: "10px 14px", marginBottom: 20, display: "flex", gap: 10, alignItems: "flex-start" }}>
        <span style={{ color: "#00e5a0", fontSize: 15, lineHeight: 1.3 }}>ℹ</span>
        <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, lineHeight: 1.7 }}>
          Deploying <strong style={{ color: "rgba(255,255,255,0.65)" }}>CyEDR</strong> (behavioural detection + automated response)?
          Use <strong style={{ color: "rgba(255,255,255,0.65)" }}>Endpoint Defence → Agent Installer</strong> instead — it installs
          CyEDR and optionally adds the CySIEM Agent in a single run. This page is for CySIEM-only deployments.
        </div>
      </div>

      {/* Server info */}
      <div style={{ ...CARD, marginBottom: 16 }}>
        <div style={{ ...LABEL, marginBottom: 10 }}>Pre-configured Server</div>
        <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
          <div>
            <div style={{ ...LABEL, marginBottom: 3, fontSize: 9 }}>Package Download URL</div>
            <code style={{ color: "#00e5a0", fontFamily: "monospace", fontSize: 12 }}>
              {loading ? "Loading…" : `${serverUrl}/agent-packages/`}
            </code>
          </div>
          <div>
            <div style={{ ...LABEL, marginBottom: 3, fontSize: 9 }}>CySIEM Manager</div>
            <code style={{ color: "#4d9eff", fontFamily: "monospace", fontSize: 12 }}>
              {loading ? "Loading…" : cySIEMManager}
            </code>
          </div>
        </div>
        {loadErr && (
          <div style={{ color: "#ff6b6b", fontSize: 11, fontFamily: "monospace", marginTop: 10 }}>
            ✗ Could not load server info: {loadErr}
          </div>
        )}
      </div>

      {/* Download buttons */}
      <div style={{ ...CARD, marginBottom: 16 }}>
        <div style={{ ...LABEL, marginBottom: 14 }}>Download Agent Manager Script</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>

          {/* Linux + macOS */}
          <div style={{ background: "rgba(0,229,160,0.03)", border: "1px solid rgba(0,229,160,0.12)", borderRadius: 5, padding: "18px 20px" }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 20 }}>🐧</span>
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 814 1000" width="16" height="16" fill="rgba(255,255,255,0.7)"><path d="M788.1 340.9c-5.8 4.5-108.2 62.2-108.2 190.5 0 148.4 130.3 200.9 134.2 202.2-.6 3.2-20.7 71.9-68.7 141.9-42.8 61.6-87.5 123.1-155.5 123.1s-85.5-39.5-164-39.5c-76 0-103.7 40.8-165.9 40.8s-105-37.6-162.2-103c-82.5-95-166.3-243.7-166.3-384.3 0-179.6 116.5-274.7 230.8-274.7 62 0 113.4 40.8 150.7 40.8 35.7 0 92-43.2 161.2-43.2 25.8 0 108.2 2.6 168.9 80.2zm-198.5-160.8c31.1-36.9 53.1-88.1 53.1-139.3 0-7.1-.6-14.3-1.9-20.1-50.6 1.9-110.8 33.7-147.1 75.8-28.5 32.4-55.1 83.6-55.1 135.5 0 7.8 1.3 15.6 1.9 18.1 3.2.6 8.4 1.3 13.6 1.3 45.4 0 102.5-30.4 135.5-71.3z"/></svg>
              <div style={{ color: "#00e5a0", fontSize: 10, letterSpacing: "1.5px", fontFamily: "monospace", fontWeight: 700 }}>
                LINUX / MACOS
              </div>
            </div>
            <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, marginBottom: 14, lineHeight: 1.6 }}>
              Bash script — detects existing agents and prompts install / upgrade / uninstall.
              Supports RPM, DEB, and macOS PKG.
            </div>
            <button onClick={() => handleDownload("unix")} style={{ ...BTN("#00e5a0"), display: "flex", alignItems: "center", gap: 6 }}>
              ↓ Download agent-installer.sh
            </button>
          </div>

          {/* Windows */}
          <div style={{ background: "rgba(77,158,255,0.03)", border: "1px solid rgba(77,158,255,0.12)", borderRadius: 5, padding: "18px 20px" }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 88 88" width="20" height="20"><path fill="#f25022" d="M0 0h42v42H0z"/><path fill="#7fba00" d="M46 0h42v42H46z"/><path fill="#00a4ef" d="M0 46h42v42H0z"/><path fill="#ffb900" d="M46 46h42v42H46z"/></svg>
              <div style={{ color: "#4d9eff", fontSize: 10, letterSpacing: "1.5px", fontFamily: "monospace", fontWeight: 700 }}>
                WINDOWS
              </div>
            </div>
            <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, marginBottom: 14, lineHeight: 1.6 }}>
              PowerShell script — detects existing agents and prompts install / upgrade / uninstall.
              Supports MSI 32-bit and 64-bit.
            </div>
            <button onClick={() => handleDownload("windows")} style={{ ...BTN("#4d9eff"), display: "flex", alignItems: "center", gap: 6 }}>
              ↓ Download agent-installer.ps1
            </button>
          </div>
        </div>

        {dlMsg && (
          <div style={{ color: dlMsg.ok === true ? "#00e5a0" : dlMsg.ok === false ? "#ff6b6b" : "#ffd93d", fontSize: 11, fontFamily: "monospace" }}>
            {dlMsg.ok === true ? "✓" : dlMsg.ok === false ? "✗" : "⋯"} {dlMsg.text}
          </div>
        )}
      </div>

      {/* Quick-start guide */}
      <div style={{ ...CARD, marginBottom: 16 }}>
        <div style={{ ...LABEL, marginBottom: 14 }}>Quick-Start Guide</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {[
            { step: "1", os: "Linux — install / upgrade",   icon: "🐧", cmds: ["chmod +x agent-installer.sh", "sudo ./agent-installer.sh"] },
            { step: "2", os: "macOS — install / upgrade",   icon: <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 814 1000" width="14" height="14" fill="rgba(255,255,255,0.7)"><path d="M788.1 340.9c-5.8 4.5-108.2 62.2-108.2 190.5 0 148.4 130.3 200.9 134.2 202.2-.6 3.2-20.7 71.9-68.7 141.9-42.8 61.6-87.5 123.1-155.5 123.1s-85.5-39.5-164-39.5c-76 0-103.7 40.8-165.9 40.8s-105-37.6-162.2-103c-82.5-95-166.3-243.7-166.3-384.3 0-179.6 116.5-274.7 230.8-274.7 62 0 113.4 40.8 150.7 40.8 35.7 0 92-43.2 161.2-43.2 25.8 0 108.2 2.6 168.9 80.2zm-198.5-160.8c31.1-36.9 53.1-88.1 53.1-139.3 0-7.1-.6-14.3-1.9-20.1-50.6 1.9-110.8 33.7-147.1 75.8-28.5 32.4-55.1 83.6-55.1 135.5 0 7.8 1.3 15.6 1.9 18.1 3.2.6 8.4 1.3 13.6 1.3 45.4 0 102.5-30.4 135.5-71.3z"/></svg>, cmds: ["chmod +x agent-installer.sh", "sudo ./agent-installer.sh"] },
            { step: "3", os: "Windows — install / upgrade", icon: <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 88 88" width="14" height="14"><path fill="#f25022" d="M0 0h42v42H0z"/><path fill="#7fba00" d="M46 0h42v42H46z"/><path fill="#00a4ef" d="M0 46h42v42H0z"/><path fill="#ffb900" d="M46 46h42v42H46z"/></svg>, cmds: ["Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force", ".\\agent-installer.ps1"] },
          ].map(({ step, os, icon, cmds }) => (
            <div key={step} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 4, padding: "12px 14px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                <span>{icon}</span>
                <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{os}</span>
              </div>
              {cmds.map((cmd, i) => (
                <pre key={i} style={{ background: "rgba(0,0,0,0.3)", borderRadius: 3, padding: "6px 10px", fontFamily: "monospace", fontSize: 11, color: "rgba(255,255,255,0.65)", margin: i < cmds.length - 1 ? "0 0 4px 0" : 0, overflowX: "auto" }}>{cmd}</pre>
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* Uninstall reference */}
      <div style={{ ...CARD, marginBottom: 16, borderColor: "rgba(255,107,107,0.15)" }}>
        <div style={{ ...LABEL, marginBottom: 10, color: "rgba(255,107,107,0.75)" }}>Remove Agents (Non-interactive)</div>
        <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, marginBottom: 14, lineHeight: 1.7 }}>
          The same script handles removal. Run interactively and choose <em>Uninstall</em>, or pass a flag to skip prompts.
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          {[
            { title: "Linux / macOS", color: "rgba(255,107,107,0.7)", lines: [
              "# Remove CySIEM Agent only",
              "sudo bash agent-installer.sh --uninstall-cysiem",
              "",
              "# Remove CyEDR Agent only",
              "sudo bash agent-installer.sh --uninstall-cyedr",
              "",
              "# Remove all CyCentra agents",
              "sudo bash agent-installer.sh --uninstall",
            ]},
            { title: "Windows (PowerShell)", color: "rgba(255,107,107,0.7)", lines: [
              "# Remove CySIEM Agent only",
              ".\\agent-installer.ps1 -Action uninstall-cysiem",
              "",
              "# Remove CyEDR Agent only",
              ".\\agent-installer.ps1 -Action uninstall-cyedr",
              "",
              "# Remove all CyCentra agents",
              ".\\agent-installer.ps1 -Action uninstall",
            ]},
          ].map(({ title, color, lines }) => (
            <div key={title} style={{ background: "rgba(255,107,107,0.03)", border: "1px solid rgba(255,107,107,0.1)", borderRadius: 4, padding: "12px 14px" }}>
              <div style={{ color, fontSize: 9, fontFamily: "monospace", letterSpacing: "1px", textTransform: "uppercase", marginBottom: 8 }}>{title}</div>
              {lines.map((line, i) => (
                <pre key={i} style={{ background: line.startsWith("#") ? "transparent" : "rgba(0,0,0,0.3)", borderRadius: line.startsWith("#") ? 0 : 3, padding: line.startsWith("#") ? "2px 0" : "5px 10px", fontFamily: "monospace", fontSize: 10, color: line.startsWith("#") ? "rgba(255,255,255,0.25)" : "rgba(255,255,255,0.65)", margin: "0 0 3px 0", overflowX: "auto" }}>{line || " "}</pre>
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* Platform matrix */}
      <div style={{ ...CARD, marginBottom: 16 }}>
        <div style={{ ...LABEL, marginBottom: 14 }}>Supported Platforms</div>
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
          {PLATFORM_MATRIX.map(({ os, icon, items }) => (
            <div key={os} style={{ flex: "1 1 180px", minWidth: 160 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                <span>{icon}</span>
                <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.5px" }}>{os}</span>
              </div>
              {items.map(item => (
                <div key={item} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                  <span style={{ color: "#00e5a0", fontSize: 10 }}>✓</span>
                  <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, fontFamily: "monospace" }}>{item}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* Packages on server */}
      <div style={{ ...CARD }}>
        <div style={{ ...LABEL, marginBottom: 12 }}>Agent Packages on Server</div>
        {loading ? (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace" }}>Loading…</div>
        ) : pkgList.length === 0 ? (
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 11, fontFamily: "monospace", lineHeight: 1.7 }}>
            No packages found at <code style={{ color: "rgba(0,229,160,0.5)" }}>/var/lib/cycentra-agent-packages/</code>.<br/>
            Packages are deployed automatically during installation via <code style={{ color: "rgba(0,229,160,0.5)" }}>cycentra-setup.sh</code>.
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 100px 120px", gap: 8, color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace", letterSpacing: "0.5px", textTransform: "uppercase", paddingBottom: 6, borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
              <span>Package</span><span>Size</span><span>Modified</span>
            </div>
            {displayGroups.map(({ version: ver, pkgs }) => (
              <div key={ver}>
                <div style={{ color: "rgba(0,229,160,0.55)", fontSize: 9, fontFamily: "monospace", letterSpacing: "0.5px", textTransform: "uppercase", marginBottom: 4 }}>v{ver}</div>
                {pkgs.map(pkg => (
                  <div key={pkg.name} style={{ display: "grid", gridTemplateColumns: "1fr 100px 120px", gap: 8, alignItems: "center", padding: "4px 0", borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                    <a href={pkg.url} style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace", textDecoration: "none" }}
                      onMouseOver={e => e.target.style.textDecoration = "underline"}
                      onMouseOut={e => e.target.style.textDecoration = "none"}>{pkg.name}</a>
                    <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, fontFamily: "monospace" }}>
                      {pkg.size_bytes >= 1048576 ? `${(pkg.size_bytes / 1048576).toFixed(1)} MB` : `${Math.round(pkg.size_bytes / 1024)} KB`}
                    </span>
                    <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, fontFamily: "monospace" }}>
                      {new Date(pkg.modified * 1000).toLocaleDateString()}
                    </span>
                  </div>
                ))}
              </div>
            ))}
            {olderGroupCount > 0 && (
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <button
                  disabled={pruning}
                  onClick={async () => {
                    setPruning(true); setPruneMsg(null);
                    try {
                      const r = await fetch(`${API_BASE}/api/system/agent-packages/prune`, { method: "DELETE", credentials: "include" });
                      const d = await r.json();
                      if (d.ok) {
                        setPruneMsg({ ok: true, text: `Deleted ${d.deleted.length} package(s) from ${olderGroupCount} older version(s).` });
                        const keep = new Set(displayGroups.flatMap(g => g.pkgs.map(p => p.name)));
                        setPkgList(prev => prev.filter(p => keep.has(p.name)));
                      } else {
                        setPruneMsg({ ok: false, text: `Errors: ${d.errors.map(e => e.file).join(", ")}` });
                      }
                    } catch { setPruneMsg({ ok: false, text: "Request failed." }); }
                    finally { setPruning(false); }
                  }}
                  style={{ background: "rgba(255,107,107,0.1)", border: "1px solid rgba(255,107,107,0.3)", color: "#ff6b6b", borderRadius: 4, padding: "5px 12px", fontSize: 11, fontFamily: "monospace", cursor: pruning ? "default" : "pointer" }}>
                  {pruning ? "Deleting…" : `Delete ${olderGroupCount} older version(s)`}
                </button>
                {pruneMsg && (
                  <span style={{ fontSize: 11, fontFamily: "monospace", color: pruneMsg.ok ? "#00e5a0" : "#ff6b6b" }}>
                    {pruneMsg.ok ? "✓" : "✗"} {pruneMsg.text}
                  </span>
                )}
              </div>
            )}
          </div>
        )}
        <div style={{ marginTop: 12, color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace", lineHeight: 1.7 }}>
          Packages served from <code style={{ color: "rgba(0,229,160,0.4)" }}>{serverUrl}/agent-packages/</code> via HTTPS.
        </div>
      </div>

    </div>
  );
}
