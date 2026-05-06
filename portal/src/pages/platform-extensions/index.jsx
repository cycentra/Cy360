/**
 * src/pages/platform-extensions/index.jsx
 * ==========================================
 * Platform Extensions — consolidated hub for:
 *   1. Platform Add-on Modules   (install + configure in one unified card)
 *   2. SIEM Integrations         (MISP, CyMind AI Chat)
 *
 * Sources consolidated here:
 *   - MarketplacePage  → AddonInstallFlow, AddonModulesSection
 *   - SystemSettingsPage → IntegrationsTab (MispTab, CyIrisTab, CyMindIntegrationTab)
 */

import { useState, useEffect, useRef } from "react";
import { API_BASE } from "../../core/constants";
import { PLATFORM_MODULES } from "../../registry/platformModules";

// ── Shared style constants (match SystemSettingsPage palette) ─────────────────
const CARD  = { background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "20px 24px", marginBottom: 20 };
const LABEL = { color: "rgba(255,255,255,0.62)", fontSize: 10, letterSpacing: "1.5px", fontFamily: "monospace", textTransform: "uppercase", marginBottom: 6 };
const INPUT = { background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 4, color: "white", fontFamily: "monospace", fontSize: 12, padding: "8px 12px", width: "100%", outline: "none", boxSizing: "border-box" };
const BTN   = (color = "#00e5a0") => ({ background: `rgba(${color === "#00e5a0" ? "0,229,160" : color === "#4d9eff" ? "77,158,255" : color === "#ff6b6b" ? "255,107,107" : color === "#ff8c00" ? "255,140,0" : "0,229,160"},0.1)`, color, border: `1px solid ${color}40`, padding: "8px 18px", borderRadius: 4, fontFamily: "monospace", fontSize: 11, fontWeight: 700, letterSpacing: "1px", cursor: "pointer", textTransform: "uppercase" });

// CyMind IP is fixed — not user-configurable
const CYMIND_URL = "http://172.16.0.2:8080";

// ── Section heading ───────────────────────────────────────────────────────────
function SectionLabel({ icon, title, badge }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20, paddingBottom: 12, borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
      {icon && <span style={{ fontSize: 16 }}>{icon}</span>}
      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, letterSpacing: "2px", fontFamily: "monospace", textTransform: "uppercase", fontWeight: 700 }}>
        {title}
      </div>
      {badge && (
        <span style={{ background: "rgba(176,110,255,0.1)", color: "#b06eff", border: "1px solid rgba(176,110,255,0.25)", fontSize: 9, fontFamily: "monospace", padding: "2px 8px", borderRadius: 2, fontWeight: 700 }}>
          {badge}
        </span>
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// AddonInstallFlow — inline install wizard (moved from MarketplacePage)
// ════════════════════════════════════════════════════════════════════════════

function AddonInstallFlow({ mod, onInstall, onCancel }) {
  const [config,   setConfig]   = useState(mod.defaultConfig || {});
  const [stage,    setStage]    = useState("config");
  const [log,      setLog]      = useState([]);
  const [progress, setProgress] = useState(0);
  const logRef  = useRef(null);
  const pollRef = useRef(null);

  useEffect(() => () => clearInterval(pollRef.current), []);

  const update = (k, v) => setConfig(prev => ({ ...prev, [k]: v }));

  const startInstall = async () => {
    setStage("installing");
    setLog(["Preparing installation…"]);
    setProgress(5);
    try {
      const res = await fetch(`${API_BASE}/api/platform/install`, {
        method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include",
        body: JSON.stringify({ module: mod.id, config }),
      });
      if (!res.ok) {
        const e = await res.json();
        setLog(p => [...p, `ERROR: ${e.error || "Install failed"}`]);
        setStage("error");
        return;
      }
      pollRef.current = setInterval(async () => {
        try {
          const lr = await fetch(`${API_BASE}/api/platform/logs/${mod.id}`, { credentials: "include" });
          if (lr.ok) {
            const l = await lr.json();
            if (l.lines?.length) {
              setLog(l.lines);
              const last = l.lines[l.lines.length - 1].toLowerCase();
              if (last.includes("pulling"))            setProgress(p => Math.max(p, 15));
              else if (last.includes("starting"))      setProgress(p => Math.max(p, 40));
              else if (last.includes("waiting"))       setProgress(p => Math.max(p, 50));
              else if (last.includes("live"))          setProgress(p => Math.max(p, 85));
              else if (last.includes("credentials"))   setProgress(p => Math.max(p, 92));
              else if (last.includes("done — status")) setProgress(100);
            }
          }
          const sr = await fetch(`${API_BASE}/api/platform/status`, { credentials: "include" });
          if (!sr.ok) return;
          const all = await sr.json();
          const s = all[mod.id];
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
      setLog(p => [...p, `Network error: ${e.message}`]);
      setStage("error");
    }
  };

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  const inpStyle = { width: "100%", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", color: "white", padding: "10px 14px", borderRadius: 4, fontSize: 13, fontFamily: "monospace", outline: "none", boxSizing: "border-box" };

  return (
    <div style={{ background: "rgba(255,255,255,0.02)", borderTop: "1px solid rgba(255,255,255,0.06)", padding: "20px 24px" }}>
      {stage === "config" && (
        <>
          <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", marginBottom: 16 }}>
            Configure {mod.name}
          </div>
          {(mod.configFields || []).map(f => (
            <div key={f.key} style={{ marginBottom: 14 }}>
              <label style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace", letterSpacing: "1px", textTransform: "uppercase", display: "block", marginBottom: 6 }}>{f.label}</label>
              <input type={f.type || "text"} value={config[f.key] || ""} onChange={e => update(f.key, e.target.value)} style={inpStyle} />
              {f.help && <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, marginTop: 4 }}>{f.help}</div>}
            </div>
          ))}
          {(mod.configFields || []).length === 0 && (
            <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 12, marginBottom: 16 }}>
              No configuration required — all secrets are auto-generated.
            </div>
          )}
          <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
            <button onClick={startInstall}
              style={{ background: mod.color, color: "#0d0f14", border: "none", borderRadius: 4, padding: "10px 24px", fontFamily: "monospace", fontSize: 12, fontWeight: 700, cursor: "pointer", letterSpacing: "1px" }}>
              Install {mod.name} →
            </button>
            <button onClick={onCancel}
              style={{ background: "transparent", color: "rgba(255,255,255,0.4)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 4, padding: "10px 18px", fontFamily: "monospace", fontSize: 12, cursor: "pointer" }}>
              Cancel
            </button>
          </div>
        </>
      )}
      {stage !== "config" && (
        <>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
            <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, fontFamily: "monospace" }}>
              {stage === "installing" ? "Installing…" : stage === "done" ? "✓ Complete" : "✗ Failed"}
            </span>
            <span style={{ color: stage === "done" ? "#00e5a0" : stage === "error" ? "#ff3b3b" : "#f5c518", fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>{progress}%</span>
          </div>
          <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2, marginBottom: 14 }}>
            <div style={{ height: "100%", width: `${progress}%`, background: stage === "error" ? "#ff3b3b" : "#00e5a0", borderRadius: 2, transition: "width 0.4s ease" }} />
          </div>
          <div ref={logRef} style={{ height: 140, overflowY: "auto", background: "rgba(0,0,0,0.4)", borderRadius: 4, padding: "10px 14px", fontFamily: "monospace", fontSize: 10, color: "rgba(255,255,255,0.5)" }}>
            {log.map((l, i) => <div key={i}>{l}</div>)}
          </div>
          {(stage === "done" || stage === "error") && (
            <button onClick={onCancel}
              style={{ marginTop: 14, background: stage === "done" ? "rgba(255,255,255,0.08)" : "rgba(255,59,59,0.2)", color: stage === "done" ? "rgba(255,255,255,0.6)" : "#ff3b3b", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 4, padding: "10px 24px", fontFamily: "monospace", fontSize: 12, fontWeight: 700, cursor: "pointer" }}>
              {stage === "done" ? "Done" : "Close"}
            </button>
          )}
        </>
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// CyIrisConfigPanel — inline integration config drawer
// Shown inside the CyIRIS unified card after module is installed.
// Consolidates CyIrisTab logic from SystemSettingsPage → Integrations.
// ════════════════════════════════════════════════════════════════════════════

function CyIrisConfigPanel() {
  const [iris,       setIris]       = useState({});
  const [loading,    setLoading]    = useState(true);
  const [saving,     setSaving]     = useState(false);
  const [saved,      setSaved]      = useState(false);
  const [testStatus, setTestStatus] = useState(null);
  const [testMsg,    setTestMsg]    = useState("");

  useEffect(() => {
    fetch(`${API_BASE}/api/ai/settings`, { credentials: "include" })
      .then(r => r.json())
      .then(d => {
        const raw = d.iris || {};
        if (!raw.mode) raw.mode = "disabled";
        if (raw.fpThreshold === undefined) raw.fpThreshold = 90;
        setIris(raw);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const mode    = iris.mode || "disabled";
  const setMode = (m) => { setIris(prev => ({ ...prev, mode: m })); setTestStatus(null); setTestMsg(""); };

  const handleSave = async () => {
    setSaving(true);
    try {
      await fetch(`${API_BASE}/api/ai/settings`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iris }),
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } finally { setSaving(false); }
  };

  const testConnection = async () => {
    if (mode === "cloud") {
      setTestStatus("testing"); setTestMsg("");
      try {
        const r = await fetch(`${API_BASE}/api/system/iris/test`, {
          method: "POST", credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: "https://cyiris.cycentra.com", apiKey: "", useStored: true }),
        });
        const d = await r.json();
        if (d.ok) { setTestStatus("ok");   setTestMsg(d.message || "Connected"); }
        else       { setTestStatus("fail"); setTestMsg(d.error  || "Connection failed"); }
      } catch { setTestStatus("fail"); setTestMsg("Cannot reach backend"); }
      return;
    }
    const _MASK = "\u2022".repeat(8);
    const url = iris.url || "";
    const key = (iris.apiKey && iris.apiKey !== _MASK) ? iris.apiKey : "";
    if (!url) { setTestStatus("fail"); setTestMsg("CyIRIS URL is required"); return; }
    if (!key) { setTestStatus("fail"); setTestMsg("API key required"); return; }
    setTestStatus("testing"); setTestMsg("");
    try {
      const r = await fetch(`${API_BASE}/api/system/iris/test`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, apiKey: key, useStored: false }),
      });
      const d = await r.json();
      if (d.ok) { setTestStatus("ok");   setTestMsg(d.message || "Connected"); }
      else       { setTestStatus("fail"); setTestMsg(d.error  || "Connection failed"); }
    } catch { setTestStatus("fail"); setTestMsg("Cannot reach backend"); }
  };

  if (loading) return <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 12, padding: "20px 24px" }}>Loading…</div>;

  const MODES = [
    { id: "disabled", label: "No CyIRIS",   desc: "Incident escalation disabled", icon: "⭕", color: "rgba(255,255,255,0.3)" },
    { id: "cloud",    label: "Cloud CyIRIS", desc: "Cycentra-managed at cyiris.cycentra.com", icon: "☁️", color: "#4d9eff" },
    { id: "local",    label: "Local CyIRIS", desc: "This installed instance — or any self-hosted DFIR IRIS", icon: "🏠", color: "#00e5a0" },
  ];

  return (
    <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", padding: "22px 24px", background: "rgba(0,0,0,0.15)" }}>
      <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700, marginBottom: 6 }}>
        Incident Escalation — Integration Settings
      </div>
      <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 12, marginBottom: 20, lineHeight: 1.6 }}>
        When enabled, the <strong style={{ color: "rgba(255,255,255,0.5)" }}>CySIEM Correlation Engine</strong> automatically
        raises tickets in DFIR IRIS for incidents that require analyst investigation.
      </div>

      {/* Mode selector */}
      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        {MODES.map(m => (
          <button key={m.id} onClick={() => setMode(m.id)}
            style={{ flex: 1, padding: "10px 8px", borderRadius: 5, cursor: "pointer", border: `1px solid ${mode === m.id ? m.color : "rgba(255,255,255,0.08)"}`, background: mode === m.id ? `${m.color}12` : "rgba(255,255,255,0.02)", transition: "all 0.15s" }}>
            <div style={{ fontSize: 16, marginBottom: 4 }}>{m.icon}</div>
            <div style={{ color: mode === m.id ? m.color : "rgba(255,255,255,0.5)", fontSize: 10, fontFamily: "monospace", fontWeight: 700, marginBottom: 3 }}>{m.label}</div>
            <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, lineHeight: 1.4 }}>{m.desc}</div>
          </button>
        ))}
      </div>

      {/* Disabled state */}
      {mode === "disabled" && (
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 5, padding: "14px 16px", marginBottom: 16 }}>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, fontFamily: "monospace" }}>
            ⭕ Incidents will not escalate to DFIR IRIS. False-positive auto-close still active.
          </div>
        </div>
      )}

      {/* Cloud mode */}
      {mode === "cloud" && (
        <div style={{ background: "rgba(77,158,255,0.04)", border: "1px solid rgba(77,158,255,0.2)", borderRadius: 5, padding: "16px 18px", marginBottom: 16 }}>
          <div style={{ color: "#4d9eff", fontSize: 11, fontFamily: "monospace", fontWeight: 700, marginBottom: 4 }}>
            ☁️ Cycentra Cloud CyIRIS — cyiris.cycentra.com
          </div>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", marginBottom: 14, lineHeight: 1.6 }}>
            Credentials provisioned via <code style={{ color: "#4d9eff" }}>CLOUD_IRIS_URL</code>,{" "}
            <code style={{ color: "#4d9eff" }}>CLOUD_IRIS_API_KEY</code>,{" "}
            <code style={{ color: "#4d9eff" }}>CLOUD_IRIS_CUSTOMER_ID</code> in{" "}
            <code style={{ color: "rgba(255,255,255,0.65)" }}>/opt/cycentra/.env</code>.
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <button onClick={testConnection} disabled={testStatus === "testing"}
              style={{ background: "rgba(77,158,255,0.12)", color: "#4d9eff", border: "1px solid rgba(77,158,255,0.35)", borderRadius: 4, padding: "7px 16px", fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer", opacity: testStatus === "testing" ? 0.6 : 1 }}>
              {testStatus === "testing" ? "Testing…" : "Test Connection"}
            </button>
            {testStatus === "ok"   && <span style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace" }}>✓ {testMsg}</span>}
            {testStatus === "fail" && <span style={{ color: "#ff4444", fontSize: 11, fontFamily: "monospace" }}>✗ {testMsg}</span>}
          </div>
        </div>
      )}

      {/* Local mode */}
      {mode === "local" && (
        <div style={{ background: "rgba(0,229,160,0.03)", border: "1px solid rgba(0,229,160,0.2)", borderRadius: 5, padding: "18px 20px", marginBottom: 16 }}>
          <div style={{ marginBottom: 12 }}>
            <div style={LABEL}>CyIRIS Server URL</div>
            <input type="text" value={iris.url || ""}
              onChange={e => setIris(prev => ({ ...prev, url: e.target.value }))}
              placeholder="https://cyiris.yourdomain.com  or  http://127.0.0.1"
              style={INPUT} />
          </div>
          <div style={{ marginBottom: 12 }}>
            <div style={LABEL}>API Key</div>
            <input type="password" value={iris.apiKey || ""}
              onChange={e => setIris(prev => ({ ...prev, apiKey: e.target.value }))}
              placeholder="IRIS Bearer token — from IRIS → My Profile → API Key"
              style={INPUT} />
            <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace", marginTop: 4 }}>
              In DFIR IRIS: click your avatar → My Settings → API Key → copy or generate
            </div>
          </div>
          <div style={{ marginBottom: 16 }}>
            <div style={LABEL}>Customer ID</div>
            <input type="number" value={iris.customerId || 1} min={1}
              onChange={e => setIris(prev => ({ ...prev, customerId: parseInt(e.target.value) || 1 }))}
              style={{ ...INPUT, width: 120 }} />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <button onClick={testConnection} disabled={testStatus === "testing"}
              style={{ background: "rgba(0,229,160,0.1)", color: "#00e5a0", border: "1px solid rgba(0,229,160,0.35)", borderRadius: 4, padding: "7px 16px", fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer", opacity: testStatus === "testing" ? 0.6 : 1 }}>
              {testStatus === "testing" ? "Testing…" : "Test Connection"}
            </button>
            {testStatus === "ok"   && <span style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace" }}>✓ {testMsg}</span>}
            {testStatus === "fail" && <span style={{ color: "#ff4444", fontSize: 11, fontFamily: "monospace" }}>✗ {testMsg}</span>}
          </div>
        </div>
      )}

      {/* FP threshold — always visible */}
      <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 5, padding: "16px 18px", marginBottom: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
          <div style={LABEL}>False Positive Auto-Close Threshold</div>
          <span style={{ color: "#00e5a0", fontFamily: "monospace", fontSize: 14, fontWeight: 700 }}>
            {iris.fpThreshold ?? 90}%
          </span>
        </div>
        <input type="range" min={50} max={99} step={1} value={iris.fpThreshold ?? 90}
          onChange={e => setIris(prev => ({ ...prev, fpThreshold: parseInt(e.target.value) }))}
          style={{ width: "100%", accentColor: "#00e5a0", cursor: "pointer", marginBottom: 6 }} />
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 11, lineHeight: 1.5 }}>
          Incidents with AI FP confidence ≥{" "}
          <strong style={{ color: "#00e5a0" }}>{iris.fpThreshold ?? 90}%</strong>{" "}
          are <strong style={{ color: "#ff8c00" }}>auto-closed</strong> without a ticket.
        </div>
      </div>

      <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
        <button onClick={handleSave} disabled={saving} style={{ ...BTN(), opacity: saving ? 0.5 : 1 }}>
          {saving ? "Saving…" : "Save CyIRIS Settings"}
        </button>
        {saved && <span style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace" }}>✓ Saved — correlation engine updated</span>}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// UnifiedModuleCard — install + configure in one card
// ════════════════════════════════════════════════════════════════════════════

function UnifiedModuleCard({ mod, installedModules, platformStatus, onInstall, onUninstall }) {
  const [installing,       setInstalling]       = useState(false);
  const [confirmUninstall, setConfirmUninstall] = useState(false);
  const [showConfig,       setShowConfig]       = useState(false);

  const liveStatus  = platformStatus[mod.id]?.status;
  const stateStatus = installedModules[mod.id]?.status;
  const status      = stateStatus || liveStatus || null;
  const isRunning   = status === "running";
  const isInstalling = status === "installing";
  const isFailed    = status === "failed";
  const isInstalled = !!installedModules[mod.id] || isRunning;
  const showFlow    = installing;

  // Auto-expand config drawer for CyIRIS when the module is installed
  useEffect(() => {
    if (mod.id === "cyiris" && isInstalled && !showConfig) {
      setShowConfig(true);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isInstalled]);

  const handleUninstallConfirm = async () => {
    try {
      const r = await fetch(`${API_BASE}/api/platform/uninstall`, {
        method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include",
        body: JSON.stringify({ module: mod.id }),
      });
      if (r.ok && onUninstall) onUninstall(mod.id);
    } catch {}
    setConfirmUninstall(false);
  };

  // Does this module have integration configuration?
  const hasConfigPanel = mod.id === "cyiris";

  return (
    <>
      <div style={{ background: "rgba(255,255,255,0.025)", border: `1px solid ${mod.color}20`, borderLeft: `3px solid ${mod.color}`, borderRadius: 6, overflow: "hidden", marginBottom: 0 }}>
        {/* ── Card body ──────────────────────────────────────────────── */}
        <div style={{ padding: "20px 22px" }}>
          {/* Header row */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
            <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
              <span style={{ fontSize: 24 }}>{mod.icon}</span>
              <div>
                <div style={{ color: "white", fontWeight: 700, fontSize: 15 }}>{mod.fullName}</div>
                <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", marginTop: 2 }}>
                  {mod.ssoProtocol || "OIDC"} SSO · {mod.ram_gb}GB RAM · {mod.disk_gb}GB disk · ~{mod.install_time}
                </div>
              </div>
            </div>
            {/* Status pill */}
            {isRunning ? (
              <span style={{ background: "rgba(0,229,160,0.12)", color: "#00e5a0", border: "1px solid rgba(0,229,160,0.3)", fontSize: 9, fontFamily: "monospace", padding: "3px 10px", borderRadius: 2, fontWeight: 700, display: "flex", alignItems: "center", gap: 5, whiteSpace: "nowrap" }}>
                <span style={{ width: 5, height: 5, borderRadius: "50%", background: "#00e5a0", animation: "pulse 2s infinite" }} />
                RUNNING
              </span>
            ) : isInstalling ? (
              <span style={{ background: "rgba(245,197,24,0.12)", color: "#f5c518", border: "1px solid rgba(245,197,24,0.3)", fontSize: 9, fontFamily: "monospace", padding: "3px 10px", borderRadius: 2, fontWeight: 700, whiteSpace: "nowrap" }}>INSTALLING…</span>
            ) : isFailed ? (
              <span style={{ background: "rgba(255,59,59,0.12)", color: "#ff3b3b", border: "1px solid rgba(255,59,59,0.3)", fontSize: 9, fontFamily: "monospace", padding: "3px 10px", borderRadius: 2, fontWeight: 700, whiteSpace: "nowrap" }}>FAILED</span>
            ) : (
              <span style={{ background: "rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.3)", border: "1px solid rgba(255,255,255,0.1)", fontSize: 9, fontFamily: "monospace", padding: "3px 10px", borderRadius: 2, fontWeight: 700, whiteSpace: "nowrap" }}>NOT INSTALLED</span>
            )}
          </div>

          <p style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, lineHeight: 1.6, margin: "0 0 12px" }}>{mod.description}</p>

          {/* Feature tags */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 16 }}>
            {(mod.features || []).slice(0, 5).map(f => (
              <span key={f} style={{ background: `${mod.color}10`, color: `${mod.color}cc`, border: `1px solid ${mod.color}25`, borderRadius: 3, padding: "2px 8px", fontSize: 10, fontFamily: "monospace" }}>{f}</span>
            ))}
          </div>

          {/* Action buttons */}
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            {isRunning && (
              <a href={mod.modulePath} target="_blank" rel="noreferrer"
                style={{ background: `${mod.color}18`, color: mod.color, border: `1px solid ${mod.color}40`, borderRadius: 4, padding: "7px 14px", fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer", textDecoration: "none", display: "inline-flex", alignItems: "center", gap: 5 }}>
                Open {mod.name} ↗
              </a>
            )}
            {!isInstalled && !showFlow && (
              <button onClick={() => setInstalling(true)}
                style={{ background: `${mod.color}18`, color: mod.color, border: `1px solid ${mod.color}40`, borderRadius: 4, padding: "7px 14px", fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer" }}>
                Install {mod.name}
              </button>
            )}
            {isInstalled && (
              <button onClick={() => setConfirmUninstall(true)}
                style={{ background: "rgba(255,59,59,0.08)", color: "#ff3b3b", border: "1px solid rgba(255,59,59,0.2)", borderRadius: 4, padding: "7px 14px", fontFamily: "monospace", fontSize: 11, cursor: "pointer" }}>
                Uninstall
              </button>
            )}
            {/* Configure Integration toggle — only for modules with config panels */}
            {hasConfigPanel && (
              <button onClick={() => setShowConfig(v => !v)}
                style={{ background: showConfig ? `rgba(0,229,160,0.08)` : "rgba(255,255,255,0.04)", color: showConfig ? "#00e5a0" : "rgba(255,255,255,0.45)", border: `1px solid ${showConfig ? "rgba(0,229,160,0.3)" : "rgba(255,255,255,0.1)"}`, borderRadius: 4, padding: "7px 14px", fontFamily: "monospace", fontSize: 11, cursor: "pointer", display: "flex", alignItems: "center", gap: 5 }}>
                <span style={{ fontSize: 10 }}>{showConfig ? "▲" : "▼"}</span>
                Integration Settings
              </button>
            )}
          </div>
        </div>

        {/* ── Inline install flow ──────────────────────────────────────── */}
        {showFlow && (
          <AddonInstallFlow
            mod={mod}
            onInstall={(id, cfg) => { if (onInstall) onInstall(id, cfg); setInstalling(false); }}
            onCancel={() => setInstalling(false)}
          />
        )}

        {/* ── Integration config drawer ────────────────────────────────── */}
        {hasConfigPanel && showConfig && <CyIrisConfigPanel />}
      </div>

      {/* Uninstall confirmation modal */}
      {confirmUninstall && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200 }}>
          <div style={{ background: "#0d0f14", border: "1px solid rgba(255,59,59,0.3)", borderRadius: 8, padding: 32, width: "min(420px,90vw)" }}>
            <div style={{ color: "#ff3b3b", fontSize: 14, fontWeight: 700, marginBottom: 10 }}>Uninstall {mod.name}?</div>
            <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, lineHeight: 1.6, marginBottom: 20 }}>
              This will stop and remove the {mod.name} container. Volume data is preserved — you can reinstall at any time.
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <button onClick={handleUninstallConfirm}
                style={{ background: "rgba(255,59,59,0.15)", color: "#ff3b3b", border: "1px solid rgba(255,59,59,0.35)", borderRadius: 4, padding: "10px 20px", fontFamily: "monospace", fontSize: 12, fontWeight: 700, cursor: "pointer" }}>
                Uninstall
              </button>
              <button onClick={() => setConfirmUninstall(false)}
                style={{ background: "transparent", color: "rgba(255,255,255,0.4)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 4, padding: "10px 20px", fontFamily: "monospace", fontSize: 12, cursor: "pointer" }}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// MispSection — MISP Threat Intelligence config
// Moved from SystemSettingsPage → IntegrationsTab → MispTab
// ════════════════════════════════════════════════════════════════════════════

function MispSection() {
  const [misp,       setMisp]       = useState({});
  const [loading,    setLoading]    = useState(true);
  const [saving,     setSaving]     = useState(false);
  const [saved,      setSaved]      = useState(false);
  const [testStatus, setTestStatus] = useState(null);
  const [testMsg,    setTestMsg]    = useState("");

  useEffect(() => {
    fetch(`${API_BASE}/api/ai/settings`, { credentials: "include" })
      .then(r => r.json())
      .then(d => {
        const raw = d.misp || {};
        if (!raw.mode) {
          if (raw.enabled) raw.mode = "local";
          else if (raw.apiKey && !raw.url) raw.mode = "cloud";
          else raw.mode = "disabled";
        }
        setMisp(raw);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const mode    = misp.mode || "disabled";
  const setMode = (m) => { setMisp(prev => ({ ...prev, mode: m })); setTestStatus(null); setTestMsg(""); };

  const handleSave = async () => {
    setSaving(true);
    try {
      await fetch(`${API_BASE}/api/ai/settings`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ misp }),
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } finally { setSaving(false); }
  };

  const testConnection = async () => {
    if (mode === "cloud") {
      setTestStatus("testing"); setTestMsg("");
      try {
        const r = await fetch(`${API_BASE}/api/system/misp/test`, {
          method: "POST", credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: "https://cymisp.cycentra.com", apiKey: "", useStored: true }),
        });
        const d = await r.json();
        if (d.ok) { setTestStatus("ok");   setTestMsg(d.message || "Connected"); }
        else       { setTestStatus("fail"); setTestMsg(d.error  || "Connection failed"); }
      } catch { setTestStatus("fail"); setTestMsg("Cannot reach backend"); }
      return;
    }
    const _MASK = "\u2022".repeat(8);
    const url = misp.url || "";
    const key = (misp.apiKey && misp.apiKey !== _MASK) ? misp.apiKey : "";
    if (!url) { setTestStatus("fail"); setTestMsg("MISP Server URL is required"); return; }
    if (!key) { setTestStatus("fail"); setTestMsg("API key required"); return; }
    setTestStatus("testing"); setTestMsg("");
    try {
      const r = await fetch(`${API_BASE}/api/system/misp/test`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, apiKey: key, useStored: false }),
      });
      const d = await r.json();
      if (d.ok) { setTestStatus("ok");   setTestMsg(d.message || "Connected"); }
      else       { setTestStatus("fail"); setTestMsg(d.error  || "Connection failed"); }
    } catch { setTestStatus("fail"); setTestMsg("Cannot reach backend"); }
  };

  if (loading) return <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 12, padding: "20px 0" }}>Loading…</div>;

  const MODES = [
    { id: "disabled", label: "Disabled",     desc: "No MISP IOC lookups — all enrichment bypassed", icon: "⭕", color: "rgba(255,255,255,0.3)" },
    { id: "cloud",    label: "Cloud CyMISP", desc: "Cycentra-managed MISP at cymisp.cycentra.com", icon: "☁️", color: "#4d9eff" },
    { id: "local",    label: "Local CyMISP", desc: "Self-hosted MISP instance — configure URL & key", icon: "🏠", color: "#ff6b6b" },
  ];

  return (
    <div style={{ ...CARD, borderLeft: "3px solid rgba(255,100,100,0.5)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
        <span style={{ fontSize: 20 }}>🔴</span>
        <div style={{ color: "rgba(255,100,100,0.9)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700 }}>
          MISP Threat Intelligence
        </div>
      </div>
      <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, marginBottom: 20, lineHeight: 1.6 }}>
        MISP settings apply to <strong style={{ color: "rgba(255,255,255,0.5)" }}>all modules</strong> —
        CySIEM Correlation Engine, ASM Deep Scans, CySOAR, and CyIRIS all read from this single configuration.
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 24 }}>
        {MODES.map(m => (
          <button key={m.id} onClick={() => setMode(m.id)}
            style={{ flex: 1, padding: "12px 10px", borderRadius: 5, cursor: "pointer", border: `1px solid ${mode === m.id ? m.color : "rgba(255,255,255,0.08)"}`, background: mode === m.id ? `${m.color}12` : "rgba(255,255,255,0.02)", transition: "all 0.15s" }}>
            <div style={{ fontSize: 18, marginBottom: 4 }}>{m.icon}</div>
            <div style={{ color: mode === m.id ? m.color : "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace", fontWeight: 700, marginBottom: 4 }}>{m.label}</div>
            <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, lineHeight: 1.4 }}>{m.desc}</div>
          </button>
        ))}
      </div>

      {mode === "disabled" && (
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 6, padding: "18px 20px", marginBottom: 20 }}>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, fontFamily: "monospace" }}>
            ⭕ MISP is disabled — IOC lookups and threat intelligence enrichment are bypassed for all modules.
          </div>
        </div>
      )}

      {mode === "cloud" && (
        <div style={{ background: "rgba(77,158,255,0.04)", border: "1px solid rgba(77,158,255,0.2)", borderRadius: 6, padding: "18px 20px", marginBottom: 20 }}>
          <div style={{ color: "#4d9eff", fontSize: 11, fontFamily: "monospace", fontWeight: 700, marginBottom: 4 }}>
            ☁️ Cycentra Cloud MISP — cymisp.cycentra.com
          </div>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", marginBottom: 16, lineHeight: 1.6 }}>
            Credentials provisioned via <code style={{ color: "#4d9eff" }}>CLOUD_MISP_URL</code> and{" "}
            <code style={{ color: "#4d9eff" }}>CLOUD_MISP_API_KEY</code> in{" "}
            <code style={{ color: "rgba(255,255,255,0.65)" }}>/opt/cycentra/.env</code>.
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <button onClick={testConnection} disabled={testStatus === "testing"}
              style={{ background: "rgba(77,158,255,0.12)", color: "#4d9eff", border: "1px solid rgba(77,158,255,0.35)", borderRadius: 4, padding: "8px 18px", fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer", opacity: testStatus === "testing" ? 0.6 : 1 }}>
              {testStatus === "testing" ? "Testing…" : "Test Connection"}
            </button>
            {testStatus === "ok"   && <span style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace" }}>✓ {testMsg}</span>}
            {testStatus === "fail" && <span style={{ color: "#ff4444", fontSize: 11, fontFamily: "monospace" }}>✗ {testMsg}</span>}
          </div>
        </div>
      )}

      {mode === "local" && (
        <div style={{ background: "rgba(255,59,59,0.04)", border: "1px solid rgba(255,59,59,0.2)", borderRadius: 6, padding: "22px 24px", marginBottom: 20 }}>
          <div style={{ marginBottom: 14 }}>
            <div style={LABEL}>MISP Server URL</div>
            <input type="text" value={misp.url || ""}
              onChange={e => setMisp(prev => ({ ...prev, url: e.target.value }))}
              placeholder="https://cymisp.yourdomain.com"
              style={INPUT} />
          </div>
          <div style={{ marginBottom: 22 }}>
            <div style={LABEL}>MISP API Key</div>
            <input type="password" value={misp.apiKey || ""}
              onChange={e => setMisp(prev => ({ ...prev, apiKey: e.target.value }))}
              placeholder="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
              style={INPUT} />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
            <button onClick={testConnection} disabled={testStatus === "testing"}
              style={{ background: "rgba(255,59,59,0.12)", color: "#ff6b6b", border: "1px solid rgba(255,59,59,0.35)", borderRadius: 4, padding: "8px 18px", fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer", opacity: testStatus === "testing" ? 0.6 : 1 }}>
              {testStatus === "testing" ? "Testing…" : "Test Connection"}
            </button>
            {testStatus === "ok"   && <span style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace" }}>✓ {testMsg}</span>}
            {testStatus === "fail" && <span style={{ color: "#ff4444", fontSize: 11, fontFamily: "monospace" }}>✗ {testMsg}</span>}
          </div>
          <div style={{ fontSize: 10, fontFamily: "monospace", color: "rgba(255,255,255,0.55)", marginBottom: 16 }}>
            {misp.url && misp.apiKey
              ? <span style={{ color: "#ff6b6b" }}>✓ Configured — IOC lookups active on Deep scans</span>
              : <span style={{ color: "#ff8c00" }}>⚠ URL and API Key required to activate</span>}
          </div>
          <div style={{ paddingTop: 14, borderTop: "1px solid rgba(255,255,255,0.05)" }}>
            <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 11, lineHeight: 1.5 }}>
              Don't have a local MISP? Install <strong style={{ color: "rgba(255,255,255,0.5)" }}>CyMISP</strong> — a fully containerised
              MISP appliance — via the CySIEM Stack environment settings.
            </div>
          </div>
        </div>
      )}

      <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
        <button onClick={handleSave} disabled={saving} style={{ ...BTN(), opacity: saving ? 0.5 : 1 }}>
          {saving ? "Saving…" : "Save MISP Configuration"}
        </button>
        {saved && <span style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace" }}>✓ Saved — all modules updated</span>}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// CyMindSection — CyMind AI Chat integration
// Moved from SystemSettingsPage → IntegrationsTab → CyMindIntegrationTab
// ════════════════════════════════════════════════════════════════════════════

function CyMindSection() {
  const [cfg,         setCfg]         = useState({});
  const [loading,     setLoading]     = useState(true);
  const [saving,      setSaving]      = useState(false);
  const [msg,         setMsg]         = useState(null);
  const [testResults, setTestResults] = useState(null);
  const [mcpStatus,   setMcpStatus]   = useState(null);
  const [adminEmail,  setAdminEmail]  = useState("");
  const [adminPw,     setAdminPw]     = useState("");
  const [showAdvanced,setShowAdvanced]= useState(false);
  const [newKey,      setNewKey]      = useState(null);
  const [chatKeyInput,setChatKeyInput]= useState("");
  const [mcpKeys,       setMcpKeys]       = useState([]);
  const [mcpKeysEp,     setMcpKeysEp]     = useState("");
  const [mcpKeysLoading,setMcpKeysLoading]= useState(false);
  const [newKeyName,    setNewKeyName]    = useState("");
  const [newKeyDesc,    setNewKeyDesc]    = useState("");
  const [genKeyResult,  setGenKeyResult]  = useState(null);
  const [mcpKeyMsg,     setMcpKeyMsg]     = useState(null);

  const fetchCfg = () => {
    setLoading(true);
    fetch(`${API_BASE}/api/system/cymind`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setCfg(d); setLoading(false); })
      .catch(() => setLoading(false));
  };

  const fetchMcpKeys = () => {
    setMcpKeysLoading(true);
    fetch(`${API_BASE}/api/system/mcp/keys`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) { setMcpKeys(d.keys || []); setMcpKeysEp(d.endpoint || ""); } setMcpKeysLoading(false); })
      .catch(() => setMcpKeysLoading(false));
  };

  useEffect(() => {
    fetchCfg();
    fetchMcpKeys();
    fetch(`${API_BASE}/api/system/mcp`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setMcpStatus(d); })
      .catch(() => {});
  }, []);

  const handleEnable = async () => {
    if (!adminEmail.trim() || !adminPw.trim()) { setMsg({ ok: false, text: "Enter CyMind admin email and password." }); return; }
    setSaving(true); setMsg({ ok: null, text: "Connecting to CyMind and provisioning service account…" });
    try {
      const r = await fetch(`${API_BASE}/api/system/cymind/enable`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cymindAdminEmail: adminEmail.trim(), cymindAdminPassword: adminPw }),
      });
      const d = await r.json();
      if (d.ok) {
        setAdminPw("");
        setMsg({ ok: true, text: "Integration enabled. The green brain FAB will appear for analyst/admin users." });
        fetchCfg();
      } else { setMsg({ ok: false, text: d.error || "Enable failed" }); }
    } catch (e) { setMsg({ ok: false, text: String(e) }); }
    finally { setSaving(false); }
  };

  const handleDisable = async () => {
    setSaving(true); setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/cymind`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: false, clearChatKey: true }),
      });
      const d = await r.json();
      if (d.ok) { setMsg({ ok: true, text: "Integration disabled." }); fetchCfg(); }
      else { setMsg({ ok: false, text: d.error || "Disable failed" }); }
    } catch (e) { setMsg({ ok: false, text: String(e) }); }
    finally { setSaving(false); }
  };

  const handleGenKey = async () => {
    setSaving(true); setMsg(null); setNewKey(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/cymind`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ generateKey: true }),
      });
      const d = await r.json();
      if (d.ok) { setNewKey(d.newKey || null); setMsg({ ok: true, text: "New M2M key generated." }); fetchCfg(); }
      else { setMsg({ ok: false, text: d.error || "Key generation failed" }); }
    } catch (e) { setMsg({ ok: false, text: String(e) }); }
    finally { setSaving(false); }
  };

  const handleSaveChatKey = async () => {
    const trimmed = chatKeyInput.trim();
    if (!trimmed.startsWith("pak_")) { setMsg({ ok: false, text: "Key must start with 'pak_'" }); return; }
    setSaving(true); setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/cymind`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chatApiKey: trimmed }),
      });
      const d = await r.json();
      if (d.ok) { setChatKeyInput(""); setMsg({ ok: true, text: "Chat key saved." }); fetchCfg(); }
      else { setMsg({ ok: false, text: d.error || "Save failed" }); }
    } catch (e) { setMsg({ ok: false, text: String(e) }); }
    finally { setSaving(false); }
  };

  const handleGenMcpKey = async () => {
    const name = newKeyName.trim();
    if (!name) { setMcpKeyMsg({ ok: false, text: "Enter a name for the key." }); return; }
    setMcpKeyMsg({ ok: null, text: "Generating…" }); setGenKeyResult(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/mcp/keys`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, description: newKeyDesc.trim() }),
      });
      const d = await r.json();
      if (d.ok) {
        setGenKeyResult({ key: d.key, name: d.name });
        setNewKeyName(""); setNewKeyDesc("");
        setMcpKeyMsg({ ok: true, text: "Key generated. Copy it now — it will not be shown again." });
        fetchMcpKeys();
      } else { setMcpKeyMsg({ ok: false, text: d.error || "Generation failed" }); }
    } catch (e) { setMcpKeyMsg({ ok: false, text: String(e) }); }
  };

  const handleRevokeMcpKey = async (keyId, keyName) => {
    if (!window.confirm(`Revoke key "${keyName}"? This cannot be undone.`)) return;
    setMcpKeyMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/mcp/keys/${keyId}`, { method: "DELETE", credentials: "include" });
      const d = await r.json();
      if (d.ok) { setMcpKeyMsg({ ok: true, text: `Key "${keyName}" revoked.` }); fetchMcpKeys(); }
      else { setMcpKeyMsg({ ok: false, text: d.error || "Revoke failed" }); }
    } catch (e) { setMcpKeyMsg({ ok: false, text: String(e) }); }
  };

  const handleTestConn = async () => {
    setMsg({ ok: null, text: "Testing connectivity…" }); setTestResults(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/cymind/test`, { credentials: "include" });
      const d = await r.json();
      setTestResults(d.results || {});
      setMsg(d.ok ? { ok: true, text: "All systems reachable." } : { ok: false, text: "One or more checks failed — see details below." });
    } catch (e) { setMsg({ ok: false, text: String(e) }); }
  };

  if (loading) return <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, fontFamily: "monospace", padding: "20px 0" }}>Loading…</div>;

  const isEnabled = cfg.enabled && cfg.hasChatKey && cfg.hasKey;

  return (
    <div style={{ ...CARD, borderLeft: "3px solid rgba(0,229,160,0.5)" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
        <span style={{ fontSize: 20 }}>🧠</span>
        <div style={{ color: "rgba(0,229,160,0.9)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700 }}>
          CyMind AI Chat Integration
        </div>
        <span style={{ background: isEnabled ? "rgba(0,229,160,0.1)" : "rgba(255,255,255,0.05)", color: isEnabled ? "#00e5a0" : "rgba(255,255,255,0.3)", border: `1px solid ${isEnabled ? "rgba(0,229,160,0.3)" : "rgba(255,255,255,0.12)"}`, borderRadius: 4, padding: "2px 8px", fontSize: 10, fontFamily: "monospace", fontWeight: 700, display: "inline-flex", alignItems: "center", gap: 5 }}>
          <span style={{ width: 6, height: 6, borderRadius: "50%", background: "currentColor" }} />
          {isEnabled ? "CONNECTED" : "NOT CONFIGURED"}
        </span>
      </div>

      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace", lineHeight: 1.6, marginBottom: 16 }}>
        {CYMIND_URL} &nbsp;·&nbsp;
        {cfg.hasKey     && <span style={{ color: "rgba(0,229,160,0.6)" }}>✓ M2M key &nbsp;</span>}
        {cfg.hasChatKey && <span style={{ color: "rgba(0,229,160,0.6)" }}>✓ Chat key</span>}
      </div>

      {/* MCP bridge status */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 20 }}>
        <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace" }}>MCP Bridge:</span>
        {mcpStatus === null ? (
          <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>checking…</span>
        ) : (
          <span style={{ background: mcpStatus.enabled ? "rgba(0,229,160,0.08)" : "rgba(255,255,255,0.03)", border: `1px solid ${mcpStatus.enabled ? "rgba(0,229,160,0.25)" : "rgba(255,255,255,0.08)"}`, borderRadius: 3, padding: "2px 8px", color: mcpStatus.enabled ? "#00e5a0" : "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
            {mcpStatus.enabled ? "ENABLED" : "DISABLED"}
          </span>
        )}
        {mcpStatus?.enabled && mcpStatus.tools?.length > 0 && (
          <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace" }}>
            {mcpStatus.tools.length} tool{mcpStatus.tools.length !== 1 ? "s" : ""} active
          </span>
        )}
      </div>

      {/* Enable form */}
      <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 5, padding: "18px 20px", marginBottom: 16 }}>
        <div style={LABEL}>{isEnabled ? "Reconfigure Integration" : "Enable CyMind Integration"}</div>
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 11, fontFamily: "monospace", lineHeight: 1.7, marginBottom: 14 }}>
          Enter your CyMind <strong style={{ color: "rgba(255,255,255,0.5)" }}>admin</strong> credentials.
          CyCentra will automatically configure both sides — no manual steps in CyMind needed.
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
          <div style={{ flex: 1, minWidth: 180 }}>
            <div style={{ ...LABEL, marginBottom: 4, fontSize: 10 }}>CyMind Admin Email</div>
            <input type="email" value={adminEmail} onChange={e => setAdminEmail(e.target.value)} placeholder="admin@cymind.local" style={{ ...INPUT, boxSizing: "border-box" }} />
          </div>
          <div style={{ flex: 1, minWidth: 180 }}>
            <div style={{ ...LABEL, marginBottom: 4, fontSize: 10 }}>CyMind Admin Password</div>
            <input type="password" value={adminPw} onChange={e => setAdminPw(e.target.value)} placeholder="••••••••" style={{ ...INPUT, boxSizing: "border-box" }} onKeyDown={e => e.key === "Enter" && handleEnable()} />
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button onClick={handleEnable} disabled={saving} style={{ ...BTN(), opacity: saving ? 0.5 : 1 }}>
            {saving ? "Enabling…" : isEnabled ? "Re-connect" : "Enable Integration"}
          </button>
          {isEnabled && (
            <button onClick={handleDisable} disabled={saving} style={{ ...BTN("#ff6b6b"), opacity: saving ? 0.5 : 1 }}>Disable</button>
          )}
          <button onClick={handleTestConn} disabled={saving} style={{ ...BTN("#4d9eff"), opacity: saving ? 0.5 : 1 }}>Test Connection</button>
        </div>
        {testResults && (
          <div style={{ marginTop: 12, background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 4, padding: "10px 12px", display: "flex", flexDirection: "column", gap: 6 }}>
            {Object.entries(testResults).map(([key, val]) => (
              <div key={key} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ color: val.ok ? "#00e5a0" : "#ff6b6b", fontSize: 12 }}>{val.ok ? "✓" : "✗"}</span>
                <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", minWidth: 80 }}>
                  {key === "cymind" ? "CyMind" : key === "mcp_engine" ? "MCP Engine" : "Chat Key"}
                </span>
                <span style={{ color: val.ok ? "rgba(255,255,255,0.5)" : "#ff6b6b", fontSize: 11, fontFamily: "monospace" }}>{val.msg}</span>
              </div>
            ))}
          </div>
        )}
        {msg && (
          <div style={{ color: msg.ok === true ? "#00e5a0" : msg.ok === false ? "#ff3b3b" : "#ffd93d", fontSize: 12, fontFamily: "monospace", marginTop: 12 }}>
            {msg.ok === true ? "✓" : msg.ok === false ? "✗" : "⋯"} {msg.text}
          </div>
        )}
      </div>

      {/* Advanced section */}
      <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 5, padding: "14px 18px", marginBottom: 16 }}>
        <button onClick={() => setShowAdvanced(v => !v)}
          style={{ background: "none", border: "none", cursor: "pointer", display: "flex", alignItems: "center", gap: 8, color: "rgba(255,255,255,0.45)", fontSize: 11, fontFamily: "monospace", padding: 0 }}>
          <span style={{ fontSize: 10 }}>{showAdvanced ? "▼" : "▶"}</span>
          Advanced / Manual Key Management
        </button>
        {showAdvanced && (
          <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 18 }}>
            <div>
              <div style={{ ...LABEL, marginBottom: 6 }}>Rotate M2M Key <span style={{ color: "rgba(255,255,255,0.35)", fontWeight: 400 }}>(cymk_… — CyMind reads SIEM via MCP)</span></div>
              <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace", marginBottom: 8 }}>After rotating: update <code style={{ color: "rgba(0,229,160,0.6)" }}>CYCENTRA_API_KEY</code> in CyMind .env.</div>
              <button onClick={handleGenKey} disabled={saving} style={{ ...BTN("#4d9eff"), opacity: saving ? 0.5 : 1 }}>
                {cfg.hasKey ? "Rotate M2M Key" : "Generate M2M Key"}
              </button>
              {newKey && (
                <div style={{ marginTop: 10, background: "rgba(0,229,160,0.06)", border: "1px solid rgba(0,229,160,0.2)", borderRadius: 4, padding: "10px 12px" }}>
                  <div style={{ color: "#00e5a0", fontSize: 10, fontFamily: "monospace", marginBottom: 4 }}>New M2M key — copy now (shown once)</div>
                  <code style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace", userSelect: "all", wordBreak: "break-all" }}>{newKey}</code>
                </div>
              )}
            </div>
            <div>
              <div style={{ ...LABEL, marginBottom: 6 }}>Manual Chat Key <span style={{ color: "rgba(255,255,255,0.35)", fontWeight: 400 }}>(pak_… — if auto-enable fails)</span>{cfg.hasChatKey && <span style={{ color: "#00e5a0", fontSize: 10, marginLeft: 8 }}>✓ set</span>}</div>
              <div style={{ display: "flex", gap: 8 }}>
                <input type="password" value={chatKeyInput} onChange={e => setChatKeyInput(e.target.value)} placeholder="pak_…" style={{ ...INPUT, flex: 1 }} />
                <button onClick={handleSaveChatKey} disabled={saving || !chatKeyInput.trim()} style={{ ...BTN("#4d9eff"), opacity: (saving || !chatKeyInput.trim()) ? 0.4 : 1 }}>Save</button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* MCP API Keys */}
      <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 5, padding: "16px 18px" }}>
        <div style={{ ...LABEL, marginBottom: 4 }}>MCP API Keys — 3rd Party Integrations</div>
        <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, fontFamily: "monospace", lineHeight: 1.7, marginBottom: 14 }}>
          Generate <code style={{ color: "rgba(0,229,160,0.5)" }}>cymk_…</code> keys for external AI agents or SIEM tools that need access to the Security MCP bridge.
        </div>
        {mcpKeysEp && (
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14, background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 4, padding: "8px 12px" }}>
            <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>ENDPOINT:</span>
            <code style={{ color: "#00e5a0", fontSize: 10, fontFamily: "monospace", flex: 1, wordBreak: "break-all" }}>{mcpKeysEp}</code>
          </div>
        )}
        <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap" }}>
          <input value={newKeyName} onChange={e => setNewKeyName(e.target.value)} placeholder="Key name (e.g. Claude Desktop)" style={{ ...INPUT, flex: 2, minWidth: 140 }} />
          <input value={newKeyDesc} onChange={e => setNewKeyDesc(e.target.value)} placeholder="Description (optional)" style={{ ...INPUT, flex: 3, minWidth: 160 }} />
          <button onClick={handleGenMcpKey} style={{ ...BTN("#00e5a0"), flexShrink: 0 }}>Generate Key</button>
        </div>
        {genKeyResult && (
          <div style={{ marginBottom: 14, background: "rgba(0,229,160,0.06)", border: "1px solid rgba(0,229,160,0.2)", borderRadius: 4, padding: "10px 12px" }}>
            <div style={{ color: "#00e5a0", fontSize: 10, fontFamily: "monospace", marginBottom: 4 }}>{genKeyResult.name} — copy now (shown once)</div>
            <code style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace", userSelect: "all", wordBreak: "break-all" }}>{genKeyResult.key}</code>
          </div>
        )}
        {mcpKeyMsg && (
          <div style={{ color: mcpKeyMsg.ok === true ? "#00e5a0" : mcpKeyMsg.ok === false ? "#ff3b3b" : "#ffd93d", fontSize: 12, fontFamily: "monospace", marginBottom: 12 }}>
            {mcpKeyMsg.text}
          </div>
        )}
        {mcpKeysLoading ? (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace" }}>Loading keys…</div>
        ) : mcpKeys.length === 0 ? (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace" }}>No API keys generated yet.</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {mcpKeys.map(k => (
              <div key={k.id} style={{ display: "flex", alignItems: "center", gap: 10, background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 4, padding: "8px 12px" }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 12, fontFamily: "monospace", fontWeight: 700 }}>{k.name}</div>
                  {k.description && <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", marginTop: 1 }}>{k.description}</div>}
                  <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace", marginTop: 1 }}>
                    Created {k.created_at ? new Date(k.created_at).toLocaleDateString() : "—"}
                    {k.last_used ? ` · Last used ${new Date(k.last_used).toLocaleDateString()}` : ""}
                  </div>
                </div>
                <button onClick={() => handleRevokeMcpKey(k.id, k.name)}
                  style={{ background: "rgba(255,59,59,0.08)", color: "#ff6b6b", border: "1px solid rgba(255,59,59,0.2)", borderRadius: 3, padding: "5px 12px", fontFamily: "monospace", fontSize: 10, cursor: "pointer" }}>
                  Revoke
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// PlatformExtensionsPage — main export
// ════════════════════════════════════════════════════════════════════════════

export function PlatformExtensionsPage({ installedModules = {}, onInstall, onUninstall }) {
  const [platformStatus, setPlatformStatus] = useState({});

  // Poll platform/status every 5 s to keep install state current
  useEffect(() => {
    const refresh = async () => {
      try {
        const r = await fetch(`${API_BASE}/api/platform/status`, { credentials: "include" });
        if (!r.ok) return;
        const data = await r.json();
        setPlatformStatus(data);
        // Sync running modules up to parent state
        Object.entries(data).forEach(([id, s]) => {
          if (s.status === "running" && installedModules[id]?.status !== "running" && onInstall) {
            onInstall(id, installedModules[id]?.config || {});
          }
        });
      } catch {}
    };
    const timer = setInterval(refresh, 5000);
    refresh();
    return () => clearInterval(timer);
  }, [installedModules, onInstall]);

  const addonModules = Object.values(PLATFORM_MODULES).filter(m => m.tier === "addon");

  return (
    <div>
      {/* Page header */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ color: "white", fontSize: 22, fontWeight: 700, fontFamily: "monospace", marginBottom: 4 }}>
          Platform Extensions
        </div>
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 13 }}>
          Install and configure add-on modules and SIEM integrations in one place
        </div>
      </div>

      {/* ── Section 1: Platform Add-on Modules ─────────────────────────────── */}
      <div style={{ marginBottom: 48 }}>
        <SectionLabel icon="🧩" title="Platform Add-on Modules" badge="INSTALLABLE" />
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))", gap: 16 }}>
          {addonModules.map(mod => (
            <UnifiedModuleCard
              key={mod.id}
              mod={mod}
              installedModules={installedModules}
              platformStatus={platformStatus}
              onInstall={onInstall}
              onUninstall={onUninstall}
            />
          ))}
        </div>
      </div>

      {/* Divider */}
      <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", marginBottom: 40 }} />

      {/* ── Section 2: SIEM Integrations ───────────────────────────────────── */}
      <div>
        <SectionLabel icon="🔌" title="SIEM Integrations" />
        <MispSection />
        <CyMindSection />
      </div>
    </div>
  );
}
