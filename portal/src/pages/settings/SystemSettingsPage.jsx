/**
 * src/pages/settings/SystemSettingsPage.jsx
 * ==========================================
 * System Settings page — tabs:
 *   1. Updates & Version
 *   2. AI Config
 *   3. Integrations (MISP)
 *   4. Environment Config
 */

import { useState, useEffect, useRef } from "react";
import { API_BASE } from "../../core/constants.js";
import { AISettingsPage } from "../ai/AISettingsPage.jsx";

// ── Shared style constants ────────────────────────────────────────────────────
const CARD  = { background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "20px 24px", marginBottom: 20 };
const LABEL = { color: "rgba(255,255,255,0.35)", fontSize: 10, letterSpacing: "1.5px", fontFamily: "monospace", textTransform: "uppercase", marginBottom: 6 };
const INPUT = { background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 4, color: "white", fontFamily: "monospace", fontSize: 12, padding: "8px 12px", width: "100%", outline: "none", boxSizing: "border-box" };
const BTN   = (color="#00e5a0") => ({ background: `rgba(${color === "#00e5a0" ? "0,229,160" : "77,158,255"},0.1)`, color, border: `1px solid ${color}40`, padding: "8px 18px", borderRadius: 4, fontFamily: "monospace", fontSize: 11, fontWeight: 700, letterSpacing: "1px", cursor: "pointer", textTransform: "uppercase" });

// ── ENV targets ───────────────────────────────────────────────────────────────
const ENV_TARGETS = [
  { id: "global",      label: "Global (.env)",        desc: "Core platform config: domain, OAuth, ports" },
  { id: "cysiemstack", label: "CySIEM Stack",          desc: "Wazuh, Redis, PostgreSQL, MISP settings" },
  { id: "cyiris",      label: "CyIRIS",                desc: "Incident response platform config" },
  { id: "cysoar",      label: "CySOAR",                desc: "SOAR / Node-RED automation settings" },
  { id: "cymisp",      label: "CyMISP",                desc: "MISP threat intelligence platform" },
];

// ════════════════════════════════════════════════════════════════════════════
// TAB 1 — Updates
// ════════════════════════════════════════════════════════════════════════════

function UpdatesTab() {
  const [versionData,  setVersionData]  = useState(null);
  const [updating,     setUpdating]     = useState(false);
  const [upgrading,    setUpgrading]    = useState(false);
  const [updateLog,    setUpdateLog]    = useState([]);
  const [logRunning,   setLogRunning]   = useState(false);
  const [error,        setError]        = useState(null);
  const [success,      setSuccess]      = useState(null);
  const [latestInfo,   setLatestInfo]   = useState(null);   // {current, latest, up_to_date, error?}
  const [checkingVer,  setCheckingVer]  = useState(false);
  const logRef  = useRef(null);
  const pollRef = useRef(null);

  useEffect(() => {
    fetch(`${API_BASE}/api/system/version`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => d && setVersionData(d))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [updateLog]);

  const startPolling = () => {
    pollRef.current = setInterval(async () => {
      try {
        const r = await fetch(`${API_BASE}/api/system/update/log`, { credentials: "include" });
        const d = await r.json();
        setUpdateLog(d.log || []);
        setLogRunning(d.running);
        if (!d.running) {
          clearInterval(pollRef.current);
          setUpdating(false);
          setUpgrading(false);
        }
      } catch {}
    }, 1500);
  };

  // Trigger update (--update flag = incremental patch, preserves config)
  const _triggerUpdate = async () => {
    setUpdateLog([]); setUpdating(true); setLogRunning(true); setError(null); setSuccess(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/update`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const d = await r.json();
      if (!d.ok) { setError(d.error || "Update failed"); setUpdating(false); return; }
      startPolling();
    } catch (e) {
      setError(String(e)); setUpdating(false);
    }
  };

  // Trigger upgrade (no flag = full re-install / major upgrade)
  const handleUpgrade = async () => {
    if (updating || upgrading) return;
    setError(null); setSuccess(null); setLatestInfo(null);
    setUpdateLog([]); setUpgrading(true); setLogRunning(true);
    try {
      const r = await fetch(`${API_BASE}/api/system/upgrade`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const d = await r.json();
      if (!d.ok) { setError(d.error || "Upgrade failed"); setUpgrading(false); return; }
      startPolling();
    } catch (e) {
      setError(String(e)); setUpgrading(false);
    }
  };

  // Primary update handler: version-check first, then update if newer is available
  const handleUpdate = async () => {
    if (updating || upgrading) return;
    setError(null); setSuccess(null); setLatestInfo(null);

    setCheckingVer(true);
    let vd = null;
    try {
      const vr = await fetch(`${API_BASE}/api/system/latest-version`, { credentials: "include" });
      vd = await vr.json();
      setLatestInfo(vd);
    } catch {
      setLatestInfo({ error: "Version check failed — proceeding with update anyway" });
    } finally {
      setCheckingVer(false);
    }

    if (vd?.up_to_date) {
      setSuccess(`Already running the latest version (${vd.latest}) — no update needed.`);
      return;
    }

    await _triggerUpdate();
  };

  useEffect(() => () => clearInterval(pollRef.current), []);

  const isUpToDate  = latestInfo?.up_to_date === true;
  const updateAvail = latestInfo && !latestInfo.error && !latestInfo.up_to_date && latestInfo.latest;
  const isBusy      = updating || upgrading || checkingVer;

  return (
    <div>
      {/* Current version + latest available */}
      <div style={CARD}>
        <div style={LABEL}>Current Version</div>
        <div style={{ display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
          <span style={{ color: "#00e5a0", fontFamily: "monospace", fontSize: 22, fontWeight: 700 }}>
            {versionData?.version || "—"}
          </span>
          <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace" }}>
            CyCentra 360
          </span>
          {isUpToDate && (
            <span style={{ background: "rgba(0,229,160,0.08)", color: "#00e5a0", border: "1px solid rgba(0,229,160,0.3)", borderRadius: 4, padding: "2px 8px", fontSize: 10, fontFamily: "monospace", letterSpacing: "0.8px" }}>
              ✓ UP TO DATE
            </span>
          )}
          {updateAvail && (
            <span style={{ background: "rgba(255,217,61,0.08)", color: "#ffd93d", border: "1px solid rgba(255,217,61,0.3)", borderRadius: 4, padding: "2px 8px", fontSize: 10, fontFamily: "monospace", letterSpacing: "0.8px" }}>
              ↑ {latestInfo.latest} AVAILABLE
            </span>
          )}
        </div>
      </div>

      {/* Action buttons */}
      <div style={CARD}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>

          {/* Run Update */}
          <div style={{ background: "rgba(0,229,160,0.03)", border: "1px solid rgba(0,229,160,0.12)", borderRadius: 5, padding: "18px 20px" }}>
            <div style={{ color: "#00e5a0", fontSize: 10, letterSpacing: "1.5px", fontFamily: "monospace", fontWeight: 700, marginBottom: 8 }}>
              RUN UPDATE
            </div>
            <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 12, marginBottom: 16, lineHeight: 1.6 }}>
              Incremental patch — checks the latest version on GitHub and applies
              <code style={{ color: "#00e5a0" }}> cycentra-setup.sh --update</code>.
              Preserves all configuration and data.
            </p>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button onClick={handleUpdate} disabled={isBusy}
                style={{ ...BTN(), opacity: isBusy ? 0.4 : 1 }}>
                {checkingVer ? "Checking…" : updating ? "Updating…" : "Run Update"}
              </button>
              {isUpToDate && !isBusy && (
                <button onClick={_triggerUpdate} style={{ ...BTN("#4d9eff"), fontSize: 10 }}>
                  Force Reinstall
                </button>
              )}
            </div>
          </div>

          {/* Run Upgrade */}
          <div style={{ background: "rgba(255,140,0,0.03)", border: "1px solid rgba(255,140,0,0.15)", borderRadius: 5, padding: "18px 20px" }}>
            <div style={{ color: "#ff8c00", fontSize: 10, letterSpacing: "1.5px", fontFamily: "monospace", fontWeight: 700, marginBottom: 8 }}>
              RUN UPGRADE
            </div>
            <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 12, marginBottom: 16, lineHeight: 1.6 }}>
              Full re-install — downloads and runs{" "}
              <code style={{ color: "#ff8c00" }}>cycentra-setup.sh</code> without flags.
              Use for major version upgrades or to re-apply all services from scratch.
            </p>
            <button onClick={handleUpgrade} disabled={isBusy}
              style={{ ...BTN("#ff8c00"), opacity: isBusy ? 0.4 : 1 }}>
              {upgrading ? "Upgrading…" : "Run Upgrade"}
            </button>
          </div>
        </div>

        <div style={{ marginTop: 14, color: "rgba(255,255,255,0.18)", fontSize: 10, fontFamily: "monospace" }}>
          GitHub credentials are configured server-side in <code>/opt/cycentra/.env</code> — no token entry required.
        </div>

        {latestInfo?.error && (
          <div style={{ color: "#ffd93d", fontSize: 11, marginTop: 10, fontFamily: "monospace" }}>
            ⚠ {latestInfo.error}
          </div>
        )}
        {error   && <div style={{ color: "#ff3b3b", fontSize: 12, marginTop: 10, fontFamily: "monospace" }}>✗ {error}</div>}
        {success && <div style={{ color: "#00e5a0", fontSize: 12, marginTop: 10, fontFamily: "monospace" }}>✓ {success}</div>}

        {/* Live log */}
        {updateLog.length > 0 && (
          <div ref={logRef} style={{ marginTop: 16, background: "rgba(0,0,0,0.4)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 4, padding: "12px 14px", maxHeight: 280, overflowY: "auto", fontFamily: "monospace", fontSize: 11, lineHeight: 1.7 }}>
            <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, letterSpacing: "1px", marginBottom: 8 }}>
              {logRunning ? `● LIVE — ${upgrading ? "UPGRADE" : "UPDATE"}` : "● FINISHED"}
            </div>
            {updateLog.map((line, i) => (
              <div key={i} style={{ color: line.includes("ERROR") ? "#ff3b3b" : line.startsWith("[UPDATE]") || line.startsWith("[UPGRADE]") ? "#00e5a0" : "rgba(255,255,255,0.55)" }}>
                {line}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Release notes */}
      <div style={CARD}>
        <div style={LABEL}>Recent Release Notes</div>
        {!versionData?.release_notes?.length && (
          <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 12, fontFamily: "monospace" }}>
            No release notes found.
          </div>
        )}
        {versionData?.release_notes?.map((rn, i) => (
          <div key={i} style={{ borderBottom: i < versionData.release_notes.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none", paddingBottom: 16, marginBottom: 16 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <span style={{ color: "#00e5a0", fontFamily: "monospace", fontSize: 13, fontWeight: 700 }}>{rn.version}</span>
              {rn.date && <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 11, fontFamily: "monospace" }}>{rn.date}</span>}
            </div>
            <pre style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace", whiteSpace: "pre-wrap", margin: 0, lineHeight: 1.7 }}>
              {rn.notes || "No details."}
            </pre>
          </div>
        ))}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// TAB 2 — Environment Config
// ════════════════════════════════════════════════════════════════════════════

const _SENSITIVE_RE = /(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY|CREDENTIAL)/i;

function EnvVarRow({ v, onChange }) {
  const [reveal, setReveal] = useState(false);
  if (v.comment || !v.key) {
    return <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace", padding: "2px 0" }}>{v.line}</div>;
  }
  const isServerProtected = v.value === "••••••••";
  const isSensitive       = _SENSITIVE_RE.test(v.key);
  return (
    <div style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: 8, alignItems: "center", padding: "4px 0", borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
      <span style={{ color: isSensitive ? "rgba(255,200,100,0.7)" : "rgba(255,255,255,0.55)", fontSize: 12, fontFamily: "monospace", wordBreak: "break-all" }}>{v.key}</span>
      {isServerProtected ? (
        <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace" }}>•••••••• (protected)</span>
      ) : isSensitive ? (
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <input
            type={reveal ? "text" : "password"}
            value={v.value || ""}
            onChange={e => onChange(v.key, e.target.value)}
            style={{ ...INPUT, padding: "5px 10px", fontSize: 11, flex: 1 }}
          />
          <button onClick={() => setReveal(r => !r)}
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.4)", borderRadius: 3, padding: "4px 8px", fontSize: 10, fontFamily: "monospace", cursor: "pointer", flexShrink: 0 }}>
            {reveal ? "hide" : "show"}
          </button>
        </div>
      ) : (
        <input
          value={v.value || ""}
          onChange={e => onChange(v.key, e.target.value)}
          style={{ ...INPUT, padding: "5px 10px", fontSize: 11 }}
        />
      )}
    </div>
  );
}

function EnvEditor({ target }) {
  const [vars,    setVars]    = useState([]);
  const [exists,  setExists]  = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving,  setSaving]  = useState(false);
  const [msg,     setMsg]     = useState(null);
  const [dirty,   setDirty]   = useState({});   // key → new value

  useEffect(() => {
    setLoading(true); setMsg(null); setDirty({});
    fetch(`${API_BASE}/api/system/env/${target}`, { credentials: "include" })
      .then(r => r.json())
      .then(d => { setVars(d.vars || []); setExists(d.exists); setLoading(false); })
      .catch(() => setLoading(false));
  }, [target]);

  const handleChange = (key, val) => {
    setDirty(prev => ({ ...prev, [key]: val }));
    setVars(prev => prev.map(v => v.key === key ? { ...v, value: val } : v));
  };

  const handleSave = async () => {
    if (!Object.keys(dirty).length) { setMsg({ ok: true, text: "No changes to save." }); return; }
    setSaving(true); setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/env/${target}`, {
        method: "PUT", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ vars: dirty }),
      });
      const d = await r.json();
      if (d.ok) { setMsg({ ok: true, text: `Saved ${d.updated} variable(s) to ${d.path}` }); setDirty({}); }
      else       { setMsg({ ok: false, text: d.error || "Save failed" }); }
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally { setSaving(false); }
  };

  if (loading) return <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 12 }}>Loading…</div>;
  if (!exists)  return <div style={{ color: "rgba(255,255,255,0.2)", fontFamily: "monospace", fontSize: 12 }}>No env file found for this module on the server.</div>;

  return (
    <div>
      <div style={{ maxHeight: 420, overflowY: "auto", marginBottom: 14 }}>
        {vars.map((v, i) => <EnvVarRow key={i} v={v} onChange={handleChange} />)}
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <button onClick={handleSave} disabled={saving} style={{ ...BTN(), opacity: saving ? 0.5 : 1 }}>
          {saving ? "Saving…" : "Save Changes"}
        </button>
        {Object.keys(dirty).length > 0 && (
          <span style={{ color: "#f5c518", fontSize: 11, fontFamily: "monospace" }}>
            {Object.keys(dirty).length} unsaved change(s)
          </span>
        )}
      </div>
      {msg && (
        <div style={{ color: msg.ok ? "#00e5a0" : "#ff3b3b", fontSize: 12, fontFamily: "monospace", marginTop: 10 }}>
          {msg.ok ? "✓" : "✗"} {msg.text}
        </div>
      )}
    </div>
  );
}

function EnvConfigTab() {
  const [activeEnv, setActiveEnv] = useState("global");

  return (
    <div style={{ display: "flex", gap: 0, minHeight: 500 }}>
      {/* Env target list */}
      <div style={{ width: 200, borderRight: "1px solid rgba(255,255,255,0.06)", paddingRight: 12, flexShrink: 0 }}>
        {ENV_TARGETS.map(t => (
          <button key={t.id} onClick={() => setActiveEnv(t.id)}
            style={{ width: "100%", textAlign: "left", background: activeEnv === t.id ? "rgba(0,229,160,0.08)" : "transparent", color: activeEnv === t.id ? "#00e5a0" : "rgba(255,255,255,0.45)", border: "none", borderLeft: activeEnv === t.id ? "2px solid #00e5a0" : "2px solid transparent", padding: "10px 12px", cursor: "pointer", marginBottom: 2, borderRadius: "0 4px 4px 0" }}>
            <div style={{ fontSize: 12, fontWeight: activeEnv === t.id ? 700 : 400, fontFamily: "monospace" }}>{t.label}</div>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,0.2)", marginTop: 2, lineHeight: 1.4 }}>{t.desc}</div>
          </button>
        ))}
      </div>
      {/* Editor */}
      <div style={{ flex: 1, paddingLeft: 24 }}>
        <div style={{ ...LABEL, marginBottom: 12 }}>{ENV_TARGETS.find(t => t.id === activeEnv)?.label}</div>
        <EnvEditor key={activeEnv} target={activeEnv} />
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// Main page
// ════════════════════════════════════════════════════════════════════════════

const TABS = [
  { id: "updates",      label: "Updates & Version" },
  { id: "ai-config",    label: "AI Config" },
  { id: "integrations", label: "Integrations" },
  { id: "env",          label: "Environment Config" },
];

// ════════════════════════════════════════════════════════════════════════════
// TAB 3 — Integrations (MISP + CyIRIS)
// ════════════════════════════════════════════════════════════════════════════

function MispTab() {
  const [misp,       setMisp]       = useState({});
  const [loading,    setLoading]    = useState(true);
  const [saving,     setSaving]     = useState(false);
  const [saved,      setSaved]      = useState(false);
  const [testStatus, setTestStatus] = useState(null);  // null | "testing" | "ok" | "fail"
  const [testMsg,    setTestMsg]    = useState("");

  useEffect(() => {
    fetch(`${API_BASE}/api/ai/settings`, { credentials: "include" })
      .then(r => r.json())
      .then(d => {
        const raw = d.misp || {};
        // Backward compat: if old format had enabled=true but no mode, map to "local"
        if (!raw.mode) raw.mode = raw.enabled ? "local" : "disabled";
        setMisp(raw);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const mode = misp.mode || "disabled";

  const setMode = (m) => {
    setMisp(prev => ({ ...prev, mode: m }));
    setTestStatus(null);
    setTestMsg("");
  };

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
    if (!misp.url) { setTestStatus("fail"); setTestMsg("MISP Server URL is required"); return; }
    if (!misp.apiKey || misp.apiKey === "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022") {
      setTestStatus("fail"); setTestMsg("Enter your API Key (currently showing masked placeholder)"); return;
    }
    setTestStatus("testing"); setTestMsg("");
    try {
      const r = await fetch(`${API_BASE}/api/system/misp/test`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: misp.url, apiKey: misp.apiKey }),
      });
      const d = await r.json();
      if (d.ok) { setTestStatus("ok");   setTestMsg(d.message || "Connected"); }
      else       { setTestStatus("fail"); setTestMsg(d.error  || "Connection failed"); }
    } catch { setTestStatus("fail"); setTestMsg("Cannot reach backend"); }
  };

  if (loading) return <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 12 }}>Loading…</div>;

  // Mode selector config
  const MODES = [
    { id: "disabled", label: "Disabled",      desc: "No MISP IOC lookups — all enrichment bypassed", icon: "⭕", color: "rgba(255,255,255,0.3)" },
    { id: "cloud",    label: "Cloud CyMISP",  desc: "Connect to Cycentra-managed MISP at misp.cycentra.com", icon: "☁️", color: "#4d9eff" },
    { id: "local",    label: "Local CyMISP",  desc: "Your self-hosted MISP instance — configure URL & key below", icon: "🏠", color: "#ff6b6b" },
  ];

  return (
    <div style={{ maxWidth: 640 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
        <span style={{ fontSize: 18 }}>🔴</span>
        <div style={{ color: "rgba(255,100,100,0.9)", fontSize: 10, letterSpacing: "1.5px",
          textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700 }}>
          MISP Threat Intelligence
        </div>
      </div>
      <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, marginBottom: 20, lineHeight: 1.6 }}>
        MISP settings apply to <strong style={{ color: "rgba(255,255,255,0.5)" }}>all modules</strong> —
        CySIEM Correlation Engine, ASM Deep Scans, CySOAR, and CyIRIS all read from this single configuration.
      </div>

      {/* Mode selector */}
      <div style={{ display: "flex", gap: 8, marginBottom: 24 }}>
        {MODES.map(m => (
          <button key={m.id} onClick={() => setMode(m.id)}
            style={{
              flex: 1, padding: "12px 10px", borderRadius: 5, cursor: "pointer",
              border: `1px solid ${mode === m.id ? m.color : "rgba(255,255,255,0.08)"}`,
              background: mode === m.id ? `${m.color}12` : "rgba(255,255,255,0.02)",
              transition: "all 0.15s",
            }}>
            <div style={{ fontSize: 18, marginBottom: 4 }}>{m.icon}</div>
            <div style={{ color: mode === m.id ? m.color : "rgba(255,255,255,0.5)", fontSize: 11,
              fontFamily: "monospace", fontWeight: 700, marginBottom: 4 }}>
              {m.label}
            </div>
            <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, lineHeight: 1.4 }}>
              {m.desc}
            </div>
          </button>
        ))}
      </div>

      {/* Mode: Disabled */}
      {mode === "disabled" && (
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 6, padding: "18px 20px" }}>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, fontFamily: "monospace" }}>
            ⭕ MISP is disabled — IOC lookups and threat intelligence enrichment are bypassed for all modules.
          </div>
        </div>
      )}

      {/* Mode: Cloud CyMISP */}
      {mode === "cloud" && (
        <div style={{ background: "rgba(77,158,255,0.04)", border: "1px solid rgba(77,158,255,0.2)", borderRadius: 6, padding: "18px 20px" }}>
          <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
            <span style={{ fontSize: 22 }}>☁️</span>
            <div>
              <div style={{ color: "#4d9eff", fontSize: 12, fontFamily: "monospace", fontWeight: 700, marginBottom: 6 }}>
                Cycentra Cloud MISP — misp.cycentra.com
              </div>
              <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, lineHeight: 1.6, marginBottom: 8 }}>
                Your platform will connect to the Cycentra-managed MISP instance using
                pre-provisioned credentials. No configuration is required — credentials
                are securely embedded in the server environment.
              </div>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace" }}>
                All modules (CySIEM, ASM, CySOAR, CyIRIS) will use this connection automatically.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Mode: Local CyMISP */}
      {mode === "local" && (
        <div style={{ background: "rgba(255,59,59,0.04)", border: "1px solid rgba(255,59,59,0.2)", borderRadius: 6, padding: "22px 24px" }}>
          {/* URL */}
          <div style={{ marginBottom: 14 }}>
            <div style={LABEL}>MISP Server URL</div>
            <input type="text" value={misp.url || ""}
              onChange={e => setMisp(prev => ({ ...prev, url: e.target.value }))}
              placeholder="https://cymisp.yourdomain.com"
              style={INPUT} />
          </div>

          {/* API Key */}
          <div style={{ marginBottom: 22 }}>
            <div style={LABEL}>MISP API Key</div>
            <input type="password" value={misp.apiKey || ""}
              onChange={e => setMisp(prev => ({ ...prev, apiKey: e.target.value }))}
              placeholder="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
              style={INPUT} />
          </div>

          {/* Test Connection */}
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
            <button onClick={testConnection} disabled={testStatus === "testing"}
              style={{ background: "rgba(255,59,59,0.12)", color: "#ff6b6b",
                border: "1px solid rgba(255,59,59,0.35)", borderRadius: 4,
                padding: "8px 18px", fontFamily: "monospace", fontSize: 11,
                fontWeight: 700, cursor: "pointer", letterSpacing: "0.5px",
                opacity: testStatus === "testing" ? 0.6 : 1 }}>
              {testStatus === "testing" ? "Testing…" : "Test Connection"}
            </button>
            {testStatus === "ok"   && <span style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace" }}>✓ {testMsg}</span>}
            {testStatus === "fail" && <span style={{ color: "#ff4444", fontSize: 11, fontFamily: "monospace" }}>✗ {testMsg}</span>}
          </div>

          <div style={{ fontSize: 10, fontFamily: "monospace", color: "rgba(255,255,255,0.25)" }}>
            {misp.url && misp.apiKey
              ? <span style={{ color: "#ff6b6b" }}>✓ Configured — IOC lookups active on Deep scans</span>
              : <span style={{ color: "#ff8c00" }}>⚠ URL and API Key required to activate</span>}
          </div>

          {/* Install CyMISP locally */}
          <div style={{ marginTop: 20, paddingTop: 16, borderTop: "1px solid rgba(255,255,255,0.05)" }}>
            <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace", marginBottom: 6 }}>
              NEED A LOCAL MISP INSTANCE?
            </div>
            <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, lineHeight: 1.5 }}>
              Install CyMISP via <strong style={{ color: "rgba(255,255,255,0.5)" }}>Platform Modules</strong> — a fully containerised
              MISP appliance will be deployed at{" "}
              <code style={{ color: "#ff6b6b", fontSize: 10 }}>cymisp.{"{yourdomain}"}</code> with an auto-generated admin passphrase.
            </div>
          </div>
        </div>
      )}

      {/* Save */}
      <div style={{ display: "flex", gap: 12, alignItems: "center", marginTop: 20 }}>
        <button onClick={handleSave} disabled={saving}
          style={{ ...BTN(), opacity: saving ? 0.5 : 1 }}>
          {saving ? "Saving…" : "Save MISP Configuration"}
        </button>
        {saved && <span style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace" }}>✓ Saved — all modules updated</span>}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// TAB 3b — CyIRIS (DFIR IRIS Integration)
// ════════════════════════════════════════════════════════════════════════════

function CyIrisTab() {
  const [iris,       setIris]       = useState({});
  const [loading,    setLoading]    = useState(true);
  const [saving,     setSaving]     = useState(false);
  const [saved,      setSaved]      = useState(false);
  const [testStatus, setTestStatus] = useState(null);   // null | "testing" | "ok" | "fail"
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
    if (!iris.url) { setTestStatus("fail"); setTestMsg("CyIRIS URL is required"); return; }
    if (!iris.apiKey || iris.apiKey === "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022") {
      setTestStatus("fail"); setTestMsg("Enter your API Key (currently showing masked placeholder)"); return;
    }
    setTestStatus("testing"); setTestMsg("");
    try {
      const r = await fetch(`${API_BASE}/api/system/iris/test`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: iris.url, apiKey: iris.apiKey }),
      });
      const d = await r.json();
      if (d.ok) { setTestStatus("ok");   setTestMsg(d.message || "Connected"); }
      else       { setTestStatus("fail"); setTestMsg(d.error  || "Connection failed"); }
    } catch { setTestStatus("fail"); setTestMsg("Cannot reach backend"); }
  };

  if (loading) return <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 12 }}>Loading…</div>;

  const MODES = [
    { id: "disabled", label: "No CyIRIS",      desc: "Incident escalation disabled — no tickets will be raised in DFIR IRIS", icon: "⭕", color: "rgba(255,255,255,0.3)" },
    { id: "cloud",    label: "Cloud CyIRIS",    desc: "Connect to Cycentra-managed DFIR IRIS at cyiris.cycentra.com", icon: "☁️",  color: "#4d9eff" },
    { id: "local",    label: "Local CyIRIS",    desc: "Your self-hosted DFIR IRIS instance — configure URL, API key, and customer ID below", icon: "🏠", color: "#00e5a0" },
  ];

  return (
    <div style={{ maxWidth: 640 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
        <span style={{ fontSize: 18 }}>🔵</span>
        <div style={{ color: "rgba(0,229,160,0.9)", fontSize: 10, letterSpacing: "1.5px",
          textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700 }}>
          CyIRIS — DFIR IRIS Incident Response
        </div>
      </div>
      <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, marginBottom: 20, lineHeight: 1.6 }}>
        When enabled, <strong style={{ color: "rgba(255,255,255,0.5)" }}>CySIEM Correlation Engine</strong> will
        automatically raise tickets in DFIR IRIS for incidents that require analyst investigation.
        Incidents with a high false-positive confidence score are auto-closed without a ticket.
      </div>

      {/* Mode selector */}
      <div style={{ display: "flex", gap: 8, marginBottom: 24 }}>
        {MODES.map(m => (
          <button key={m.id} onClick={() => setMode(m.id)}
            style={{
              flex: 1, padding: "12px 10px", borderRadius: 5, cursor: "pointer",
              border: `1px solid ${mode === m.id ? m.color : "rgba(255,255,255,0.08)"}`,
              background: mode === m.id ? `${m.color}12` : "rgba(255,255,255,0.02)",
              transition: "all 0.15s",
            }}>
            <div style={{ fontSize: 18, marginBottom: 4 }}>{m.icon}</div>
            <div style={{ color: mode === m.id ? m.color : "rgba(255,255,255,0.5)", fontSize: 11,
              fontFamily: "monospace", fontWeight: 700, marginBottom: 4 }}>
              {m.label}
            </div>
            <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, lineHeight: 1.4 }}>
              {m.desc}
            </div>
          </button>
        ))}
      </div>

      {/* Mode: Disabled */}
      {mode === "disabled" && (
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 6, padding: "18px 20px" }}>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, fontFamily: "monospace" }}>
            ⭕ CyIRIS is disabled — incidents will not escalate to DFIR IRIS. False-positive auto-close still active based on threshold.
          </div>
        </div>
      )}

      {/* Mode: Cloud CyIRIS */}
      {mode === "cloud" && (
        <div style={{ background: "rgba(77,158,255,0.04)", border: "1px solid rgba(77,158,255,0.2)", borderRadius: 6, padding: "18px 20px" }}>
          <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
            <span style={{ fontSize: 22 }}>☁️</span>
            <div>
              <div style={{ color: "#4d9eff", fontSize: 12, fontFamily: "monospace", fontWeight: 700, marginBottom: 6 }}>
                Cycentra Cloud CyIRIS — cyiris.cycentra.com
              </div>
              <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, lineHeight: 1.6, marginBottom: 8 }}>
                Your platform will connect to the Cycentra-managed DFIR IRIS instance using
                pre-provisioned credentials embedded securely in the server environment. No
                configuration is required.
              </div>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace" }}>
                Incidents from CySIEM Correlation Engine will be escalated automatically.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Mode: Local CyIRIS */}
      {mode === "local" && (
        <div style={{ background: "rgba(0,229,160,0.03)", border: "1px solid rgba(0,229,160,0.2)", borderRadius: 6, padding: "22px 24px" }}>
          {/* URL */}
          <div style={{ marginBottom: 14 }}>
            <div style={LABEL}>CyIRIS Server URL</div>
            <input type="text" value={iris.url || ""}
              onChange={e => setIris(prev => ({ ...prev, url: e.target.value }))}
              placeholder="https://cyiris.yourdomain.com  or  http://127.0.0.1"
              style={INPUT} />
          </div>

          {/* API Key */}
          <div style={{ marginBottom: 14 }}>
            <div style={LABEL}>API Key</div>
            <input type="password" value={iris.apiKey || ""}
              onChange={e => setIris(prev => ({ ...prev, apiKey: e.target.value }))}
              placeholder="IRIS Bearer token — from IRIS → My Profile → API Key"
              style={INPUT} />
            <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace", marginTop: 4 }}>
              In DFIR IRIS: click your avatar → My Settings → scroll to API Key → copy or generate
            </div>
          </div>

          {/* Customer ID */}
          <div style={{ marginBottom: 22 }}>
            <div style={LABEL}>Customer ID</div>
            <input type="number" value={iris.customerId || 1} min={1}
              onChange={e => setIris(prev => ({ ...prev, customerId: parseInt(e.target.value) || 1 }))}
              placeholder="1"
              style={{ ...INPUT, width: 120 }} />
            <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace", marginTop: 4 }}>
              In DFIR IRIS: Global Settings → Customers → copy the numeric ID
            </div>
          </div>

          {/* Test Connection */}
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
            <button onClick={testConnection} disabled={testStatus === "testing"}
              style={{ background: "rgba(0,229,160,0.1)", color: "#00e5a0",
                border: "1px solid rgba(0,229,160,0.35)", borderRadius: 4,
                padding: "8px 18px", fontFamily: "monospace", fontSize: 11,
                fontWeight: 700, cursor: "pointer", letterSpacing: "0.5px",
                opacity: testStatus === "testing" ? 0.6 : 1 }}>
              {testStatus === "testing" ? "Testing…" : "Test Connection"}
            </button>
            {testStatus === "ok"   && <span style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace" }}>✓ {testMsg}</span>}
            {testStatus === "fail" && <span style={{ color: "#ff4444", fontSize: 11, fontFamily: "monospace" }}>✗ {testMsg}</span>}
          </div>

          {/* Status hint */}
          <div style={{ fontSize: 10, fontFamily: "monospace", color: "rgba(255,255,255,0.25)" }}>
            {iris.url && iris.apiKey
              ? <span style={{ color: "#00e5a0" }}>✓ Configured — incidents will be escalated to CyIRIS</span>
              : <span style={{ color: "#ff8c00" }}>⚠ URL and API Key required to activate</span>}
          </div>
        </div>
      )}

      {/* False-positive threshold slider — always visible */}
      <div style={{ marginTop: 24, background: "rgba(255,255,255,0.02)",
        border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "18px 20px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <div style={LABEL}>FALSE POSITIVE AUTO-CLOSE THRESHOLD</div>
          <span style={{ color: "#00e5a0", fontFamily: "monospace", fontSize: 14, fontWeight: 700 }}>
            {iris.fpThreshold ?? 90}%
          </span>
        </div>
        <input
          type="range" min={50} max={99} step={1}
          value={iris.fpThreshold ?? 90}
          onChange={e => setIris(prev => ({ ...prev, fpThreshold: parseInt(e.target.value) }))}
          style={{ width: "100%", accentColor: "#00e5a0", cursor: "pointer", marginBottom: 8 }}
        />
        <div style={{ display: "flex", justifyContent: "space-between" }}>
          <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>50% (more tickets)</span>
          <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>99% (fewer tickets)</span>
        </div>
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 11, marginTop: 8, lineHeight: 1.5 }}>
          Incidents where the AI confidence score is{" "}
          <strong style={{ color: "#00e5a0" }}>≥ {iris.fpThreshold ?? 90}%</strong>{" "}
          false positive are <strong style={{ color: "#ff8c00" }}>auto-closed</strong> without raising a ticket.
          All others are escalated to CyIRIS for analyst review.
        </div>
      </div>

      {/* Save */}
      <div style={{ display: "flex", gap: 12, alignItems: "center", marginTop: 20 }}>
        <button onClick={handleSave} disabled={saving}
          style={{ ...BTN(), opacity: saving ? 0.5 : 1 }}>
          {saving ? "Saving…" : "Save CyIRIS Configuration"}
        </button>
        {saved && <span style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace" }}>✓ Saved — correlation engine updated</span>}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// TAB 3 wrapper — Integrations (MISP + CyIRIS)
// ════════════════════════════════════════════════════════════════════════════

function IntegrationsTab() {
  return (
    <div>
      {/* MISP Section */}
      <div style={{ marginBottom: 40 }}>
        <MispTab />
      </div>

      {/* Divider */}
      <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", marginBottom: 40 }} />

      {/* CyIRIS Section */}
      <CyIrisTab />
    </div>
  );
}

export function SystemSettingsPage({ aiConfig, onSaveAIConfig }) {
  const [tab, setTab] = useState("updates");

  return (
    <div>
      {/* Page header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ color: "white", fontSize: 22, fontWeight: 700, fontFamily: "monospace", marginBottom: 4 }}>
          System Settings
        </div>
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 13 }}>
          Platform updates, release notes, and environment configuration
        </div>
      </div>

      {/* Tab bar */}
      <div style={{ display: "flex", gap: 4, borderBottom: "1px solid rgba(255,255,255,0.06)", marginBottom: 24 }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ background: "none", border: "none", borderBottom: tab === t.id ? "2px solid #00e5a0" : "2px solid transparent", color: tab === t.id ? "#00e5a0" : "rgba(255,255,255,0.45)", padding: "8px 18px", fontFamily: "monospace", fontSize: 12, fontWeight: tab === t.id ? 700 : 400, cursor: "pointer", marginBottom: -1, letterSpacing: "0.5px" }}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "updates"      && <UpdatesTab />}
      {tab === "ai-config"    && <AISettingsPage aiConfig={aiConfig || {}} onSave={onSaveAIConfig || (() => {})} embedded={true} />}
      {tab === "integrations" && <IntegrationsTab />}
      {tab === "env"          && <EnvConfigTab />}
    </div>
  );
}
