/**
 * src/pages/settings/SystemSettingsPage.jsx
 * ==========================================
 * System Settings page — two tabs:
 *   1. Updates  — show current version, last 5 release notes, trigger update
 *   2. Env Config — read/edit .env files for global / per-module
 */

import { useState, useEffect, useRef } from "react";
import { API_BASE } from "../../core/constants.js";

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
  { id: "cysiem",      label: "CySIEM Engine",         desc: "Correlation engine tuning parameters" },
];

// ════════════════════════════════════════════════════════════════════════════
// TAB 1 — Updates
// ════════════════════════════════════════════════════════════════════════════

function UpdatesTab() {
  const [versionData,  setVersionData]  = useState(null);
  const [ghToken,      setGhToken]      = useState("");
  const [updating,     setUpdating]     = useState(false);
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
        }
      } catch {}
    }, 1500);
  };

  // Trigger the actual update script (bypasses version check)
  const _triggerUpdate = async () => {
    setUpdateLog([]); setUpdating(true); setLogRunning(true);
    try {
      const r = await fetch(`${API_BASE}/api/system/update`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ghToken: ghToken.trim() }),
      });
      const d = await r.json();
      if (!d.ok) { setError(d.error || "Update failed"); setUpdating(false); return; }
      startPolling();
    } catch (e) {
      setError(String(e)); setUpdating(false);
    }
  };

  // Primary handler: version-check first, then update if needed
  const handleUpdate = async () => {
    if (!ghToken.trim()) { setError("Enter your GitHub Token (GH_TOKEN) first"); return; }
    setError(null); setSuccess(null); setLatestInfo(null);

    // Step 1: lightweight version check
    setCheckingVer(true);
    let vd = null;
    try {
      const vr = await fetch(
        `${API_BASE}/api/system/latest-version?ghToken=${encodeURIComponent(ghToken.trim())}`,
        { credentials: "include" },
      );
      vd = await vr.json();
      setLatestInfo(vd);
    } catch {
      // Network error — non-fatal; show warning but let the update proceed
      setLatestInfo({ error: "Version check failed — proceeding with update anyway" });
    } finally {
      setCheckingVer(false);
    }

    // Step 2: gate on version equality (unless check failed)
    if (vd?.up_to_date) {
      setSuccess(`Already running the latest version (${vd.latest}) — no update needed.`);
      return;
    }

    await _triggerUpdate();
  };

  useEffect(() => () => clearInterval(pollRef.current), []);

  const isUpToDate  = latestInfo?.up_to_date === true;
  const updateAvail = latestInfo && !latestInfo.error && !latestInfo.up_to_date && latestInfo.latest;

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

      {/* Trigger update */}
      <div style={CARD}>
        <div style={LABEL}>Pull Latest Update</div>
        <p style={{ color: "rgba(255,255,255,0.4)", fontSize: 12, marginBottom: 16, lineHeight: 1.6 }}>
          Checks the latest published version on GitHub Releases against your installed version before running the update.
          Runs <code style={{ color: "#00e5a0" }}>cycentra-setup.sh --update</code> on the server only when a newer version is available.
        </p>
        <div style={{ marginBottom: 12 }}>
          <div style={LABEL}>GitHub Personal Access Token (GH_TOKEN)</div>
          <input
            type="password"
            placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
            value={ghToken}
            onChange={e => { setGhToken(e.target.value); setLatestInfo(null); setSuccess(null); setError(null); }}
            style={INPUT}
          />
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <button
            onClick={handleUpdate}
            disabled={updating || checkingVer}
            style={{ ...BTN(), opacity: (updating || checkingVer) ? 0.5 : 1 }}
          >
            {checkingVer ? "Checking version…" : updating ? "Updating…" : "Run Update"}
          </button>

          {/* Force reinstall — shown only when server is already on the latest version */}
          {isUpToDate && !updating && (
            <button
              onClick={_triggerUpdate}
              style={{ ...BTN("#4d9eff"), fontSize: 10 }}
            >
              Force Reinstall
            </button>
          )}
        </div>

        {latestInfo?.error && (
          <div style={{ color: "#ffd93d", fontSize: 11, marginTop: 10, fontFamily: "monospace" }}>
            ⚠ {latestInfo.error}
          </div>
        )}
        {error   && <div style={{ color: "#ff3b3b", fontSize: 12, marginTop: 10, fontFamily: "monospace" }}>✗ {error}</div>}
        {success && (
          <div style={{ color: "#00e5a0", fontSize: 12, marginTop: 10, fontFamily: "monospace" }}>
            ✓ {success}
          </div>
        )}

        {/* Live log */}
        {updateLog.length > 0 && (
          <div ref={logRef} style={{ marginTop: 16, background: "rgba(0,0,0,0.4)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 4, padding: "12px 14px", maxHeight: 280, overflowY: "auto", fontFamily: "monospace", fontSize: 11, lineHeight: 1.7 }}>
            <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, letterSpacing: "1px", marginBottom: 8 }}>
              {logRunning ? "● LIVE OUTPUT" : "● FINISHED"}
            </div>
            {updateLog.map((line, i) => (
              <div key={i} style={{ color: line.startsWith("[UPDATE ERROR]") ? "#ff3b3b" : line.startsWith("[UPDATE]") ? "#00e5a0" : "rgba(255,255,255,0.55)" }}>
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

function EnvVarRow({ v, onChange }) {
  if (v.comment || !v.key) {
    return <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace", padding: "2px 0" }}>{v.line}</div>;
  }
  const isSecret = v.value === "••••••••";
  return (
    <div style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: 8, alignItems: "center", padding: "4px 0", borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
      <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 12, fontFamily: "monospace", wordBreak: "break-all" }}>{v.key}</span>
      {isSecret ? (
        <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace" }}>•••••••• (protected)</span>
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
  { id: "integrations", label: "Integrations" },
  { id: "env",          label: "Environment Config" },
];

// ════════════════════════════════════════════════════════════════════════════
// TAB 3 — Integrations (MISP)
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
      .then(d => { setMisp(d.misp || {}); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

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

  return (
    <div style={{ maxWidth: 620 }}>
      <div style={{ background: "rgba(255,59,59,0.04)", border: "1px solid rgba(255,59,59,0.2)", borderRadius: 6, padding: "22px 24px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
          <span style={{ fontSize: 18 }}>🔴</span>
          <div style={{ color: "rgba(255,100,100,0.9)", fontSize: 10, letterSpacing: "1.5px",
            textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700 }}>MISP Threat Intelligence</div>
        </div>
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, marginBottom: 20, lineHeight: 1.6 }}>
          Connect to your MISP instance. Discovered IPs from ASM Deep scans are checked
          against MISP <strong style={{ color: "rgba(255,255,255,0.5)" }}>before AI enrichment</strong> —
          IOC matches are attached to findings and included in the AI narrative.
        </div>

        {/* Enable toggle */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
          <input type="checkbox" id="misp-enabled" checked={!!misp.enabled}
            onChange={e => setMisp(prev => ({ ...prev, enabled: e.target.checked }))}
            style={{ accentColor: "#ff4444", width: 16, height: 16, cursor: "pointer" }} />
          <label htmlFor="misp-enabled" style={{ color: "rgba(255,255,255,0.65)", fontSize: 12,
            fontFamily: "monospace", cursor: "pointer" }}>
            Enable MISP IOC enrichment on Deep scans
          </label>
        </div>

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
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
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

        {/* Status summary */}
        <div style={{ fontSize: 10, fontFamily: "monospace", color: "rgba(255,255,255,0.25)" }}>
          {misp.enabled && misp.url && misp.apiKey
            ? <span style={{ color: "#ff6b6b" }}>✓ Configured — IOC lookups active on Deep scans</span>
            : misp.enabled
              ? <span style={{ color: "#ff8c00" }}>⚠ URL and API Key required to activate</span>
              : "Disabled — enable above to activate IOC enrichment"}
        </div>
      </div>

      {/* Save */}
      <div style={{ display: "flex", gap: 12, alignItems: "center", marginTop: 20 }}>
        <button onClick={handleSave} disabled={saving}
          style={{ ...BTN(), opacity: saving ? 0.5 : 1 }}>
          {saving ? "Saving…" : "Save MISP Configuration"}
        </button>
        {saved && <span style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace" }}>✓ Saved</span>}
      </div>
    </div>
  );
}

export function SystemSettingsPage() {
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
      {tab === "integrations" && <MispTab />}
      {tab === "env"          && <EnvConfigTab />}
    </div>
  );
}
