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
// License status + upload card
// ════════════════════════════════════════════════════════════════════════════

function LicenseCard() {
  const [info,      setInfo]      = useState(null);
  const [loading,   setLoading]   = useState(true);
  const [uploading, setUploading] = useState(false);
  const [msg,       setMsg]       = useState(null);
  const fileRef = useRef(null);

  const fetchLicense = () => {
    setLoading(true);
    fetch(`${API_BASE}/api/system/license`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => { setInfo(d); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => { fetchLicense(); }, []);

  const handleUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.name.endsWith(".lic")) {
      setMsg({ ok: false, text: "File must be a .lic file" }); return;
    }
    setUploading(true); setMsg(null);
    const body = new FormData();
    body.append("license", file);
    try {
      const r = await fetch(`${API_BASE}/api/system/license/upload`, {
        method: "POST", credentials: "include", body,
      });
      const d = await r.json();
      if (d.ok) { setMsg({ ok: true, text: d.message }); fetchLicense(); }
      else       { setMsg({ ok: false, text: d.error || "Upload failed" }); }
    } catch (ex) { setMsg({ ok: false, text: String(ex) }); }
    finally { setUploading(false); if (fileRef.current) fileRef.current.value = ""; }
  };

  const licType    = info?.type;
  const typeColor  = licType === "full" ? "#00e5a0" : licType === "demo" ? "#ffd93d" : "#ff3b3b";
  const daysLeft   = info?.days_remaining ?? 0;
  const daysColor  = daysLeft <= 5 ? "#ff3b3b" : daysLeft <= 15 ? "#ffd93d" : "#00e5a0";

  return (
    <div style={CARD}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
        <div style={LABEL}>License</div>
        {!loading && info && (
          <span style={{ background: `${typeColor}18`, color: typeColor, border: `1px solid ${typeColor}40`,
            borderRadius: 4, padding: "2px 10px", fontSize: 10, fontFamily: "monospace", letterSpacing: "1px" }}>
            {licType?.toUpperCase() || "UNKNOWN"}
          </span>
        )}
      </div>

      {loading && <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>}

      {!loading && info && (
        <div style={{ display: "flex", gap: 32, flexWrap: "wrap", marginBottom: 16 }}>
          <div>
            <div style={{ ...LABEL, marginBottom: 3 }}>Customer</div>
            <div style={{ color: "rgba(255,255,255,0.8)", fontSize: 12, fontFamily: "monospace" }}>
              {info.customer || "—"}
            </div>
          </div>
          <div>
            <div style={{ ...LABEL, marginBottom: 3 }}>Days Remaining</div>
            <div style={{ color: daysColor, fontSize: 18, fontFamily: "monospace", fontWeight: 700 }}>
              {daysLeft}
            </div>
          </div>
          <div style={{ flex: 1, minWidth: 180 }}>
            <div style={{ ...LABEL, marginBottom: 3 }}>Status</div>
            <div style={{ color: info.valid ? "#00e5a0" : "#ff3b3b", fontSize: 11, fontFamily: "monospace", lineHeight: 1.5 }}>
              {info.valid ? "✓" : "✗"} {info.message || "—"}
            </div>
          </div>
        </div>
      )}

      {/* Upload section */}
      <div style={{ borderTop: "1px solid rgba(255,255,255,0.05)", paddingTop: 14 }}>
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 11, marginBottom: 12, lineHeight: 1.6 }}>
          Received a new <code style={{ color: "#00e5a0", fontFamily: "monospace" }}>.lic</code> file from Cycentra?
          Upload it here — the license activates immediately, no restart required.
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <input ref={fileRef} type="file" accept=".lic" onChange={handleUpload}
            style={{ display: "none" }} id="lic-upload-input" />
          <button onClick={() => fileRef.current?.click()} disabled={uploading}
            style={{ ...BTN(), opacity: uploading ? 0.5 : 1 }}>
            {uploading ? "Applying…" : "Upload License (.lic)"}
          </button>
          {!info?.valid && !loading && (
            <span style={{ color: "#ffd93d", fontSize: 10, fontFamily: "monospace" }}>
              ↑ Apply a full license to unlock all features
            </span>
          )}
        </div>
        {msg && (
          <div style={{ color: msg.ok ? "#00e5a0" : "#ff3b3b", fontSize: 12, fontFamily: "monospace", marginTop: 10 }}>
            {msg.ok ? "✓" : "✗"} {msg.text}
          </div>
        )}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// TAB 1 — Updates
// ════════════════════════════════════════════════════════════════════════════

function UpdatesTab() {
  const [versionData,  setVersionData]  = useState(null);
  const [updating,     setUpdating]     = useState(false);
  const [upgrading,    setUpgrading]    = useState(false);
  const [upgradeConfirm, setUpgradeConfirm] = useState(false);
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
  const _triggerUpgrade = async () => {
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

  // Upgrade: show confirmation modal first, only proceed on confirm
  const handleUpgrade = () => { if (!updating && !upgrading) setUpgradeConfirm(true); };
  const handleUpgradeConfirm = () => { setUpgradeConfirm(false); _triggerUpgrade(); };

  useEffect(() => () => clearInterval(pollRef.current), []);

  const isUpToDate  = latestInfo?.up_to_date === true;
  const updateAvail = latestInfo && !latestInfo.error && !latestInfo.up_to_date && latestInfo.latest;
  const isBusy      = updating || upgrading || checkingVer;

  return (
    <div>
      {/* Upgrade confirmation modal */}
      {upgradeConfirm && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ background: "#13151a", border: "1px solid rgba(255,140,0,0.45)", borderRadius: 8, padding: "28px 32px", width: 460, maxWidth: "90vw" }}>
            <div style={{ color: "#ff8c00", fontSize: 12, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1.5px", marginBottom: 16 }}>⚠ CONFIRM FULL UPGRADE</div>
            <p style={{ color: "rgba(255,255,255,0.7)", fontSize: 13, lineHeight: 1.8, marginBottom: 8 }}>
              This will perform a <span style={{ color: "#ff8c00", fontWeight: 700 }}>full reinstall</span> from the latest release.
            </p>
            <p style={{ color: "#ff3b3b", fontSize: 12, fontFamily: "monospace", lineHeight: 1.7, marginBottom: 24 }}>
              ✗ All custom configuration and existing data will be wiped.<br/>
              ✗ This action cannot be undone.
            </p>
            <div style={{ display: "flex", gap: 12, justifyContent: "flex-end" }}>
              <button onClick={() => setUpgradeConfirm(false)} style={{ ...BTN("#4d9eff") }}>Cancel</button>
              <button onClick={handleUpgradeConfirm} style={{ ...BTN("#ff3b3b") }}>Yes, Wipe &amp; Upgrade</button>
            </div>
          </div>
        </div>
      )}

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

      {/* License status + upload */}
      <LicenseCard />

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
// TAB 5 — User Management (admin only)
// ════════════════════════════════════════════════════════════════════════════

const VALID_ROLES = ["admin", "analyst", "viewer", "cyiris", "cysoar"];
const ROLE_APPS_MAP = {
  admin:   ["cy360", "cysiem", "cyiris", "cysoar", "cyasm"],
  analyst: ["cy360", "cysiem", "cyiris", "cysoar", "cyasm"],
  viewer:  ["cy360", "cysiem"],
  cyiris:  ["cyiris"],
  cysoar:  ["cysoar"],
};
// RFC 5322 simplified: requires local@domain.tld structure
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function UserManagementTab() {
  const [authRole,  setAuthRole]  = useState(null);   // null = loading
  const [authErr,   setAuthErr]   = useState(null);
  const [users,     setUsers]     = useState({});
  const [loading,   setLoading]   = useState(true);
  const [msg,       setMsg]       = useState(null);
  const [newEmail,  setNewEmail]  = useState("");
  const [newRole,   setNewRole]   = useState("viewer");
  const [adding,    setAdding]    = useState(false);

  const showMsg = (ok, text) => {
    setMsg({ ok, text });
    setTimeout(() => setMsg(null), 4000);
  };

  useEffect(() => {
    fetch(`${API_BASE}/api/auth/verify`, { credentials: "include" })
      .then(r => r.json())
      .then(d => {
        const role = d.role || "viewer";
        setAuthRole(role);
        if (role === "admin") {
          return fetch(`${API_BASE}/api/rbac/users`, { credentials: "include" })
            .then(r2 => r2.json())
            .then(d2 => setUsers(d2 || {}));
        }
      })
      .catch(e => { setAuthErr(String(e)); setAuthRole("viewer"); })
      .finally(() => setLoading(false));
  }, []);

  const reloadUsers = () =>
    fetch(`${API_BASE}/api/rbac/users`, { credentials: "include" })
      .then(r => r.json())
      .then(d => setUsers(d || {}));

  const handleRoleChange = async (email, role) => {
    const r = await fetch(`${API_BASE}/api/rbac/users`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, role }),
    });
    if (r.ok) {
      setUsers(prev => ({ ...prev, [email]: { ...prev[email], role } }));
      showMsg(true, `Updated ${email} → ${role}`);
    } else {
      const d = await r.json().catch(() => ({}));
      showMsg(false, d.error || "Update failed");
    }
  };

  const handleDelete = async (email) => {
    if (!window.confirm(`Remove ${email} from RBAC? They will revert to the 'viewer' default.`)) return;
    const r = await fetch(`${API_BASE}/api/rbac/users/${encodeURIComponent(email)}`, {
      method: "DELETE", credentials: "include",
    });
    if (r.ok) {
      setUsers(prev => { const n = { ...prev }; delete n[email]; return n; });
      showMsg(true, `Removed ${email}`);
    } else {
      showMsg(false, "Delete failed");
    }
  };

  const handleAdd = async () => {
    const trimmed = newEmail.trim().toLowerCase();
    if (!trimmed) return;
    if (!EMAIL_RE.test(trimmed)) {
      showMsg(false, "Invalid email address format");
      return;
    }
    setAdding(true);
    const r = await fetch(`${API_BASE}/api/rbac/users`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: trimmed, role: newRole }),
    });
    const d = await r.json().catch(() => ({}));
    if (r.ok) {
      await reloadUsers();
      setNewEmail("");
      setNewRole("viewer");
      showMsg(true, `Added ${trimmed} as ${newRole}`);
    } else {
      showMsg(false, d.error || "Add failed");
    }
    setAdding(false);
  };

  if (loading) {
    return <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 12 }}>Loading…</div>;
  }

  if (authRole !== "admin") {
    return (
      <div style={{ ...CARD, textAlign: "center", padding: "48px 24px" }}>
        <div style={{ fontSize: 32, marginBottom: 12 }}>🔒</div>
        <div style={{ color: "rgba(255,255,255,0.7)", fontFamily: "monospace", fontSize: 14, marginBottom: 6 }}>
          Admin access required
        </div>
        {authErr ? (
          <div style={{ color: "#ff6b6b", fontFamily: "monospace", fontSize: 12 }}>
            Could not verify session: {authErr}
          </div>
        ) : (
          <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 12 }}>
            Only administrators can manage user roles.
          </div>
        )}
      </div>
    );
  }

  const entries = Object.entries(users).sort(([a], [b]) => a.localeCompare(b));

  return (
    <div style={{ maxWidth: 820 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
        <span style={{ fontSize: 18 }}>👤</span>
        <div style={{ color: "rgba(0,229,160,0.9)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700 }}>
          User Management
        </div>
      </div>
      <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, marginBottom: 20, lineHeight: 1.6 }}>
        Manage user roles and portal access. Changes take effect on the user's next request.
      </div>

      {msg && (
        <div style={{ color: msg.ok ? "#00e5a0" : "#ff3b3b", fontSize: 12, fontFamily: "monospace", marginBottom: 14 }}>
          {msg.ok ? "✓" : "✗"} {msg.text}
        </div>
      )}

      {/* User table */}
      <div style={{ ...CARD, padding: 0, overflow: "hidden", marginBottom: 20 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 150px 1fr 90px", gap: 0, padding: "10px 16px", borderBottom: "1px solid rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.02)" }}>
          <span style={{ ...LABEL, marginBottom: 0 }}>Email</span>
          <span style={{ ...LABEL, marginBottom: 0 }}>Role</span>
          <span style={{ ...LABEL, marginBottom: 0 }}>Apps</span>
          <span />
        </div>
        {entries.length === 0 ? (
          <div style={{ padding: "20px 16px", color: "rgba(255,255,255,0.2)", fontFamily: "monospace", fontSize: 12 }}>
            No users configured. Add one below.
          </div>
        ) : (
          entries.map(([email, entry]) => {
            const role = entry.role || "viewer";
            const apps = entry.apps || ROLE_APPS_MAP[role] || [];
            return (
              <div key={email} style={{ display: "grid", gridTemplateColumns: "1fr 150px 1fr 90px", gap: 0, padding: "10px 16px", borderBottom: "1px solid rgba(255,255,255,0.04)", alignItems: "center" }}>
                <span style={{ color: "rgba(255,255,255,0.7)", fontSize: 12, fontFamily: "monospace", wordBreak: "break-all", paddingRight: 8 }}>{email}</span>
                <select
                  value={role}
                  onChange={e => handleRoleChange(email, e.target.value)}
                  style={{ ...INPUT, padding: "4px 8px", fontSize: 11, width: "100%" }}
                >
                  {VALID_ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
                <span style={{ color: "rgba(255,255,255,0.4)", fontSize: 11, fontFamily: "monospace", paddingLeft: 12 }}>
                  {apps.join(", ") || "—"}
                </span>
                <button
                  onClick={() => handleDelete(email)}
                  style={{ background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.3)", color: "#ff6b6b", borderRadius: 3, padding: "4px 10px", fontSize: 10, fontFamily: "monospace", cursor: "pointer", fontWeight: 700, letterSpacing: "0.5px", marginLeft: 8 }}
                >
                  DELETE
                </button>
              </div>
            );
          })
        )}
      </div>

      {/* Add user form */}
      <div style={{ ...CARD }}>
        <div style={{ ...LABEL }}>Add User</div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input
            type="email"
            placeholder="user@example.com"
            value={newEmail}
            onChange={e => setNewEmail(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleAdd()}
            style={{ ...INPUT, flex: 1, minWidth: 220 }}
          />
          <select
            value={newRole}
            onChange={e => setNewRole(e.target.value)}
            style={{ ...INPUT, width: "auto", padding: "8px 12px", flex: "0 0 auto" }}
          >
            {VALID_ROLES.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
          <button
            onClick={handleAdd}
            disabled={adding || !newEmail.trim()}
            style={{ ...BTN(), opacity: adding || !newEmail.trim() ? 0.5 : 1, flexShrink: 0 }}
          >
            {adding ? "Adding…" : "Add User"}
          </button>
        </div>
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
  { id: "cymind",       label: "CyMind" },
  { id: "mcp",          label: "MCP" },
  { id: "env",          label: "Environment Config" },
  { id: "users",        label: "User Management" },
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
        // Backward compat: infer mode when absent
        // - old enabled=true (pre-mode field) → "local"
        // - apiKey present + no url → was saved as cloud (matches get_misp_config() inference)
        // - anything else → "disabled"
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
    if (mode === "cloud") {
      // Credentials are in .env — always delegate to backend
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
    // Local mode
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

  if (loading) return <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 12 }}>Loading…</div>;

  // Mode selector config
  const MODES = [
    { id: "disabled", label: "Disabled",      desc: "No MISP IOC lookups — all enrichment bypassed", icon: "⭕", color: "rgba(255,255,255,0.3)" },
    { id: "cloud",    label: "Cloud CyMISP",  desc: "Connect to Cycentra-managed MISP at cymisp.cycentra.com", icon: "☁️", color: "#4d9eff" },
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

      {/* Mode: Cloud CyMISP — credentials live in .env, no UI input needed */}
      {mode === "cloud" && (
        <div style={{ background: "rgba(77,158,255,0.04)", border: "1px solid rgba(77,158,255,0.2)", borderRadius: 6, padding: "18px 20px" }}>
          <div style={{ color: "#4d9eff", fontSize: 11, fontFamily: "monospace", fontWeight: 700, marginBottom: 4 }}>
            ☁️ Cycentra Cloud MISP — cymisp.cycentra.com
          </div>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", marginBottom: 16, lineHeight: 1.6 }}>
            Credentials are provisioned server-side via <code style={{ color: "#4d9eff" }}>CLOUD_MISP_URL</code> and{" "}
            <code style={{ color: "#4d9eff" }}>CLOUD_MISP_API_KEY</code> in{" "}
            <code style={{ color: "rgba(255,255,255,0.4)" }}>/opt/cycentra/.env</code>. No manual entry required.
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
            <button onClick={testConnection} disabled={testStatus === "testing"}
              style={{ background: "rgba(77,158,255,0.12)", color: "#4d9eff",
                border: "1px solid rgba(77,158,255,0.35)", borderRadius: 4,
                padding: "8px 18px", fontFamily: "monospace", fontSize: 11,
                fontWeight: 700, cursor: "pointer", letterSpacing: "0.5px",
                opacity: testStatus === "testing" ? 0.6 : 1 }}>
              {testStatus === "testing" ? "Testing…" : "Test Connection"}
            </button>
            {testStatus === "ok"   && <span style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace" }}>✓ {testMsg}</span>}
            {testStatus === "fail" && <span style={{ color: "#ff4444", fontSize: 11, fontFamily: "monospace" }}>✗ {testMsg}</span>}
          </div>
          <div style={{ fontSize: 10, fontFamily: "monospace", color: "rgba(255,255,255,0.25)" }}>
            ℹ️ Cloud credentials are set at install time — contact Cycentra support to rotate your key.
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
    if (mode === "cloud") {
      // Credentials are in .env — always delegate to backend
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
    // Local mode
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

      {/* Mode: Cloud CyIRIS — credentials live in .env, no UI input needed */}
      {mode === "cloud" && (
        <div style={{ background: "rgba(77,158,255,0.04)", border: "1px solid rgba(77,158,255,0.2)", borderRadius: 6, padding: "18px 20px" }}>
          <div style={{ color: "#4d9eff", fontSize: 11, fontFamily: "monospace", fontWeight: 700, marginBottom: 4 }}>
            ☁️ Cycentra Cloud CyIRIS — cyiris.cycentra.com
          </div>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", marginBottom: 16, lineHeight: 1.6 }}>
            Credentials are provisioned server-side via <code style={{ color: "#4d9eff" }}>CLOUD_IRIS_URL</code>,{" "}
            <code style={{ color: "#4d9eff" }}>CLOUD_IRIS_API_KEY</code>, and{" "}
            <code style={{ color: "#4d9eff" }}>CLOUD_IRIS_CUSTOMER_ID</code> in{" "}
            <code style={{ color: "rgba(255,255,255,0.4)" }}>/opt/cycentra/.env</code>. No manual entry required.
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
            <button onClick={testConnection} disabled={testStatus === "testing"}
              style={{ background: "rgba(77,158,255,0.12)", color: "#4d9eff",
                border: "1px solid rgba(77,158,255,0.35)", borderRadius: 4,
                padding: "8px 18px", fontFamily: "monospace", fontSize: 11,
                fontWeight: 700, cursor: "pointer", letterSpacing: "0.5px",
                opacity: testStatus === "testing" ? 0.6 : 1 }}>
              {testStatus === "testing" ? "Testing…" : "Test Connection"}
            </button>
            {testStatus === "ok"   && <span style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace" }}>✓ {testMsg}</span>}
            {testStatus === "fail" && <span style={{ color: "#ff4444", fontSize: 11, fontFamily: "monospace" }}>✗ {testMsg}</span>}
          </div>
          <div style={{ fontSize: 10, fontFamily: "monospace", color: "rgba(255,255,255,0.25)" }}>
            ℹ️ Cloud credentials are set at install time — contact Cycentra support to rotate your key.
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
// TAB 5 — MCP Configuration
// ════════════════════════════════════════════════════════════════════════════

function McpTab() {
  const [status,  setStatus]  = useState(null);   // null | {enabled, endpoint, public_url, tools, ...}
  const [loading, setLoading] = useState(true);
  const [loadErr, setLoadErr] = useState(false);
  const [saving,  setSaving]  = useState(false);
  const [msg,     setMsg]     = useState(null);    // {ok, text}
  const [copied,  setCopied]  = useState(false);

  useEffect(() => {
    fetch(`${API_BASE}/api/system/mcp`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setStatus(d); setLoading(false); })
      .catch(() => { setLoadErr(true); setLoading(false); });
  }, []);

  const toggle = async () => {
    if (!status) return;
    setSaving(true); setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/mcp`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !status.enabled }),
      });
      const d = await r.json();
      if (d.ok) {
        setStatus(prev => ({ ...prev, enabled: d.enabled }));
        setMsg({ ok: true, text: d.message });
      } else {
        setMsg({ ok: false, text: d.error || "Failed to update MCP setting" });
      }
    } catch (ex) {
      setMsg({ ok: false, text: String(ex) });
    } finally {
      setSaving(false);
    }
  };

  const copyEndpoint = () => {
    const url = status?.public_url || status?.endpoint || "";
    if (!url) return;
    navigator.clipboard.writeText(url).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  if (loading) return (
    <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 12 }}>Loading…</div>
  );

  if (loadErr || !status) return (
    <div style={{ color: "#ff4444", fontFamily: "monospace", fontSize: 12 }}>
      ✗ Unable to load MCP status — check that the backend is reachable and you have viewer access.
    </div>
  );

  const enabled     = status.enabled;
  const accentColor = enabled ? "#00e5a0" : "rgba(255,255,255,0.3)";
  const tools       = status.tools || [];

  return (
    <div style={{ maxWidth: 720 }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
        <span style={{ fontSize: 18 }}>⚡</span>
        <div style={{ color: "#00e5a0", fontSize: 10, letterSpacing: "1.5px",
          textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700 }}>
          Model Context Protocol (MCP)
        </div>
        <span style={{ marginLeft: 4, background: enabled ? "rgba(0,229,160,0.12)" : "rgba(255,255,255,0.06)",
          color: enabled ? "#00e5a0" : "rgba(255,255,255,0.35)", border: `1px solid ${enabled ? "rgba(0,229,160,0.3)" : "rgba(255,255,255,0.1)"}`,
          borderRadius: 4, padding: "2px 8px", fontSize: 10, fontFamily: "monospace", letterSpacing: "1px" }}>
          {enabled ? "ENABLED" : "DISABLED"}
        </span>
      </div>
      <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, marginBottom: 24, lineHeight: 1.6 }}>
        The Security MCP bridge exposes{" "}
        <strong style={{ color: "rgba(255,255,255,0.5)" }}>{tools.length} SIEM, UEBA, and Wazuh tools</strong>{" "}
        to external AI clients (Claude Desktop, OpenAI Agents SDK, custom LLM toolchains).
        It runs inside the <code style={{ color: "#4d9eff", fontFamily: "monospace" }}>cysiemstack-engine</code>{" "}
        process — no separate service or extra port required.
      </div>

      {/* Enable/Disable toggle */}
      <div style={{ ...CARD, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 16 }}>
        <div>
          <div style={LABEL}>MCP Bridge</div>
          <div style={{ color: "rgba(255,255,255,0.6)", fontSize: 12, fontFamily: "monospace" }}>
            {enabled
              ? "Active — AI clients can connect via SSE transport"
              : "Inactive — restart engine after enabling to activate"}
          </div>
        </div>
        <button onClick={toggle} disabled={saving}
          style={{ background: enabled ? "rgba(255,59,59,0.1)" : "rgba(0,229,160,0.1)",
            color: enabled ? "#ff6b6b" : "#00e5a0",
            border: `1px solid ${enabled ? "rgba(255,59,59,0.35)" : "rgba(0,229,160,0.35)"}`,
            borderRadius: 4, padding: "8px 20px", fontFamily: "monospace", fontSize: 11,
            fontWeight: 700, cursor: saving ? "not-allowed" : "pointer", letterSpacing: "0.5px",
            opacity: saving ? 0.6 : 1 }}>
          {saving ? "Saving…" : enabled ? "Disable MCP" : "Enable MCP"}
        </button>
      </div>

      {msg && (
        <div style={{ marginBottom: 16, fontFamily: "monospace", fontSize: 11,
          color: msg.ok ? "#00e5a0" : "#ff4444" }}>
          {msg.ok ? "✓ " : "✗ "}{msg.text}
        </div>
      )}

      {/* SSE Endpoint */}
      <div style={CARD}>
        <div style={LABEL}>SSE Endpoint</div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
          <code style={{ flex: 1, background: "rgba(0,229,160,0.05)", border: "1px solid rgba(0,229,160,0.15)",
            borderRadius: 4, padding: "8px 12px", color: "#00e5a0", fontFamily: "monospace",
            fontSize: 12, wordBreak: "break-all" }}>
            {status?.public_url || status?.endpoint || "—"}
          </code>
          <button onClick={copyEndpoint}
            style={{ background: "rgba(0,229,160,0.08)", color: "#00e5a0",
              border: "1px solid rgba(0,229,160,0.25)", borderRadius: 4,
              padding: "8px 14px", fontFamily: "monospace", fontSize: 10,
              fontWeight: 700, cursor: "pointer", whiteSpace: "nowrap" }}>
            {copied ? "✓ Copied" : "Copy"}
          </button>
        </div>
        <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
          <div>
            <div style={{ ...LABEL, marginBottom: 2 }}>Transport</div>
            <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace" }}>
              {status?.transport || "SSE (Server-Sent Events)"}
            </div>
          </div>
          <div>
            <div style={{ ...LABEL, marginBottom: 2 }}>Protocol</div>
            <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace" }}>
              {status?.protocol || "MCP 2024-11-05"}
            </div>
          </div>
        </div>
      </div>

      {/* Connection guide */}
      <div style={CARD}>
        <div style={LABEL}>Connect a 3rd-party AI Client</div>

        {/* Claude Desktop */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace",
            fontWeight: 700, marginBottom: 8 }}>Claude Desktop</div>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 11, marginBottom: 6, lineHeight: 1.5 }}>
            Add the following block to your{" "}
            <code style={{ color: "#4d9eff", fontFamily: "monospace" }}>claude_desktop_config.json</code>:
          </div>
          <pre style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 4, padding: "12px 14px", fontFamily: "monospace", fontSize: 11,
            color: "rgba(255,255,255,0.7)", overflowX: "auto", margin: 0, lineHeight: 1.6 }}>{
`{
  "mcpServers": {
    "cycentra-siem": {
      "url": "${status?.public_url || status?.endpoint || "<MCP_ENDPOINT>"}",
      "transport": "sse"
    }
  }
}`
          }</pre>
        </div>

        {/* OpenAI Agents SDK */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace",
            fontWeight: 700, marginBottom: 8 }}>OpenAI Agents SDK / custom Python client</div>
          <pre style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 4, padding: "12px 14px", fontFamily: "monospace", fontSize: 11,
            color: "rgba(255,255,255,0.7)", overflowX: "auto", margin: 0, lineHeight: 1.6 }}>{
`from mcp.client.sse import sse_client

async with sse_client("${status?.public_url || status?.endpoint || "<MCP_ENDPOINT>"}") as (r, w):
    # r = read stream, w = write stream
    ...`
          }</pre>
        </div>

        {/* mcp CLI */}
        <div>
          <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace",
            fontWeight: 700, marginBottom: 8 }}>MCP Inspector / CLI</div>
          <pre style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 4, padding: "12px 14px", fontFamily: "monospace", fontSize: 11,
            color: "rgba(255,255,255,0.7)", overflowX: "auto", margin: 0 }}>{
`npx @modelcontextprotocol/inspector ${status?.public_url || status?.endpoint || "<MCP_ENDPOINT>"}`
          }</pre>
        </div>
      </div>

      {/* Available tools */}
      <div style={CARD}>
        <div style={{ ...LABEL, marginBottom: 14 }}>Available Tools ({tools.length})</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {tools.map(t => (
            <div key={t.name} style={{ display: "flex", gap: 12, alignItems: "flex-start",
              background: "rgba(0,229,160,0.03)", border: "1px solid rgba(0,229,160,0.08)",
              borderRadius: 4, padding: "8px 12px" }}>
              <code style={{ color: accentColor, fontFamily: "monospace", fontSize: 11,
                fontWeight: 700, minWidth: 0, flex: "0 0 auto", maxWidth: "55%", wordBreak: "break-all" }}>
                {t.name}
              </code>
              <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, lineHeight: 1.5 }}>
                {t.description}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Notes */}
      <div style={{ fontSize: 10, fontFamily: "monospace", color: "rgba(255,255,255,0.2)", lineHeight: 1.8 }}>
        ℹ️ The MCP bridge starts automatically when the <code>mcp[cli]</code> package is installed with the engine.
        Changes to MCP_ENABLED take effect after restarting the <code>cysiemstack-engine</code> service.
        Set <code>MCP_ENABLED=false</code> in <code>/opt/cycentra/cysiemstack.env</code> to disable without uninstalling.
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// CyMind Integration Settings tab
// ════════════════════════════════════════════════════════════════════════════

function CyMindIntegrationTab() {
  const [cfg,         setCfg]         = useState({});
  const [loading,     setLoading]     = useState(true);
  const [saving,      setSaving]      = useState(false);
  const [msg,         setMsg]         = useState(null);
  const [url,         setUrl]         = useState("");
  const [newKey,      setNewKey]      = useState(null);      // cymk_... M2M key, shown once
  const [newChatKey,  setNewChatKey]  = useState(null);      // pak_... chat key, shown once
  const [testResults, setTestResults] = useState(null);

  const fetchCfg = () => {
    setLoading(true);
    fetch(`${API_BASE}/api/system/cymind`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (d) { setCfg(d); setUrl(d.cymindUrl || ""); }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => { fetchCfg(); }, []);

  const handleSave = async () => {
    setSaving(true); setMsg(null); setNewKey(null); setNewChatKey(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/cymind`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cymindUrl: url }),
      });
      const d = await r.json();
      if (d.ok) {
        const extra = d.nginxStatus ? ` (${d.nginxStatus})` : "";
        setMsg({ ok: true, text: `Saved.${extra}` });
        fetchCfg();
      } else { setMsg({ ok: false, text: d.error || "Save failed" }); }
    } catch (e) { setMsg({ ok: false, text: String(e) }); }
    finally { setSaving(false); }
  };

  const handleGenKey = async () => {
    setSaving(true); setMsg(null); setNewKey(null); setNewChatKey(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/cymind`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ generateKey: true }),
      });
      const d = await r.json();
      if (d.ok) {
        setNewKey(d.newKey || null);
        setMsg({ ok: true, text: "New M2M key generated. Copy it now." });
        fetchCfg();
      } else { setMsg({ ok: false, text: d.error || "Key generation failed" }); }
    } catch (e) { setMsg({ ok: false, text: String(e) }); }
    finally { setSaving(false); }
  };

  const handleGenChatKey = async () => {
    setSaving(true); setMsg(null); setNewKey(null); setNewChatKey(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/cymind`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ generateChatKey: true }),
      });
      const d = await r.json();
      if (d.ok) {
        setNewChatKey(d.newChatKey || null);
        setMsg({ ok: true, text: "Chat API key generated. Register it in CyMind." });
        fetchCfg();
      } else { setMsg({ ok: false, text: d.error || "Key generation failed" }); }
    } catch (e) { setMsg({ ok: false, text: String(e) }); }
    finally { setSaving(false); }
  };

  const handleTestConn = async () => {
    setMsg({ ok: null, text: "Testing connectivity…" });
    setTestResults(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/cymind/test`, { credentials: "include" });
      const d = await r.json();
      setTestResults(d.results || {});
      setMsg(d.ok
        ? { ok: true,  text: "All systems reachable." }
        : { ok: false, text: "One or more checks failed — see details below." }
      );
    } catch (e) { setMsg({ ok: false, text: String(e) }); }
  };

  if (loading) return <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>;

  return (
    <div>
      <div style={{ ...CARD }}>
        <div style={{ ...LABEL, marginBottom: 14 }}>CyMind RAG-Chat Integration</div>
        <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 12, lineHeight: 1.7, marginBottom: 20 }}>
          Connect CyCentra 360 to your on-prem <strong style={{ color: "rgba(255,255,255,0.6)" }}>CyMind</strong> instance.
          Analysts will see a native chat overlay with live SIEM data via the MCP bridge.
        </div>

        {/* Status badges */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
          <span style={{
            display: "inline-flex", alignItems: "center", gap: 5,
            background: cfg.enabled ? "rgba(0,229,160,0.1)" : "rgba(255,255,255,0.05)",
            border: `1px solid ${cfg.enabled ? "rgba(0,229,160,0.3)" : "rgba(255,255,255,0.12)"}`,
            borderRadius: 4, padding: "3px 10px",
            color: cfg.enabled ? "#00e5a0" : "rgba(255,255,255,0.3)",
            fontSize: 10, fontFamily: "monospace", fontWeight: 700,
          }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "currentColor" }} />
            {cfg.enabled ? "ENABLED" : "DISABLED"}
          </span>
          {cfg.hasKey     && <span style={{ color: "#00e5a0", fontSize: 10, fontFamily: "monospace" }}>✓ M2M key set</span>}
          {cfg.hasChatKey && <span style={{ color: "#00e5a0", fontSize: 10, fontFamily: "monospace" }}>✓ Chat key set</span>}
        </div>

        {/* CyMind URL */}
        <div style={{ marginBottom: 16 }}>
          <div style={LABEL}>CyMind Base URL</div>
          <div style={{ display: "flex", gap: 8 }}>
            <input
              type="url"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://cymind.corp.example.com"
              style={{ ...INPUT, flex: 1 }}
            />
            <button onClick={handleSave} disabled={saving}
              style={{ ...BTN(), opacity: saving ? 0.5 : 1 }}>
              {saving ? "Saving…" : "Save"}
            </button>
          </div>
        </div>

        {/* CyCentra URL hint */}
        <div style={{ marginBottom: 18 }}>
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace", lineHeight: 1.7 }}>
            In CyMind <code style={{ color: "#00e5a0" }}>.env</code> set:<br/>
            <code style={{ color: "rgba(0,229,160,0.7)" }}>CYCENTRA_URL=https://cysoc.cycentra.com</code><br/>
            <code style={{ color: "rgba(0,229,160,0.7)" }}>CYCENTRA_API_KEY=&lt;M2M key below&gt;</code>
          </div>
        </div>

        {/* M2M API key (CyMind → CyCentra MCP) */}
        <div style={{ marginBottom: 16, paddingBottom: 16, borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
          <div style={{ ...LABEL, marginBottom: 8 }}>CyCentra M2M API Key <span style={{ color: "rgba(255,255,255,0.25)", fontWeight: 400 }}>(cymk_... — CyMind reads SIEM data)</span></div>
          <button onClick={handleGenKey} disabled={saving}
            style={{ ...BTN("#4d9eff"), opacity: saving ? 0.5 : 1 }}>
            {cfg.hasKey ? "Rotate M2M Key" : "Generate M2M Key"}
          </button>
          {newKey && (
            <div style={{
              marginTop: 12, background: "rgba(0,229,160,0.06)", border: "1px solid rgba(0,229,160,0.25)",
              borderRadius: 4, padding: "10px 12px",
            }}>
              <div style={{ ...LABEL, marginBottom: 4, color: "#00e5a0", fontSize: 10 }}>New M2M Key — copy now</div>
              <code style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace", userSelect: "all", wordBreak: "break-all" }}>{newKey}</code>
              <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", marginTop: 6 }}>
                Set as <code style={{ color: "rgba(0,229,160,0.6)" }}>CYCENTRA_API_KEY</code> in CyMind's .env, then restart CyMind.
              </div>
            </div>
          )}
        </div>

        {/* Chat API key (CyCentra overlay → CyMind) */}
        <div style={{ marginBottom: 16 }}>
          <div style={{ ...LABEL, marginBottom: 4 }}>Chat API Key <span style={{ color: "rgba(255,255,255,0.25)", fontWeight: 400 }}>(pak_... — portal overlay authenticates to CyMind)</span></div>
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace", lineHeight: 1.6, marginBottom: 8 }}>
            Generate this key, then register it in CyMind as an API key with the <code style={{ color: "rgba(0,229,160,0.6)" }}>analyst</code> role.
          </div>
          <button onClick={handleGenChatKey} disabled={saving}
            style={{ ...BTN("#4d9eff"), opacity: saving ? 0.5 : 1 }}>
            {cfg.hasChatKey ? "Rotate Chat Key" : "Generate Chat Key"}
          </button>
          {newChatKey && (
            <div style={{
              marginTop: 12, background: "rgba(0,229,160,0.06)", border: "1px solid rgba(0,229,160,0.25)",
              borderRadius: 4, padding: "10px 12px",
            }}>
              <div style={{ ...LABEL, marginBottom: 4, color: "#00e5a0", fontSize: 10 }}>New Chat Key — copy now</div>
              <code style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace", userSelect: "all", wordBreak: "break-all" }}>{newChatKey}</code>
              <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", marginTop: 6 }}>
                In CyMind admin: create an API key with this value and the <code style={{ color: "rgba(0,229,160,0.6)" }}>analyst</code> role.
              </div>
            </div>
          )}
        </div>

        {/* Test connection */}
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 0 }}>
          <button onClick={handleTestConn} disabled={saving}
            style={{ ...BTN("#4d9eff"), opacity: saving ? 0.5 : 1 }}>
            Test Connectivity
          </button>
        </div>

        {/* Test results */}
        {testResults && (
          <div style={{
            marginTop: 12, background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 4, padding: "10px 12px", display: "flex", flexDirection: "column", gap: 6,
          }}>
            {Object.entries(testResults).map(([key, val]) => (
              <div key={key} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ color: val.ok ? "#00e5a0" : "#ff6b6b", fontSize: 12 }}>{val.ok ? "✓" : "✗"}</span>
                <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", minWidth: 80 }}>
                  {key === "cymind" ? "CyMind" : key === "mcp_engine" ? "MCP Engine" : "Chat Key"}
                </span>
                <span style={{ color: val.ok ? "rgba(255,255,255,0.5)" : "#ff6b6b", fontSize: 11, fontFamily: "monospace" }}>
                  {val.msg}
                </span>
              </div>
            ))}
          </div>
        )}

        {msg && (
          <div style={{ color: msg.ok === true ? "#00e5a0" : msg.ok === false ? "#ff3b3b" : "#ffd93d",
            fontSize: 12, fontFamily: "monospace", marginTop: 12 }}>
            {msg.ok === true ? "✓" : msg.ok === false ? "✗" : "⋯"} {msg.text}
          </div>
        )}
      </div>

      {/* Quick-start checklist */}
      <div style={{ ...CARD }}>
        <div style={{ ...LABEL, marginBottom: 14 }}>Setup Checklist</div>
        {[
          { done: !!cfg.cymindUrl, text: "Set CyMind base URL (above)" },
          { done: cfg.hasKey,      text: "Generate M2M key and set CYCENTRA_API_KEY in CyMind .env" },
          { done: cfg.hasChatKey,  text: "Generate chat key and register it in CyMind as an API key" },
          { done: !!cfg.cymindUrl, text: "Set CYCENTRA_URL=https://cysoc.cycentra.com in CyMind .env" },
          { done: false,           text: "Set CYCENTRA_ORIGIN in CyMind .env, then restart CyMind" },
        ].map((item, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 0",
            borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
            <span style={{ color: item.done ? "#00e5a0" : "rgba(255,255,255,0.2)", fontSize: 14 }}>
              {item.done ? "✓" : "○"}
            </span>
            <span style={{ color: item.done ? "rgba(255,255,255,0.6)" : "rgba(255,255,255,0.35)",
              fontSize: 12, fontFamily: "monospace",
              textDecoration: item.done ? "line-through" : "none" }}>
              {item.text}
            </span>
          </div>
        ))}
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
      {tab === "cymind"       && <CyMindIntegrationTab />}
      {tab === "mcp"          && <McpTab />}
      {tab === "env"          && <EnvConfigTab />}
      {tab === "users"        && <UserManagementTab />}
    </div>
  );
}
