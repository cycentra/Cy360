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
import { API_BASE, CYSCAN_URL } from "../../core/constants.js";
import { getSavedUser } from "../../core/auth.js";
import { SSOTab } from "./SSOTab.jsx";

// ── Shared style constants ────────────────────────────────────────────────────
const CARD  = { background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "20px 24px", marginBottom: 20 };

// ── Collapsible section wrapper (collapsed by default) ───────────────────────
function CollapsibleSection({ icon, title, badge, children, initialOpen = false }) {
  const [open, setOpen] = useState(initialOpen);
  return (
    <div style={{ ...CARD, padding: 0, marginBottom: 20 }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{ display: "flex", alignItems: "center", gap: 10, padding: "16px 24px", cursor: "pointer", userSelect: "none", borderBottom: open ? "1px solid rgba(255,255,255,0.06)" : "none" }}
      >
        {icon && <span style={{ fontSize: 18 }}>{icon}</span>}
        <div style={{ flex: 1, color: "rgba(0,229,160,0.9)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700 }}>
          {title}
        </div>
        {badge}
        <span style={{ color: "rgba(255,255,255,0.62)", fontSize: 13, fontFamily: "monospace", lineHeight: 1, marginLeft: 8 }}>{open ? "▲" : "▼"}</span>
      </div>
      {open && <div style={{ padding: "20px 24px" }}>{children}</div>}
    </div>
  );
}
const LABEL = { color: "rgba(255,255,255,0.62)", fontSize: 10, letterSpacing: "1.5px", fontFamily: "monospace", textTransform: "uppercase", marginBottom: 6 };
const INPUT = { background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 4, color: "white", fontFamily: "monospace", fontSize: 12, padding: "8px 12px", width: "100%", outline: "none", boxSizing: "border-box" };
const BTN   = (color="#00e5a0") => ({ background: `rgba(${color === "#00e5a0" ? "0,229,160" : "77,158,255"},0.1)`, color, border: `1px solid ${color}40`, padding: "8px 18px", borderRadius: 4, fontFamily: "monospace", fontSize: 11, fontWeight: 700, letterSpacing: "1px", cursor: "pointer", textTransform: "uppercase" });

// ── ENV targets ───────────────────────────────────────────────────────────────
const ENV_TARGETS = [
  { id: "global",      label: "Global (.env)",        desc: "Core platform config: domain, OAuth, ports" },
  { id: "cysiemstack", label: "CySIEM Stack",          desc: "Wazuh, Redis, PostgreSQL, MISP settings" },
  { id: "cysoar",      label: "CySOAR",                desc: "SOAR / Node-RED automation settings" },
];

// ════════════════════════════════════════════════════════════════════════════
// License status + upload card
// ════════════════════════════════════════════════════════════════════════════

function LicenseCard({ noCard = false }) {
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
    <div style={noCard ? {} : CARD}>
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
    // Cleanup update-log poll on unmount (e.g. user switches tabs mid-update)
    return () => { clearInterval(pollRef.current); };
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

      <CollapsibleSection icon="🔄" title="Current Version" initialOpen={true}>
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
      </CollapsibleSection>

      <CollapsibleSection icon="🔑" title="License">
        <LicenseCard noCard />
      </CollapsibleSection>

      <CollapsibleSection icon="⚡" title="Update / Upgrade">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>

          {/* Run Update */}
          <div style={{ background: "rgba(0,229,160,0.03)", border: "1px solid rgba(0,229,160,0.12)", borderRadius: 5, padding: "18px 20px" }}>
            <div style={{ color: "#00e5a0", fontSize: 10, letterSpacing: "1.5px", fontFamily: "monospace", fontWeight: 700, marginBottom: 8 }}>
              RUN UPDATE
            </div>
            <p style={{ color: "rgba(255,255,255,0.62)", fontSize: 12, marginBottom: 16, lineHeight: 1.6 }}>
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
            <p style={{ color: "rgba(255,255,255,0.62)", fontSize: 12, marginBottom: 16, lineHeight: 1.6 }}>
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

        <div style={{ marginTop: 14, color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace" }}>
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
      </CollapsibleSection>

      <CollapsibleSection icon="📋" title="Release Notes">
        {!versionData?.release_notes?.length && (
          <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 12, fontFamily: "monospace" }}>
            No release notes found.
          </div>
        )}
        {versionData?.release_notes?.map((rn, i) => (
          <div key={i} style={{ borderBottom: i < versionData.release_notes.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none", paddingBottom: 16, marginBottom: 16 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <span style={{ color: "#00e5a0", fontFamily: "monospace", fontSize: 13, fontWeight: 700 }}>{rn.version}</span>
              {rn.date && <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace" }}>{rn.date}</span>}
            </div>
            <pre style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace", whiteSpace: "pre-wrap", margin: 0, lineHeight: 1.7 }}>
              {rn.notes || "No details."}
            </pre>
          </div>
        ))}
      </CollapsibleSection>
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
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.65)", borderRadius: 3, padding: "4px 8px", fontSize: 10, fontFamily: "monospace", cursor: "pointer", flexShrink: 0 }}>
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

const VALID_ROLES = ["admin", "analyst", "viewer", "cysoar"];
const ROLE_APPS_MAP = {
  admin:   ["cy360", "cysiem", "cysoar", "cyasm"],
  analyst: ["cy360", "cysiem", "cysoar", "cyasm"],
  viewer:  ["cy360", "cysiem"],
  cysoar:  ["cysoar"],
};
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Approval status badge styles
const STATUS_STYLE = {
  approved: { bg: "rgba(0,229,160,0.1)",  color: "#00e5a0", border: "rgba(0,229,160,0.3)",  label: "APPROVED" },
  pending:  { bg: "rgba(255,165,0,0.12)", color: "#ffa500", border: "rgba(255,165,0,0.35)", label: "PENDING"  },
  rejected: { bg: "rgba(255,59,59,0.1)",  color: "#ff6b6b", border: "rgba(255,59,59,0.3)",  label: "REJECTED" },
};

function UserManagementTab() {
  const [authRole,  setAuthRole]  = useState(null);
  const [authErr,   setAuthErr]   = useState(null);
  const [users,     setUsers]     = useState({});
  const [loading,   setLoading]   = useState(true);
  const [msg,       setMsg]       = useState(null);
  const [filter,    setFilter]    = useState("all"); // all | approved | pending | rejected | local
  const [newEmail,    setNewEmail]    = useState("");
  const [newRole,     setNewRole]     = useState("viewer");
  const [newAuthType, setNewAuthType] = useState("sso");
  const [newPassword, setNewPassword] = useState("");
  const [adding,      setAdding]      = useState(false);
  const [resetFor,     setResetFor]     = useState(null);
  const [resetPw,      setResetPw]      = useState("");
  const [resetLoading, setResetLoading] = useState(false);
  const [approving,    setApproving]    = useState(null); // email being approved
  const [rejectFor,    setRejectFor]    = useState(null); // email open for rejection
  const [rejectReason, setRejectReason] = useState("");

  const showMsg = (ok, text) => {
    setMsg({ ok, text });
    setTimeout(() => setMsg(null), 5000);
  };

  const reloadUsers = () =>
    fetch(`${CYSCAN_URL}/api/rbac/users`, { credentials: "include" })
      .then(r => {
        if (!r.ok) throw new Error(`Server returned ${r.status}`);
        return r.json();
      })
      .then(d => {
        if (d && d.error) throw new Error(d.error);
        setUsers(d || {});
        setAuthErr(null);
      })
      .catch(e => setAuthErr(String(e)));

  useEffect(() => {
    const saved = getSavedUser();
    const role = saved?.role || "viewer";
    setAuthRole(role);
    if (role === "admin") {
      fetch(`${CYSCAN_URL}/api/rbac/users`, { credentials: "include" })
        .then(r => {
          if (!r.ok) throw new Error(`Server returned ${r.status} — check backend logs`);
          return r.json();
        })
        .then(d => {
          if (d && d.error) throw new Error(d.error);
          setUsers(d || {});
        })
        .catch(e => setAuthErr(String(e)))
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const handleRoleChange = async (email, role) => {
    const r = await fetch(`${CYSCAN_URL}/api/rbac/users`, {
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
    if (!window.confirm(`Remove ${email}? They will no longer be able to log in.`)) return;
    const r = await fetch(`${CYSCAN_URL}/api/rbac/users/${encodeURIComponent(email)}`, {
      method: "DELETE", credentials: "include",
    });
    if (r.ok) {
      setUsers(prev => { const n = { ...prev }; delete n[email]; return n; });
      showMsg(true, `Removed ${email}`);
    } else {
      showMsg(false, "Delete failed");
    }
  };

  const handleApprove = async (email) => {
    setApproving(email);
    const r = await fetch(`${CYSCAN_URL}/api/sso/approve/${encodeURIComponent(email)}`, {
      method: "POST", credentials: "include",
    });
    const d = await r.json().catch(() => ({}));
    setApproving(null);
    if (r.ok) {
      setUsers(prev => ({ ...prev, [email]: { ...prev[email], approval_status: "approved" } }));
      showMsg(true, `Approved ${email} — they can now log in`);
    } else {
      showMsg(false, d.error || "Approval failed");
    }
  };

  const handleRevoke = async (email) => {
    if (!window.confirm(`Revoke approval for ${email}? They will be blocked until re-approved.`)) return;
    const r = await fetch(`${CYSCAN_URL}/api/sso/revoke/${encodeURIComponent(email)}`, {
      method: "POST", credentials: "include",
    });
    const d = await r.json().catch(() => ({}));
    if (r.ok) {
      setUsers(prev => ({ ...prev, [email]: { ...prev[email], approval_status: "pending" } }));
      showMsg(true, `Revoked approval for ${email} — they will be blocked on next login`);
    } else {
      showMsg(false, d.error || "Revoke failed");
    }
  };

  const handleReject = async (email) => {
    setRejectFor(null);
    const r = await fetch(`${CYSCAN_URL}/api/sso/reject/${encodeURIComponent(email)}`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: rejectReason }),
    });
    const d = await r.json().catch(() => ({}));
    setRejectReason("");
    if (r.ok) {
      setUsers(prev => ({ ...prev, [email]: { ...prev[email], approval_status: "rejected", rejection_reason: rejectReason } }));
      showMsg(true, `Rejected ${email}`);
    } else {
      showMsg(false, d.error || "Rejection failed");
    }
  };

  const handleAdd = async () => {
    const trimmed = newEmail.trim().toLowerCase();
    if (!trimmed) return;
    if (!EMAIL_RE.test(trimmed)) { showMsg(false, "Invalid email address format"); return; }
    if (newAuthType === "local" && !newPassword.trim()) { showMsg(false, "Password is required for local accounts"); return; }
    setAdding(true);
    const payload = { email: trimmed, role: newRole, auth_type: newAuthType };
    if (newAuthType === "local") payload.password = newPassword;
    const r = await fetch(`${CYSCAN_URL}/api/rbac/users`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const d = await r.json().catch(() => ({}));
    if (r.ok) {
      await reloadUsers();
      setNewEmail(""); setNewRole("viewer"); setNewAuthType("sso"); setNewPassword("");
      showMsg(true, `Added ${trimmed} as ${newRole} (${newAuthType})`);
    } else {
      showMsg(false, d.error || "Add failed");
    }
    setAdding(false);
  };

  const handleResetPassword = async (email) => {
    if (resetPw.trim().length < 8) { showMsg(false, "Password must be at least 8 characters"); return; }
    setResetLoading(true);
    const r = await fetch(`${CYSCAN_URL}/api/rbac/users/${encodeURIComponent(email)}/reset-password`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: resetPw }),
    });
    const d = await r.json().catch(() => ({}));
    setResetLoading(false);
    if (r.ok) { setResetFor(null); setResetPw(""); showMsg(true, `Password updated for ${email}`); }
    else showMsg(false, d.error || "Password reset failed");
  };

  if (loading) return (
    <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 12, padding: 20 }}>Loading…</div>
  );

  if (authRole !== "admin") return (
    <div style={{ ...CARD, textAlign: "center", padding: "48px 24px" }}>
      <div style={{ fontSize: 32, marginBottom: 12 }}>🔒</div>
      <div style={{ color: "rgba(255,255,255,0.7)", fontFamily: "monospace", fontSize: 14, marginBottom: 6 }}>Admin access required</div>
      {authErr
        ? <div style={{ color: "#ff6b6b", fontFamily: "monospace", fontSize: 12 }}>Could not verify session: {authErr}</div>
        : <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 12 }}>Only administrators can manage user roles.</div>
      }
    </div>
  );

  // ── Stats ───────────────────────────────────────────────────────────────────
  const allEntries = Object.entries(users);
  const totalCount    = allEntries.length;
  const pendingCount  = allEntries.filter(([, e]) => (e.approval_status || "approved") === "pending").length;
  const approvedCount = allEntries.filter(([, e]) => (e.approval_status || "approved") === "approved").length;
  const localCount    = allEntries.filter(([, e]) => e.auth_type === "local").length;
  const ssoCount      = allEntries.filter(([, e]) => e.auth_type !== "local").length;
  const roleCounts    = VALID_ROLES.reduce((acc, r) => {
    acc[r] = allEntries.filter(([, e]) => e.role === r).length;
    return acc;
  }, {});

  // ── Filter ──────────────────────────────────────────────────────────────────
  const filtered = allEntries
    .filter(([, e]) => {
      const status = e.approval_status || "approved";
      if (filter === "pending")  return status === "pending";
      if (filter === "approved") return status === "approved";
      if (filter === "rejected") return status === "rejected";
      if (filter === "local")    return e.auth_type === "local";
      return true;
    })
    .sort(([a], [b]) => a.localeCompare(b));

  const FILTER_TABS = [
    { id: "all",      label: `All (${totalCount})` },
    { id: "approved", label: `Approved (${approvedCount})` },
    { id: "pending",  label: `Pending (${pendingCount})`, highlight: pendingCount > 0 },
    { id: "local",    label: `Local (${localCount})` },
  ];

  return (
    <div style={{ maxWidth: 900 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
        <span style={{ fontSize: 18 }}>👤</span>
        <div style={{ color: "rgba(0,229,160,0.9)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700 }}>
          User Management
        </div>
        <button onClick={reloadUsers} style={{ marginLeft: "auto", background: "rgba(0,229,160,0.08)", border: "1px solid rgba(0,229,160,0.4)", color: "#00e5a0", borderRadius: 4, padding: "4px 12px", fontSize: 10, fontFamily: "monospace", cursor: "pointer", fontWeight: 700, letterSpacing: "0.8px" }}>
          ↻ REFRESH
        </button>
      </div>

      {/* API error banner (shown to admins when backend call fails) */}
      {authErr && (
        <div style={{ background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.3)", borderRadius: 6, padding: "10px 14px", marginBottom: 14, color: "#ff6b6b", fontSize: 11, fontFamily: "monospace" }}>
          ⚠ Could not load users: {authErr}
          <button onClick={reloadUsers} style={{ marginLeft: 12, background: "none", border: "1px solid rgba(255,59,59,0.4)", color: "#ff6b6b", borderRadius: 3, padding: "2px 8px", fontSize: 10, cursor: "pointer", fontFamily: "monospace" }}>Retry</button>
        </div>
      )}

      {/* Stats row */}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 16 }}>
        {[
          { label: "Total users",     value: totalCount,    color: "rgba(255,255,255,0.6)" },
          { label: "SSO",             value: ssoCount,      color: "#4d9eff" },
          { label: "Local",           value: localCount,    color: "#00e5a0" },
          { label: "Pending approval",value: pendingCount,  color: pendingCount > 0 ? "#ffa500" : "rgba(255,255,255,0.3)" },
          ...VALID_ROLES.filter(r => roleCounts[r] > 0).map(r => ({ label: r, value: roleCounts[r], color: "rgba(255,255,255,0.62)" })),
        ].map(stat => (
          <div key={stat.label} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 6, padding: "8px 14px", display: "flex", flexDirection: "column", alignItems: "center", minWidth: 80 }}>
            <span style={{ color: stat.color, fontSize: 20, fontWeight: 700, fontFamily: "monospace" }}>{stat.value}</span>
            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.8px", marginTop: 2 }}>{stat.label}</span>
          </div>
        ))}
      </div>

      {msg && (
        <div style={{ color: msg.ok ? "#00e5a0" : "#ff3b3b", fontSize: 12, fontFamily: "monospace", marginBottom: 14 }}>
          {msg.ok ? "✓" : "✗"} {msg.text}
        </div>
      )}

      {/* Filter tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 12 }}>
        {FILTER_TABS.map(f => (
          <button
            key={f.id}
            onClick={() => setFilter(f.id)}
            style={{
              background: filter === f.id ? "rgba(0,229,160,0.12)" : "rgba(255,255,255,0.03)",
              border: `1px solid ${filter === f.id ? "rgba(0,229,160,0.4)" : "rgba(255,255,255,0.08)"}`,
              color: filter === f.id ? "#00e5a0" : (f.highlight ? "#ffa500" : "rgba(255,255,255,0.4)"),
              borderRadius: 4, padding: "5px 12px", fontSize: 11, fontFamily: "monospace", cursor: "pointer", fontWeight: filter === f.id ? 700 : 400,
            }}
          >{f.label}</button>
        ))}
      </div>

      {/* User table */}
      <div style={{ ...CARD, padding: 0, overflow: "hidden", marginBottom: 20 }}>
        {/* Table header */}
        <div style={{ display: "grid", gridTemplateColumns: "120px minmax(0,1fr) 58px 90px 110px 175px", gap: 0, padding: "8px 16px", borderBottom: "1px solid rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.02)" }}>
          {["Name", "Email", "Auth", "Status", "Role", "Actions"].map(h => (
            <span key={h} style={{ ...LABEL, marginBottom: 0, fontSize: 9 }}>{h}</span>
          ))}
        </div>

        {filtered.length === 0 ? (
          <div style={{ padding: "24px 16px", color: "rgba(255,255,255,0.2)", fontFamily: "monospace", fontSize: 12 }}>
            {filter === "all" ? "No users yet. Add one below." : `No ${filter} users.`}
          </div>
        ) : filtered.map(([email, entry]) => {
          const role       = entry.role || "viewer";
          const authType   = entry.auth_type || "sso";
          const isLocal    = authType === "local";
          const status     = entry.approval_status || "approved";
          const statusCfg  = STATUS_STYLE[status] || STATUS_STYLE.approved;
          const displayName = entry.name || "";
          const isPending  = status === "pending";
          const rowBg      = isPending ? "rgba(255,165,0,0.03)" : "transparent";

          return (
            <div key={email}>
              <div style={{ display: "grid", gridTemplateColumns: "120px minmax(0,1fr) 58px 90px 110px 175px", gap: 0, padding: "10px 16px", borderBottom: "1px solid rgba(255,255,255,0.04)", alignItems: "center", background: rowBg }}>
                {/* Name */}
                <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", paddingRight: 6 }} title={displayName}>
                  {displayName || <span style={{ color: "rgba(255,255,255,0.2)" }}>—</span>}
                </span>
                {/* Email */}
                <span style={{ color: "rgba(255,255,255,0.75)", fontSize: 11, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", paddingRight: 10 }} title={email}>{email}</span>
                {/* Auth badge */}
                <span>
                  <span style={{ fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "0.5px", padding: "2px 5px", borderRadius: 3,
                    background: isLocal ? "rgba(0,229,160,0.1)" : "rgba(77,158,255,0.1)",
                    color:      isLocal ? "#00e5a0" : "#4d9eff",
                    border: `1px solid ${isLocal ? "rgba(0,229,160,0.3)" : "rgba(77,158,255,0.3)"}`,
                  }}>{isLocal ? "LOCAL" : "SSO"}</span>
                </span>
                {/* Approval status badge */}
                <span>
                  <span style={{ fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "0.5px", padding: "2px 6px", borderRadius: 3,
                    background: statusCfg.bg, color: statusCfg.color, border: `1px solid ${statusCfg.border}`,
                  }}>{statusCfg.label}</span>
                </span>
                {/* Role selector */}
                <select
                  value={role}
                  onChange={e => handleRoleChange(email, e.target.value)}
                  disabled={isPending}
                  style={{ ...INPUT, padding: "4px 8px", fontSize: 11, width: "100%", opacity: isPending ? 0.45 : 1 }}
                >
                  {VALID_ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
                {/* Actions */}
                <div style={{ display: "flex", gap: 4, flexWrap: "nowrap", alignItems: "center" }}>
                  {isPending ? (
                    <>
                      <button
                        onClick={() => handleApprove(email)}
                        disabled={approving === email}
                        style={{ background: "rgba(0,229,160,0.12)", border: "1px solid rgba(0,229,160,0.4)", color: "#00e5a0", borderRadius: 3, padding: "4px 8px", fontSize: 10, fontFamily: "monospace", cursor: "pointer", fontWeight: 700, letterSpacing: "0.5px", opacity: approving === email ? 0.5 : 1 }}
                      >
                        {approving === email ? "…" : "✓ APPROVE"}
                      </button>
                      <button
                        onClick={() => { setRejectFor(rejectFor === email ? null : email); setRejectReason(""); }}
                        style={{ background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.3)", color: "#ff6b6b", borderRadius: 3, padding: "4px 8px", fontSize: 10, fontFamily: "monospace", cursor: "pointer", fontWeight: 700, letterSpacing: "0.5px" }}
                      >
                        {rejectFor === email ? "✕" : "✗ REJECT"}
                      </button>
                    </>
                  ) : (
                    <>
                      {/* Revoke approval for non-local (SSO) approved users */}
                      {!isLocal && status === "approved" && (
                        <button
                          onClick={() => handleRevoke(email)}
                          style={{ background: "rgba(255,165,0,0.06)", border: "1px solid rgba(255,165,0,0.25)", color: "#ffa500", borderRadius: 3, padding: "4px 8px", fontSize: 10, fontFamily: "monospace", cursor: "pointer", fontWeight: 700, letterSpacing: "0.5px", whiteSpace: "nowrap" }}
                          title="Set this user back to pending — they will be blocked on next login"
                        >
                          REVOKE
                        </button>
                      )}
                      {isLocal && (
                        <button
                          onClick={() => { setResetFor(resetFor === email ? null : email); setResetPw(""); }}
                          style={{ background: resetFor === email ? "rgba(255,165,0,0.15)" : "rgba(255,165,0,0.06)", border: `1px solid rgba(255,165,0,${resetFor === email ? "0.5" : "0.25"})`, color: "#ffa500", borderRadius: 3, padding: "4px 8px", fontSize: 10, fontFamily: "monospace", cursor: "pointer", fontWeight: 700, letterSpacing: "0.5px", whiteSpace: "nowrap" }}
                        >
                          {resetFor === email ? "✕ CANCEL" : "RESET PW"}
                        </button>
                      )}
                      <button
                        onClick={() => handleDelete(email)}
                        style={{ background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.3)", color: "#ff6b6b", borderRadius: 3, padding: "4px 10px", fontSize: 10, fontFamily: "monospace", cursor: "pointer", fontWeight: 700, letterSpacing: "0.5px" }}
                      >
                        DELETE
                      </button>
                    </>
                  )}
                </div>
              </div>

              {/* Reject reason form */}
              {rejectFor === email && (
                <div style={{ padding: "10px 16px 14px", borderBottom: "1px solid rgba(255,255,255,0.04)", background: "rgba(255,59,59,0.03)" }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <input
                      placeholder="Rejection reason (optional)"
                      value={rejectReason}
                      onChange={e => setRejectReason(e.target.value)}
                      onKeyDown={e => e.key === "Enter" && handleReject(email)}
                      style={{ ...INPUT, flex: 1 }}
                      autoFocus
                    />
                    <button
                      onClick={() => handleReject(email)}
                      style={{ background: "rgba(255,59,59,0.12)", color: "#ff6b6b", border: "1px solid rgba(255,59,59,0.4)", borderRadius: 3, padding: "8px 14px", fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer", letterSpacing: "0.5px", whiteSpace: "nowrap" }}
                    >
                      Confirm Reject
                    </button>
                  </div>
                </div>
              )}

              {/* Password reset form */}
              {resetFor === email && (
                <div style={{ padding: "10px 16px 14px", borderBottom: "1px solid rgba(255,255,255,0.04)", background: "rgba(255,165,0,0.03)" }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <input
                      type="password"
                      placeholder="New password (min 8 characters)"
                      value={resetPw}
                      onChange={e => setResetPw(e.target.value)}
                      onKeyDown={e => e.key === "Enter" && handleResetPassword(email)}
                      style={{ ...INPUT, flex: 1 }}
                      autoComplete="new-password"
                    />
                    <button
                      onClick={() => handleResetPassword(email)}
                      disabled={resetLoading || resetPw.trim().length < 8}
                      style={{ background: "rgba(255,165,0,0.12)", color: "#ffa500", border: "1px solid rgba(255,165,0,0.4)", borderRadius: 3, padding: "8px 14px", fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer", letterSpacing: "0.5px", opacity: resetLoading || resetPw.trim().length < 8 ? 0.5 : 1, whiteSpace: "nowrap" }}
                    >
                      {resetLoading ? "Saving…" : "Set Password"}
                    </button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Add user form */}
      <div style={{ ...CARD }}>
        <div style={{ ...LABEL }}>Add User</div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: newAuthType === "local" ? 8 : 0 }}>
          <input
            type="email"
            placeholder="user@example.com"
            value={newEmail}
            onChange={e => setNewEmail(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleAdd()}
            style={{ ...INPUT, flex: 1, minWidth: 220 }}
          />
          <select value={newRole} onChange={e => setNewRole(e.target.value)} style={{ ...INPUT, width: "auto", padding: "8px 12px", flex: "0 0 auto" }}>
            {VALID_ROLES.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
          <select value={newAuthType} onChange={e => { setNewAuthType(e.target.value); setNewPassword(""); }} style={{ ...INPUT, width: "auto", padding: "8px 12px", flex: "0 0 auto" }}>
            <option value="sso">SSO</option>
            <option value="local">Local</option>
          </select>
          <button onClick={handleAdd} disabled={adding || !newEmail.trim()} style={{ ...BTN(), opacity: adding || !newEmail.trim() ? 0.5 : 1, flexShrink: 0 }}>
            {adding ? "Adding…" : "Add User"}
          </button>
        </div>
        {newAuthType === "local" && (
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 8 }}>
            <input
              type="password"
              placeholder="Initial password"
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleAdd()}
              style={{ ...INPUT, flex: 1, minWidth: 220 }}
              autoComplete="new-password"
            />
            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 11, fontFamily: "monospace" }}>
              Required for local accounts — stored as bcrypt hash
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// Main page
// ════════════════════════════════════════════════════════════════════════════

const TABS = [
  { id: "updates",   label: "Updates & Version" },
  { id: "env",       label: "Environment Config" },
  { id: "scheduler", label: "Scheduler" },
  { id: "users",     label: "Users & Auth" },
  { id: "backup",    label: "Backup & Restore" },
];


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
              <span style={{ color: "rgba(255,255,255,0.62)", fontSize: 11, lineHeight: 1.5 }}>
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

// CyMind IP is fixed — not user-configurable
const CYMIND_URL = "http://172.16.0.2:8080";

function CyMindIntegrationTab() {
  const [cfg,         setCfg]         = useState({});
  const [loading,     setLoading]     = useState(true);
  const [saving,      setSaving]      = useState(false);
  const [msg,         setMsg]         = useState(null);
  const [testResults, setTestResults] = useState(null);
  const [mcpStatus,   setMcpStatus]   = useState(null);

  // Enable form
  const [adminEmail,  setAdminEmail]  = useState("");
  const [adminPw,     setAdminPw]     = useState("");
  const [showAdvanced,setShowAdvanced]= useState(false);

  // Advanced: manual M2M key rotation or manual chat key paste
  const [newKey,      setNewKey]      = useState(null);
  const [chatKeyInput,setChatKeyInput]= useState("");

  // MCP API Keys (3rd-party)
  const [mcpKeys,       setMcpKeys]       = useState([]);
  const [mcpKeysEp,     setMcpKeysEp]     = useState("");
  const [mcpKeysLoading,setMcpKeysLoading]= useState(false);
  const [newKeyName,    setNewKeyName]    = useState("");
  const [newKeyDesc,    setNewKeyDesc]    = useState("");
  const [genKeyResult,  setGenKeyResult]  = useState(null);   // {key, name} shown once
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

  // ── One-click enable ───────────────────────────────────────────────────────
  const handleEnable = async () => {
    if (!adminEmail.trim() || !adminPw.trim()) { setMsg({ ok: false, text: "Enter CyMind admin email and password." }); return; }
    setSaving(true); setMsg({ ok: null, text: "Connecting to CyMind and provisioning service account…" });
    try {
      const r = await fetch(`${API_BASE}/api/system/cymind/enable`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          cymindAdminEmail:    adminEmail.trim(),
          cymindAdminPassword: adminPw,
        }),
      });
      const d = await r.json();
      if (d.ok) {
        setAdminPw("");  // clear password from state
        setMsg({ ok: true, text: "Integration enabled. The green brain FAB will appear for analyst/admin users." });
        fetchCfg();
      } else { setMsg({ ok: false, text: d.error || "Enable failed" }); }
    } catch (e) { setMsg({ ok: false, text: String(e) }); }
    finally { setSaving(false); }
  };

  // ── Disable ────────────────────────────────────────────────────────────────
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

  // ── Advanced: manual M2M key rotation ─────────────────────────────────────
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

  // ── Advanced: manual chat key paste ───────────────────────────────────────
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

  // ── MCP API key generation ─────────────────────────────────────────────────
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
      const r = await fetch(`${API_BASE}/api/system/mcp/keys/${keyId}`, {
        method: "DELETE", credentials: "include",
      });
      const d = await r.json();
      if (d.ok) { setMcpKeyMsg({ ok: true, text: `Key "${keyName}" revoked.` }); fetchMcpKeys(); }
      else { setMcpKeyMsg({ ok: false, text: d.error || "Revoke failed" }); }
    } catch (e) { setMcpKeyMsg({ ok: false, text: String(e) }); }
  };

  // ── Connectivity test ──────────────────────────────────────────────────────
  const handleTestConn = async () => {
    setMsg({ ok: null, text: "Testing connectivity…" }); setTestResults(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/cymind/test`, { credentials: "include" });
      const d = await r.json();
      setTestResults(d.results || {});
      setMsg(d.ok ? { ok: true, text: "All systems reachable." } : { ok: false, text: "One or more checks failed — see details below." });
    } catch (e) { setMsg({ ok: false, text: String(e) }); }
  };

  if (loading) return <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>;

  const isEnabled = cfg.enabled && cfg.hasChatKey && cfg.hasKey;

  return (
    <div>
      {/* ── Status card ───────────────────────────────────────────────────── */}
      <div style={{ ...CARD, marginBottom: 16 }}>
        <div style={{ ...LABEL, marginBottom: 10 }}>CyMind AI Chat — Integration Status</div>
        <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          <span style={{
            display: "inline-flex", alignItems: "center", gap: 6,
            background: isEnabled ? "rgba(0,229,160,0.1)" : "rgba(255,255,255,0.05)",
            border: `1px solid ${isEnabled ? "rgba(0,229,160,0.3)" : "rgba(255,255,255,0.12)"}`,
            borderRadius: 4, padding: "4px 12px",
            color: isEnabled ? "#00e5a0" : "rgba(255,255,255,0.3)",
            fontSize: 11, fontFamily: "monospace", fontWeight: 700,
          }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: "currentColor" }} />
            {isEnabled ? "CONNECTED" : "NOT CONFIGURED"}
          </span>
          <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace" }}>{CYMIND_URL}</span>
          {cfg.hasKey     && <span style={{ color: "rgba(0,229,160,0.6)", fontSize: 10, fontFamily: "monospace" }}>✓ M2M key</span>}
          {cfg.hasChatKey && <span style={{ color: "rgba(0,229,160,0.6)", fontSize: 10, fontFamily: "monospace" }}>✓ Chat key</span>}
        </div>

        {/* MCP status inline */}
        <div style={{ marginTop: 12, display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, fontFamily: "monospace" }}>MCP Bridge:</span>
          {mcpStatus === null ? (
            <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>checking…</span>
          ) : (
            <>
              <span style={{
                display: "inline-flex", alignItems: "center", gap: 5,
                background: mcpStatus.enabled ? "rgba(0,229,160,0.08)" : "rgba(255,255,255,0.03)",
                border: `1px solid ${mcpStatus.enabled ? "rgba(0,229,160,0.25)" : "rgba(255,255,255,0.08)"}`,
                borderRadius: 3, padding: "2px 8px",
                color: mcpStatus.enabled ? "#00e5a0" : "rgba(255,255,255,0.25)",
                fontSize: 10, fontFamily: "monospace", fontWeight: 700,
              }}>
                <span style={{ width: 5, height: 5, borderRadius: "50%", background: "currentColor" }} />
                {mcpStatus.enabled ? "ENABLED" : "DISABLED"}
              </span>
              {mcpStatus.enabled && Array.isArray(mcpStatus.tools) && mcpStatus.tools.length > 0 && (
                <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, fontFamily: "monospace" }}>
                  {mcpStatus.tools.length} tool{mcpStatus.tools.length !== 1 ? "s" : ""} active
                </span>
              )}
            </>
          )}
        </div>
      </div>

      {/* ── Enable form ───────────────────────────────────────────────────── */}
      <div style={{ ...CARD }}>
        <div style={{ ...LABEL, marginBottom: 6 }}>
          {isEnabled ? "Reconfigure Integration" : "Enable CyMind Integration"}
        </div>
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 11, fontFamily: "monospace", lineHeight: 1.7, marginBottom: 16 }}>
          Enter your CyMind <strong style={{ color: "rgba(255,255,255,0.5)" }}>admin</strong> credentials.
          CyCentra will automatically configure both sides — no manual steps in CyMind needed.
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 16 }}>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <div style={{ flex: 1, minWidth: 180 }}>
              <div style={{ ...LABEL, marginBottom: 4, fontSize: 10 }}>CyMind Admin Email</div>
              <input
                type="email"
                value={adminEmail}
                onChange={e => setAdminEmail(e.target.value)}
                placeholder="admin@cymind.local"
                style={{ ...INPUT, width: "100%", boxSizing: "border-box" }}
              />
            </div>
            <div style={{ flex: 1, minWidth: 180 }}>
              <div style={{ ...LABEL, marginBottom: 4, fontSize: 10 }}>CyMind Admin Password</div>
              <input
                type="password"
                value={adminPw}
                onChange={e => setAdminPw(e.target.value)}
                placeholder="••••••••"
                style={{ ...INPUT, width: "100%", boxSizing: "border-box" }}
                onKeyDown={e => e.key === "Enter" && handleEnable()}
              />
            </div>
          </div>
        </div>

        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button onClick={handleEnable} disabled={saving}
            style={{ ...BTN("#00e5a0"), opacity: saving ? 0.5 : 1 }}>
            {saving ? "Enabling…" : isEnabled ? "Re-connect" : "Enable Integration"}
          </button>
          {isEnabled && (
            <button onClick={handleDisable} disabled={saving}
              style={{ ...BTN("#ff6b6b"), opacity: saving ? 0.5 : 1 }}>
              Disable
            </button>
          )}
          <button onClick={handleTestConn} disabled={saving}
            style={{ ...BTN("#4d9eff"), opacity: saving ? 0.5 : 1 }}>
            Test Connection
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

      {/* ── Advanced (collapsed by default) ───────────────────────────────── */}
      <div style={{ ...CARD, marginTop: 12 }}>
        <button
          onClick={() => setShowAdvanced(v => !v)}
          style={{ background: "none", border: "none", cursor: "pointer", display: "flex", alignItems: "center",
            gap: 8, color: "rgba(255,255,255,0.65)", fontSize: 11, fontFamily: "monospace", padding: 0 }}>
          <span style={{ fontSize: 10 }}>{showAdvanced ? "▼" : "▶"}</span>
          Advanced / Manual Key Management
        </button>

        {showAdvanced && (
          <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 20 }}>
            {/* M2M key rotation */}
            <div>
              <div style={{ ...LABEL, marginBottom: 6 }}>
                Rotate M2M Key <span style={{ color: "rgba(255,255,255,0.55)", fontWeight: 400 }}>(cymk_… — CyMind reads SIEM via MCP)</span>
              </div>
              <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, fontFamily: "monospace", marginBottom: 8 }}>
                After rotating: update <code style={{ color: "rgba(0,229,160,0.6)" }}>CYCENTRA_API_KEY</code> in CyMind .env and restart, or re-run Enable Integration above.
              </div>
              <button onClick={handleGenKey} disabled={saving}
                style={{ ...BTN("#4d9eff"), opacity: saving ? 0.5 : 1 }}>
                {cfg.hasKey ? "Rotate M2M Key" : "Generate M2M Key"}
              </button>
              {newKey && (
                <div style={{ marginTop: 10, background: "rgba(0,229,160,0.06)", border: "1px solid rgba(0,229,160,0.2)",
                  borderRadius: 4, padding: "10px 12px" }}>
                  <div style={{ color: "#00e5a0", fontSize: 10, fontFamily: "monospace", marginBottom: 4 }}>New M2M key — copy now (shown once)</div>
                  <code style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace", userSelect: "all", wordBreak: "break-all" }}>{newKey}</code>
                </div>
              )}
            </div>

            {/* Manual chat key paste */}
            <div>
              <div style={{ ...LABEL, marginBottom: 6 }}>
                Manual Chat Key <span style={{ color: "rgba(255,255,255,0.55)", fontWeight: 400 }}>(pak_… — if auto-enable fails, paste manually)</span>
                {cfg.hasChatKey && <span style={{ color: "#00e5a0", fontSize: 10, marginLeft: 10 }}>✓ set</span>}
              </div>
              <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, fontFamily: "monospace", marginBottom: 8 }}>
                In CyMind: Users → cycentra-portal → API Keys → Generate. Paste the pak_… key below.
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  type="password"
                  value={chatKeyInput}
                  onChange={e => setChatKeyInput(e.target.value)}
                  placeholder="pak_…"
                  style={{ ...INPUT, flex: 1, fontFamily: "monospace" }}
                />
                <button onClick={handleSaveChatKey} disabled={saving || !chatKeyInput.trim()}
                  style={{ ...BTN("#4d9eff"), opacity: (saving || !chatKeyInput.trim()) ? 0.4 : 1 }}>
                  Save
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── MCP API Keys — 3rd-party integrations ─────────────────────────── */}
      <div style={{ ...CARD, marginTop: 12 }}>
        <div style={{ ...LABEL, marginBottom: 4 }}>MCP API Keys — 3rd Party Integrations</div>
        <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace", lineHeight: 1.7, marginBottom: 14 }}>
          Generate <code style={{ color: "rgba(0,229,160,0.5)" }}>cymk_…</code> keys for external AI agents or SIEM tools that need access to the Security MCP bridge.
          CyMind uses its own built-in key above — this section is for additional integrations only.
        </div>

        {mcpKeysEp && (
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14,
            background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: 4, padding: "8px 12px" }}>
            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", whiteSpace: "nowrap" }}>MCP Endpoint:</span>
            <code style={{ color: "rgba(0,229,160,0.7)", fontSize: 11, fontFamily: "monospace", wordBreak: "break-all" }}>{mcpKeysEp}</code>
          </div>
        )}

        {/* Generate form */}
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 14 }}>
          <input
            value={newKeyName}
            onChange={e => setNewKeyName(e.target.value)}
            placeholder="Key name (e.g. splunk-integration)"
            style={{ ...INPUT, flex: 2, minWidth: 160, fontFamily: "monospace" }}
            onKeyDown={e => e.key === "Enter" && handleGenMcpKey()}
          />
          <input
            value={newKeyDesc}
            onChange={e => setNewKeyDesc(e.target.value)}
            placeholder="Description (optional)"
            style={{ ...INPUT, flex: 3, minWidth: 160 }}
          />
          <button onClick={handleGenMcpKey} disabled={!newKeyName.trim()}
            style={{ ...BTN("#00e5a0"), opacity: newKeyName.trim() ? 1 : 0.4 }}>
            Generate Key
          </button>
        </div>

        {/* One-time key reveal */}
        {genKeyResult && (
          <div style={{ marginBottom: 14, background: "rgba(0,229,160,0.06)", border: "1px solid rgba(0,229,160,0.2)",
            borderRadius: 4, padding: "10px 14px" }}>
            <div style={{ color: "#00e5a0", fontSize: 10, fontFamily: "monospace", marginBottom: 6 }}>
              {genKeyResult.name} — copy now, this key will not be shown again
            </div>
            <code style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace", userSelect: "all", wordBreak: "break-all" }}>
              {genKeyResult.key}
            </code>
          </div>
        )}

        {mcpKeyMsg && (
          <div style={{ color: mcpKeyMsg.ok === true ? "#00e5a0" : mcpKeyMsg.ok === false ? "#ff3b3b" : "#ffd93d",
            fontSize: 11, fontFamily: "monospace", marginBottom: 12 }}>
            {mcpKeyMsg.ok === true ? "✓" : mcpKeyMsg.ok === false ? "✗" : "⋯"} {mcpKeyMsg.text}
          </div>
        )}

        {/* Keys table */}
        {mcpKeysLoading ? (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace" }}>Loading…</div>
        ) : mcpKeys.length === 0 ? (
          <div style={{ color: "rgba(255,255,255,0.42)", fontSize: 11, fontFamily: "monospace" }}>No 3rd-party keys yet.</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {/* Header row */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 2fr 80px", gap: 8,
              color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace",
              letterSpacing: "0.5px", textTransform: "uppercase", paddingBottom: 4,
              borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
              <span>Name</span><span>Created</span><span>Key (masked)</span><span></span>
            </div>
            {mcpKeys.map(k => (
              <div key={k.id} style={{ display: "grid", gridTemplateColumns: "1fr 1fr 2fr 80px", gap: 8,
                alignItems: "center", padding: "6px 0",
                borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 11, fontFamily: "monospace",
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {k.name}
                </span>
                <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, fontFamily: "monospace" }}>
                  {k.created_at ? new Date(k.created_at).toLocaleDateString() : "—"}
                </span>
                <code style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace",
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {k.key}
                </code>
                <button onClick={() => handleRevokeMcpKey(k.id, k.name)}
                  style={{ background: "rgba(255,59,48,0.08)", border: "1px solid rgba(255,59,48,0.2)",
                    borderRadius: 3, color: "#ff6b6b", fontSize: 10, fontFamily: "monospace",
                    padding: "3px 8px", cursor: "pointer" }}>
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
// TAB 6 — Scheduler
// Manage cron schedules for docker-maintenance, ASM wordlist, ASM scan
// ════════════════════════════════════════════════════════════════════════════

// Common IANA timezones shown in the selector.  The browser's detected zone
// is prepended at runtime if it's not already in this list.
const COMMON_TIMEZONES = [
  "UTC",
  "America/New_York","America/Chicago","America/Denver","America/Los_Angeles",
  "America/Toronto","America/Vancouver","America/Sao_Paulo","America/Mexico_City",
  "Europe/London","Europe/Paris","Europe/Berlin","Europe/Madrid","Europe/Rome",
  "Europe/Amsterdam","Europe/Stockholm","Europe/Warsaw","Europe/Istanbul",
  "Europe/Moscow","Asia/Dubai","Asia/Kolkata","Asia/Colombo",
  "Asia/Dhaka","Asia/Kathmandu","Asia/Bangkok","Asia/Singapore",
  "Asia/Hong_Kong","Asia/Tokyo","Asia/Seoul","Asia/Karachi",
  "Australia/Sydney","Australia/Melbourne","Pacific/Auckland","Pacific/Auckland",
];

const FREQ_OPTIONS = [
  { value: "minute",    label: "Every Minute"  },
  { value: "hourly",    label: "Hourly"        },
  { value: "daily",     label: "Daily"         },
  { value: "weekly",    label: "Weekly (Mon)"  },
  { value: "monthly",   label: "Monthly (1st)" },
  { value: "quarterly", label: "Quarterly"     },
  { value: "yearly",    label: "Yearly (Jan 1)"},
];

const SCAN_TYPES = [
  { value: "passive",  label: "Passive — DNS & certificate recon only, no active probing" },
  { value: "standard", label: "Standard — Full surface mapping with active checks"        },
  { value: "deep",     label: "Deep — Exhaustive scan including dark web & supply chain"  },
];

function SchedulerTask({ taskId, task, onChange, baseDomain, timezone, noHeader = false }) {
  const accent = task.enabled ? "#00e5a0" : "rgba(255,255,255,0.25)";
  const showTime = task.frequency !== "minute";

  // Compute UTC equivalent of the configured local time for display in the log footer.
  const utcPreview = (() => {
    if (!showTime || !timezone || timezone === "UTC") return null;
    try {
      const h = task.hour ?? 0;
      const m = task.minute ?? 0;
      const now = new Date();
      now.setHours(h, m, 0, 0);
      const utcStr = now.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "UTC" });
      return `${String(h).padStart(2,"0")}:${String(m).padStart(2,"0")} ${timezone} = ${utcStr} UTC`;
    } catch { return null; }
  })();
  const [logLines, setLogLines] = useState(null);
  const [logError, setLogError] = useState(false);

  useEffect(() => {
    if (!task.enabled) { setLogLines(null); return; }
    fetch(`${API_BASE}/api/system/schedule-log/${taskId}`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (d?.ok) setLogLines(d.lines || []);
        else setLogError(true);
      })
      .catch(() => setLogError(true));
  }, [taskId, task.enabled]);

  return (
    <div style={{ background: "rgba(255,255,255,0.025)", border: `1px solid ${accent}25`, borderLeft: `3px solid ${accent}`, borderRadius: 5, padding: "18px 20px", marginBottom: 14 }}>
      {/* Header row */}
      {!noHeader && (
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
          <div>
            <div style={{ color: "white", fontWeight: 700, fontSize: 14 }}>{task.label}</div>
            <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 11, marginTop: 3 }}>{task.desc}</div>
            {taskId === "asm_wordlist" && task._available === false && (
              <div style={{ color: "#ffd93d", fontSize: 10, fontFamily: "monospace", marginTop: 4 }}>
                ⚠ update_wordlist.py not found on server — install cy-asm package first
              </div>
            )}
          </div>
          {/* Enable toggle */}
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ color: "rgba(255,255,255,0.62)", fontSize: 11, fontFamily: "monospace" }}>
              {task.enabled ? "ENABLED" : "DISABLED"}
            </span>
            <div
              onClick={() => onChange(taskId, "enabled", !task.enabled)}
              style={{ width: 36, height: 20, borderRadius: 10, background: task.enabled ? "rgba(0,229,160,0.3)" : "rgba(255,255,255,0.1)", border: `1px solid ${task.enabled ? "rgba(0,229,160,0.5)" : "rgba(255,255,255,0.15)"}`, cursor: "pointer", position: "relative", transition: "background 0.2s" }}>
              <div style={{ position: "absolute", top: 2, left: task.enabled ? 17 : 2, width: 14, height: 14, borderRadius: "50%", background: task.enabled ? "#00e5a0" : "rgba(255,255,255,0.35)", transition: "left 0.2s" }}/>
            </div>
          </div>
        </div>
      )}
      {noHeader && (
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
          <div>
            <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, lineHeight: 1.6 }}>{task.desc}</div>
            {taskId === "asm_wordlist" && task._available === false && (
              <div style={{ color: "#ffd93d", fontSize: 10, fontFamily: "monospace", marginTop: 4 }}>
                ⚠ update_wordlist.py not found on server — install cy-asm package first
              </div>
            )}
          </div>
          {/* Enable toggle */}
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
            <span style={{ color: "rgba(255,255,255,0.62)", fontSize: 11, fontFamily: "monospace" }}>
              {task.enabled ? "ENABLED" : "DISABLED"}
            </span>
            <div
              onClick={() => onChange(taskId, "enabled", !task.enabled)}
              style={{ width: 36, height: 20, borderRadius: 10, background: task.enabled ? "rgba(0,229,160,0.3)" : "rgba(255,255,255,0.1)", border: `1px solid ${task.enabled ? "rgba(0,229,160,0.5)" : "rgba(255,255,255,0.15)"}`, cursor: "pointer", position: "relative", transition: "background 0.2s" }}>
              <div style={{ position: "absolute", top: 2, left: task.enabled ? 17 : 2, width: 14, height: 14, borderRadius: "50%", background: task.enabled ? "#00e5a0" : "rgba(255,255,255,0.35)", transition: "left 0.2s" }}/>
            </div>
          </div>
        </div>
      )}

      {/* Config row */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}>
        {/* Frequency */}
        <div>
          <div style={{ ...LABEL, marginBottom: 4 }}>Frequency</div>
          <select
            value={task.frequency || "daily"}
            onChange={e => onChange(taskId, "frequency", e.target.value)}
            style={{ ...INPUT, width: 180, padding: "6px 10px" }}>
            {FREQ_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>

        {/* Time (hour:minute) — hidden for "minute" frequency */}
        {showTime && (
          <>
            <div>
              <div style={{ ...LABEL, marginBottom: 4 }}>Hour (0–23)</div>
              <input
                type="number" min={0} max={23}
                value={task.hour ?? 0}
                onChange={e => onChange(taskId, "hour", Math.max(0, Math.min(23, parseInt(e.target.value) || 0)))}
                style={{ ...INPUT, width: 80, padding: "6px 10px" }}/>
            </div>
            <div>
              <div style={{ ...LABEL, marginBottom: 4 }}>Minute (0–59)</div>
              <input
                type="number" min={0} max={59}
                value={task.minute ?? 0}
                onChange={e => onChange(taskId, "minute", Math.max(0, Math.min(59, parseInt(e.target.value) || 0)))}
                style={{ ...INPUT, width: 80, padding: "6px 10px" }}/>
            </div>
          </>
        )}

        {/* Backup: retain count + retain days */}
        {taskId === "backup" && (
          <>
            <div>
              <div style={{ ...LABEL, marginBottom: 4 }}>Keep Last N</div>
              <input
                type="number" min={1} max={365}
                value={task.retain_count ?? 14}
                onChange={e => onChange(taskId, "retain_count", Math.max(1, parseInt(e.target.value) || 14))}
                style={{ ...INPUT, width: 90, padding: "6px 10px" }}/>
              <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, marginTop: 3 }}>archives</div>
            </div>
            <div>
              <div style={{ ...LABEL, marginBottom: 4 }}>Delete After</div>
              <input
                type="number" min={1} max={730}
                value={task.retain_days ?? 30}
                onChange={e => onChange(taskId, "retain_days", Math.max(1, parseInt(e.target.value) || 30))}
                style={{ ...INPUT, width: 90, padding: "6px 10px" }}/>
              <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, marginTop: 3 }}>days</div>
            </div>
          </>
        )}

        {/* ASM scan: domain (read-only from BASE_DOMAIN) + scan type */}
        {taskId === "asm_scan" && (
          <>
            <div>
              <div style={{ ...LABEL, marginBottom: 4 }}>Target Domain</div>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ background: "rgba(0,229,160,0.08)", border: "1px solid rgba(0,229,160,0.25)", borderRadius: 4, color: "#00e5a0", fontFamily: "monospace", fontSize: 12, padding: "6px 12px", letterSpacing: "0.5px" }}>
                  {baseDomain || "BASE_DOMAIN not set"}
                </span>
                <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>from /opt/cycentra/.env</span>
              </div>
            </div>
            <div>
              <div style={{ ...LABEL, marginBottom: 4 }}>Scan Type</div>
              <select
                value={task.scan_type || "passive"}
                onChange={e => onChange(taskId, "scan_type", e.target.value)}
                style={{ ...INPUT, width: 130, padding: "6px 10px" }}>
                {SCAN_TYPES.map(o => <option key={o.value} value={o.value}>{o.label.split(" — ")[0]}</option>)}
              </select>
              {task.scan_type && (
                <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, marginTop: 4, maxWidth: 260 }}>
                  {SCAN_TYPES.find(o => o.value === task.scan_type)?.label.split(" — ")[1] || ""}
                </div>
              )}
            </div>
          </>
        )}
      </div>

      {/* Log path + recent output */}
      {task.enabled && (
        <div style={{ marginTop: 12, background: "rgba(0,0,0,0.3)", borderRadius: 3, padding: "8px 10px", fontFamily: "monospace", fontSize: 10 }}>
          {task.log && (
            <div style={{ color: "rgba(0,229,160,0.6)", marginBottom: logLines && logLines.length > 0 ? 6 : 0 }}>
              Log → <code style={{ color: "rgba(255,255,255,0.62)" }}>{task.log}</code>
              {utcPreview && (
                <span style={{ marginLeft: 12, color: "rgba(255,200,0,0.55)", fontSize: 10, fontFamily: "monospace" }}>
                  ⏱ {utcPreview}
                </span>
              )}
            </div>
          )}
          {logLines && logLines.length > 0 && (
            <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: 6 }}>
              {logLines.slice(-8).map((ln, i) => {
                const isError = /error|not found|failed|exception/i.test(ln);
                return (
                  <div key={i} style={{ color: isError ? "#ff6b6b" : "rgba(255,255,255,0.45)", lineHeight: 1.5, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                    {ln}
                  </div>
                );
              })}
            </div>
          )}
          {logLines && logLines.length === 0 && (
            <div style={{ color: "rgba(255,255,255,0.2)" }}>No output yet — job has not run since log was created.</div>
          )}
          {logError && (
            <div style={{ color: "rgba(255,255,255,0.2)" }}>Log file not readable.</div>
          )}
        </div>
      )}
    </div>
  );
}

function SchedulerTab() {
  const [schedules,   setSchedules]   = useState(null);
  const [baseDomain,  setBaseDomain]  = useState("");
  const [loading,     setLoading]     = useState(true);
  const [saving,      setSaving]      = useState(false);
  const [msg,         setMsg]         = useState(null);

  // Auto-detect browser timezone; prepend to list if not already present
  const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  const tzOptions  = COMMON_TIMEZONES.includes(browserTz)
    ? COMMON_TIMEZONES
    : [browserTz, ...COMMON_TIMEZONES];

  const [timezone, setTimezone] = useState(browserTz);

  useEffect(() => {
    fetch(`${API_BASE}/api/system/schedules`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (d?.schedules) setSchedules(d.schedules);
        if (d?.base_domain) setBaseDomain(d.base_domain);
        // Restore saved timezone or keep the browser-detected one
        if (d?.timezone && d.timezone !== "UTC") setTimezone(d.timezone);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const handleChange = (taskId, field, value) => {
    setSchedules(prev => ({ ...prev, [taskId]: { ...prev[taskId], [field]: value } }));
  };

  const handleSave = async () => {
    setSaving(true); setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/system/schedules`, {
        method: "PUT", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ schedules, timezone }),
      });
      const d = await r.json();
      if (d.ok) {
        setMsg({ ok: true, text: `Schedules saved. ${d.applied} cron job(s) active. Times stored as ${timezone}, converted to UTC for cron.` });
      } else {
        setMsg({ ok: false, text: d.error || "Save failed" });
      }
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally { setSaving(false); }
  };

  if (loading) return <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 12 }}>Loading…</div>;
  if (!schedules) return <div style={{ color: "#ff3b3b", fontFamily: "monospace", fontSize: 12 }}>Failed to load schedules.</div>;

  const taskOrder = ["docker_maintenance", "backup"];
  const TASK_ICONS = { docker_maintenance: "🐳", backup: "💾" };

  return (
    <div style={{ maxWidth: 860 }}>
      <div style={{ marginBottom: 20 }}>
        <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 12, lineHeight: 1.7 }}>
          Configure automated cron schedules for maintenance and scanning tasks.
          Changes are applied to the server crontab immediately on save.
        </div>
      </div>

      {/* Timezone selector — applies to all tasks */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 22, background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 5, padding: "12px 16px" }}>
        <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, fontFamily: "monospace", letterSpacing: "0.8px", textTransform: "uppercase", whiteSpace: "nowrap" }}>Your Timezone</span>
        <select
          value={timezone}
          onChange={e => setTimezone(e.target.value)}
          style={{ ...INPUT, flex: 1, maxWidth: 320, padding: "6px 10px" }}>
          {tzOptions.map(tz => <option key={tz} value={tz}>{tz}</option>)}
        </select>
        <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>
          Hour/minute values you enter are in this timezone · backend converts to UTC for cron
        </span>
      </div>

      {taskOrder.map(id => schedules[id] && (
        <CollapsibleSection
          key={id}
          icon={TASK_ICONS[id] || "⏱"}
          title={schedules[id].label || id}
          badge={
            <span style={{ background: schedules[id].enabled ? "rgba(0,229,160,0.08)" : "rgba(255,255,255,0.04)", color: schedules[id].enabled ? "#00e5a0" : "rgba(255,255,255,0.3)", border: `1px solid ${schedules[id].enabled ? "rgba(0,229,160,0.3)" : "rgba(255,255,255,0.08)"}`, borderRadius: 4, padding: "2px 8px", fontSize: 9, fontFamily: "monospace", letterSpacing: "1px" }}>
              {schedules[id].enabled ? "ENABLED" : "DISABLED"}
            </span>
          }
        >
          <SchedulerTask taskId={id} task={schedules[id]} onChange={handleChange} baseDomain={baseDomain} timezone={timezone} noHeader />
        </CollapsibleSection>
      ))}

      <div style={{ display: "flex", alignItems: "center", gap: 14, marginTop: 8 }}>
        <button onClick={handleSave} disabled={saving}
          style={{ ...BTN(), opacity: saving ? 0.5 : 1 }}>
          {saving ? "Saving…" : "Save Schedules"}
        </button>
        <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>
          Writes to /opt/cycentra/schedules.json · applies to server crontab
        </span>
      </div>

      {msg && (
        <div style={{ color: msg.ok ? "#00e5a0" : "#ff3b3b", fontSize: 12, fontFamily: "monospace", marginTop: 12 }}>
          {msg.ok ? "✓" : "✗"} {msg.text}
        </div>
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// TAB — Backup & Restore
// Scheduling lives in the Scheduler tab (same system as other cron tasks).
// ════════════════════════════════════════════════════════════════════════════

const BACKUP_INCLUDES = [
  { file: "/opt/cycentra/*.json",           desc: "RBAC, module state, AI settings, schedules" },
  { file: "/opt/cycentra/.env",             desc: "Core config — OAuth keys, BASE_DOMAIN, ports" },
  { file: "/opt/cycentra/*.env",            desc: "CySIEM stack, per-component env files" },
  { file: "/opt/cycentra/*.lic",            desc: "License file(s)" },
  { file: "/opt/cycentra/modules/**/*.json", desc: "Per-module config files" },
  { file: "/opt/cycentra/modules/**/.env",  desc: "Per-module env (CySOAR, CyMISP, …)" },
  { file: "database_dump.sql",              desc: "PostgreSQL dump — only if DATABASE_URL is set" },
];

function BackupTab() {
  const [backups,   setBackups]   = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [creating,  setCreating]  = useState(false);
  const [restoring, setRestoring] = useState(null);
  const [deleting,  setDeleting]  = useState(null);
  const [msg,       setMsg]       = useState(null);

  const fetchBackups = () => {
    setLoading(true);
    fetch(`${API_BASE}/api/backup/list`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d?.backups) setBackups(d.backups); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => { fetchBackups(); }, []);

  const flash = (ok, text) => { setMsg({ ok, text }); setTimeout(() => setMsg(null), 5000); };

  const handleCreate = async () => {
    setCreating(true); setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/backup/create`, { method: "POST", credentials: "include" });
      const d = await r.json();
      if (d.ok) { flash(true, `Backup created: ${d.backup.id}  (${d.backup.size_mb} MB · ${d.backup.files} files)`); fetchBackups(); }
      else       flash(false, d.error || "Backup failed");
    } catch (e) { flash(false, String(e)); }
    finally { setCreating(false); }
  };

  const handleRestore = async (backupId) => {
    if (!window.confirm(
      `Restore from ${backupId}?\n\n` +
      `• All config files under /opt/cycentra/ will be overwritten.\n` +
      `• A pre-restore snapshot is saved automatically so you can undo.\n\n` +
      `The platform must be restarted after restore for changes to take effect.`
    )) return;
    setRestoring(backupId); setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/backup/restore/${encodeURIComponent(backupId)}`,
        { method: "POST", credentials: "include" });
      const d = await r.json();
      if (d.ok) flash(true, `${d.message}  |  pre-restore snapshot: ${d.pre_backup_id || "n/a"}`);
      else       flash(false, d.error || "Restore failed");
    } catch (e) { flash(false, String(e)); }
    finally { setRestoring(null); fetchBackups(); }
  };

  const handleDelete = async (backupId) => {
    if (!window.confirm(`Permanently delete ${backupId}? This cannot be undone.`)) return;
    setDeleting(backupId);
    try {
      const r = await fetch(`${API_BASE}/api/backup/${encodeURIComponent(backupId)}`,
        { method: "DELETE", credentials: "include" });
      const d = await r.json();
      if (!d.ok) flash(false, d.error || "Delete failed");
    } catch (e) { flash(false, String(e)); }
    finally { setDeleting(null); fetchBackups(); }
  };

  return (
    <div style={{ maxWidth: 920 }}>

      {/* ── What's included ─────────────────────────────────────── */}
      <div style={{ ...CARD, marginBottom: 20 }}>
        <div style={LABEL}>What Every Backup Contains</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px 24px", marginTop: 8 }}>
          {BACKUP_INCLUDES.map(it => (
            <div key={it.file} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
              <code style={{ color: "#00e5a0", fontFamily: "monospace", fontSize: 11, whiteSpace: "nowrap", minWidth: 0, flexShrink: 0 }}>
                {it.file}
              </code>
              <span style={{ color: "rgba(255,255,255,0.62)", fontSize: 11, lineHeight: 1.5 }}>{it.desc}</span>
            </div>
          ))}
        </div>
        <div style={{ marginTop: 12, borderTop: "1px solid rgba(255,255,255,0.05)", paddingTop: 10,
          color: "rgba(255,255,255,0.2)", fontSize: 11, lineHeight: 1.7 }}>
          <strong style={{ color: "rgba(255,255,255,0.62)" }}>Not backed up:</strong>{" "}
          Docker images · log files · Python source code (all re-deployable via <code style={{ fontFamily: "monospace" }}>cycentra-setup.sh</code>).
          <br/>
          <strong style={{ color: "rgba(255,255,255,0.62)" }}>Scheduling:</strong>{" "}
          Configure automated backup runs in the <strong>Scheduler</strong> tab (Automated Backup task).
        </div>
      </div>

      {/* ── Create + List ───────────────────────────────────────── */}
      <div style={CARD}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <div style={LABEL}>Backup Archives</div>
          <button onClick={handleCreate} disabled={creating}
            style={{ ...BTN(), opacity: creating ? 0.5 : 1, whiteSpace: "nowrap" }}>
            {creating ? "Creating…" : "Create Backup Now"}
          </button>
        </div>

        {loading ? (
          <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 12 }}>Loading…</div>
        ) : backups.length === 0 ? (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, fontFamily: "monospace", padding: "8px 0" }}>
            No backups yet — click "Create Backup Now" or enable the Automated Backup task in the Scheduler tab.
          </div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, fontFamily: "monospace" }}>
            <thead>
              <tr>
                {["Archive", "Created", "Size", "Actions"].map(h => (
                  <th key={h} style={{ ...LABEL, textAlign: "left", paddingBottom: 8, paddingRight: 16 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {backups.map(b => (
                <tr key={b.id} style={{ borderTop: "1px solid rgba(255,255,255,0.04)" }}>
                  <td style={{ color: "rgba(255,255,255,0.65)", padding: "9px 16px 9px 0", maxWidth: 320, wordBreak: "break-all" }}>
                    {b.id}
                  </td>
                  <td style={{ color: "rgba(255,255,255,0.45)", paddingRight: 16, whiteSpace: "nowrap" }}>{b.created}</td>
                  <td style={{ color: "rgba(255,255,255,0.45)", paddingRight: 16, whiteSpace: "nowrap" }}>{b.size_mb} MB</td>
                  <td>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      <button onClick={() => handleRestore(b.id)} disabled={!!restoring}
                        style={{ ...BTN(), padding: "4px 12px", fontSize: 10, opacity: restoring === b.id ? 0.5 : 1 }}>
                        {restoring === b.id ? "Restoring…" : "Restore"}
                      </button>
                      <a href={`${API_BASE}/api/backup/download/${encodeURIComponent(b.id)}`}
                        style={{ ...BTN("#4d9eff"), padding: "4px 12px", fontSize: 10, textDecoration: "none", display: "inline-block" }}>
                        Download
                      </a>
                      <button onClick={() => handleDelete(b.id)} disabled={deleting === b.id}
                        style={{ background: "rgba(255,59,59,0.08)", color: "#ff3b3b",
                          border: "1px solid rgba(255,59,59,0.25)", padding: "4px 12px",
                          borderRadius: 4, fontFamily: "monospace", fontSize: 10, cursor: "pointer",
                          opacity: deleting === b.id ? 0.5 : 1 }}>
                        {deleting === b.id ? "Deleting…" : "Delete"}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {msg && (
          <div style={{ color: msg.ok ? "#00e5a0" : "#ff3b3b", fontSize: 12, fontFamily: "monospace", marginTop: 14 }}>
            {msg.ok ? "✓" : "✗"} {msg.text}
          </div>
        )}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// TAB 3 wrapper — Integrations (CyMind)
// ════════════════════════════════════════════════════════════════════════════

function IntegrationsTab() {
  return (
    <div>
      <CyMindIntegrationTab />
    </div>
  );
}

// ── GRC Compliance Settings tabs ─────────────────────────────────────────────

function CompSIEMSourcesTab() {
  const [connections, setConnections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ name: "", siem_type: "wazuh", host: "", port: 55000, username: "" });

  const load = () => {
    setLoading(true);
    fetch(`${API_BASE}/api/comp/settings/siem-connections`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setConnections(d.connections || []); setLoading(false); })
      .catch(() => setLoading(false));
  };
  useEffect(() => { load(); }, []);

  const handleAdd = () => {
    fetch(`${API_BASE}/api/comp/settings/siem-connections`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(form),
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(() => { setShowAdd(false); load(); })
      .catch(e => alert(`Failed: ${e}`));
  };

  const handleDelete = (id) => {
    if (!confirm("Remove this SIEM connection?")) return;
    fetch(`${API_BASE}/api/comp/settings/siem-connections/${id}`, { method: "DELETE", credentials: "include" })
      .then(r => r.ok ? load() : alert("Delete failed"));
  };

  const inp = { ...INPUT, width: "100%", boxSizing: "border-box" };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <div style={{ ...LABEL }}>SIEM Sources for Compliance Ingestion</div>
        <button onClick={() => setShowAdd(s => !s)} style={BTN()}>
          {showAdd ? "Cancel" : "+ Add SIEM Source"}
        </button>
      </div>
      {showAdd && (
        <div style={{ ...CARD, marginBottom: 16, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          {[
            { label: "Name", key: "name" }, { label: "Host", key: "host" }, { label: "Username", key: "username" },
          ].map(({ label, key }) => (
            <div key={key}>
              <div style={LABEL}>{label}</div>
              <input style={inp} value={form[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))} />
            </div>
          ))}
          <div>
            <div style={LABEL}>SIEM Type</div>
            <select style={{ ...inp, cursor: "pointer" }} value={form.siem_type}
              onChange={e => setForm(f => ({ ...f, siem_type: e.target.value }))}>
              {["wazuh", "splunk", "elastic", "sentinel", "qradar", "correlation_engine"].map(t =>
                <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <div style={LABEL}>Port</div>
            <input style={inp} type="number" value={form.port}
              onChange={e => setForm(f => ({ ...f, port: +e.target.value }))} />
          </div>
          <div style={{ gridColumn: "1/-1", display: "flex", justifyContent: "flex-end" }}>
            <button onClick={handleAdd} style={BTN()}>Save Connection</button>
          </div>
        </div>
      )}
      {loading ? (
        <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 11 }}>Loading...</div>
      ) : connections.length === 0 ? (
        <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 11, padding: 16 }}>
          No SIEM sources configured. The built-in Correlation Engine adapter runs automatically.
        </div>
      ) : connections.map(c => (
        <div key={c.id} style={{ ...CARD, display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <div>
            <div style={{ color: "rgba(255,255,255,0.82)", fontSize: 12, fontWeight: 600 }}>{c.name}</div>
            <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace", marginTop: 2 }}>
              {c.siem_type} — {c.host || "internal"}:{c.port}
            </div>
          </div>
          <button onClick={() => handleDelete(c.id)}
            style={{ ...BTN("#ff3b3b"), padding: "5px 12px", fontSize: 10 }}>Remove</button>
        </div>
      ))}
    </div>
  );
}

function CompGRCSettingsTab() {
  const [settings, setSettings] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState(null);
  const [keyVisible, setKeyVisible] = useState(false);
  const [newKey, setNewKey] = useState("");

  const load = () => {
    setLoading(true);
    fetch(`${API_BASE}/api/comp/settings`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setSettings(d); setLoading(false); })
      .catch(() => setLoading(false));
  };
  useEffect(() => { load(); }, []);

  const handleSave = () => {
    setSaving(true); setMsg(null);
    // Only save the admin key for RAG collection management;
    // URL is inherited from global CyMind integration automatically
    const payload = {};
    if (newKey) payload.cymind_admin_key = newKey;
    fetch(`${API_BASE}/api/comp/settings`, {
      method: "PUT", credentials: "include",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(() => { setMsg({ ok: true, text: "Settings saved" }); setNewKey(""); })
      .catch(e => setMsg({ ok: false, text: `Save failed: ${e}` }))
      .finally(() => setSaving(false));
  };

  const inp = { ...INPUT, width: "100%", boxSizing: "border-box" };
  const globalEnabled = settings.global_cymind_enabled;

  return (
    <div>
      <div style={{ ...CARD, marginBottom: 16 }}>
        <div style={{ ...LABEL, marginBottom: 4 }}>CyMind RAG — Policy Document Pipeline</div>
        <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, fontFamily: "monospace", marginBottom: 16 }}>
          Policy documents uploaded in cy-comp are indexed in CyMind's vector database using the existing integration below.
        </div>

        {/* Global CyMind integration status — read-only */}
        <div style={{ background: globalEnabled ? "rgba(0,229,160,0.06)" : "rgba(255,59,59,0.06)",
          border: `1px solid ${globalEnabled ? "rgba(0,229,160,0.25)" : "rgba(255,59,59,0.25)"}`,
          borderRadius: 6, padding: "12px 14px", marginBottom: 16, display: "flex",
          alignItems: "flex-start", gap: 10 }}>
          <span style={{ fontSize: 14, marginTop: 1 }}>{globalEnabled ? "✓" : "✗"}</span>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700,
              color: globalEnabled ? "#00e5a0" : "#ff3b3b", fontFamily: "monospace" }}>
              {globalEnabled ? "Global CyMind integration is active" : "CyMind integration is not configured"}
            </div>
            {globalEnabled && settings.global_cymind_url && (
              <div style={{ fontSize: 10, color: "rgba(255,255,255,0.4)", fontFamily: "monospace", marginTop: 3 }}>
                {settings.global_cymind_url}
              </div>
            )}
            {!globalEnabled && (
              <div style={{ fontSize: 10, color: "rgba(255,255,255,0.35)", marginTop: 3 }}>
                Enable CyMind in <strong style={{ color: "rgba(255,255,255,0.5)" }}>Integrations → CyMind</strong> tab.
                RAG pipeline for policy documents requires an active CyMind connection.
              </div>
            )}
          </div>
        </div>

        {/* Admin key — only needed for collection management (create sub-collections by framework) */}
        <div style={{ marginBottom: 16 }}>
          <div style={LABEL}>CyMind Admin API Key</div>
          <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace", marginBottom: 6 }}>
            Required for collection management (create per-framework policy sub-collections).
            The standard CyMind key handles document upload — this is only needed for admin-level operations.
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <input style={{ ...inp }} type={keyVisible ? "text" : "password"}
              value={newKey || (settings.cymind_admin_key === "***" ? "" : settings.cymind_admin_key || "")}
              onChange={e => setNewKey(e.target.value)}
              placeholder={settings.cymind_admin_key === "***" ? "Key is set (enter new to replace)" : "Enter CyMind admin API key"} />
            <button onClick={() => setKeyVisible(v => !v)}
              style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)",
                color: "rgba(255,255,255,0.45)", padding: "7px 12px", borderRadius: 4,
                fontFamily: "monospace", fontSize: 10, cursor: "pointer", whiteSpace: "nowrap" }}>
              {keyVisible ? "Hide" : "Show"}
            </button>
          </div>
        </div>

        {msg && <div style={{ color: msg.ok ? "#00e5a0" : "#ff3b3b", fontSize: 10,
          fontFamily: "monospace", marginBottom: 10 }}>{msg.text}</div>}
        <button onClick={handleSave} disabled={saving || !newKey.trim()} style={BTN()}>
          {saving ? "Saving..." : "Save Admin Key"}
        </button>
      </div>
    </div>
  );
}

function CompNotificationsTab() {
  return (
    <div style={{ ...CARD }}>
      <div style={{ ...LABEL, marginBottom: 12 }}>Compliance Notifications</div>
      <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 12, fontFamily: "monospace" }}>
        Notification rules for compliance threshold breaches and new critical findings will be configurable here in a future release. Email notifications use the SMTP settings configured in Users & Auth.
      </div>
    </div>
  );
}

// ── Framework Documents Tab (Security Compliance) ─────────────────────────────

const FW_INFO = {
  iso27001: { label: "ISO/IEC 27001",  color: "#00e5a0" },
  nis2:     { label: "NIS2",           color: "#4d9eff" },
  dora:     { label: "DORA",           color: "#b06eff" },
  soc2:     { label: "SOC 2 Type II",  color: "#ff8c00" },
  nist_csf: { label: "NIST CSF 2.0",  color: "#6378ff" },
  pci_dss:  { label: "PCI DSS 4.0",   color: "#ff3b3b" },
  gdpr:     { label: "GDPR",          color: "#8b5cf6" },
};

function FrameworkDropZone({ framework, onUploaded, locked }) {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [lockUpload, setLockUpload] = useState(false);
  const [msg, setMsg] = useState(null);
  const ref = useRef(null);

  const uploadFile = (file) => {
    if (!file || locked) return;
    setUploading(true); setMsg(null);
    const fd = new FormData();
    fd.append("file", file);
    fd.append("locked", lockUpload ? "true" : "false");
    fetch(`${API_BASE}/api/comp/framework-docs/${framework}/documents`, {
      method: "POST", credentials: "include", body: fd,
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(() => { setMsg({ ok: true, text: "Uploaded and queued for indexing" }); onUploaded(); })
      .catch(e => setMsg({ ok: false, text: `Upload failed (${e})` }))
      .finally(() => setUploading(false));
  };

  return (
    <div>
      <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 8 }}>
        <label style={{ display: "flex", alignItems: "center", gap: 6,
          color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace", cursor: "pointer" }}>
          <input type="checkbox" checked={lockUpload} onChange={e => setLockUpload(e.target.checked)}
            style={{ accentColor: "#ff8c00" }} />
          Lock after upload (base doc — prevent deletion)
        </label>
      </div>
      <div
        onDragEnter={() => setDragging(true)}
        onDragLeave={() => setDragging(false)}
        onDragOver={e => e.preventDefault()}
        onDrop={e => { e.preventDefault(); setDragging(false); uploadFile(e.dataTransfer.files[0]); }}
        onClick={() => ref.current?.click()}
        style={{
          border: `2px dashed ${dragging ? "#00e5a0" : "rgba(255,255,255,0.12)"}`,
          borderRadius: 6, padding: "20px 16px", textAlign: "center", cursor: "pointer",
          background: dragging ? "rgba(0,229,160,0.04)" : "rgba(255,255,255,0.01)",
          transition: "all 0.2s",
        }}>
        <input ref={ref} type="file" style={{ display: "none" }}
          accept=".pdf,.docx,.txt,.md"
          onChange={e => uploadFile(e.target.files[0])} />
        <div style={{ color: uploading ? "#00e5a0" : "rgba(255,255,255,0.3)",
          fontSize: 11, fontFamily: "monospace" }}>
          {uploading ? "Uploading..." : "Drop document or click to browse · PDF, DOCX, TXT, MD"}
        </div>
      </div>
      {msg && <div style={{ color: msg.ok ? "#00e5a0" : "#ff3b3b",
        fontSize: 10, fontFamily: "monospace", marginTop: 6 }}>{msg.text}</div>}
    </div>
  );
}

function CompFrameworkDocsTab() {
  const [frameworks, setFrameworks] = useState([]);
  const [activeFw, setActiveFw]    = useState("iso27001");
  const [docs, setDocs]            = useState([]);
  const [loadingFws, setLoadingFws] = useState(true);
  const [loadingDocs, setLoadingDocs] = useState(false);
  const [locking, setLocking]      = useState(null);
  const [deleting, setDeleting]    = useState(null);

  const loadFrameworks = () => {
    setLoadingFws(true);
    fetch(`${API_BASE}/api/comp/framework-docs/frameworks`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setFrameworks(d.frameworks || []); setLoadingFws(false); })
      .catch(() => setLoadingFws(false));
  };

  const loadDocs = (fw) => {
    setLoadingDocs(true);
    fetch(`${API_BASE}/api/comp/framework-docs/${fw}/documents`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setDocs(d.documents || []); setLoadingDocs(false); })
      .catch(() => setLoadingDocs(false));
  };

  useEffect(() => { loadFrameworks(); }, []);
  useEffect(() => { if (activeFw) loadDocs(activeFw); }, [activeFw]);

  const handleToggleLock = (docId, currentLocked) => {
    setLocking(docId);
    fetch(`${API_BASE}/api/comp/framework-docs/documents/${docId}/lock`, {
      method: "PUT", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ locked: !currentLocked }),
    })
      .then(r => r.ok ? loadDocs(activeFw) : alert("Failed to update lock"))
      .finally(() => setLocking(null));
  };

  const handleDelete = (doc) => {
    if (doc.locked) { alert("This document is locked. Unlock it first."); return; }
    if (!confirm(`Delete "${doc.name}" from ${activeFw.toUpperCase()} reference library?`)) return;
    setDeleting(doc.id);
    fetch(`${API_BASE}/api/comp/framework-docs/documents/${doc.id}`, {
      method: "DELETE", credentials: "include" })
      .then(r => {
        if (r.ok) { loadDocs(activeFw); loadFrameworks(); }
        else r.json().then(d => alert(d.error || "Delete failed"));
      })
      .finally(() => setDeleting(null));
  };

  const fwInfo = FW_INFO[activeFw] || { label: activeFw.toUpperCase(), color: "#00e5a0" };

  return (
    <div>
      <div style={{ ...LABEL, marginBottom: 4 }}>Framework Reference Documents</div>
      <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, fontFamily: "monospace",
        marginBottom: 20, lineHeight: 1.6 }}>
        Each supported compliance framework has a dedicated reference library in the CyMind RAG pipeline.
        Upload framework standards, controls lists, and official guidance documents here.
        Locked documents (base docs) cannot be deleted without first unlocking them.
      </div>

      {loadingFws ? (
        <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 11 }}>
          Initialising framework collections...
        </div>
      ) : (
        <div style={{ display: "flex", gap: 20 }}>
          {/* Framework selector */}
          <div style={{ width: 200, flexShrink: 0 }}>
            {frameworks.map(fw => {
              const info = FW_INFO[fw.id] || fw;
              return (
                <button key={fw.id} onClick={() => setActiveFw(fw.id)}
                  style={{
                    width: "100%", padding: "10px 14px", borderRadius: 6, marginBottom: 6,
                    background: activeFw === fw.id ? `${info.color}0e` : "rgba(255,255,255,0.02)",
                    border: `1px solid ${activeFw === fw.id ? `${info.color}40` : "rgba(255,255,255,0.06)"}`,
                    color: activeFw === fw.id ? info.color : "rgba(255,255,255,0.45)",
                    fontFamily: "monospace", fontSize: 11, cursor: "pointer", textAlign: "left",
                  }}>
                  <div style={{ fontWeight: 700 }}>{info.label || fw.id.toUpperCase()}</div>
                  <div style={{ fontSize: 9, marginTop: 2, opacity: 0.7 }}>
                    {fw.doc_count} doc{fw.doc_count !== 1 ? "s" : ""}
                    {fw.locked_count > 0 ? ` · ${fw.locked_count} locked` : ""}
                  </div>
                </button>
              );
            })}
          </div>

          {/* Document panel */}
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ color: fwInfo.color, fontSize: 14, fontFamily: "monospace",
              fontWeight: 700, marginBottom: 14 }}>
              {fwInfo.label} Reference Library
            </div>

            <div style={{ ...CARD, marginBottom: 16 }}>
              <FrameworkDropZone framework={activeFw} onUploaded={() => { loadDocs(activeFw); loadFrameworks(); }} />
            </div>

            {loadingDocs ? (
              <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 11 }}>
                Loading documents...
              </div>
            ) : docs.length === 0 ? (
              <div style={{ ...CARD, textAlign: "center", color: "rgba(255,255,255,0.3)",
                fontFamily: "monospace", fontSize: 11, padding: 24 }}>
                No reference documents yet. Upload the {fwInfo.label} standard, controls list, or official guidance above.
              </div>
            ) : (
              <div style={{ background: "#0d1117", border: "1px solid rgba(255,255,255,0.07)",
                borderRadius: 8, overflow: "hidden" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
                      {["Document", "Status", "Lock", "Uploaded", ""].map(h => (
                        <th key={h} style={{ padding: "9px 14px", textAlign: "left",
                          color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace",
                          letterSpacing: "1px", textTransform: "uppercase" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {docs.map((d, i) => (
                      <tr key={d.id} style={{
                        borderBottom: "1px solid rgba(255,255,255,0.03)",
                        background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)",
                      }}>
                        <td style={{ padding: "10px 14px" }}>
                          <div style={{ color: "rgba(255,255,255,0.82)", fontSize: 11 }}>{d.name}</div>
                          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 9,
                            fontFamily: "monospace", marginTop: 1 }}>
                            {d.file_type?.toUpperCase() || "—"}
                          </div>
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          <span style={{ color: d.indexed ? "#00e5a0" : "#ff8c00",
                            fontSize: 10, fontFamily: "monospace" }}>
                            {d.indexed ? "✓ Indexed" : "⧗ Pending"}
                          </span>
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          <button
                            onClick={() => handleToggleLock(d.id, d.locked)}
                            disabled={locking === d.id}
                            title={d.locked ? "Click to unlock" : "Click to lock (base doc)"}
                            style={{
                              background: d.locked ? "rgba(255,140,0,0.12)" : "rgba(255,255,255,0.04)",
                              border: `1px solid ${d.locked ? "rgba(255,140,0,0.35)" : "rgba(255,255,255,0.1)"}`,
                              color: d.locked ? "#ff8c00" : "rgba(255,255,255,0.35)",
                              padding: "3px 10px", borderRadius: 4, fontFamily: "monospace",
                              fontSize: 9, cursor: "pointer", fontWeight: 700,
                              opacity: locking === d.id ? 0.5 : 1,
                            }}>
                            {d.locked ? "🔒 Locked" : "🔓 Unlocked"}
                          </button>
                        </td>
                        <td style={{ padding: "10px 14px",
                          color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace" }}>
                          {d.created_at ? new Date(d.created_at).toLocaleDateString("en-US",
                            { month: "short", day: "2-digit", year: "numeric" }) : "—"}
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          <button
                            onClick={() => handleDelete(d)}
                            disabled={d.locked || deleting === d.id}
                            title={d.locked ? "Unlock first" : "Delete"}
                            style={{
                              background: "rgba(255,59,59,0.1)", border: "1px solid rgba(255,59,59,0.25)",
                              color: "#ff3b3b", padding: "4px 10px", borderRadius: 3,
                              fontFamily: "monospace", fontSize: 9, cursor: d.locked ? "not-allowed" : "pointer",
                              fontWeight: 700, opacity: d.locked || deleting === d.id ? 0.35 : 1,
                            }}>
                            {deleting === d.id ? "..." : "Delete"}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Server Status Tab ─────────────────────────────────────────────────────────

function ServerStatusTab() {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const load = () => {
    setLoading(true);
    setError(null);
    fetch("/api/system/server-status", { credentials: "include" })
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(d => { setData(d); setLoading(false); })
      .catch(e => { setError(e.message); setLoading(false); });
  };

  useEffect(() => { load(); }, []);

  function fmtUptime(s) {
    if (!s) return "—";
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  function MeterRow({ label, pct, rightText, warn }) {
    const color = warn ? "#f87171" : "#00e5a0";
    const safePct = Math.min(100, Math.max(0, pct || 0));
    return (
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 0", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
        <span style={{ color: "rgba(255,255,255,0.4)", fontSize: 11, fontFamily: "monospace", width: 90, flexShrink: 0 }}>{label}</span>
        <div style={{ flex: 1, background: "rgba(255,255,255,0.07)", borderRadius: 2, height: 5, overflow: "hidden" }}>
          <div style={{ height: "100%", width: `${safePct}%`, background: color, borderRadius: 2, transition: "width 0.7s ease" }} />
        </div>
        <span style={{ color: warn ? "#f87171" : "rgba(255,255,255,0.75)", fontSize: 11, fontFamily: "monospace", minWidth: 200, textAlign: "right", flexShrink: 0 }}>
          {rightText}
        </span>
      </div>
    );
  }

  if (loading) return (
    <div style={{ color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 12, padding: 24 }}>Loading server status…</div>
  );
  if (error) return (
    <div style={{ color: "#f87171", fontFamily: "monospace", fontSize: 12, padding: 24 }}>
      Failed: {error}
      <button onClick={load} style={{ marginLeft: 12, background: "rgba(248,113,113,0.1)", border: "1px solid rgba(248,113,113,0.3)", color: "#f87171", borderRadius: 4, padding: "3px 10px", fontSize: 11, cursor: "pointer" }}>
        Retry
      </button>
    </div>
  );
  if (!data) return null;

  const cpuWarn  = (data.cpu_percent  ?? 0) > 85;
  const ramWarn  = (data.ram_percent  ?? 0) > 90;
  const diskWarn = (data.disk_percent ?? 0) > 90;
  const loadVal  = data.load_avg?.[0] ?? 0;
  const loadPct  = Math.min(100, (loadVal / Math.max(1, data.cpu_count ?? 1)) * 100);
  const loadWarn = loadPct > 85;

  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
        <span style={{ color: "rgba(255,255,255,0.7)", fontSize: 13, fontFamily: "monospace", fontWeight: 700 }}>Server Status</span>
        <button onClick={load} style={{ background: "rgba(0,229,160,0.08)", border: "1px solid rgba(0,229,160,0.25)", color: "#00e5a0", borderRadius: 4, padding: "4px 12px", fontSize: 10, fontFamily: "monospace", cursor: "pointer" }}>
          ↻ Refresh
        </button>
      </div>

      {/* System info grid */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2px 32px", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "12px 16px", marginBottom: 14 }}>
        {[
          ["Hostname",   data.hostname],
          ["Platform",   data.platform],
          ["Uptime",     fmtUptime(data.uptime_seconds)],
          ["Python",     data.python_version],
          ["CPU Cores",  data.cpu_count],
        ].map(([k, v]) => (
          <div key={k} style={{ display: "flex", gap: 10, padding: "5px 0" }}>
            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 11, fontFamily: "monospace", minWidth: 76 }}>{k}</span>
            <span style={{ color: "rgba(255,255,255,0.75)", fontSize: 11, fontFamily: "monospace" }}>{v ?? "—"}</span>
          </div>
        ))}
      </div>

      {/* Resource meters */}
      <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "4px 16px", marginBottom: 14 }}>
        <MeterRow
          label="CPU Usage"
          pct={data.cpu_percent}
          warn={cpuWarn}
          rightText={`${(data.cpu_percent ?? 0).toFixed(1)}%`}
        />
        <MeterRow
          label="RAM Usage"
          pct={data.ram_percent}
          warn={ramWarn}
          rightText={`${(data.ram_percent ?? 0).toFixed(1)}%  (${(data.ram_used_gb ?? 0).toFixed(1)} GB / ${(data.ram_total_gb ?? 0).toFixed(1)} GB)`}
        />
        <MeterRow
          label="Disk Usage"
          pct={data.disk_percent}
          warn={diskWarn}
          rightText={`${(data.disk_percent ?? 0).toFixed(1)}%  (${(data.disk_used_gb ?? 0).toFixed(1)} GB / ${(data.disk_total_gb ?? 0).toFixed(1)} GB)`}
        />
        <MeterRow
          label="Load Avg"
          pct={loadPct}
          warn={loadWarn}
          rightText={`${loadVal.toFixed(2)} · 5m ${data.load_avg?.[1]?.toFixed(2) ?? "—"} · 15m ${data.load_avg?.[2]?.toFixed(2) ?? "—"}`}
        />
      </div>

      {/* Top processes */}
      {data.top_processes && data.top_processes.length > 0 && (
        <>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", letterSpacing: "1px", marginBottom: 8 }}>
            TOP PROCESSES
          </div>
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "4px 16px" }}>
            {data.top_processes.map((p, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "7px 0", borderBottom: i < data.top_processes.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none" }}>
                <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace", maxWidth: "55%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {p.name}
                  <span style={{ color: "rgba(255,255,255,0.2)", marginLeft: 8 }}>pid {p.pid}</span>
                </span>
                <span style={{ color: "rgba(255,255,255,0.4)", fontSize: 11, fontFamily: "monospace" }}>
                  CPU {p.cpu_percent?.toFixed(1)}% · MEM {p.mem_percent?.toFixed(1)}%
                </span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// Agent Installer
// ════════════════════════════════════════════════════════════════════════════

const AGENT_PACKAGES = [
  { os: "Linux",   id: "linux-rpm-amd64",   label: "RPM amd64"           },
  { os: "Linux",   id: "linux-rpm-aarch64", label: "RPM aarch64"         },
  { os: "Linux",   id: "linux-deb-amd64",   label: "DEB amd64"           },
  { os: "Linux",   id: "linux-deb-aarch64", label: "DEB aarch64"         },
  { os: "Windows", id: "windows-msi",       label: "MSI 32-bit / 64-bit" },
  { os: "MacOS",   id: "macos-intel",       label: "Intel"               },
  { os: "MacOS",   id: "macos-arm64",       label: "Apple Silicon"       },
];

function getInstallCmd(pkg, manager) {
  const m = (manager || "").trim() || "x.x.x.x";
  const cmds = {
    "linux-rpm-amd64":
      `curl -o wazuh-agent-4.14.5-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.5-1.x86_64.rpm && \\\nsudo WAZUH_MANAGER='${m}' rpm -ihv wazuh-agent-4.14.5-1.x86_64.rpm`,
    "linux-rpm-aarch64":
      `curl -o wazuh-agent-4.14.5-1.aarch64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.5-1.aarch64.rpm && \\\nsudo WAZUH_MANAGER='${m}' rpm -ihv wazuh-agent-4.14.5-1.aarch64.rpm`,
    "linux-deb-amd64":
      `wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.5-1_amd64.deb && \\\nsudo WAZUH_MANAGER='${m}' dpkg -i ./wazuh-agent_4.14.5-1_amd64.deb`,
    "linux-deb-aarch64":
      `wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.5-1_arm64.deb && \\\nsudo WAZUH_MANAGER='${m}' dpkg -i ./wazuh-agent_4.14.5-1_arm64.deb`,
    "windows-msi":
      `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi -OutFile $env:tmp\\wazuh-agent;\nmsiexec.exe /i $env:tmp\\wazuh-agent /q WAZUH_MANAGER='${m}'`,
    "macos-intel":
      `curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.5-1.intel64.pkg && \\\necho "WAZUH_MANAGER='${m}'" > /tmp/wazuh_envs && \\\nsudo installer -pkg ./wazuh-agent.pkg -target /`,
    "macos-arm64":
      `curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.5-1.arm64.pkg && \\\necho "WAZUH_MANAGER='${m}'" > /tmp/wazuh_envs && \\\nsudo installer -pkg ./wazuh-agent.pkg -target /`,
  };
  return cmds[pkg] || "";
}

function getStartCmd(pkg) {
  if (pkg.startsWith("linux-")) return "sudo systemctl daemon-reload\nsudo systemctl enable wazuh-agent\nsudo systemctl start wazuh-agent";
  if (pkg === "windows-msi")    return "NET START Wazuh";
  return "sudo launchctl load /Library/LaunchDaemons/com.wazuh.agent.plist";
}

function CopyableCode({ code }) {
  const [copied, setCopied] = useState(false);
  return (
    <div style={{ position: "relative" }}>
      <pre style={{ background: "rgba(0,0,0,0.45)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 5, padding: "14px 16px", fontFamily: "monospace", fontSize: 12, color: "rgba(255,255,255,0.75)", whiteSpace: "pre-wrap", margin: 0, lineHeight: 1.6 }}>
        {code}
      </pre>
      <button
        onClick={() => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
        style={{ position: "absolute", top: 8, right: 8, background: copied ? "rgba(0,229,160,0.15)" : "rgba(255,255,255,0.06)", border: `1px solid ${copied ? "rgba(0,229,160,0.4)" : "rgba(255,255,255,0.12)"}`, color: copied ? "#00e5a0" : "rgba(255,255,255,0.4)", borderRadius: 3, padding: "4px 10px", fontSize: 10, fontFamily: "monospace", cursor: "pointer", transition: "all 0.15s" }}>
        {copied ? "✓ Copied" : "Copy"}
      </button>
    </div>
  );
}

function AgentInstallerTab() {
  const [pkg,      setPkg]      = useState("linux-rpm-amd64");
  const [addrType, setAddrType] = useState("fqdn");
  const [fqdn,     setFqdn]     = useState("");
  const [publicIp, setPublicIp] = useState("");

  const manager  = addrType === "fqdn" ? fqdn : publicIp;
  const osGroups = [...new Set(AGENT_PACKAGES.map(p => p.os))];

  return (
    <div style={{ maxWidth: 720 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 24 }}>
        <span style={{ fontSize: 18 }}>📦</span>
        <div style={{ color: "rgba(0,229,160,0.9)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700 }}>
          Deploy New Agent
        </div>
      </div>

      {/* Step 1 — Select package */}
      <div style={{ ...CARD, marginBottom: 16 }}>
        <div style={{ ...LABEL, marginBottom: 14 }}>Step 1 — Select Package to Download and Install on Your System</div>
        {osGroups.map(os => (
          <div key={os} style={{ marginBottom: 14 }}>
            <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace", letterSpacing: "1px", textTransform: "uppercase", marginBottom: 8 }}>{os}</div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {AGENT_PACKAGES.filter(p => p.os === os).map(p => (
                <button key={p.id} onClick={() => setPkg(p.id)}
                  style={{ background: pkg === p.id ? "rgba(0,229,160,0.12)" : "rgba(255,255,255,0.03)", border: `1px solid ${pkg === p.id ? "rgba(0,229,160,0.45)" : "rgba(255,255,255,0.08)"}`, color: pkg === p.id ? "#00e5a0" : "rgba(255,255,255,0.5)", borderRadius: 4, padding: "7px 14px", fontFamily: "monospace", fontSize: 11, fontWeight: pkg === p.id ? 700 : 400, cursor: "pointer", letterSpacing: "0.5px" }}>
                  {p.label}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Step 2 — Server address */}
      <div style={{ ...CARD, marginBottom: 16 }}>
        <div style={{ ...LABEL, marginBottom: 14 }}>Step 2 — Select Server Address</div>
        <div style={{ display: "flex", gap: 20, marginBottom: 12 }}>
          {[{ id: "fqdn", label: "Server FQDN" }, { id: "ip", label: "Public IP" }].map(opt => (
            <label key={opt.id} style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
              <input type="radio" name="agentAddrType" value={opt.id} checked={addrType === opt.id} onChange={() => setAddrType(opt.id)}
                style={{ accentColor: "#00e5a0", cursor: "pointer" }} />
              <span style={{ color: addrType === opt.id ? "#00e5a0" : "rgba(255,255,255,0.5)", fontFamily: "monospace", fontSize: 12, fontWeight: addrType === opt.id ? 700 : 400 }}>
                {opt.label}
              </span>
            </label>
          ))}
        </div>
        <input
          value={addrType === "fqdn" ? fqdn : publicIp}
          onChange={e => addrType === "fqdn" ? setFqdn(e.target.value) : setPublicIp(e.target.value)}
          placeholder={addrType === "fqdn" ? "e.g. cycentra.example.com" : "e.g. 203.0.113.45"}
          style={{ ...INPUT }}
        />
      </div>

      {/* Step 3 — Install command */}
      <div style={{ ...CARD, marginBottom: 16 }}>
        <div style={{ ...LABEL, marginBottom: 14 }}>Step 3 — Install Command</div>
        <CopyableCode code={getInstallCmd(pkg, manager)} />
      </div>

      {/* Step 4 — Start agent */}
      <div style={{ ...CARD }}>
        <div style={{ ...LABEL, marginBottom: 14 }}>Step 4 — Start Agent</div>
        <CopyableCode code={getStartCmd(pkg)} />
      </div>
    </div>
  );
}


// ════════════════════════════════════════════════════════════════════════════
// SIEM Automation — FP threshold + auto-case configuration
// ════════════════════════════════════════════════════════════════════════════

function SiemAutomationTab() {
  const [fpThreshold, setFpThreshold] = useState(90);
  const [saving,      setSaving]      = useState(false);
  const [saved,       setSaved]       = useState(false);
  const [err,         setErr]         = useState("");

  useEffect(() => {
    fetch(`${API_BASE}/api/ai/settings`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => {
        const val = d?.system?.fpThreshold;
        if (val != null) setFpThreshold(Number(val));
      })
      .catch(() => {});
  }, []);

  const handleSave = () => {
    setSaving(true); setErr(""); setSaved(false);
    fetch(`${API_BASE}/api/ai/settings`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ system: { fpThreshold: fpThreshold } }),
    })
      .then(r => r.ok ? r.json() : r.json().then(d => Promise.reject(d.error || "Save failed")))
      .then(() => { setSaving(false); setSaved(true); setTimeout(() => setSaved(false), 2500); })
      .catch(e => { setSaving(false); setErr(String(e)); });
  };

  const LABEL_S = { color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace",
    letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 8 };
  const CARD_S  = { background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.06)",
    borderRadius: 5, padding: "18px 20px", marginBottom: 16 };

  return (
    <div>
      <div style={{ color: "white", fontSize: 14, fontWeight: 600, marginBottom: 4 }}>SIEM Automation</div>
      <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, marginBottom: 24 }}>
        Configure automatic incident lifecycle transitions. Changes take effect on the next alert processed.
      </div>

      {/* FP threshold slider */}
      <div style={CARD_S}>
        <div style={LABEL_S}>False Positive Auto-Close Threshold</div>
        <div style={{ color: "rgba(255,255,255,0.6)", fontSize: 12, marginBottom: 14, lineHeight: 1.6 }}>
          Incidents whose FP probability reaches or exceeds this threshold are automatically closed
          without analyst review. Lowering this value closes more incidents automatically;
          raising it sends more to the analyst queue.
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <input
            type="range" min={50} max={99} step={1} value={fpThreshold}
            onChange={e => setFpThreshold(Number(e.target.value))}
            style={{ flex: 1, accentColor: "#00e5a0" }}
          />
          <span style={{ color: "#00e5a0", fontFamily: "monospace", fontWeight: 700, fontSize: 14, minWidth: 42, textAlign: "right" }}>
            {fpThreshold}%
          </span>
        </div>
      </div>

      {/* Band explanation */}
      <div style={CARD_S}>
        <div style={LABEL_S}>Automated Decision Bands (read-only)</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {[
            { range: `≥ ${fpThreshold}%`, action: "Auto-close",        color: "#ff3b3b",
              desc: "Immediately closed. No analyst review. Audit: auto_close." },
            { range: `40% – ${fpThreshold - 1}%`, action: "Investigating", color: "#f5c518",
              desc: "Held in the ambiguity band. Re-evaluated on every new correlated alert." },
            { range: "< 40%",             action: "In Review → Case",  color: "#00e5a0",
              desc: "Advanced to in_review. If severity is high/critical and ≥ 3 alerts, a CyCases investigation opens automatically." },
          ].map(b => (
            <div key={b.range} style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
              <span style={{ background: `${b.color}18`, border: `1px solid ${b.color}40`, color: b.color,
                fontSize: 9, fontFamily: "monospace", fontWeight: 700, padding: "3px 8px", borderRadius: 2,
                whiteSpace: "nowrap", minWidth: 110, textAlign: "center" }}>{b.range}</span>
              <div>
                <span style={{ color: b.color, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{b.action}</span>
                <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, marginLeft: 8 }}>{b.desc}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Case auto-open criteria */}
      <div style={CARD_S}>
        <div style={LABEL_S}>Case Auto-Open Criteria</div>
        <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, lineHeight: 1.8, fontFamily: "monospace" }}>
          All conditions must be true for CyCases to open automatically:<br/>
          {"  "}① FP probability &lt; 40%<br/>
          {"  "}② Severity is <span style={{ color: "#ff3b3b" }}>critical</span> or <span style={{ color: "#ff8c00" }}>high</span><br/>
          {"  "}③ Alert count ≥ 3 correlated alerts<br/>
          {"  "}④ No case already open for this incident<br/>
          {"  "}⑤ Enrichment complete (MISP ran, LLM ran, or ≥ 3 alerts)
        </div>
      </div>

      {err && <div style={{ color: "#ff6464", fontSize: 11, fontFamily: "monospace", marginBottom: 10 }}>✗ {err}</div>}
      <button
        onClick={handleSave}
        disabled={saving}
        style={{
          background: saved ? "rgba(0,229,160,0.15)" : "rgba(0,229,160,0.1)",
          border: "1px solid rgba(0,229,160,0.35)", color: "#00e5a0",
          padding: "8px 22px", borderRadius: 3, fontFamily: "monospace", fontSize: 12,
          fontWeight: 700, cursor: saving ? "not-allowed" : "pointer",
        }}>
        {saving ? "Saving…" : saved ? "✓ Saved" : "Save Automation Settings"}
      </button>
    </div>
  );
}

// ── Two-column Settings layout ────────────────────────────────────────────────

const PLATFORM_TABS = [
  { id: "updates",    label: "Updates & Version" },
  { id: "env",        label: "Environment Config" },
  { id: "scheduler",  label: "Scheduler" },
  { id: "users",      label: "Users & Auth" },
  { id: "backup",     label: "Backup & Restore" },
  { id: "server",     label: "Server Status" },
  { id: "automation", label: "SIEM Automation" },
];

const COMP_TABS = [
  { id: "comp-siem",           label: "SIEM Sources"        },
  { id: "comp-framework-docs", label: "Framework Documents" },
  { id: "comp-grc-settings",   label: "GRC Settings"        },
  { id: "comp-notifications",  label: "Notifications"       },
];

const AGENT_INSTALLER_TABS = [
  { id: "deploy", label: "Deploy New Agent" },
];

const MODULES = [
  { id: "platform",        label: "Platform Settings",   icon: "⚙️", color: "#00e5a0" },
  { id: "comp",            label: "Security Compliance", icon: "🛡️", color: "#4d9eff" },
  { id: "agent-installer", label: "Agent Installer",     icon: "📦", color: "#b06eff" },
];

export function SystemSettingsPage() {
  const [module, setModule] = useState("platform");
  const [tab, setTab]       = useState("updates");
  const [compTab, setCompTab] = useState("comp-siem");

  const currentTabs = module === "platform" ? PLATFORM_TABS : module === "comp" ? COMP_TABS : AGENT_INSTALLER_TABS;

  return (
    <div>
      {/* Page header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ color: "white", fontSize: 22, fontWeight: 700, fontFamily: "monospace", marginBottom: 4 }}>
          Settings
        </div>
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 13 }}>
          Platform configuration and Security Compliance (GRC) settings
        </div>
      </div>

      {/* Two-column layout */}
      <div style={{ display: "flex", gap: 20 }}>

        {/* Left: module selector */}
        <div style={{ width: 210, flexShrink: 0 }}>
          <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace",
            letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 10 }}>Module</div>
          {MODULES.map(m => (
            <button key={m.id} onClick={() => {
              setModule(m.id);
              if (m.id === "platform") setTab("updates");
              else if (m.id === "comp") setCompTab("comp-siem");
            }}
              style={{
                width: "100%", padding: "12px 14px", borderRadius: 6, marginBottom: 6,
                background: module === m.id ? `${m.color}0e` : "rgba(255,255,255,0.02)",
                border: `1px solid ${module === m.id ? `${m.color}40` : "rgba(255,255,255,0.06)"}`,
                color: module === m.id ? m.color : "rgba(255,255,255,0.45)",
                fontFamily: "monospace", fontSize: 12, fontWeight: module === m.id ? 700 : 400,
                cursor: "pointer", textAlign: "left", display: "flex", alignItems: "center", gap: 8,
                transition: "all 0.15s",
              }}>
              <span style={{ fontSize: 16 }}>{m.icon}</span>
              {m.label}
            </button>
          ))}
        </div>

        {/* Right: tab content */}
        <div style={{ flex: 1, minWidth: 0 }}>
          {/* Tab bar */}
          <div style={{ display: "flex", gap: 4, borderBottom: "1px solid rgba(255,255,255,0.06)", marginBottom: 24 }}>
            {currentTabs.map(t => {
              const active = module === "platform" ? tab === t.id : module === "comp" ? compTab === t.id : true;
              return (
                <button key={t.id}
                  onClick={() => { if (module === "platform") setTab(t.id); else if (module === "comp") setCompTab(t.id); }}
                  style={{
                    background: "none", border: "none",
                    borderBottom: active ? "2px solid #00e5a0" : "2px solid transparent",
                    color: active ? "#00e5a0" : "rgba(255,255,255,0.45)",
                    padding: "8px 18px", fontFamily: "monospace", fontSize: 12,
                    fontWeight: active ? 700 : 400, cursor: "pointer",
                    marginBottom: -1, letterSpacing: "0.5px",
                  }}>
                  {t.label}
                </button>
              );
            })}
          </div>

          {/* Platform Settings tabs (unchanged) */}
          {module === "platform" && (
            <>
              {tab === "updates"   && <UpdatesTab />}
              {tab === "env"       && <EnvConfigTab />}
              {tab === "scheduler" && <SchedulerTab />}
              {tab === "users"     && (
                <>
                  <CollapsibleSection icon="👤" title="User Management">
                    <UserManagementTab />
                  </CollapsibleSection>
                  <SSOTab />
                </>
              )}
              {tab === "backup"    && <BackupTab />}
              {tab === "server"    && <ServerStatusTab />}
              {tab === "automation" && <SiemAutomationTab />}
            </>
          )}

          {/* Security Compliance (GRC) Settings tabs */}
          {module === "comp" && (
            <>
              {compTab === "comp-siem"           && <CompSIEMSourcesTab />}
              {compTab === "comp-framework-docs" && <CompFrameworkDocsTab />}
              {compTab === "comp-grc-settings"   && <CompGRCSettingsTab />}
              {compTab === "comp-notifications"  && <CompNotificationsTab />}
            </>
          )}

          {/* Agent Installer */}
          {module === "agent-installer" && <AgentInstallerTab />}
        </div>
      </div>
    </div>
  );
}
