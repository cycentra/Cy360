/**
 * src/pages/scan/ScanPage.jsx
 * ============================
 * Enhanced: Three-tier scan comparison matrix (Passive / Standard / Deep),
 * CTEM Continuous Sync with configurable refresh interval (min 1 hour),
 * and full standard scan type support.
 */

import { useState, useRef, useEffect, useCallback } from "react";
import { API_BASE, _BASE_DOMAIN } from '../../core/constants.js';

const CUSTOMER_DOMAIN = window.__CYCENTRA_DOMAIN__ || _BASE_DOMAIN || "";

const MODULES = [
  "DNS Reconnaissance", "Subdomain Enumeration", "Web Analysis", "Crypto & SSL Audit",
  "Email Security Check", "WHOIS & History", "OSINT Gathering", "Cloud Infrastructure",
  "Dark Web Monitoring", "Supply Chain Analysis", "AI Risk Enrichment", "Generating Report",
];

// ── Scan tier definitions ─────────────────────────────────────────────────────
const SCAN_TIERS = [
  {
    id: "passive",
    label: "Passive",
    badge: "OSINT",
    color: "#b06eff",
    bg: "rgba(176,110,255,0.08)",
    border: "rgba(176,110,255,0.3)",
    time: "~20s",
    desc: "Non-intrusive. Zero network footprint.",
    features: [
      { label: "DNS & WHOIS lookup", included: true },
      { label: "Certificate transparency", included: true },
      { label: "Email security (SPF/DMARC/DKIM)", included: true },
      { label: "Dark web mention search", included: true },
      { label: "OSINT & threat intel feeds", included: true },
      { label: "Active port scanning", included: false },
      { label: "Protocol handshaking", included: false },
      { label: "AI enrichment & remediation", included: false },
      { label: "PDF Executive Report", included: false },
    ],
  },
  {
    id: "standard",
    label: "Standard",
    badge: "BALANCED",
    color: "#00e5a0",
    bg: "rgba(0,229,160,0.08)",
    border: "rgba(0,229,160,0.3)",
    time: "~60s",
    desc: "Balanced active discovery. Recommended.",
    features: [
      { label: "DNS & WHOIS lookup", included: true },
      { label: "Certificate transparency", included: true },
      { label: "Email security (SPF/DMARC/DKIM)", included: true },
      { label: "Dark web mention search", included: true },
      { label: "OSINT & threat intel feeds", included: true },
      { label: "Active port scanning (14 ports)", included: true },
      { label: "Protocol handshaking (SSH/RDP/SMB)", included: true },
      { label: "AI enrichment & remediation", included: true },
      { label: "PDF Executive Report", included: true },
    ],
  },
  {
    id: "deep",
    label: "Deep",
    badge: "FULL SUITE",
    color: "#ff8c00",
    bg: "rgba(255,140,0,0.08)",
    border: "rgba(255,140,0,0.3)",
    time: "~90s",
    desc: "Full probing. Heavy payload testing.",
    note: "Deep scans can impact network performance.",
    features: [
      { label: "DNS & WHOIS lookup", included: true },
      { label: "Certificate transparency", included: true },
      { label: "Email security (SPF/DMARC/DKIM)", included: true },
      { label: "Dark web mention search", included: true },
      { label: "OSINT & threat intel feeds", included: true },
      { label: "Full port range (1–65535)", included: true },
      { label: "Protocol handshaking (SSH/RDP/SMB/FTP)", included: true },
      { label: "AI enrichment & step-by-step remediation", included: true },
      { label: "PDF Executive + Technical Reports", included: true },
    ],
  },
];

const SYNC_INTERVALS = [
  { label: "Hourly",     hours: 1,   seconds: 3600 },
  { label: "Every 4h",  hours: 4,   seconds: 14400 },
  { label: "Every 8h",  hours: 8,   seconds: 28800 },
  { label: "Every 12h", hours: 12,  seconds: 43200 },
  { label: "Daily",     hours: 24,  seconds: 86400 },
  { label: "Every 48h", hours: 48,  seconds: 172800 },
  { label: "Weekly",    hours: 168, seconds: 604800 },
];

// ── Sub-components ─────────────────────────────────────────────────────────────

function ScanTierMatrix({ selected, onSelect, disabled }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <label style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", display: "block", marginBottom: 12 }}>
        Scan Mode
      </label>
      {/* Bubble selector */}
      <div style={{ display: "flex", gap: 6, marginBottom: 16 }}>
        {SCAN_TIERS.map(t => (
          <button key={t.id} onClick={() => !disabled && onSelect(t.id)} disabled={disabled}
            style={{
              flex: 1, padding: "8px 6px", border: `1px solid ${selected === t.id ? t.border : "rgba(255,255,255,0.08)"}`,
              borderRadius: 4, background: selected === t.id ? t.bg : "rgba(255,255,255,0.02)",
              cursor: disabled ? "not-allowed" : "pointer", transition: "all 0.15s",
              outline: "none", opacity: disabled ? 0.5 : 1,
            }}>
            <div style={{ color: selected === t.id ? t.color : "rgba(255,255,255,0.35)", fontSize: 9, fontFamily: "monospace", letterSpacing: "1px", textTransform: "uppercase", marginBottom: 2 }}>{t.badge}</div>
            <div style={{ color: selected === t.id ? t.color : "rgba(255,255,255,0.6)", fontSize: 13, fontWeight: 700 }}>{t.label}</div>
            <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>{t.time}</div>
          </button>
        ))}
      </div>

      {/* Feature comparison grid */}
      {(() => {
        const tier = SCAN_TIERS.find(t => t.id === selected);
        if (!tier) return null;
        return (
          <div style={{ background: "rgba(0,0,0,0.2)", border: `1px solid ${tier.border}`, borderRadius: 4, padding: "12px 14px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
              <div style={{ color: tier.color, fontSize: 12, fontWeight: 700 }}>{tier.label} Scan</div>
              <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 11 }}>—</div>
              <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 11 }}>{tier.desc}</div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "5px 10px" }}>
              {tier.features.map((f, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ color: f.included ? tier.color : "rgba(255,255,255,0.12)", fontSize: 11, flexShrink: 0 }}>
                    {f.included ? "✓" : "–"}
                  </span>
                  <span style={{ color: f.included ? "rgba(255,255,255,0.55)" : "rgba(255,255,255,0.2)", fontSize: 11 }}>{f.label}</span>
                </div>
              ))}
            </div>
            {tier.note && (
              <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 6, borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: 8 }}>
                <span style={{ color: "#f5c518", fontSize: 10 }}>⚠</span>
                <span style={{ color: "rgba(245,197,24,0.7)", fontSize: 10, fontFamily: "monospace" }}>{tier.note}</span>
              </div>
            )}
          </div>
        );
      })()}
    </div>
  );
}

function CTEMSyncPanel({ domain, scanType, includeSubdomains, user }) {
  const [enabled,       setEnabled]     = useState(false);
  const [intervalSec,   setIntervalSec] = useState(3600);
  const [activeJob,     setActiveJob]   = useState(null);
  const [saving,        setSaving]      = useState(false);
  const [statusMsg,     setStatusMsg]   = useState("");

  // Load any existing CTEM job for this domain
  useEffect(() => {
    fetch(`${API_BASE}/api/scheduler/jobs`, { credentials: "include" })
      .then(r => r.ok ? r.json() : [])
      .then(jobs => {
        const mine = Array.isArray(jobs) ? jobs.find(j => j.params?.domain === domain && j.type === "asm_scan") : null;
        if (mine) {
          setActiveJob(mine);
          setEnabled(mine.enabled !== false);
          if (mine.schedule?.seconds) setIntervalSec(mine.schedule.seconds);
        }
      })
      .catch(() => {});
  }, [domain]);

  const saveSync = async () => {
    if (!domain) return;
    setSaving(true);
    setStatusMsg("");
    try {
      // Delete existing job if any
      if (activeJob?.id) {
        await fetch(`${API_BASE}/api/scheduler/jobs/${activeJob.id}`, { method: "DELETE", credentials: "include" });
      }

      if (!enabled) {
        setActiveJob(null);
        setStatusMsg("Continuous Sync disabled.");
        setSaving(false);
        return;
      }

      const res = await fetch(`${API_BASE}/api/scheduler/jobs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          type: "asm_scan",
          name: `CTEM Continuous Sync — ${domain}`,
          params: { domain, scan_type: scanType, include_subdomains: includeSubdomains, actor_uid: user?.id || "ctem" },
          schedule: { type: "interval", seconds: intervalSec },
        }),
      });
      const job = await res.json();
      if (res.ok) {
        setActiveJob(job);
        const iv = SYNC_INTERVALS.find(i => i.seconds === intervalSec);
        setStatusMsg(`Continuous Sync active — refreshing ${iv?.label?.toLowerCase() || `every ${intervalSec / 3600}h`}.`);
      } else {
        setStatusMsg(`Error: ${job.error || "Could not save"}`);
      }
    } catch (e) {
      setStatusMsg(`Error: ${e.message}`);
    }
    setSaving(false);
  };

  const syncAccentColor = enabled ? "#00e5a0" : "rgba(255,255,255,0.2)";

  return (
    <div style={{ marginTop: 24, background: "rgba(0,229,160,0.03)", border: "1px solid rgba(0,229,160,0.1)", borderRadius: 6, padding: "18px 20px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {/* Toggle */}
          <div onClick={() => setEnabled(v => !v)} style={{ width: 36, height: 20, borderRadius: 10, background: enabled ? "rgba(0,229,160,0.3)" : "rgba(255,255,255,0.08)", border: `1px solid ${syncAccentColor}`, cursor: "pointer", position: "relative", flexShrink: 0, transition: "all 0.2s" }}>
            <div style={{ position: "absolute", top: 2, left: enabled ? 17 : 2, width: 14, height: 14, borderRadius: "50%", background: enabled ? "#00e5a0" : "rgba(255,255,255,0.25)", transition: "left 0.2s", boxShadow: enabled ? "0 0 6px #00e5a0" : "none" }}/>
          </div>
          <div>
            <div style={{ color: enabled ? "#00e5a0" : "rgba(255,255,255,0.5)", fontSize: 12, fontWeight: 700, letterSpacing: "0.5px" }}>Continuous Sync</div>
            <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace", marginTop: 1 }}>CTEM Refresh Interval — min. 1 hour</div>
          </div>
        </div>
        {activeJob && (
          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#00e5a0", animation: "pulse 2s infinite" }}/>
            <span style={{ color: "rgba(0,229,160,0.6)", fontSize: 10, fontFamily: "monospace" }}>ACTIVE</span>
          </div>
        )}
      </div>

      {enabled && (
        <>
          <div style={{ marginBottom: 14 }}>
            <label style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace", letterSpacing: "1px", textTransform: "uppercase", display: "block", marginBottom: 8 }}>Refresh Interval</label>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {SYNC_INTERVALS.map(iv => (
                <button key={iv.seconds} onClick={() => setIntervalSec(iv.seconds)}
                  style={{
                    padding: "5px 12px", borderRadius: 3, fontSize: 11, fontFamily: "monospace", cursor: "pointer",
                    background: intervalSec === iv.seconds ? "rgba(0,229,160,0.15)" : "rgba(255,255,255,0.04)",
                    border: `1px solid ${intervalSec === iv.seconds ? "rgba(0,229,160,0.4)" : "rgba(255,255,255,0.08)"}`,
                    color: intervalSec === iv.seconds ? "#00e5a0" : "rgba(255,255,255,0.45)",
                    outline: "none",
                  }}>
                  {iv.label}
                </button>
              ))}
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", background: "rgba(0,0,0,0.2)", borderRadius: 3, marginBottom: 14 }}>
            <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>NEXT SCAN TYPE</span>
            <span style={{ color: "#00e5a0", fontSize: 10, fontFamily: "monospace", fontWeight: 700, textTransform: "uppercase" }}>{scanType}</span>
            <span style={{ color: "rgba(255,255,255,0.15)", fontSize: 10, fontFamily: "monospace", marginLeft: "auto" }}>domain: {domain}</span>
          </div>
        </>
      )}

      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <button onClick={saveSync} disabled={saving}
          style={{ background: enabled ? "rgba(0,229,160,0.1)" : "rgba(255,255,255,0.04)", color: enabled ? "#00e5a0" : "rgba(255,255,255,0.3)", border: `1px solid ${enabled ? "rgba(0,229,160,0.3)" : "rgba(255,255,255,0.08)"}`, borderRadius: 3, padding: "7px 16px", fontSize: 11, fontFamily: "monospace", fontWeight: 700, cursor: saving ? "not-allowed" : "pointer", letterSpacing: "0.5px", opacity: saving ? 0.5 : 1 }}>
          {saving ? "Saving..." : enabled ? "Apply Sync" : "Save (Disabled)"}
        </button>
        {statusMsg && (
          <span style={{ color: statusMsg.startsWith("Error") ? "#ff6b6b" : "rgba(0,229,160,0.6)", fontSize: 11, fontFamily: "monospace" }}>{statusMsg}</span>
        )}
      </div>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

export function ScanPage({ user, onScanComplete }) {
  const [domain,            setDomain]     = useState(CUSTOMER_DOMAIN);
  const [email,             setEmail]      = useState(user?.email || "");
  const [scanType,          setScanType]   = useState("deep");
  const [includeSubdomains, setIncludeSub] = useState(true);
  const [scanState,         setScanState]  = useState("idle");
  const [progress,          setProgress]   = useState(0);
  const [currentModule,     setCurrentModule] = useState("");
  const [elapsed,           setElapsed]    = useState(0);
  const [lastLog,           setLastLog]    = useState("");
  const [reports,           setReports]    = useState([]);
  const [reportsLoading,    setReportsLoading] = useState(false);
  const timerRef = useRef(null);
  const pollRef  = useRef(null);

  const fetchReports = useCallback(() => {
    setReportsLoading(true);
    fetch(`${API_BASE}/api/scans/reports`, { credentials: "include" })
      .then(r => r.ok ? r.json() : [])
      .then(d => { setReports(Array.isArray(d) ? d : []); setReportsLoading(false); })
      .catch(() => setReportsLoading(false));
  }, []);

  useEffect(() => { fetchReports(); }, [fetchReports]);

  const fmt           = s => `${String(Math.floor(s / 60)).padStart(2,"0")}:${String(s % 60).padStart(2,"0")}`;
  const circumference = 2 * Math.PI * 54;
  const strokeDash    = circumference - (progress / 100) * circumference;
  const tierDef       = SCAN_TIERS.find(t => t.id === scanType) || SCAN_TIERS[1];

  const pollStatus = () => {
    let noProgressCount = 0;
    let pollCount       = 0;
    pollRef.current = setInterval(async () => {
      try {
        pollCount++;
        const res = await fetch(`${API_BASE}/api/scan/status`, { credentials: "include" });
        if (!res.ok) return;
        const s = await res.json();
        if (s.progress != null && s.progress > 0) setProgress(s.progress);
        if (s.current_module) setCurrentModule(s.current_module);
        if (s.last_log)       setLastLog(s.last_log);
        const logText = (s.last_log || "").toLowerCase();
        const isDone  = (!s.running && s.progress >= 98) ||
                        logText.includes("portal json saved") ||
                        logText.includes("ndjson report saved") ||
                        logText.includes("all done") ||
                        logText.includes("scan complete");
        if (isDone) {
          clearInterval(pollRef.current); clearInterval(timerRef.current);
          setProgress(100); setCurrentModule("Complete"); setScanState("done");
          fetchReports();
          try {
            const r2 = await fetch(`${API_BASE}/api/scans/latest?uid=${encodeURIComponent(user?.id || "")}`, { credentials: "include" });
            if (r2.ok) onScanComplete(await r2.json());
          } catch {}
          return;
        }
        if (pollCount > 8 && s.running === false && (s.progress || 0) < 5) {
          noProgressCount++;
          if (noProgressCount >= 4) {
            try {
              const r2 = await fetch(`${API_BASE}/api/scans/latest?uid=${encodeURIComponent(user?.id || "")}`, { credentials: "include" });
              if (r2.ok) {
                const raw = await r2.json();
                if (raw?.assets?.length) {
                  clearInterval(pollRef.current); clearInterval(timerRef.current);
                  setProgress(100); setScanState("done"); onScanComplete(raw);
                } else {
                  clearInterval(pollRef.current); clearInterval(timerRef.current);
                  setLastLog("Scan engine not responding. Check backend logs at /var/log/cycentra/cy-asm/logs/");
                  setScanState("error");
                }
              }
            } catch {}
          }
        } else if (s.running === true || s.progress > 0) {
          noProgressCount = 0;
        }
      } catch {}
    }, 3000);
  };

  const startScan = async () => {
    if (!domain) return;
    setScanState("running"); setProgress(2); setElapsed(0);
    setLastLog("Connecting to scan engine..."); setCurrentModule("Initialising...");
    let secs = 0;
    timerRef.current = setInterval(() => { secs++; setElapsed(secs); }, 1000);
    try {
      const res = await fetch(`${API_BASE}/api/scan/trigger`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ domain, scan_type: scanType, notify_email: email, include_subdomains: includeSubdomains, uid: user?.id || "anonymous" }),
      });
      const body = await res.json().catch(() => ({}));
      if (res.status === 503) {
        setLastLog(body.error || "Scan engine not found");
        setCurrentModule("Waiting for scan engine...");
      } else if (!res.ok) {
        setLastLog(`Error: ${body.error || res.statusText}`);
        setScanState("error"); clearInterval(timerRef.current); return;
      } else {
        setLastLog(`Scan started for ${domain} — polling for progress...`);
        setCurrentModule("DNS Reconnaissance"); setProgress(5);
      }
    } catch (e) {
      setLastLog(`Cannot reach backend: ${e.message}`);
      setScanState("error"); clearInterval(timerRef.current); return;
    }
    pollStatus();
  };

  const resetScan = () => {
    clearInterval(timerRef.current); clearInterval(pollRef.current);
    setScanState("idle"); setProgress(0); setElapsed(0); setCurrentModule(""); setLastLog("");
  };

  const viewReport = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/scans/latest?uid=${encodeURIComponent(user?.id || "")}`);
      if (res.ok) onScanComplete(await res.json());
    } catch {}
  };

  const handleDownloadReport = async (filename) => {
    try {
      const res = await fetch(`${API_BASE}/api/scans/reports/download?file=${encodeURIComponent(filename)}`, { credentials: "include" });
      if (!res.ok) return;
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url);
    } catch {}
  };

  return (
    <div>
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: "white" }}>Scan Operations</h1>
        <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13, marginTop: 4 }}>Configure, launch, and schedule your attack surface reconnaissance</p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 360px", gap: 24, alignItems: "start" }}>

        {/* ── Left: Form ─────────────────────────────────────────────────────── */}
        <div>
          <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderTop: `2px solid ${tierDef.color}`, borderRadius: 6, padding: 28 }}>

            {/* Three-tier scan mode selector */}
            <ScanTierMatrix selected={scanType} onSelect={setScanType} disabled={scanState === "running"} />

            {/* Domain */}
            <div style={{ marginBottom: 18 }}>
              <label style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", display: "block", marginBottom: 8 }}>Target Domain</label>
              <div style={{ display: "flex", alignItems: "center", gap: 10, background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 4, padding: "12px 16px" }}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="rgba(0,229,160,0.6)" strokeWidth="2">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
                <span style={{ color: "#00e5a0", fontSize: 14, fontFamily: "monospace", fontWeight: 600 }}>{domain}</span>
                <span style={{ marginLeft: "auto", color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace" }}>YOUR DOMAIN</span>
              </div>
            </div>

            {/* Notify Email */}
            <div style={{ marginBottom: 18 }}>
              <label style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", display: "block", marginBottom: 8 }}>Notify Email</label>
              <input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="security@company.com" disabled={scanState === "running"}
                style={{ width: "100%", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", color: "white", padding: "12px 16px", borderRadius: 4, fontSize: 14, fontFamily: "monospace", outline: "none", boxSizing: "border-box", opacity: scanState === "running" ? 0.5 : 1 }}/>
            </div>

            {/* Subdomain toggle */}
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 22 }}>
              <div onClick={() => scanState !== "running" && setIncludeSub(v => !v)}
                style={{ width: 18, height: 18, borderRadius: 3, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, border: `2px solid ${includeSubdomains ? "#00e5a0" : "rgba(255,255,255,0.2)"}`, background: includeSubdomains ? "#00e5a0" : "transparent" }}>
                {includeSubdomains && <span style={{ color: "#0d0f14", fontSize: 11, fontWeight: 900 }}>✓</span>}
              </div>
              <span style={{ color: "rgba(255,255,255,0.7)", fontSize: 13 }}>Include Subdomain Enumeration</span>
            </div>

            {/* Action buttons */}
            {scanState === "idle" && (
              <button onClick={startScan}
                style={{ width: "100%", background: tierDef.color, color: "#0d0f14", fontFamily: "'Space Mono',monospace", fontWeight: 700, fontSize: 13, letterSpacing: "1px", padding: "14px 24px", border: "none", borderRadius: 4, cursor: "pointer", textTransform: "uppercase" }}>
                Launch {tierDef.label} Scan →
              </button>
            )}
            {scanState === "running" && (
              <button disabled style={{ width: "100%", background: "rgba(0,229,160,0.1)", color: "rgba(0,229,160,0.4)", fontFamily: "monospace", fontSize: 13, padding: "14px", border: "1px solid rgba(0,229,160,0.2)", borderRadius: 4, cursor: "not-allowed" }}>
                Scanning...
              </button>
            )}
            {scanState === "done" && (
              <div style={{ display: "flex", gap: 10 }}>
                <button onClick={resetScan} style={{ flex: 1, background: "transparent", color: "rgba(255,255,255,0.5)", border: "1px solid rgba(255,255,255,0.15)", borderRadius: 4, padding: "12px", fontFamily: "monospace", fontSize: 12, cursor: "pointer" }}>New Scan</button>
                <button onClick={viewReport} style={{ flex: 1, background: "#00e5a0", color: "#0d0f14", border: "none", borderRadius: 4, padding: "12px", fontFamily: "monospace", fontSize: 12, fontWeight: 700, cursor: "pointer" }}>View Report →</button>
              </div>
            )}
            {scanState === "error" && (
              <button onClick={resetScan} style={{ width: "100%", background: "rgba(255,59,59,0.15)", color: "#ff3b3b", border: "1px solid rgba(255,59,59,0.3)", borderRadius: 4, padding: "12px", fontFamily: "monospace", fontSize: 12, cursor: "pointer" }}>← Try Again</button>
            )}

            {/* CLI */}
            <div style={{ marginTop: 14, background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 4, padding: "10px 14px" }}>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace", marginBottom: 4 }}>CLI EQUIVALENT</div>
              <code style={{ color: "#00e5a0", fontSize: 11 }}>python3 cycentra_scan.py {domain} {user?.id || "<uid>"} {scanType}</code>
            </div>
          </div>

          {/* ── CTEM Continuous Sync ───────────────────────────────────────────── */}
          <CTEMSyncPanel domain={domain} scanType={scanType} includeSubdomains={includeSubdomains} user={user} />
        </div>

        {/* ── Right: Progress panel ──────────────────────────────────────────── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

          <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: 24, textAlign: "center" }}>
            <div style={{ position: "relative", display: "inline-flex", alignItems: "center", justifyContent: "center", marginBottom: 16 }}>
              <svg width="128" height="128" style={{ transform: "rotate(-90deg)" }}>
                <circle cx="64" cy="64" r="54" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8"/>
                <circle cx="64" cy="64" r="54" fill="none"
                  stroke={scanState === "error" ? "#ff3b3b" : scanState !== "idle" ? tierDef.color : "rgba(0,229,160,0.2)"}
                  strokeWidth="8" strokeLinecap="round"
                  strokeDasharray={circumference} strokeDashoffset={strokeDash}
                  style={{ transition: "stroke-dashoffset 1s ease", filter: scanState !== "idle" ? `drop-shadow(0 0 8px ${tierDef.color}60)` : "none" }}/>
              </svg>
              <div style={{ position: "absolute", textAlign: "center" }}>
                <div style={{ color: scanState === "error" ? "#ff3b3b" : tierDef.color, fontSize: 26, fontFamily: "'Space Mono',monospace", fontWeight: 700 }}>
                  {scanState === "idle" ? "--:--" : fmt(elapsed)}
                </div>
                <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, letterSpacing: "1.5px", fontFamily: "monospace", marginTop: 2 }}>
                  {scanState === "idle" ? "READY" : scanState === "done" ? "COMPLETE" : scanState === "error" ? "FAILED" : "ELAPSED"}
                </div>
              </div>
            </div>

            {scanState === "running" && <div style={{ color: tierDef.color, fontSize: 12, fontFamily: "monospace", marginBottom: 10 }}>{currentModule}...</div>}
            {scanState === "done"    && <div style={{ color: "#00e5a0", fontSize: 14, fontWeight: 700, marginBottom: 6 }}>✓ Scan Complete</div>}
            {scanState === "error"   && <div style={{ color: "#ff3b3b", fontSize: 13, marginBottom: 6 }}>✗ Could not reach backend</div>}

            <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2 }}>
              <div style={{ height: "100%", width: `${progress}%`, background: scanState === "error" ? "#ff3b3b" : tierDef.color, borderRadius: 2, transition: "width 1s ease" }}/>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 5 }}>
              <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>0%</span>
              <span style={{ color: progress > 0 ? tierDef.color : "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>{Math.round(progress)}%</span>
              <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>100%</span>
            </div>

            {lastLog && (
              <div style={{ marginTop: 8, background: "rgba(0,0,0,0.3)", borderRadius: 3, padding: "5px 10px", color: scanState === "error" ? "#ff6b6b" : "rgba(0,229,160,0.5)", fontSize: 10, fontFamily: "monospace", whiteSpace: "normal", overflow: "hidden", wordBreak: "break-word", lineHeight: 1.5 }}>
                {lastLog}
              </div>
            )}
          </div>

          {/* Module checklist */}
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 6, padding: 18 }}>
            <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", marginBottom: 10 }}>Scan Modules</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {MODULES.map((m, i) => {
                const modIdx = Math.min(MODULES.length - 1, Math.floor((progress / 100) * MODULES.length));
                const done   = progress > 0 && i < modIdx;
                const active = i === modIdx && scanState === "running";
                return (
                  <div key={m} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div style={{ width: 13, height: 13, borderRadius: "50%", flexShrink: 0, background: done ? tierDef.color : active ? `${tierDef.color}33` : "rgba(255,255,255,0.05)", border: active ? `1.5px solid ${tierDef.color}` : "none", display: "flex", alignItems: "center", justifyContent: "center" }}>
                      {done   && <span style={{ fontSize: 7, color: "#0d0f14", fontWeight: 900 }}>✓</span>}
                      {active && <div style={{ width: 5, height: 5, borderRadius: "50%", background: tierDef.color, animation: "pulse 1s infinite" }}/>}
                    </div>
                    <span style={{ fontSize: 11, fontFamily: "monospace", color: done ? "rgba(255,255,255,0.7)" : active ? tierDef.color : "rgba(255,255,255,0.25)" }}>{m}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* ── PDF Reports ────────────────────────────────────────────────────────── */}
      <div style={{ marginTop: 28 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700 }}>PDF Reports</span>
            <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>— last 6 generated</span>
          </div>
          <button onClick={fetchReports} disabled={reportsLoading}
            style={{ background: "transparent", border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.65)", borderRadius: 3, padding: "4px 10px", fontSize: 10, fontFamily: "monospace", cursor: "pointer", opacity: reportsLoading ? 0.5 : 1 }}>
            {reportsLoading ? "Loading…" : "↺ Refresh"}
          </button>
        </div>

        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, overflow: "hidden" }}>
          {reportsLoading ? (
            <div style={{ padding: "20px 16px", color: "rgba(255,255,255,0.2)", fontFamily: "monospace", fontSize: 12 }}>Loading reports…</div>
          ) : reports.length === 0 ? (
            <div style={{ padding: "20px 16px", color: "rgba(255,255,255,0.2)", fontFamily: "monospace", fontSize: 12 }}>
              No PDF reports found. Run a scan to generate Executive &amp; Technical reports.
            </div>
          ) : (
            reports.map((r, i) => {
              const dt        = new Date(r.modified * 1000);
              const dateStr   = dt.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
              const timeStr   = dt.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
              const isExec    = r.type === "executive";
              const typeColor = isExec ? "#4d9eff" : "#00e5a0";
              return (
                <div key={r.filename} style={{ display: "flex", alignItems: "center", gap: 14, padding: "12px 16px", borderBottom: i < reports.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none" }}>
                  <div style={{ width: 7, height: 7, borderRadius: "50%", background: typeColor, flexShrink: 0 }}/>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 12, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.filename}</div>
                    <div style={{ display: "flex", gap: 10, marginTop: 3 }}>
                      <span style={{ color: typeColor, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase", fontWeight: 700 }}>{r.type}</span>
                      {r.domain && <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace" }}>{r.domain}</span>}
                    </div>
                  </div>
                  <div style={{ textAlign: "right", flexShrink: 0 }}>
                    <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>{dateStr}</div>
                    <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, fontFamily: "monospace" }}>{timeStr} · {r.size_kb} KB</div>
                  </div>
                  <button onClick={() => handleDownloadReport(r.filename)}
                    style={{ background: `rgba(${isExec ? "77,158,255" : "0,229,160"},0.08)`, color: typeColor, border: `1px solid ${typeColor}40`, borderRadius: 3, padding: "5px 14px", fontSize: 10, fontFamily: "monospace", fontWeight: 700, cursor: "pointer", letterSpacing: "0.5px", flexShrink: 0 }}>
                    ↓ PDF
                  </button>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
