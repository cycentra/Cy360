/**
 * src/pages/guest-scan/GuestScanPage.jsx
 * =========================================
 * Standalone guest scan page — accessible at /guest-scan without login.
 * Offers Standard scan only (Deep/Passive are visible but greyed out).
 * After completion, shows a limited free-tier dashboard.
 *
 * Uses the same /api/scan/* endpoints as the main app; no auth required
 * since the Flask backend doesn't enforce session on these routes.
 */

import { useState, useRef, useEffect } from "react";

// ── Helpers ───────────────────────────────────────────────────────────────────

const API_BASE = "";

function genGuestUid() {
  return "guest_" + Math.random().toString(36).slice(2, 10);
}

const MODULES = [
  "DNS Reconnaissance", "Subdomain Enumeration", "Web Analysis",
  "Crypto & SSL Audit", "Email Security Check", "WHOIS & History",
  "OSINT Gathering", "Cloud Infrastructure", "Generating Report",
];

const RISK_CONFIG = {
  critical: { color: "#ff3b3b", bg: "rgba(255,59,59,0.12)", label: "CRITICAL" },
  high:     { color: "#ff8c00", bg: "rgba(255,140,0,0.12)",  label: "HIGH"     },
  medium:   { color: "#f5c518", bg: "rgba(245,197,24,0.12)", label: "MEDIUM"   },
  low:      { color: "#00e5a0", bg: "rgba(0,229,160,0.12)",  label: "LOW"      },
};

// ── GuestDashboard ────────────────────────────────────────────────────────────

function RiskDonut({ assets = [] }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  assets.forEach(a => (a.vulnerabilities || []).forEach(v => {
    const s = v.severity?.toLowerCase();
    if (counts[s] !== undefined) counts[s]++;
  }));
  const total      = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  const colors     = ["#ff3b3b", "#ff8c00", "#f5c518", "#00e5a0"];
  const keys       = ["critical", "high", "medium", "low"];
  const totalVulns = Object.values(counts).reduce((a, b) => a + b, 0);
  let cumulative   = 0;
  const segments   = keys.map((k, i) => {
    const pct = counts[k] / total;
    const s   = cumulative * 360;
    const e   = (cumulative + pct) * 360;
    cumulative += pct;
    const r = 60, cx = 80, cy = 80;
    const toR = deg => (deg - 90) * Math.PI / 180;
    const x1 = cx + r * Math.cos(toR(s)); const y1 = cy + r * Math.sin(toR(s));
    const x2 = cx + r * Math.cos(toR(e)); const y2 = cy + r * Math.sin(toR(e));
    const d  = pct === 0 ? "" : `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${pct > 0.5 ? 1 : 0} 1 ${x2} ${y2} Z`;
    return { d, color: colors[i], key: k, count: counts[k] };
  });
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
      <svg width="160" height="160" style={{ flexShrink: 0 }}>
        <circle cx="80" cy="80" r="60" fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.05)" strokeWidth="1"/>
        {segments.map(s => s.d && <path key={s.key} d={s.d} fill={s.color} opacity="0.85"/>)}
        <circle cx="80" cy="80" r="38" fill="#0d1117"/>
        <text x="80" y="76" textAnchor="middle" fill="white" fontSize="22" fontWeight="800" fontFamily="'Space Mono',monospace">{totalVulns}</text>
        <text x="80" y="94" textAnchor="middle" fill="rgba(255,255,255,0.35)" fontSize="9" fontFamily="monospace">FINDINGS</text>
      </svg>
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {keys.map((k, i) => (
          <div key={k} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: colors[i] }}/>
            <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, width: 65 }}>
              {k.charAt(0).toUpperCase() + k.slice(1)}
            </span>
            <span style={{ color: colors[i], fontFamily: "monospace", fontSize: 13, fontWeight: 700 }}>{counts[k]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function LockedWidget({ title, accent = "#00e5a0" }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
      borderTop: `2px solid ${accent}40`, borderRadius: 5, padding: "18px 22px", position: "relative", overflow: "hidden" }}>
      <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, letterSpacing: "1.5px",
        textTransform: "uppercase", fontFamily: "monospace", marginBottom: 14 }}>{title}</div>
      {/* Blurred placeholder rows */}
      {[80, 60, 70, 50].map((w, i) => (
        <div key={i} style={{ height: 12, width: `${w}%`, background: "rgba(255,255,255,0.05)",
          borderRadius: 3, marginBottom: 10, filter: "blur(2px)" }}/>
      ))}
      {/* Lock overlay */}
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center", background: "rgba(9,11,16,0.65)",
        backdropFilter: "blur(3px)" }}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.25)" strokeWidth="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace",
          marginTop: 6, letterSpacing: "1px" }}>FULL ACCESS REQUIRED</div>
      </div>
    </div>
  );
}

function GuestDashboard({ data, onRescan }) {
  const assets    = data?.assets || [];
  const domain    = data?.meta?.domain || "—";
  const scanId    = data?.meta?.scan_id || "—";
  const totalAssets = assets.length;
  const totalFindings = assets.reduce((n, a) => n + (a.vulnerabilities?.length || 0), 0);
  const critCount = assets.reduce((n, a) =>
    n + (a.vulnerabilities || []).filter(v => v.severity?.toLowerCase() === "critical").length, 0);
  const highCount = assets.reduce((n, a) =>
    n + (a.vulnerabilities || []).filter(v => v.severity?.toLowerCase() === "high").length, 0);
  const subdomains = assets.filter(a => a.type === "Subdomain").length;

  return (
    <div style={{ minHeight: "100vh", background: "#090b10",
      backgroundImage: "radial-gradient(ellipse at 20% 30%, rgba(0,229,160,0.025) 0%, transparent 50%)",
      fontFamily: "system-ui, sans-serif" }}>

      {/* Top bar */}
      <div style={{ height: 52, background: "rgba(10,12,18,0.98)", borderBottom: "1px solid rgba(255,255,255,0.06)",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 24px", position: "sticky", top: 0, zIndex: 60 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <svg width="20" height="20" viewBox="0 0 24 24">
            <polygon points="12,2 22,8 22,16 12,22 2,16 2,8" fill="none" stroke="#00e5a0" strokeWidth="1.5"/>
            <circle cx="12" cy="12" r="2" fill="#00e5a0"/>
          </svg>
          <div style={{ color: "white", fontFamily: "'Space Mono',monospace", fontSize: 12, fontWeight: 700, letterSpacing: "2px" }}>
            CY<span style={{ color: "#00e5a0" }}>CENTRA</span>
            <span style={{ color: "#00e5a0", fontSize: 8, letterSpacing: "4px", opacity: 0.6, marginLeft: 4 }}>360°</span>
          </div>
          <span style={{ background: "rgba(0,229,160,0.12)", color: "#00e5a0", fontSize: 9, fontFamily: "monospace",
            fontWeight: 700, padding: "2px 8px", borderRadius: 2, letterSpacing: "1px", marginLeft: 8 }}>
            FREE SCAN
          </span>
        </div>
        <button onClick={onRescan}
          style={{ background: "transparent", color: "rgba(255,255,255,0.4)", border: "1px solid rgba(255,255,255,0.12)",
            borderRadius: 4, padding: "5px 14px", fontSize: 11, fontFamily: "monospace", cursor: "pointer" }}>
          ← New Scan
        </button>
      </div>

      <div style={{ padding: "28px 32px", maxWidth: 1200, margin: "0 auto" }}>

        {/* Header */}
        <div style={{ marginBottom: 22 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: "white", margin: 0 }}>Free Scan Results</h1>
            <span style={{ background: "rgba(0,229,160,0.1)", color: "#00e5a0", border: "1px solid rgba(0,229,160,0.3)",
              fontSize: 10, fontFamily: "monospace", fontWeight: 700, padding: "2px 8px", borderRadius: 2 }}>
              STANDARD SCAN
            </span>
          </div>
          <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13, marginTop: 4, marginBottom: 0 }}>
            {domain} · Scan ID: {scanId}
          </p>
        </div>

        {/* Stat cards */}
        <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
          {[
            { label: "Assets Found",   value: totalAssets,   accent: "#00e5a0" },
            { label: "Total Findings", value: totalFindings, accent: "#ff8c00" },
            { label: "Critical",       value: critCount,     accent: "#ff3b3b" },
            { label: "High",           value: highCount,     accent: "#ff8c00" },
            { label: "Subdomains",     value: subdomains,    accent: "#4d9eff" },
          ].map(c => (
            <div key={c.label} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
              borderTop: `2px solid ${c.accent}`, padding: "16px 20px", borderRadius: 4, flex: 1, minWidth: 120 }}>
              <div style={{ color: c.accent, fontSize: 28, fontWeight: 800, fontFamily: "'Space Mono',monospace", lineHeight: 1 }}>{c.value}</div>
              <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 10, letterSpacing: "1.5px", marginTop: 5, textTransform: "uppercase" }}>{c.label}</div>
            </div>
          ))}
        </div>

        {/* Row 1: Risk donut + 2 locked widgets */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14, marginBottom: 14 }}>
          <div style={{ background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.07)",
            borderTop: "2px solid #ff3b3b", borderRadius: 5, padding: "18px 22px" }}>
            <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, letterSpacing: "1.5px",
              textTransform: "uppercase", fontFamily: "monospace", marginBottom: 14 }}>
              Overall Risk Overview
            </div>
            <RiskDonut assets={assets}/>
          </div>
          <LockedWidget title="SSL / Crypto Health" accent="#f5c518"/>
          <LockedWidget title="Infrastructure & Cloud" accent="#4d9eff"/>
        </div>

        {/* Row 2: 3 locked widgets */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14, marginBottom: 24 }}>
          <LockedWidget title="Email Security" accent="#b06eff"/>
          <LockedWidget title="Web Security" accent="#ff8c00"/>
          <LockedWidget title="Brand & External Exposure" accent="#ff3b3b"/>
        </div>

        {/* CTA banner */}
        <div style={{ background: "linear-gradient(135deg, rgba(0,229,160,0.08) 0%, rgba(77,158,255,0.06) 100%)",
          border: "1px solid rgba(0,229,160,0.2)", borderRadius: 8, padding: "28px 32px",
          display: "flex", alignItems: "center", justifyContent: "space-between", gap: 24, flexWrap: "wrap" }}>
          <div>
            <div style={{ color: "white", fontSize: 18, fontWeight: 700, marginBottom: 6 }}>
              Want full visibility into your attack surface?
            </div>
            <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 13, lineHeight: 1.6, maxWidth: 560 }}>
              This free scan shows only an overview. The full CyCentra 360 platform gives you complete
              SSL/Crypto health, Email security posture, Web vulnerabilities, Supply chain risk,
              Brand exposure monitoring, and AI-powered remediation guidance — in real time.
            </div>
          </div>
          <a href="https://cycentra.com/contact" target="_blank" rel="noreferrer"
            style={{ display: "inline-block", background: "#00e5a0", color: "#0d0f14",
              fontFamily: "'Space Mono',monospace", fontWeight: 700, fontSize: 13, letterSpacing: "1px",
              padding: "14px 28px", borderRadius: 4, textDecoration: "none", whiteSpace: "nowrap",
              flexShrink: 0 }}>
            Get Full Access →
          </a>
        </div>

        <div style={{ marginTop: 16, textAlign: "center", color: "rgba(255,255,255,0.15)", fontSize: 11, fontFamily: "monospace" }}>
          Powered by CyCentra 360 · Free scan provided as a courtesy · Results are indicative only
        </div>
      </div>
    </div>
  );
}

// ── GuestScanPage ─────────────────────────────────────────────────────────────

export function GuestScanPage() {
  const [domain,        setDomain]      = useState("");
  const [email,         setEmail]       = useState("");
  const [scanState,     setScanState]   = useState("idle");
  const [progress,      setProgress]    = useState(0);
  const [currentModule, setCurrentModule] = useState("");
  const [elapsed,       setElapsed]     = useState(0);
  const [lastLog,       setLastLog]     = useState("");
  const [scanData,      setScanData]    = useState(null);
  const uidRef   = useRef(genGuestUid());
  const timerRef = useRef(null);
  const pollRef  = useRef(null);

  // Cleanup intervals on unmount (e.g. user navigates away mid-scan)
  useEffect(() => {
    return () => {
      clearInterval(pollRef.current);
      clearInterval(timerRef.current);
    };
  }, []);

  const fmt           = s => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  const circumference = 2 * Math.PI * 54;
  const strokeDash    = circumference - (progress / 100) * circumference;

  // Retry fetching the scan result — the log says "done" before the JSON is flushed to disk
  const fetchResultWithRetry = async (uid, attempts = 8, delayMs = 2500) => {
    for (let i = 0; i < attempts; i++) {
      try {
        const r = await fetch(`${API_BASE}/api/scans/latest?uid=${encodeURIComponent(uid)}`);
        if (r.ok) {
          const raw = await r.json();
          if (raw?.assets || raw?.meta) return raw; // valid result
        }
      } catch {}
      if (i < attempts - 1) await new Promise(res => setTimeout(res, delayMs));
    }
    return null;
  };

  const pollStatus = () => {
    let noProgressCount = 0, pollCount = 0;
    pollRef.current = setInterval(async () => {
      try {
        pollCount++;
        const res = await fetch(`${API_BASE}/api/scan/status`);
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
          setLastLog("Loading your results...");
          // Retry loop: the JSON file may not be flushed yet when the log fires
          const raw = await fetchResultWithRetry(uidRef.current);
          if (raw) {
            setScanData(raw);
          } else {
            setLastLog("Results unavailable — please try scanning again.");
            setScanState("error");
          }
          return;
        }

        if (pollCount > 8 && s.running === false && (s.progress || 0) < 5) {
          noProgressCount++;
          if (noProgressCount >= 4) {
            const raw = await fetchResultWithRetry(uidRef.current, 3, 1500);
            if (raw?.assets?.length) {
              clearInterval(pollRef.current); clearInterval(timerRef.current);
              setProgress(100); setScanState("done"); setScanData(raw);
            } else {
              clearInterval(pollRef.current); clearInterval(timerRef.current);
              setLastLog("Scan engine not responding. Please try again later.");
              setScanState("error");
            }
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
        body: JSON.stringify({
          domain,
          scan_type: "standard",
          notify_email: email,
          include_subdomains: true,
          uid: uidRef.current,
        }),
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
    uidRef.current = genGuestUid();
    setScanState("idle"); setProgress(0); setElapsed(0);
    setCurrentModule(""); setLastLog(""); setScanData(null);
  };

  // Show limited dashboard after scan completes
  if (scanState === "done" && scanData) {
    return <GuestDashboard data={scanData} onRescan={resetScan}/>;
  }

  return (
    <div style={{ minHeight: "100vh", background: "#090b10",
      backgroundImage: "radial-gradient(ellipse at 20% 30%, rgba(0,229,160,0.025) 0%, transparent 50%)",
      fontFamily: "system-ui, sans-serif" }}>

      {/* Top bar */}
      <div style={{ height: 52, background: "rgba(10,12,18,0.98)", borderBottom: "1px solid rgba(255,255,255,0.06)",
        display: "flex", alignItems: "center", padding: "0 24px", position: "sticky", top: 0, zIndex: 60 }}>
        <svg width="20" height="20" viewBox="0 0 24 24" style={{ marginRight: 10 }}>
          <polygon points="12,2 22,8 22,16 12,22 2,16 2,8" fill="none" stroke="#00e5a0" strokeWidth="1.5"/>
          <circle cx="12" cy="12" r="2" fill="#00e5a0"/>
        </svg>
        <div style={{ color: "white", fontFamily: "'Space Mono',monospace", fontSize: 12, fontWeight: 700, letterSpacing: "2px" }}>
          CY<span style={{ color: "#00e5a0" }}>CENTRA</span>
          <span style={{ color: "#00e5a0", fontSize: 8, letterSpacing: "4px", opacity: 0.6, marginLeft: 4 }}>360°</span>
        </div>
        <span style={{ background: "rgba(0,229,160,0.1)", color: "#00e5a0", fontSize: 9, fontFamily: "monospace",
          fontWeight: 700, padding: "2px 8px", borderRadius: 2, letterSpacing: "1px", marginLeft: 12 }}>
          FREE SCAN
        </span>
      </div>

      {/* Hero */}
      <div style={{ textAlign: "center", padding: "48px 24px 32px" }}>
        <h1 style={{ color: "white", fontSize: 28, fontWeight: 700, margin: "0 0 10px" }}>
          Free Attack Surface Scan
        </h1>
        <p style={{ color: "rgba(255,255,255,0.4)", fontSize: 14, maxWidth: 500, margin: "0 auto" }}>
          Get an instant security overview of any domain — powered by CyCentra's ASM engine.
          No account required.
        </p>
      </div>

      {/* Main content */}
      <div style={{ maxWidth: 960, margin: "0 auto", padding: "0 24px 48px",
        display: "grid", gridTemplateColumns: "1fr 340px", gap: 24, alignItems: "start" }}>

        {/* Form panel */}
        <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 6, padding: 28 }}>

          {/* Domain input */}
          <div style={{ marginBottom: 18 }}>
            <label style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, letterSpacing: "1.5px",
              textTransform: "uppercase", fontFamily: "monospace", display: "block", marginBottom: 8 }}>
              Target Domain *
            </label>
            <input type="text" value={domain} onChange={e => setDomain(e.target.value)}
              placeholder="example.com" disabled={scanState === "running"}
              style={{ width: "100%", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
                color: "white", padding: "12px 16px", borderRadius: 4, fontSize: 14, fontFamily: "monospace",
                outline: "none", boxSizing: "border-box", opacity: scanState === "running" ? 0.5 : 1 }}/>
          </div>

          {/* Email input */}
          <div style={{ marginBottom: 18 }}>
            <label style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, letterSpacing: "1.5px",
              textTransform: "uppercase", fontFamily: "monospace", display: "block", marginBottom: 8 }}>
              Notify Email <span style={{ color: "rgba(255,255,255,0.2)", fontWeight: 400 }}>(optional)</span>
            </label>
            <input type="email" value={email} onChange={e => setEmail(e.target.value)}
              placeholder="you@company.com" disabled={scanState === "running"}
              style={{ width: "100%", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
                color: "white", padding: "12px 16px", borderRadius: 4, fontSize: 14, fontFamily: "monospace",
                outline: "none", boxSizing: "border-box", opacity: scanState === "running" ? 0.5 : 1 }}/>
          </div>

          {/* Scan type selector */}
          <div style={{ marginBottom: 18 }}>
            <label style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, letterSpacing: "1.5px",
              textTransform: "uppercase", fontFamily: "monospace", display: "block", marginBottom: 10 }}>
              Scan Type
            </label>

            {/* Standard — active, selectable */}
            <div style={{ display: "flex", alignItems: "flex-start", gap: 12, padding: "12px 14px", marginBottom: 6,
              background: "rgba(0,229,160,0.08)", border: "1px solid rgba(0,229,160,0.3)", borderRadius: 4, cursor: scanState === "running" ? "not-allowed" : "default" }}>
              <div style={{ width: 16, height: 16, borderRadius: "50%", flexShrink: 0, marginTop: 2,
                border: "2px solid #00e5a0", background: "#00e5a0", boxShadow: "0 0 8px #00e5a0" }}/>
              <div>
                <div style={{ color: "#00e5a0", fontSize: 13, fontWeight: 600 }}>Standard (Recommended)</div>
                <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, marginTop: 2 }}>
                  DNS, Web, Crypto, Email, OSINT — ~45s
                </div>
              </div>
            </div>

            {/* Deep Scan — greyed out */}
            <div style={{ display: "flex", alignItems: "flex-start", gap: 12, padding: "12px 14px", marginBottom: 6,
              background: "rgba(255,255,255,0.01)", border: "1px solid rgba(255,255,255,0.05)",
              borderRadius: 4, opacity: 0.4, cursor: "not-allowed" }}>
              <div style={{ width: 16, height: 16, borderRadius: "50%", flexShrink: 0, marginTop: 2,
                border: "2px solid rgba(255,255,255,0.15)", background: "transparent" }}/>
              <div>
                <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 13, fontWeight: 600 }}>
                  Deep Scan
                  <span style={{ marginLeft: 8, fontSize: 9, fontFamily: "monospace", color: "rgba(255,255,255,0.3)",
                    background: "rgba(255,255,255,0.05)", padding: "1px 6px", borderRadius: 2 }}>PAID</span>
                </div>
                <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 11, marginTop: 2 }}>
                  Full suite + AI enrichment — ~90s
                </div>
              </div>
            </div>

            {/* Passive Scan — greyed out */}
            <div style={{ display: "flex", alignItems: "flex-start", gap: 12, padding: "12px 14px",
              background: "rgba(255,255,255,0.01)", border: "1px solid rgba(255,255,255,0.05)",
              borderRadius: 4, opacity: 0.4, cursor: "not-allowed" }}>
              <div style={{ width: 16, height: 16, borderRadius: "50%", flexShrink: 0, marginTop: 2,
                border: "2px solid rgba(255,255,255,0.15)", background: "transparent" }}/>
              <div>
                <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 13, fontWeight: 600 }}>
                  Passive Scan
                  <span style={{ marginLeft: 8, fontSize: 9, fontFamily: "monospace", color: "rgba(255,255,255,0.3)",
                    background: "rgba(255,255,255,0.05)", padding: "1px 6px", borderRadius: 2 }}>PAID</span>
                </div>
                <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 11, marginTop: 2 }}>
                  Read-only, no active probing — ~20s
                </div>
              </div>
            </div>
          </div>

          {/* Subdomain enumeration — always on, greyed out toggle */}
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 22, opacity: 0.45, cursor: "not-allowed" }}>
            <div style={{ width: 18, height: 18, borderRadius: 3, display: "flex", alignItems: "center",
              justifyContent: "center", flexShrink: 0, border: "2px solid rgba(255,255,255,0.2)",
              background: "transparent", pointerEvents: "none" }}/>
            <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 13 }}>Include Subdomain Enumeration</span>
            <span style={{ fontSize: 9, fontFamily: "monospace", color: "rgba(255,255,255,0.3)",
              background: "rgba(255,255,255,0.05)", padding: "1px 6px", borderRadius: 2 }}>PAID</span>
          </div>

          {/* Action buttons */}
          {scanState === "idle" && (
            <button onClick={startScan} disabled={!domain}
              style={{ width: "100%", background: domain ? "#00e5a0" : "rgba(0,229,160,0.2)",
                color: domain ? "#0d0f14" : "rgba(0,229,160,0.3)", fontFamily: "'Space Mono',monospace",
                fontWeight: 700, fontSize: 13, letterSpacing: "1px", padding: "14px 24px",
                border: "none", borderRadius: 4, cursor: domain ? "pointer" : "not-allowed", textTransform: "uppercase" }}>
              Launch Free Scan →
            </button>
          )}

          {scanState === "running" && (
            <button disabled style={{ width: "100%", background: "rgba(0,229,160,0.1)", color: "rgba(0,229,160,0.4)",
              fontFamily: "monospace", fontSize: 13, padding: "14px", border: "1px solid rgba(0,229,160,0.2)",
              borderRadius: 4, cursor: "not-allowed" }}>
              Scanning...
            </button>
          )}

          {scanState === "done" && !scanData && (
            <div style={{ display: "flex", gap: 10 }}>
              <button onClick={resetScan} style={{ flex: 1, background: "transparent", color: "rgba(255,255,255,0.5)",
                border: "1px solid rgba(255,255,255,0.15)", borderRadius: 4, padding: "12px", fontFamily: "monospace",
                fontSize: 12, cursor: "pointer" }}>New Scan</button>
              <button
                onClick={async () => {
                  setLastLog("Retrying...");
                  const raw = await fetchResultWithRetry(uidRef.current, 5, 2000);
                  if (raw) setScanData(raw);
                  else setLastLog("Still loading — please wait a moment and try again.");
                }}
                style={{ flex: 1, background: "rgba(0,229,160,0.08)", color: "#00e5a0",
                  border: "1px solid rgba(0,229,160,0.25)", borderRadius: 4, padding: "12px", fontFamily: "monospace",
                  fontSize: 12, cursor: "pointer", fontWeight: 700 }}>
                View Results →
              </button>
            </div>
          )}

          {scanState === "error" && (
            <button onClick={resetScan} style={{ width: "100%", background: "rgba(255,59,59,0.15)", color: "#ff3b3b",
              border: "1px solid rgba(255,59,59,0.3)", borderRadius: 4, padding: "12px",
              fontFamily: "monospace", fontSize: 12, cursor: "pointer" }}>← Try Again</button>
          )}
        </div>

        {/* Progress panel */}
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

          <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 6, padding: 24, textAlign: "center" }}>
            <div style={{ position: "relative", display: "inline-flex", alignItems: "center",
              justifyContent: "center", marginBottom: 16 }}>
              <svg width="128" height="128" style={{ transform: "rotate(-90deg)" }}>
                <circle cx="64" cy="64" r="54" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8"/>
                <circle cx="64" cy="64" r="54" fill="none"
                  stroke={scanState === "error" ? "#ff3b3b" : scanState !== "idle" ? "#00e5a0" : "rgba(0,229,160,0.2)"}
                  strokeWidth="8" strokeLinecap="round"
                  strokeDasharray={circumference} strokeDashoffset={strokeDash}
                  style={{ transition: "stroke-dashoffset 1s ease", filter: scanState !== "idle" ? "drop-shadow(0 0 8px #00e5a060)" : "none" }}/>
              </svg>
              <div style={{ position: "absolute", textAlign: "center" }}>
                <div style={{ color: scanState === "error" ? "#ff3b3b" : "#00e5a0", fontSize: 26,
                  fontFamily: "'Space Mono',monospace", fontWeight: 700 }}>
                  {scanState === "idle" ? "--:--" : fmt(elapsed)}
                </div>
                <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, letterSpacing: "1.5px",
                  fontFamily: "monospace", marginTop: 2 }}>
                  {scanState === "idle" ? "READY" : scanState === "done" ? "COMPLETE" : scanState === "error" ? "FAILED" : "ELAPSED"}
                </div>
              </div>
            </div>

            {scanState === "running" && <div style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace", marginBottom: 10 }}>{currentModule}...</div>}
            {scanState === "done"    && <div style={{ color: "#00e5a0", fontSize: 14, fontWeight: 700, marginBottom: 6 }}>✓ Scan Complete</div>}
            {scanState === "error"   && <div style={{ color: "#ff3b3b", fontSize: 13, marginBottom: 6 }}>✗ Could not reach backend</div>}

            <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2 }}>
              <div style={{ height: "100%", width: `${progress}%`, background: scanState === "error" ? "#ff3b3b" : "#00e5a0",
                borderRadius: 2, transition: "width 1s ease" }}/>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 5 }}>
              <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>0%</span>
              <span style={{ color: progress > 0 ? "#00e5a0" : "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>{Math.round(progress)}%</span>
              <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>100%</span>
            </div>

            {lastLog && (
              <div style={{ marginTop: 8, background: "rgba(0,0,0,0.3)", borderRadius: 3, padding: "5px 10px",
                color: scanState === "error" ? "#ff6b6b" : "rgba(0,229,160,0.5)", fontSize: 10,
                fontFamily: "monospace", whiteSpace: "normal", wordBreak: "break-word", lineHeight: 1.5 }}>
                {lastLog}
              </div>
            )}
          </div>

          {/* Module checklist */}
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: 6, padding: 18 }}>
            <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, letterSpacing: "1.5px",
              textTransform: "uppercase", fontFamily: "monospace", marginBottom: 10 }}>Scan Modules</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {MODULES.map((m, i) => {
                const modIdx = Math.min(MODULES.length - 1, Math.floor((progress / 100) * MODULES.length));
                const done   = progress > 0 && i < modIdx;
                const active = i === modIdx && scanState === "running";
                return (
                  <div key={m} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div style={{ width: 13, height: 13, borderRadius: "50%", flexShrink: 0,
                      background: done ? "#00e5a0" : active ? "rgba(0,229,160,0.2)" : "rgba(255,255,255,0.05)",
                      border: active ? "1.5px solid #00e5a0" : "none",
                      display: "flex", alignItems: "center", justifyContent: "center" }}>
                      {done   && <span style={{ fontSize: 7, color: "#0d0f14", fontWeight: 900 }}>✓</span>}
                      {active && <div style={{ width: 5, height: 5, borderRadius: "50%", background: "#00e5a0" }}/>}
                    </div>
                    <span style={{ fontSize: 11, fontFamily: "monospace",
                      color: done ? "rgba(255,255,255,0.7)" : active ? "#00e5a0" : "rgba(255,255,255,0.25)" }}>
                      {m}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Trust badge */}
          <div style={{ background: "rgba(0,229,160,0.04)", border: "1px solid rgba(0,229,160,0.12)",
            borderRadius: 6, padding: "14px 18px", textAlign: "center" }}>
            <div style={{ color: "rgba(0,229,160,0.7)", fontSize: 11, fontFamily: "monospace", fontWeight: 700, marginBottom: 4 }}>
              ✓ No registration required
            </div>
            <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, lineHeight: 1.5 }}>
              Scan results are not stored beyond 24 hours.<br/>
              For continuous monitoring, get full access.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
