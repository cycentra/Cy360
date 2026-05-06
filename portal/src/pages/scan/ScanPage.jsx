/**
 * src/pages/scan/ScanPage.jsx
 * ============================
 * Original look & feel — 3 scan levels, circular elapsed timer,
 * progress bar with %, module checklist, notify email, CLI equivalent block.
 */

import { useState, useRef, useEffect, useCallback } from "react";
import { API_BASE, _BASE_DOMAIN } from '../../core/constants.js';

// Locked to the customer's own base domain — not a free-entry field
const CUSTOMER_DOMAIN = window.__CYCENTRA_DOMAIN__ || _BASE_DOMAIN || "";

const MODULES = [
  "DNS Reconnaissance", "Subdomain Enumeration", "Web Analysis", "Crypto & SSL Audit",
  "Email Security Check", "WHOIS & History", "OSINT Gathering", "Cloud Infrastructure",
  "Dark Web Monitoring", "Supply Chain Analysis", "AI Risk Enrichment", "Generating Report",
];

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
    if (!domain) return; // domain is fixed to CUSTOMER_DOMAIN but guard stays as safety
    setScanState("running"); setProgress(2); setElapsed(0);
    setLastLog("Connecting to scan engine..."); setCurrentModule("Initialising...");

    let secs = 0;
    timerRef.current = setInterval(() => { secs++; setElapsed(secs); }, 1000);

    try {
      const res = await fetch(`${API_BASE}/api/scan/trigger`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          domain, scan_type: scanType, notify_email: email,
          include_subdomains: includeSubdomains, uid: user?.id || "anonymous",
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
        setCurrentModule("DNS Reconnaissance");
        setProgress(5);
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
      const res = await fetch(
        `${API_BASE}/api/scans/reports/download?file=${encodeURIComponent(filename)}`,
        { credentials: "include" }
      );
      if (!res.ok) return;
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href     = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch {}
  };

  return (
    <div>
      <div style={{ marginBottom:28 }}>
        <h1 style={{ fontSize:22, fontWeight:700, color:"white" }}>Initiate ASM Scan</h1>
        <p style={{ color:"rgba(255,255,255,0.35)", fontSize:13, marginTop:4 }}>Launch automated reconnaissance &amp; exposure assessment</p>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 360px", gap:24, alignItems:"start" }}>

        {/* Form panel */}
        <div style={{ background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:6, padding:28 }}>

          {/* Domain — locked to the customer's own base domain */}
          <div style={{ marginBottom:18 }}>
            <label style={{ color:"rgba(255,255,255,0.5)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", display:"block", marginBottom:8 }}>Target Domain</label>
            <div style={{ display:"flex", alignItems:"center", gap:10, background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.08)", borderRadius:4, padding:"12px 16px" }}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="rgba(0,229,160,0.6)" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
              <span style={{ color:"#00e5a0", fontSize:14, fontFamily:"monospace", fontWeight:600 }}>{domain}</span>
              <span style={{ marginLeft:"auto", color:"rgba(255,255,255,0.2)", fontSize:9, fontFamily:"monospace" }}>YOUR DOMAIN</span>
            </div>
          </div>

          {/* Notify Email */}
          <div style={{ marginBottom:18 }}>
            <label style={{ color:"rgba(255,255,255,0.5)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", display:"block", marginBottom:8 }}>Notify Email</label>
            <input type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="security@company.com" disabled={scanState==="running"}
              style={{ width:"100%", background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.12)", color:"white", padding:"12px 16px", borderRadius:4, fontSize:14, fontFamily:"monospace", outline:"none", boxSizing:"border-box", opacity:scanState==="running"?0.5:1 }}/>
          </div>

          <div style={{ marginBottom:18 }}>
            <label style={{ color:"rgba(255,255,255,0.5)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", display:"block", marginBottom:10 }}>Scan Type</label>
            {[
              {id:"deep",    label:"Deep Scan",   desc:"Full suite + AI enrichment — ~90s"},
              {id:"passive", label:"Passive Scan", desc:"Read-only, no active probing — ~20s"},
            ].map(t => (
              <div key={t.id} onClick={() => scanState!=="running" && setScanType(t.id)}
                style={{ display:"flex", alignItems:"flex-start", gap:12, padding:"12px 14px", marginBottom:6, background:scanType===t.id?"rgba(0,229,160,0.08)":"rgba(255,255,255,0.02)", border:`1px solid ${scanType===t.id?"rgba(0,229,160,0.3)":"rgba(255,255,255,0.06)"}`, borderRadius:4, cursor:scanState==="running"?"not-allowed":"pointer" }}>
                <div style={{ width:16, height:16, borderRadius:"50%", flexShrink:0, marginTop:2, border:`2px solid ${scanType===t.id?"#00e5a0":"rgba(255,255,255,0.2)"}`, background:scanType===t.id?"#00e5a0":"transparent", boxShadow:scanType===t.id?"0 0 8px #00e5a0":"none" }}/>
                <div>
                  <div style={{ color:scanType===t.id?"#00e5a0":"rgba(255,255,255,0.8)", fontSize:13, fontWeight:600 }}>{t.label}</div>
                  <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, marginTop:2 }}>{t.desc}</div>
                </div>
              </div>
            ))}
          </div>

          <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:22 }}>
            <div onClick={() => scanState!=="running" && setIncludeSub(v=>!v)}
              style={{ width:18, height:18, borderRadius:3, cursor:"pointer", display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0, border:`2px solid ${includeSubdomains?"#00e5a0":"rgba(255,255,255,0.2)"}`, background:includeSubdomains?"#00e5a0":"transparent" }}>
              {includeSubdomains && <span style={{ color:"#0d0f14", fontSize:11, fontWeight:900 }}>✓</span>}
            </div>
            <span style={{ color:"rgba(255,255,255,0.7)", fontSize:13 }}>Include Subdomain Enumeration</span>
          </div>

          {scanState==="idle" && (
            <button onClick={startScan}
              style={{ width:"100%", background:"#00e5a0", color:"#0d0f14", fontFamily:"'Space Mono',monospace", fontWeight:700, fontSize:13, letterSpacing:"1px", padding:"14px 24px", border:"none", borderRadius:4, cursor:"pointer", textTransform:"uppercase" }}>
              Launch ASM Scan →
            </button>
          )}

          {scanState==="running" && (
            <button disabled style={{ width:"100%", background:"rgba(0,229,160,0.1)", color:"rgba(0,229,160,0.4)", fontFamily:"monospace", fontSize:13, padding:"14px", border:"1px solid rgba(0,229,160,0.2)", borderRadius:4, cursor:"not-allowed" }}>
              Scanning...
            </button>
          )}

          {scanState==="done" && (
            <div style={{ display:"flex", gap:10 }}>
              <button onClick={resetScan} style={{ flex:1, background:"transparent", color:"rgba(255,255,255,0.5)", border:"1px solid rgba(255,255,255,0.15)", borderRadius:4, padding:"12px", fontFamily:"monospace", fontSize:12, cursor:"pointer" }}>New Scan</button>
              <button onClick={viewReport} style={{ flex:1, background:"#00e5a0", color:"#0d0f14", border:"none", borderRadius:4, padding:"12px", fontFamily:"monospace", fontSize:12, fontWeight:700, cursor:"pointer" }}>View Report →</button>
            </div>
          )}

          {scanState==="error" && (
            <button onClick={resetScan} style={{ width:"100%", background:"rgba(255,59,59,0.15)", color:"#ff3b3b", border:"1px solid rgba(255,59,59,0.3)", borderRadius:4, padding:"12px", fontFamily:"monospace", fontSize:12, cursor:"pointer" }}>← Try Again</button>
          )}

          <div style={{ marginTop:14, background:"rgba(0,0,0,0.3)", border:"1px solid rgba(255,255,255,0.05)", borderRadius:4, padding:"10px 14px" }}>
            <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace", marginBottom:4 }}>CLI EQUIVALENT</div>
            <code style={{ color:"#00e5a0", fontSize:11 }}>python3 cycentra_scan.py {domain} {user?.id||"<uid>"} {scanType}</code>
          </div>
        </div>

        {/* Progress panel */}
        <div style={{ display:"flex", flexDirection:"column", gap:14 }}>

          <div style={{ background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:6, padding:24, textAlign:"center" }}>
            <div style={{ position:"relative", display:"inline-flex", alignItems:"center", justifyContent:"center", marginBottom:16 }}>
              <svg width="128" height="128" style={{ transform:"rotate(-90deg)" }}>
                <circle cx="64" cy="64" r="54" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8"/>
                <circle cx="64" cy="64" r="54" fill="none"
                  stroke={scanState==="error"?"#ff3b3b":scanState!=="idle"?"#00e5a0":"rgba(0,229,160,0.2)"}
                  strokeWidth="8" strokeLinecap="round"
                  strokeDasharray={circumference} strokeDashoffset={strokeDash}
                  style={{ transition:"stroke-dashoffset 1s ease", filter:scanState!=="idle"?"drop-shadow(0 0 8px #00e5a060)":"none" }}/>
              </svg>
              <div style={{ position:"absolute", textAlign:"center" }}>
                <div style={{ color:scanState==="error"?"#ff3b3b":"#00e5a0", fontSize:26, fontFamily:"'Space Mono',monospace", fontWeight:700 }}>
                  {scanState==="idle"?"--:--":fmt(elapsed)}
                </div>
                <div style={{ color:"rgba(255,255,255,0.3)", fontSize:9, letterSpacing:"1.5px", fontFamily:"monospace", marginTop:2 }}>
                  {scanState==="idle"?"READY":scanState==="done"?"COMPLETE":scanState==="error"?"FAILED":"ELAPSED"}
                </div>
              </div>
            </div>

            {scanState==="running" && <div style={{ color:"#00e5a0", fontSize:12, fontFamily:"monospace", marginBottom:10 }}>{currentModule}...</div>}
            {scanState==="done"    && <div style={{ color:"#00e5a0", fontSize:14, fontWeight:700, marginBottom:6 }}>✓ Scan Complete</div>}
            {scanState==="error"   && <div style={{ color:"#ff3b3b", fontSize:13, marginBottom:6 }}>✗ Could not reach backend</div>}

            <div style={{ height:4, background:"rgba(255,255,255,0.06)", borderRadius:2 }}>
              <div style={{ height:"100%", width:`${progress}%`, background:scanState==="error"?"#ff3b3b":"#00e5a0", borderRadius:2, transition:"width 1s ease" }}/>
            </div>
            <div style={{ display:"flex", justifyContent:"space-between", marginTop:5 }}>
              <span style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace" }}>0%</span>
              <span style={{ color:progress>0?"#00e5a0":"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace", fontWeight:700 }}>{Math.round(progress)}%</span>
              <span style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace" }}>100%</span>
            </div>

            {lastLog && (
              <div style={{ marginTop:8, background:"rgba(0,0,0,0.3)", borderRadius:3, padding:"5px 10px", color:scanState==="error"?"#ff6b6b":"rgba(0,229,160,0.5)", fontSize:10, fontFamily:"monospace", whiteSpace:"normal", overflow:"hidden", wordBreak:"break-word", lineHeight:1.5 }}>
                {lastLog}
              </div>
            )}
          </div>

          {/* Module checklist */}
          <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:6, padding:18 }}>
            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:10 }}>Scan Modules</div>
            <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
              {MODULES.map((m, i) => {
                const modIdx = Math.min(MODULES.length-1, Math.floor((progress/100)*MODULES.length));
                const done   = progress > 0 && i < modIdx;
                const active = i === modIdx && scanState === "running";
                return (
                  <div key={m} style={{ display:"flex", alignItems:"center", gap:8 }}>
                    <div style={{ width:13, height:13, borderRadius:"50%", flexShrink:0, background:done?"#00e5a0":active?"rgba(0,229,160,0.2)":"rgba(255,255,255,0.05)", border:active?"1.5px solid #00e5a0":"none", display:"flex", alignItems:"center", justifyContent:"center" }}>
                      {done   && <span style={{ fontSize:7, color:"#0d0f14", fontWeight:900 }}>✓</span>}
                      {active && <div style={{ width:5, height:5, borderRadius:"50%", background:"#00e5a0", animation:"pulse 1s infinite" }}/>}
                    </div>
                    <span style={{ fontSize:11, fontFamily:"monospace", color:done?"rgba(255,255,255,0.7)":active?"#00e5a0":"rgba(255,255,255,0.25)" }}>{m}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* ── PDF Reports ───────────────────────────────────────────── */}
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
              const dt       = new Date(r.modified * 1000);
              const dateStr  = dt.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
              const timeStr  = dt.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
              const isExec   = r.type === "executive";
              const typeColor = isExec ? "#4d9eff" : "#00e5a0";
              return (
                <div key={r.filename} style={{ display: "flex", alignItems: "center", gap: 14, padding: "12px 16px", borderBottom: i < reports.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none" }}>
                  <div style={{ width: 7, height: 7, borderRadius: "50%", background: typeColor, flexShrink: 0 }} />
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
