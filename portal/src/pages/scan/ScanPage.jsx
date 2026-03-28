/**
 * src/pages/scan/ScanPage.jsx
 */

import { useState, useRef } from "react";
import { API_BASE } from '../../core/constants.js';

const MODULES = [
  "DNS Reconnaissance","Subdomain Enumeration","Web Analysis","Crypto & SSL Audit",
  "Email Security Check","WHOIS & History","OSINT Gathering","Cloud Infrastructure",
  "Dark Web Monitoring","Supply Chain Analysis","AI Risk Enrichment","Generating Report",
];

export function ScanPage({ user, onScanComplete }) {
  const [domain,    setDomain]    = useState("");
  const [scanState, setScanState] = useState("idle"); // idle | running | done | error
  const [progress,  setProgress]  = useState(0);
  const [curMod,    setCurMod]    = useState("");
  const [elapsed,   setElapsed]   = useState(0);
  const [lastLog,   setLastLog]   = useState("");
  const timerRef = useRef(null);
  const pollRef  = useRef(null);

  const startScan = async () => {
    if (!domain || !domain.includes(".")) return;
    setScanState("running"); setProgress(0); setCurMod(""); setElapsed(0); setLastLog("");

    timerRef.current = setInterval(() => setElapsed(e => e + 1), 1000);

    try {
      const res = await fetch(`${API_BASE}/api/scan/trigger`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ domain, uid: user?.id || "anonymous" }),
      });
      if (!res.ok) { setScanState("error"); setLastLog("Failed to start scan"); clearInterval(timerRef.current); return; }
    } catch (e) { setScanState("error"); setLastLog(String(e)); clearInterval(timerRef.current); return; }

    let pollCount = 0;
    pollRef.current = setInterval(async () => {
      try {
        pollCount++;
        const r = await fetch(`${API_BASE}/api/scan/status`, { credentials: "include" });
        if (!r.ok) return;
        const s = await r.json();
        if (s.progress > 0)  setProgress(s.progress);
        if (s.current_module) setCurMod(s.current_module);
        if (s.last_log)      setLastLog(s.last_log);

        const done = (!s.running && s.progress >= 98) ||
          (s.last_log || "").toLowerCase().includes("portal json saved") ||
          (s.last_log || "").toLowerCase().includes("all done");

        if (done) {
          clearInterval(pollRef.current); clearInterval(timerRef.current);
          setProgress(100); setCurMod("Complete"); setScanState("done");
          const r2 = await fetch(`${API_BASE}/api/scans/latest?uid=${encodeURIComponent(user?.id || "")}`, { credentials: "include" });
          if (r2.ok) onScanComplete(await r2.json());
        }
      } catch {}
    }, 3000);
  };

  const fmt = s => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;

  return (
    <div style={{ maxWidth: 760 }}>
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700 }}>New Attack Surface Scan</h1>
        <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13, marginTop: 4 }}>Enter a domain to begin a full attack surface analysis.</p>
      </div>

      {scanState === "idle" && (
        <div>
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "28px 32px" }}>
            <div style={{ marginBottom: 20 }}>
              <label style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace", letterSpacing: "1px", display: "block", marginBottom: 8 }}>TARGET DOMAIN</label>
              <input value={domain} onChange={e => setDomain(e.target.value.trim())}
                onKeyDown={e => e.key === "Enter" && startScan()}
                placeholder="example.com"
                style={{ width: "100%", background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.12)", color: "white", padding: "12px 16px", borderRadius: 4, fontSize: 16, fontFamily: "monospace", outline: "none" }}/>
            </div>
            <button onClick={startScan} disabled={!domain.includes(".")}
              style={{ background: domain.includes(".") ? "#00e5a0" : "rgba(0,229,160,0.2)", color: domain.includes(".") ? "#0d0f14" : "rgba(0,229,160,0.4)", border: "none", borderRadius: 4, padding: "12px 32px", fontFamily: "monospace", fontSize: 13, fontWeight: 700, cursor: domain.includes(".") ? "pointer" : "default", letterSpacing: "1px", textTransform: "uppercase" }}>
              Start Scan
            </button>
          </div>
        </div>
      )}

      {scanState === "running" && (
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "28px 32px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
            <div>
              <div style={{ color: "white", fontFamily: "monospace", fontSize: 14, fontWeight: 700 }}>{domain}</div>
              <div style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace", marginTop: 2 }}>{curMod || "Initialising…"}</div>
            </div>
            <div style={{ color: "rgba(255,255,255,0.35)", fontFamily: "monospace", fontSize: 13 }}>{fmt(elapsed)}</div>
          </div>

          {/* Progress bar */}
          <div style={{ height: 4, background: "rgba(255,255,255,0.07)", borderRadius: 2, marginBottom: 20 }}>
            <div style={{ height: "100%", width: `${progress}%`, background: "#00e5a0", borderRadius: 2, transition: "width 0.5s ease", boxShadow: "0 0 8px rgba(0,229,160,0.5)" }}/>
          </div>

          {/* Module grid */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 6 }}>
            {MODULES.map(m => {
              const done   = MODULES.indexOf(m) < MODULES.indexOf(curMod);
              const active = m === curMod;
              return (
                <div key={m} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <div style={{ width: 14, height: 14, borderRadius: "50%", flexShrink: 0, background: done ? "#00e5a0" : active ? "rgba(0,229,160,0.2)" : "rgba(255,255,255,0.05)", border: active ? "1.5px solid #00e5a0" : "none", display: "flex", alignItems: "center", justifyContent: "center" }}>
                    {done   && <span style={{ fontSize: 7, color: "#0d0f14", fontWeight: 900 }}>✓</span>}
                    {active && <div style={{ width: 5, height: 5, borderRadius: "50%", background: "#00e5a0", animation: "pulse 1s infinite" }}/>}
                  </div>
                  <span style={{ fontSize: 11, fontFamily: "monospace", color: done ? "rgba(255,255,255,0.7)" : active ? "#00e5a0" : "rgba(255,255,255,0.25)" }}>{m}</span>
                </div>
              );
            })}
          </div>

          {lastLog && (
            <div style={{ marginTop: 16, color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {lastLog}
            </div>
          )}
        </div>
      )}

      {scanState === "error" && (
        <div style={{ background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.3)", borderRadius: 6, padding: 24 }}>
          <div style={{ color: "#ff3b3b", fontFamily: "monospace", marginBottom: 8 }}>Scan failed</div>
          <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, marginBottom: 16 }}>{lastLog}</div>
          <button onClick={() => setScanState("idle")} style={{ background: "transparent", border: "1px solid rgba(255,255,255,0.2)", color: "white", padding: "8px 20px", borderRadius: 4, fontFamily: "monospace", cursor: "pointer" }}>Try Again</button>
        </div>
      )}
    </div>
  );
}
