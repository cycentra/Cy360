import { useState, useEffect } from "react";
import { API_BASE } from "../core/constants.js";

const POLL_MS = 60 * 60 * 1000; // re-check every hour

export function LicenseBanner() {
  const [lic, setLic]         = useState(null);
  const [dismissed, setDism]  = useState({});

  useEffect(() => {
    let alive = true;
    async function check() {
      try {
        const r = await fetch(`${API_BASE}/api/system/license`, { credentials: "include" });
        if (!alive) return;
        if (r.ok) setLic(await r.json());
      } catch {}
    }
    check();
    const t = setInterval(check, POLL_MS);
    return () => { alive = false; clearInterval(t); };
  }, []);

  if (!lic) return null;

  const status    = lic.status || (lic.valid ? "valid" : "blocked");
  const hStatus   = lic.host_status || "ok";
  const needsLic  = status === "expiry_warning" || status === "grace" || status === "blocked";
  const needsHost = hStatus === "host_warning" || hStatus === "host_blocked";

  if (!needsLic && !needsHost) return null;

  // ── Full portal block (past 30-day grace) ─────────────────────────────────
  if (status === "blocked") {
    return (
      <div style={{
        position: "fixed", inset: 0, zIndex: 9999,
        background: "rgba(5,5,10,0.97)", display: "flex",
        alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 20,
      }}>
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#ff3b3b" strokeWidth="1.5">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <line x1="12" y1="9" x2="12" y2="13"/><circle cx="12" cy="17" r="0.5" fill="#ff3b3b"/>
        </svg>
        <div style={{ color: "#ff3b3b", fontFamily: "monospace", fontSize: 11, letterSpacing: "2px" }}>
          LICENSE EXPIRED — PORTAL ACCESS BLOCKED
        </div>
        <div style={{ color: "rgba(255,255,255,0.5)", fontFamily: "monospace", fontSize: 13, maxWidth: 480, textAlign: "center", lineHeight: 1.7 }}>
          {lic.message}
        </div>
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 11, fontFamily: "monospace", marginTop: 8 }}>
          Upload a renewed license via SSH:&nbsp;
          <span style={{ color: "#00e5a0" }}>scp *.lic root@server:/opt/cycentra/cycentra.lic</span>
        </div>
        <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>
          Services remain running. Only portal access is locked. Contact cycentra.com to renew.
        </div>
      </div>
    );
  }

  const banners = [];

  // ── License warning banners ────────────────────────────────────────────────
  if (status === "grace" && !dismissed["grace"]) {
    const graceLeft = lic.grace_days_remaining ?? 0;
    banners.push(
      <div key="grace" style={bannerStyle("#ff6b00", "rgba(255,107,0,0.12)")}>
        <BannerIcon color="#ff6b00" />
        <span>
          <strong>LICENSE IN GRACE PERIOD</strong> — Expired {30 - graceLeft} day(s) ago.
          Portal access will be blocked in <strong>{graceLeft} day(s)</strong>.
          Renew at <a href="https://cycentra.com" target="_blank" rel="noreferrer"
            style={{ color: "#ff6b00" }}>cycentra.com</a>
        </span>
        <DismissBtn onClick={() => setDism(d => ({ ...d, grace: true }))} />
      </div>
    );
  }

  if (status === "expiry_warning" && !dismissed["expiry"]) {
    banners.push(
      <div key="expiry" style={bannerStyle("#f5a623", "rgba(245,166,35,0.1)")}>
        <BannerIcon color="#f5a623" />
        <span>
          <strong>LICENSE EXPIRING SOON</strong> — {lic.days_remaining} day(s) remaining (expires {lic.subscription_end}).
          Renew at <a href="https://cycentra.com" target="_blank" rel="noreferrer"
            style={{ color: "#f5a623" }}>cycentra.com</a>
        </span>
        <DismissBtn onClick={() => setDism(d => ({ ...d, expiry: true }))} />
      </div>
    );
  }

  // ── Host limit banners ─────────────────────────────────────────────────────
  if (hStatus === "host_blocked" && !dismissed["host_blocked"]) {
    banners.push(
      <div key="host_blocked" style={bannerStyle("#ff3b3b", "rgba(255,59,59,0.1)")}>
        <BannerIcon color="#ff3b3b" />
        <span>
          <strong>HOST LIMIT EXCEEDED — NEW REGISTRATIONS BLOCKED</strong> —&nbsp;
          {lic.registered_hosts} hosts registered, license allows {lic.max_hosts}.
          Limit exceeded for {lic.host_limit_days_exceeded} day(s). Upgrade your license or remove hosts.
        </span>
        <DismissBtn onClick={() => setDism(d => ({ ...d, host_blocked: true }))} />
      </div>
    );
  }

  if (hStatus === "host_warning" && !dismissed["host_warning"]) {
    const daysLeft = _HOST_LIMIT_WARN_DAYS - (lic.host_limit_days_exceeded ?? 0);
    banners.push(
      <div key="host_warning" style={bannerStyle("#f5a623", "rgba(245,166,35,0.1)")}>
        <BannerIcon color="#f5a623" />
        <span>
          <strong>HOST LIMIT EXCEEDED</strong> —&nbsp;
          {lic.registered_hosts} hosts registered, license allows {lic.max_hosts}.
          New host registration will be blocked in <strong>{daysLeft} day(s)</strong>.
          Upgrade your license or remove unused hosts.
        </span>
        <DismissBtn onClick={() => setDism(d => ({ ...d, host_warning: true }))} />
      </div>
    );
  }

  return banners.length > 0 ? <>{banners}</> : null;
}

const _HOST_LIMIT_WARN_DAYS = 15;

function bannerStyle(color, bg) {
  return {
    display: "flex", alignItems: "center", gap: 10, padding: "9px 20px",
    background: bg, borderBottom: `1px solid ${color}30`,
    fontFamily: "monospace", fontSize: 12, color: "rgba(255,255,255,0.85)",
    lineHeight: 1.5, flexShrink: 0,
  };
}

function BannerIcon({ color }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" style={{ flexShrink: 0 }}>
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  );
}

function DismissBtn({ onClick }) {
  return (
    <button onClick={onClick} style={{
      marginLeft: "auto", background: "none", border: "none", color: "rgba(255,255,255,0.3)",
      cursor: "pointer", fontSize: 14, padding: "0 4px", flexShrink: 0,
    }}>×</button>
  );
}
