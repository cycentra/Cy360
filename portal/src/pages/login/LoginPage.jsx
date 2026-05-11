/**
 * src/pages/login/LoginPage.jsx
 * ==============================
 * OAuth login screen — Google, Microsoft SSO and local (username/password) login.
 */

import { useState, useEffect } from "react";
import { CYSCAN_URL, API_BASE } from '../../core/constants.js';

export function LoginPage() {
  const [loading, setLoading]       = useState(null);
  const [showLocal, setShowLocal]   = useState(false);
  const [localEmail, setLocalEmail] = useState("");
  const [localPass, setLocalPass]   = useState("");
  const [localError, setLocalError] = useState("");

  // ── Access request form state ──────────────────────────────────────────
  const [showRequestAccess, setShowRequestAccess] = useState(false);
  const [reqEmail,   setReqEmail]   = useState("");
  const [reqName,    setReqName]    = useState("");
  const [reqErr,     setReqErr]     = useState("");
  const [reqSuccess, setReqSuccess] = useState(false);

  // ── Pending approval / auth-error state from URL params ──────────────────
  const [pendingEmail, setPendingEmail]   = useState(null);  // non-null → approval-pending view
  const [authErrMsg,   setAuthErrMsg]     = useState(null);  // non-null → error banner
  // providerCfg: { enabled: bool, provider_id: string, provider_name: string, configured: bool }
  const [providerCfg,  setProviderCfg]    = useState(null);  // null = loading

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);

    // sso_error=pending_approval  (from approval gate in oauth.py + sso/routes.py)
    if (params.get("sso_error") === "pending_approval") {
      setPendingEmail(decodeURIComponent(params.get("email") || ""));
      // Clean the URL so a refresh doesn't re-trigger
      window.history.replaceState({}, "", window.location.pathname);
    }

    // auth=error&message=...
    if (params.get("auth") === "error") {
      const msg = params.get("message");
      setAuthErrMsg(msg ? decodeURIComponent(msg) : "Authentication failed. Please try again.");
      window.history.replaceState({}, "", window.location.pathname);
    }

    // Fetch which SSO provider the admin has configured
    fetch(`${API_BASE}/api/sso/providers`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => setProviderCfg({
        enabled:       !!(d?.sso_enabled && d?.configured),
        provider_id:   d?.provider_id   || "",
        provider_name: d?.provider_name || "",
      }))
      .catch(() => setProviderCfg({ enabled: false, provider_id: "", provider_name: "" }));
  }, []);

  const handleSSO = (provider) => {
    setLoading(provider);
    // Always use the admin-configured OIDC flow (/api/sso/redirect → /api/sso/callback).
    // The redirect_uri registered in the IdP app MUST be FRONTEND_URL/api/sso/callback —
    // which is exactly what sso_redirect() sends. The direct /auth/google and
    // /auth/microsoft routes use separate hardcoded credentials and a different
    // redirect_uri (BASE_URL/auth/<provider>/callback), causing redirect_uri_mismatch
    // when the admin has configured their own OAuth app through the SSO settings.
    window.location.href = `${CYSCAN_URL}/api/sso/redirect`;
  };

  const handleLocalLogin = async (e) => {
    e.preventDefault();
    setLocalError("");
    setLoading("local");
    try {
      const resp = await fetch(`${CYSCAN_URL}/auth/local`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: localEmail, password: localPass }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setLocalError(data.error || "Login failed");
        setLoading(null);
        return;
      }
      // Mirror the SSO redirect query params so App.jsx picks up the session
      const params = new URLSearchParams({
        auth:     "success",
        provider: "local",
        name:     data.name    || "",
        email:    data.email   || "",
        uid:      data.uid     || "",
        avatar:   data.avatar  || "",
        role:     data.role    || "viewer",
        apps:     JSON.stringify(data.apps || []),
      });
      window.location.href = `${window.location.origin}?${params.toString()}`;
    } catch {
      setLocalError("Network error — please try again");
      setLoading(null);
    }
  };

  const handleRequestAccess = async (e) => {
    e.preventDefault();
    setReqErr("");
    setLoading("request");
    try {
      const resp = await fetch(`${CYSCAN_URL}/api/auth/request-access`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: reqEmail, name: reqName }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setReqErr(data.error || "Request failed");
        setLoading(null);
        return;
      }
      setReqSuccess(true);
      setLoading(null);
    } catch {
      setReqErr("Network error — please try again");
      setLoading(null);
    }
  };

  return (
    <div style={{
      minHeight: "100vh", background: "#090b10", display: "flex",
      fontFamily: "'Barlow',sans-serif",
      backgroundImage: "radial-gradient(ellipse at 15% 50%, rgba(0,229,160,0.06) 0%, transparent 55%), radial-gradient(ellipse at 85% 20%, rgba(0,120,255,0.05) 0%, transparent 55%)",
    }}>
      {/* Left — branding */}
      <div style={{ flex: "1 1 55%", display: "flex", flexDirection: "column", justifyContent: "center", padding: "60px 64px", borderRight: "1px solid rgba(255,255,255,0.05)" }}>
        <div style={{ animation: "fadeUp 0.5s ease", maxWidth: 520 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 48 }}>
            <svg width="40" height="40" viewBox="0 0 24 24" style={{ animation: "hexPulse 4s ease-in-out infinite" }}>
              <polygon points="12,2 22,8 22,16 12,22 2,16 2,8" fill="none" stroke="#00e5a0" strokeWidth="1.5"/>
              <polygon points="12,6 18,10 18,14 12,18 6,14 6,10" fill="rgba(0,229,160,0.12)" stroke="#00e5a0" strokeWidth="0.75"/>
              <circle cx="12" cy="12" r="2" fill="#00e5a0"/>
            </svg>
            <div>
              <div style={{ color: "white", fontFamily: "'Space Mono',monospace", fontSize: 22, fontWeight: 700, letterSpacing: "3px" }}>
                CY<span style={{ color: "#00e5a0" }}>CENTRA</span>
              </div>
              <div style={{ color: "#00e5a0", fontFamily: "'Space Mono',monospace", fontSize: 10, letterSpacing: "5px", opacity: 0.6 }}>360°</div>
            </div>
          </div>
          <h1 style={{ color: "white", fontSize: 34, fontWeight: 700, lineHeight: 1.25, marginBottom: 10 }}>
            One Platform.{" "}
            <span style={{ color: "#00e5a0" }}>Six Modules.</span>
          </h1>
          <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 14,
            fontFamily: "'Space Mono',monospace", letterSpacing: "2.5px",
            marginBottom: 28, fontWeight: 400, textTransform: "uppercase" }}>
            From Signals to Strength
          </div>
                    {/* ── Module pill strip ──────────────────────────────────────────── */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: 7, marginBottom: 26 }}>
            {[
              { label: "CyASM",     color: "#00e5a0" },
              { label: "CySIEM",    color: "#ff3b3b" },
              { label: "UEBA",      color: "#ff8c00" },
              { label: "CySOAR",    color: "#4d9eff" },
              { label: "CyIRIS",    color: "#b06eff" },
              { label: "CyComp",    color: "#4d9eff" },
              { label: "CyMind AI", color: "#00e5a0" },
            ].map(({ label, color }) => (
              <span key={label} style={{
                background: `${color}12`, color,
                border: `1px solid ${color}35`,
                fontSize: 9, fontFamily: "'Space Mono',monospace", fontWeight: 700,
                padding: "4px 10px", borderRadius: 3, letterSpacing: "0.8px",
              }}>
                {label}
              </span>
            ))}
          </div>

          {/* ── Seven-module capability cards ───────────────────────────────── */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 9 }}>
            {[
              {
                key: "asm", name: "Attack Surface", tag: "CyASM", color: "#00e5a0",
                desc: "14-module external recon: DNS, subdomains, SSL, email, cloud & dark web",
                icon: (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 6.36 15.36M5.64 18.36A9 9 0 0 1 12 3"/><circle cx="12" cy="12" r="3"/></svg>),
              },
              {
                key: "siem", name: "Correlation Engine", tag: "CySIEM", color: "#ff3b3b",
                desc: "Wazuh + ML correlation · MITRE ATT&CK · MISP IOC enrichment",
                icon: (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>),
              },
              {
                key: "ueba", name: "UEBA", tag: "Behavioural", color: "#ff8c00",
                desc: "User & entity baselines · anomaly detection · risk scoring",
                icon: (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>),
              },
              {
                key: "soar", name: "SOAR", tag: "CySOAR", color: "#4d9eff",
                desc: "Node-RED automation · playbooks · response orchestration",
                icon: (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>),
              },
              {
                key: "grc", name: "GRC & DFIR", tag: "CyComp · CyIRIS", color: "#b06eff",
                desc: "Risk register · NIS2 / DORA / ISO 27001 · case management",
                icon: (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>),
              },
              {
                key: "cymind", name: "AI Analyst", tag: "CyMind", color: "#00e5a0",
                desc: "On-prem LLM · RAG · live SIEM grounding · zero egress",
                icon: (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><circle cx="9" cy="10" r="1" fill="currentColor"/><circle cx="12" cy="10" r="1" fill="currentColor"/><circle cx="15" cy="10" r="1" fill="currentColor"/></svg>),
              },
            ].map(({ key, name, tag, color, desc, icon }) => (
              <div key={key}
                style={{
                  background: "rgba(255,255,255,0.025)",
                  border: "1px solid rgba(255,255,255,0.06)",
                  borderLeft: `2px solid ${color}`,
                  borderRadius: 5, padding: "11px 13px",
                  display: "flex", gap: 10, alignItems: "flex-start",
                  transition: "background 0.2s",
                }}
                onMouseEnter={e => e.currentTarget.style.background = `${color}08`}
                onMouseLeave={e => e.currentTarget.style.background = "rgba(255,255,255,0.025)"}
              >
                <div style={{
                  width: 28, height: 28, borderRadius: 5, flexShrink: 0,
                  background: `${color}14`, border: `1px solid ${color}28`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  color, padding: 5,
                }}>
                  {icon}
                </div>
                <div style={{ minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: 3, flexWrap: "wrap" }}>
                    <span style={{ color: "white", fontSize: 11, fontWeight: 600 }}>{name}</span>
                    <span style={{
                      background: `${color}15`, color, border: `1px solid ${color}35`,
                      fontSize: 8, fontFamily: "'Space Mono',monospace", fontWeight: 700,
                      padding: "1px 5px", borderRadius: 2, letterSpacing: "0.5px",
                    }}>{tag}</span>
                  </div>
                  <div style={{ color: "rgba(255,255,255,0.38)", fontSize: 10,
                    lineHeight: 1.45, fontFamily: "system-ui,sans-serif" }}>{desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Right — auth */}
      <div style={{ flex: "1 1 45%", display: "flex", alignItems: "center", justifyContent: "center", padding: 40 }}>
        <div style={{ width: "100%", maxWidth: 380, animation: "fadeUp 0.6s ease 0.1s both" }}>
          {/* ── Pending approval banner ── */}
          {pendingEmail && (
            <div style={{ marginBottom: 28, padding: "20px 22px", background: "rgba(255,217,61,0.06)", border: "1px solid rgba(255,217,61,0.3)", borderRadius: 8 }}>
              <div style={{ color: "#ffd93d", fontFamily: "monospace", fontSize: 11, fontWeight: 700, letterSpacing: "1.5px", marginBottom: 10 }}>ACCESS REQUEST RECEIVED</div>
              <p style={{ color: "rgba(255,255,255,0.6)", fontSize: 13, lineHeight: 1.7, margin: 0 }}>
                Your request for <strong style={{ color: "white" }}>{pendingEmail}</strong> is pending admin approval.
              </p>
              <p style={{ color: "rgba(255,255,255,0.62)", fontSize: 12, marginTop: 8, lineHeight: 1.6 }}>
                You will receive an email once your access is approved or rejected. Contact your administrator if this takes longer than expected.
              </p>
              <button
                onClick={() => setPendingEmail(null)}
                style={{ marginTop: 14, background: "none", border: "1px solid rgba(255,255,255,0.15)", borderRadius: 4, color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace", padding: "6px 14px", cursor: "pointer" }}>
                ← Back to Sign in
              </button>
            </div>
          )}

          {/* ── Auth error banner ── */}
          {authErrMsg && !pendingEmail && (
            <div style={{ marginBottom: 20, padding: "12px 16px", background: "rgba(255,59,59,0.07)", border: "1px solid rgba(255,59,59,0.25)", borderRadius: 6 }}>
              <div style={{ color: "#ff3b3b", fontSize: 12, lineHeight: 1.6 }}>{authErrMsg}</div>
              <button onClick={() => setAuthErrMsg(null)} style={{ marginTop: 8, background: "none", border: "none", color: "rgba(255,255,255,0.62)", fontSize: 11, cursor: "pointer" }}>Dismiss</button>
            </div>
          )}

          {!pendingEmail && (
          <>
          <div style={{ marginBottom: 32 }}>
            <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, letterSpacing: "2px", fontFamily: "monospace", marginBottom: 8 }}>SECURE ACCESS</div>
            <h2 style={{ color: "white", fontSize: 24, fontWeight: 700, marginBottom: 8 }}>Sign in to CyCentra</h2>
            <p style={{ color: "rgba(255,255,255,0.62)", fontSize: 13 }}>
              {showLocal ? "Enter your local account credentials." : "Use your organisation's SSO credentials."}
            </p>
          </div>

          {!showLocal ? (
            /* ── SSO buttons — rendered based on admin-configured provider ── */
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>

              {/* Skeleton shimmer while providers are loading */}
              {providerCfg === null && (
                <div style={{ height: 52, borderRadius: 6, background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", animation: "pulse 1.5s ease-in-out infinite" }} />
              )}

              {/* Google — shown only when admin configured provider=google */}
              {providerCfg?.enabled && providerCfg.provider_id === "google" && (
                <button onClick={() => handleSSO("google")} disabled={!!loading}
                  style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, padding: "14px 24px", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 6, color: "white", fontSize: 14, fontWeight: 500, cursor: loading ? "default" : "pointer", transition: "all 0.2s" }}>
                  {loading === "google"
                    ? <div style={{ width: 18, height: 18, border: "2px solid rgba(255,255,255,0.2)", borderTopColor: "#4285f4", borderRadius: "50%", animation: "spin 0.8s linear infinite" }}/>
                    : <svg width="18" height="18" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
                  }
                  {loading === "google" ? "Connecting…" : "Continue with Google"}
                </button>
              )}

              {/* Microsoft — shown only when admin configured provider=microsoft */}
              {providerCfg?.enabled && providerCfg.provider_id === "microsoft" && (
                <button onClick={() => handleSSO("microsoft")} disabled={!!loading}
                  style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, padding: "14px 24px", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 6, color: "white", fontSize: 14, fontWeight: 500, cursor: loading ? "default" : "pointer", transition: "all 0.2s" }}>
                  {loading === "microsoft"
                    ? <div style={{ width: 18, height: 18, border: "2px solid rgba(255,255,255,0.2)", borderTopColor: "#00b4f0", borderRadius: "50%", animation: "spin 0.8s linear infinite" }}/>
                    : <svg width="18" height="18" viewBox="0 0 21 21"><rect x="1" y="1" width="9" height="9" fill="#F25022"/><rect x="11" y="1" width="9" height="9" fill="#7FBA00"/><rect x="1" y="11" width="9" height="9" fill="#00A4EF"/><rect x="11" y="11" width="9" height="9" fill="#FFB900"/></svg>
                  }
                  {loading === "microsoft" ? "Connecting…" : "Continue with Microsoft"}
                </button>
              )}

              {/* Generic OIDC — any provider that isn't google or microsoft */}
              {providerCfg?.enabled && providerCfg.provider_id !== "google" && providerCfg.provider_id !== "microsoft" && (
                <button onClick={() => handleSSO(providerCfg.provider_id)} disabled={!!loading}
                  style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, padding: "14px 24px", background: "rgba(0,229,160,0.04)", border: "1px solid rgba(0,229,160,0.25)", borderRadius: 6, color: "#00e5a0", fontSize: 14, fontWeight: 500, cursor: loading ? "default" : "pointer", transition: "all 0.2s" }}>
                  {loading === providerCfg.provider_id
                    ? <div style={{ width: 18, height: 18, border: "2px solid rgba(0,229,160,0.2)", borderTopColor: "#00e5a0", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
                    : <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                      </svg>
                  }
                  {loading === providerCfg.provider_id ? "Redirecting…" : `Sign in with ${providerCfg.provider_name || "SSO"}`}
                </button>
              )}

              {/* Local auth toggle — always shown */}
              <button onClick={() => setShowLocal(true)} disabled={!!loading}
                style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, padding: "14px 24px", background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 6, color: "rgba(255,255,255,0.6)", fontSize: 14, fontWeight: 500, cursor: loading ? "default" : "pointer", transition: "all 0.2s" }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/>
                </svg>
                Sign in with local account
              </button>
            </div>
          ) : showRequestAccess ? (
            /* ── Request access form / confirmation ── */
            reqSuccess ? (
              <div style={{ padding: "20px 22px", background: "rgba(0,229,160,0.04)", border: "1px solid rgba(0,229,160,0.2)", borderRadius: 8 }}>
                <div style={{ color: "#00e5a0", fontFamily: "monospace", fontSize: 11, fontWeight: 700, letterSpacing: "1.5px", marginBottom: 10 }}>REQUEST SUBMITTED</div>
                <p style={{ color: "rgba(255,255,255,0.6)", fontSize: 13, lineHeight: 1.7, margin: 0 }}>
                  Your access request for <strong style={{ color: "white" }}>{reqEmail}</strong> has been sent to the administrator.
                </p>
                <p style={{ color: "rgba(255,255,255,0.62)", fontSize: 12, marginTop: 8, lineHeight: 1.6 }}>
                  You will be notified by email once your account is approved.
                </p>
                <button onClick={() => { setShowRequestAccess(false); setReqSuccess(false); setReqEmail(""); setReqName(""); setShowLocal(false); }}
                  style={{ marginTop: 14, background: "none", border: "1px solid rgba(255,255,255,0.15)", borderRadius: 4, color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace", padding: "6px 14px", cursor: "pointer" }}>
                  ← Back to Sign in
                </button>
              </div>
            ) : (
              <form onSubmit={handleRequestAccess} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                <div style={{ marginBottom: 8 }}>
                  <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, letterSpacing: "2px", fontFamily: "monospace", marginBottom: 6 }}>LOCAL ACCOUNT</div>
                  <div style={{ color: "white", fontSize: 18, fontWeight: 700 }}>Request Access</div>
                  <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 12, marginTop: 4 }}>The administrator will review and approve your request.</div>
                </div>
                <input type="text" placeholder="Full name" value={reqName} onChange={e => setReqName(e.target.value)}
                  required autoFocus
                  style={{ padding: "12px 16px", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 6, color: "white", fontSize: 14, outline: "none" }}
                />
                <input type="email" placeholder="Email address" value={reqEmail} onChange={e => setReqEmail(e.target.value)}
                  required
                  style={{ padding: "12px 16px", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 6, color: "white", fontSize: 14, outline: "none" }}
                />
                {reqErr && (
                  <div style={{ color: "#ff5e5e", fontSize: 12, padding: "8px 12px", background: "rgba(255,94,94,0.08)", borderRadius: 4 }}>{reqErr}</div>
                )}
                <button type="submit" disabled={!!loading}
                  style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, padding: "14px 24px", background: "rgba(0,229,160,0.12)", border: "1px solid rgba(0,229,160,0.3)", borderRadius: 6, color: "#00e5a0", fontSize: 14, fontWeight: 600, cursor: loading ? "default" : "pointer", transition: "all 0.2s" }}>
                  {loading === "request" ? <div style={{ width: 18, height: 18, border: "2px solid rgba(0,229,160,0.2)", borderTopColor: "#00e5a0", borderRadius: "50%", animation: "spin 0.8s linear infinite" }}/> : null}
                  {loading === "request" ? "Submitting…" : "Submit Request"}
                </button>
                <button type="button" onClick={() => { setShowRequestAccess(false); setReqErr(""); }} disabled={!!loading}
                  style={{ background: "none", border: "none", color: "rgba(255,255,255,0.3)", fontSize: 12, cursor: "pointer", textAlign: "center", padding: "4px 0" }}>
                  ← Back to Sign in
                </button>
              </form>
            )
          ) : (
            /* ── Local login form ── */
            <form onSubmit={handleLocalLogin} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <input
                type="email"
                placeholder="Email address"
                value={localEmail}
                onChange={e => setLocalEmail(e.target.value)}
                required
                autoFocus
                style={{ padding: "12px 16px", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 6, color: "white", fontSize: 14, outline: "none" }}
              />
              <input
                type="password"
                placeholder="Password"
                value={localPass}
                onChange={e => setLocalPass(e.target.value)}
                required
                style={{ padding: "12px 16px", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 6, color: "white", fontSize: 14, outline: "none" }}
              />
              {localError && (
                <div style={{ color: "#ff5e5e", fontSize: 12, padding: "8px 12px", background: "rgba(255,94,94,0.08)", borderRadius: 4 }}>
                  {localError}
                </div>
              )}
              <button type="submit" disabled={!!loading}
                style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, padding: "14px 24px", background: "rgba(0,229,160,0.12)", border: "1px solid rgba(0,229,160,0.3)", borderRadius: 6, color: "#00e5a0", fontSize: 14, fontWeight: 600, cursor: loading ? "default" : "pointer", transition: "all 0.2s" }}>
                {loading === "local"
                  ? <div style={{ width: 18, height: 18, border: "2px solid rgba(0,229,160,0.2)", borderTopColor: "#00e5a0", borderRadius: "50%", animation: "spin 0.8s linear infinite" }}/>
                  : null}
                {loading === "local" ? "Signing in…" : "Sign in"}
              </button>
              <button type="button" onClick={() => { setShowLocal(false); setLocalError(""); }} disabled={!!loading}
                style={{ background: "none", border: "none", color: "rgba(255,255,255,0.3)", fontSize: 12, cursor: "pointer", textAlign: "center", padding: "4px 0" }}>
                ← Back to SSO options
              </button>
              <button type="button" onClick={() => { setShowRequestAccess(true); setLocalError(""); }} disabled={!!loading}
                style={{ background: "none", border: "none", color: "rgba(0,229,160,0.45)", fontSize: 12, cursor: loading ? "default" : "pointer", textAlign: "center", padding: "4px 0" }}>
                No account? Request access →
              </button>
            </form>
          )}

          <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: 20, marginTop: 24, color: "rgba(255,255,255,0.2)", fontSize: 11, textAlign: "center", lineHeight: 1.6 }}>
            Single sign-on gateway · All modules share this session<br/>
            CyASM · CySIEM · UEBA · CySOAR · CyIRIS · CyComp · CyMind — one login
          </div>
          </>
          )}
        </div>
      </div>
    </div>
  );
}
