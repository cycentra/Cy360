/**
 * src/pages/login/LoginPage.jsx
 * ==============================
 * OAuth login screen — Google, Microsoft SSO and local (username/password) login.
 */

import { useState } from "react";
import { CYSCAN_URL } from '../../core/constants.js';

export function LoginPage() {
  const [loading, setLoading]   = useState(null);
  const [showLocal, setShowLocal] = useState(false);
  const [localEmail, setLocalEmail] = useState("");
  const [localPass, setLocalPass]   = useState("");
  const [localError, setLocalError] = useState("");

  const handleSSO = (provider) => {
    setLoading(provider);
    window.location.href = `${CYSCAN_URL}/auth/${provider}?redirect=${encodeURIComponent(window.location.origin)}`;
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
          <h1 style={{ color: "white", fontSize: 36, fontWeight: 700, lineHeight: 1.2, marginBottom: 16 }}>
            Attack Surface<br/>
            <span style={{ color: "#00e5a0" }}>Intelligence</span> Platform
          </h1>
          <p style={{ color: "rgba(255,255,255,0.4)", fontSize: 16, lineHeight: 1.7, marginBottom: 40 }}>
            Unified security operations — ASM scanning, SIEM correlation, incident response and SOAR automation in one platform.
          </p>
          <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
            {[
              { icon: "👁️", label: "CySIEM", sub: "Endpoint & Log Intelligence" },
              { icon: "🎫", label: "CyIRIS", sub: "Incident Response" },
              { icon: "🛡️", label: "CySOAR", sub: "Security Automation" },
            ].map(m => (
              <div key={m.label} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span style={{ fontSize: 16 }}>{m.icon}</span>
                <div>
                  <div style={{ color: "white", fontSize: 12, fontWeight: 600 }}>{m.label}</div>
                  <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10 }}>{m.sub}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Right — auth */}
      <div style={{ flex: "1 1 45%", display: "flex", alignItems: "center", justifyContent: "center", padding: 40 }}>
        <div style={{ width: "100%", maxWidth: 380, animation: "fadeUp 0.6s ease 0.1s both" }}>
          <div style={{ marginBottom: 32 }}>
            <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, letterSpacing: "2px", fontFamily: "monospace", marginBottom: 8 }}>SECURE ACCESS</div>
            <h2 style={{ color: "white", fontSize: 24, fontWeight: 700, marginBottom: 8 }}>Sign in to CyCentra</h2>
            <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13 }}>
              {showLocal ? "Enter your local account credentials." : "Use your organisation's SSO credentials."}
            </p>
          </div>

          {!showLocal ? (
            /* ── SSO buttons ── */
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <button onClick={() => handleSSO("google")} disabled={!!loading}
                style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, padding: "14px 24px", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 6, color: "white", fontSize: 14, fontWeight: 500, cursor: loading ? "default" : "pointer", transition: "all 0.2s", opacity: loading === "microsoft" ? 0.5 : 1 }}>
                {loading === "google"
                  ? <div style={{ width: 18, height: 18, border: "2px solid rgba(255,255,255,0.2)", borderTopColor: "#4285f4", borderRadius: "50%", animation: "spin 0.8s linear infinite" }}/>
                  : <svg width="18" height="18" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
                }
                {loading === "google" ? "Connecting…" : "Continue with Google"}
              </button>

              <button onClick={() => handleSSO("microsoft")} disabled={!!loading}
                style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, padding: "14px 24px", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 6, color: "white", fontSize: 14, fontWeight: 500, cursor: loading ? "default" : "pointer", transition: "all 0.2s", opacity: loading === "google" ? 0.5 : 1 }}>
                {loading === "microsoft"
                  ? <div style={{ width: 18, height: 18, border: "2px solid rgba(255,255,255,0.2)", borderTopColor: "#00b4f0", borderRadius: "50%", animation: "spin 0.8s linear infinite" }}/>
                  : <svg width="18" height="18" viewBox="0 0 21 21"><rect x="1" y="1" width="9" height="9" fill="#F25022"/><rect x="11" y="1" width="9" height="9" fill="#7FBA00"/><rect x="1" y="11" width="9" height="9" fill="#00A4EF"/><rect x="11" y="11" width="9" height="9" fill="#FFB900"/></svg>
                }
                {loading === "microsoft" ? "Connecting…" : "Continue with Microsoft"}
              </button>

              {/* Local auth toggle */}
              <button onClick={() => setShowLocal(true)} disabled={!!loading}
                style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, padding: "14px 24px", background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 6, color: "rgba(255,255,255,0.6)", fontSize: 14, fontWeight: 500, cursor: loading ? "default" : "pointer", transition: "all 0.2s" }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/>
                </svg>
                Sign in with local account
              </button>
            </div>
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
            </form>
          )}

          <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: 20, marginTop: 24, color: "rgba(255,255,255,0.2)", fontSize: 11, textAlign: "center", lineHeight: 1.6 }}>
            Single sign-on gateway · All modules share this session<br/>
            CySIEM · CyIRIS · CySOAR — one login to rule them all
          </div>
        </div>
      </div>
    </div>
  );
}

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
          <h1 style={{ color: "white", fontSize: 36, fontWeight: 700, lineHeight: 1.2, marginBottom: 16 }}>
            Attack Surface<br/>
            <span style={{ color: "#00e5a0" }}>Intelligence</span> Platform
          </h1>
          <p style={{ color: "rgba(255,255,255,0.4)", fontSize: 16, lineHeight: 1.7, marginBottom: 40 }}>
            Unified security operations — ASM scanning, SIEM correlation, incident response and SOAR automation in one platform.
          </p>
          <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
            {[
              { icon: "👁️", label: "CySIEM", sub: "Endpoint & Log Intelligence" },
              { icon: "🎫", label: "CyIRIS", sub: "Incident Response" },
              { icon: "🛡️", label: "CySOAR", sub: "Security Automation" },
            ].map(m => (
              <div key={m.label} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span style={{ fontSize: 16 }}>{m.icon}</span>
                <div>
                  <div style={{ color: "white", fontSize: 12, fontWeight: 600 }}>{m.label}</div>
                  <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10 }}>{m.sub}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Right — auth */}
      <div style={{ flex: "1 1 45%", display: "flex", alignItems: "center", justifyContent: "center", padding: 40 }}>
        <div style={{ width: "100%", maxWidth: 380, animation: "fadeUp 0.6s ease 0.1s both" }}>
          <div style={{ marginBottom: 32 }}>
            <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, letterSpacing: "2px", fontFamily: "monospace", marginBottom: 8 }}>SECURE ACCESS</div>
            <h2 style={{ color: "white", fontSize: 24, fontWeight: 700, marginBottom: 8 }}>Sign in to CyCentra</h2>
            <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13 }}>Use your organisation's SSO credentials.</p>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <button onClick={() => handleSSO("google")} disabled={!!loading}
              style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, padding: "14px 24px", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 6, color: "white", fontSize: 14, fontWeight: 500, cursor: loading ? "default" : "pointer", transition: "all 0.2s", opacity: loading === "microsoft" ? 0.5 : 1 }}>
              {loading === "google"
                ? <div style={{ width: 18, height: 18, border: "2px solid rgba(255,255,255,0.2)", borderTopColor: "#4285f4", borderRadius: "50%", animation: "spin 0.8s linear infinite" }}/>
                : <svg width="18" height="18" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
              }
              {loading === "google" ? "Connecting…" : "Continue with Google"}
            </button>

            <button onClick={() => handleSSO("microsoft")} disabled={!!loading}
              style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 12, padding: "14px 24px", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 6, color: "white", fontSize: 14, fontWeight: 500, cursor: loading ? "default" : "pointer", transition: "all 0.2s", opacity: loading === "google" ? 0.5 : 1 }}>
              {loading === "microsoft"
                ? <div style={{ width: 18, height: 18, border: "2px solid rgba(255,255,255,0.2)", borderTopColor: "#00b4f0", borderRadius: "50%", animation: "spin 0.8s linear infinite" }}/>
                : <svg width="18" height="18" viewBox="0 0 21 21"><rect x="1" y="1" width="9" height="9" fill="#F25022"/><rect x="11" y="1" width="9" height="9" fill="#7FBA00"/><rect x="1" y="11" width="9" height="9" fill="#00A4EF"/><rect x="11" y="11" width="9" height="9" fill="#FFB900"/></svg>
              }
              {loading === "microsoft" ? "Connecting…" : "Continue with Microsoft"}
            </button>
          </div>

          <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: 20, marginTop: 24, color: "rgba(255,255,255,0.2)", fontSize: 11, textAlign: "center", lineHeight: 1.6 }}>
            Single sign-on gateway · All modules share this session<br/>
            CySIEM · CyIRIS · CySOAR — one login to rule them all
          </div>
        </div>
      </div>
    </div>
  );
}
