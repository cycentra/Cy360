/**
 * portal/src/pages/settings/SSOTab.jsx
 * ======================================
 * SSO & SMTP settings tab for SystemSettingsPage.
 *
 * Sections:
 *  1. SSO Provider configuration (OIDC/OAuth2)
 *  2. SMTP / email notification settings
 *  3. Pending users approval table
 */

import { useState, useEffect, useRef } from "react";
import { API_BASE } from "../../core/constants.js";

// Known OIDC discovery URL defaults per built-in provider.
// Auto-applied when the admin switches provider — not on initial load.
const DISCOVERY_DEFAULTS = {
  google:      "https://accounts.google.com/.well-known/openid-configuration",
  microsoft:   "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
  okta:        "",   // tenant-specific — must be supplied manually
  keycloak:    "",   // realm-specific — must be supplied manually
  cycentra360: "",   // auto-filled by the backend from BASE_URL
  custom:      "",   // fully manual
};

// ── Shared style constants (copied from SystemSettingsPage to stay self-contained) ──
const CARD  = { background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "20px 24px", marginBottom: 20 };
const LABEL = { color: "rgba(255,255,255,0.35)", fontSize: 10, letterSpacing: "1.5px", fontFamily: "monospace", textTransform: "uppercase", marginBottom: 6 };
const INPUT = { background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 4, color: "white", fontFamily: "monospace", fontSize: 12, padding: "8px 12px", width: "100%", outline: "none", boxSizing: "border-box" };
const BTN   = (color = "#00e5a0") => ({
  background:   `rgba(${color === "#00e5a0" ? "0,229,160" : color === "#4d9eff" ? "77,158,255" : color === "#ff3b3b" ? "255,59,59" : "255,140,0"},0.1)`,
  color,
  border:       `1px solid ${color}40`,
  padding:      "8px 18px",
  borderRadius: 4,
  fontFamily:   "monospace",
  fontSize:     11,
  fontWeight:   700,
  letterSpacing: "1px",
  cursor:       "pointer",
  textTransform: "uppercase",
});

const STATUS_OK  = { color: "#00e5a0", fontSize: 12, fontFamily: "monospace", marginTop: 10 };
const STATUS_ERR = { color: "#ff3b3b", fontSize: 12, fontFamily: "monospace", marginTop: 10 };

const BUILTIN_PROVIDERS = [
  { id: "google",      name: "Google Workspace" },
  { id: "microsoft",   name: "Microsoft / Azure AD" },
  { id: "okta",        name: "Okta" },
  { id: "keycloak",    name: "Keycloak" },
  { id: "cycentra360", name: "CyCentra 360 IdP" },
  { id: "custom",      name: "Custom OIDC" },
];

// ════════════════════════════════════════════════════════════════════════════
// Section 1 — SSO Provider
// ════════════════════════════════════════════════════════════════════════════

function SSOProviderCard({ onStatusMsg }) {
  const [cfg, setCfg]         = useState(null);
  const [status, setStatus]   = useState(null);   // { ok, ...} from /api/sso/status
  const [saving, setSaving]   = useState(false);
  const [disabling, setDis]   = useState(false);
  const [msg, setMsg]         = useState(null);

  // Form fields
  const [provider,       setProvider]       = useState("google");
  const [clientId,       setClientId]       = useState("");
  const [clientSecret,   setClientSecret]   = useState("");
  const [discoveryUrl,   setDiscoveryUrl]   = useState("");
  const [redirectUri,    setRedirectUri]    = useState("");
  const [defaultRole,    setDefaultRole]    = useState("viewer");
  const [autoProvision,  setAutoProvision]  = useState(true);
  const [requireApproval, setRequireApproval] = useState(false);
  const [allowedDomains, setAllowedDomains] = useState("");
  const [secretConfigured, setSecretConfigured] = useState(false);

  // Tracks whether the provider was changed interactively by the user.
  // Prevents auto-fill from overwriting server-loaded values on first render.
  const userChangedProvider = useRef(false);

  const load = () => {
    // /api/sso/config (admin) — returns full editable config for pre-populating the form.
    // Falls back to /api/sso/providers (public) for non-admins / unauthenticated.
    fetch(`${API_BASE}/api/sso/config`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (!d || d.error) return;
        if (d.provider)         setProvider(d.provider);
        if (d.client_id)        setClientId(d.client_id);
        if (d.discovery_url)    setDiscoveryUrl(d.discovery_url);
        if (d.redirect_uri)     setRedirectUri(d.redirect_uri);
        if (d.default_role)     setDefaultRole(d.default_role);
        if (d.auto_provision   !== undefined) setAutoProvision(d.auto_provision);
        if (d.require_approval !== undefined) setRequireApproval(d.require_approval);
        if (d.allowed_domains  !== undefined) setAllowedDomains(d.allowed_domains);
        if (d.secret_configured !== undefined) setSecretConfigured(d.secret_configured);
      })
      .catch(() => {});

    fetch(`${API_BASE}/api/sso/providers`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setCfg(d); })
      .catch(() => {});

    fetch(`${API_BASE}/api/sso/status`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => d && setStatus(d))
      .catch(() => {});
  };

  useEffect(() => { load(); }, []);

  // When the admin manually switches provider, auto-fill known discovery URLs
  // and reset the redirect URI to the default callback.  This effect is skipped
  // on the initial render so it does not overwrite values loaded from the server.
  useEffect(() => {
    if (!userChangedProvider.current) return;

    // Apply per-provider defaults
    setDiscoveryUrl(DISCOVERY_DEFAULTS[provider] ?? "");
    setRedirectUri(`${window.location.origin}/api/sso/callback`);

    if (provider === "cycentra360") {
      setClientId("cy360sso");
      // discovery URL and client_secret are provisioned server-side — leave blank
    }
  }, [provider]);

  const handleSave = async () => {
    setSaving(true); setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/sso/configure`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider:        provider,
          client_id:       clientId,
          client_secret:   clientSecret,
          discovery_url:   discoveryUrl,
          redirect_uri:    redirectUri,
          default_role:    defaultRole,
          auto_provision:  autoProvision,
          require_approval: requireApproval,
          allowed_domains: allowedDomains,
        }),
      });
      const d = await r.json();
      if (d.ok) {
        setMsg({ ok: true, text: `SSO configured — provider: ${d.provider}` });
        load();
      } else {
        setMsg({ ok: false, text: d.error || "Save failed" });
      }
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setSaving(false);
    }
  };

  const handleDisable = async () => {
    setDis(true); setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/sso/disable`, { method: "POST", credentials: "include" });
      const d = await r.json();
      setMsg(d.ok ? { ok: true, text: "SSO disabled" } : { ok: false, text: d.error || "Failed" });
      if (d.ok) load();
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setDis(false);
    }
  };

  const handleProbe = async () => {
    setMsg(null);
    const r = await fetch(`${API_BASE}/api/sso/status`, { credentials: "include" }).catch(() => null);
    const d = r ? await r.json() : null;
    if (d?.ok) {
      setMsg({ ok: true, text: `Provider reachable — issuer: ${d.issuer}` });
    } else {
      setMsg({ ok: false, text: d?.error || "Provider unreachable" });
    }
  };

  const ssoEnabled = cfg?.sso_enabled;

  return (
    <div style={CARD}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 16, lineHeight: 1 }}>🔐</span>
          <div style={{ color: "rgba(0,229,160,0.9)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700 }}>SSO Provider (OIDC / OAuth2)</div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {ssoEnabled && (
            <span style={{ background: "rgba(0,229,160,0.08)", color: "#00e5a0", border: "1px solid rgba(0,229,160,0.3)", borderRadius: 4, padding: "2px 8px", fontSize: 10, fontFamily: "monospace" }}>
              ENABLED — {cfg?.provider_name || cfg?.provider_id}
            </span>
          )}
          {status && (
            <span style={{ background: status.ok ? "rgba(0,229,160,0.06)" : "rgba(255,59,59,0.06)", color: status.ok ? "#00e5a0" : "#ff3b3b", border: `1px solid ${status.ok ? "rgba(0,229,160,0.2)" : "rgba(255,59,59,0.2)"}`, borderRadius: 4, padding: "2px 8px", fontSize: 10, fontFamily: "monospace" }}>
              {status.ok ? "● CONNECTED" : "✗ UNREACHABLE"}
            </span>
          )}
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
        {/* Provider selector */}
        <div>
          <div style={LABEL}>Provider</div>
          <select value={provider} onChange={e => { userChangedProvider.current = true; setProvider(e.target.value); }} style={{ ...INPUT, cursor: "pointer" }}>
            {BUILTIN_PROVIDERS.map(p => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
        </div>
        {/* Default role */}
        <div>
          <div style={LABEL}>Default Role for New Users</div>
          <select value={defaultRole} onChange={e => setDefaultRole(e.target.value)} style={{ ...INPUT, cursor: "pointer" }}>
            {["viewer", "analyst", "admin"].map(r => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
        </div>
        {/* Client ID */}
        <div>
          <div style={LABEL}>Client ID</div>
          <input type="text" value={clientId} onChange={e => setClientId(e.target.value)}
            placeholder="OAuth client_id from your IdP"
            readOnly={provider === "cycentra360"}
            style={{ ...INPUT, ...(provider === "cycentra360" ? { opacity: 0.6, cursor: "default" } : {}) }} />
          {provider === "cycentra360" && (
            <div style={{ color: "rgba(0,229,160,0.55)", fontSize: 10, fontFamily: "monospace", marginTop: 4 }}>
              Fixed to <code>cy360sso</code> — the registered OIDC client for CyCentra 360 self-authentication.
            </div>
          )}
        </div>
        {/* Client Secret */}
        <div>
          <div style={LABEL}>Client Secret</div>
          <input type="password" value={clientSecret} onChange={e => setClientSecret(e.target.value)}
            placeholder={provider === "cycentra360" ? "Auto-provisioned from server config — leave blank" : secretConfigured ? "•••••••• (stored — leave blank to keep)" : "Paste your IdP client secret"}
            style={INPUT} />
          {secretConfigured && provider !== "cycentra360" && (
            <div style={{ color: "rgba(0,229,160,0.5)", fontSize: 10, fontFamily: "monospace", marginTop: 4 }}>
              ✓ A secret is stored. Leave blank to keep it, or paste a new value to replace.
            </div>
          )}
        </div>
        {/* Discovery URL */}
        <div style={{ gridColumn: "1 / -1" }}>
          <div style={LABEL}>OIDC Discovery URL</div>
          <input type="url" value={discoveryUrl} onChange={e => setDiscoveryUrl(e.target.value)}
            placeholder="https://…/.well-known/openid-configuration  (auto-filled for Google/Microsoft/CyCentra360)" style={INPUT} />
          <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 10, fontFamily: "monospace", marginTop: 4, lineHeight: 1.6 }}>
            This is your <strong style={{ color: "rgba(255,255,255,0.4)" }}>identity provider's</strong> URL, not this portal's URL.
            {provider === "google"      && " Auto-filled for Google — leave blank."}
            {provider === "microsoft"   && " Auto-filled for Microsoft / Azure AD — leave blank."}
            {provider === "cycentra360" && " Auto-filled to the CyCentra OIDC endpoint — leave blank."}
            {provider === "okta"        && " Example: https://your-org.okta.com/.well-known/openid-configuration"}
            {provider === "keycloak"    && " Example: https://keycloak.host/realms/your-realm/.well-known/openid-configuration"}
            {provider === "custom"      && " Enter your IdP's OIDC discovery document URL."}
          </div>
        </div>
        {/* Redirect URI */}
        <div style={{ gridColumn: "1 / -1" }}>
          <div style={LABEL}>Redirect URI (callback)</div>
          <input type="url" value={redirectUri} onChange={e => setRedirectUri(e.target.value)}
            placeholder={`${window.location.origin}/api/sso/callback`}
            readOnly={provider === "cycentra360"}
            style={{ ...INPUT, ...(provider === "cycentra360" ? { opacity: 0.6, cursor: "default" } : {}) }} />
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace", marginTop: 4 }}>
            {provider === "cycentra360"
              ? "Fixed to the portal's SSO callback — already registered in the CyCentra 360 OIDC provider."
              : "Edit if your IdP requires a custom callback URL. Register this exact value as an authorised redirect URI in your IdP application settings."
            }
          </div>
        </div>
        {/* Allowed domains */}
        <div style={{ gridColumn: "1 / -1" }}>
          <div style={LABEL}>Allowed Email Domains (optional)</div>
          <input type="text" value={allowedDomains} onChange={e => setAllowedDomains(e.target.value)}
            placeholder="cycentra.com,partner.com  (comma-separated, leave blank to allow all)" style={INPUT} />
        </div>
      </div>

      {/* Toggles */}
      <div style={{ display: "flex", gap: 24, marginBottom: 18 }}>
        <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", color: "rgba(255,255,255,0.6)", fontSize: 12 }}>
          <input type="checkbox" checked={autoProvision} onChange={e => setAutoProvision(e.target.checked)}
            style={{ accentColor: "#00e5a0", width: 14, height: 14 }} />
          Auto-provision new SSO users
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", color: "rgba(255,255,255,0.6)", fontSize: 12 }}>
          <input type="checkbox" checked={requireApproval} onChange={e => setRequireApproval(e.target.checked)}
            style={{ accentColor: "#ffd93d", width: 14, height: 14 }} />
          <span>
            Require admin approval for new users
            {requireApproval && <span style={{ color: "#ffd93d", marginLeft: 4 }}>— admin will receive an email per login attempt</span>}
          </span>
        </label>
      </div>

      {/* Actions */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        <button onClick={handleSave} disabled={saving} style={{ ...BTN(), opacity: saving ? 0.5 : 1 }}>
          {saving ? "Saving…" : "Save & Enable SSO"}
        </button>
        <button onClick={handleProbe} style={BTN("#4d9eff")}>Test Connection</button>
        {ssoEnabled && (
          <button onClick={handleDisable} disabled={disabling} style={{ ...BTN("#ff3b3b"), opacity: disabling ? 0.5 : 1 }}>
            {disabling ? "Disabling…" : "Disable SSO"}
          </button>
        )}
      </div>

      {msg && <div style={msg.ok ? STATUS_OK : STATUS_ERR}>{msg.ok ? "✓" : "✗"} {msg.text}</div>}

      <div style={{ marginTop: 14, color: "rgba(255,255,255,0.18)", fontSize: 10, fontFamily: "monospace", lineHeight: 1.8 }}>
        SSO login URL: <code style={{ color: "#00e5a0" }}>{`${window.location.origin}/api/sso/redirect`}</code><br/>
        Callback URL: <code style={{ color: "#00e5a0" }}>{`${window.location.origin}/api/sso/callback`}</code>
      </div>
    </div>
  );
}


// ════════════════════════════════════════════════════════════════════════════
// Section 2 — SMTP
// ════════════════════════════════════════════════════════════════════════════

function SMTPCard() {
  const [cfg, setCfg]       = useState(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTest]  = useState(false);
  const [msg, setMsg]       = useState(null);
  const [pwdSaved, setPwdSaved] = useState(false);

  const [host,       setHost]       = useState("");
  const [port,       setPort]       = useState("587");
  const [user,       setUser]       = useState("");
  const [pass,       setPass]       = useState("");
  const [from_,      setFrom]       = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [useTls,     setUseTls]     = useState(true);
  const [testTo,     setTestTo]     = useState("");

  useEffect(() => {
    fetch(`${API_BASE}/api/sso/smtp/config`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (!d) return;
        setCfg(d);
        setHost(d.smtp_host || "");
        setPort(String(d.smtp_port || 587));
        setUser(d.smtp_user || "");
        setFrom(d.smtp_from || "");
        setAdminEmail(d.smtp_admin_email || "");
        setUseTls(d.smtp_use_tls !== false);
        setPwdSaved(!!d.smtp_password);  // "••••••••" = password is set
        // never pre-fill the password field
      })
      .catch(() => {});
  }, []);

  const handleSave = async () => {
    setSaving(true); setMsg(null);
    try {
      const body = {
        smtp_host:        host,
        smtp_port:        port,
        smtp_user:        user,
        smtp_from:        from_,
        smtp_admin_email: adminEmail,
        smtp_use_tls:     useTls ? "true" : "false",
      };
      if (pass) body.smtp_password = pass;

      const r = await fetch(`${API_BASE}/api/sso/smtp/config`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (d.ok) { setMsg({ ok: true, text: "SMTP settings saved" }); if (pass) { setPwdSaved(true); setPass(""); } }
      else setMsg({ ok: false, text: d.error || "Save failed" });
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    setTest(true); setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/sso/smtp/test`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: testTo || adminEmail }),
      });
      const d = await r.json();
      setMsg(d.ok ? { ok: true, text: d.message } : { ok: false, text: d.error || "Test failed" });
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setTest(false);
    }
  };

  return (
    <div style={CARD}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 16, lineHeight: 1 }}>✉️</span>
          <div style={{ color: "rgba(0,229,160,0.9)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace", fontWeight: 700 }}>SMTP / Email Notifications</div>
        </div>
        {cfg?.smtp_host && (
          <span style={{ background: "rgba(0,229,160,0.08)", color: "#00e5a0", border: "1px solid rgba(0,229,160,0.25)", borderRadius: 4, padding: "2px 8px", fontSize: 10, fontFamily: "monospace" }}>
            CONFIGURED — {cfg.smtp_host}
          </span>
        )}
      </div>

      <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 11, marginBottom: 16, lineHeight: 1.6 }}>
        When SMTP is configured and "Require approval" is enabled, new SSO users receive a
        hold email and the admin receives an approve / reject email with one-click links.
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
        <div>
          <div style={LABEL}>SMTP Host</div>
          <input type="text" value={host} onChange={e => setHost(e.target.value)}
            placeholder="smtp.gmail.com" style={INPUT} />
        </div>
        <div>
          <div style={LABEL}>Port</div>
          <input type="number" value={port} onChange={e => setPort(e.target.value)}
            placeholder="587" style={INPUT} />
        </div>
        <div>
          <div style={LABEL}>Username</div>
          <input type="text" value={user} onChange={e => setUser(e.target.value)}
            placeholder="noreply@cycentra.com" style={INPUT} />
        </div>
        <div>
          <div style={{ ...LABEL, display: "flex", alignItems: "center", gap: 6 }}>
            Password
            {pwdSaved && <span style={{ fontSize: 10, color: "#00e5a0", fontFamily: "monospace" }}>✓ Saved</span>}
          </div>
          <input type="password" value={pass} onChange={e => setPass(e.target.value)}
            placeholder={pwdSaved ? "•••••••• (leave blank to keep)" : "SMTP password or app password"}
            style={INPUT} />
        </div>
        <div>
          <div style={LABEL}>From Address</div>
          <input type="email" value={from_} onChange={e => setFrom(e.target.value)}
            placeholder="CyCentra 360 <noreply@cycentra.com>" style={INPUT} />
        </div>
        <div>
          <div style={LABEL}>Admin Email (approval recipient)</div>
          <input type="email" value={adminEmail} onChange={e => setAdminEmail(e.target.value)}
            placeholder="admin@cycentra.com" style={INPUT} />
        </div>
      </div>

      <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", color: "rgba(255,255,255,0.6)", fontSize: 12, marginBottom: 16 }}>
        <input type="checkbox" checked={useTls} onChange={e => setUseTls(e.target.checked)}
          style={{ accentColor: "#00e5a0", width: 14, height: 14 }} />
        Use STARTTLS (recommended for port 587)
      </label>

      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
        <button onClick={handleSave} disabled={saving} style={{ ...BTN(), opacity: saving ? 0.5 : 1 }}>
          {saving ? "Saving…" : "Save SMTP Settings"}
        </button>
        <input type="email" value={testTo} onChange={e => setTestTo(e.target.value)}
          placeholder="Send test to… (defaults to admin email)"
          style={{ ...INPUT, width: 240, display: "inline-block" }} />
        <button onClick={handleTest} disabled={testing} style={{ ...BTN("#4d9eff"), opacity: testing ? 0.5 : 1 }}>
          {testing ? "Sending…" : "Send Test Email"}
        </button>
      </div>

      {msg && <div style={msg.ok ? STATUS_OK : STATUS_ERR}>{msg.ok ? "✓" : "✗"} {msg.text}</div>}
    </div>
  );
}


// ════════════════════════════════════════════════════════════════════════════
// Section 3 — Pending approvals
// ════════════════════════════════════════════════════════════════════════════

function PendingUsersCard() {
  const [pending,  setPending]  = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [working,  setWorking]  = useState({});   // { email: "approve"|"reject" }
  const [reject,   setReject]   = useState({});   // { email: reason_string }
  const [showReject, setShowR]  = useState(null); // email currently in reject modal
  const [msg, setMsg]           = useState(null);

  const load = () => {
    setLoading(true);
    fetch(`${API_BASE}/api/sso/pending`, { credentials: "include" })
      .then(r => r.ok ? r.json() : { pending: [] })
      .then(d => { setPending(d.pending || []); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const doApprove = async (email) => {
    setWorking(w => ({ ...w, [email]: "approve" }));
    const r = await fetch(`${API_BASE}/api/sso/approve/${encodeURIComponent(email)}`, {
      method: "POST", credentials: "include",
    }).catch(() => null);
    const d = r ? await r.json() : null;
    if (d?.ok) {
      setMsg({ ok: true, text: `Approved ${email}` });
      load();
    } else {
      setMsg({ ok: false, text: d?.error || "Approve failed" });
    }
    setWorking(w => { const n = { ...w }; delete n[email]; return n; });
  };

  const doReject = async (email) => {
    const reason = (reject[email] || "").trim();
    setWorking(w => ({ ...w, [email]: "reject" }));
    const r = await fetch(`${API_BASE}/api/sso/reject/${encodeURIComponent(email)}`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    }).catch(() => null);
    const d = r ? await r.json() : null;
    if (d?.ok) {
      setMsg({ ok: true, text: `Rejected ${email}` });
      setShowR(null);
      load();
    } else {
      setMsg({ ok: false, text: d?.error || "Reject failed" });
    }
    setWorking(w => { const n = { ...w }; delete n[email]; return n; });
  };

  return (
    <div style={CARD}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div style={LABEL}>Pending Approvals</div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {pending.length > 0 && (
            <span style={{ background: "rgba(255,217,61,0.1)", color: "#ffd93d", border: "1px solid rgba(255,217,61,0.3)", borderRadius: 4, padding: "2px 8px", fontSize: 10, fontFamily: "monospace" }}>
              {pending.length} WAITING
            </span>
          )}
          <button onClick={load} style={{ ...BTN("#4d9eff"), padding: "4px 12px" }}>Refresh</button>
        </div>
      </div>

      {loading && (
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>
      )}

      {!loading && pending.length === 0 && (
        <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 12, fontFamily: "monospace" }}>
          No users are pending approval.
        </div>
      )}

      {!loading && pending.length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr>
                {["Email", "Name", "Role", "Provider", "Requested At", "Actions"].map(h => (
                  <th key={h} style={{ textAlign: "left", padding: "6px 10px", color: "rgba(255,255,255,0.3)", fontFamily: "monospace", fontSize: 10, letterSpacing: "1px", borderBottom: "1px solid rgba(255,255,255,0.06)", textTransform: "uppercase" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {pending.map(u => (
                <tr key={u.email} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                  <td style={{ padding: "10px 10px", color: "rgba(255,255,255,0.8)", fontFamily: "monospace" }}>{u.email}</td>
                  <td style={{ padding: "10px 10px", color: "rgba(255,255,255,0.55)" }}>{u.name || "—"}</td>
                  <td style={{ padding: "10px 10px" }}>
                    <span style={{ background: "rgba(0,229,160,0.08)", color: "#00e5a0", borderRadius: 3, padding: "2px 7px", fontSize: 10, fontFamily: "monospace" }}>{u.role}</span>
                  </td>
                  <td style={{ padding: "10px 10px", color: "rgba(255,255,255,0.4)", fontSize: 11, fontFamily: "monospace" }}>{u.sso_provider || "—"}</td>
                  <td style={{ padding: "10px 10px", color: "rgba(255,255,255,0.35)", fontSize: 11, fontFamily: "monospace" }}>
                    {u.approval_requested_at ? new Date(u.approval_requested_at).toLocaleString() : "—"}
                  </td>
                  <td style={{ padding: "10px 10px" }}>
                    <div style={{ display: "flex", gap: 6 }}>
                      <button
                        onClick={() => doApprove(u.email)}
                        disabled={!!working[u.email]}
                        style={{ ...BTN(), padding: "4px 12px", opacity: working[u.email] ? 0.5 : 1 }}>
                        {working[u.email] === "approve" ? "…" : "Approve"}
                      </button>
                      <button
                        onClick={() => setShowR(u.email)}
                        disabled={!!working[u.email]}
                        style={{ ...BTN("#ff3b3b"), padding: "4px 12px", opacity: working[u.email] ? 0.5 : 1 }}>
                        Reject
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {msg && <div style={{ ...(msg.ok ? STATUS_OK : STATUS_ERR), marginTop: 12 }}>{msg.ok ? "✓" : "✗"} {msg.text}</div>}

      {/* Reject reason modal */}
      {showReject && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ background: "#13151a", border: "1px solid rgba(255,59,59,0.35)", borderRadius: 8, padding: "28px 32px", width: 420, maxWidth: "90vw" }}>
            <div style={{ color: "#ff3b3b", fontSize: 11, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1.5px", marginBottom: 12 }}>REJECT ACCESS — {showReject}</div>
            <div style={LABEL}>Reason (optional — sent to user)</div>
            <textarea
              value={reject[showReject] || ""}
              onChange={e => setReject(r => ({ ...r, [showReject]: e.target.value }))}
              rows={3}
              placeholder="e.g. Account not authorised for this instance."
              style={{ ...INPUT, resize: "vertical", height: 72 }}
            />
            <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", marginTop: 16 }}>
              <button onClick={() => setShowR(null)} style={BTN("#4d9eff")}>Cancel</button>
              <button onClick={() => doReject(showReject)} disabled={!!working[showReject]}
                style={{ ...BTN("#ff3b3b"), opacity: working[showReject] ? 0.5 : 1 }}>
                {working[showReject] === "reject" ? "Rejecting…" : "Confirm Reject"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


// ════════════════════════════════════════════════════════════════════════════
// Exported tab component
// ════════════════════════════════════════════════════════════════════════════

export function SSOTab() {
  return (
    <div>
      <SSOProviderCard />
      <SMTPCard />
      <PendingUsersCard />
    </div>
  );
}
