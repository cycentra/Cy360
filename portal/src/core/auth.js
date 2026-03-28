/**
 * src/core/auth.js
 * ================
 * SSO token and user session helpers.
 * Pure functions — no React, no JSX, no side effects beyond localStorage.
 */

// ── SSO token ─────────────────────────────────────────────────────────────────

export function getSSOToken() {
  try {
    const t = localStorage.getItem("cy_sso_token");
    return t?.trim() || null;
  } catch { return null; }
}

export function setSSOToken(token) {
  try {
    if (token) localStorage.setItem("cy_sso_token", token);
  } catch {}
}

export function clearSSOToken() {
  try {
    localStorage.removeItem("cy_sso_token");
    localStorage.removeItem("cy_user");
  } catch {}
}

// ── User session ──────────────────────────────────────────────────────────────

export function getSavedUser() {
  try {
    const raw = localStorage.getItem("cy_user");
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

export function saveUser(u) {
  try { localStorage.setItem("cy_user", JSON.stringify(u)); } catch {}
}
