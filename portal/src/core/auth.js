/**
 * src/core/auth.js
 * ================
 * SSO token and user session helpers.
 * Pure functions — no React, no JSX, no side effects beyond localStorage.
 */

// ── Storage schema version ────────────────────────────────────────────────────
// Bump this when the shape of any persisted key changes.
// On mismatch, validateStorage() clears all keys and reloads.
const STORAGE_SCHEMA_VERSION = "2";
const STORAGE_VER_KEY = "cy_storage_ver";

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

// ── Storage validation ────────────────────────────────────────────────────────
/**
 * Called once on app init. Validates every persisted key and clears/repairs
 * any that are corrupted or from an incompatible schema version.
 * Returns true if storage was clean, false if repairs were needed.
 */
export function validateStorage() {
  let repaired = false;

  // ── Schema version gate ──
  try {
    const ver = localStorage.getItem(STORAGE_VER_KEY);
    if (ver && ver !== STORAGE_SCHEMA_VERSION) {
      // Old schema — wipe all app keys and write fresh version
      const keysToWipe = [
        "cy_sso_token", "cy_user", "cycentra_ai_config",
        "cycentra_modules", "cycentra_asset_statuses",
        "cycentra_cymind_config",
      ];
      keysToWipe.forEach(k => { try { localStorage.removeItem(k); } catch {} });
      localStorage.setItem(STORAGE_VER_KEY, STORAGE_SCHEMA_VERSION);
      return false;
    }
    if (!ver) localStorage.setItem(STORAGE_VER_KEY, STORAGE_SCHEMA_VERSION);
  } catch {}

  // ── cy_user ──
  try {
    const raw = localStorage.getItem("cy_user");
    if (raw) {
      const u = JSON.parse(raw);
      if (typeof u !== "object" || u === null || !u.id || !u.role) {
        localStorage.removeItem("cy_user");
        localStorage.removeItem("cy_sso_token");
        repaired = true;
      }
    }
  } catch {
    try { localStorage.removeItem("cy_user"); localStorage.removeItem("cy_sso_token"); } catch {}
    repaired = true;
  }

  // ── cycentra_ai_config ──
  try {
    const raw = localStorage.getItem("cycentra_ai_config");
    if (raw) {
      const cfg = JSON.parse(raw);
      if (typeof cfg !== "object" || cfg === null || typeof cfg.provider !== "string") {
        localStorage.removeItem("cycentra_ai_config");
        repaired = true;
      }
    }
  } catch {
    try { localStorage.removeItem("cycentra_ai_config"); } catch {}
    repaired = true;
  }

  // ── cycentra_modules ──
  try {
    const raw = localStorage.getItem("cycentra_modules");
    if (raw) {
      const mods = JSON.parse(raw);
      if (typeof mods !== "object" || mods === null || Array.isArray(mods)) {
        localStorage.removeItem("cycentra_modules");
        repaired = true;
      }
    }
  } catch {
    try { localStorage.removeItem("cycentra_modules"); } catch {}
    repaired = true;
  }

  // ── cycentra_asset_statuses — cap at 500 entries to prevent unbounded growth ──
  try {
    const raw = localStorage.getItem("cycentra_asset_statuses");
    if (raw) {
      const map = JSON.parse(raw);
      if (typeof map !== "object" || map === null || Array.isArray(map)) {
        localStorage.removeItem("cycentra_asset_statuses");
        repaired = true;
      } else {
        const entries = Object.entries(map);
        if (entries.length > 500) {
          // Keep the last 500 by truncating oldest (object insertion order)
          const trimmed = Object.fromEntries(entries.slice(entries.length - 500));
          localStorage.setItem("cycentra_asset_statuses", JSON.stringify(trimmed));
          repaired = true;
        }
      }
    }
  } catch {
    try { localStorage.removeItem("cycentra_asset_statuses"); } catch {}
    repaired = true;
  }

  return !repaired;
}

// ── Non-essential cache clear (used by Error Boundary) ───────────────────────
export function clearNonEssentialCache() {
  const nonEssential = [
    "cycentra_ai_config",
    "cycentra_modules",
    "cycentra_asset_statuses",
    "cycentra_cymind_config",
  ];
  nonEssential.forEach(k => { try { localStorage.removeItem(k); } catch {} });
  try { sessionStorage.clear(); } catch {}
}
