/**
 * src/core/constants.js
 * =====================
 * Single source of truth for all URL constants, color configs,
 * and domain-derived values. Replaces portal/src/config/constants.js
 * (that file should be deleted after this is in place).
 *
 * Import from here everywhere — never reference _BASE_DOMAIN directly
 * in component files.
 */

// ── Dynamic domain resolution ─────────────────────────────────────────────────
// setup.sh injects: <script>window.__CYCENTRA_DOMAIN__='clientdomain.com';</script>
// into index.html. Falls back to hostname derivation for dev.
export const _BASE_DOMAIN = (
  window.__CYCENTRA_DOMAIN__ ||
  window.location.hostname.replace(/^cy360\./, "")
);

// ── Service URLs ─────────────────────────────────────────────────────────
export const CYSCAN_URL    = `https://cyasm.${_BASE_DOMAIN}`;
export const PORTAL_URL    = `https://cy360.${_BASE_DOMAIN}`;
export const PORTAL_ISSUER = `https://cy360.${_BASE_DOMAIN}`;
export const SIEM_BASE_URL = `https://cysiem.${_BASE_DOMAIN}`;
export const IRIS_BASE_URL = `https://cyiris.${_BASE_DOMAIN}`;
export const MISP_BASE_URL = `https://cymisp.${_BASE_DOMAIN}`;

// API_BASE is empty — all fetch() calls use same-origin relative URLs.
// nginx proxies /api/ /auth/ /oidc/ → Flask on port 5252.
export const API_BASE = "";

// ── Module default URLs ───────────────────────────────────────────────────────
export const MODULE_DEFAULT_URLS = {
  cysiem: SIEM_BASE_URL,
  cyiris: IRIS_BASE_URL,
  cysoar: `${PORTAL_URL}/cysoar`,
  cymisp: MISP_BASE_URL,
};

export function getModuleUrl(moduleId) {
  try {
    const saved = localStorage.getItem(`cycentra_url_${moduleId}`);
    if (saved?.trim()) return saved.trim().replace(/\/$/, "");
  } catch {}
  return MODULE_DEFAULT_URLS[moduleId] || CYSCAN_URL;
}

export function navigateToModule(moduleId) {
  const url = getModuleUrl(moduleId);
  window.history.pushState({ moduleId, from: "portal" }, "", window.location.pathname);
  window.location.href = url;
}

// ── Risk & status display config ──────────────────────────────────────────────
export const RISK_CONFIG = {
  critical: { color: "#ff3b3b", bg: "rgba(255,59,59,0.12)",  label: "CRITICAL" },
  high:     { color: "#ff8c00", bg: "rgba(255,140,0,0.12)",  label: "HIGH"     },
  medium:   { color: "#f5c518", bg: "rgba(245,197,24,0.12)", label: "MEDIUM"   },
  low:      { color: "#00e5a0", bg: "rgba(0,229,160,0.12)",  label: "LOW"      },
};

export const STATUS_CONFIG = {
  // ── Asset lifecycle states ────────────────────────────────────────────────
  "new":            { color: "#00e5a0", label: "NEW"           },
  "baseline":       { color: "#4d9eff", label: "BASELINE"      },
  "under_review":   { color: "#f5c518", label: "UNDER REVIEW"  },
  "ignored":        { color: "#888888", label: "IGNORED"       },
  "dropped":        { color: "#ff8c00", label: "DROPPED"       },
  // ── Finding lifecycle states ──────────────────────────────────────────────
  "open":           { color: "#00e5a0", label: "OPEN"          },
  "investigating":  { color: "#f5c518", label: "INVESTIGATING" },
  "in_review":      { color: "#4d9eff", label: "IN REVIEW"     },
  "resolved":       { color: "#888888", label: "RESOLVED"      },
  "false_positive": { color: "#ff8c00", label: "FALSE POSITIVE"},
};

// Ordered lifecycle steps for display
export const STATUS_LIFECYCLE = [
  { key: "new",          label: "New",          color: "#00e5a0" },
  { key: "baseline",     label: "Baseline",     color: "#4d9eff" },
  { key: "under_review", label: "Under Review", color: "#f5c518" },
  { key: "ignored",      label: "Ignored",      color: "#888888" },
  { key: "dropped",      label: "Dropped",      color: "#ff8c00" },
];

// Analyst-available transitions from each asset state (mirrors backend _ASSET_ALLOWED_TRANSITIONS)
export const STATUS_TRANSITIONS = {
  // ── Asset states ──────────────────────────────────────────────────────────
  "new":            ["baseline", "under_review", "ignored"],
  "baseline":       ["under_review", "ignored"],
  "under_review":   ["baseline", "ignored", "new"],
  "ignored":        ["new", "baseline"],
  "dropped":        ["new", "baseline"],
  // ── Finding states ────────────────────────────────────────────────────────
  "open":           ["investigating", "resolved", "false_positive"],
  "investigating":  ["in_review", "resolved", "false_positive"],
  "in_review":      ["resolved", "false_positive", "open"],
  "resolved":       ["open"],
  "false_positive": ["open"],
};
