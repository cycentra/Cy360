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
  "open":           { color: "#ff3b3b", label: "OPEN"           },
  "investigating":  { color: "#ff8c00", label: "INVESTIGATING"  },
  "in_review":      { color: "#f5c518", label: "IN REVIEW"      },
  "in-review":      { color: "#f5c518", label: "IN REVIEW"      },
  "held":           { color: "#b36bff", label: "HELD"           },
  "resolved":       { color: "#00e5a0", label: "RESOLVED"       },
  "false_positive": { color: "#888888", label: "FALSE POSITIVE" },
  "closed":         { color: "#555555", label: "CLOSED"         },
};

// Ordered lifecycle steps for display
export const STATUS_LIFECYCLE = [
  { key: "investigating",  label: "Investigating",  color: "#ff8c00" },
  { key: "in_review",      label: "In Review",      color: "#f5c518" },
  { key: "resolved",       label: "Resolved",       color: "#00e5a0" },
  { key: "false_positive", label: "False Positive", color: "#888888" },
];

// Analyst-available transitions from each status
export const STATUS_TRANSITIONS = {
  "open":           ["investigating", "in_review", "resolved", "false_positive", "closed"],
  "investigating":  ["in_review", "resolved", "false_positive", "closed"],
  "in_review":      ["resolved", "false_positive", "closed", "investigating"],
  "held":           ["investigating", "in_review", "resolved", "false_positive", "closed"],
  "resolved":       ["investigating", "in_review", "closed"],
  "false_positive": ["investigating", "closed"],
  "closed":         ["investigating"],
};
