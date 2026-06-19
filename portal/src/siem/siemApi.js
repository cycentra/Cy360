/**
 * siemApi.js
 * Centralised fetch client for all /api/siem/* calls.
 * All calls use same-origin relative URLs with credentials so the Flask
 * session cookie is forwarded by the browser.
 *
 * Usage:
 *   import { siemApi } from './siemApi';
 *   const data = await siemApi.getIncidents({ status: 'open', limit: 50 });
 */

const SIEM = "/api/siem";

async function _get(path, params = {}) {
  const qs = new URLSearchParams(
    Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined && v !== ""))
  ).toString();
  const url = qs ? `${SIEM}${path}?${qs}` : `${SIEM}${path}`;
  const r = await fetch(url, { credentials: "include" });
  return r;
}

async function _patch(path, body) {
  return fetch(`${SIEM}${path}`, {
    method: "PATCH",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function _post(path, body) {
  return fetch(`${SIEM}${path}`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export const siemApi = {
  /** Liveness probe — used by SiemEngineStatus guard */
  getHealth: () => _get("/health"),

  /** Engine metrics: alert count, incident count, uptime */
  getStats: () => _get("/stats"),

  /**
   * Paginated incident list.
   * @param {{ status?: string, severity?: string, limit?: number, offset?: number }} params
   */
  getIncidents: (params = {}) => _get("/incidents", params),

  /** Full incident detail including child alerts, MISP hits, LLM narrative */
  getIncident: (id) => _get(`/incidents/${id}`),

  /**
   * Update incident (analyst+ role required).
   * @param {string} id
   * @param {{ status?: string, assigned_to?: string, notes?: string, false_positive_reason?: string }} body
   */
  patchIncident: (id, body) => _patch(`/incidents/${id}`, body),

  /**
   * Entity risk leaderboard.
   * @param {{ entity_type?: 'host'|'user', min_score?: number, limit?: number }} params
   */
  getRiskScores: (params = {}) => _get("/risk-scores", params),

  /** List all UEBA baselines
   * @param {{ category?: 'human'|'service'|'system', has_anomaly?: boolean, top_activity?: number }} params
   */
  getUebaUsers: (params = {}) => _get("/ueba/users", params),

  /** Full UEBA profile for a user: baseline + anomaly history */
  getUebaUser: (username) => _get(`/ueba/${encodeURIComponent(username)}`),

  /** Fetch the full chronological audit trail for an incident. */
  getAuditLog: (id) => _get(`/incidents/${id}/audit`),

  /**
   * Analyst-initiated status transition with mandatory audit comment.
   * @param {string} id Incident ID
   * @param {{ to_status: string, comment: string }} body
   */
  transitionIncident: (id, body) => _post(`/incidents/${id}/transition`, body),

  /** Returns integration URLs (iris_url, wazuh_url, iris_enabled, wazuh_enabled) */
  getUebaIntegrations: () => _get("/ueba/integrations"),

  /** Recent raw alert list */
  getAlerts: (params = {}) => _get("/alerts", params),

  /** Engine configuration (sanitised, no secrets) */
  getConfig: () => _get("/config"),

  /** Engine Docker status */
  getEngineStatus: () => _get("/engine/status"),

  /**
   * Hard-delete incidents by status. Admin role required.
   * @param {string} [status] Comma-separated statuses e.g. 'resolved,false_positive'. Omit for ALL.
   */
  purgeIncidents: (status) => {
    const qs = status ? `?status=${encodeURIComponent(status)}` : "";
    return fetch(`${SIEM}/incidents${qs}`, { method: "DELETE", credentials: "include" });
  },

  /**
   * Soft-close all false_positive and resolved incidents → closed.
   * Does NOT delete rows. Analyst role required.
   */
  batchCloseIncidents: (comment = "Archived via analyst action") =>
    fetch(`${SIEM}/incidents/batch-close`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ comment }),
    }),

  /**
   * Trigger on-demand LLM AI analysis for any incident. Analyst+.
   * @param {string} id Incident ID
   */
  requestAiAnalysis: (id) => _post(`/incidents/${id}/analyse`, {}),

  /** List all learned FP patterns. */
  getFpPatterns: () => _get("/fp-patterns"),

  /**
   * Toggle auto_close or update threshold/description for an FP pattern. Analyst+.
   * @param {number} id Pattern ID
   * @param {{ auto_close?: boolean, threshold?: number, description?: string }} body
   */
  toggleFpPattern: (id, body) => _patch(`/fp-patterns/${id}`, body),

  /**
   * Delete a learned FP pattern. Admin only.
   * @param {number} id Pattern ID
   */
  deleteFpPattern: (id) =>
    fetch(`${SIEM}/fp-patterns/${id}`, { method: "DELETE", credentials: "include" }),

  /**
   * Create a WebSocket connection to the engine live feed.
   * Authenticated via same-origin cookie.
   * Returns a native WebSocket instance.
   */
  connectLive: () => {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    return new WebSocket(`${proto}://${location.host}/api/siem/ws/live`);
  },

  /** List all active threat hunt rules with finding counts. */
  getThreatHuntRules: () => _get("/threat-hunting/rules"),

  /**
   * Paginated threat hunt finding list (hunt_finding incidents).
   * @param {{ status?: string, severity?: string, limit?: number, offset?: number }} params
   */
  getThreatHuntFindings: (params = {}) => _get("/threat-hunting/findings", params),

  /** Aggregate hunt summary: rules_total, findings_open, findings_critical_high, etc. */
  getThreatHuntSummary: () => _get("/threat-hunting/summary"),

  /** Trigger an on-demand threat hunt run. Admin role required. */
  runThreatHunt: () => _post("/threat-hunting/run", {}),

  /** Request CyMind AI analysis of current hunt findings. */
  analyzeThreatHunt: () => _post("/threat-hunting/analyze", {}),
};

/**
 * Helper: safely parse a JSON response and return the data,
 * or return { error } if the response was not OK or the engine is offline.
 */
export async function siemFetch(responseProm) {
  try {
    const r = await responseProm;
    if (r.status === 503) {
      // Distinguish: Flask engine-offline response vs engine app-level service error
      const body = await r.json().catch(() => ({}));
      if (body.error === "engine_unavailable") return { _offline: true };
      return { _error: body.error || body.detail || body.message || "Service unavailable" };
    }
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      // body.error = Flask errors; body.detail = FastAPI HTTPException errors
      return { _error: body.error || body.detail || `HTTP ${r.status}` };
    }
    return await r.json();
  } catch (e) {
    return { _offline: true };
  }
}
