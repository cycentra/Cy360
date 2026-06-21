/**
 * SiemIncidentsPage.jsx
 * Correlated incident list from the CySIEM Correlation Engine.
 * Connects to WebSocket for real-time updates, polls every 30s as fallback.
 */

import { useState, useEffect, useRef, useCallback } from "react";
import { siemApi, siemFetch } from "./siemApi";
import { SiemEngineStatus } from "./SiemEngineStatus";
import { RISK_CONFIG, STATUS_CONFIG, STATUS_TRANSITIONS } from "../core/constants";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// ── Severity badge ─────────────────────────────────────────────────────────────
function SevBadge({ severity }) {
  const cfg = RISK_CONFIG[severity] || RISK_CONFIG.low;
  return (
    <span style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40`,
      fontSize: 10, fontWeight: 700, letterSpacing: "1.5px", fontFamily: "monospace",
      padding: "2px 8px", borderRadius: 2 }}>
      {cfg.label}
    </span>
  );
}

// ── Status badge ───────────────────────────────────────────────────────────────
function StatBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || { color: "#888", label: status?.toUpperCase() || "?" };
  return (
    <span style={{ color: cfg.color, fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
      {cfg.label}
    </span>
  );
}

// ── Live indicator ─────────────────────────────────────────────────────────────
function LiveDot({ connected }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5,
      color: connected ? "#00e5a0" : "rgba(255,255,255,0.25)", fontSize: 10,
      fontFamily: "monospace" }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%",
        background: connected ? "#00e5a0" : "rgba(255,255,255,0.2)",
        animation: connected ? "pulse 2s infinite" : "none", display: "inline-block" }} />
      {connected ? "LIVE" : "POLLING"}
    </span>
  );
}

// ── Helpers ─────────────────────────────────────────────────────────────────
function fmtTs(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" })
    + " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function SectionLabel({ children }) {
  return (
    <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace",
      letterSpacing: "1px", marginBottom: 6, marginTop: 18 }}>{children}</div>
  );
}

const KILL_CHAIN_NAMES = [
  "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
  "Installation", "Command & Control", "Actions on Objectives",
];

const CAT_COLORS = {
  authentication: "#ff8c00", brute_force: "#ff3b3b", malware: "#ff3b3b",
  fim: "#f5c518", web: "#4d9eff", scan: "#b36bff", vulnerability: "#ff8c00",
  system: "rgba(255,255,255,0.4)",
  // Cloud integration sources (specific and legacy generic)
  cloud: "#4d9eff", o365: "#4d9eff", azure: "#4d9eff",
  aws: "#ff8c00", gcp: "#f5c518", github: "#b36bff",
};

// Known cloud-source category keys → human-readable label
const CLOUD_CATEGORIES = {
  o365:   "Microsoft 365",
  azure:  "Microsoft Azure",
  aws:    "AWS",
  gcp:    "Google Cloud",
  github: "GitHub",
  cloud:  "Cloud",   // legacy fallback for incidents ingested before this fix
};

// Return the cloud service label if any category is a cloud source, else null.
// Specific sources (o365, azure, aws, gcp, github) are checked before the
// generic 'cloud' fallback so that incidents whose categories array contains
// both a legacy 'cloud' entry and a specific 'o365' entry (written by newer
// normaliser code) resolve to the specific name rather than the generic label.
const _SPECIFIC_CLOUD_SOURCES = ['o365', 'azure', 'aws', 'gcp', 'github'];
function getCloudSource(categories) {
  const cats = categories || [];
  for (const s of _SPECIFIC_CLOUD_SOURCES) {
    if (cats.includes(s)) return CLOUD_CATEGORIES[s];
  }
  if (cats.includes('cloud')) return CLOUD_CATEGORIES.cloud;
  return null;
}

// ── Incident drawer ────────────────────────────────────────────────────────────
function IncidentDrawer({ incident: initialIncident, onClose, onPatched, onOpenCase }) {
  const [inc, setInc]           = useState(initialIncident);
  const [loadingDetail, setLoadingDetail] = useState(true);
  const [notes, setNotes]       = useState(initialIncident.notes || "");
  const [assignee, setAssignee] = useState(initialIncident.assigned_to || "");
  const [saving, setSaving]     = useState(false);
  const [saved, setSaved]       = useState(false);
  const [alertsExpanded, setAlertsExpanded] = useState(false);
  const [raising, setRaising]   = useState(false);
  const [raiseErr, setRaiseErr] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [deleteErr, setDeleteErr] = useState("");
  // Analyst list for assignment dropdown
  const [analysts, setAnalysts] = useState([]);
  // Transition modal state
  const [showTransition, setShowTransition] = useState(false);
  const [transitionTo, setTransitionTo]     = useState("");
  const [transitionComment, setTransitionComment] = useState("");
  const [transitioning, setTransitioning]   = useState(false);
  const [transitionErr, setTransitionErr]   = useState("");
  // Audit trail
  const [auditLog, setAuditLog] = useState([]);
  const [auditVisible, setAuditVisible] = useState(false);
  const [auditLoading, setAuditLoading] = useState(false);
  const [wazuhLaunching, setWazuhLaunching] = useState(false);
  const [requestingAi, setRequestingAi]     = useState(false);
  const [aiRequestErr, setAiRequestErr]     = useState("");

  // Fetch full incident detail + analyst list on mount
  useEffect(() => {
    fetch("/api/cases/assignable-users", { credentials: "include" })
      .then(r => r.ok ? r.json() : [])
      .then(d => setAnalysts(Array.isArray(d) ? d : []))
      .catch(() => {});
  }, []);

  // Preserve case_opened_at if DB hasn't propagated it yet.
  useEffect(() => {
    (async () => {
      const data = await siemFetch(siemApi.getIncident(initialIncident.id));
      if (!data._error && !data._offline) {
        setInc(prev => ({
          ...data,
          case_opened_at: data.case_opened_at || prev.case_opened_at,
        }));
        setNotes(data.notes || "");
        setAssignee(data.assigned_to || "");
      }
      setLoadingDetail(false);
    })();
  }, [initialIncident.id]);

  const fetchAudit = async () => {
    setAuditLoading(true);
    const data = await siemFetch(siemApi.getAuditLog(inc.id));
    setAuditLoading(false);
    if (!data._error && !data._offline) setAuditLog(Array.isArray(data) ? data : []);
  };

  const toggleAudit = () => {
    if (!auditVisible && auditLog.length === 0) fetchAudit();
    setAuditVisible(v => !v);
  };

  // Open the transition modal for a target status
  const openTransition = (toStatus) => {
    setTransitionTo(toStatus);
    setTransitionComment("");
    setTransitionErr("");
    setShowTransition(true);
  };

  const confirmTransition = async () => {
    if (!transitionComment.trim()) {
      setTransitionErr("Audit comment is required.");
      return;
    }
    setTransitioning(true);
    setTransitionErr("");
    const data = await siemFetch(
      siemApi.transitionIncident(inc.id, { to_status: transitionTo, comment: transitionComment.trim() })
    );
    setTransitioning(false);
    if (data._error || data._offline) {
      setTransitionErr(data._error || "Request failed — engine may be offline.");
      return;
    }
    setInc(data);
    setShowTransition(false);
    onPatched?.(data);
    // Refresh audit log
    fetchAudit();
    setAuditVisible(true);
  };

  const handleSave = async () => {
    setSaving(true);
    const data = await siemFetch(
      siemApi.patchIncident(inc.id, { notes, assigned_to: assignee })
    );
    setSaving(false);
    if (!data._error && !data._offline) {
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
      const updated = { ...inc, notes, assigned_to: assignee };
      setInc(updated);
      onPatched?.(updated);
    }
  };

  const handleRequestAi = async () => {
    setRequestingAi(true);
    setAiRequestErr("");
    const data = await siemFetch(siemApi.requestAiAnalysis(inc.id));
    setRequestingAi(false);
    if (data._offline) { setAiRequestErr("Engine offline — try again shortly."); return; }
    if (data._error)   { setAiRequestErr(data._error); return; }
    setInc(prev => ({
      ...prev,
      llm_summary:      data.llm_summary,
      llm_remediation:  data.llm_remediation,
      llm_generated_at: data.llm_generated_at,
    }));
  };

  const handleDeleteCase = async () => {
    if (!window.confirm("Remove this case? The incident is kept but the case investigation record will be cleared.")) return;
    setDeleting(true);
    setDeleteErr("");
    try {
      const res = await fetch(`/api/cases/${inc.id}`, { method: "DELETE", credentials: "include" });
      const data = await res.json().catch(() => ({}));
      setDeleting(false);
      if (!res.ok) { setDeleteErr(data.error || `HTTP ${res.status}`); return; }
      const updated = { ...inc, case_opened_at: null, case_type: "generic",
                        case_mttd_seconds: null, case_mtta_seconds: null };
      setInc(updated);
      onPatched?.(updated);
    } catch {
      setDeleting(false);
      setDeleteErr("Network error — try again.");
    }
  };

  const handleRaise = async () => {
    setRaising(true);
    setRaiseErr("");
    try {
      const res = await fetch("/api/cases", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ incident_id: inc.id }),
      });
      const data = await res.json().catch(() => ({}));
      setRaising(false);
      if (!res.ok) { setRaiseErr(data.error || `HTTP ${res.status}`); return; }
      // Guarantee case_opened_at is set immediately — don't depend on re-fetch timing.
      // Use the value from the POST response; fall back to current time.
      const caseOpenedAt = data.case_opened_at || new Date().toISOString();
      // Re-fetch for other fresh fields but always keep the authoritative case_opened_at.
      const freshRes = await siemFetch(siemApi.getIncident(inc.id)).catch(() => null);
      const updated = {
        ...inc,
        ...(freshRes && !freshRes._error && !freshRes._offline ? freshRes : {}),
        case_opened_at: caseOpenedAt,
      };
      setInc(updated);
      onPatched?.(updated);
    } catch {
      setRaising(false);
      setRaiseErr("Network error — try again shortly.");
    }
  };

  const handleWazuhLaunch = async () => {
    setWazuhLaunching(true);
    try {
      const res = await fetch("/api/siem/wazuh-launch", { credentials: "include" });
      if (res.redirected) {
        window.open(res.url, "_blank", "noopener,noreferrer");
        return;
      }
      const data = await res.json();
      if (data.token) {
        sessionStorage.setItem("wazuh_auth_token", data.token);
      }
      window.open(data.launch_url || wazuhUrl, "_blank", "noopener,noreferrer");
    } catch {
      window.open(wazuhUrl, "_blank", "noopener,noreferrer");
    } finally {
      setWazuhLaunching(false);
    }
  };

  // Derive Wazuh Dashboard URL from current hostname (fallback only)
  const host = window.location.hostname;
  const wazuhHost = host.startsWith("cy360.")
    ? host.replace("cy360.", "cysiem.")
    : `${host}:5601`;
  const wazuhUrl = `https://${wazuhHost}/app/wazuh`;

  const misp       = inc.misp_enrichment || {};
  const corrRules  = inc.correlated_rules || [];
  const uebaFlags  = inc.ueba_flags || [];
  const alerts     = inc.alerts || [];
  const categories = inc.categories || [];
  const srcIps     = inc.src_ips || [];
  const users      = inc.affected_users || [];
  const agents     = inc.affected_agents || [];
  const killStage  = inc.kill_chain_stage;

  return (
    <div style={{ position: "fixed", top: 0, right: 0, width: "min(640px, 96vw)", height: "100vh",
      background: "#0d1117", borderLeft: "1px solid rgba(255,255,255,0.08)", zIndex: 200,
      display: "flex", flexDirection: "column", overflowY: "auto" }}>

      {/* Header */}
      <div style={{ padding: "18px 24px", borderBottom: "1px solid rgba(255,255,255,0.07)",
        display: "flex", justifyContent: "space-between", alignItems: "flex-start",
        position: "sticky", top: 0, background: "#0d1117", zIndex: 10 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <span style={{ color: "#4d9eff", fontSize: 12, fontFamily: "monospace", fontWeight: 700 }}>
              {inc.id}
            </span>
            <SevBadge severity={inc.severity} />
            <StatBadge status={inc.status} />
            {categories.slice(0, 2).map(cat => (
              <span key={cat} style={{ background: "rgba(255,255,255,0.06)",
                color: CAT_COLORS[cat] || "rgba(255,255,255,0.5)",
                fontSize: 10, fontFamily: "monospace", padding: "2px 8px",
                borderRadius: 2, textTransform: "uppercase" }}>{cat.replace(/_/g, " ")}</span>
            ))}
            {killStage > 0 && (
              <span style={{ background: "rgba(179,107,255,0.1)", color: "#b36bff",
                fontSize: 10, fontFamily: "monospace", padding: "2px 8px", borderRadius: 2 }}>
                KC-{killStage} {KILL_CHAIN_NAMES[killStage - 1] || ""}
              </span>
            )}
          </div>
          <div style={{ display: "flex", gap: 16, marginTop: 6, flexWrap: "wrap" }}>
            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 11 }}>
              First seen: <span style={{ color: "rgba(255,255,255,0.6)" }}>{fmtTs(inc.first_seen)}</span>
            </span>
            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 11 }}>
              Last seen: <span style={{ color: "rgba(255,255,255,0.6)" }}>{fmtTs(inc.last_seen)}</span>
            </span>
            {inc.risk_score > 0 && (
              <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 11 }}>
                Risk: <span style={{ color: inc.risk_score >= 8 ? "#ff3b3b" : inc.risk_score >= 5 ? "#ff8c00" : "#f5c518",
                  fontWeight: 700 }}>{inc.risk_score?.toFixed(1)}</span>
              </span>
            )}
            {inc.fp_probability != null && (() => {
              const fp = inc.fp_probability;
              const fpLabel = fp >= 90 ? "Very likely false positive"
                            : fp >= 70 ? "Probably noise"
                            : fp >= 40 ? "Uncertain — review recommended"
                            : fp >= 20 ? "Likely real threat"
                            :            "High confidence — real threat";
              const fpColor = fp >= 70 ? "#ff8c00"
                            : fp >= 40 ? "#f5c518"
                            :            "#ff3b3b";
              return (
                <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 11 }}
                  title="Multi-factor FP probability: rule confidence + UEBA anomalies + MISP IOC hits + kill-chain stage + asset criticality.">
                  FP: <span style={{ color: fpColor, fontWeight: 700 }}>{fp.toFixed(0)}%</span>
                  <span style={{ color: fpColor, fontSize: 10, marginLeft: 4 }}>— {fpLabel}</span>
                </span>
              );
            })()}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0, marginLeft: 12 }}>
          <button
            onClick={handleWazuhLaunch}
            disabled={wazuhLaunching}
            title="Opens Wazuh dashboard with your CyCentra session (SSO)"
            style={{ background: wazuhLaunching ? "rgba(77,158,255,0.05)" : "rgba(77,158,255,0.1)",
              border: "1px solid rgba(77,158,255,0.3)",
              color: "#4d9eff", padding: "6px 12px", borderRadius: 4,
              cursor: wazuhLaunching ? "wait" : "pointer",
              fontSize: 11, fontFamily: "monospace", whiteSpace: "nowrap" }}>
            {wazuhLaunching ? "Launching…" : "↗ Investigate in CySIEM Dashboard"}
          </button>
          <button onClick={onClose}
            style={{ background: "none", border: "none", color: "rgba(255,255,255,0.65)",
              cursor: "pointer", fontSize: 20, padding: 4, flexShrink: 0 }}>✕</button>
        </div>
      </div>

      <div style={{ padding: "18px 24px", flex: 1 }}>

        {loadingDetail && (
          <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 12, fontFamily: "monospace",
            marginBottom: 16 }}>Loading full incident detail…</div>
        )}

        {/* Stats row */}
        <div style={{ display: "flex", gap: 10, marginBottom: 4, flexWrap: "wrap" }}>
          {[
            { label: "Alerts",   value: inc.alert_count },
            { label: "Agents",   value: agents.length },
            { label: "Users",    value: users.length },
            { label: "Src IPs",  value: srcIps.length },
          ].map(s => (
            <div key={s.label} style={{ background: "rgba(255,255,255,0.03)",
              border: "1px solid rgba(255,255,255,0.07)", borderRadius: 4, padding: "10px 14px" }}>
              <div style={{ color: "#00e5a0", fontSize: 20, fontWeight: 700, fontFamily: "monospace" }}>{s.value}</div>
              <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 10, fontFamily: "monospace" }}>{s.label}</div>
            </div>
          ))}
        </div>

        {/* Agents / Cloud collector */}
        {agents.length > 0 && (() => {
          const cloudSource = getCloudSource(categories);
          return (
            <>
              <SectionLabel>{cloudSource ? `CLOUD COLLECTOR AGENT (☁ ${cloudSource})` : "AFFECTED HOSTS"}</SectionLabel>
              {cloudSource && (
                <div style={{ color: "rgba(77,158,255,0.8)", fontSize: 11, fontFamily: "monospace",
                  marginBottom: 8, padding: "7px 10px",
                  background: "rgba(77,158,255,0.06)", border: "1px solid rgba(77,158,255,0.18)",
                  borderRadius: 3, lineHeight: 1.5 }}>
                  ☁ <strong>{cloudSource}</strong> event — this is the Wazuh agent that <em>collected</em> the
                  event, not the victim host. Check <strong>Affected Users</strong> for the actual identity.
                </div>
              )}
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {agents.map(a => (
                  <span key={a} style={{ background: "rgba(255,255,255,0.05)",
                    color: "rgba(255,255,255,0.7)", fontSize: 11, fontFamily: "monospace",
                    padding: "3px 10px", borderRadius: 2, border: "1px solid rgba(255,255,255,0.1)" }}>{a}</span>
                ))}
              </div>
            </>
          );
        })()}

        {/* Source IPs */}
        {srcIps.length > 0 && (
          <>
            <SectionLabel>SOURCE IPs ({srcIps.length})</SectionLabel>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {srcIps.map(ip => (
                <span key={ip} style={{ background: "rgba(255,59,59,0.07)",
                  color: "#ff8c00", fontSize: 11, fontFamily: "monospace",
                  padding: "3px 10px", borderRadius: 2, border: "1px solid rgba(255,140,0,0.25)" }}>{ip}</span>
              ))}
            </div>
          </>
        )}

        {/* Users */}
        {users.length > 0 && (
          <>
            <SectionLabel>AFFECTED USERS ({users.length})</SectionLabel>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {users.map(u => (
                <span key={u} style={{ background: "rgba(245,197,24,0.07)",
                  color: "#f5c518", fontSize: 11, fontFamily: "monospace",
                  padding: "3px 10px", borderRadius: 2, border: "1px solid rgba(245,197,24,0.2)" }}>{u}</span>
              ))}
            </div>
          </>
        )}

        {/* MITRE ATT&CK */}
        {(inc.mitre_ids || []).length > 0 && (
          <>
            <SectionLabel>MITRE ATT&CK</SectionLabel>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {(inc.mitre_ids || []).map((id, idx) => {
                const tactic = (inc.mitre_tactics || [])[idx];
                return (
                  <a key={id} href={`https://attack.mitre.org/techniques/${id.replace(".", "/")}`}
                    target="_blank" rel="noopener noreferrer"
                    style={{ background: "rgba(77,158,255,0.08)", color: "#4d9eff",
                      border: "1px solid rgba(77,158,255,0.25)", fontSize: 10,
                      fontFamily: "monospace", padding: "3px 10px", borderRadius: 2,
                      textDecoration: "none", display: "inline-flex", flexDirection: "column", gap: 1 }}>
                    <span style={{ fontWeight: 700 }}>{id}</span>
                    {tactic && <span style={{ color: "rgba(77,158,255,0.6)", fontSize: 9 }}>{tactic}</span>}
                  </a>
                );
              })}
            </div>
          </>
        )}

        {/* Correlation rules */}
        {corrRules.length > 0 && (
          <>
            <SectionLabel>CORRELATION RULES TRIGGERED</SectionLabel>
            {corrRules.map((r, i) => (
              <div key={i} style={{ display: "flex", gap: 8, marginBottom: 4, alignItems: "flex-start" }}>
                <span style={{ color: "#f5c518", fontSize: 10, fontFamily: "monospace",
                  flexShrink: 0, marginTop: 2 }}>[{r.rule_id}]</span>
                <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 12 }}>{r.name || r.description}</span>
              </div>
            ))}
          </>
        )}

        {/* UEBA flags */}
        {uebaFlags.length > 0 && (
          <>
            <SectionLabel>UEBA FLAGS</SectionLabel>
            {uebaFlags.map((f, i) => (
              <div key={i} style={{ display: "flex", gap: 8, marginBottom: 4, alignItems: "center" }}>
                <span style={{ color: "#ff8c00", fontSize: 10 }}>⚡</span>
                <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 12 }}>{f}</span>
              </div>
            ))}
          </>
        )}

        {/* MISP hits */}
        {(misp.ioc_hits || []).length > 0 && (
          <>
            <SectionLabel>🔴 THREAT INTEL MATCHES (MISP)</SectionLabel>
            <div style={{ background: "rgba(255,59,59,0.05)", border: "1px solid rgba(255,59,59,0.2)",
              borderRadius: 4, padding: "12px 14px" }}>
              {(misp.ioc_hits || []).map((hit, i) => (
                <div key={i} style={{ color: "rgba(255,255,255,0.6)", fontSize: 12, marginBottom: 4 }}>
                  <span style={{ color: "#ff3b3b", fontFamily: "monospace" }}>{hit.ioc}</span>
                  {" — "}{hit.threat_level} threat · MISP events: {(hit.events || []).join(", ")}
                </div>
              ))}
            </div>
          </>
        )}

        {/* Unified TI reputation panel (Phase 1) */}
        {inc.ti_reputation && (
          <>
            <SectionLabel>🌐 THREAT INTELLIGENCE REPUTATION</SectionLabel>
            {(() => {
              const ti = inc.ti_reputation;
              const verdictColor = {
                malicious:  "#ff3b3b",
                suspicious: "#f5c518",
                benign:     "#00e5a0",
                unknown:    "#888",
              }[ti.verdict] || "#888";
              return (
                <div style={{ background: "rgba(255,255,255,0.02)", border: `1px solid ${verdictColor}33`,
                  borderRadius: 4, padding: "12px 14px" }}>
                  {/* Verdict row */}
                  <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
                    <span style={{
                      background: `${verdictColor}18`, border: `1px solid ${verdictColor}44`,
                      color: verdictColor, fontSize: 11, fontWeight: 700, padding: "3px 10px",
                      borderRadius: 12, fontFamily: "monospace", letterSpacing: "0.06em",
                    }}>
                      {(ti.verdict || "unknown").toUpperCase()}
                    </span>
                    {/* Confidence bar */}
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 10, color: "rgba(255,255,255,0.35)", marginBottom: 3 }}>
                        TI Confidence: {ti.confidence ?? 0}%
                      </div>
                      <div style={{ height: 4, background: "rgba(255,255,255,0.08)", borderRadius: 2, overflow: "hidden" }}>
                        <div style={{ height: "100%", width: `${ti.confidence ?? 0}%`,
                          background: verdictColor, borderRadius: 2, transition: "width 0.4s" }} />
                      </div>
                    </div>
                  </div>
                  {/* Sources used */}
                  {(ti.sources_used || []).length > 0 && (
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
                      {ti.sources_used.map(s => (
                        <span key={s} style={{ fontSize: 10, padding: "2px 8px", borderRadius: 10,
                          background: "rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.5)",
                          fontFamily: "monospace" }}>
                          {s}
                        </span>
                      ))}
                    </div>
                  )}
                  {/* IOC hits from external sources */}
                  {(ti.ioc_hits || []).length > 0 && (
                    <div style={{ marginTop: 6 }}>
                      <div style={{ fontSize: 10, color: "rgba(255,255,255,0.35)", marginBottom: 4,
                        textTransform: "uppercase", letterSpacing: "0.5px" }}>
                        External IOC Matches
                      </div>
                      {ti.ioc_hits.map((hit, i) => (
                        <div key={i} style={{ display: "flex", alignItems: "center", gap: 8,
                          marginBottom: 4, fontSize: 12 }}>
                          <span style={{ fontFamily: "monospace", color: "rgba(255,255,255,0.75)" }}>
                            {hit.ioc}
                          </span>
                          <span style={{ fontSize: 10, color: "rgba(255,255,255,0.35)" }}>
                            [{hit.type}]
                          </span>
                          <span style={{ fontSize: 10, fontWeight: 700,
                            color: { malicious: "#ff3b3b", suspicious: "#f5c518", benign: "#00e5a0", unknown: "#888" }[hit.verdict] || "#888" }}>
                            {(hit.verdict || "unknown").toUpperCase()}
                          </span>
                          {(hit.sources || []).map(s => (
                            <span key={s.source} style={{ fontSize: 9, padding: "1px 5px", borderRadius: 6,
                              background: "rgba(255,255,255,0.05)", color: "rgba(255,255,255,0.4)",
                              fontFamily: "monospace" }}>
                              {s.source}
                            </span>
                          ))}
                        </div>
                      ))}
                    </div>
                  )}
                  {ti.checked_at && (
                    <div style={{ fontSize: 10, color: "rgba(255,255,255,0.2)", marginTop: 8 }}>
                      Checked: {new Date(ti.checked_at).toLocaleString()}
                    </div>
                  )}
                </div>
              );
            })()}
          </>
        )}

        {/* Case management */}
        {inc.case_opened_at ? (
          <>
            <SectionLabel>🗂️ CASE MANAGEMENT</SectionLabel>
            <div style={{
              background: inc.status === "closed" ? "rgba(0,229,160,0.04)" : "rgba(77,158,255,0.04)",
              border: `1px solid ${inc.status === "closed" ? "rgba(0,229,160,0.2)" : "rgba(77,158,255,0.2)"}`,
              borderRadius: 4, padding: "14px 16px",
            }}>
              <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                    <span style={{
                      background: inc.status === "closed" ? "rgba(0,229,160,0.15)" : "rgba(77,158,255,0.15)",
                      color: inc.status === "closed" ? "#00e5a0" : "#4d9eff",
                      border: `1px solid ${inc.status === "closed" ? "rgba(0,229,160,0.4)" : "rgba(77,158,255,0.4)"}`,
                      fontSize: 10, fontFamily: "monospace", fontWeight: 700, padding: "2px 8px", borderRadius: 2,
                      letterSpacing: "0.5px",
                    }}>
                      {inc.status === "closed" ? "✓ CLOSED" : "● OPEN"}
                    </span>
                    <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, fontFamily: "monospace" }}>
                      {inc.status?.toUpperCase()}
                    </span>
                  </div>
                  <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 11 }}>
                    Case opened for this incident and assigned to an analyst for investigation.
                  </div>
                  {deleteErr && (
                    <div style={{ color: "#ff6464", fontSize: 11, fontFamily: "monospace", marginTop: 6 }}>
                      ✗ {deleteErr}
                    </div>
                  )}
                </div>
                <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
                  <button
                    onClick={() => onOpenCase ? onOpenCase(inc.id) : null}
                    style={{
                      background: "rgba(77,158,255,0.1)", border: "1px solid rgba(77,158,255,0.3)",
                      color: "#4d9eff", padding: "6px 12px", borderRadius: 4, fontSize: 11,
                      fontFamily: "monospace", cursor: onOpenCase ? "pointer" : "default",
                      fontWeight: 700, whiteSpace: "nowrap",
                    }}>
                    View Case →
                  </button>
                  <button
                    onClick={handleDeleteCase}
                    disabled={deleting}
                    style={{
                      background: "rgba(255,59,59,0.07)", border: "1px solid rgba(255,59,59,0.25)",
                      color: "#ff6464", padding: "6px 12px", borderRadius: 4, fontSize: 11,
                      fontFamily: "monospace", fontWeight: 700, whiteSpace: "nowrap",
                      cursor: deleting ? "wait" : "pointer",
                    }}>
                    {deleting ? "Removing…" : "✕ Remove Case"}
                  </button>
                </div>
              </div>
            </div>
          </>
        ) : (
          <>
            <SectionLabel>🗂️ CASE MANAGEMENT</SectionLabel>
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
              borderRadius: 4, padding: "14px 16px", display: "flex",
              alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
              <div>
                <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, marginBottom: 4 }}>
                  No case opened automatically for this incident.
                </div>
                <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace" }}>
                  Open a case to assign this incident for analyst investigation.
                </div>
                {raiseErr && (
                  <div style={{ color: "#ff6464", fontSize: 11, fontFamily: "monospace", marginTop: 6 }}>
                    ✗ {raiseErr}
                  </div>
                )}
              </div>
              <button
                onClick={handleRaise}
                disabled={raising}
                style={{
                  background: raising ? "rgba(77,158,255,0.05)" : "rgba(77,158,255,0.1)",
                  border: "1px solid rgba(77,158,255,0.35)",
                  color: "#4d9eff", padding: "8px 16px", borderRadius: 4, cursor: raising ? "wait" : "pointer",
                  fontSize: 12, fontFamily: "monospace", fontWeight: 700, whiteSpace: "nowrap", flexShrink: 0,
                }}>
                {raising ? "Opening case…" : "🗂️ Open Case"}
              </button>
            </div>
          </>
        )}

        {/* LLM narrative — show analysis or request button */}
        <SectionLabel>🤖 AI ANALYSIS</SectionLabel>
        {inc.llm_summary ? (
          <div style={{ background: "rgba(0,229,160,0.03)", border: "1px solid rgba(0,229,160,0.2)",
            borderRadius: 4, padding: "14px 16px" }}>
            {inc.llm_generated_at && (
              <div style={{ color: "rgba(0,229,160,0.45)", fontSize: 10, fontFamily: "monospace",
                marginBottom: 10 }}>
                Generated {fmtTs(inc.llm_generated_at)}
              </div>
            )}
            <div style={{ color: "rgba(255,255,255,0.75)", fontSize: 13, lineHeight: 1.8, whiteSpace: "pre-wrap" }}>
              {inc.llm_summary}
            </div>
            {inc.llm_remediation && (
              <div style={{ marginTop: 14, borderTop: "1px solid rgba(0,229,160,0.12)", paddingTop: 12 }}>
                <div style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace",
                  fontWeight: 700, letterSpacing: "1px", marginBottom: 8 }}>REMEDIATION STEPS</div>
                {inc.llm_remediation.split(/\n/).filter(l => l.trim()).map((line, i) => {
                  const isStep = /^\d+[\.\)]/.test(line.trim());
                  return (
                    <div key={i} style={{ display: "flex", gap: 10, marginBottom: 6, alignItems: "flex-start" }}>
                      {isStep && (
                        <span style={{ background: "rgba(0,229,160,0.15)", color: "#00e5a0",
                          fontSize: 10, fontFamily: "monospace", fontWeight: 700,
                          padding: "2px 7px", borderRadius: 2, flexShrink: 0, marginTop: 1 }}>
                          {line.trim().match(/^(\d+)/)[1]}
                        </span>
                      )}
                      <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 12, lineHeight: 1.7 }}>
                        {isStep ? line.trim().replace(/^\d+[\.\)]\s*/, "") : line}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        ) : (
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 4, padding: "14px 16px", display: "flex",
            alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
            <div>
              <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, marginBottom: 4 }}>
                No AI analysis available for this incident.
              </div>
              <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, fontFamily: "monospace" }}>
                AI analysis runs automatically for critical/high incidents with 3+ alerts.
                Click to request it now for any incident.
              </div>
              {aiRequestErr && (
                <div style={{ color: "#ff6464", fontSize: 11, fontFamily: "monospace", marginTop: 6 }}>
                  ✗ {aiRequestErr}
                </div>
              )}
            </div>
            <button
              onClick={handleRequestAi}
              disabled={requestingAi || ["false_positive", "closed"].includes(inc.status)}
              style={{
                background: requestingAi ? "rgba(0,229,160,0.04)" : "rgba(0,229,160,0.08)",
                border: "1px solid rgba(0,229,160,0.3)",
                color: "#00e5a0", padding: "8px 16px", borderRadius: 4,
                cursor: requestingAi ? "wait" : "pointer",
                fontSize: 12, fontFamily: "monospace", fontWeight: 700, whiteSpace: "nowrap", flexShrink: 0,
                opacity: ["false_positive", "closed"].includes(inc.status) ? 0.4 : 1,
              }}>
              {requestingAi ? "Analysing…" : "🤖 Request AI Analysis"}
            </button>
          </div>
        )}

        {/* Alerts table */}
        {alerts.length > 0 && (
          <>
            <SectionLabel>
              ALERTS ({alerts.length}{inc.alert_count > alerts.length ? ` of ${inc.alert_count}` : ""})
              <button onClick={() => setAlertsExpanded(v => !v)}
                style={{ background: "none", border: "none", color: "#4d9eff",
                  cursor: "pointer", fontSize: 10, fontFamily: "monospace",
                  marginLeft: 12, padding: 0 }}>
                {alertsExpanded ? "▲ collapse" : "▼ expand"}
              </button>
            </SectionLabel>
            {alertsExpanded && (
              <div style={{ overflowX: "auto", borderRadius: 4,
                border: "1px solid rgba(255,255,255,0.07)" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11,
                  fontFamily: "monospace" }}>
                  <thead>
                    <tr style={{ background: "rgba(255,255,255,0.04)" }}>
                      {["Time", "Rule ID", "Level", "Description", "Src IP", "User"].map(h => (
                        <th key={h} style={{ padding: "7px 10px", textAlign: "left",
                          color: "rgba(255,255,255,0.3)", fontWeight: 600,
                          borderBottom: "1px solid rgba(255,255,255,0.07)", whiteSpace: "nowrap" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.map((a, i) => {
                      const lvlColor = a.rule_level >= 12 ? "#ff3b3b" : a.rule_level >= 8 ? "#ff8c00" : "#f5c518";
                      return (
                        <tr key={a.id || i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}
                          onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.025)"}
                          onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                          <td style={{ padding: "6px 10px", color: "rgba(255,255,255,0.62)", whiteSpace: "nowrap" }}>
                            {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : "—"}
                          </td>
                          <td style={{ padding: "6px 10px", color: "#4d9eff" }}>{a.rule_id}</td>
                          <td style={{ padding: "6px 10px", color: lvlColor, fontWeight: 700 }}>{a.rule_level}</td>
                          <td style={{ padding: "6px 10px", color: "rgba(255,255,255,0.65)",
                            maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {a.rule_desc || "—"}
                          </td>
                          <td style={{ padding: "6px 10px", color: "#ff8c00" }}>{a.src_ip || "—"}</td>
                          <td style={{ padding: "6px 10px", color: "#f5c518" }}>{a.username || "—"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            {!alertsExpanded && (
              <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace",
                padding: "8px 0" }}>
                Click ▼ expand to view individual alerts
              </div>
            )}
          </>
        )}

        {/* Status transitions */}
        <SectionLabel>STATUS TRANSITION</SectionLabel>
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 4, padding: "16px 18px", marginBottom: 8 }}>
          <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 11, fontFamily: "monospace", marginBottom: 10 }}>
            Current: <StatBadge status={inc.status} />
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {(STATUS_TRANSITIONS[inc.status] || []).map(st => {
              const cfg = STATUS_CONFIG[st] || { color: "#888", label: st.toUpperCase() };
              return (
                <button key={st} onClick={() => openTransition(st)}
                  style={{ background: `${cfg.color}12`, border: `1px solid ${cfg.color}40`,
                    color: cfg.color, padding: "5px 12px", borderRadius: 3,
                    cursor: "pointer", fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>
                  → {cfg.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Audit trail toggle */}
        <button onClick={toggleAudit}
          style={{ background: "none", border: "none", color: "#4d9eff", fontSize: 11,
            fontFamily: "monospace", cursor: "pointer", padding: "6px 0", marginBottom: 8 }}>
          {auditVisible ? "▲ Hide Audit Trail" : "▼ Show Audit Trail"}
          {auditLog.length > 0 && ` (${auditLog.length})`}
        </button>
        {auditVisible && (
          <div style={{ marginBottom: 18, border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 4, overflow: "hidden" }}>
            {auditLoading && <div style={{ padding: "12px 16px", color: "rgba(255,255,255,0.3)",
              fontSize: 11, fontFamily: "monospace" }}>Loading…</div>}
            {!auditLoading && auditLog.length === 0 && (
              <div style={{ padding: "12px 16px", color: "rgba(255,255,255,0.2)",
                fontSize: 11, fontFamily: "monospace" }}>No audit entries yet.</div>
            )}
            {auditLog.map((entry, i) => {
              const isSystem = entry.actor === "system";
              const actionColor = {
                status_change: "#f5c518", case_auto_opened: "#4d9eff",
                soar_triggered: "#b36bff", auto_fp: "#888", comment: "#00e5a0",
              }[entry.action] || "#888";
              return (
                <div key={i} style={{ padding: "10px 16px",
                  borderBottom: i < auditLog.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none",
                  display: "flex", gap: 12, alignItems: "flex-start" }}>
                  <div style={{ width: 8, height: 8, borderRadius: "50%",
                    background: actionColor, flexShrink: 0, marginTop: 4 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap",
                      marginBottom: 3 }}>
                      <span style={{ color: actionColor, fontSize: 10, fontFamily: "monospace",
                        fontWeight: 700, textTransform: "uppercase" }}>{entry.action?.replace("_", " ")}</span>
                      {entry.from_status && entry.to_status && (
                        <span style={{ color: "rgba(255,255,255,0.62)", fontSize: 10, fontFamily: "monospace" }}>
                          {entry.from_status} → {entry.to_status}
                        </span>
                      )}
                      <span style={{ color: isSystem ? "rgba(255,255,255,0.3)" : "#00e5a0",
                        fontSize: 10, fontFamily: "monospace" }}>
                        {isSystem ? "⚙ system" : `👤 ${entry.actor}`}
                      </span>
                      <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, marginLeft: "auto" }}>
                        {entry.created_at ? new Date(entry.created_at).toLocaleString() : ""}
                      </span>
                    </div>
                    {entry.comment && (
                      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace" }}>
                        {entry.comment}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Notes / Assignee (no status change here) */}
        <SectionLabel>NOTES & ASSIGNMENT</SectionLabel>
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 4, padding: "16px 18px" }}>
          <div style={{ marginBottom: 10 }}>
            <label style={{ color: "rgba(255,255,255,0.65)", fontSize: 11, fontFamily: "monospace" }}>
              Assign To Analyst
            </label>
            {analysts.length > 0 ? (
              <select
                value={assignee}
                onChange={e => setAssignee(e.target.value)}
                style={{ width: "100%", background: "rgba(255,255,255,0.05)",
                  border: "1px solid rgba(255,255,255,0.12)", color: "white",
                  padding: "8px 10px", borderRadius: 4, fontSize: 12, marginTop: 4,
                  boxSizing: "border-box", cursor: "pointer" }}>
                <option value="">— Unassigned —</option>
                {analysts.map(a => (
                  <option key={a.email} value={a.email}>
                    {a.name !== a.email ? `${a.name} (${a.email})` : a.email} · {a.role}
                  </option>
                ))}
              </select>
            ) : (
              <input value={assignee} onChange={e => setAssignee(e.target.value)}
                placeholder="analyst email…"
                style={{ width: "100%", background: "rgba(255,255,255,0.05)",
                  border: "1px solid rgba(255,255,255,0.12)", color: "white",
                  padding: "8px 10px", borderRadius: 4, fontSize: 12, marginTop: 4, boxSizing: "border-box" }} />
            )}
          </div>
          <div style={{ marginBottom: 10 }}>
            <label style={{ color: "rgba(255,255,255,0.65)", fontSize: 11, fontFamily: "monospace" }}>Notes</label>
            <textarea value={notes} onChange={e => setNotes(e.target.value)}
              rows={3} placeholder="Investigation notes…"
              style={{ width: "100%", background: "rgba(255,255,255,0.05)",
                border: "1px solid rgba(255,255,255,0.12)", color: "white",
                padding: "8px 10px", borderRadius: 4, fontSize: 12, marginTop: 4,
                resize: "vertical", fontFamily: "monospace", boxSizing: "border-box" }} />
          </div>
          <button onClick={handleSave} disabled={saving}
            style={{ background: saved ? "rgba(0,229,160,0.2)" : "rgba(0,229,160,0.12)",
              border: `1px solid rgba(0,229,160,${saved ? 0.6 : 0.4})`,
              color: "#00e5a0", padding: "9px 20px", borderRadius: 4, cursor: "pointer",
              fontSize: 13, fontFamily: "monospace", fontWeight: 700 }}>
            {saving ? "Saving…" : saved ? "✓ Saved" : "Save Notes"}
          </button>
        </div>
      </div>

      {/* Transition modal */}
      {showTransition && (
        <div style={{ position: "fixed", inset: 0, zIndex: 300,
          background: "rgba(0,0,0,0.7)", display: "flex", alignItems: "center", justifyContent: "center" }}
          onClick={e => e.target === e.currentTarget && setShowTransition(false)}>
          <div style={{ background: "#0d1117", border: "1px solid rgba(255,255,255,0.12)",
            borderRadius: 6, padding: "28px 32px", width: "min(480px, 92vw)" }}>
            <div style={{ color: "white", fontSize: 15, fontWeight: 700, marginBottom: 20 }}>
              Transition Incident Status
            </div>
            <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 20 }}>
              <StatBadge status={inc.status} />
              <span style={{ color: "rgba(255,255,255,0.3)" }}>→</span>
              <StatBadge status={transitionTo} />
            </div>
            <label style={{ color: "rgba(255,255,255,0.5)", fontSize: 11,
              fontFamily: "monospace", display: "block", marginBottom: 6 }}>
              AUDIT COMMENT (required)
            </label>
            <textarea
              autoFocus
              value={transitionComment}
              onChange={e => setTransitionComment(e.target.value)}
              rows={4}
              placeholder="Describe why you are changing this status…"
              style={{ width: "100%", background: "rgba(255,255,255,0.05)",
                border: `1px solid ${transitionErr ? "#ff3b3b" : "rgba(255,255,255,0.15)"}`,
                color: "white", padding: "10px 12px", borderRadius: 4, fontSize: 12,
                fontFamily: "monospace", resize: "vertical", boxSizing: "border-box", marginBottom: 8 }}
            />
            {transitionErr && (
              <div style={{ color: "#ff6464", fontSize: 11, fontFamily: "monospace", marginBottom: 8 }}>
                ✗ {transitionErr}
              </div>
            )}
            <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
              <button onClick={() => setShowTransition(false)}
                style={{ background: "none", border: "1px solid rgba(255,255,255,0.15)",
                  color: "rgba(255,255,255,0.5)", padding: "8px 18px", borderRadius: 4,
                  cursor: "pointer", fontSize: 12, fontFamily: "monospace" }}>
                Cancel
              </button>
              <button onClick={confirmTransition} disabled={transitioning}
                style={{ background: "rgba(0,229,160,0.12)", border: "1px solid rgba(0,229,160,0.4)",
                  color: "#00e5a0", padding: "8px 22px", borderRadius: 4, cursor: "pointer",
                  fontSize: 12, fontFamily: "monospace", fontWeight: 700 }}>
                {transitioning ? "Transitioning…" : "Confirm Transition"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Summary chart helpers ──────────────────────────────────────────────────────

function svgArc(cx, cy, r, startDeg, endDeg) {
  if (endDeg - startDeg >= 360) endDeg = startDeg + 359.99;
  const toRad = d => (d - 90) * Math.PI / 180;
  const sx = cx + r * Math.cos(toRad(endDeg));
  const sy = cy + r * Math.sin(toRad(endDeg));
  const ex = cx + r * Math.cos(toRad(startDeg));
  const ey = cy + r * Math.sin(toRad(startDeg));
  const large = endDeg - startDeg > 180 ? 1 : 0;
  return `M ${cx} ${cy} L ${sx} ${sy} A ${r} ${r} 0 ${large} 0 ${ex} ${ey} Z`;
}

function IncidentDonut({ data, title, activeId, onSegmentClick }) {
  const [hovered, setHovered] = useState(null);
  const total = data.reduce((s, d) => s + d.count, 0);

  if (total === 0) return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
      borderRadius: 6, padding: "14px 16px" }}>
      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace",
        letterSpacing: "1.5px", marginBottom: 8 }}>{title}</div>
      <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, padding: "30px 0",
        textAlign: "center" }}>No data</div>
    </div>
  );

  const CX = 70, CY = 70, R = 57, RI = 32;
  let ang = 0;
  const arcs = data.filter(d => d.count > 0).map(seg => {
    const sweep = (seg.count / total) * 360;
    const path  = svgArc(CX, CY, R, ang, ang + sweep);
    ang += sweep;
    return { ...seg, path, pct: Math.round((seg.count / total) * 100) };
  });
  const hov = hovered != null ? arcs[hovered] : null;

  return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
      borderRadius: 6, padding: "14px 16px" }}>
      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace",
        letterSpacing: "1.5px", marginBottom: 10 }}>{title}</div>
      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        <svg width="140" height="140" viewBox="0 0 140 140" style={{ flexShrink: 0 }}>
          <circle cx={CX} cy={CY} r={RI} fill="#090b10"/>
          {arcs.map((arc, i) => (
            <path key={arc.id} d={arc.path}
              fill={arc.color}
              opacity={hovered === null && !activeId ? 0.85 : (hovered === i || activeId === arc.id) ? 1 : 0.28}
              style={{ cursor: "pointer", transition: "opacity 0.15s" }}
              onMouseEnter={() => setHovered(i)}
              onMouseLeave={() => setHovered(null)}
              onClick={() => onSegmentClick?.(activeId === arc.id ? "" : arc.id)}
            />
          ))}
          <circle cx={CX} cy={CY} r={RI} fill="#090b10"/>
          {hov ? (
            <>
              <text x={CX} y={CY - 6} textAnchor="middle" fill={hov.color} fontSize="17"
                fontFamily="monospace" fontWeight="700">{hov.count}</text>
              <text x={CX} y={CY + 11} textAnchor="middle" fill={hov.color} fontSize="8"
                fontFamily="monospace">{hov.label.toUpperCase()}</text>
            </>
          ) : (
            <>
              <text x={CX} y={CY - 6} textAnchor="middle" fill="white" fontSize="17"
                fontFamily="monospace" fontWeight="700">{total}</text>
              <text x={CX} y={CY + 11} textAnchor="middle" fill="rgba(255,255,255,0.3)" fontSize="8"
                fontFamily="monospace">TOTAL</text>
            </>
          )}
        </svg>
        <div style={{ display: "flex", flexDirection: "column", gap: 7, flex: 1, minWidth: 0 }}>
          {arcs.map((arc, i) => (
            <div key={arc.id}
              onMouseEnter={() => setHovered(i)}
              onMouseLeave={() => setHovered(null)}
              onClick={() => onSegmentClick?.(activeId === arc.id ? "" : arc.id)}
              style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer",
                opacity: hovered === null && !activeId ? 1 : (hovered === i || activeId === arc.id) ? 1 : 0.35,
                transition: "opacity 0.15s" }}>
              <div style={{ width: 8, height: 8, borderRadius: 2, background: arc.color, flexShrink: 0 }}/>
              <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 10, fontFamily: "monospace",
                flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {arc.label}
              </span>
              <span style={{ color: arc.color, fontSize: 12, fontFamily: "monospace", fontWeight: 700 }}>
                {arc.count}
              </span>
              <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace",
                minWidth: 28, textAlign: "right" }}>{arc.pct}%</span>
            </div>
          ))}
        </div>
      </div>
      {activeId && (
        <div style={{ marginTop: 8, textAlign: "right" }}>
          <button onClick={() => onSegmentClick?.("")}
            style={{ background: "none", border: "none", color: "#4d9eff", fontSize: 9,
              fontFamily: "monospace", cursor: "pointer", padding: 0 }}>
            ✕ clear filter
          </button>
        </div>
      )}
    </div>
  );
}

function IncidentCategoryBar({ incidents }) {
  const [hovered, setHovered] = useState(null);
  const catCounts = {};
  incidents.forEach(inc => {
    (inc.categories || []).forEach(cat => { catCounts[cat] = (catCounts[cat] || 0) + 1; });
  });
  const entries = Object.entries(catCounts).sort((a, b) => b[1] - a[1]).slice(0, 7);
  if (entries.length === 0) return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
      borderRadius: 6, padding: "14px 16px" }}>
      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace",
        letterSpacing: "1.5px", marginBottom: 8 }}>CATEGORY DISTRIBUTION</div>
      <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, padding: "30px 0", textAlign: "center" }}>
        No categories
      </div>
    </div>
  );
  const maxVal = entries[0][1];

  return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
      borderRadius: 6, padding: "14px 16px" }}>
      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace",
        letterSpacing: "1.5px", marginBottom: 12 }}>CATEGORY DISTRIBUTION</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
        {entries.map(([cat, count], i) => {
          const color = CAT_COLORS[cat] || "rgba(255,255,255,0.4)";
          return (
            <div key={cat}
              onMouseEnter={() => setHovered(i)}
              onMouseLeave={() => setHovered(null)}
              style={{ opacity: hovered === null ? 1 : hovered === i ? 1 : 0.4, transition: "opacity 0.15s" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                <span style={{ color, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase" }}>
                  {cat.replace(/_/g, " ")}
                </span>
                <span style={{ color, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{count}</span>
              </div>
              <div style={{ height: 5, background: "rgba(255,255,255,0.06)", borderRadius: 2, overflow: "hidden" }}>
                <div style={{ width: `${(count / maxVal) * 100}%`, height: "100%", background: color,
                  borderRadius: 2, transition: "width 0.4s ease" }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function IncidentTrendLine({ incidents }) {
  const [tooltip, setTooltip] = useState(null);
  const now  = new Date();
  const days = Array.from({ length: 14 }, (_, i) => {
    const d = new Date(now);
    d.setDate(d.getDate() - (13 - i));
    return d;
  });
  const dayKey = d => d.toISOString().slice(0, 10);
  const counts = {};
  incidents.forEach(inc => {
    if (inc.first_seen) {
      const k = inc.first_seen.slice(0, 10);
      counts[k] = (counts[k] || 0) + 1;
    }
  });
  const pts = days.map(d => ({ d, k: dayKey(d), n: counts[dayKey(d)] || 0 }));
  const hasData = pts.some(p => p.n > 0);

  const W = 520, H = 80;
  const P = { t: 10, r: 10, b: 20, l: 26 };
  const iW = W - P.l - P.r, iH = H - P.t - P.b;
  const n  = pts.length;
  const mx = Math.max(...pts.map(p => p.n), 1);
  const xOf = i => P.l + (i / (n - 1)) * iW;
  const yOf = v => P.t + iH - Math.min((v / mx) * iH, iH);

  const linePath = pts.map((p, i) => {
    const x = xOf(i), y = yOf(p.n);
    if (i === 0) return `M ${x} ${y}`;
    const px = xOf(i - 1), py = yOf(pts[i - 1].n);
    const cx = (px + x) / 2;
    return `C ${cx} ${py} ${cx} ${y} ${x} ${y}`;
  }).join(" ");
  const areaPath = linePath + ` L ${xOf(n - 1)} ${P.t + iH} L ${P.l} ${P.t + iH} Z`;

  const [open, setOpen] = useState(false);

  return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
      borderRadius: 6, padding: "14px 16px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
        marginBottom: open ? 8 : 0 }}>
        <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace",
          letterSpacing: "1.5px" }}>INCIDENT TREND — LAST 14 DAYS</div>
        <button onClick={() => setOpen(v => !v)}
          style={{ background: "none", border: "none", color: "rgba(255,255,255,0.3)",
            cursor: "pointer", fontSize: 11, fontFamily: "monospace", padding: "0 2px",
            lineHeight: 1 }}>
          {open ? "▲ hide" : "▼ show"}
        </button>
      </div>
      {open && !hasData ? (
        <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, padding: "20px 0", textAlign: "center" }}>
          No incidents recorded in this period
        </div>
      ) : open ? (
        <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", display: "block", overflow: "visible" }}>
          {[0, 0.5, 1].map(f => {
            const y = yOf(mx * f), lbl = Math.round(mx * f);
            return (
              <g key={f}>
                <line x1={P.l} y1={y} x2={W - P.r} y2={y} stroke="rgba(255,255,255,0.05)"
                  strokeWidth="1" strokeDasharray="3 4"/>
                <text x={P.l - 4} y={y + 3} textAnchor="end" fill="rgba(255,255,255,0.2)"
                  fontSize="7" fontFamily="monospace">{lbl}</text>
              </g>
            );
          })}
          <path d={areaPath} fill="rgba(255,59,59,0.07)"/>
          <path d={linePath} fill="none" stroke="#ff6b6b" strokeWidth="1.5"/>
          {pts.map((p, i) => (
            <g key={i}>
              {p.n > 0 && (
                <circle cx={xOf(i)} cy={yOf(p.n)} r={3.5}
                  fill="#ff6b6b" stroke="#0d1117" strokeWidth="1.5"/>
              )}
              <rect x={xOf(i) - 14} y={P.t} width={28} height={iH} fill="transparent"
                onMouseEnter={e => p.n > 0 && setTooltip({ sx: e.clientX, sy: e.clientY, p })}
                onMouseMove={e  => setTooltip(t => t ? { ...t, sx: e.clientX, sy: e.clientY } : null)}
                onMouseLeave={() => setTooltip(null)}/>
              {i % 2 === 0 && (
                <text x={xOf(i)} y={H - 2} textAnchor="middle"
                  fill="rgba(255,255,255,0.18)" fontSize="7" fontFamily="monospace">
                  {p.d.toLocaleDateString("en-US", { month: "numeric", day: "numeric" })}
                </text>
              )}
            </g>
          ))}
        </svg>
      ) : null}
      {open && tooltip && (
        <div style={{ position: "fixed", left: tooltip.sx + 12, top: tooltip.sy - 10, zIndex: 9999,
          background: "#0d1117", border: "1px solid rgba(255,255,255,0.15)", borderRadius: 5,
          padding: "8px 12px", pointerEvents: "none", boxShadow: "0 4px 16px rgba(0,0,0,0.5)" }}>
          <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 10, fontFamily: "monospace", marginBottom: 3 }}>
            {tooltip.p.d.toLocaleDateString("en-US", { month: "short", day: "numeric" })}
          </div>
          <div style={{ color: "#ff6b6b", fontSize: 14, fontFamily: "monospace", fontWeight: 700 }}>
            {tooltip.p.n} incident{tooltip.p.n !== 1 ? "s" : ""}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────
// ── Severity Trend Panel (collapsible, 30-day by severity) ──────────────────────────────
function SeverityTrendPanel({ incidents }) {
  const [open, setOpen] = useState(false);

  const DAYS = 30;
  const W = 700, H = 150, PAD = { t: 16, r: 16, b: 32, l: 40 };
  const SEV_COLORS = { critical: "#ff3b3b", high: "#ff8c00", medium: "#f5c518", low: "#00e5a0" };
  const SEV_WIDTHS = { critical: 2.5, high: 2.5, medium: 1.5, low: 1.5 };
  const SEV_KEYS   = ["critical", "high", "medium", "low"];

  const now = Date.now();
  const buckets = Array.from({ length: DAYS }, (_, i) => {
    const d = new Date(now - (DAYS - 1 - i) * 864e5);
    return { day: d.toISOString().slice(0, 10), critical: 0, high: 0, medium: 0, low: 0 };
  });
  const dayMap = Object.fromEntries(buckets.map((b, i) => [b.day, i]));
  incidents.forEach(inc => {
    const day = (inc.first_seen || "").slice(0, 10);
    if (dayMap[day] != null) {
      const sev = (inc.severity || "low").toLowerCase();
      if (buckets[dayMap[day]][sev] != null) buckets[dayMap[day]][sev]++;
    }
  });

  const maxCount = Math.max(...buckets.flatMap(b => SEV_KEYS.map(k => b[k])), 1);
  const xScale   = i => PAD.l + (i / (DAYS - 1)) * (W - PAD.l - PAD.r);
  const yScale   = v => PAD.t + (1 - v / maxCount) * (H - PAD.t - PAD.b);

  const critHighSums = buckets.map(b => b.critical + b.high);
  const spikeDays = buckets.map((b, i) => {
    if (i < 7) return false;
    const window7 = critHighSums.slice(i - 7, i);
    const avg = window7.reduce((a, c) => a + c, 0) / window7.length;
    const ch = b.critical + b.high;
    return avg > 0 && ch >= avg * 1.5 && ch >= 2;
  });

  const labelIdx = [0, Math.floor(DAYS / 2), DAYS - 1];
  const now7 = new Date(now - 7 * 864e5).toISOString().slice(0, 10);
  const recentSpike = buckets.find((b, i) => spikeDays[i] && b.day >= now7);
  const sevTotals = Object.fromEntries(SEV_KEYS.map(k => [k, buckets.reduce((s, b) => s + b[k], 0)]));
  const polyline = (sevKey) => buckets.map((b, i) => `${xScale(i)},${yScale(b[sevKey])}`).join(" ");

  return (
    <div style={{
      background: "rgba(255,255,255,0.025)",
      border: "1px solid rgba(255,255,255,0.07)",
      borderTop: "2px solid #ff3b3b",
      borderRadius: 5,
      padding: "14px 20px",
      marginBottom: 16,
    }}>
      {/* Header row — always visible */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
        <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace" }}>
          SEVERITY TREND — 30 DAYS
        </span>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          {SEV_KEYS.map(k => (
            <span key={k} style={{ background: `${SEV_COLORS[k]}15`, color: SEV_COLORS[k], border: `1px solid ${SEV_COLORS[k]}40`, borderRadius: 3, padding: "1px 8px", fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
              {k.charAt(0).toUpperCase() + k.slice(1)}: {sevTotals[k]}
            </span>
          ))}
          <button
            onClick={() => setOpen(v => !v)}
            style={{ background: "none", border: "1px solid rgba(255,255,255,0.15)", color: "rgba(255,255,255,0.5)", padding: "3px 10px", borderRadius: 3, cursor: "pointer", fontSize: 10, fontFamily: "monospace" }}>
            {open ? "▲ Hide" : "▼ Show"}
          </button>
        </div>
      </div>
      {/* Expandable body */}
      {open && (
        <div style={{ marginTop: 14 }}>
          <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ overflow: "visible", display: "block" }}>
            {[0, 0.25, 0.5, 0.75, 1].map(r => {
              const y = PAD.t + (1 - r) * (H - PAD.t - PAD.b);
              return <line key={r} x1={PAD.l} x2={W - PAD.r} y1={y} y2={y} stroke="rgba(255,255,255,0.05)" strokeWidth="1"/>;
            })}
            {[0, maxCount].map((v, i) => {
              const y = yScale(v);
              return <text key={i} x={PAD.l - 4} y={y + 4} textAnchor="end" fill="rgba(255,255,255,0.25)" fontSize="9" fontFamily="monospace">{v}</text>;
            })}
            {buckets.map((b, i) => spikeDays[i] && (
              <line key={`spike-${i}`} x1={xScale(i)} x2={xScale(i)} y1={PAD.t} y2={H - PAD.b}
                stroke="rgba(255,59,59,0.4)" strokeWidth="1" strokeDasharray="3 3"/>
            ))}
            {SEV_KEYS.map(k => (
              <polyline key={k} points={polyline(k)} fill="none" stroke={SEV_COLORS[k]}
                strokeWidth={SEV_WIDTHS[k]} strokeLinejoin="round" strokeLinecap="round" opacity="0.9"/>
            ))}
            {buckets.map((b, i) => spikeDays[i] && b.critical > 0 && (
              <circle key={`dot-${i}`} cx={xScale(i)} cy={yScale(b.critical)} r="3" fill="#ff3b3b"/>
            ))}
            {labelIdx.map(i => (
              <text key={i} x={xScale(i)} y={H - 4} textAnchor="middle" fill="rgba(255,255,255,0.2)" fontSize="8" fontFamily="monospace">
                {buckets[i].day.slice(5)}
              </text>
            ))}
            <line x1={PAD.l} x2={W - PAD.r} y1={H - PAD.b} y2={H - PAD.b} stroke="rgba(255,255,255,0.07)" strokeWidth="1"/>
          </svg>
          {/* Legend */}
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 8, alignItems: "center" }}>
            {SEV_KEYS.map(k => (
              <span key={k} style={{ color: SEV_COLORS[k], fontSize: 9, fontFamily: "monospace" }}>
                ■ {k.charAt(0).toUpperCase() + k.slice(1)} {sevTotals[k]}
              </span>
            ))}
          </div>
          {/* Spike alert banner */}
          {recentSpike && (
            <div style={{
              background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.25)",
              color: "#ff3b3b", fontSize: 11, fontFamily: "monospace", padding: "8px 12px",
              borderRadius: 3, marginTop: 8,
            }}>
              ⚠ Critical/High spike detected on {recentSpike.day} — {recentSpike.critical + recentSpike.high} incidents in 24h
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function SiemIncidentsPage({ onOpenCase } = {}) {
  const [incidents, setIncidents]   = useState([]);
  const [total, setTotal]           = useState(0);
  const [loading, setLoading]       = useState(true);
  const [filters, setFilters]       = useState({ status: "active", severity: "" });
  const [selected, setSelected]     = useState(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [closeConfirm, setCloseConfirm] = useState(false); // close FP+resolved → closed
  const [closing, setClosing]       = useState(false);
  const [purgeConfirm, setPurgeConfirm] = useState(false); // purge closed from DB
  const [purging, setPurging]       = useState(false);
  const [sortField, setSortField]   = useState("severity");
  const [sortDir, setSortDir]       = useState("asc");
  const [pageSize, setPageSize]     = useState(50);
  const [currentPage, setCurrentPage] = useState(1);
  const [showFpPatterns, setShowFpPatterns] = useState(false);
  const [fpPatterns, setFpPatterns]   = useState([]);
  const [fpPatternsLoading, setFpPatternsLoading] = useState(false);
  const wsRef       = useRef(null);
  const wsDebounce  = useRef(null); // timer ref for WS-triggered refetch debounce

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    // Map frontend sort fields to backend sort_by values. Fields not in this map
    // fall back to last_seen on the server; the client then re-sorts the current page.
    const SERVER_SORTABLE = { severity: "severity", last_seen: "last_seen", alerts: "alert_count", risk_score: "risk_score", status: "status" };
    const apiParams = {
      limit:    pageSize,
      offset:   (currentPage - 1) * pageSize,
      sort_by:  SERVER_SORTABLE[sortField] || "last_seen",
      sort_dir: sortDir,
    };
    // "active" is the server's multi-status shorthand (open + investigating + in_review + held).
    // Normalize legacy hyphen variant "in-review" → "in_review" for single-status filters.
    if (filters.status) apiParams.status = filters.status.replace("-", "_");
    if (filters.severity) apiParams.severity = filters.severity;

    const d = await siemFetch(siemApi.getIncidents(apiParams));
    if (d._offline || d._error) { setLoading(false); return; }
    setIncidents(d.incidents || []);
    setTotal(d.total || 0);
    setLoading(false);
  }, [filters, currentPage, pageSize, sortField, sortDir]);

  const loadFpPatterns = async () => {
    setFpPatternsLoading(true);
    const data = await siemFetch(siemApi.getFpPatterns());
    setFpPatternsLoading(false);
    if (!data._error && !data._offline) setFpPatterns(Array.isArray(data) ? data : []);
  };

  const handleToggleFpPattern = async (id, autoClose) => {
    await siemFetch(siemApi.toggleFpPattern(id, { auto_close: autoClose }));
    setFpPatterns(prev => prev.map(p => p.id === id ? { ...p, auto_close: autoClose } : p));
  };

  const handleDeleteFpPattern = async (id) => {
    await siemFetch(siemApi.deleteFpPattern(id));
    setFpPatterns(prev => prev.filter(p => p.id !== id));
  };

  // Initial load + polling fallback (30s)
  useEffect(() => {
    setLoading(true);
    fetchIncidents();
    const timer = setInterval(fetchIncidents, 30_000);
    return () => clearInterval(timer);
  }, [fetchIncidents]);

  // WebSocket live feed
  useEffect(() => {
    const ws = siemApi.connectLive();
    wsRef.current = ws;
    ws.onopen  = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onerror = () => setWsConnected(false);
    ws.onmessage = (evt) => {
      try {
        const e = JSON.parse(evt.data);
        if (e.type === "alert_processed") {
          // Debounce: coalesce rapid bursts of alerts into a single refetch
          // so a flood of incoming alerts doesn't hammer the API on every message.
          clearTimeout(wsDebounce.current);
          wsDebounce.current = setTimeout(fetchIncidents, 4000);
        }
      } catch {}
    };
    return () => {
      ws.close();
      clearTimeout(wsDebounce.current);
    };
  }, [fetchIncidents]);

  // Listen for agentic-action updates from the CyMind chat overlay so the
  // Incidents table refreshes immediately after close/FP actions are confirmed
  useEffect(() => {
    const handler = () => fetchIncidents();
    window.addEventListener("cycentra:incident-updated", handler);
    return () => window.removeEventListener("cycentra:incident-updated", handler);
  }, [fetchIncidents]);

  useEffect(() => { setCurrentPage(1); }, [filters]);

  const handleSort = (col) => {
    if (sortField === col) {
      setSortDir(d => d === "asc" ? "desc" : "asc");
    } else {
      setSortField(col);
      setSortDir("asc");
    }
    setCurrentPage(1);
  };

  const handlePatched = (updated) => {
    setIncidents(prev => prev.map(inc => inc.id === updated.id ? { ...inc, ...updated } : inc));
    setSelected(prev => prev?.id === updated.id ? { ...prev, ...updated } : prev);
  };

  // Step 1: soft-close — transitions false_positive + resolved → closed (no deletion)
  const handleBatchClose = async () => {
    setClosing(true);
    const data = await siemFetch(siemApi.batchCloseIncidents("Archived by analyst — bulk close action"));
    setClosing(false);
    setCloseConfirm(false);
    if (!data._error && !data._offline) {
      await fetchIncidents();
    }
  };

  // Step 2: hard-delete — removes only closed incidents from DB
  const handlePurge = async () => {
    setPurging(true);
    const data = await siemFetch(siemApi.purgeIncidents("closed"));
    setPurging(false);
    setPurgeConfirm(false);
    if (!data._error && !data._offline) {
      await fetchIncidents();
    }
  };

  const getFieldVal = (inc, field) => {
    switch (field) {
      case "id":       return (inc.id || "").toLowerCase();
      case "severity": return SEV_ORDER[inc.severity] ?? 4;
      case "source":   return ((inc.affected_agents || [])[0] || "").toLowerCase();
      case "category": return ((inc.categories || [])[0] || "").toLowerCase();
      case "alerts":   return inc.alert_count || 0;
      case "status":   return (inc.status || "").toLowerCase();
      case "last_seen":return new Date(inc.last_seen || 0).getTime();
      default:         return 0;
    }
  };

  const sortedIncidents = [...incidents].sort((a, b) => {
    const va = getFieldVal(a, sortField);
    const vb = getFieldVal(b, sortField);
    let cmp = typeof va === "number" ? va - vb : (va < vb ? -1 : va > vb ? 1 : 0);
    return sortDir === "asc" ? cmp : -cmp;
  });

  // Server already returns exactly one page; totalPages drives the pagination controls using the full API total.
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  // Client-side sort applies to the current page only (server handles sort for the mapped fields above).
  const pagedIncidents = sortedIncidents;

  // ── Chart data (derived from the main incidents list) ─────────────────────
  const severityData = [
    { id: "critical", label: "Critical",       color: "#ff3b3b", count: incidents.filter(i => i.severity === "critical").length },
    { id: "high",     label: "High",           color: "#ff8c00", count: incidents.filter(i => i.severity === "high").length },
    { id: "medium",   label: "Medium",         color: "#f5c518", count: incidents.filter(i => i.severity === "medium").length },
    { id: "low",      label: "Low",            color: "#00e5a0", count: incidents.filter(i => i.severity === "low").length },
  ];
  const statusData = [
    { id: "open",          label: "Open",           color: "#ff3b3b", count: incidents.filter(i => i.status === "open").length },
    { id: "investigating", label: "Investigating",  color: "#ff8c00", count: incidents.filter(i => i.status === "investigating").length },
    { id: "in-review",     label: "In Review",      color: "#f5c518", count: incidents.filter(i => i.status === "in-review" || i.status === "in_review").length },
    { id: "resolved",      label: "Resolved",       color: "#00e5a0", count: incidents.filter(i => i.status === "resolved").length },
    { id: "false_positive",label: "False Positive", color: "#888888", count: incidents.filter(i => i.status === "false_positive").length },
  ];
  const summaryTiles = [
    { label: "Total",         value: total,                                                                                color: "rgba(255,255,255,0.85)" },
    { label: "Open",          value: incidents.filter(i => i.status === "open").length,                                  color: "#ff3b3b"                 },
    { label: "Investigating", value: incidents.filter(i => i.status === "investigating").length,                         color: "#ff8c00"                 },
    { label: "In Review",     value: incidents.filter(i => i.status === "in-review" || i.status === "in_review").length, color: "#f5c518"                 },
    { label: "Resolved",      value: incidents.filter(i => i.status === "resolved").length,                              color: "#00e5a0"                 },
    { label: "Critical",      value: incidents.filter(i => i.severity === "critical").length,                            color: "#ff3b3b"                 },
    { label: "High",          value: incidents.filter(i => i.severity === "high").length,                                color: "#ff8c00"                 },
  ];

  return (
    <SiemEngineStatus>
      <div style={{ position: "relative" }}>
        {/* Header */}
        <div style={{ marginBottom: 22 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: "white" }}>Incidents</h1>
            <span style={{ background: "rgba(255,59,59,0.12)", color: "#ff3b3b", fontSize: 10,
              fontFamily: "monospace", padding: "3px 10px", borderRadius: 2, fontWeight: 700,
              letterSpacing: "1px" }}>CORRELATION ENGINE</span>
            <LiveDot connected={wsConnected} />
          </div>
          <p style={{ color: "rgba(255,255,255,0.62)", fontSize: 13 }}>
            {total} incident{total !== 1 ? "s" : ""} — grouped by temporal + entity correlation across Wazuh alerts.
          </p>
        </div>

        {/* ── Summary visualizations ───────────────────────────────────────── */}
        {!loading && (
          <div style={{ marginBottom: 24 }}>
            {/* Stat tiles */}
            <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
              {summaryTiles.map(t => (
                <div key={t.label} style={{ background: "rgba(255,255,255,0.03)",
                  border: "1px solid rgba(255,255,255,0.07)", borderRadius: 5, padding: "10px 16px",
                  minWidth: 70 }}>
                  <div style={{ color: t.color, fontSize: 22, fontWeight: 700, fontFamily: "monospace" }}>
                    {t.value}
                  </div>
                  <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10,
                    fontFamily: "monospace", marginTop: 2 }}>{t.label}</div>
                </div>
              ))}
            </div>

            {/* Charts row — 3 equal columns */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 12 }}>
              <IncidentDonut
                title="SEVERITY BREAKDOWN"
                data={severityData}
                activeId={filters.severity}
                onSegmentClick={id => setFilters(prev => ({ ...prev, severity: id }))}
              />
              <IncidentDonut
                title="STATUS BREAKDOWN"
                data={statusData}
                activeId={filters.status}
                onSegmentClick={id => setFilters(prev => ({ ...prev, status: id }))}
              />
              <IncidentCategoryBar incidents={incidents}/>
            </div>

            {/* Trend line — full width */}
            <IncidentTrendLine incidents={incidents}/>
          </div>
        )}

        {/* Filters */}
        <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
          {[
            { key: "status", opts: ["", "active", "open", "investigating", "in-review", "resolved", "false_positive", "closed"],
              labels: ["All Statuses", "Active (non-closed)", "Open", "Investigating", "In Review", "Resolved", "False Positive", "Closed"] },
            { key: "severity", opts: ["", "critical", "high", "medium", "low"],
              labels: ["All Severities", "Critical", "High", "Medium", "Low"] },
          ].map(({ key, opts, labels }) => (
            <select key={key} value={filters[key]}
              onChange={e => setFilters(prev => ({ ...prev, [key]: e.target.value }))}
              style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
                color: "white", padding: "8px 12px", borderRadius: 4, fontSize: 12, fontFamily: "monospace" }}>
              {opts.map((o, i) => <option key={o} value={o}>{labels[i]}</option>)}
            </select>
          ))}
          <select value={pageSize}
            onChange={e => { setPageSize(Number(e.target.value)); setCurrentPage(1); }}
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
              color: "white", padding: "8px 12px", borderRadius: 4, fontSize: 12, fontFamily: "monospace" }}>
            {[50, 100, 250].map(n => <option key={n} value={n}>{n} / page</option>)}
          </select>
          <button onClick={fetchIncidents}
            style={{ background: "rgba(0,229,160,0.08)", border: "1px solid rgba(0,229,160,0.3)",
              color: "#00e5a0", padding: "8px 16px", borderRadius: 4, cursor: "pointer",
              fontSize: 12, fontFamily: "monospace" }}>
            ↻ Refresh
          </button>
          {/* Step 1: Close FP + Resolved → closed (soft, audit-logged, no deletion) */}
          {!closeConfirm ? (
            <button onClick={() => setCloseConfirm(true)}
              title="Transitions all False Positive and Resolved incidents to Closed status. No data is deleted."
              style={{ background: "rgba(245,197,24,0.07)", border: "1px solid rgba(245,197,24,0.3)",
                color: "#f5c518", padding: "8px 16px", borderRadius: 4, cursor: "pointer",
                fontSize: 12, fontFamily: "monospace" }}>
              ✓ Archive FP &amp; Resolved
            </button>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: 8,
              background: "rgba(245,197,24,0.07)", border: "1px solid rgba(245,197,24,0.35)",
              borderRadius: 4, padding: "6px 12px" }}>
              <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 11, fontFamily: "monospace" }}>
                Move all FP &amp; Resolved → Closed?
              </span>
              <button onClick={handleBatchClose} disabled={closing}
                style={{ background: "rgba(245,197,24,0.25)", border: "1px solid rgba(245,197,24,0.6)",
                  color: "#f5c518", padding: "4px 12px", borderRadius: 3, cursor: "pointer",
                  fontSize: 12, fontFamily: "monospace", fontWeight: 700 }}>
                {closing ? "Closing…" : "Confirm"}
              </button>
              <button onClick={() => setCloseConfirm(false)}
                style={{ background: "none", border: "none", color: "rgba(255,255,255,0.65)",
                  cursor: "pointer", fontSize: 11, fontFamily: "monospace" }}>
                Cancel
              </button>
            </div>
          )}
          {/* FP Patterns management */}
          <button
            onClick={() => { setShowFpPatterns(v => !v); if (!showFpPatterns) loadFpPatterns(); }}
            title="View and manage learned false-positive suppression patterns"
            style={{ background: showFpPatterns ? "rgba(179,107,255,0.15)" : "rgba(179,107,255,0.06)",
              border: `1px solid ${showFpPatterns ? "rgba(179,107,255,0.5)" : "rgba(179,107,255,0.25)"}`,
              color: "#b36bff", padding: "8px 16px", borderRadius: 4, cursor: "pointer",
              fontSize: 12, fontFamily: "monospace" }}>
            🧠 FP Patterns
          </button>

          {/* Step 2: Purge Closed — hard-deletes closed incidents from DB */}
          {!purgeConfirm ? (
            <button onClick={() => setPurgeConfirm(true)}
              title="Permanently deletes Closed incidents from the database. This cannot be undone."
              style={{ background: "rgba(255,59,59,0.06)", border: "1px solid rgba(255,59,59,0.25)",
                color: "rgba(255,100,100,0.8)", padding: "8px 16px", borderRadius: 4, cursor: "pointer",
                fontSize: 12, fontFamily: "monospace" }}>
              ⊘ Purge Closed
            </button>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: 8,
              background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.35)",
              borderRadius: 4, padding: "6px 12px" }}>
              <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 11, fontFamily: "monospace" }}>
                Permanently delete all Closed incidents?
              </span>
              <button onClick={handlePurge} disabled={purging}
                style={{ background: "rgba(255,59,59,0.3)", border: "1px solid rgba(255,59,59,0.6)",
                  color: "#ff6464", padding: "4px 12px", borderRadius: 3, cursor: "pointer",
                  fontSize: 12, fontFamily: "monospace", fontWeight: 700 }}>
                {purging ? "Deleting…" : "Confirm Delete"}
              </button>
              <button onClick={() => setPurgeConfirm(false)}
                style={{ background: "none", border: "none", color: "rgba(255,255,255,0.65)",
                  cursor: "pointer", fontSize: 11, fontFamily: "monospace" }}>
                Cancel
              </button>
            </div>
          )}
        </div>

        {/* FP Patterns panel */}
        {showFpPatterns && (
          <div style={{ background: "rgba(179,107,255,0.04)", border: "1px solid rgba(179,107,255,0.2)",
            borderRadius: 6, padding: "18px 20px", marginBottom: 22 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
              marginBottom: 14 }}>
              <div>
                <div style={{ color: "#b36bff", fontSize: 13, fontWeight: 700, fontFamily: "monospace" }}>
                  🧠 LEARNED FALSE-POSITIVE PATTERNS
                </div>
                <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 11, marginTop: 4 }}>
                  Alerts that match an active pattern are suppressed before opening an incident.
                  Patterns promote to auto-close after analysts mark {" "}
                  <span style={{ color: "#b36bff" }}>N</span> matching incidents as false positives
                  (configurable via <code style={{ fontSize: 10 }}>FP_PATTERN_CLOSE_THRESHOLD</code> in cysiemstack.env).
                </div>
              </div>
              <button onClick={loadFpPatterns} disabled={fpPatternsLoading}
                style={{ background: "none", border: "1px solid rgba(179,107,255,0.3)",
                  color: "#b36bff", padding: "6px 12px", borderRadius: 4, cursor: "pointer",
                  fontSize: 11, fontFamily: "monospace", flexShrink: 0, marginLeft: 16 }}>
                {fpPatternsLoading ? "Loading…" : "↻ Refresh"}
              </button>
            </div>

            {fpPatterns.length === 0 ? (
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 12, fontFamily: "monospace",
                padding: "20px 0", textAlign: "center" }}>
                No learned patterns yet. Close incidents as False Positive to start building the pattern memory.
              </div>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11,
                  fontFamily: "monospace" }}>
                  <thead>
                    <tr style={{ background: "rgba(179,107,255,0.06)" }}>
                      {["Rule", "Description", "Closes", "Threshold", "Auto-Close", "Last Seen", "Actions"].map(h => (
                        <th key={h} style={{ padding: "7px 10px", textAlign: "left",
                          color: "rgba(255,255,255,0.3)", fontWeight: 600,
                          borderBottom: "1px solid rgba(179,107,255,0.15)", whiteSpace: "nowrap" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {fpPatterns.map(p => (
                      <tr key={p.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}
                        onMouseEnter={e => e.currentTarget.style.background = "rgba(179,107,255,0.04)"}
                        onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                        <td style={{ padding: "7px 10px", color: "#4d9eff" }}>{p.rule_id || "—"}</td>
                        <td style={{ padding: "7px 10px", color: "rgba(255,255,255,0.65)",
                          maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                          title={p.raw_sample || p.description}>
                          {p.description || p.fingerprint}
                        </td>
                        <td style={{ padding: "7px 10px", textAlign: "center" }}>
                          <span style={{ background: "rgba(179,107,255,0.12)", color: "#b36bff",
                            padding: "2px 8px", borderRadius: 2, fontWeight: 700 }}>
                            {p.close_count}
                          </span>
                        </td>
                        <td style={{ padding: "7px 10px", color: "rgba(255,255,255,0.5)",
                          textAlign: "center" }}>{p.threshold}</td>
                        <td style={{ padding: "7px 10px", textAlign: "center" }}>
                          <button
                            onClick={() => handleToggleFpPattern(p.id, !p.auto_close)}
                            title={p.auto_close ? "Click to disable auto-close" : "Click to enable auto-close"}
                            style={{ background: p.auto_close ? "rgba(0,229,160,0.12)" : "rgba(255,255,255,0.04)",
                              border: `1px solid ${p.auto_close ? "rgba(0,229,160,0.4)" : "rgba(255,255,255,0.12)"}`,
                              color: p.auto_close ? "#00e5a0" : "rgba(255,255,255,0.35)",
                              padding: "3px 10px", borderRadius: 3, cursor: "pointer",
                              fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
                            {p.auto_close ? "✓ ACTIVE" : "INACTIVE"}
                          </button>
                        </td>
                        <td style={{ padding: "7px 10px", color: "rgba(255,255,255,0.35)",
                          whiteSpace: "nowrap" }}>
                          {p.last_seen ? new Date(p.last_seen).toLocaleDateString() : "—"}
                        </td>
                        <td style={{ padding: "7px 10px" }}>
                          <button
                            onClick={() => { if (window.confirm(`Delete FP pattern for rule ${p.rule_id}?`)) handleDeleteFpPattern(p.id); }}
                            style={{ background: "none", border: "1px solid rgba(255,59,59,0.25)",
                              color: "rgba(255,100,100,0.7)", padding: "3px 8px", borderRadius: 3,
                              cursor: "pointer", fontSize: 10, fontFamily: "monospace" }}>
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {loading ? (
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 13, padding: "40px 0" }}>
            Loading incidents…
          </div>
        ) : sortedIncidents.length === 0 ? (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, padding: "40px 0", textAlign: "center" }}>
            No incidents match the current filters.
          </div>
        ) : (
          <>
            <SeverityTrendPanel incidents={incidents} />
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
              borderRadius: 4, overflow: "hidden" }}>
            {/* Table header */}
            {(() => {
              const COL_KEY = { "ID": "id", "SEVERITY": "severity", "HOST ID": "source",
                "HOST NAME": null,
                "TYPE / CATEGORY": "category", "ALERTS": "alerts", "STATUS": "status",
                "INTEL": null, "RISK LEVEL": "risk_score", "FP PROB": "fp_probability",
                "LAST SEEN": "last_seen" };
              return (
                <div style={{ display: "grid",
                  gridTemplateColumns: "130px 75px 140px 130px 110px 60px 75px 80px 80px 65px 100px",
                  gap: 10, padding: "10px 16px",
                  background: "rgba(255,255,255,0.03)", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
                  {Object.entries(COL_KEY).map(([h, key]) => {
                    const active = key && sortField === key;
                    return (
                      <div key={h}
                        onClick={() => key && handleSort(key)}
                        style={{ color: active ? "rgba(255,255,255,0.7)" : "rgba(255,255,255,0.3)",
                          fontSize: 10, fontFamily: "monospace", letterSpacing: "1px",
                          cursor: key ? "pointer" : "default",
                          display: "flex", alignItems: "center", gap: 3,
                          userSelect: "none" }}>
                        {h}
                        {key && (
                          <span style={{ fontSize: 13, opacity: active ? 1 : 0.4, lineHeight: 1 }}>
                            {active ? (sortDir === "asc" ? "↑" : "↓") : "↕"}
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>
              );
            })()}

            {/* Rows */}
            {pagedIncidents.map(inc => (
              <div key={inc.id}
                onClick={() => setSelected(inc)}
                style={{ display: "grid",
                  gridTemplateColumns: "130px 75px 140px 130px 110px 60px 75px 80px 80px 65px 100px",
                  gap: 10, padding: "12px 16px", cursor: "pointer",
                  borderBottom: "1px solid rgba(255,255,255,0.04)",
                  background: selected?.id === inc.id ? "rgba(0,229,160,0.04)" : "transparent",
                  transition: "background 0.15s" }}
                onMouseEnter={e => { if (selected?.id !== inc.id) e.currentTarget.style.background = "rgba(255,255,255,0.025)"; }}
                onMouseLeave={e => { if (selected?.id !== inc.id) e.currentTarget.style.background = "transparent"; }}>
                <div style={{ color: "#4d9eff", fontSize: 11, fontFamily: "monospace",
                  fontWeight: 700 }}>{inc.id}</div>
                <div><SevBadge severity={inc.severity} /></div>
                <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {(() => {
                    const cloudSource = getCloudSource(inc.categories);
                    if (cloudSource) return (
                      <span title={`Cloud collector: ${(inc.affected_agents || []).join(", ")}`}
                        style={{ color: "#4d9eff", fontSize: 11, fontFamily: "monospace",
                          display: "flex", alignItems: "center", gap: 4 }}>
                        <span style={{ fontSize: 10 }}>☁</span>
                        <span style={{ fontWeight: 600 }}>{cloudSource}</span>
                        {(inc.affected_users || []).length > 0 && (
                          <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 10 }}>
                            · {(inc.affected_users || []).slice(0, 1).join(", ")}
                          </span>
                        )}
                      </span>
                    );
                    return (
                      <span style={{ color: "rgba(255,255,255,0.7)", fontSize: 12 }}>
                        {(inc.affected_agents || []).join(", ") || "—"}
                      </span>
                    );
                  })()}
                </div>
                {/* HOST NAME */}
                <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  color: "rgba(255,255,255,0.7)", fontSize: 12 }}
                  title={(inc.affected_agent_names || []).join(", ") || undefined}>
                  {(inc.affected_agent_names || []).join(", ") || <span style={{ color: "rgba(255,255,255,0.25)" }}>—</span>}
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                  {(inc.categories || []).slice(0, 2).map(cat => (
                    <span key={cat} style={{ background: "rgba(255,255,255,0.05)",
                      color: CAT_COLORS[cat] || "rgba(255,255,255,0.4)",
                      fontSize: 9, fontFamily: "monospace", padding: "1px 5px",
                      borderRadius: 2, textTransform: "uppercase" }}>
                      {cat.replace(/_/g, " ")}
                    </span>
                  ))}
                  {!(inc.categories || []).length && (
                    <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 11 }}>—</span>
                  )}
                </div>
                <div style={{ color: "rgba(255,255,255,0.6)", fontSize: 12,
                  fontFamily: "monospace" }}>{inc.alert_count}</div>
                <div><StatBadge status={inc.status} /></div>
                {/* Intel badges: AI narrative + MISP IOC hits */}
                <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                  {inc.llm_summary && (
                    <span title="AI narrative available" style={{ background: "rgba(0,229,160,0.1)",
                      color: "#00e5a0", border: "1px solid rgba(0,229,160,0.25)",
                      fontSize: 9, fontFamily: "monospace", padding: "1px 5px",
                      borderRadius: 2, fontWeight: 700, letterSpacing: "0.5px" }}>
                      🤖 AI
                    </span>
                  )}
                  {(inc.misp_enrichment?.ioc_hits || []).length > 0 && (
                    <span title={`${inc.misp_enrichment.ioc_hits.length} MISP IOC hit(s)`}
                      style={{ background: "rgba(255,59,59,0.12)",
                      color: "#ff6b6b", border: "1px solid rgba(255,59,59,0.3)",
                      fontSize: 9, fontFamily: "monospace", padding: "1px 5px",
                      borderRadius: 2, fontWeight: 700 }}>
                      🔴 IOC
                    </span>
                  )}
                  {inc.ti_reputation?.verdict && inc.ti_reputation.verdict !== "unknown" && (
                    <span
                      title={`TI: ${inc.ti_reputation.verdict} (${inc.ti_reputation.confidence ?? 0}% confidence) · ${(inc.ti_reputation.sources_used || []).join(", ")}`}
                      style={{
                        background: {malicious:"rgba(255,59,59,0.12)",suspicious:"rgba(245,197,24,0.12)",benign:"rgba(0,229,160,0.1)"}[inc.ti_reputation.verdict] || "rgba(255,255,255,0.06)",
                        color: {malicious:"#ff6b6b",suspicious:"#f5c518",benign:"#00e5a0"}[inc.ti_reputation.verdict] || "#888",
                        border: `1px solid ${{malicious:"rgba(255,59,59,0.3)",suspicious:"rgba(245,197,24,0.3)",benign:"rgba(0,229,160,0.25)"}[inc.ti_reputation.verdict] || "rgba(255,255,255,0.1)"}`,
                        fontSize: 9, fontFamily: "monospace", padding: "1px 5px",
                        borderRadius: 2, fontWeight: 700,
                      }}>
                      🌐 {inc.ti_reputation.confidence ?? 0}%
                    </span>
                  )}
                  {inc.case_opened_at && (
                    <span
                      title={`CyCases — ${inc.status}`}
                      style={{
                        background: "rgba(77,158,255,0.12)",
                        color: "#4d9eff",
                        border: "1px solid rgba(77,158,255,0.3)",
                        fontSize: 9, fontFamily: "monospace", padding: "1px 5px",
                        borderRadius: 2, fontWeight: 700, cursor: "pointer",
                      }}
                      onClick={e => { e.stopPropagation(); onOpenCase?.(inc.id); }}
                    >
                      🗂️ CASE
                    </span>
                  )}
                  {!inc.llm_summary && !(inc.misp_enrichment?.ioc_hits || []).length && !inc.case_opened_at && (
                    <span style={{ color: "rgba(255,255,255,0.42)", fontSize: 10 }}>—</span>
                  )}
                </div>
                {/* RISK LEVEL */}
                <div style={{ display: "flex", alignItems: "center" }}>
                  {inc.risk_score > 0 ? (() => {
                    const rs = inc.risk_score;
                    const [label, color, bg] = rs >= 8
                      ? ["CRIT", "#ff3b3b", "rgba(255,59,59,0.12)"]
                      : rs >= 5
                        ? ["HIGH", "#ff8c00", "rgba(255,140,0,0.12)"]
                        : rs >= 3
                          ? ["MED", "#f5c518", "rgba(245,197,24,0.10)"]
                          : ["LOW", "#00e5a0", "rgba(0,229,160,0.10)"];
                    return (
                      <span title={`Risk Score: ${rs?.toFixed(1)}`}
                        style={{ background: bg, color, border: `1px solid ${color}55`,
                          fontSize: 9, fontFamily: "monospace", padding: "2px 5px",
                          borderRadius: 2, fontWeight: 700, letterSpacing: "0.5px",
                          whiteSpace: "nowrap" }}>
                        {label} {rs?.toFixed(1)}
                      </span>
                    );
                  })() : <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 11 }}>—</span>}
                </div>
                {/* FP PROB */}
                <div style={{ display: "flex", alignItems: "center" }}>
                  {inc.fp_probability != null
                    ? <span
                        title={`False-Positive Probability: ${inc.fp_probability?.toFixed(1)}% — high value = likely noise`}
                        style={{ color: inc.fp_probability >= 90 ? "#ff8c00" : inc.fp_probability >= 70 ? "#f5c518" : "#4d9eff",
                          fontSize: 11, fontFamily: "monospace", fontWeight: 600 }}>
                        {inc.fp_probability?.toFixed(0)}%
                      </span>
                    : <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 11 }}>—</span>}
                </div>
                <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 10, fontFamily: "monospace" }}>
                  {fmtTs(inc.last_seen)}
                </div>
              </div>
            ))}

            {/* Pagination controls */}
            {totalPages > 1 && (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "10px 16px", borderTop: "1px solid rgba(255,255,255,0.06)",
                background: "rgba(255,255,255,0.01)" }}>
                <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace" }}>
                  {(currentPage - 1) * pageSize + 1}–{Math.min(currentPage * pageSize, total)} of {total}
                </span>
                <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
                  <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1}
                    style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)",
                      color: currentPage === 1 ? "rgba(255,255,255,0.15)" : "rgba(255,255,255,0.5)",
                      padding: "3px 10px", borderRadius: 3,
                      cursor: currentPage === 1 ? "default" : "pointer",
                      fontSize: 11, fontFamily: "monospace" }}>‹ Prev</button>
                  {Array.from({ length: totalPages }, (_, i) => i + 1)
                    .filter(p => p === 1 || p === totalPages || Math.abs(p - currentPage) <= 1)
                    .reduce((acc, p, idx, arr) => {
                      if (idx > 0 && p - arr[idx - 1] > 1) acc.push("…");
                      acc.push(p);
                      return acc;
                    }, [])
                    .map((p, i) => typeof p === "string" ? (
                      <span key={`ell-${i}`} style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, padding: "0 2px" }}>…</span>
                    ) : (
                      <button key={p} onClick={() => setCurrentPage(p)}
                        style={{ background: p === currentPage ? "rgba(0,229,160,0.12)" : "rgba(255,255,255,0.04)",
                          border: `1px solid ${p === currentPage ? "rgba(0,229,160,0.4)" : "rgba(255,255,255,0.1)"}`,
                          color: p === currentPage ? "#00e5a0" : "rgba(255,255,255,0.4)",
                          padding: "3px 8px", borderRadius: 3, cursor: "pointer",
                          fontSize: 11, fontFamily: "monospace", minWidth: 28 }}>{p}</button>
                    ))}
                  <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages}
                    style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)",
                      color: currentPage === totalPages ? "rgba(255,255,255,0.15)" : "rgba(255,255,255,0.5)",
                      padding: "3px 10px", borderRadius: 3,
                      cursor: currentPage === totalPages ? "default" : "pointer",
                      fontSize: 11, fontFamily: "monospace" }}>Next ›</button>
                </div>
              </div>
            )}
          </div>
          </>
        )}

        {/* Incident drawer */}
        {selected && (
          <>
            <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 199 }}
              onClick={() => setSelected(null)} />
            <IncidentDrawer
              incident={selected}
              onClose={() => setSelected(null)}
              onPatched={handlePatched}
              onOpenCase={onOpenCase}
            />
          </>
        )}
      </div>
    </SiemEngineStatus>
  );
}
