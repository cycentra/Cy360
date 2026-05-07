/**
 * SiemUebaPage.jsx
 * UEBA baseline profiles and anomaly timeline.
 * Features: category grouping, smart filters, anomaly highlights, Top-20 activity view.
 */

import { useState, useEffect, useMemo } from "react";
import { siemApi, siemFetch } from "./siemApi";
import { SiemEngineStatus } from "./SiemEngineStatus";
import { STATUS_CONFIG, STATUS_TRANSITIONS } from "../core/constants.js";

// ── Constants ──────────────────────────────────────────────────────────────────

const ANOMALY_LABELS = {
  off_hours_login:          "Off-Hours Login",
  high_auth_fail_rate:      "Elevated Auth Failures",
  new_agent_access:         "New Host Access",
  multi_host_burst:         "Multi-Host Burst",
  svc_account_interactive:  "Service Account Interactive Session",
  privilege_escalation:     "Privilege Escalation",
  impossible_travel:        "Impossible Travel",
};

const ANOMALY_COLORS = {
  off_hours_login:          "#f5c518",
  high_auth_fail_rate:      "#ff8c00",
  new_agent_access:         "#4d9eff",
  multi_host_burst:         "#ff8c00",
  svc_account_interactive:  "#ff3b3b",
  privilege_escalation:     "#ff3b3b",
  impossible_travel:        "#ff3b3b",
};

const CATEGORY_META = {
  human:   { label: "Human User",    color: "#00e5a0", icon: "👤", description: "Interactive user — real person who logs in" },
  service: { label: "Service Acct",  color: "#4d9eff", icon: "⚙️",  description: "Application or infrastructure service account" },
  system:  { label: "System Acct",   color: "#888",    icon: "🖥️", description: "OS-level daemon or system account — not interactive" },
};

const FILTER_TABS = [
  { id: "all",         label: "All Users",       icon: "🗂️"  },
  { id: "anomaly",     label: "With Anomaly",    icon: "🔴"  },
  { id: "human",       label: "Human",           icon: "👤"  },
  { id: "service",     label: "Service",         icon: "⚙️"  },
  { id: "system",      label: "System",          icon: "🖥️" },
  { id: "top20",       label: "Top 20 Activity", icon: "📊"  },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Stable ID for a UEBA anomaly — used as storage key for statuses & audit log */
function makeAnomalyId(a) {
  const raw = `${a.username || ""}_${a.anomaly_type || ""}_${a.detected_at || ""}`;
  return raw.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

// ── UEBA Confidence & Auto-Status (mirrors ASM confidence logic) ──────────────
// Maps each anomaly type to a severity tier so the same confidence formula
// used in VulnerabilityPage can be applied here.

const ANOMALY_SEVERITY = {
  privilege_escalation:    "critical",
  svc_account_interactive: "critical",
  impossible_travel:       "critical",
  high_auth_fail_rate:     "high",
  multi_host_burst:        "high",
  off_hours_login:         "medium",
  new_agent_access:        "low",
};

function computeUebaConfidence(a) {
  const SEV_CONF = { critical: 95, high: 80, medium: 55, low: 30 };
  const sev   = ANOMALY_SEVERITY[a.anomaly_type] || "medium";
  const base  = SEV_CONF[sev];
  const boost = a.risk_contribution != null ? (a.risk_contribution - 5) * 1.5 : 0;
  return Math.min(100, Math.max(0, Math.round(base + boost)));
}

// open → investigating : confidence ≥ 75 OR risk_contribution ≥ 3 OR critical type
// investigating → in_review : confidence ≥ 90 OR risk_contribution ≥ 6 OR critical type

function computeUebaAutoStatus(a, curStat) {
  const conf        = computeUebaConfidence(a);
  const critTypes   = ["privilege_escalation", "svc_account_interactive", "impossible_travel"];
  const rc          = a.risk_contribution || 0;
  if (curStat === "open") {
    if (conf >= 75 || rc >= 3 || critTypes.includes(a.anomaly_type))
      return { to: "investigating", reason: `Confidence ${conf}  •  Risk +${rc}  •  ${ANOMALY_LABELS[a.anomaly_type] || a.anomaly_type}` };
  }
  if (curStat === "investigating") {
    if (conf >= 90 || rc >= 6 || critTypes.includes(a.anomaly_type))
      return { to: "in_review", reason: `High-risk anomaly  •  Confidence ${conf}  •  Risk +${rc}` };
  }
  return null;
}

function UebaConfidenceBar({ confidence }) {
  const color = confidence >= 90 ? "#ff3b3b"
              : confidence >= 75 ? "#ff8c00"
              : confidence >= 55 ? "#f5c518"
              : "#4d9eff";
  return (
    <div style={{ marginTop: 8, marginBottom: 8 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 2 }}>
        <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 9,
          fontFamily: "monospace", letterSpacing: "1px" }}>CONFIDENCE</span>
        <span style={{ color, fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>{confidence}</span>
      </div>
      <div style={{ height: 3, background: "rgba(255,255,255,0.07)", borderRadius: 2 }}>
        <div style={{ width: `${confidence}%`, height: "100%", background: color,
          borderRadius: 2, transition: "width 0.4s ease" }} />
      </div>
    </div>
  );
}

function UebaAutoStatusBanner({ autoSug, onApply, busy }) {
  if (!autoSug) return null;
  const tc = STATUS_CONFIG[autoSug.to] || { color: "#888", label: autoSug.to };
  return (
    <div style={{
      background: `${tc.color}08`, border: `1px solid ${tc.color}35`,
      borderRadius: 4, padding: "8px 10px",
      display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap",
      marginBottom: 8,
    }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ color: tc.color, fontSize: 9, fontFamily: "monospace",
          fontWeight: 700, letterSpacing: "1px", marginBottom: 2 }}>
          AUTO-STATUS SUGGESTION
        </div>
        <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10 }}>{autoSug.reason}</div>
      </div>
      <div style={{ display: "flex", gap: 5, alignItems: "center", flexShrink: 0 }}>
        <span style={{
          background: `${tc.color}18`, color: tc.color,
          border: `1px solid ${tc.color}40`, fontSize: 10,
          fontFamily: "monospace", fontWeight: 700, padding: "2px 6px", borderRadius: 2,
        }}>→ {tc.label}</span>
        <button onClick={onApply} disabled={busy} style={{
          background: `${tc.color}15`, border: `1px solid ${tc.color}50`, color: tc.color,
          fontSize: 10, fontFamily: "monospace", fontWeight: 700,
          padding: "3px 8px", borderRadius: 3, cursor: busy ? "wait" : "pointer",
        }}>{busy ? "Applying…" : "Apply"}</button>
      </div>
    </div>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function HoursGrid({ hours = [] }) {
  const hourSet = new Set(hours);
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(24, 1fr)", gap: 2 }}>
      {Array.from({ length: 24 }, (_, h) => (
        <div key={h} title={`${String(h).padStart(2, "0")}:00`}
          style={{ height: 16, borderRadius: 2,
            background: hourSet.has(h) ? "#00e5a0" : "rgba(255,255,255,0.06)" }} />
      ))}
      <div style={{ gridColumn: "1 / -1", display: "flex", justifyContent: "space-between",
        color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>
        <span>00</span><span>06</span><span>12</span><span>18</span><span>23</span>
      </div>
    </div>
  );
}

function CategoryBadge({ category, small = false }) {
  const meta = CATEGORY_META[category] || CATEGORY_META.human;
  return (
    <span title={meta.description} style={{
      background: `${meta.color}18`,
      color: meta.color,
      border: `1px solid ${meta.color}40`,
      fontSize: small ? 9 : 10,
      fontFamily: "monospace",
      padding: small ? "1px 5px" : "2px 7px",
      borderRadius: 2,
      fontWeight: 700,
      letterSpacing: "0.5px",
      whiteSpace: "nowrap",
    }}>
      {meta.icon} {meta.label}
    </span>
  );
}

function AnomalyBadge({ active, total }) {
  if (!active && !total) return null;
  return (
    <span style={{
      background: active > 0 ? "rgba(255,59,59,0.15)" : "rgba(255,255,255,0.05)",
      color: active > 0 ? "#ff3b3b" : "rgba(255,255,255,0.3)",
      border: `1px solid ${active > 0 ? "rgba(255,59,59,0.4)" : "rgba(255,255,255,0.1)"}`,
      fontSize: 9, fontFamily: "monospace", padding: "2px 6px", borderRadius: 2, fontWeight: 700,
    }}>
      {active > 0 ? `⚠ ${active} ACTIVE` : `${total} resolved`}
    </span>
  );
}

// ── Anomaly detail card with investigation context ────────────────────────────
/**
 * anomalyStatus: { status, audit_log } from parent-managed state
 * onStatusChange(anomalyId, newStatus): callback to update parent
 */
function AnomalyCard({ a, integrations, anomalyStatus, onStatusChange }) {
  const [expanded,     setExpanded]     = useState(false);
  const [escalating,   setEscalating]   = useState(false);
  const [escalated,    setEscalated]    = useState(null);  // { case_id, case_url }
  const [escalateErr,  setEscalateErr]  = useState(null);
  // Status lifecycle (inline in expanded panel)
  const [txTarget,       setTxTarget]       = useState(null);
  const [txComment,      setTxComment]      = useState("");
  const [txErr,          setTxErr]          = useState("");
  const [txBusy,         setTxBusy]         = useState(false);
  const [autoBusy,       setAutoBusy]       = useState(false);
  const [wazuhLaunching, setWazuhLaunching] = useState(false);

  const color      = ANOMALY_COLORS[a.anomaly_type] || "#888";
  const anomalyId  = makeAnomalyId(a);
  const curStat    = anomalyStatus?.status || "open";
  const targets    = STATUS_TRANSITIONS[curStat] || [];
  const statCfg    = STATUS_CONFIG[curStat] || STATUS_CONFIG.open;

  // Confidence score + automated status suggestion
  const confidence = computeUebaConfidence(a);
  const autoSug    = computeUebaAutoStatus(a, curStat);

  // Already has a ticket (auto-raised by engine OR raised this session)
  const hasTicket  = a.iris_case_id || (escalated?.case_id);
  const ticketId   = a.iris_case_id || escalated?.case_id;
  const ticketUrl  = a.iris_case_url || escalated?.case_url;

  const startTx  = (t) => { setTxTarget(t); setTxComment(""); setTxErr(""); };
  const cancelTx = () => setTxTarget(null);

  const handleAutoApply = async () => {
    if (!autoSug) return;
    setAutoBusy(true);
    try {
      const r = await fetch(`/api/siem/ueba/anomaly/${encodeURIComponent(anomalyId)}/status`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          to_status: autoSug.to,
          comment:   `Auto-applied — ${autoSug.reason}`,
        }),
      });
      if (!r.ok) {
        const b = await r.json().catch(() => ({}));
        setTxErr(b.error || `Auto-apply HTTP ${r.status}`);
      } else {
        onStatusChange?.(anomalyId, autoSug.to);
      }
    } catch { setTxErr("Network error."); }
    setAutoBusy(false);
  };

  const confirmTx = async () => {
    if (!txComment.trim()) { setTxErr("A comment is required."); return; }
    setTxBusy(true);
    try {
      const r = await fetch(`/api/siem/ueba/anomaly/${encodeURIComponent(anomalyId)}/status`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ to_status: txTarget, comment: txComment }),
      });
      if (!r.ok) {
        const b = await r.json().catch(() => ({}));
        setTxErr(b.error || `HTTP ${r.status}`);
      } else {
        onStatusChange?.(anomalyId, txTarget);
        setTxTarget(null);
      }
    } catch { setTxErr("Network error."); }
    setTxBusy(false);
  };

  async function handleEscalate(e) {
    e.stopPropagation();
    setEscalating(true);
    setEscalateErr(null);
    try {
      const resp = await siemApi.escalateToIris({
        username:         a.username,
        anomaly_type:     a.anomaly_type,
        description:      a.description,
        agent_name:       a.agent_name,
        src_ip:           a.src_ip,
        rule_id:          a.rule_id,
        rule_desc:        a.rule_desc,
        process_name:     a.process_name,
        file_path:        a.file_path,
        raw_log:          a.raw_log,
        detected_at:      a.detected_at,
        incident_id:      a.incident_id,
        risk_contribution: a.risk_contribution,
      });
      const data = await resp.json();
      if (!resp.ok || data.error) {
        setEscalateErr(data.error || `HTTP ${resp.status}`);
      } else {
        setEscalated(data);
      }
    } catch {
      setEscalateErr("Network error — check IRIS connectivity.");
    } finally {
      setEscalating(false);
    }
  }

  // Wazuh deep-link: opens Wazuh Discover filtered by the first alert_id
  const wazuhLink = (integrations?.wazuh_url && (a.alert_ids?.[0]))
    ? `${integrations.wazuh_url}/app/discover#/?_g=(time:(from:now-1d,to:now))&_a=(query:(language:kuery,query:'_id:"${a.alert_ids[0]}"'))`
    : null;

  const handleWazuhLaunch = async (e) => {
    e.stopPropagation();
    if (!wazuhLink) return;
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
      // Always open the specific Discover deep-link, not the generic launch_url
      window.open(wazuhLink, "_blank", "noopener,noreferrer");
    } catch {
      window.open(wazuhLink, "_blank", "noopener,noreferrer");
    } finally {
      setWazuhLaunching(false);
    }
  };

  const hasContext = a.agent_name || a.src_ip || a.rule_id || a.process_name || a.file_path;

  return (
    <div style={{
      background: a.resolved ? "rgba(255,255,255,0.01)" : "rgba(255,255,255,0.03)",
      border: `1px solid rgba(255,255,255,${a.resolved ? 0.04 : 0.07})`,
      borderLeft: `3px solid ${a.resolved ? "rgba(255,255,255,0.08)" : color}`,
      borderRadius: "0 4px 4px 0",
      opacity: a.resolved ? 0.6 : 1,
    }}>
      {/* ── Card header (always visible) ── */}
      <div
        onClick={() => hasContext && setExpanded(v => !v)}
        style={{ display: "flex", gap: 12, padding: "10px 14px",
          cursor: hasContext ? "pointer" : "default" }}>
        {/* Timestamp */}
        <div style={{ minWidth: 72, color: "rgba(255,255,255,0.3)", fontSize: 10,
          fontFamily: "monospace", flexShrink: 0, lineHeight: 1.5 }}>
          {a.detected_at ? new Date(a.detected_at).toLocaleDateString() : "—"}
          <br />
          {a.detected_at ? new Date(a.detected_at).toLocaleTimeString() : ""}
        </div>

        {/* Main content */}
        <div style={{ flex: 1, minWidth: 0 }}>
          {/* Row 1: type + score + status */}
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4,
            flexWrap: "wrap" }}>
            <span style={{ color, fontSize: 11, fontWeight: 700, fontFamily: "monospace" }}>
              {ANOMALY_LABELS[a.anomaly_type] || a.anomaly_type}
            </span>
            <span style={{ background: `${color}20`, color, border: `1px solid ${color}40`,
              fontSize: 9, fontFamily: "monospace", padding: "1px 6px", borderRadius: 2 }}>
              +{a.risk_contribution}
            </span>
            {a.resolved && (
              <span style={{ color: "#00e5a0", fontSize: 9, fontFamily: "monospace" }}>
                ✓ RESOLVED
              </span>
            )}
            {a.mitre_id && (
              <span style={{ color: "#b06eff", fontSize: 9, fontFamily: "monospace",
                background: "rgba(176,110,255,0.1)", padding: "1px 6px", borderRadius: 2,
                border: "1px solid rgba(176,110,255,0.2)" }}>
                {a.mitre_id}
              </span>
            )}
          </div>

          {/* Row 2: description */}
          <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, marginBottom: 5 }}>
            {a.description}
          </div>

          {/* Row 3: key facts inline (always visible when data exists) */}
          {hasContext && (
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              {a.agent_name && (
                <span style={{ color: "rgba(255,255,255,0.62)", fontSize: 10,
                  fontFamily: "monospace" }}>
                  🖥 {a.agent_name}
                </span>
              )}
              {a.src_ip && (
                <span style={{ color: "rgba(255,255,255,0.62)", fontSize: 10,
                  fontFamily: "monospace" }}>
                  🌐 {a.src_ip}
                </span>
              )}
              {a.rule_id && (
                <span style={{ color: "rgba(255,255,255,0.62)", fontSize: 10,
                  fontFamily: "monospace" }}>
                  📋 Rule {a.rule_id}
                </span>
              )}
              {a.process_name && (
                <span style={{ color: "rgba(255,255,255,0.62)", fontSize: 10,
                  fontFamily: "monospace" }}>
                  ⚡ {a.process_name}
                </span>
              )}
            </div>
          )}
        </div>

        {/* Expand chevron */}
        {hasContext && (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, flexShrink: 0,
            alignSelf: "center" }}>
            {expanded ? "▾" : "▸"}
          </div>
        )}
      </div>

      {/* ── Expanded detail panel ── */}
      {expanded && (
        <div style={{ borderTop: "1px solid rgba(255,255,255,0.05)",
          padding: "12px 14px 14px 14px", display: "flex", flexDirection: "column", gap: 12 }}>

          {/* Context grid */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            {[
              { label: "HOST",     val: a.agent_name },
              { label: "SOURCE IP", val: a.src_ip },
              { label: "RULE",     val: a.rule_id ? `${a.rule_id}${a.rule_level ? ` (L${a.rule_level})` : ""}` : null },
              { label: "RULE DESC", val: a.rule_desc },
              { label: "PROCESS",  val: a.process_name },
              { label: "FILE",     val: a.file_path },
              { label: "INCIDENT", val: a.incident_id },
              { label: "CATEGORY", val: a.category },
            ].filter(r => r.val).map(({ label, val }) => (
              <div key={label}>
                <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9,
                  fontFamily: "monospace", letterSpacing: "1px", marginBottom: 2 }}>
                  {label}
                </div>
                <div style={{ color: "rgba(255,255,255,0.7)", fontSize: 11,
                  fontFamily: "monospace", wordBreak: "break-all" }}>
                  {val}
                </div>
              </div>
            ))}
          </div>

          {/* Raw log */}
          {a.raw_log && (
            <div>
              <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9,
                fontFamily: "monospace", letterSpacing: "1px", marginBottom: 4 }}>
                RAW LOG
              </div>
              <pre style={{ margin: 0, padding: "8px 10px",
                background: "rgba(0,0,0,0.35)", borderRadius: 3,
                color: "rgba(255,255,255,0.5)", fontSize: 10, fontFamily: "monospace",
                whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 120,
                overflow: "auto", lineHeight: 1.5 }}>
                {a.raw_log.slice(0, 800)}{a.raw_log.length > 800 ? "…" : ""}
              </pre>
            </div>
          )}

          {/* ── Status Lifecycle section ────────────────────────────── */}
          <div style={{ background: "rgba(255,255,255,0.025)",
            border: "1px solid rgba(255,255,255,0.08)", borderRadius: 4,
            padding: "12px 14px" }}>
            <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace",
              letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 6 }}>
              Status Lifecycle
            </div>

            {/* Confidence bar */}
            <UebaConfidenceBar confidence={confidence} />

            {/* Current active state */}
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: txTarget ? 10 : (targets.length > 0 ? 8 : 0) }}>
              <span style={{ color: "rgba(255,255,255,0.65)", fontSize: 11 }}>Current:</span>
              <span style={{ background: `${statCfg.color}18`, color: statCfg.color,
                border: `1px solid ${statCfg.color}50`, fontSize: 11, fontWeight: 700,
                fontFamily: "monospace", padding: "3px 10px", borderRadius: 3 }}>
                {statCfg.label}
              </span>
            </div>

            {/* Auto-status suggestion banner (confidence-driven) */}
            {!txTarget && (
              <>
                <UebaAutoStatusBanner autoSug={autoSug} onApply={handleAutoApply} busy={autoBusy} />
                {txErr && !txTarget && <div style={{ color: "#ff6464", fontSize: 10,
                  fontFamily: "monospace", marginBottom: 6 }}>{txErr}</div>}
              </>
            )}

            {/* Inline transition form */}
            {txTarget ? (
              <div>
                <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 10,
                  fontFamily: "monospace", marginBottom: 6 }}>
                  Transitioning to:{" "}
                  <span style={{ color: STATUS_CONFIG[txTarget]?.color || "#888", fontWeight: 700 }}>
                    {STATUS_CONFIG[txTarget]?.label || txTarget}
                  </span>
                </div>
                <textarea value={txComment} onChange={e => setTxComment(e.target.value)}
                  placeholder="Reason for this status change (required)…"
                  rows={2}
                  style={{ width: "100%", boxSizing: "border-box",
                    background: "rgba(255,255,255,0.03)",
                    border: `1px solid ${txErr ? "#ff3b3b" : "rgba(255,255,255,0.1)"}`,
                    borderRadius: 3, color: "rgba(255,255,255,0.8)", fontSize: 11,
                    fontFamily: "monospace", padding: "6px 8px", resize: "vertical" }} />
                {txErr && <div style={{ color: "#ff6464", fontSize: 10,
                  fontFamily: "monospace", marginTop: 3 }}>{txErr}</div>}
                <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
                  <button onClick={cancelTx} style={{ background: "none",
                    border: "1px solid rgba(255,255,255,0.1)",
                    color: "rgba(255,255,255,0.65)", padding: "4px 10px", borderRadius: 3,
                    fontFamily: "monospace", fontSize: 10, cursor: "pointer" }}>Cancel</button>
                  <button onClick={confirmTx} disabled={txBusy} style={{
                    background: `${STATUS_CONFIG[txTarget]?.color || "#888"}20`,
                    border: `1px solid ${STATUS_CONFIG[txTarget]?.color || "#888"}50`,
                    color: STATUS_CONFIG[txTarget]?.color || "#888",
                    padding: "4px 12px", borderRadius: 3, fontFamily: "monospace",
                    fontSize: 11, fontWeight: 700, cursor: txBusy ? "wait" : "pointer",
                  }}>{txBusy ? "Saving…" : "Confirm"}</button>
                </div>
              </div>
            ) : (
              targets.length > 0 && (
                <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                  {targets.map(t => {
                    const tc = STATUS_CONFIG[t] || { color: "#888", label: t };
                    return (
                      <button key={t} onClick={() => startTx(t)} style={{
                        background: `${tc.color}12`, border: `1px solid ${tc.color}40`,
                        color: tc.color, fontSize: 9, fontFamily: "monospace", fontWeight: 700,
                        padding: "3px 8px", borderRadius: 3, cursor: "pointer",
                      }}>→ {tc.label}</button>
                    );
                  })}
                </div>
              )
            )}
          </div>

          {/* ── CyIRIS Ticket indicator ────────────────────────────────── */}
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            {/* Wazuh deep-link — SSO launch */}
            {wazuhLink && (
              <button
                onClick={handleWazuhLaunch}
                disabled={wazuhLaunching}
                title="Opens Wazuh Discover for this alert with your CyCentra session (SSO)"
                style={{ display: "inline-flex", alignItems: "center", gap: 5,
                  background: wazuhLaunching ? "rgba(77,158,255,0.03)" : "rgba(77,158,255,0.08)",
                  border: "1px solid rgba(77,158,255,0.25)",
                  color: "#4d9eff", fontSize: 11, fontFamily: "monospace",
                  padding: "5px 12px", borderRadius: 3,
                  cursor: wazuhLaunching ? "wait" : "pointer" }}>
                {wazuhLaunching ? "Launching…" : "View in Wazuh"}
              </button>
            )}

            {/* SUCCESS — ticket already exists */}
            {hasTicket && (
              <a href={ticketUrl} target="_blank" rel="noopener noreferrer"
                style={{ display: "inline-flex", alignItems: "center", gap: 5,
                  background: "rgba(0,229,160,0.08)", border: "1px solid rgba(0,229,160,0.3)",
                  color: "#00e5a0", fontSize: 11, fontFamily: "monospace",
                  padding: "5px 12px", borderRadius: 3, textDecoration: "none" }}>
                ✓ IRIS Case #{ticketId} ↗
              </a>
            )}

            {/* FAILED — auto-raise attempt failed */}
            {!hasTicket && escalateErr && (
              <>
                <span style={{ background: "rgba(255,59,59,0.1)", border: "1px solid rgba(255,59,59,0.3)",
                  color: "#ff6b6b", fontSize: 10, fontFamily: "monospace",
                  padding: "4px 10px", borderRadius: 3 }}>
                  ⚠ Auto-raise failed
                </span>
                {integrations?.iris_enabled && (
                  <button onClick={handleEscalate} disabled={escalating} style={{
                    display: "inline-flex", alignItems: "center", gap: 5,
                    background: "rgba(255,140,0,0.1)", border: "1px solid rgba(255,140,0,0.35)",
                    color: "#ff8c00", fontSize: 11, fontFamily: "monospace",
                    padding: "5px 12px", borderRadius: 3,
                    cursor: escalating ? "wait" : "pointer" }}>
                    {escalating ? "⏳ Raising…" : "🎫 Manual Ticket"}
                  </button>
                )}
              </>
            )}

            {/* NONE — no ticket yet, ready to escalate */}
            {!hasTicket && !escalateErr && integrations?.iris_enabled && (
              <button onClick={handleEscalate} disabled={escalating}
                style={{ display: "inline-flex", alignItems: "center", gap: 5,
                  background: escalating ? "rgba(255,255,255,0.03)" : "rgba(255,59,59,0.08)",
                  border: `1px solid ${escalating ? "rgba(255,255,255,0.1)" : "rgba(255,59,59,0.3)"}`,
                  color: escalating ? "rgba(255,255,255,0.3)" : "#ff6b6b",
                  fontSize: 11, fontFamily: "monospace", padding: "5px 12px",
                  borderRadius: 3, cursor: escalating ? "default" : "pointer" }}>
                {escalating ? "⏳ Escalating…" : "🚨 Escalate to IRIS"}
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function UserProfile({ username, integrations, anomalyStatuses, onStatusChange }) {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    siemFetch(siemApi.getUebaUser(username)).then(data => {
      if (cancelled) return;
      if (!data._offline && !data._error) setProfile(data);
      setLoading(false);
    });
    return () => { cancelled = true; };
  }, [username]);

  if (loading) return (
    <div style={{ color: "rgba(255,255,255,0.3)", padding: 20 }}>Loading profile…</div>
  );
  if (!profile) return (
    <div style={{ color: "rgba(255,255,255,0.3)", padding: 20 }}>Profile not found.</div>
  );

  const { baseline, anomalies = [] } = profile;
  const activeAnomalies = anomalies.filter(a => !a.resolved);

  const byType = {};
  anomalies.forEach(a => {
    byType[a.anomaly_type] = (byType[a.anomaly_type] || 0) + (a.risk_contribution || 0);
  });
  const maxContrib = Math.max(...Object.values(byType), 1);

  return (
    <div>
      {/* Baseline stats */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 20 }}>
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 4, padding: "14px 16px" }}>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace",
            letterSpacing: "1px", marginBottom: 8 }}>TYPICAL WORKING HOURS</div>
          {baseline ? <HoursGrid hours={baseline.typical_hours || []} /> : (
            <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12 }}>No baseline yet</div>
          )}
        </div>
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 4, padding: "14px 16px" }}>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace",
            letterSpacing: "1px", marginBottom: 10 }}>BEHAVIOURAL BASELINE</div>
          {baseline ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {[
                { label: "Avg Daily Events", val: Math.round(baseline.avg_daily_events || 0) },
                { label: "Avg Fail Rate",    val: `${((baseline.avg_fail_rate || 0) * 100).toFixed(1)}%` },
                { label: "Typical Agents",   val: (baseline.typical_agents || []).length },
                { label: "Last Updated",     val: baseline.updated_at ? new Date(baseline.updated_at).toLocaleDateString() : "—" },
              ].map(({ label, val }) => (
                <div key={label} style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "rgba(255,255,255,0.65)", fontSize: 12 }}>{label}</span>
                  <span style={{ color: "white", fontSize: 12, fontFamily: "monospace" }}>{val}</span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12 }}>
              Building baseline… check back in 30 days.
            </div>
          )}
        </div>
      </div>

      {/* Anomaly type contribution chart */}
      {Object.keys(byType).length > 0 && (
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 4, padding: "14px 16px", marginBottom: 20 }}>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace",
            letterSpacing: "1px", marginBottom: 12 }}>RISK CONTRIBUTION BY ANOMALY TYPE</div>
          {Object.entries(byType).sort(([, a], [, b]) => b - a).map(([type, total]) => {
            const color = ANOMALY_COLORS[type] || "#888";
            return (
              <div key={type} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, width: 200, flexShrink: 0 }}>
                  {ANOMALY_LABELS[type] || type}
                </div>
                <div style={{ flex: 1, height: 6, background: "rgba(255,255,255,0.06)", borderRadius: 3 }}>
                  <div style={{ width: `${(total / maxContrib) * 100}%`, height: "100%",
                    background: color, borderRadius: 3 }} />
                </div>
                <span style={{ color, fontSize: 11, fontFamily: "monospace", minWidth: 28,
                  textAlign: "right" }}>+{total}</span>
              </div>
            );
          })}
        </div>
      )}

      {/* Anomaly timeline */}
      <div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace",
            letterSpacing: "1px" }}>ANOMALY TIMELINE</div>
          {activeAnomalies.length > 0 && (
            <span style={{ background: "rgba(255,59,59,0.12)", color: "#ff3b3b",
              fontSize: 10, fontFamily: "monospace", padding: "2px 8px",
              borderRadius: 2, fontWeight: 700 }}>
              {activeAnomalies.length} ACTIVE
            </span>
          )}
          {integrations?.iris_enabled && (
            <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 9,
              fontFamily: "monospace" }}>
              • Expand any alert to escalate to IRIS
            </span>
          )}
        </div>

        {anomalies.length === 0 ? (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, padding: "20px 0" }}>
            No anomalies detected for this user.
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {anomalies.slice(0, 50).map(a => (
              <AnomalyCard key={a.id} a={a} integrations={integrations}
                anomalyStatus={anomalyStatuses?.[makeAnomalyId(a)]}
                onStatusChange={onStatusChange} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/** Collapsible group of users in the sidebar list */
function UserGroup({ title, icon, color, users, selected, onSelect, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen);

  if (users.length === 0) return null;
  return (
    <div style={{ marginBottom: 14 }}>
      <button onClick={() => setOpen(v => !v)}
        style={{ width: "100%", display: "flex", alignItems: "center", gap: 6,
          background: "none", border: "none", cursor: "pointer",
          color: "rgba(255,255,255,0.65)", padding: "4px 0", textAlign: "left" }}>
        <span style={{ fontSize: 10, fontFamily: "monospace", letterSpacing: "1px",
          color, flex: 1, fontWeight: 700 }}>
          {icon} {title.toUpperCase()} ({users.length})
        </span>
        <span style={{ fontSize: 10, color: "rgba(255,255,255,0.55)" }}>
          {open ? "▾" : "▸"}
        </span>
      </button>

      {open && (
        <div style={{ display: "flex", flexDirection: "column", gap: 3, marginTop: 4 }}>
          {users.map(u => {
            const isSelected = selected === u.username;
            return (
              <button key={u.username} onClick={() => onSelect(u.username)}
                style={{
                  background: isSelected ? "rgba(176,110,255,0.1)" : "rgba(255,255,255,0.01)",
                  border: `1px solid ${isSelected ? "rgba(176,110,255,0.4)" : "rgba(255,255,255,0.06)"}`,
                  borderRadius: 4, padding: "8px 10px", cursor: "pointer", textAlign: "left",
                  transition: "all 0.15s",
                }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
                  gap: 6, marginBottom: u.active_anomalies > 0 ? 4 : 0 }}>
                  <div style={{ color: "white", fontSize: 12,
                    fontWeight: isSelected ? 700 : 400, fontFamily: "monospace",
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
                    {u.username}
                  </div>
                  <AnomalyBadge active={u.active_anomalies} total={u.total_anomalies} />
                </div>
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <CategoryBadge category={u.category} small />
                  {u.avg_daily_events > 0 && (
                    <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 9,
                      fontFamily: "monospace" }}>
                      ~{Math.round(u.avg_daily_events)} evt/day
                    </span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

/** Compact summary strip of users with active anomalies — shown at top of main panel */
function AnomalyAlertStrip({ users, selected, onSelect }) {
  const atRisk = users.filter(u => u.active_anomalies > 0)
    .sort((a, b) => b.active_anomalies - a.active_anomalies);

  if (atRisk.length === 0) return null;

  return (
    <div style={{ background: "rgba(255,59,59,0.06)", border: "1px solid rgba(255,59,59,0.2)",
      borderRadius: 4, padding: "12px 16px", marginBottom: 20 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <span style={{ color: "#ff3b3b", fontSize: 11, fontFamily: "monospace",
          fontWeight: 700, letterSpacing: "1px" }}>⚠ USERS WITH ACTIVE ANOMALIES</span>
        <span style={{ background: "rgba(255,59,59,0.2)", color: "#ff3b3b",
          fontSize: 10, fontFamily: "monospace", padding: "1px 7px", borderRadius: 2,
          fontWeight: 700 }}>{atRisk.length}</span>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
        {atRisk.map(u => (
          <button key={u.username} onClick={() => onSelect(u.username)}
            style={{
              background: selected === u.username ? "rgba(255,59,59,0.18)" : "rgba(255,59,59,0.08)",
              border: `1px solid ${selected === u.username ? "rgba(255,59,59,0.6)" : "rgba(255,59,59,0.25)"}`,
              borderRadius: 4, padding: "6px 10px", cursor: "pointer",
              display: "flex", alignItems: "center", gap: 6,
            }}>
            <span style={{ color: "white", fontSize: 11, fontFamily: "monospace" }}>
              {u.username}
            </span>
            <span style={{ background: "rgba(255,59,59,0.25)", color: "#ff3b3b",
              fontSize: 9, fontFamily: "monospace", padding: "1px 5px", borderRadius: 2,
              fontWeight: 700 }}>
              {u.active_anomalies} ⚠
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}

// ── Summary stats bar ──────────────────────────────────────────────────────────
function StatBar({ users }) {
  const total   = users.length;
  const human   = users.filter(u => u.category === "human").length;
  const service = users.filter(u => u.category === "service").length;
  const system  = users.filter(u => u.category === "system").length;
  const atRisk  = users.filter(u => u.active_anomalies > 0).length;

  const stats = [
    { label: "Total",       val: total,   color: "rgba(255,255,255,0.5)" },
    { label: "Human",       val: human,   color: "#00e5a0" },
    { label: "Service",     val: service, color: "#4d9eff" },
    { label: "System",      val: system,  color: "#888" },
    { label: "With Anomaly",val: atRisk,  color: "#ff3b3b" },
  ];

  return (
    <div style={{ display: "flex", gap: 16, marginBottom: 16, flexWrap: "wrap" }}>
      {stats.map(({ label, val, color }) => (
        <div key={label} style={{ display: "flex", flexDirection: "column", alignItems: "center",
          background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
          borderRadius: 4, padding: "8px 14px", minWidth: 70 }}>
          <span style={{ color, fontSize: 18, fontWeight: 700, fontFamily: "monospace" }}>{val}</span>
          <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace",
            marginTop: 2, letterSpacing: "0.5px" }}>{label.toUpperCase()}</span>
        </div>
      ))}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────
export function SiemUebaPage() {
  const [users,           setUsers]           = useState([]);
  const [loading,         setLoading]         = useState(true);
  const [search,          setSearch]          = useState("");
  const [selected,        setSelected]        = useState(null);
  const [activeTab,       setActiveTab]       = useState("all");
  const [integrations,    setIntegrations]    = useState(null);
  const [anomalyStatuses, setAnomalyStatuses] = useState({});

  useEffect(() => {
    siemFetch(siemApi.getUebaUsers()).then(data => {
      if (!data._offline && !data._error) {
        setUsers(Array.isArray(data) ? data : []);
      }
      setLoading(false);
    });
    siemFetch(siemApi.getUebaIntegrations()).then(data => {
      if (data && !data._offline && !data._error) setIntegrations(data);
    });
    // Load persisted UEBA anomaly statuses
    fetch("/api/siem/ueba/anomaly/statuses", { credentials: "include" })
      .then(r => r.ok ? r.json() : {})
      .then(d => setAnomalyStatuses(d))
      .catch(() => {});
  }, []);

  const handleAnomalyStatusChange = (anomalyId, newStatus) =>
    setAnomalyStatuses(prev => ({
      ...prev,
      [anomalyId]: { ...(prev[anomalyId] || {}), status: newStatus },
    }));

  // Apply search + tab filter, then split into groups
  const filtered = useMemo(() => {
    let list = users;

    // Search
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(u => u.username?.toLowerCase().includes(q));
    }

    // Tab filter
    if (activeTab === "anomaly") {
      list = list.filter(u => u.active_anomalies > 0);
    } else if (activeTab === "human") {
      list = list.filter(u => u.category === "human");
    } else if (activeTab === "service") {
      list = list.filter(u => u.category === "service");
    } else if (activeTab === "system") {
      list = list.filter(u => u.category === "system");
    } else if (activeTab === "top20") {
      list = [...list].sort((a, b) => b.avg_daily_events - a.avg_daily_events).slice(0, 20);
    }

    return list;
  }, [users, search, activeTab]);

  // Split by category for grouped view
  const grouped = useMemo(() => {
    const withAnomaly = filtered.filter(u => u.active_anomalies > 0)
      .sort((a, b) => b.active_anomalies - a.active_anomalies);
    const human   = filtered.filter(u => u.category === "human" && u.active_anomalies === 0)
      .sort((a, b) => b.avg_daily_events - a.avg_daily_events);
    const service = filtered.filter(u => u.category === "service" && u.active_anomalies === 0);
    const system  = filtered.filter(u => u.category === "system" && u.active_anomalies === 0);
    return { withAnomaly, human, service, system };
  }, [filtered]);

  const useGrouped = activeTab === "all" || activeTab === "anomaly";

  return (
    <SiemEngineStatus>
      <div>
        {/* Header */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: "white" }}>UEBA</h1>
            <span style={{ background: "rgba(176,110,255,0.12)", color: "#b06eff", fontSize: 10,
              fontFamily: "monospace", padding: "3px 10px", borderRadius: 2, fontWeight: 700,
              letterSpacing: "1px" }}>USER & ENTITY BEHAVIOUR</span>
          </div>
          <p style={{ color: "rgba(255,255,255,0.62)", fontSize: 13, margin: 0 }}>
            Rolling behavioural baselines per user. Human, service, and system accounts are
            automatically classified. Filter to find what matters.
          </p>
        </div>

        {/* Stats bar */}
        {!loading && <StatBar users={users} />}

        {/* Anomaly alert strip — shown in all/anomaly tabs */}
        {!loading && (activeTab === "all" || activeTab === "anomaly") && (
          <AnomalyAlertStrip users={users} selected={selected} onSelect={setSelected} />
        )}

        <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: 20, alignItems: "start" }}>
          {/* ── Left: filter + user list ── */}
          <div>
            {/* Search */}
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search users…"
              style={{ width: "100%", background: "rgba(255,255,255,0.05)",
                border: "1px solid rgba(255,255,255,0.12)", color: "white",
                padding: "8px 12px", borderRadius: 4, fontSize: 12, fontFamily: "monospace",
                marginBottom: 12, boxSizing: "border-box", outline: "none" }} />

            {/* Filter tabs */}
            <div style={{ display: "flex", flexDirection: "column", gap: 2, marginBottom: 16 }}>
              {FILTER_TABS.map(tab => {
                // Count badge per tab
                let count = 0;
                if (tab.id === "all")     count = users.length;
                else if (tab.id === "anomaly")  count = users.filter(u => u.active_anomalies > 0).length;
                else if (tab.id === "human")    count = users.filter(u => u.category === "human").length;
                else if (tab.id === "service")  count = users.filter(u => u.category === "service").length;
                else if (tab.id === "system")   count = users.filter(u => u.category === "system").length;
                else if (tab.id === "top20")    count = Math.min(users.length, 20);

                const isActive = activeTab === tab.id;
                return (
                  <button key={tab.id} onClick={() => { setActiveTab(tab.id); setSelected(null); }}
                    style={{
                      background: isActive ? "rgba(176,110,255,0.12)" : "rgba(255,255,255,0.02)",
                      border: `1px solid ${isActive ? "rgba(176,110,255,0.4)" : "rgba(255,255,255,0.06)"}`,
                      borderRadius: 4, padding: "8px 12px", cursor: "pointer",
                      display: "flex", alignItems: "center", gap: 8, textAlign: "left",
                    }}>
                    <span style={{ fontSize: 12 }}>{tab.icon}</span>
                    <span style={{ color: isActive ? "#b06eff" : "rgba(255,255,255,0.6)",
                      fontSize: 12, fontFamily: "monospace", flex: 1 }}>
                      {tab.label}
                    </span>
                    <span style={{ background: isActive ? "rgba(176,110,255,0.2)" : "rgba(255,255,255,0.05)",
                      color: isActive ? "#b06eff" : "rgba(255,255,255,0.3)",
                      fontSize: 10, fontFamily: "monospace", padding: "1px 6px", borderRadius: 2 }}>
                      {count}
                    </span>
                  </button>
                );
              })}
            </div>

            <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: 14 }}>
              {loading ? (
                <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, padding: "20px 0" }}>
                  Loading users…
                </div>
              ) : filtered.length === 0 ? (
                <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, padding: "20px 0" }}>
                  {search ? "No users match your search." : "No UEBA baselines yet."}
                </div>
              ) : useGrouped ? (
                <>
                  <UserGroup title="With Active Anomaly" icon="⚠" color="#ff3b3b"
                    users={grouped.withAnomaly} selected={selected} onSelect={setSelected}
                    defaultOpen={true} />
                  <UserGroup title="Human Users" icon="👤" color="#00e5a0"
                    users={grouped.human} selected={selected} onSelect={setSelected}
                    defaultOpen={grouped.human.length <= 20} />
                  <UserGroup title="Service Accounts" icon="⚙️" color="#4d9eff"
                    users={grouped.service} selected={selected} onSelect={setSelected}
                    defaultOpen={false} />
                  <UserGroup title="System Accounts" icon="🖥️" color="#888"
                    users={grouped.system} selected={selected} onSelect={setSelected}
                    defaultOpen={false} />
                </>
              ) : (
                /* Flat list for single-category or top20 views */
                <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                  {filtered.map(u => {
                    const isSelected = selected === u.username;
                    return (
                      <button key={u.username} onClick={() => setSelected(u.username)}
                        style={{
                          background: isSelected ? "rgba(176,110,255,0.1)" : "rgba(255,255,255,0.01)",
                          border: `1px solid ${isSelected ? "rgba(176,110,255,0.4)" : "rgba(255,255,255,0.06)"}`,
                          borderRadius: 4, padding: "8px 10px", cursor: "pointer", textAlign: "left",
                        }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
                          gap: 6, marginBottom: 4 }}>
                          <span style={{ color: "white", fontSize: 12, fontFamily: "monospace",
                            fontWeight: isSelected ? 700 : 400, overflow: "hidden",
                            textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
                            {u.username}
                          </span>
                          <AnomalyBadge active={u.active_anomalies} total={u.total_anomalies} />
                        </div>
                        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                          <CategoryBadge category={u.category} small />
                          {u.avg_daily_events > 0 && activeTab === "top20" && (
                            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 9,
                              fontFamily: "monospace" }}>
                              ~{Math.round(u.avg_daily_events)} evt/day
                            </span>
                          )}
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* ── Right: profile panel ── */}
          <div>
            {!selected ? (
              <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, padding: "40px 0",
                textAlign: "center" }}>
                <div style={{ fontSize: 32, marginBottom: 12 }}>👤</div>
                Select a user from the list to view their UEBA profile, behavioural baseline,
                and anomaly timeline.
              </div>
            ) : (
              <div>
                {/* Profile header */}
                {(() => {
                  const u = users.find(x => x.username === selected);
                  return (
                    <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20,
                      padding: "14px 16px",
                      background: "rgba(255,255,255,0.02)",
                      border: "1px solid rgba(255,255,255,0.08)", borderRadius: 4 }}>
                      <span style={{ fontSize: 22 }}>
                        {u ? CATEGORY_META[u.category]?.icon : "👤"}
                      </span>
                      <div style={{ flex: 1 }}>
                        <div style={{ color: "white", fontSize: 16, fontWeight: 700,
                          fontFamily: "monospace", marginBottom: 4 }}>
                          {selected}
                        </div>
                        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                          {u && <CategoryBadge category={u.category} />}
                          {u && u.active_anomalies > 0 && (
                            <AnomalyBadge active={u.active_anomalies} total={u.total_anomalies} />
                          )}
                          {u && (
                            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 11 }}>
                              {u.description}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })()}
                <UserProfile username={selected} integrations={integrations}
                  anomalyStatuses={anomalyStatuses}
                  onStatusChange={handleAnomalyStatusChange} />
              </div>
            )}
          </div>
        </div>
      </div>
    </SiemEngineStatus>
  );
}
