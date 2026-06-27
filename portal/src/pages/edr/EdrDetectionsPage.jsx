/**
 * pages/edr/EdrDetectionsPage.jsx — EDR Detections & Alerts Feed
 *
 * Shows behavioral detections from enrolled agents with severity breakdown,
 * MITRE ATT&CK mapping, confidence score, and analyst actions.
 */
import React, { useEffect, useState, useCallback } from "react";

const CARD_BG     = "rgba(255,255,255,0.03)";
const CARD_BORDER = "1px solid rgba(255,255,255,0.07)";
const ACCENT      = "#00e5a0";

const SEV_CFG = {
  critical: { color: "#ff3b3b", bg: "rgba(255,59,59,0.12)",  label: "CRITICAL" },
  high:     { color: "#ff8c00", bg: "rgba(255,140,0,0.12)",  label: "HIGH"     },
  medium:   { color: "#f5c518", bg: "rgba(245,197,24,0.12)", label: "MEDIUM"   },
  low:      { color: "#00e5a0", bg: "rgba(0,229,160,0.12)",  label: "LOW"      },
};

const STATUS_CFG = {
  open:           { color: "#ff3b3b", label: "Open"           },
  investigating:  { color: "#f5c518", label: "Investigating"  },
  in_review:      { color: "#4d9eff", label: "In Review"      },
  resolved:       { color: "#00e5a0", label: "Resolved"       },
  false_positive: { color: "#888",    label: "False Positive" },
};

function SevBadge({ severity }) {
  const cfg = SEV_CFG[severity] || SEV_CFG.low;
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, letterSpacing: 1,
      padding: "2px 8px", borderRadius: 4,
      color: cfg.color, background: cfg.bg,
    }}>{cfg.label}</span>
  );
}

function ScoreBar({ score }) {
  const color = score >= 75 ? "#ff3b3b" : score >= 50 ? "#ff8c00" : score >= 25 ? "#f5c518" : "#00e5a0";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ width: 80, height: 5, background: "#1a2035", borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: `${score}%`, height: "100%", background: color, borderRadius: 3 }} />
      </div>
      <span style={{ fontSize: 11, color, fontWeight: 700 }}>{score?.toFixed(0)}</span>
    </div>
  );
}

function DetectionRow({ det, onStatusChange, onResponseAction }) {
  const [expanded, setExpanded] = useState(false);
  const sevCfg = SEV_CFG[det.severity] || SEV_CFG.low;
  const stCfg  = STATUS_CFG[det.status] || { color: "#888", label: det.status };

  const triggers = Array.isArray(det.triggers) ? det.triggers : [];

  return (
    <div style={{
      background: CARD_BG, border: CARD_BORDER, borderRadius: 10, marginBottom: 8,
      borderLeft: `3px solid ${sevCfg.color}`,
    }}>
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          padding: "12px 16px", cursor: "pointer",
          display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
        }}
      >
        <SevBadge severity={det.severity} />
        <ScoreBar score={parseFloat(det.score) || 0} />
        <div style={{ flex: 1, minWidth: 200 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "#e8eaf0" }}>{det.rule_desc}</div>
          <div style={{ fontSize: 11, color: "#666", marginTop: 2 }}>
            {det.hostname || det.agent_id?.slice(0, 8)} · {det.process_name || "—"} ·{" "}
            {det.event_category}
          </div>
        </div>
        {det.mitre_id && (
          <span style={{
            fontSize: 10, color: "#b06eff", border: "1px solid #b06eff44",
            borderRadius: 4, padding: "2px 7px", whiteSpace: "nowrap",
          }}>{det.mitre_id}</span>
        )}
        <span style={{ fontSize: 11, color: stCfg.color, fontWeight: 600 }}>{stCfg.label}</span>
        <span style={{ fontSize: 11, color: "#555", whiteSpace: "nowrap" }}>
          {det.detected_at ? new Date(det.detected_at).toLocaleString() : "—"}
        </span>
        <span style={{ color: "#555", fontSize: 14 }}>{expanded ? "▲" : "▼"}</span>
      </div>

      {expanded && (
        <div style={{ padding: "0 16px 16px", borderTop: "1px solid rgba(255,255,255,0.05)" }}>
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginTop: 14, marginBottom: 14 }}>
            <Detail label="Agent"        value={det.hostname || det.agent_id} />
            <Detail label="OS Type"      value={det.os_type} />
            <Detail label="Asset Type"   value={det.asset_type} />
            <Detail label="Rule ID"      value={det.rule_id} />
            <Detail label="MITRE Tactic" value={det.mitre_tactic || "—"} />
            <Detail label="Src IP"       value={det.src_ip || "—"} />
            <Detail label="Dst IP"       value={det.dst_ip || "—"} />
            <Detail label="Username"     value={det.username || "—"} />
            <Detail label="File Path"    value={det.file_path || "—"} mono />
            <Detail label="TI Match"     value={det.ti_match ? "YES" : "No"}
              color={det.ti_match ? "#ff3b3b" : "#555"} />
          </div>

          {triggers.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: "#555", marginBottom: 6 }}>Triggers</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {triggers.map(t => (
                  <span key={t} style={{
                    fontSize: 11, border: "1px solid rgba(255,140,0,0.3)",
                    borderRadius: 4, padding: "2px 8px", color: "#ff8c00",
                  }}>{t.replace(/_/g, " ")}</span>
                ))}
              </div>
            </div>
          )}

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }}>
            <ActionBtn label="Mark Investigating" color="#f5c518"
              onClick={() => onStatusChange(det.id, "investigating")} />
            <ActionBtn label="Mark Resolved"      color="#00e5a0"
              onClick={() => onStatusChange(det.id, "resolved")} />
            <ActionBtn label="False Positive"     color="#888"
              onClick={() => onStatusChange(det.id, "false_positive")} />
            <ActionBtn label="Isolate Endpoint"   color="#ff3b3b"
              onClick={() => onResponseAction("isolate", det)} />
            <ActionBtn label="Kill Process"       color="#ff8c00"
              onClick={() => onResponseAction("kill", det)} />
            <ActionBtn label="Collect Forensics"  color="#b06eff"
              onClick={() => onResponseAction("forensics", det)} />
          </div>
        </div>
      )}
    </div>
  );
}

function Detail({ label, value, mono, color }) {
  return (
    <div style={{ minWidth: 110 }}>
      <div style={{ fontSize: 10, color: "#555", marginBottom: 2 }}>{label}</div>
      <div style={{
        fontSize: 11, color: color || "#9aa0b0",
        fontFamily: mono ? "monospace" : "inherit",
        wordBreak: "break-all", maxWidth: 220,
      }}>{value || "—"}</div>
    </div>
  );
}

function ActionBtn({ label, color, onClick }) {
  const [h, setH] = useState(false);
  return (
    <button onClick={onClick}
      onMouseEnter={() => setH(true)} onMouseLeave={() => setH(false)}
      style={{
        border: `1px solid ${color}44`, borderRadius: 6,
        background: h ? `${color}22` : "transparent",
        color, fontSize: 11, fontWeight: 600, padding: "4px 10px",
        cursor: "pointer", transition: "all 0.15s",
      }}
    >{label}</button>
  );
}

function Filters({ severity, setSeverity, status, setStatus, agentId, setAgentId }) {
  const style = {
    background: CARD_BG, border: CARD_BORDER, borderRadius: 6, color: "#e8eaf0",
    padding: "6px 10px", fontSize: 12, cursor: "pointer",
  };
  return (
    <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 20 }}>
      <select style={style} value={severity} onChange={e => setSeverity(e.target.value)}>
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <select style={style} value={status} onChange={e => setStatus(e.target.value)}>
        <option value="">All Statuses</option>
        <option value="open">Open</option>
        <option value="investigating">Investigating</option>
        <option value="in_review">In Review</option>
        <option value="resolved">Resolved</option>
        <option value="false_positive">False Positive</option>
      </select>
      <input
        placeholder="Filter by Agent ID…"
        value={agentId} onChange={e => setAgentId(e.target.value)}
        style={{ ...style, width: 180 }}
      />
    </div>
  );
}

export default function EdrDetectionsPage() {
  const [detections, setDetections] = useState([]);
  const [total,      setTotal]      = useState(0);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState(null);
  const [severity,   setSeverity]   = useState("");
  const [status,     setStatus]     = useState("open");
  const [agentId,    setAgentId]    = useState("");
  const [offset,     setOffset]     = useState(0);
  const LIMIT = 50;

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    const params = new URLSearchParams({ limit: LIMIT, offset });
    if (severity) params.set("severity", severity);
    if (status)   params.set("status",   status);
    if (agentId)  params.set("agent_id", agentId);
    try {
      const res = await fetch(`/api/edr/detections?${params}`);
      if (!res.ok) throw new Error(`${res.status}`);
      const data = await res.json();
      setDetections(data.detections || []);
      setTotal(data.total || 0);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [severity, status, agentId, offset]);

  useEffect(() => { load(); }, [load]);

  const handleStatusChange = async (detId, newStatus) => {
    try {
      await fetch(`/api/edr/detections/${detId}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      await load();
    } catch (e) {
      setError(e.message);
    }
  };

  const handleResponseAction = async (action, det) => {
    const endpoints = {
      isolate:   `/api/edr/response/${det.agent_id}/isolate`,
      kill:      `/api/edr/response/${det.agent_id}/kill-process`,
      forensics: `/api/edr/response/${det.agent_id}/collect-forensics`,
    };
    const url = endpoints[action];
    if (!url) return;
    const body = {
      detection_id: det.id,
      reason: `Manual action from detections console`,
      ...(action === "kill" ? { image_name: det.process_name } : {}),
    };
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`${res.status}`);
    } catch (e) {
      setError(`Response action failed: ${e.message}`);
    }
  };

  return (
    <div style={{ padding: "28px 32px", minHeight: "100vh", background: "#0a0e1a" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800, color: "#e8eaf0" }}>EDR Detections</h1>
          <div style={{ fontSize: 12, color: "#555", marginTop: 4 }}>
            Behavioral detections from all enrolled endpoints — {total.toLocaleString()} total
          </div>
        </div>
        <button onClick={load} style={{
          border: `1px solid ${ACCENT}44`, borderRadius: 6, background: "transparent",
          color: ACCENT, padding: "6px 14px", fontWeight: 600, cursor: "pointer", fontSize: 12,
        }}>Refresh</button>
      </div>

      <Filters
        severity={severity} setSeverity={v => { setSeverity(v); setOffset(0); }}
        status={status}     setStatus={v => { setStatus(v); setOffset(0); }}
        agentId={agentId}   setAgentId={v => { setAgentId(v); setOffset(0); }}
      />

      {error && (
        <div style={{
          background: "#ff3b3b22", border: "1px solid #ff3b3b44", borderRadius: 8,
          padding: "12px 16px", color: "#ff7070", fontSize: 13, marginBottom: 16,
        }}>{error}</div>
      )}

      {loading ? (
        <div style={{ textAlign: "center", color: "#555", padding: 40, fontSize: 13 }}>
          Loading detections…
        </div>
      ) : detections.length === 0 ? (
        <div style={{ textAlign: "center", color: "#555", padding: 60, fontSize: 13 }}>
          No detections match the current filters.
        </div>
      ) : (
        <>
          {detections.map(det => (
            <DetectionRow
              key={det.id}
              det={det}
              onStatusChange={handleStatusChange}
              onResponseAction={handleResponseAction}
            />
          ))}
          <div style={{ display: "flex", gap: 10, justifyContent: "center", marginTop: 20 }}>
            <button
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - LIMIT))}
              style={{
                border: `1px solid ${ACCENT}44`, borderRadius: 6, background: "transparent",
                color: offset === 0 ? "#555" : ACCENT, padding: "6px 16px",
                cursor: offset === 0 ? "default" : "pointer", fontSize: 12,
              }}
            >← Previous</button>
            <span style={{ color: "#555", fontSize: 12, alignSelf: "center" }}>
              {offset + 1}–{Math.min(offset + LIMIT, total)} of {total}
            </span>
            <button
              disabled={offset + LIMIT >= total}
              onClick={() => setOffset(offset + LIMIT)}
              style={{
                border: `1px solid ${ACCENT}44`, borderRadius: 6, background: "transparent",
                color: offset + LIMIT >= total ? "#555" : ACCENT, padding: "6px 16px",
                cursor: offset + LIMIT >= total ? "default" : "pointer", fontSize: 12,
              }}
            >Next →</button>
          </div>
        </>
      )}
    </div>
  );
}
