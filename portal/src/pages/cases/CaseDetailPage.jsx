/**
 * CaseDetailPage.jsx
 * ==================
 * Tabbed detail view for a single case. Accepts `incidentId` as a prop
 * (App.jsx passes it when activeTab === "cases-detail").
 *
 * Tabs: Overview | Comments | IOCs | Evidence | Checklist | Graph
 */

import { useState, useEffect, useRef, useCallback } from "react";

// ── Palette ───────────────────────────────────────────────────────────────────
const C = {
  bg:      "#090b10",
  surface: "#0d1117",
  card:    "#111520",
  border:  "rgba(255,255,255,0.07)",
  text:    "rgba(255,255,255,0.82)",
  muted:   "rgba(255,255,255,0.38)",
  dim:     "rgba(255,255,255,0.22)",
  accent:  "#00e5a0",
  red:     "#ff3b3b",
  orange:  "#ff8c00",
  blue:    "#4d9eff",
  purple:  "#b06eff",
  yellow:  "#f5c518",
  teal:    "#00e5a0",
};

const SEV_CFG = {
  critical: { color: "#ff3b3b", bg: "rgba(255,59,59,0.12)",   label: "CRITICAL" },
  high:     { color: "#ff8c00", bg: "rgba(255,140,0,0.12)",   label: "HIGH"     },
  medium:   { color: "#4d9eff", bg: "rgba(77,158,255,0.12)",  label: "MEDIUM"   },
  low:      { color: "#888888", bg: "rgba(136,136,136,0.12)", label: "LOW"      },
};

const STATUS_OPTIONS = [
  { value: "open",          label: "Open"          },
  { value: "investigating", label: "Investigating" },
  { value: "in_review",     label: "In Review"     },
  { value: "resolved",      label: "Resolved"      },
  { value: "closed",        label: "Closed"        },
];

const IOC_TYPES = ["ip", "domain", "hash", "url", "email", "filename", "other"];

// ── Graph node colours ────────────────────────────────────────────────────────
const GRAPH_COLORS = {
  incident: "#ff3b3b",
  alert:    "#ff8c00",
  host:     "#4d9eff",
  user:     "#b06eff",
  ioc:      "#ffd166",
  ip:       "#00e5a0",
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtTs(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("en-US", {
      month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit",
    });
  } catch { return iso; }
}

function fmtMttd(s) {
  if (!s && s !== 0) return "—";
  return `${Math.round(s / 3600)}h`;
}

// ── Shared UI primitives ──────────────────────────────────────────────────────
function SevBadge({ severity }) {
  const cfg = SEV_CFG[severity] || SEV_CFG.low;
  return (
    <span style={{
      background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40`,
      fontSize: 9, fontWeight: 700, fontFamily: "monospace",
      padding: "2px 7px", borderRadius: 2, letterSpacing: "0.8px",
    }}>{cfg.label}</span>
  );
}

function Pill({ label, color }) {
  return (
    <span style={{
      background: `${color}14`, color, border: `1px solid ${color}28`,
      fontSize: 10, fontFamily: "monospace", fontWeight: 700,
      padding: "3px 9px", borderRadius: 10,
    }}>{label}</span>
  );
}

function Chip({ label, color }) {
  return (
    <span style={{
      background: `${color}14`, color, border: `1px solid ${color}22`,
      fontSize: 9, fontFamily: "monospace",
      padding: "2px 6px", borderRadius: 3,
    }}>{label}</span>
  );
}

function SectionLabel({ children }) {
  return (
    <div style={{
      color: C.dim, fontSize: 9, fontFamily: "monospace",
      letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 6, marginTop: 18,
    }}>{children}</div>
  );
}

function InfoRow({ label, value }) {
  return (
    <div style={{ display: "flex", gap: 12, alignItems: "flex-start", marginBottom: 8 }}>
      <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace", width: 130, flexShrink: 0 }}>{label}</div>
      <div style={{ color: C.text, fontSize: 11, fontFamily: "monospace", wordBreak: "break-all" }}>{value || "—"}</div>
    </div>
  );
}

function Spinner({ size = 28 }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "60px 0" }}>
      <div style={{
        width: size, height: size, borderRadius: "50%",
        border: `2px solid rgba(255,255,255,0.08)`,
        borderTop: `2px solid ${C.accent}`,
        animation: "spin 0.8s linear infinite",
      }} />
    </div>
  );
}

function ErrorState({ message, onRetry }) {
  return (
    <div style={{ padding: "40px 20px", textAlign: "center", color: C.red, fontFamily: "monospace", fontSize: 12 }}>
      <div style={{ marginBottom: 8 }}>Failed to load</div>
      <div style={{ color: C.muted, fontSize: 10, marginBottom: 16 }}>{message}</div>
      {onRetry && (
        <button onClick={onRetry} style={{
          background: "rgba(255,59,59,0.1)", border: `1px solid ${C.red}40`,
          color: C.red, padding: "6px 14px", borderRadius: 3,
          fontFamily: "monospace", fontSize: 11, cursor: "pointer",
        }}>Retry</button>
      )}
    </div>
  );
}

// ── Tab bar ───────────────────────────────────────────────────────────────────
const TABS = ["Overview", "Comments", "IOCs", "Evidence", "Checklist", "Graph"];

function TabBar({ active, onChange }) {
  return (
    <div style={{ display: "flex", borderBottom: `1px solid ${C.border}`, marginBottom: 0 }}>
      {TABS.map(t => (
        <button key={t} onClick={() => onChange(t)} style={{
          background: "none", border: "none",
          borderBottom: active === t ? `2px solid ${C.accent}` : "2px solid transparent",
          color: active === t ? C.accent : C.muted,
          padding: "10px 18px", cursor: "pointer",
          fontFamily: "monospace", fontSize: 11, fontWeight: active === t ? 700 : 400,
          transition: "color 0.15s",
          marginBottom: -1,
        }}>{t}</button>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// TAB: Overview
// ─────────────────────────────────────────────────────────────────────────────
function OverviewTab({ caseData }) {
  const inc = caseData || {};
  return (
    <div style={{ padding: "20px 0" }}>
      {/* KPI pills */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 24 }}>
        <Pill label={`MTTD ${fmtMttd(inc.case_mttd_seconds)}`} color={C.blue} />
        {inc.case_mtta_seconds != null && (
          <Pill label={`MTTA ${fmtMttd(inc.case_mtta_seconds)}`} color={C.purple} />
        )}
        <Pill label={(inc.status || "unknown").toUpperCase().replace(/_/g, " ")} color={C.accent} />
        <SevBadge severity={inc.severity} />
      </div>

      {/* Core info */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 32px" }}>
        <div>
          <SectionLabel>Case Details</SectionLabel>
          <InfoRow label="Incident ID"   value={inc.incident_id} />
          <InfoRow label="Type"          value={(inc.incident_type || "—").replace(/_/g, " ")} />
          <InfoRow label="Assigned To"   value={inc.assigned_to} />
          <InfoRow label="Opened At"     value={fmtTs(inc.case_opened_at)} />
          <InfoRow label="Last Updated"  value={fmtTs(inc.updated_at)} />
        </div>
        <div>
          <SectionLabel>Scope</SectionLabel>
          {(inc.affected_hosts?.length > 0) && (
            <>
              <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace", marginBottom: 4 }}>Affected Hosts</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginBottom: 12 }}>
                {inc.affected_hosts.map(h => <Chip key={h} label={h} color={C.blue} />)}
              </div>
            </>
          )}
          {(inc.affected_users?.length > 0) && (
            <>
              <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace", marginBottom: 4 }}>Affected Users</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginBottom: 12 }}>
                {inc.affected_users.map(u => <Chip key={u} label={u} color={C.purple} />)}
              </div>
            </>
          )}
          {(inc.source_ips?.length > 0) && (
            <>
              <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace", marginBottom: 4 }}>Source IPs</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginBottom: 12 }}>
                {inc.source_ips.map(ip => <Chip key={ip} label={ip} color={C.teal} />)}
              </div>
            </>
          )}
        </div>
      </div>

      {/* MITRE tactics */}
      {(inc.mitre_tactics?.length > 0) && (
        <>
          <SectionLabel>MITRE ATT&CK Tactics</SectionLabel>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
            {inc.mitre_tactics.map(t => <Chip key={t} label={t} color={C.orange} />)}
          </div>
        </>
      )}

      {/* LLM Summary */}
      {inc.llm_summary && (
        <>
          <SectionLabel>AI Summary</SectionLabel>
          <div style={{
            background: "rgba(77,158,255,0.04)", border: `1px solid rgba(77,158,255,0.12)`,
            borderRadius: 4, padding: "14px 16px",
            color: C.text, fontSize: 12, lineHeight: 1.7,
          }}>{inc.llm_summary}</div>
        </>
      )}

      {/* LLM Remediation */}
      {inc.llm_remediation && (
        <>
          <SectionLabel>AI Remediation Guidance</SectionLabel>
          <div style={{
            background: "rgba(0,229,160,0.03)", border: `1px solid rgba(0,229,160,0.12)`,
            borderRadius: 4, padding: "14px 16px",
            color: C.text, fontSize: 12, lineHeight: 1.7,
          }}>{inc.llm_remediation}</div>
        </>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// TAB: Comments
// ─────────────────────────────────────────────────────────────────────────────
function CommentsTab({ caseId, initialComments }) {
  const [comments, setComments] = useState(initialComments || []);
  const [body, setBody]         = useState("");
  const [posting, setPosting]   = useState(false);
  const [err, setErr]           = useState("");
  const pollRef                 = useRef(null);
  const feedRef                 = useRef(null);

  const fetchComments = useCallback(() => {
    fetch(`/api/cases/${caseId}/comments`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => setComments(d.comments || d || []))
      .catch(() => {});
  }, [caseId]);

  useEffect(() => {
    fetchComments();
    pollRef.current = setInterval(fetchComments, 15_000);
    return () => clearInterval(pollRef.current);
  }, [fetchComments]);

  // scroll to bottom on new comment
  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [comments.length]);

  const handlePost = async () => {
    const text = body.trim();
    if (!text) return;
    setPosting(true); setErr("");
    try {
      const r = await fetch(`/api/cases/${caseId}/comments`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ body: text }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setBody("");
      fetchComments();
    } catch (e) {
      setErr(e.message);
    } finally {
      setPosting(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", padding: "16px 0" }}>
      {/* Feed */}
      <div ref={feedRef} style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: 10, marginBottom: 16 }}>
        {comments.length === 0 ? (
          <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 11, textAlign: "center", padding: "30px 0" }}>
            No comments yet
          </div>
        ) : comments.map((c, i) => (
          <div key={c.id || i} style={{
            background: c.is_system ? "rgba(255,255,255,0.02)" : C.surface,
            border: `1px solid ${C.border}`,
            borderLeft: c.is_system ? `3px solid rgba(255,255,255,0.12)` : `3px solid ${C.blue}40`,
            borderRadius: 3, padding: "10px 14px",
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
              <span style={{
                color: c.is_system ? C.dim : C.accent,
                fontSize: 10, fontFamily: "monospace", fontWeight: 600,
              }}>
                {c.is_system ? "SYSTEM" : (c.author || "analyst")}
              </span>
              <span style={{ color: C.dim, fontSize: 9, fontFamily: "monospace" }}>{fmtTs(c.created_at)}</span>
            </div>
            <div style={{
              color: c.is_system ? C.muted : C.text,
              fontSize: 12, lineHeight: 1.6,
              fontStyle: c.is_system ? "italic" : "normal",
            }}>{c.body}</div>
          </div>
        ))}
      </div>

      {/* Input */}
      <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 14 }}>
        <textarea
          value={body}
          onChange={e => setBody(e.target.value)}
          onKeyDown={e => { if (e.key === "Enter" && e.ctrlKey) handlePost(); }}
          placeholder="Add a comment… (Ctrl+Enter to submit)"
          rows={3}
          style={{
            width: "100%", boxSizing: "border-box",
            background: C.bg, border: `1px solid rgba(255,255,255,0.1)`,
            color: C.text, padding: "9px 12px", borderRadius: 3,
            fontFamily: "monospace", fontSize: 12, resize: "vertical", outline: "none",
          }}
        />
        {err && <div style={{ color: C.red, fontSize: 10, fontFamily: "monospace", marginTop: 4 }}>{err}</div>}
        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 8 }}>
          <button
            onClick={handlePost}
            disabled={posting || !body.trim()}
            style={{
              background: "rgba(0,229,160,0.1)", border: `1px solid ${C.accent}35`,
              color: C.accent, padding: "7px 18px", borderRadius: 3,
              fontFamily: "monospace", fontSize: 11, fontWeight: 700,
              cursor: posting || !body.trim() ? "not-allowed" : "pointer",
              opacity: !body.trim() ? 0.5 : 1,
            }}
          >{posting ? "Posting…" : "Add Comment"}</button>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// TAB: IOCs
// ─────────────────────────────────────────────────────────────────────────────
function IOCsTab({ caseId, initialIocs }) {
  const [iocs, setIocs]       = useState(initialIocs || []);
  const [form, setForm]       = useState({ value: "", type: "ip", context_note: "" });
  const [adding, setAdding]   = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [err, setErr]         = useState("");

  const fetchIocs = useCallback(() => {
    fetch(`/api/cases/${caseId}/iocs`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => setIocs(d.iocs || d || []))
      .catch(() => {});
  }, [caseId]);

  const handleAdd = async () => {
    if (!form.value.trim()) { setErr("IOC value required."); return; }
    setAdding(true); setErr("");
    try {
      const r = await fetch(`/api/cases/${caseId}/iocs`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setForm({ value: "", type: "ip", context_note: "" });
      setShowForm(false);
      fetchIocs();
    } catch (e) {
      setErr(e.message);
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (iocId) => {
    if (!window.confirm("Remove this IOC?")) return;
    try {
      const r = await fetch(`/api/cases/${caseId}/iocs/${iocId}`, {
        method: "DELETE", credentials: "include",
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      fetchIocs();
    } catch (e) {
      alert(`Remove failed: ${e.message}`);
    }
  };

  const iocTypeColor = { ip: C.teal, domain: C.blue, hash: C.orange, url: C.purple, email: C.yellow, filename: C.muted, other: C.dim };

  return (
    <div style={{ padding: "16px 0" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>{iocs.length} indicator{iocs.length !== 1 ? "s" : ""}</div>
        <button onClick={() => setShowForm(v => !v)} style={{
          background: "rgba(0,229,160,0.08)", border: `1px solid ${C.accent}30`,
          color: C.accent, padding: "5px 14px", borderRadius: 3,
          fontFamily: "monospace", fontSize: 10, fontWeight: 700, cursor: "pointer",
        }}>+ Add IOC</button>
      </div>

      {/* Add form */}
      {showForm && (
        <div style={{
          background: C.surface, border: `1px solid ${C.border}`,
          borderRadius: 4, padding: 16, marginBottom: 14,
          display: "grid", gridTemplateColumns: "1fr 120px 1fr auto", gap: 8, alignItems: "end",
        }}>
          <div>
            <div style={{ color: C.dim, fontSize: 9, fontFamily: "monospace", marginBottom: 4 }}>VALUE</div>
            <input
              value={form.value} onChange={e => setForm(f => ({ ...f, value: e.target.value }))}
              placeholder="e.g. 1.2.3.4 or evil.com"
              style={{ width: "100%", boxSizing: "border-box", background: C.bg, border: `1px solid rgba(255,255,255,0.1)`, color: C.text, padding: "7px 10px", borderRadius: 3, fontFamily: "monospace", fontSize: 11, outline: "none" }}
            />
          </div>
          <div>
            <div style={{ color: C.dim, fontSize: 9, fontFamily: "monospace", marginBottom: 4 }}>TYPE</div>
            <select value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))}
              style={{ width: "100%", background: C.bg, border: `1px solid rgba(255,255,255,0.1)`, color: C.text, padding: "7px 8px", borderRadius: 3, fontFamily: "monospace", fontSize: 11, outline: "none" }}>
              {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <div style={{ color: C.dim, fontSize: 9, fontFamily: "monospace", marginBottom: 4 }}>NOTE (optional)</div>
            <input
              value={form.context_note} onChange={e => setForm(f => ({ ...f, context_note: e.target.value }))}
              placeholder="Context or source"
              style={{ width: "100%", boxSizing: "border-box", background: C.bg, border: `1px solid rgba(255,255,255,0.1)`, color: C.text, padding: "7px 10px", borderRadius: 3, fontFamily: "monospace", fontSize: 11, outline: "none" }}
            />
          </div>
          <button onClick={handleAdd} disabled={adding} style={{
            background: "rgba(0,229,160,0.1)", border: `1px solid ${C.accent}35`,
            color: C.accent, padding: "7px 14px", borderRadius: 3,
            fontFamily: "monospace", fontSize: 10, fontWeight: 700, cursor: "pointer",
          }}>{adding ? "…" : "Add"}</button>
          {err && <div style={{ gridColumn: "1/-1", color: C.red, fontSize: 10, fontFamily: "monospace" }}>{err}</div>}
        </div>
      )}

      {/* IOC table */}
      {iocs.length === 0 ? (
        <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 11, textAlign: "center", padding: "30px 0" }}>No IOCs added</div>
      ) : (
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, overflow: "hidden" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 80px 100px 120px 1fr 36px", padding: "7px 14px", background: "rgba(255,255,255,0.02)", borderBottom: `1px solid ${C.border}` }}>
            {["VALUE", "TYPE", "THREAT LVL", "ADDED BY", "NOTE", ""].map(h => (
              <div key={h} style={{ color: C.dim, fontSize: 8, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px" }}>{h}</div>
            ))}
          </div>
          {iocs.map((ioc, i) => (
            <div key={ioc.id || i} style={{
              display: "grid", gridTemplateColumns: "1fr 80px 100px 120px 1fr 36px",
              padding: "9px 14px", alignItems: "center",
              borderBottom: i < iocs.length - 1 ? `1px solid rgba(255,255,255,0.03)` : "none",
              background: i % 2 === 1 ? "rgba(255,255,255,0.01)" : "transparent",
            }}>
              <div style={{ color: C.text, fontSize: 11, fontFamily: "monospace", wordBreak: "break-all" }}>{ioc.value}</div>
              <div>
                <Chip label={ioc.ioc_type || ioc.type || "—"} color={iocTypeColor[ioc.ioc_type || ioc.type] || C.dim} />
              </div>
              <div>
                {ioc.misp_threat_level ? (
                  <Chip label={`TLP:${ioc.misp_threat_level}`} color={C.orange} />
                ) : <span style={{ color: C.dim, fontSize: 10 }}>—</span>}
              </div>
              <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>{ioc.added_by || "—"}</div>
              <div style={{ color: C.muted, fontSize: 11, fontStyle: "italic" }}>{ioc.context_note || "—"}</div>
              <div>
                <button onClick={() => handleRemove(ioc.id)} style={{
                  background: "none", border: "none", color: C.dim, cursor: "pointer",
                  fontSize: 12, padding: "2px 4px", borderRadius: 2,
                }} title="Remove">✕</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// TAB: Evidence
// ─────────────────────────────────────────────────────────────────────────────
function EvidenceTab({ caseId, initialEvidence }) {
  const [evidence, setEvidence]   = useState(initialEvidence || []);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress]   = useState(0);
  const [err, setErr]             = useState("");
  const fileRef                   = useRef(null);
  const dropRef                   = useRef(null);
  const [dragOver, setDragOver]   = useState(false);

  const fetchEvidence = useCallback(() => {
    fetch(`/api/cases/${caseId}/evidence`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => setEvidence(d.evidence || d || []))
      .catch(() => {});
  }, [caseId]);

  const uploadFile = async (file) => {
    setUploading(true); setProgress(0); setErr("");
    const fd = new FormData();
    fd.append("file", file);

    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `/api/cases/${caseId}/evidence`);
      xhr.withCredentials = true;
      xhr.upload.onprogress = e => {
        if (e.lengthComputable) setProgress(Math.round((e.loaded / e.total) * 100));
      };
      xhr.onload = () => {
        setUploading(false);
        if (xhr.status < 300) { fetchEvidence(); resolve(); }
        else { setErr(`Upload failed: HTTP ${xhr.status}`); reject(); }
      };
      xhr.onerror = () => { setUploading(false); setErr("Network error"); reject(); };
      xhr.send(fd);
    });
  };

  const handleFiles = (files) => {
    if (!files?.length) return;
    uploadFile(files[0]).catch(() => {});
  };

  const handleDrop = (e) => {
    e.preventDefault(); setDragOver(false);
    handleFiles(e.dataTransfer.files);
  };

  const handleDragOver = (e) => { e.preventDefault(); setDragOver(true); };
  const handleDragLeave = () => setDragOver(false);

  return (
    <div style={{ padding: "16px 0" }}>
      {/* Drop zone */}
      <div
        ref={dropRef}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => !uploading && fileRef.current?.click()}
        style={{
          border: `2px dashed ${dragOver ? C.accent : "rgba(255,255,255,0.1)"}`,
          borderRadius: 5, padding: "22px 20px", textAlign: "center",
          marginBottom: 16, cursor: uploading ? "not-allowed" : "pointer",
          background: dragOver ? "rgba(0,229,160,0.04)" : "transparent",
          transition: "all 0.15s",
        }}
      >
        <input
          ref={fileRef} type="file" style={{ display: "none" }}
          onChange={e => handleFiles(e.target.files)}
        />
        {uploading ? (
          <div>
            <div style={{ color: C.accent, fontFamily: "monospace", fontSize: 11, marginBottom: 8 }}>
              Uploading… {progress}%
            </div>
            <div style={{ height: 4, background: "rgba(255,255,255,0.08)", borderRadius: 2, width: "100%" }}>
              <div style={{ height: "100%", background: C.accent, borderRadius: 2, width: `${progress}%`, transition: "width 0.2s" }} />
            </div>
          </div>
        ) : (
          <>
            <div style={{ fontSize: 22, marginBottom: 8, opacity: 0.3 }}>📎</div>
            <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 11 }}>
              Drag & drop file or click to browse
            </div>
          </>
        )}
      </div>
      {err && <div style={{ color: C.red, fontSize: 10, fontFamily: "monospace", marginBottom: 10 }}>{err}</div>}

      {/* Evidence list */}
      {evidence.length === 0 ? (
        <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 11, textAlign: "center", padding: "30px 0" }}>No evidence uploaded</div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {evidence.map((ev, i) => (
            <div key={ev.id || i} style={{
              background: C.surface, border: `1px solid ${C.border}`,
              borderRadius: 4, padding: "12px 16px",
              display: "flex", alignItems: "center", gap: 14,
            }}>
              <div style={{ fontSize: 18, opacity: 0.5 }}>📄</div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ color: C.text, fontFamily: "monospace", fontSize: 12, fontWeight: 600, marginBottom: 3 }}>
                  {ev.filename}
                </div>
                <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
                  <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                    {ev.file_size ? `${Math.round(ev.file_size / 1024)} KB` : "—"}
                  </span>
                  <span style={{ color: C.dim, fontSize: 10, fontFamily: "monospace" }} title={ev.sha256}>
                    SHA256: {ev.sha256 ? ev.sha256.slice(0, 8) + "…" : "—"}
                  </span>
                  <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                    {ev.uploaded_by || "—"} · {fmtTs(ev.uploaded_at)}
                  </span>
                </div>
                {ev.description && (
                  <div style={{ color: C.muted, fontSize: 11, marginTop: 4, fontStyle: "italic" }}>{ev.description}</div>
                )}
              </div>
              <a
                href={`/api/cases/${caseId}/evidence/${ev.id}/download`}
                download={ev.filename}
                onClick={e => e.stopPropagation()}
                style={{
                  background: "rgba(77,158,255,0.1)", border: `1px solid ${C.blue}30`,
                  color: C.blue, padding: "5px 12px", borderRadius: 3,
                  fontFamily: "monospace", fontSize: 10, fontWeight: 700,
                  textDecoration: "none", flexShrink: 0,
                }}
              >Download</a>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// TAB: Checklist
// ─────────────────────────────────────────────────────────────────────────────
function ChecklistTab({ caseId, initialChecklist }) {
  const [items,    setItems]    = useState(initialChecklist || []);
  // keyed by item.index (integer) — was incorrectly item.id (undefined)
  const [notes,    setNotes]    = useState({});
  const [expanded, setExpanded] = useState({});
  const [saving,   setSaving]   = useState({});   // {index: "toggle"|"note"|false}

  const fetchChecklist = useCallback(() => {
    fetch(`/api/cases/${caseId}/checklist`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject())
      // endpoint returns {case_type, steps:[...]}; get_case embeds as {checklist:[...]}
      .then(d => setItems(d.steps || d.checklist || []))
      .catch(() => {});
  }, [caseId]);

  const handleToggle = async (item) => {
    const idx = item.index;
    setSaving(s => ({ ...s, [idx]: "toggle" }));
    try {
      const r = await fetch(`/api/cases/${caseId}/checklist/${idx}`, {
        method: "PATCH", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ checked: !item.checked }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      fetchChecklist();
    } catch { /* silently leave state as-is */ }
    finally { setSaving(s => ({ ...s, [idx]: false })); }
  };

  const handleSaveNote = async (item) => {
    const idx  = item.index;
    const text = (notes[idx] ?? item.note ?? "").trim();
    setSaving(s => ({ ...s, [idx]: "note" }));
    try {
      const r = await fetch(`/api/cases/${caseId}/checklist/${idx}`, {
        method: "PATCH", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ checked: item.checked, note: text }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      // Merge saved note back into local items so UI stays consistent
      setItems(prev => prev.map(it => it.index === idx ? { ...it, note: text } : it));
      setNotes(n => ({ ...n, [idx]: text }));
    } catch { /* leave textarea as-is */ }
    finally { setSaving(s => ({ ...s, [idx]: false })); }
  };

  const checked = items.filter(i => i.checked).length;
  const pct     = items.length ? Math.round((checked / items.length) * 100) : 0;

  return (
    <div style={{ padding: "16px 0" }}>
      {/* Progress bar */}
      {items.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
            <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
              {checked} / {items.length} steps completed
            </span>
            <span style={{ color: pct === 100 ? C.accent : C.muted, fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
              {pct}%
            </span>
          </div>
          <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2 }}>
            <div style={{ height: "100%", borderRadius: 2,
              background: pct === 100 ? C.accent : C.blue,
              width: `${pct}%`, transition: "width 0.3s" }} />
          </div>
        </div>
      )}

      {items.length === 0 ? (
        <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 11, textAlign: "center", padding: "30px 0" }}>
          No checklist items
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {items.map((item) => {
            const idx         = item.index;
            const isExpanded  = expanded[idx] || false;
            const isSaving    = saving[idx];
            const noteVal     = notes[idx] ?? item.note ?? "";
            const noteDirty   = notes[idx] !== undefined && notes[idx] !== (item.note || "");

            return (
              <div key={idx} style={{
                background: C.surface,
                border: `1px solid ${item.checked ? "rgba(0,229,160,0.15)" : C.border}`,
                borderRadius: 4, overflow: "hidden",
              }}>
                {/* ── Main row ── */}
                <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "11px 14px" }}>
                  {/* Checkbox */}
                  <button
                    onClick={() => isSaving !== "toggle" && handleToggle(item)}
                    disabled={isSaving === "toggle"}
                    style={{
                      width: 18, height: 18, borderRadius: 3, flexShrink: 0,
                      cursor: isSaving === "toggle" ? "wait" : "pointer",
                      border: `2px solid ${item.checked ? C.accent : "rgba(255,255,255,0.2)"}`,
                      background: item.checked ? `${C.accent}20` : "transparent",
                      display: "flex", alignItems: "center", justifyContent: "center",
                    }}
                  >
                    {item.checked && <span style={{ color: C.accent, fontSize: 10, fontWeight: 900 }}>✓</span>}
                  </button>

                  {/* Step number */}
                  <span style={{ color: C.dim, fontSize: 9, fontFamily: "monospace", minWidth: 16 }}>
                    {idx + 1}.
                  </span>

                  {/* Title */}
                  <div style={{
                    flex: 1,
                    color: item.checked ? C.muted : C.text,
                    fontSize: 12,
                    textDecoration: item.checked ? "line-through" : "none",
                  }}>
                    {item.title}
                  </div>

                  {/* Checked-by badge */}
                  {item.checked && item.checked_by && (
                    <span style={{ color: C.dim, fontSize: 9, fontFamily: "monospace", whiteSpace: "nowrap" }}>
                      {item.checked_by} · {fmtTs(item.checked_at)}
                    </span>
                  )}

                  {/* Saved note indicator */}
                  {item.note && !isExpanded && (
                    <span title={item.note}
                      style={{ color: C.yellow, fontSize: 10, cursor: "default" }}>📝</span>
                  )}

                  {/* Expand toggle (guidance + note) */}
                  <button
                    onClick={() => setExpanded(e => ({ ...e, [idx]: !e[idx] }))}
                    title={isExpanded ? "Collapse" : "Guidance & note"}
                    style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", fontSize: 11, padding: "0 2px" }}
                  >
                    {isExpanded ? "▲" : "▼"}
                  </button>
                </div>

                {/* ── Expanded: guidance ── */}
                {isExpanded && item.guidance && (
                  <div style={{
                    borderTop: `1px solid ${C.border}`,
                    padding: "9px 14px 9px 54px",
                    color: C.muted, fontSize: 11, lineHeight: 1.6, fontStyle: "italic",
                    background: "rgba(255,255,255,0.01)",
                  }}>
                    {item.guidance}
                  </div>
                )}

                {/* ── Expanded: note input + save ── */}
                {isExpanded && (
                  <div style={{ padding: "10px 14px 12px 54px", borderTop: `1px solid ${C.border}` }}>
                    <div style={{ color: C.dim, fontSize: 9, fontFamily: "monospace", letterSpacing: "1px", marginBottom: 5 }}>
                      STEP NOTE
                    </div>
                    <textarea
                      value={noteVal}
                      onChange={e => setNotes(n => ({ ...n, [idx]: e.target.value }))}
                      onKeyDown={e => { if (e.key === "Enter" && e.ctrlKey) handleSaveNote(item); }}
                      placeholder="Add a note for this step… (Ctrl+Enter to save)"
                      rows={2}
                      style={{
                        width: "100%", boxSizing: "border-box",
                        background: C.bg,
                        border: `1px solid ${noteDirty ? "rgba(77,158,255,0.35)" : "rgba(255,255,255,0.08)"}`,
                        color: C.text, padding: "7px 10px", borderRadius: 3,
                        fontFamily: "monospace", fontSize: 11, resize: "vertical", outline: "none",
                        transition: "border-color 0.15s",
                      }}
                    />
                    <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 6, gap: 8 }}>
                      {noteDirty && (
                        <button
                          onClick={() => setNotes(n => ({ ...n, [idx]: item.note || "" }))}
                          style={{ background: "none", border: "none", color: C.dim,
                            fontFamily: "monospace", fontSize: 10, cursor: "pointer" }}>
                          Discard
                        </button>
                      )}
                      <button
                        onClick={() => handleSaveNote(item)}
                        disabled={isSaving === "note"}
                        style={{
                          background: noteDirty ? "rgba(77,158,255,0.12)" : "rgba(255,255,255,0.04)",
                          border: `1px solid ${noteDirty ? "rgba(77,158,255,0.35)" : "rgba(255,255,255,0.1)"}`,
                          color: noteDirty ? C.blue : C.dim,
                          padding: "5px 14px", borderRadius: 3, fontFamily: "monospace",
                          fontSize: 10, fontWeight: noteDirty ? 700 : 400,
                          cursor: isSaving === "note" ? "wait" : "pointer",
                        }}
                      >
                        {isSaving === "note" ? "Saving…" : "Save Note"}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// TAB: Graph
// ─────────────────────────────────────────────────────────────────────────────
function GraphTab({ caseId }) {
  const [graph, setGraph]     = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr]         = useState("");
  const [hoveredNode, setHoveredNode] = useState(null);

  const W = 700, H = 420, CX = W / 2, CY = H / 2;

  useEffect(() => {
    fetch(`/api/cases/${caseId}/graph`, { credentials: "include" })
      .then(r => r.ok ? r.json() : r.json().then(d => Promise.reject(d.error || `HTTP ${r.status}`)))
      .then(d => { setGraph(d); setLoading(false); })
      .catch(e => { setErr(String(e)); setLoading(false); });
  }, [caseId]);

  if (loading) return <Spinner />;
  if (err)     return <ErrorState message={err} />;
  if (!graph || !graph.nodes?.length) {
    return <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 11, textAlign: "center", padding: "30px 0" }}>No graph data</div>;
  }

  // Position nodes in a circle around centre, with the incident node at centre
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];

  const incidentNode = nodes.find(n => n.type === "incident");
  const otherNodes   = nodes.filter(n => n.type !== "incident");

  const positioned = [];
  if (incidentNode) {
    positioned.push({ ...incidentNode, x: CX, y: CY });
  }
  const r = Math.min(CX, CY) * 0.72;
  otherNodes.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / otherNodes.length - Math.PI / 2;
    positioned.push({ ...n, x: CX + r * Math.cos(angle), y: CY + r * Math.sin(angle) });
  });

  const nodeById = {};
  positioned.forEach(n => { nodeById[n.id] = n; });

  const NODE_R = 16;

  return (
    <div style={{ padding: "16px 0" }}>
      <div style={{
        background: C.surface, border: `1px solid ${C.border}`,
        borderRadius: 5, overflow: "hidden",
      }}>
        <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ display: "block", maxWidth: W }}>
          {/* Edges */}
          {edges.map((e, i) => {
            const src = nodeById[e.source]; const tgt = nodeById[e.target];
            if (!src || !tgt) return null;
            return (
              <line key={i} x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
                stroke="rgba(255,255,255,0.12)" strokeWidth={1.5} />
            );
          })}

          {/* Nodes */}
          {positioned.map(n => {
            const col = GRAPH_COLORS[n.type] || "#888888";
            const isHovered = hoveredNode === n.id;
            return (
              <g key={n.id}
                onMouseEnter={() => setHoveredNode(n.id)}
                onMouseLeave={() => setHoveredNode(null)}
                style={{ cursor: "default" }}
              >
                {/* Glow ring on hover */}
                {isHovered && (
                  <circle cx={n.x} cy={n.y} r={NODE_R + 5}
                    fill="none" stroke={col} strokeWidth={1} opacity={0.3} />
                )}
                <circle cx={n.x} cy={n.y} r={NODE_R}
                  fill={`${col}22`} stroke={col} strokeWidth={1.5} />
                <text x={n.x} y={n.y + 1} textAnchor="middle" dominantBaseline="middle"
                  style={{ fill: col, fontSize: 8, fontFamily: "monospace", fontWeight: 700, pointerEvents: "none" }}>
                  {(n.type || "?").slice(0, 3).toUpperCase()}
                </text>
                <text x={n.x} y={n.y + NODE_R + 11} textAnchor="middle"
                  style={{ fill: isHovered ? col : "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace", pointerEvents: "none" }}>
                  {(n.label || n.id || "").length > 14 ? (n.label || n.id).slice(0, 14) + "…" : (n.label || n.id)}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Legend */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10, padding: "10px 16px", borderTop: `1px solid ${C.border}` }}>
          {Object.entries(GRAPH_COLORS).map(([type, color]) => (
            <div key={type} style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <div style={{ width: 10, height: 10, borderRadius: "50%", background: `${color}30`, border: `1.5px solid ${color}` }} />
              <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>{type}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main: CaseDetailPage
// ─────────────────────────────────────────────────────────────────────────────
export default function CaseDetailPage({ incidentId, onBack }) {
  const [caseData, setCaseData] = useState(null);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState("");
  const [activeTab, setActiveTab] = useState("Overview");
  const [patchingStatus, setPatchingStatus] = useState(false);

  const fetchCase = useCallback(() => {
    if (!incidentId) return;
    setLoading(true); setError("");
    fetch(`/api/cases/${encodeURIComponent(incidentId)}`, { credentials: "include" })
      .then(r => r.ok ? r.json() : r.json().then(d => Promise.reject(d.error || `HTTP ${r.status}`)))
      .then(d => { setCaseData(d); setLoading(false); })
      .catch(e => { setError(String(e)); setLoading(false); });
  }, [incidentId]);

  useEffect(() => { fetchCase(); }, [fetchCase]);

  const handleStatusChange = async (newStatus) => {
    if (!caseData) return;
    setPatchingStatus(true);
    try {
      const r = await fetch(`/api/cases/${encodeURIComponent(incidentId)}`, {
        method: "PATCH", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const updated = await r.json();
      setCaseData(d => ({ ...d, ...updated }));
    } catch (e) {
      alert(`Status update failed: ${e.message}`);
    } finally {
      setPatchingStatus(false);
    }
  };

  return (
    <>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>

      <div style={{ background: C.bg, minHeight: "100%", padding: "20px 28px" }}>

        {/* ── Back button ─────────────────────────────────────────────── */}
        {onBack && (
          <button onClick={onBack} style={{
            background: "none", border: "none",
            color: C.muted, fontFamily: "monospace", fontSize: 11,
            cursor: "pointer", marginBottom: 16, padding: 0,
            display: "flex", alignItems: "center", gap: 5,
          }}>
            ← Back to Cases
          </button>
        )}

        {loading ? (
          <Spinner />
        ) : error ? (
          <ErrorState message={error} onRetry={fetchCase} />
        ) : !caseData ? (
          <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12, textAlign: "center", padding: "60px 0" }}>
            Case not found
          </div>
        ) : (
          <>
            {/* ── Header card ───────────────────────────────────────── */}
            <div style={{
              background: C.surface, border: `1px solid ${C.border}`,
              borderRadius: 5, padding: "18px 20px", marginBottom: 18,
            }}>
              <div style={{ display: "flex", alignItems: "flex-start", gap: 14, flexWrap: "wrap" }}>
                {/* ID + type + restricted */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 6 }}>
                    <span style={{ color: C.text, fontSize: 16, fontFamily: "monospace", fontWeight: 700 }}>
                      {caseData.incident_id}
                    </span>
                    <SevBadge severity={caseData.severity} />
                    <Chip
                      label={(caseData.incident_type || "generic").replace(/_/g, " ").toUpperCase()}
                      color={C.purple}
                    />
                    {caseData.case_restricted && (
                      <span title="Restricted case" style={{ fontSize: 14 }}>🔒</span>
                    )}
                  </div>
                  <div style={{ color: C.muted, fontSize: 11, fontFamily: "monospace" }}>
                    Assigned to {caseData.assigned_to || "Unassigned"} · Opened {fmtTs(caseData.case_opened_at)}
                  </div>
                </div>

                {/* Status dropdown */}
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ color: C.dim, fontSize: 9, fontFamily: "monospace", letterSpacing: "1px" }}>STATUS</span>
                  <select
                    value={caseData.status || ""}
                    onChange={e => handleStatusChange(e.target.value)}
                    disabled={patchingStatus}
                    style={{
                      background: C.bg, border: `1px solid rgba(255,255,255,0.12)`,
                      color: C.text, padding: "6px 10px", borderRadius: 3,
                      fontFamily: "monospace", fontSize: 11, cursor: "pointer", outline: "none",
                      opacity: patchingStatus ? 0.6 : 1,
                    }}
                  >
                    {STATUS_OPTIONS.map(o => (
                      <option key={o.value} value={o.value}>{o.label}</option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            {/* ── Tabs ──────────────────────────────────────────────── */}
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 5 }}>
              <div style={{ padding: "0 16px" }}>
                <TabBar active={activeTab} onChange={setActiveTab} />
              </div>
              <div style={{ padding: "0 20px 20px", minHeight: 300 }}>
                {activeTab === "Overview"  && <OverviewTab caseData={caseData} />}
                {activeTab === "Comments"  && <CommentsTab caseId={caseData.id || caseData.incident_id} initialComments={caseData.comments} />}
                {activeTab === "IOCs"      && <IOCsTab     caseId={caseData.id || caseData.incident_id} initialIocs={caseData.iocs} />}
                {activeTab === "Evidence"  && <EvidenceTab caseId={caseData.id || caseData.incident_id} initialEvidence={caseData.evidence} />}
                {activeTab === "Checklist" && <ChecklistTab caseId={caseData.id || caseData.incident_id} initialChecklist={caseData.checklist} />}
                {activeTab === "Graph"     && <GraphTab    caseId={caseData.id || caseData.incident_id} />}
              </div>
            </div>
          </>
        )}
      </div>
    </>
  );
}
