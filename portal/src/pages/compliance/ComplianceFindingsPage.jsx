/**
 * ComplianceFindingsPage.jsx
 * ===========================
 * Compliance findings with verdict badges (BREACH/WARNING/COMPLIANT),
 * source tagging (automated/questionnaire/manual), remediation panel,
 * and AI analysis.
 */

import { useState, useEffect, useCallback } from "react";
import { API_BASE } from "../../core/constants.js";
import { CY_FW_FILTER_KEY } from "./ComplianceDashboardPage.jsx";
import { ComplianceLiveAlertsPage } from "./ComplianceLiveAlertsPage.jsx";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};

const SEV_COLORS = { critical: C.red, high: C.orange, medium: C.blue, low: C.muted };
const VERDICT_COLORS = { breach: C.red, warning: C.orange, compliant: C.accent, open: C.muted };
const VERDICT_LABELS = { breach: "BREACH", warning: "WARNING", compliant: "COMPLIANT", open: "OPEN" };

const FW_COLORS = {
  nis2: "#6378ff", iso27001: "#00e5c0", dora: "#ffd166",
  soc2: "#ff6b6b", nist_csf: "#38bdf8", pci_dss: "#f97316", gdpr: "#8b5cf6",
};
const FW_LABELS = {
  nis2: "NIS2", dora: "DORA", iso27001: "ISO 27001",
  soc2: "SOC 2", nist_csf: "NIST CSF", pci_dss: "PCI DSS", gdpr: "GDPR",
};

function _getEnabledFws() {
  try {
    const s = JSON.parse(localStorage.getItem(CY_FW_FILTER_KEY));
    if (Array.isArray(s) && s.length) return s;
  } catch { /* ignore */ }
  return null;
}

const ALL_FRAMEWORKS = ["", "nis2", "dora", "iso27001", "soc2", "nist_csf", "pci_dss", "gdpr"];
const FRAMEWORKS = ALL_FRAMEWORKS;
const SEVERITIES = ["", "critical", "high", "medium", "low"];
const STATUSES   = ["", "open", "in_progress", "resolved", "accepted"];
const VERDICTS   = ["", "breach", "warning", "compliant"];
const SOURCES    = ["", "automated", "questionnaire", "manual"];

function SevBadge({ sev }) {
  const c = SEV_COLORS[sev] || C.muted;
  return (
    <span style={{ background: `${c}18`, color: c, border: `1px solid ${c}30`,
      fontSize: 9, fontFamily: "monospace", fontWeight: 700,
      padding: "2px 6px", borderRadius: 3, textTransform: "uppercase" }}>{sev}</span>
  );
}

function VerdictBadge({ verdict }) {
  const v = verdict || "open";
  const c = VERDICT_COLORS[v] || C.muted;
  const l = VERDICT_LABELS[v] || v.toUpperCase();
  return (
    <span style={{ background: `${c}18`, color: c, border: `1px solid ${c}40`,
      fontSize: 9, fontFamily: "monospace", fontWeight: 700,
      padding: "2px 8px", borderRadius: 3 }}>{l}</span>
  );
}

function SourceBadge({ source }) {
  const configs = {
    automated:    { color: C.blue,   label: "AUTO" },
    questionnaire:{ color: C.purple, label: "SURVEY" },
    manual:       { color: C.muted,  label: "MANUAL" },
  };
  const { color, label } = configs[source] || configs.manual;
  return (
    <span style={{ background: `${color}12`, color, border: `1px solid ${color}30`,
      fontSize: 8, fontFamily: "monospace", fontWeight: 700,
      padding: "1px 5px", borderRadius: 3 }}>{label}</span>
  );
}

function fmtTs(ts) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleDateString("en-US",
    { month: "short", day: "2-digit", year: "numeric" }); }
  catch { return ts; }
}

function RemediationPanel({ findingId, onClose }) {
  const [rem, setRem]       = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/api/comp/findings/${findingId}/remediation`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setRem(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [findingId]);

  return (
    <tr>
      <td colSpan={8} style={{ padding: "16px 20px",
        background: "rgba(255,140,0,0.04)", borderBottom: `1px solid rgba(255,255,255,0.03)` }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
            fontFamily: "monospace", textTransform: "uppercase", marginBottom: 12 }}>
            Remediation Guidance
          </div>
          <button onClick={onClose}
            style={{ background: "none", border: "none", color: C.muted,
              cursor: "pointer", fontSize: 12, padding: 0 }}>✕</button>
        </div>
        {loading ? (
          <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 11 }}>Loading...</div>
        ) : rem ? (
          <div>
            <div style={{ color: C.orange, fontFamily: "monospace", fontSize: 12,
              fontWeight: 700, marginBottom: 10 }}>{rem.title}</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {(rem.actions || []).map((action, i) => (
                <div key={i} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                  <div style={{ width: 20, height: 20, borderRadius: "50%", flexShrink: 0,
                    background: "rgba(255,140,0,0.15)", border: "1px solid rgba(255,140,0,0.3)",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    color: C.orange, fontSize: 9, fontFamily: "monospace", fontWeight: 700 }}>
                    {i + 1}
                  </div>
                  <div style={{ color: C.text, fontSize: 11, lineHeight: 1.6 }}>{action}</div>
                </div>
              ))}
            </div>
            {rem.controls && Object.keys(rem.controls).length > 0 && (
              <div style={{ marginTop: 14, display: "flex", gap: 8, flexWrap: "wrap" }}>
                {Object.entries(rem.controls).map(([fw, ctrls]) => (
                  <span key={fw} style={{
                    fontSize: 9, fontFamily: "monospace", fontWeight: 700,
                    background: `${FW_COLORS[fw] || C.blue}15`,
                    color: FW_COLORS[fw] || C.blue,
                    border: `1px solid ${FW_COLORS[fw] || C.blue}30`,
                    padding: "2px 6px", borderRadius: 3,
                  }}>
                    {FW_LABELS[fw] || fw.toUpperCase()}: {ctrls.join(", ")}
                  </span>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 11 }}>
            No specific remediation guidance available for this finding.
          </div>
        )}
      </td>
    </tr>
  );
}

function FindingsTab() {
  const [findings, setFindings]   = useState([]);
  const [total, setTotal]         = useState(0);
  const [loading, setLoading]     = useState(true);
  // Pre-select framework from global filter if exactly one is selected
  const [framework, setFramework] = useState(() => {
    const enabled = _getEnabledFws();
    return (enabled && enabled.length === 1) ? enabled[0] : "";
  });
  const [severity, setSeverity]   = useState("");
  const [status, setStatus]       = useState("open");
  const [verdict, setVerdict]     = useState("");
  const [source, setSource]       = useState("");
  const [page, setPage]           = useState(1);
  const [showForm, setShowForm]   = useState(false);
  const [form, setForm]           = useState(() => {
    const enabled = _getEnabledFws();
    const defaultFw = (enabled && enabled.length >= 1) ? enabled[0] : "iso27001";
    return { title: "", framework: defaultFw, severity: "medium", description: "" };
  });

  // Restrict framework dropdown to globally selected frameworks (or all if no filter)
  const enabledFws = _getEnabledFws();
  const filteredFrameworks = enabledFws
    ? ["", ...ALL_FRAMEWORKS.filter(f => f && enabledFws.includes(f))]
    : FRAMEWORKS;
  const [aiMap, setAiMap]         = useState({});
  const [aiLoading, setAiLoading] = useState({});
  const [remOpen, setRemOpen]     = useState(null);
  const [genning, setGenning]     = useState(false);
  const [genMsg, setGenMsg]       = useState(null);

  const PER_PAGE = 50;

  const load = useCallback(() => {
    setLoading(true);
    const p = new URLSearchParams({ page, per_page: PER_PAGE });
    if (framework) p.set("framework", framework);
    if (severity)  p.set("severity", severity);
    if (status)    p.set("status", status);
    if (verdict)   p.set("verdict", verdict);
    if (source)    p.set("source_type", source);
    fetch(`${API_BASE}/api/comp/findings?${p}`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setFindings(d.findings || []); setTotal(d.total || 0); setLoading(false); })
      .catch(() => setLoading(false));
  }, [page, framework, severity, status, verdict, source]);

  useEffect(() => { load(); }, [load]);

  const handleCreate = () => {
    fetch(`${API_BASE}/api/comp/findings`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(form),
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(() => {
        setShowForm(false);
        setForm({ title: "", framework: "iso27001", severity: "medium", description: "" });
        load();
      })
      .catch(e => alert(`Create failed: ${e}`));
  };

  const handleStatusUpdate = (id, newStatus) => {
    fetch(`${API_BASE}/api/comp/findings/${id}`, {
      method: "PUT", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus }),
    }).then(r => r.ok ? load() : null);
  };

  const handleAnalyze = (finding) => {
    setAiLoading(m => ({ ...m, [finding.id]: true }));
    fetch(`${API_BASE}/api/comp/findings/${finding.id}/analyze`, {
      method: "POST", credentials: "include",
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => setAiMap(m => ({ ...m, [finding.id]: d.analysis })))
      .catch(() => {})
      .finally(() => setAiLoading(m => ({ ...m, [finding.id]: false })));
  };

  const handleAutoGenerate = () => {
    setGenning(true); setGenMsg(null);
    const body = framework ? JSON.stringify({ framework }) : "{}";
    fetch(`${API_BASE}/api/comp/findings/auto-generate`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" }, body,
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        const r = d.result || {};
        setGenMsg(`${r.created || 0} created, ${r.updated || 0} updated`);
        load();
      })
      .catch(e => setGenMsg(`Failed (${e})`))
      .finally(() => setGenning(false));
  };

  const inp = {
    background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
    borderRadius: 4, color: C.text, fontFamily: "monospace", fontSize: 12,
    padding: "7px 10px", width: "100%", outline: "none", boxSizing: "border-box",
  };

  const totalPages = Math.ceil(total / PER_PAGE);

  // Verdict summary counts (from visible findings)
  const verdictCounts = findings.reduce((acc, f) => {
    const v = f.verdict || "open";
    acc[v] = (acc[v] || 0) + 1;
    return acc;
  }, {});

  return (
    <div>
      {/* Action bar (no page title — shared header is in the wrapper) */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
        <span style={{ color: C.muted, fontSize: 11, fontFamily: "monospace" }}>{total} findings</span>
        <div style={{ display: "flex", gap: 8 }}>
          {genMsg && <span style={{ color: genMsg.includes("Failed") ? C.red : C.accent,
            fontSize: 10, fontFamily: "monospace", alignSelf: "center" }}>{genMsg}</span>}
          <button onClick={handleAutoGenerate} disabled={genning}
            style={{ background: `${C.orange}10`, border: `1px solid ${C.orange}40`, color: C.orange,
              padding: "7px 14px", borderRadius: 4, fontFamily: "monospace", fontSize: 11,
              fontWeight: 700, cursor: "pointer", opacity: genning ? 0.6 : 1 }}>
            {genning ? "Generating..." : "Auto-Generate from Alerts"}
          </button>
          <button onClick={() => setShowForm(s => !s)}
            style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
              color: C.accent, padding: "7px 14px", borderRadius: 4, fontFamily: "monospace",
              fontSize: 11, fontWeight: 700, cursor: "pointer" }}>
            {showForm ? "Close" : "+ Manual Finding"}
          </button>
        </div>
      </div>


      {/* Verdict summary pills */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
        {[
          { key: "breach",   label: "Breach" },
          { key: "warning",  label: "Warning" },
          { key: "compliant",label: "Compliant" },
          { key: "open",     label: "Unscored" },
        ].map(({ key, label }) => {
          const cnt = verdictCounts[key] || 0;
          const c   = VERDICT_COLORS[key];
          return cnt > 0 ? (
            <div key={key}
              style={{ background: `${c}10`, border: `1px solid ${c}30`,
                borderRadius: 6, padding: "6px 14px", display: "flex", gap: 8, alignItems: "center" }}>
              <span style={{ color: c, fontSize: 16, fontFamily: "monospace", fontWeight: 700 }}>{cnt}</span>
              <span style={{ color: c, fontSize: 10, fontFamily: "monospace" }}>{label}</span>
            </div>
          ) : null;
        })}
      </div>

      {/* Create form */}
      {showForm && (
        <div style={{ background: "#0d1117", border: `1px solid ${C.border}`, borderRadius: 8,
          padding: 20, marginBottom: 20, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <div style={{ gridColumn: "1/-1" }}>
            <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
              letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 5 }}>Title *</div>
            <input style={inp} value={form.title}
              onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
          </div>
          {[
            { key: "framework", opts: filteredFrameworks.filter(Boolean), label: "Framework" },
            { key: "severity",  opts: SEVERITIES.filter(Boolean), label: "Severity" },
          ].map(({ key, opts, label }) => (
            <div key={key}>
              <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 5 }}>{label}</div>
              <select style={{ ...inp, cursor: "pointer" }} value={form[key]}
                onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}>
                {opts.map(o => <option key={o} value={o}>{o.toUpperCase()}</option>)}
              </select>
            </div>
          ))}
          <div style={{ gridColumn: "1/-1" }}>
            <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
              letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 5 }}>Description</div>
            <textarea style={{ ...inp, height: 64, resize: "vertical" }}
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          </div>
          <div style={{ gridColumn: "1/-1", display: "flex", gap: 10, justifyContent: "flex-end" }}>
            <button onClick={() => setShowForm(false)}
              style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
                color: C.muted, padding: "8px 18px", borderRadius: 4,
                fontFamily: "monospace", fontSize: 11, cursor: "pointer" }}>Cancel</button>
            <button onClick={handleCreate}
              style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
                color: C.accent, padding: "8px 18px", borderRadius: 4,
                fontFamily: "monospace", fontSize: 11, fontWeight: 700, cursor: "pointer" }}>
              Create Finding
            </button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
        {[
          { label: "Framework", value: framework, setValue: setFramework, options: filteredFrameworks },
          { label: "Severity",  value: severity,  setValue: setSeverity,  options: SEVERITIES },
          { label: "Status",    value: status,    setValue: setStatus,    options: STATUSES },
          { label: "Verdict",   value: verdict,   setValue: setVerdict,   options: VERDICTS },
          { label: "Source",    value: source,    setValue: setSource,    options: SOURCES },
        ].map(({ label, value, setValue, options }) => (
          <select key={label} value={value}
            onChange={e => { setValue(e.target.value); setPage(1); }}
            style={{ background: "#0d1117", border: `1px solid ${C.border}`, color: C.text,
              borderRadius: 4, padding: "6px 10px", fontFamily: "monospace",
              fontSize: 11, cursor: "pointer" }}>
            <option value="">{label}: All</option>
            {options.filter(Boolean).map(o =>
              <option key={o} value={o}>{o.replace(/_/g, " ").toUpperCase()}</option>
            )}
          </select>
        ))}
      </div>

      {/* Findings table */}
      <div style={{ background: "#0d1117", border: `1px solid ${C.border}`,
        borderRadius: 8, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {["Verdict / Sev", "Framework", "Control", "Finding", "Alerts", "Status", "Date", "Actions"].map(h => (
                <th key={h} style={{ padding: "10px 14px", textAlign: "left",
                  color: C.muted, fontSize: 9, fontFamily: "monospace",
                  letterSpacing: "1px", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={8} style={{ padding: 32, textAlign: "center",
                color: C.muted, fontFamily: "monospace" }}>Loading...</td></tr>
            ) : findings.length === 0 ? (
              <tr><td colSpan={8} style={{ padding: 32, textAlign: "center",
                color: C.muted, fontFamily: "monospace", fontSize: 12 }}>
                No findings match the selected filters.
                {status === "open" && total === 0 && (
                  <div style={{ marginTop: 8, color: "rgba(255,255,255,0.25)", fontSize: 11 }}>
                    Click "Auto-Generate from Alerts" to create findings from enriched alerts.
                  </div>
                )}
              </td></tr>
            ) : findings.flatMap((f, i) => {
              const isRemOpen = remOpen === f.id;
              const fwColor   = FW_COLORS[f.framework] || C.blue;
              const rows = [
                <tr key={f.id}
                  style={{ borderBottom: `1px solid rgba(255,255,255,0.03)`,
                    background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)",
                    verticalAlign: "top" }}>

                  {/* Verdict + Severity */}
                  <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                    <div style={{ marginBottom: 4 }}><VerdictBadge verdict={f.verdict} /></div>
                    <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
                      <SevBadge sev={f.severity} />
                      <SourceBadge source={f.source_type} />
                    </div>
                  </td>

                  {/* Framework */}
                  <td style={{ padding: "10px 14px" }}>
                    <span style={{ color: fwColor, fontSize: 9, fontFamily: "monospace",
                      fontWeight: 700, background: `${fwColor}12`, border: `1px solid ${fwColor}30`,
                      padding: "2px 6px", borderRadius: 3 }}>
                      {FW_LABELS[f.framework] || f.framework?.toUpperCase() || "—"}
                    </span>
                  </td>

                  {/* Control */}
                  <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10,
                    fontFamily: "monospace", maxWidth: 120 }}>
                    <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {f.control_id || "—"}
                    </div>
                  </td>

                  {/* Title + description */}
                  <td style={{ padding: "10px 14px", maxWidth: 300 }}>
                    <div style={{ color: C.text, fontSize: 11, fontWeight: 600, marginBottom: 2 }}>
                      {f.title}
                    </div>
                    {f.description && (
                      <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                        maxWidth: 280 }}>
                        {f.description}
                      </div>
                    )}
                    {f.last_seen_at && (
                      <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 9,
                        fontFamily: "monospace", marginTop: 2 }}>
                        Last seen: {fmtTs(f.last_seen_at)}
                      </div>
                    )}
                  </td>

                  {/* Alert count */}
                  <td style={{ padding: "10px 14px", textAlign: "center" }}>
                    {f.alert_count > 0 ? (
                      <span style={{ color: C.orange, fontSize: 12,
                        fontFamily: "monospace", fontWeight: 700 }}>{f.alert_count}</span>
                    ) : (
                      <span style={{ color: "rgba(255,255,255,0.15)", fontSize: 10,
                        fontFamily: "monospace" }}>—</span>
                    )}
                  </td>

                  {/* Status selector */}
                  <td style={{ padding: "10px 14px" }}>
                    <select value={f.status}
                      onChange={e => handleStatusUpdate(f.id, e.target.value)}
                      style={{
                        background: "rgba(255,255,255,0.04)",
                        border: `1px solid ${C.border}`,
                        color: f.status === "open" ? C.orange
                          : f.status === "resolved" ? C.accent : C.muted,
                        borderRadius: 3, padding: "3px 6px",
                        fontFamily: "monospace", fontSize: 9,
                        cursor: "pointer", textTransform: "uppercase",
                      }}>
                      {STATUSES.filter(Boolean).map(s =>
                        <option key={s} value={s}>{s.toUpperCase()}</option>
                      )}
                    </select>
                  </td>

                  {/* Date */}
                  <td style={{ padding: "10px 14px", color: C.muted,
                    fontSize: 10, fontFamily: "monospace", whiteSpace: "nowrap" }}>
                    {fmtTs(f.created_at)}
                  </td>

                  {/* Actions */}
                  <td style={{ padding: "10px 14px" }}>
                    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      <button
                        onClick={() => setRemOpen(isRemOpen ? null : f.id)}
                        style={{ background: isRemOpen ? `${C.orange}20` : `${C.orange}08`,
                          border: `1px solid ${C.orange}${isRemOpen ? "60" : "25"}`,
                          color: C.orange, padding: "3px 8px", borderRadius: 3,
                          fontFamily: "monospace", fontSize: 9, fontWeight: 700,
                          cursor: "pointer", whiteSpace: "nowrap" }}>
                        {isRemOpen ? "Hide Fix" : "Show Fix"}
                      </button>
                      <button
                        onClick={() => handleAnalyze(f)}
                        disabled={aiLoading[f.id]}
                        style={{ background: `${C.purple}08`, border: `1px solid ${C.purple}25`,
                          color: C.purple, padding: "3px 8px", borderRadius: 3,
                          fontFamily: "monospace", fontSize: 9, fontWeight: 700,
                          cursor: "pointer", opacity: aiLoading[f.id] ? 0.6 : 1,
                          whiteSpace: "nowrap" }}>
                        {aiLoading[f.id] ? "AI..." : "AI Analyze"}
                      </button>
                    </div>
                  </td>
                </tr>,
              ];

              // Remediation panel
              if (isRemOpen) {
                rows.push(<RemediationPanel key={`${f.id}-rem`} findingId={f.id}
                  onClose={() => setRemOpen(null)} />);
              }

              // AI analysis row
              if (aiMap[f.id] || f.ai_analysis) {
                rows.push(
                  <tr key={`${f.id}-ai`} style={{ background: "rgba(176,110,255,0.04)",
                    borderBottom: `1px solid rgba(255,255,255,0.03)` }}>
                    <td colSpan={8} style={{ padding: "10px 20px" }}>
                      <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                        letterSpacing: "1px", textTransform: "uppercase", marginBottom: 6 }}>
                        AI Analysis
                      </div>
                      <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 11,
                        fontFamily: "monospace", lineHeight: 1.6,
                        whiteSpace: "pre-wrap", maxWidth: 900 }}>
                        {aiMap[f.id] || f.ai_analysis}
                      </div>
                    </td>
                  </tr>
                );
              }

              return rows;
            })}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 16 }}>
          <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
            style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
              color: C.text, padding: "6px 14px", borderRadius: 4, fontFamily: "monospace",
              fontSize: 11, cursor: "pointer", opacity: page === 1 ? 0.4 : 1 }}>Previous</button>
          <span style={{ color: C.muted, fontSize: 11, fontFamily: "monospace",
            display: "flex", alignItems: "center" }}>{page} / {totalPages}</span>
          <button disabled={page === totalPages} onClick={() => setPage(p => p + 1)}
            style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
              color: C.text, padding: "6px 14px", borderRadius: 4, fontFamily: "monospace",
              fontSize: 11, cursor: "pointer", opacity: page === totalPages ? 0.4 : 1 }}>Next</button>
        </div>
      )}
    </div>
  );
}

const TABS = [
  { id: "findings",     label: "Findings" },
  { id: "live-alerts",  label: "Live Alerts" },
];

export function ComplianceFindingsPage() {
  const [tab, setTab] = useState("findings");
  return (
    <div>
      {/* Shared page header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px", fontFamily: "monospace",
          textTransform: "uppercase", marginBottom: 4 }}>SECURITY COMPLIANCE</div>
        <h1 style={{ color: C.text, fontSize: 20, fontWeight: 700, margin: 0 }}>Findings & Alerts</h1>
        <div style={{ color: C.muted, fontSize: 11, marginTop: 4, fontFamily: "monospace" }}>
          Compliance findings, live correlation alerts and enrichment
        </div>
      </div>

      {/* Tab switcher — pill style matching Risk Management */}
      <div style={{ display: "flex", gap: 4, marginBottom: 20 }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ padding: "7px 16px", borderRadius: 6, cursor: "pointer",
              fontFamily: "monospace", fontSize: 11, fontWeight: 600,
              background: tab === t.id ? `${C.blue}20` : "transparent",
              border: `1px solid ${tab === t.id ? `${C.blue}60` : C.border}`,
              color: tab === t.id ? C.blue : C.muted }}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "findings"    && <FindingsTab />}
      {tab === "live-alerts" && <ComplianceLiveAlertsPage />}
    </div>
  );
}
