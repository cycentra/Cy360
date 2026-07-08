/**
 * ComplianceAssessmentPage.jsx
 * ==============================
 * Framework-first compliance assessment tool.
 * Left: framework selector tabs with completion rings.
 * Right: two sub-tabs — Controls List | Questionnaire
 *
 * Controls list merges questionnaire + auto-findings + alert data.
 * Questionnaire: section navigation, yes/no/score/text inputs, auto-save.
 */

import { useState, useEffect, useCallback } from "react";
import { API_BASE } from "../../core/constants.js";
import { CY_FW_FILTER_KEY } from "./ComplianceDashboardPage.jsx";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};

const FW_META = {
  nis2:      { label: "NIS2 Directive",      color: "#6378ff", region: "EU" },
  dora:      { label: "DORA",                color: "#ffd166", region: "EU" },
  iso27001:  { label: "ISO 27001:2022",      color: "#00e5c0", region: "INTL" },
  soc2:      { label: "SOC 2",               color: "#ff6b6b", region: "US" },
  nist_csf:  { label: "NIST CSF 2.0",        color: "#38bdf8", region: "US" },
  pci_dss:   { label: "PCI DSS v4.0",        color: "#f97316", region: "PCI" },
  gdpr:      { label: "GDPR",                color: "#8b5cf6", region: "EU" },
  eu_ai_act: { label: "EU AI Act",           color: "#06b6d4", region: "EU" },
  iso42001:  { label: "ISO 42001:2023",      color: "#10b981", region: "AI" },
};

function _getEnabledFws() {
  try {
    const s = JSON.parse(localStorage.getItem(CY_FW_FILTER_KEY));
    if (Array.isArray(s) && s.length) return s;
  } catch { /* ignore */ }
  return null;
}

const STATUS_COLORS = {
  compliant:    C.accent,
  partial:      C.orange,
  gap:          C.red,
  breach:       C.red,
  not_assessed: "rgba(255,255,255,0.2)",
};
const STATUS_LABELS = {
  compliant:    "Compliant",
  partial:      "Partial",
  gap:          "Gap",
  breach:       "Breach",
  not_assessed: "Not assessed",
};

function MiniRing({ pct, color, size = 36 }) {
  const r     = (size - 5) / 2;
  const circ  = 2 * Math.PI * r;
  const dash  = (pct / 100) * circ;
  return (
    <svg width={size} height={size} style={{ transform: "rotate(-90deg)", flexShrink: 0 }}>
      <circle cx={size/2} cy={size/2} r={r} fill="none"
        stroke="rgba(255,255,255,0.07)" strokeWidth={4} />
      <circle cx={size/2} cy={size/2} r={r} fill="none"
        stroke={color} strokeWidth={4}
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round" />
    </svg>
  );
}

// ── Controls List ──────────────────────────────────────────────────────────────

function ControlsList({ framework }) {
  const [controls, setControls] = useState([]);
  const [loading, setLoading]   = useState(true);
  const [filter, setFilter]     = useState("all");

  useEffect(() => {
    setLoading(true);
    fetch(`${API_BASE}/api/comp/controls-view/${framework}`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setControls(d.controls || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, [framework]);

  const filtered = filter === "all" ? controls
    : controls.filter(c => c.status === filter);

  const counts = controls.reduce((acc, c) => {
    acc[c.status] = (acc[c.status] || 0) + 1; return acc;
  }, {});

  return (
    <div>
      {/* Filter pills */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        {[
          { key: "all",          label: `All (${controls.length})` },
          { key: "gap",          label: `Gaps (${counts.gap || 0})` },
          { key: "breach",       label: `Breach (${counts.breach || 0})` },
          { key: "partial",      label: `Partial (${counts.partial || 0})` },
          { key: "compliant",    label: `Compliant (${counts.compliant || 0})` },
          { key: "not_assessed", label: `Unassessed (${counts.not_assessed || 0})` },
        ].map(({ key, label }) => {
          const color = STATUS_COLORS[key] || C.blue;
          const active = filter === key;
          return (
            <button key={key} onClick={() => setFilter(key)}
              style={{ background: active ? `${color}15` : "rgba(255,255,255,0.03)",
                border: `1px solid ${active ? `${color}50` : "rgba(255,255,255,0.07)"}`,
                color: active ? color : C.muted, padding: "4px 10px", borderRadius: 4,
                fontFamily: "monospace", fontSize: 9, fontWeight: active ? 700 : 400,
                cursor: "pointer" }}>
              {label}
            </button>
          );
        })}
      </div>

      {loading ? (
        <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 11, padding: 20 }}>
          Loading controls…
        </div>
      ) : filtered.length === 0 ? (
        <div style={{ color: "rgba(255,255,255,0.15)", fontFamily: "monospace", fontSize: 11,
          padding: 20 }}>
          {controls.length === 0
            ? "No controls found. Complete the questionnaire to populate this view."
            : "No controls match the selected filter."}
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {filtered.map(ctrl => {
            const sc    = ctrl.status;
            const color = STATUS_COLORS[sc] || C.muted;
            const label = STATUS_LABELS[sc] || sc;
            return (
              <div key={ctrl.control_ref}
                style={{ padding: "10px 14px", borderRadius: 6,
                  background: "rgba(255,255,255,0.02)",
                  border: `1px solid rgba(255,255,255,0.04)`,
                  borderLeft: `3px solid ${color}` }}>
                <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                  {/* Status + sources */}
                  <div style={{ flexShrink: 0, minWidth: 80 }}>
                    <span style={{ background: `${color}15`, color, border: `1px solid ${color}30`,
                      fontSize: 8, fontFamily: "monospace", fontWeight: 700,
                      padding: "2px 6px", borderRadius: 3, display: "block",
                      textAlign: "center", textTransform: "uppercase", marginBottom: 4 }}>
                      {label}
                    </span>
                    <div style={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                      {(ctrl.sources || []).map(src => (
                        <span key={src} style={{ fontSize: 7, fontFamily: "monospace",
                          color: src === "automated" ? C.blue : src === "questionnaire" ? C.purple : C.muted,
                          background: "rgba(255,255,255,0.04)", padding: "1px 3px",
                          borderRadius: 2, fontWeight: 700 }}>
                          {src === "questionnaire" ? "Q" : src === "automated" ? "A" : "M"}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", gap: 6, alignItems: "center",
                      marginBottom: 3 }}>
                      <span style={{ color: C.blue, fontSize: 9, fontFamily: "monospace",
                        fontWeight: 700, background: `${C.blue}12`, padding: "1px 5px",
                        borderRadius: 2, flexShrink: 0 }}>
                        {ctrl.control_ref}
                      </span>
                      {ctrl.section && (
                        <span style={{ color: C.muted, fontSize: 9,
                          fontFamily: "monospace" }}>{ctrl.section}</span>
                      )}
                    </div>
                    <div style={{ color: C.text, fontSize: 11, lineHeight: 1.4 }}>
                      {ctrl.question}
                    </div>
                    {ctrl.response && (
                      <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                        marginTop: 4 }}>
                        Response: <span style={{ color: ctrl.score >= 2 ? C.accent
                          : ctrl.score === 1 ? C.orange : C.red }}>
                          {ctrl.response}
                        </span>
                        {ctrl.notes && <span style={{ marginLeft: 8 }}>· {ctrl.notes}</span>}
                      </div>
                    )}
                  </div>

                  <div style={{ flexShrink: 0, textAlign: "right" }}>
                    {ctrl.alert_count > 0 && (
                      <div style={{ color: C.orange, fontSize: 11, fontFamily: "monospace",
                        fontWeight: 700 }}>{ctrl.alert_count}</div>
                    )}
                    {ctrl.alert_count > 0 && (
                      <div style={{ color: C.muted, fontSize: 8,
                        fontFamily: "monospace" }}>alerts</div>
                    )}
                    {ctrl.weight === 3 && (
                      <span style={{ color: C.red, fontSize: 8, fontFamily: "monospace",
                        display: "block", marginTop: 2 }}>CRITICAL</span>
                    )}
                  </div>
                </div>

                {/* Breach findings */}
                {(ctrl.findings || []).filter(f => f.verdict === "breach").map((f, i) => (
                  <div key={i} style={{ marginTop: 6, padding: "4px 8px", borderRadius: 3,
                    background: `${C.red}08`, border: `1px solid ${C.red}20`,
                    fontSize: 9, color: C.red, fontFamily: "monospace" }}>
                    ⚠ BREACH: {f.title?.slice(0, 100)}
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Questionnaire ──────────────────────────────────────────────────────────────

function QuestionRow({ q, response, onSave, onReset, saving, resetting }) {
  const [val, setVal]     = useState(response?.response || "");
  const [notes, setNotes] = useState(response?.notes || "");
  const [open, setOpen]   = useState(false);

  // Sync if response changes from parent reload
  useEffect(() => { setVal(response?.response || ""); setNotes(response?.notes || ""); }, [response]);

  const sc    = response?.score ?? null;
  const statusColor = sc === null ? C.muted : sc >= 2 ? C.accent : sc === 1 ? C.orange : C.red;
  const isPropagated = Boolean(response?.propagated_from);

  const submit = () => {
    if (!val) return;
    onSave(q.question_id, val, notes);
    setOpen(false);
  };

  return (
    <div style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", padding: "12px 0" }}>
      <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
        <div style={{ width: 7, height: 7, borderRadius: "50%", background: statusColor,
          marginTop: 5, flexShrink: 0 }} />
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", gap: 8, alignItems: "flex-start",
            cursor: "pointer" }} onClick={() => setOpen(o => !o)}>
            <div style={{ flex: 1 }}>
              <div style={{ color: C.text, fontSize: 11, lineHeight: 1.5 }}>
                {q.question}
              </div>
              <div style={{ display: "flex", gap: 6, marginTop: 4, flexWrap: "wrap" }}>
                {q.control_ref && (
                  <span style={{ color: C.blue, fontSize: 8, fontFamily: "monospace",
                    background: `${C.blue}12`, padding: "1px 5px", borderRadius: 3 }}>
                    {q.control_ref}
                  </span>
                )}
                {response && (
                  <span style={{ color: statusColor, fontSize: 8, fontFamily: "monospace",
                    background: `${statusColor}12`, padding: "1px 5px", borderRadius: 3 }}>
                    {response.response}
                  </span>
                )}
                {isPropagated && (
                  <span style={{ color: "#6378ff", fontSize: 8, fontFamily: "monospace",
                    background: "rgba(99,120,255,0.1)", padding: "1px 5px", borderRadius: 3,
                    border: "1px solid rgba(99,120,255,0.25)" }} title="Answer propagated from another framework">
                    propagated
                  </span>
                )}
                {q.weight === 3 && (
                  <span style={{ color: C.red, fontSize: 8, fontFamily: "monospace",
                    fontWeight: 700 }}>Critical weight</span>
                )}
              </div>
            </div>
            {/* Per-question reset — only shown when an answer exists */}
            {response && (
              <button
                onClick={e => { e.stopPropagation(); onReset(q.question_id); }}
                disabled={resetting}
                title="Clear this answer"
                style={{ background: "none", border: "none", color: "rgba(255,255,255,0.2)",
                  cursor: "pointer", fontSize: 12, padding: "2px 4px", lineHeight: 1,
                  flexShrink: 0, marginTop: 1,
                  transition: "color 0.15s" }}
                onMouseEnter={e => (e.currentTarget.style.color = C.red)}
                onMouseLeave={e => (e.currentTarget.style.color = "rgba(255,255,255,0.2)")}>
                {resetting ? "…" : "✕"}
              </button>
            )}
            <span style={{ color: C.muted, fontSize: 10, marginTop: 2 }}>{open ? "▲" : "▼"}</span>
          </div>

          {open && (
            <div style={{ marginTop: 12 }}>
              {q.guidance && (
                <div style={{ color: C.muted, fontSize: 10, lineHeight: 1.6,
                  background: "rgba(255,255,255,0.02)", borderRadius: 4,
                  padding: "8px 12px", marginBottom: 12, fontFamily: "monospace",
                  borderLeft: `2px solid ${C.blue}30` }}>
                  <span style={{ color: C.blue, fontWeight: 700 }}>Guidance: </span>{q.guidance}
                </div>
              )}

              {q.question_type === "yes_no" ? (
                <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
                  {["yes", "no", "partial"].map(opt => (
                    <button key={opt} onClick={() => setVal(opt)}
                      style={{
                        background: val === opt
                          ? (opt === "yes" ? `${C.accent}20` : opt === "no" ? `${C.red}20` : `${C.orange}20`)
                          : "rgba(255,255,255,0.04)",
                        border: `1px solid ${val === opt
                          ? (opt === "yes" ? C.accent : opt === "no" ? C.red : C.orange)
                          : "rgba(255,255,255,0.1)"}`,
                        color: val === opt
                          ? (opt === "yes" ? C.accent : opt === "no" ? C.red : C.orange) : C.muted,
                        borderRadius: 4, padding: "6px 18px", fontFamily: "monospace",
                        fontSize: 11, fontWeight: 700, cursor: "pointer",
                        textTransform: "uppercase", letterSpacing: "0.5px",
                      }}>
                      {opt}
                    </button>
                  ))}
                </div>
              ) : q.question_type === "score_1_5" ? (
                <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 10 }}>
                  {[1, 2, 3, 4, 5].map(n => (
                    <button key={n} onClick={() => setVal(String(n))}
                      style={{
                        width: 38, height: 38,
                        background: val === String(n) ? `${C.blue}25` : "rgba(255,255,255,0.04)",
                        border: `1px solid ${val === String(n) ? C.blue : "rgba(255,255,255,0.1)"}`,
                        color: val === String(n) ? C.blue : C.muted,
                        borderRadius: 4, fontFamily: "monospace", fontSize: 14,
                        fontWeight: 700, cursor: "pointer",
                      }}>
                      {n}
                    </button>
                  ))}
                  <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                    marginLeft: 6 }}>1 = None  ·  5 = Fully implemented</span>
                </div>
              ) : q.question_type === "multi_choice" && q.options?.length > 0 ? (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 10 }}>
                  {q.options.map(opt => (
                    <button key={opt} onClick={() => setVal(opt)}
                      style={{
                        background: val === opt ? `${C.purple}20` : "rgba(255,255,255,0.04)",
                        border: `1px solid ${val === opt ? C.purple : "rgba(255,255,255,0.1)"}`,
                        color: val === opt ? C.purple : C.muted,
                        borderRadius: 4, padding: "5px 12px",
                        fontFamily: "monospace", fontSize: 10, cursor: "pointer",
                      }}>
                      {opt}
                    </button>
                  ))}
                </div>
              ) : (
                <textarea value={val} onChange={e => setVal(e.target.value)}
                  placeholder="Enter your response…" rows={2}
                  style={{ width: "100%", background: "#0d1117",
                    border: `1px solid ${C.border}`, color: C.text, borderRadius: 4,
                    padding: "8px 10px", fontFamily: "monospace", fontSize: 11,
                    resize: "vertical", marginBottom: 8, boxSizing: "border-box" }} />
              )}

              <input value={notes} onChange={e => setNotes(e.target.value)}
                placeholder="Notes / evidence reference (optional)…"
                style={{ width: "100%", background: "#0d1117", border: `1px solid ${C.border}`,
                  color: C.text, borderRadius: 4, padding: "6px 10px",
                  fontFamily: "monospace", fontSize: 10, marginBottom: 10,
                  boxSizing: "border-box" }} />

              <button onClick={submit} disabled={!val || saving}
                style={{ background: `${C.accent}15`, border: `1px solid ${C.accent}40`,
                  color: C.accent, borderRadius: 4, padding: "6px 18px",
                  fontFamily: "monospace", fontSize: 11, fontWeight: 700,
                  cursor: "pointer", opacity: !val || saving ? 0.5 : 1 }}>
                {saving ? "Saving…" : "Save Answer"}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function QuestionnaireView({ framework, color }) {
  const [data, setData]             = useState(null);
  const [loading, setLoading]       = useState(true);
  const [saving, setSaving]         = useState({});
  const [resetting, setResetting]   = useState({});   // per-question reset state
  const [section, setSection]       = useState(null);
  const [genMsg, setGenMsg]         = useState(null);
  const [genning, setGenning]       = useState(false);
  const [panelKey, setPanelKey]     = useState(0);
  // Framework-level reset
  const [fwResetting, setFwResetting] = useState(false);
  const [fwResetMsg, setFwResetMsg]   = useState(null);
  const [fwConfirm, setFwConfirm]     = useState(false);  // show confirm step

  const load = useCallback(() => {
    setLoading(true);
    fetch(`${API_BASE}/api/comp/questionnaire/${framework}`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setData(d); setSection(null); setLoading(false); })
      .catch(() => setLoading(false));
  }, [framework]);

  useEffect(() => { load(); }, [load]);

  const handleSave = (question_id, response, notes) => {
    setSaving(s => ({ ...s, [question_id]: true }));
    fetch(`${API_BASE}/api/comp/questionnaire/${framework}/respond/${question_id}`, {
      method: "PUT", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ response, notes }),
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(() => { load(); setPanelKey(k => k + 1); })
      .catch(e => console.error("save failed", e))
      .finally(() => setSaving(s => ({ ...s, [question_id]: false })));
  };

  const handleReset = (question_id) => {
    setResetting(s => ({ ...s, [question_id]: true }));
    fetch(`${API_BASE}/api/comp/questionnaire/${framework}/respond/${question_id}`, {
      method: "DELETE", credentials: "include",
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(() => { load(); setPanelKey(k => k + 1); })
      .catch(e => console.error("reset failed", e))
      .finally(() => setResetting(s => ({ ...s, [question_id]: false })));
  };

  const handleFrameworkReset = () => {
    if (!fwConfirm) { setFwConfirm(true); return; }
    setFwResetting(true); setFwResetMsg(null); setFwConfirm(false);
    fetch(`${API_BASE}/api/comp/questionnaire/${framework}/responses`, {
      method: "DELETE", credentials: "include",
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setFwResetMsg(`${d.deleted} answers cleared`); load(); setPanelKey(k => k + 1); })
      .catch(e => setFwResetMsg(`Failed (${e})`))
      .finally(() => setFwResetting(false));
  };

  const handleGenFindings = () => {
    setGenning(true); setGenMsg(null);
    fetch(`${API_BASE}/api/comp/questionnaire/${framework}/generate-findings`, {
      method: "POST", credentials: "include",
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        const r = d.result || {};
        setGenMsg(`${r.created || 0} gap findings created`);
      })
      .catch(e => setGenMsg(`Failed (${e})`))
      .finally(() => setGenning(false));
  };

  if (loading || !data) return (
    <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 11, padding: 20 }}>
      Loading…
    </div>
  );

  const templates  = data.templates || [];
  const responses  = data.responses || {};
  const score      = data.score || {};
  const sections   = [...new Set(templates.map(t => t.section))];
  const activeSec  = section || sections[0];
  const visible    = templates.filter(t => t.section === activeSec);
  const answered   = templates.filter(t => responses[t.question_id]).length;
  const gaps       = score.gaps?.length || 0;

  return (
    <div>
      {/* Score strip */}
      <div style={{ display: "flex", gap: 24, alignItems: "center", marginBottom: 20,
        padding: "12px 16px", borderRadius: 6, background: `${color}08`,
        border: `1px solid ${color}20` }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ color: color, fontSize: 28, fontFamily: "monospace", fontWeight: 800 }}>
            {Math.round(score.score || 0)}%
          </div>
          <div style={{ color: C.muted, fontSize: 8, fontFamily: "monospace" }}>Score</div>
        </div>
        <div style={{ display: "flex", gap: 20 }}>
          {[
            { label: "Total",    val: score.total || templates.length, c: C.text },
            { label: "Answered", val: answered,   c: C.accent },
            { label: "Gaps",     val: gaps,       c: gaps > 0 ? C.red : C.muted },
            { label: "Partial",  val: score.partial?.length || 0, c: C.orange },
          ].map(({ label, val, c }) => (
            <div key={label} style={{ textAlign: "center" }}>
              <div style={{ color: c, fontSize: 18, fontFamily: "monospace", fontWeight: 700 }}>{val}</div>
              <div style={{ color: C.muted, fontSize: 8, fontFamily: "monospace" }}>{label}</div>
            </div>
          ))}
        </div>
        <div style={{ marginLeft: "auto", display: "flex", flexDirection: "column", gap: 6,
          alignItems: "flex-end" }}>
          <button onClick={handleGenFindings} disabled={genning}
            style={{ background: `${C.orange}10`, border: `1px solid ${C.orange}40`,
              color: C.orange, padding: "5px 12px", borderRadius: 4, fontFamily: "monospace",
              fontSize: 9, fontWeight: 700, cursor: "pointer", opacity: genning ? 0.6 : 1,
              whiteSpace: "nowrap" }}>
            {genning ? "Generating…" : "Generate Gap Findings"}
          </button>
          {genMsg && <span style={{ color: genMsg.includes("fail") ? C.red : C.orange,
            fontSize: 9, fontFamily: "monospace" }}>{genMsg}</span>}

          {/* Framework-level reset */}
          {fwConfirm ? (
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <span style={{ color: C.red, fontSize: 9, fontFamily: "monospace" }}>
                Clear all answers?
              </span>
              <button onClick={handleFrameworkReset} disabled={fwResetting}
                style={{ background: `${C.red}15`, border: `1px solid ${C.red}50`,
                  color: C.red, padding: "4px 10px", borderRadius: 4,
                  fontFamily: "monospace", fontSize: 9, fontWeight: 700, cursor: "pointer" }}>
                Confirm
              </button>
              <button onClick={() => setFwConfirm(false)}
                style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
                  color: C.muted, padding: "4px 8px", borderRadius: 4,
                  fontFamily: "monospace", fontSize: 9, cursor: "pointer" }}>
                Cancel
              </button>
            </div>
          ) : (
            <button onClick={handleFrameworkReset} disabled={fwResetting}
              style={{ background: "rgba(255,59,59,0.07)", border: `1px solid rgba(255,59,59,0.2)`,
                color: "rgba(255,100,100,0.75)", padding: "5px 12px", borderRadius: 4,
                fontFamily: "monospace", fontSize: 9, cursor: "pointer",
                opacity: fwResetting ? 0.6 : 1, whiteSpace: "nowrap" }}>
              {fwResetting ? "Resetting…" : "↺ Reset Framework"}
            </button>
          )}
          {fwResetMsg && (
            <span style={{ color: fwResetMsg.includes("fail") ? C.red : C.muted,
              fontSize: 9, fontFamily: "monospace" }}>{fwResetMsg}</span>
          )}
        </div>
      </div>

      {/* Cross-framework propagation suggestions */}
      <PropagationPanel
        key={panelKey}
        framework={framework}
        onApplied={() => { load(); setPanelKey(k => k + 1); }}
      />

      <div style={{ display: "flex", gap: 20 }}>
        {/* Section tabs */}
        <div style={{ width: 180, flexShrink: 0 }}>
          <div style={{ color: C.muted, fontSize: 8, letterSpacing: "1px",
            fontFamily: "monospace", textTransform: "uppercase", marginBottom: 8 }}>Sections</div>
          {sections.map(sec => {
            const secQs   = templates.filter(t => t.section === sec);
            const secDone = secQs.filter(t => responses[t.question_id]).length;
            const secGaps = secQs.filter(t => {
              const r = responses[t.question_id];
              return r && r.score === 0;
            }).length;
            const act = (section || sections[0]) === sec;
            return (
              <button key={sec} onClick={() => setSection(sec)}
                style={{ display: "block", width: "100%", textAlign: "left",
                  background: act ? `${color}12` : "rgba(255,255,255,0.02)",
                  border: `1px solid ${act ? `${color}35` : "rgba(255,255,255,0.05)"}`,
                  color: act ? color : C.muted, borderRadius: 4,
                  padding: "7px 10px", fontFamily: "monospace", fontSize: 9,
                  cursor: "pointer", marginBottom: 4 }}>
                <div style={{ fontWeight: act ? 700 : 400, marginBottom: 2 }}>{sec}</div>
                <div style={{ opacity: 0.7, fontSize: 8 }}>
                  {secDone}/{secQs.length}
                  {secGaps > 0 && <span style={{ color: C.red }}> · {secGaps} gap</span>}
                  {secDone === secQs.length && secGaps === 0 && secDone > 0
                    && <span style={{ color: C.accent }}> ✓</span>}
                </div>
              </button>
            );
          })}
        </div>

        {/* Questions */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ color: C.muted, fontSize: 8, letterSpacing: "1px",
            fontFamily: "monospace", textTransform: "uppercase", marginBottom: 10 }}>
            {activeSec}
          </div>
          {visible.map(q => (
            <QuestionRow key={q.question_id} q={q} response={responses[q.question_id]}
              onSave={handleSave} saving={Boolean(saving[q.question_id])}
              onReset={handleReset} resetting={Boolean(resetting[q.question_id])} />
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Cross-Framework Propagation Panel ─────────────────────────────────────────

const FW_COLORS = {
  nis2:      "#6378ff", dora:     "#ffd166", iso27001: "#00e5c0",
  soc2:      "#ff6b6b", nist_csf: "#38bdf8", pci_dss:  "#f97316",
  gdpr:      "#8b5cf6", eu_ai_act: "#06b6d4",
};
const FW_LABELS = {
  nis2: "NIS2", dora: "DORA", iso27001: "ISO 27001", soc2: "SOC 2",
  nist_csf: "NIST CSF", pci_dss: "PCI DSS", gdpr: "GDPR", eu_ai_act: "EU AI Act",
};

function PropagationPanel({ framework, onApplied }) {
  const [items, setItems]     = useState([]);
  const [loading, setLoading] = useState(true);
  const [applying, setApplying] = useState(false);
  // reviewMode: null | { item } — shows individual confirmation for each suggestion
  const [reviewMode, setReviewMode] = useState(null);
  const [reviewIdx, setReviewIdx]   = useState(0);
  const [dismissed, setDismissed]   = useState(new Set());

  const load = () => {
    setLoading(true);
    fetch(`${API_BASE}/api/comp/questionnaire/${framework}/correlations`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setItems(d.suggestions || []); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => { load(); }, [framework]); // eslint-disable-line react-hooks/exhaustive-deps

  // Expose refresh to parent after save
  PropagationPanel._refresh = load;

  const visible = items.filter(item => !dismissed.has(item.answered.question_id));
  if (loading || visible.length === 0) return null;

  // Collect all unique framework→question pairs across all visible items
  const allTargets = visible.flatMap(item =>
    item.suggestions.map(s => ({
      source_question_id: item.answered.question_id,
      source_framework:   framework,
      response:           item.answered.response,
      target_qid:         s.question_id,
      target_fw:          s.framework,
      cluster_theme:      item.cluster_theme,
    }))
  );

  const applyAll = () => {
    setApplying(true);
    // Group by source question to batch propagation calls
    const bySource = visible.reduce((acc, item) => {
      if (!acc[item.answered.question_id]) acc[item.answered.question_id] = item;
      return acc;
    }, {});

    const calls = Object.values(bySource).map(item =>
      fetch(`${API_BASE}/api/comp/questionnaire/propagate`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_question_id: item.answered.question_id,
          source_framework:   framework,
          response:           item.answered.response,
          accepted_targets:   item.suggestions.map(s => s.question_id),
        }),
      }).then(r => r.ok ? r.json() : Promise.reject(r.status))
    );

    Promise.all(calls)
      .then(() => { setItems([]); onApplied?.(); })
      .catch(e => console.error("propagation failed", e))
      .finally(() => setApplying(false));
  };

  const skipAll = () => {
    setDismissed(new Set(visible.map(item => item.answered.question_id)));
  };

  // ── Render ─────────────────────────────────────────────────────────────────

  // Flatten all individual suggestions for the "Review individually" flow
  const allSuggestions = visible.flatMap(item =>
    item.suggestions.map(s => ({ ...s, answered: item.answered, cluster_theme: item.cluster_theme }))
  );

  if (reviewMode) {
    const total = allSuggestions.length;
    const cur   = allSuggestions[reviewIdx];
    if (!cur) { setReviewMode(null); return null; }
    const fwColor = FW_COLORS[cur.framework] || C.blue;
    const fwLabel = FW_LABELS[cur.framework] || cur.framework;

    const applyOne = () => {
      fetch(`${API_BASE}/api/comp/questionnaire/propagate`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_question_id: cur.answered.question_id,
          source_framework:   framework,
          response:           cur.answered.response,
          accepted_targets:   [cur.question_id],
        }),
      })
        .then(r => r.ok ? r.json() : Promise.reject(r.status))
        .then(() => {
          if (reviewIdx + 1 >= total) { setReviewMode(null); onApplied?.(); }
          else setReviewIdx(i => i + 1);
        })
        .catch(e => console.error("propagation failed", e));
    };

    const rejectOne = () => {
      fetch(`${API_BASE}/api/comp/questionnaire/reject-propagation`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_question_id: cur.answered.question_id,
          target_question_id: cur.question_id,
        }),
      }).catch(() => {});
      if (reviewIdx + 1 >= total) { setReviewMode(null); }
      else setReviewIdx(i => i + 1);
    };

    return (
      <div style={{ margin: "0 0 20px 0", padding: "16px 20px", borderRadius: 8,
        background: `${fwColor}08`, border: `1px solid ${fwColor}30` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
          <span style={{ fontSize: 14 }}>🔗</span>
          <span style={{ color: fwColor, fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
            Review individually — {reviewIdx + 1} of {total}
          </span>
          <button onClick={() => setReviewMode(null)}
            style={{ marginLeft: "auto", background: "none", border: "none",
              color: C.muted, cursor: "pointer", fontSize: 14 }}>✕</button>
        </div>

        <div style={{ marginBottom: 10 }}>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
            marginBottom: 4 }}>Your answer to:</div>
          <div style={{ color: C.text, fontSize: 11, lineHeight: 1.4 }}>
            {cur.answered.question}
          </div>
          <div style={{ marginTop: 6, display: "flex", gap: 6, alignItems: "center" }}>
            <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>Response:</span>
            <span style={{ color: cur.answered.score >= 2 ? C.accent
              : cur.answered.score === 1 ? C.orange : C.red,
              fontFamily: "monospace", fontSize: 10, fontWeight: 700 }}>
              {cur.answered.response?.toUpperCase()}
            </span>
          </div>
        </div>

        <div style={{ padding: "10px 14px", borderRadius: 6,
          background: "rgba(255,255,255,0.02)", border: `1px solid rgba(255,255,255,0.06)`,
          marginBottom: 14 }}>
          <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 6 }}>
            <span style={{ background: `${fwColor}15`, color: fwColor,
              border: `1px solid ${fwColor}30`, fontSize: 8, fontFamily: "monospace",
              fontWeight: 700, padding: "2px 7px", borderRadius: 10 }}>
              {fwLabel}
            </span>
            {cur.control_ref && (
              <span style={{ color: C.blue, fontSize: 8, fontFamily: "monospace",
                background: `${C.blue}12`, padding: "1px 5px", borderRadius: 3 }}>
                {cur.control_ref}
              </span>
            )}
            <span style={{ color: C.muted, fontSize: 8, fontFamily: "monospace" }}>
              {cur.cluster_theme}
            </span>
          </div>
          <div style={{ color: C.text, fontSize: 11, lineHeight: 1.5 }}>{cur.question}</div>
        </div>

        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={applyOne}
            style={{ background: `${C.accent}15`, border: `1px solid ${C.accent}40`,
              color: C.accent, padding: "7px 20px", borderRadius: 4,
              fontFamily: "monospace", fontSize: 10, fontWeight: 700, cursor: "pointer" }}>
            Apply same answer
          </button>
          <button onClick={rejectOne}
            style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
              color: C.muted, padding: "7px 14px", borderRadius: 4,
              fontFamily: "monospace", fontSize: 10, cursor: "pointer" }}>
            Answer separately
          </button>
        </div>
      </div>
    );
  }

  // ── Default view: summary banner ──────────────────────────────────────────
  const uniqueFws = [...new Set(allTargets.map(t => t.target_fw))];

  return (
    <div style={{ margin: "0 0 20px 0", padding: "16px 20px", borderRadius: 8,
      background: "rgba(99,120,255,0.07)", border: "1px solid rgba(99,120,255,0.25)" }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
        <span style={{ fontSize: 16, flexShrink: 0 }}>🔗</span>
        <div style={{ flex: 1 }}>
          <div style={{ color: "#6378ff", fontSize: 11, fontWeight: 700,
            fontFamily: "monospace", marginBottom: 4 }}>
            Your answers apply to {allTargets.length} question{allTargets.length !== 1 ? "s" : ""} in other frameworks
          </div>
          <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace",
            lineHeight: 1.6, marginBottom: 10 }}>
            We detected similar controls across:&nbsp;
            {uniqueFws.map(fw => (
              <span key={fw} style={{ background: `${FW_COLORS[fw] || C.blue}15`,
                color: FW_COLORS[fw] || C.blue,
                border: `1px solid ${FW_COLORS[fw] || C.blue}30`,
                fontSize: 9, fontFamily: "monospace", fontWeight: 700,
                padding: "1px 7px", borderRadius: 10, marginRight: 4 }}>
                {FW_LABELS[fw] || fw}
              </span>
            ))}
            <br />
            Apply the same answers to avoid re-entering identical information.
          </div>
          {/* Per-cluster preview */}
          <div style={{ display: "flex", flexDirection: "column", gap: 4, marginBottom: 12 }}>
            {visible.map(item => (
              <div key={item.answered.question_id}
                style={{ display: "flex", gap: 8, alignItems: "flex-start",
                  padding: "6px 10px", borderRadius: 5,
                  background: "rgba(255,255,255,0.02)" }}>
                <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                  flexShrink: 0, marginTop: 1 }}>
                  {item.cluster_theme}
                </span>
                <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>→</span>
                <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                  {item.suggestions.map(s => (
                    <span key={s.question_id}
                      style={{ background: `${FW_COLORS[s.framework] || C.blue}12`,
                        color: FW_COLORS[s.framework] || C.blue,
                        border: `1px solid ${FW_COLORS[s.framework] || C.blue}25`,
                        fontSize: 8, fontFamily: "monospace",
                        padding: "1px 6px", borderRadius: 3 }}>
                      {FW_LABELS[s.framework] || s.framework}: {s.question_id}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={applyAll} disabled={applying}
              style={{ background: `${C.accent}15`, border: `1px solid ${C.accent}40`,
                color: C.accent, padding: "7px 20px", borderRadius: 4,
                fontFamily: "monospace", fontSize: 10, fontWeight: 700,
                cursor: "pointer", opacity: applying ? 0.6 : 1 }}>
              {applying ? "Applying…" : `Apply to all ${allTargets.length}`}
            </button>
            <button onClick={() => { setReviewMode(true); setReviewIdx(0); }}
              style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
                color: C.text, padding: "7px 14px", borderRadius: 4,
                fontFamily: "monospace", fontSize: 10, cursor: "pointer" }}>
              Review individually
            </button>
            <button onClick={skipAll}
              style={{ background: "none", border: "none", color: C.muted,
                padding: "7px 10px", fontFamily: "monospace", fontSize: 10, cursor: "pointer" }}>
              Skip
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Statement of Applicability (ISO 27001 only) ────────────────────────────────

const SOA_THEME_COLORS = {
  Organisational: "#6378ff",
  People:         "#f97316",
  Physical:       "#38bdf8",
  Technological:  "#00e5a0",
};

const SOA_STATUS_COLORS = {
  compliant:    C.accent,
  partial:      C.orange,
  gap:          C.red,
  breach:       C.red,
  excluded:     "rgba(255,255,255,0.2)",
  not_assessed: "rgba(255,255,255,0.15)",
};

const SOA_STATUS_LABELS = {
  compliant:    "Compliant",
  partial:      "Partial",
  gap:          "Gap",
  breach:       "Breach",
  excluded:     "Excluded",
  not_assessed: "Not Assessed",
};

function SoAControlRow({ ctrl, onUpdate }) {
  const [open, setOpen]          = useState(false);
  const [justification, setJust] = useState(ctrl.justification || "");
  const [saving, setSaving]      = useState(false);

  const sc    = SOA_STATUS_COLORS[ctrl.status] || C.muted;
  const label = SOA_STATUS_LABELS[ctrl.status] || ctrl.status;

  const handleToggle = (included) => {
    setSaving(true);
    fetch(`${API_BASE}/api/comp/soa/iso27001/${ctrl.control_id}`, {
      method: "PUT", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ included, justification: justification || null }),
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => onUpdate(d))
      .catch(e => console.error("SoA update failed", e))
      .finally(() => setSaving(false));
  };

  const handleJustSave = () => {
    setSaving(true);
    fetch(`${API_BASE}/api/comp/soa/iso27001/${ctrl.control_id}`, {
      method: "PUT", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ included: ctrl.included, justification: justification || null }),
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => onUpdate(d))
      .catch(e => console.error("SoA update failed", e))
      .finally(() => setSaving(false));
  };

  return (
    <div style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", padding: "8px 0" }}>
      <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
        {/* Status badge */}
        <div style={{ width: 78, flexShrink: 0, paddingTop: 2 }}>
          <span style={{
            background: `${sc}15`, color: sc, border: `1px solid ${sc}30`,
            fontSize: 7, fontFamily: "monospace", fontWeight: 700,
            padding: "2px 5px", borderRadius: 3, display: "block",
            textAlign: "center", textTransform: "uppercase",
            opacity: ctrl.included ? 1 : 0.45,
          }}>
            {label}
          </span>
        </div>

        {/* Control info */}
        <div style={{ flex: 1, minWidth: 0, cursor: "pointer" }}
          onClick={() => setOpen(o => !o)}>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <span style={{ color: C.blue, fontSize: 8, fontFamily: "monospace",
              fontWeight: 700, background: `${C.blue}12`,
              padding: "1px 5px", borderRadius: 2, flexShrink: 0 }}>
              {ctrl.control_id}
            </span>
            <span style={{ color: ctrl.included ? C.text : C.muted, fontSize: 10,
              lineHeight: 1.3, fontWeight: 600 }}>
              {ctrl.title}
            </span>
            {ctrl.question_id && (
              <span style={{ color: C.purple, fontSize: 7, fontFamily: "monospace",
                background: `${C.purple}10`, padding: "1px 4px", borderRadius: 2,
                flexShrink: 0, marginLeft: "auto" }}>
                Q: {ctrl.question_id}
              </span>
            )}
          </div>
          {open && (
            <div style={{ color: C.muted, fontSize: 9, lineHeight: 1.5, marginTop: 4,
              fontFamily: "monospace" }}>
              {ctrl.description}
            </div>
          )}
        </div>

        {/* Include/Exclude toggle */}
        <div style={{ flexShrink: 0, display: "flex", gap: 4, alignItems: "center" }}>
          <button
            onClick={() => !saving && handleToggle(true)}
            disabled={saving}
            style={{
              background: ctrl.included ? `${C.accent}20` : "rgba(255,255,255,0.04)",
              border: `1px solid ${ctrl.included ? C.accent : "rgba(255,255,255,0.1)"}`,
              color: ctrl.included ? C.accent : C.muted,
              fontSize: 7, fontFamily: "monospace", fontWeight: 700,
              padding: "3px 8px", borderRadius: 3, cursor: "pointer",
            }}>
            IN
          </button>
          <button
            onClick={() => !saving && handleToggle(false)}
            disabled={saving}
            style={{
              background: !ctrl.included ? `${C.red}20` : "rgba(255,255,255,0.04)",
              border: `1px solid ${!ctrl.included ? C.red : "rgba(255,255,255,0.1)"}`,
              color: !ctrl.included ? C.red : C.muted,
              fontSize: 7, fontFamily: "monospace", fontWeight: 700,
              padding: "3px 8px", borderRadius: 3, cursor: "pointer",
            }}>
            EX
          </button>
        </div>
      </div>

      {/* Justification — shown when excluded OR when row is expanded */}
      {(open || !ctrl.included) && (
        <div style={{ display: "flex", gap: 6, marginTop: 8, paddingLeft: 88 }}>
          <input
            value={justification}
            onChange={e => setJust(e.target.value)}
            placeholder={ctrl.included
              ? "Justification for inclusion (optional)…"
              : "Justification for exclusion (required)…"}
            style={{ flex: 1, background: "#0d1117", border: `1px solid ${C.border}`,
              color: C.text, borderRadius: 4, padding: "5px 8px",
              fontFamily: "monospace", fontSize: 9 }}
          />
          <button onClick={handleJustSave} disabled={saving}
            style={{ background: `${C.blue}15`, border: `1px solid ${C.blue}40`,
              color: C.blue, padding: "4px 10px", borderRadius: 4,
              fontFamily: "monospace", fontSize: 9, cursor: "pointer",
              opacity: saving ? 0.6 : 1 }}>
            {saving ? "…" : "Save"}
          </button>
        </div>
      )}
    </div>
  );
}

function SoAView() {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [theme, setTheme]     = useState("all");
  const [filter, setFilter]   = useState("all");

  const load = useCallback(() => {
    setLoading(true);
    fetch(`${API_BASE}/api/comp/soa/iso27001`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleUpdate = (updated) => {
    if (!data) return;
    setData(prev => ({
      ...prev,
      controls: prev.controls.map(c =>
        c.control_id === updated.control_id
          ? { ...c, included: updated.included, justification: updated.justification,
              status: !updated.included ? "excluded" : c.status }
          : c
      ),
    }));
  };

  if (loading || !data) return (
    <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 11, padding: 20 }}>
      Loading Statement of Applicability…
    </div>
  );

  const { controls, summary } = data;
  const THEMES = ["all", "Organisational", "People", "Physical", "Technological"];

  const visible = controls.filter(c => {
    const themeOk  = theme === "all" || c.theme === theme;
    const filterOk = filter === "all" || c.status === filter
      || (filter === "gap" && c.status === "breach");
    return themeOk && filterOk;
  });

  const byTheme = theme === "all"
    ? THEMES.slice(1).reduce((acc, t) => {
        acc[t] = visible.filter(c => c.theme === t);
        return acc;
      }, {})
    : { [theme]: visible };

  return (
    <div>
      {/* Summary strip */}
      <div style={{ display: "flex", gap: 16, alignItems: "center", marginBottom: 20,
        padding: "12px 16px", borderRadius: 6,
        background: "rgba(0,229,160,0.06)", border: "1px solid rgba(0,229,160,0.2)" }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ color: C.accent, fontSize: 26, fontFamily: "monospace",
            fontWeight: 800 }}>
            {summary.coverage_pct}%
          </div>
          <div style={{ color: C.muted, fontSize: 8, fontFamily: "monospace" }}>
            Coverage
          </div>
        </div>
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
          {[
            { label: "Total",       val: summary.total,        c: C.text },
            { label: "Compliant",   val: summary.compliant,    c: C.accent },
            { label: "Partial",     val: summary.partial,      c: C.orange },
            { label: "Gap/Breach",  val: summary.gap,          c: C.red },
            { label: "Excluded",    val: summary.excluded,     c: C.muted },
            { label: "Unassessed",  val: summary.not_assessed, c: "rgba(255,255,255,0.25)" },
          ].map(({ label, val, c }) => (
            <div key={label} style={{ textAlign: "center" }}>
              <div style={{ color: c, fontSize: 18, fontFamily: "monospace",
                fontWeight: 700 }}>{val}</div>
              <div style={{ color: C.muted, fontSize: 7, fontFamily: "monospace" }}>
                {label}
              </div>
            </div>
          ))}
        </div>
        <div style={{ marginLeft: "auto", fontSize: 8, fontFamily: "monospace",
          color: C.muted, textAlign: "right" }}>
          ISO/IEC 27001:2022<br />Cl.6.1.3(d) SoA<br />
          <span style={{ color: C.blue }}>{controls.length} controls</span>
        </div>
      </div>

      {/* Theme + Status filters */}
      <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
        {THEMES.map(t => {
          const color = t === "all" ? C.blue : SOA_THEME_COLORS[t] || C.blue;
          const act   = theme === t;
          const cnt   = t === "all" ? controls.length
            : controls.filter(c => c.theme === t).length;
          return (
            <button key={t} onClick={() => setTheme(t)}
              style={{ background: act ? `${color}15` : "rgba(255,255,255,0.03)",
                border: `1px solid ${act ? `${color}50` : "rgba(255,255,255,0.07)"}`,
                color: act ? color : C.muted, padding: "4px 10px", borderRadius: 4,
                fontFamily: "monospace", fontSize: 9, cursor: "pointer",
                fontWeight: act ? 700 : 400 }}>
              {t === "all" ? `All (${cnt})` : `${t} (${cnt})`}
            </button>
          );
        })}
        <span style={{ width: 1, background: C.border, margin: "0 4px" }} />
        {[
          { key: "all",          label: "All" },
          { key: "gap",          label: "Gaps" },
          { key: "partial",      label: "Partial" },
          { key: "compliant",    label: "Compliant" },
          { key: "not_assessed", label: "Unassessed" },
          { key: "excluded",     label: "Excluded" },
        ].map(({ key, label }) => {
          const color = SOA_STATUS_COLORS[key] || C.blue;
          const act   = filter === key;
          return (
            <button key={key} onClick={() => setFilter(key)}
              style={{ background: act ? `${color}15` : "rgba(255,255,255,0.03)",
                border: `1px solid ${act ? `${color}50` : "rgba(255,255,255,0.07)"}`,
                color: act ? color : C.muted, padding: "4px 10px", borderRadius: 4,
                fontFamily: "monospace", fontSize: 9, cursor: "pointer",
                fontWeight: act ? 700 : 400 }}>
              {label}
            </button>
          );
        })}
      </div>

      {/* Controls grouped by theme */}
      {Object.entries(byTheme).map(([t, ctrls]) => {
        if (!ctrls.length) return null;
        const themeColor = SOA_THEME_COLORS[t] || C.blue;
        const ts = summary.by_theme?.[t] || {};
        return (
          <div key={t} style={{ marginBottom: 24 }}>
            {/* Theme header */}
            <div style={{ display: "flex", alignItems: "center", gap: 10,
              marginBottom: 8, paddingBottom: 6,
              borderBottom: `1px solid ${themeColor}25` }}>
              <span style={{ color: themeColor, fontSize: 10, fontFamily: "monospace",
                fontWeight: 700, textTransform: "uppercase", letterSpacing: "1px" }}>
                {t}
              </span>
              <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>
                {ctrls.length} shown
              </span>
              <div style={{ display: "flex", gap: 6, marginLeft: "auto" }}>
                {[
                  { label: "Compliant", val: ts.compliant, c: C.accent },
                  { label: "Partial",   val: ts.partial,   c: C.orange },
                  { label: "Gap",       val: (ts.gap || 0) + (ts.breach || 0), c: C.red },
                ].map(({ label, val, c }) => val > 0 && (
                  <span key={label} style={{ color: c, fontSize: 8,
                    fontFamily: "monospace", background: `${c}10`,
                    padding: "1px 6px", borderRadius: 3 }}>
                    {val} {label}
                  </span>
                ))}
              </div>
            </div>
            {ctrls.map(ctrl => (
              <SoAControlRow key={ctrl.control_id} ctrl={ctrl} onUpdate={handleUpdate} />
            ))}
          </div>
        );
      })}
    </div>
  );
}

// ── Main export ───────────────────────────────────────────────────────────────

const ALL_FW_ORDERED = Object.keys(FW_META);

// ── What-If Simulation Panel ──────────────────────────────────────────────────

function SimulateView({ framework, color }) {
  const [data, setData]         = useState(null);
  const [loading, setLoading]   = useState(true);
  const [overrides, setOverrides] = useState({});   // question_id → score (0|1|2)
  const [result, setResult]     = useState(null);
  const [simming, setSimming]   = useState(false);

  useEffect(() => {
    setLoading(true); setOverrides({}); setResult(null);
    fetch(`${API_BASE}/api/comp/questionnaire/${framework}`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [framework]);

  const toggle = (qid, currentScore) => {
    setResult(null);
    setOverrides(prev => {
      const next = { ...prev };
      if (next[qid] !== undefined) {
        delete next[qid]; // revert to actual
      } else {
        // If currently failing/partial → simulate as passing (2); if passing → simulate as failing (0)
        next[qid] = currentScore >= 2 ? 0 : 2;
      }
      return next;
    });
  };

  const runSim = () => {
    if (!Object.keys(overrides).length) return;
    setSimming(true); setResult(null);
    const ovList = Object.entries(overrides).map(([question_id, score]) => ({ question_id, score }));
    fetch(`${API_BASE}/api/comp/simulate`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ framework, overrides: ovList }),
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setResult(d); setSimming(false); })
      .catch(e => { setResult({ error: String(e) }); setSimming(false); });
  };

  if (loading) return (
    <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 11, padding: 24 }}>Loading questions…</div>
  );
  if (!data) return (
    <div style={{ color: C.red, fontFamily: "monospace", fontSize: 11, padding: 24 }}>Failed to load questionnaire.</div>
  );

  const templates = data.templates || [];
  // responses is returned as a dict keyed by question_id (not a list)
  const respMap   = data.responses || {};
  const changed   = Object.keys(overrides).length;

  return (
    <div style={{ padding: "20px 0" }}>
      {/* Result banner */}
      {result && !result.error && (
        <div style={{ background: "rgba(0,229,160,0.06)", border: `1px solid rgba(0,229,160,0.25)`,
          borderRadius: 8, padding: "14px 18px", marginBottom: 20,
          display: "flex", gap: 32, alignItems: "center", flexWrap: "wrap" }}>
          <div>
            <div style={{ color: C.muted, fontSize: 8, fontFamily: "monospace",
              textTransform: "uppercase", letterSpacing: "1.5px" }}>Current Score</div>
            <div style={{ color: C.orange, fontSize: 26, fontFamily: "monospace",
              fontWeight: 800 }}>{(result.actual_score ?? 0).toFixed(1)}%</div>
          </div>
          <div style={{ fontSize: 22, color: C.muted }}>→</div>
          <div>
            <div style={{ color: C.muted, fontSize: 8, fontFamily: "monospace",
              textTransform: "uppercase", letterSpacing: "1.5px" }}>Simulated Score</div>
            <div style={{ color: result.delta > 0 ? C.accent : C.red, fontSize: 26,
              fontFamily: "monospace", fontWeight: 800 }}>
              {(result.simulated_score ?? 0).toFixed(1)}%
            </div>
          </div>
          <div>
            <div style={{ color: C.muted, fontSize: 8, fontFamily: "monospace",
              textTransform: "uppercase", letterSpacing: "1.5px" }}>Delta</div>
            <div style={{ color: result.delta > 0 ? C.accent : C.red, fontSize: 26,
              fontFamily: "monospace", fontWeight: 800 }}>
              {result.delta > 0 ? "+" : ""}{(result.delta ?? 0).toFixed(1)}%
            </div>
          </div>
          <div style={{ fontSize: 10, color: C.muted, fontFamily: "monospace" }}>
            {result.changed_questions ?? changed} question{changed !== 1 ? "s" : ""} modified
          </div>
        </div>
      )}
      {result?.error && (
        <div style={{ color: C.red, fontFamily: "monospace", fontSize: 10, marginBottom: 16 }}>
          {result.error}
        </div>
      )}

      {/* Controls bar */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16,
        flexWrap: "wrap" }}>
        <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
          Toggle questions to change their simulated score.
          {changed > 0 && <span style={{ color }}> {changed} override{changed !== 1 ? "s" : ""} pending.</span>}
        </div>
        <button onClick={() => { setOverrides({}); setResult(null); }}
          disabled={!changed}
          style={{ background: "rgba(255,255,255,0.04)", border: `1px solid rgba(255,255,255,0.10)`,
            color: C.muted, padding: "5px 12px", borderRadius: 4, fontFamily: "monospace",
            fontSize: 10, cursor: changed ? "pointer" : "default", opacity: changed ? 1 : 0.4 }}>
          Clear
        </button>
        <button onClick={runSim} disabled={!changed || simming}
          style={{ background: `${color}12`, border: `1px solid ${color}40`,
            color, padding: "5px 16px", borderRadius: 4, fontFamily: "monospace",
            fontSize: 10, fontWeight: 700, cursor: (changed && !simming) ? "pointer" : "default",
            opacity: (!changed || simming) ? 0.5 : 1 }}>
          {simming ? "Simulating…" : "Run Simulation"}
        </button>
      </div>

      {/* Question list */}
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {templates.map(q => {
          const resp      = respMap[q.question_id];
          const currScore = resp?.response === "yes" ? 2 : resp?.response === "partial" ? 1 : 0;
          const ovScore   = overrides[q.question_id];
          const isChanged = ovScore !== undefined;
          const dispScore = isChanged ? ovScore : currScore;
          const scoreColor = dispScore >= 2 ? C.accent : dispScore === 1 ? C.orange : C.red;
          const scoreLabel = dispScore >= 2 ? "Pass" : dispScore === 1 ? "Partial" : "Fail";
          return (
            <div key={q.question_id}
              onClick={() => toggle(q.question_id, currScore)}
              style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 12px",
                borderRadius: 6, cursor: "pointer",
                background: isChanged ? `${color}08` : "rgba(255,255,255,0.01)",
                border: `1px solid ${isChanged ? `${color}30` : "rgba(255,255,255,0.06)"}`,
                transition: "all 0.1s" }}>
              <div style={{ width: 48, textAlign: "center", flexShrink: 0,
                color: scoreColor, fontSize: 9, fontFamily: "monospace", fontWeight: 700,
                textTransform: "uppercase" }}>
                {scoreLabel}{isChanged ? "*" : ""}
              </div>
              <div style={{ flex: 1, fontSize: 11, color: C.text, lineHeight: 1.4 }}>
                {q.question || q.control_ref || q.question_id}
              </div>
              <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                flexShrink: 0 }}>w:{q.weight ?? 1}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function ComplianceAssessmentPage() {
  // Only show tabs for globally-enabled frameworks; default to first enabled
  const [activeFw, setActiveFw]   = useState(() => {
    const enabled = _getEnabledFws();
    if (enabled && enabled.length) {
      const first = ALL_FW_ORDERED.find(fw => enabled.includes(fw));
      return first || "nis2";
    }
    return "nis2";
  });
  const enabledFws = _getEnabledFws();
  const ALL_FW     = enabledFws
    ? ALL_FW_ORDERED.filter(fw => enabledFws.includes(fw))
    : ALL_FW_ORDERED;
  const [activeTab, setActiveTab]     = useState("questionnaire");
  const [hub, setHub]                 = useState(null);
  const [seeding, setSeeding]         = useState(false);
  const [seedMsg, setSeedMsg]         = useState(null);
  // Global reset state
  const [globalConfirm, setGlobalConfirm] = useState(false);
  const [globalResetting, setGlobalResetting] = useState(false);
  const [globalResetMsg, setGlobalResetMsg]   = useState(null);
  // key to remount QuestionnaireView after a global or framework reset
  const [viewKey, setViewKey] = useState(0);

  const loadHub = () => {
    fetch(`${API_BASE}/api/comp/questionnaire/hub`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setHub(d.frameworks || []); })
      .catch(() => {});
  };

  useEffect(() => { loadHub(); }, []);

  const handleSeed = () => {
    setSeeding(true); setSeedMsg(null);
    fetch(`${API_BASE}/api/comp/questionnaire/seed`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ force: true }),
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => setSeedMsg(`${d.result?.inserted || 0} questions seeded`))
      .catch(e => setSeedMsg(`Seed failed (${e})`))
      .finally(() => setSeeding(false));
  };

  const handleGlobalReset = () => {
    if (!globalConfirm) { setGlobalConfirm(true); return; }
    setGlobalResetting(true); setGlobalResetMsg(null); setGlobalConfirm(false);
    fetch(`${API_BASE}/api/comp/questionnaire/responses`, {
      method: "DELETE", credentials: "include",
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        setGlobalResetMsg(`${d.deleted} answers cleared across all frameworks`);
        loadHub();
        setViewKey(k => k + 1);
      })
      .catch(e => setGlobalResetMsg(`Failed (${e})`))
      .finally(() => setGlobalResetting(false));
  };

  const meta   = FW_META[activeFw] || { label: activeFw.toUpperCase(), color: C.blue };
  const hubFw  = hub?.find(f => f.framework === activeFw);
  const pct    = hubFw?.pct || 0;

  return (
    <div style={{ display: "flex", gap: 0, height: "100%", minHeight: 600 }}>

      {/* ── Left: Framework selector ─────────────────────────────────────── */}
      <div style={{ width: 200, flexShrink: 0, borderRight: `1px solid ${C.border}`,
        paddingRight: 20, marginRight: 24 }}>
        <div style={{ marginBottom: 20 }}>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px",
            fontFamily: "monospace", textTransform: "uppercase", marginBottom: 4 }}>
            COMPLIANCE
          </div>
          <div style={{ color: C.text, fontSize: 16, fontWeight: 700 }}>Assessments</div>
        </div>

        <div style={{ color: C.muted, fontSize: 8, letterSpacing: "1px",
          fontFamily: "monospace", textTransform: "uppercase", marginBottom: 8 }}>
          Frameworks
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {ALL_FW.map(fw => {
            const m   = FW_META[fw];
            const hf  = hub?.find(f => f.framework === fw);
            const fp  = hf?.pct || 0;
            const sc  = hf?.score || 0;
            const act = fw === activeFw;
            return (
              <button key={fw} onClick={() => { setActiveFw(fw); if (fw !== "iso27001") setActiveTab(t => t === "soa" ? "questionnaire" : t); }}
                style={{ display: "flex", alignItems: "center", gap: 8,
                  background: act ? `${m.color}12` : "rgba(255,255,255,0.02)",
                  border: `1px solid ${act ? `${m.color}40` : "rgba(255,255,255,0.05)"}`,
                  color: act ? m.color : C.muted, borderRadius: 6,
                  padding: "8px 10px", fontFamily: "monospace", cursor: "pointer",
                  textAlign: "left", width: "100%" }}>
                <MiniRing pct={fp} color={m.color} size={32} />
                <div>
                  <div style={{ fontSize: 10, fontWeight: act ? 700 : 400 }}>{m.label}</div>
                  <div style={{ fontSize: 8, opacity: 0.6 }}>
                    {Math.round(sc)}% · {hf?.answered || 0}/{hf?.total || 0}
                  </div>
                </div>
              </button>
            );
          })}
        </div>

        <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 6 }}>
          <button onClick={handleSeed} disabled={seeding}
            style={{ width: "100%", background: "rgba(255,255,255,0.04)",
              border: `1px solid ${C.border}`, color: C.muted, padding: "7px 10px",
              borderRadius: 4, fontFamily: "monospace", fontSize: 9, cursor: "pointer",
              opacity: seeding ? 0.6 : 1 }}>
            {seeding ? "Seeding…" : "↻ Re-seed Templates"}
          </button>
          {seedMsg && (
            <div style={{ color: seedMsg.includes("fail") ? C.red : C.accent,
              fontSize: 9, fontFamily: "monospace" }}>{seedMsg}</div>
          )}

          {/* ── Global reset ────────────────────────────────────────────── */}
          <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 8, marginTop: 4 }}>
            <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 7, fontFamily: "monospace",
              textTransform: "uppercase", letterSpacing: "1px", marginBottom: 6 }}>
              Danger zone
            </div>
            {globalConfirm ? (
              <div style={{ background: "rgba(255,59,59,0.06)",
                border: `1px solid rgba(255,59,59,0.25)`,
                borderRadius: 5, padding: "10px 10px" }}>
                <div style={{ color: C.red, fontSize: 9, fontFamily: "monospace",
                  marginBottom: 8, lineHeight: 1.5 }}>
                  This will clear ALL answers across every framework. This cannot be undone.
                </div>
                <div style={{ display: "flex", gap: 6 }}>
                  <button onClick={handleGlobalReset} disabled={globalResetting}
                    style={{ flex: 1, background: `${C.red}20`,
                      border: `1px solid ${C.red}50`, color: C.red,
                      padding: "5px 0", borderRadius: 4, fontFamily: "monospace",
                      fontSize: 9, fontWeight: 700, cursor: "pointer" }}>
                    {globalResetting ? "…" : "Confirm"}
                  </button>
                  <button onClick={() => setGlobalConfirm(false)}
                    style={{ flex: 1, background: "rgba(255,255,255,0.04)",
                      border: `1px solid ${C.border}`, color: C.muted,
                      padding: "5px 0", borderRadius: 4, fontFamily: "monospace",
                      fontSize: 9, cursor: "pointer" }}>
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <button onClick={handleGlobalReset} disabled={globalResetting}
                style={{ width: "100%", background: "rgba(255,59,59,0.06)",
                  border: `1px solid rgba(255,59,59,0.2)`,
                  color: "rgba(255,100,100,0.65)", padding: "7px 10px", borderRadius: 4,
                  fontFamily: "monospace", fontSize: 9, cursor: "pointer",
                  opacity: globalResetting ? 0.6 : 1 }}>
                ✕ Reset All Answers
              </button>
            )}
            {globalResetMsg && (
              <div style={{ color: globalResetMsg.includes("fail") ? C.red : C.muted,
                fontSize: 9, fontFamily: "monospace", marginTop: 6 }}>
                {globalResetMsg}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Right: Content area ───────────────────────────────────────────── */}
      <div style={{ flex: 1, minWidth: 0 }}>
        {/* Framework header */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
          marginBottom: 20 }}>
          <div>
            <div style={{ color: C.muted, fontSize: 8, letterSpacing: "2px",
              fontFamily: "monospace", textTransform: "uppercase", marginBottom: 4 }}>
              {meta.region}
            </div>
            <h2 style={{ color: meta.color, fontSize: 18, fontWeight: 700, margin: 0 }}>
              {meta.label}
            </h2>
          </div>
          {/* Sub-tabs */}
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {[
              { key: "questionnaire", label: "Questionnaire" },
              { key: "controls",      label: "Controls List" },
              { key: "simulate",      label: "What-If Simulation" },
              ...(activeFw === "iso27001"
                ? [{ key: "soa", label: "Statement of Applicability" }]
                : []),
            ].map(({ key, label }) => (
              <button key={key} onClick={() => setActiveTab(key)}
                style={{ background: activeTab === key ? `${meta.color}15` : "rgba(255,255,255,0.04)",
                  border: `1px solid ${activeTab === key ? `${meta.color}50` : "rgba(255,255,255,0.07)"}`,
                  color: activeTab === key ? meta.color : C.muted,
                  padding: "6px 14px", borderRadius: 4, fontFamily: "monospace",
                  fontSize: 10, fontWeight: activeTab === key ? 700 : 400,
                  cursor: "pointer" }}>
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        {activeTab === "questionnaire" ? (
          <QuestionnaireView key={`${activeFw}-${viewKey}`} framework={activeFw} color={meta.color} />
        ) : activeTab === "simulate" ? (
          <SimulateView key={`sim-${activeFw}`} framework={activeFw} color={meta.color} />
        ) : activeTab === "soa" && activeFw === "iso27001" ? (
          <SoAView key="soa" />
        ) : (
          <ControlsList key={activeFw} framework={activeFw} />
        )}
      </div>
    </div>
  );
}
