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

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};

const FW_META = {
  nis2:     { label: "NIS2 Directive",      color: "#6378ff", region: "EU" },
  dora:     { label: "DORA",                color: "#ffd166", region: "EU" },
  iso27001: { label: "ISO 27001:2022",      color: "#00e5c0", region: "INTL" },
  soc2:     { label: "SOC 2",               color: "#ff6b6b", region: "US" },
  nist_csf: { label: "NIST CSF 2.0",        color: "#38bdf8", region: "US" },
  pci_dss:  { label: "PCI DSS v4.0",        color: "#f97316", region: "PCI" },
};

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

function QuestionRow({ q, response, onSave, saving }) {
  const [val, setVal]     = useState(response?.response || "");
  const [notes, setNotes] = useState(response?.notes || "");
  const [open, setOpen]   = useState(false);

  // Sync if response changes from parent reload
  useEffect(() => { setVal(response?.response || ""); setNotes(response?.notes || ""); }, [response]);

  const sc    = response?.score ?? null;
  const statusColor = sc === null ? C.muted : sc >= 2 ? C.accent : sc === 1 ? C.orange : C.red;

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
                {q.weight === 3 && (
                  <span style={{ color: C.red, fontSize: 8, fontFamily: "monospace",
                    fontWeight: 700 }}>Critical weight</span>
                )}
              </div>
            </div>
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
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving]   = useState({});
  const [section, setSection] = useState(null);
  const [genMsg, setGenMsg]   = useState(null);
  const [genning, setGenning] = useState(false);

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
      .then(() => load())
      .catch(e => console.error("save failed", e))
      .finally(() => setSaving(s => ({ ...s, [question_id]: false })));
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
        <div style={{ marginLeft: "auto", display: "flex", flexDirection: "column", gap: 6 }}>
          <button onClick={handleGenFindings} disabled={genning}
            style={{ background: `${C.orange}10`, border: `1px solid ${C.orange}40`,
              color: C.orange, padding: "5px 12px", borderRadius: 4, fontFamily: "monospace",
              fontSize: 9, fontWeight: 700, cursor: "pointer", opacity: genning ? 0.6 : 1,
              whiteSpace: "nowrap" }}>
            {genning ? "Generating…" : "Generate Gap Findings"}
          </button>
          {genMsg && <span style={{ color: genMsg.includes("fail") ? C.red : C.orange,
            fontSize: 9, fontFamily: "monospace" }}>{genMsg}</span>}
        </div>
      </div>

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
              onSave={handleSave} saving={Boolean(saving[q.question_id])} />
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Main export ───────────────────────────────────────────────────────────────

const ALL_FW = Object.keys(FW_META);

export function ComplianceAssessmentPage() {
  const [activeFw, setActiveFw]   = useState("nis2");
  const [activeTab, setActiveTab] = useState("questionnaire"); // "questionnaire" | "controls"
  const [hub, setHub]             = useState(null);
  const [seeding, setSeeding]     = useState(false);
  const [seedMsg, setSeedMsg]     = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/api/comp/questionnaire/hub`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setHub(d.frameworks || []); })
      .catch(() => {});
  }, []);

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
              <button key={fw} onClick={() => setActiveFw(fw)}
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

        <div style={{ marginTop: 16 }}>
          <button onClick={handleSeed} disabled={seeding}
            style={{ width: "100%", background: "rgba(255,255,255,0.04)",
              border: `1px solid ${C.border}`, color: C.muted, padding: "7px 10px",
              borderRadius: 4, fontFamily: "monospace", fontSize: 9, cursor: "pointer",
              opacity: seeding ? 0.6 : 1 }}>
            {seeding ? "Seeding…" : "↻ Re-seed Templates"}
          </button>
          {seedMsg && (
            <div style={{ color: seedMsg.includes("fail") ? C.red : C.accent,
              fontSize: 9, fontFamily: "monospace", marginTop: 6 }}>{seedMsg}</div>
          )}
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
          <div style={{ display: "flex", gap: 6 }}>
            {[
              { key: "questionnaire", label: "Questionnaire" },
              { key: "controls",      label: "Controls List" },
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
          <QuestionnaireView key={activeFw} framework={activeFw} color={meta.color} />
        ) : (
          <ControlsList key={activeFw} framework={activeFw} />
        )}
      </div>
    </div>
  );
}
