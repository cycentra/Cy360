/**
 * ComplianceAssessmentPage.jsx
 * ==============================
 * Two views in one component:
 *   Hub  — all-framework progress cards + seed / generate-findings actions
 *   Form — per-framework questionnaire with section navigation
 */

import { useState, useEffect, useCallback } from "react";
import { API_BASE } from "../../core/constants.js";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};
const CARD = {
  background: "rgba(255,255,255,0.02)", border: `1px solid ${C.border}`,
  borderRadius: 8, padding: "20px 24px",
};

const FW_COLORS = {
  nis2: "#6378ff", iso27001: "#00e5c0", dora: "#ffd166",
  soc2: "#ff6b6b", avg: "#a78bfa", nist_csf: "#38bdf8", pci_dss: "#f97316",
};
const FW_LABELS = {
  nis2: "NIS2", dora: "DORA", iso27001: "ISO 27001",
  soc2: "SOC 2", nist_csf: "NIST CSF", pci_dss: "PCI DSS", avg: "GDPR/AVG",
};

function scoreColor(s) {
  if (s >= 80) return C.accent;
  if (s >= 60) return C.orange;
  return C.red;
}

// ── Hub ───────────────────────────────────────────────────────────────────────

function FrameworkCard({ fw, onOpen }) {
  const color = FW_COLORS[fw.framework] || C.blue;
  const sc    = scoreColor(fw.score);
  return (
    <div style={{ ...CARD, position: "relative", overflow: "hidden", cursor: "pointer" }}
      onClick={() => onOpen(fw.framework)}>
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 3,
        background: `linear-gradient(90deg, ${color}80, ${color}10)` }} />

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
        <div>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px", fontFamily: "monospace",
            textTransform: "uppercase", marginBottom: 6 }}>{fw.label || fw.framework}</div>
          <div style={{ display: "flex", alignItems: "flex-end", gap: 4 }}>
            <span style={{ color: sc, fontSize: 32, fontFamily: "monospace", fontWeight: 700, lineHeight: 1 }}>
              {Math.round(fw.score)}
            </span>
            <span style={{ color: sc, fontSize: 14, fontFamily: "monospace", marginBottom: 3 }}>%</span>
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>Progress</div>
          <div style={{ color: C.text, fontSize: 18, fontFamily: "monospace", fontWeight: 700 }}>
            {fw.answered}/{fw.total}
          </div>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>questions</div>
        </div>
      </div>

      {/* Progress bar */}
      <div style={{ height: 4, background: "rgba(255,255,255,0.05)", borderRadius: 2, marginBottom: 14 }}>
        <div style={{ height: "100%", width: `${fw.pct}%`, background: color, borderRadius: 2,
          transition: "width 1s ease" }} />
      </div>

      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
        {[
          { label: "Gaps",    val: fw.gap_count,     color: fw.gap_count > 0 ? C.red : C.muted },
          { label: "Partial", val: fw.partial_count, color: fw.partial_count > 0 ? C.orange : C.muted },
          { label: "Done %",  val: `${Math.round(fw.pct)}%`, color: color },
        ].map(({ label, val, color: vc }) => (
          <div key={label} style={{ textAlign: "center" }}>
            <div style={{ color: vc, fontSize: 14, fontFamily: "monospace", fontWeight: 700 }}>{val}</div>
            <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>{label}</div>
          </div>
        ))}
      </div>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end" }}>
        <span style={{ color, fontSize: 10, fontFamily: "monospace", fontWeight: 700,
          letterSpacing: "0.5px" }}>
          START ASSESSMENT →
        </span>
      </div>
    </div>
  );
}

function Hub({ onOpen }) {
  const [frameworks, setFrameworks] = useState([]);
  const [loading, setLoading]       = useState(true);
  const [seeding, setSeeding]       = useState(false);
  const [seedMsg, setSeedMsg]       = useState(null);
  const [genMsg, setGenMsg]         = useState(null);
  const [genning, setGenning]       = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    fetch(`${API_BASE}/api/comp/questionnaire/hub`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setFrameworks(d.frameworks || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleSeed = () => {
    setSeeding(true); setSeedMsg(null);
    fetch(`${API_BASE}/api/comp/questionnaire/seed`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ force: true }),
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        setSeedMsg(`Seeded ${d.result?.inserted || 0} questions (${d.result?.skipped || 0} existing skipped)`);
        load();
      })
      .catch(e => setSeedMsg(`Seed failed (${e})`))
      .finally(() => setSeeding(false));
  };

  const handleGenFindings = () => {
    setGenning(true); setGenMsg(null);
    fetch(`${API_BASE}/api/comp/findings/auto-generate`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        const r = d.result || {};
        setGenMsg(`Findings: ${r.created || 0} created, ${r.updated || 0} updated across ${(r.frameworks_processed || []).length} frameworks`);
      })
      .catch(e => setGenMsg(`Failed (${e})`))
      .finally(() => setGenning(false));
  };

  const totalFws     = frameworks.length;
  const totalQs      = frameworks.reduce((s, f) => s + f.total, 0);
  const totalAnswered = frameworks.reduce((s, f) => s + f.answered, 0);
  const totalGaps    = frameworks.reduce((s, f) => s + f.gap_count, 0);

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px", fontFamily: "monospace",
          textTransform: "uppercase", marginBottom: 6 }}>SECURITY COMPLIANCE</div>
        <h1 style={{ color: C.text, fontSize: 22, fontWeight: 700, margin: 0 }}>
          Compliance Assessment Hub
        </h1>
        <div style={{ color: C.muted, fontSize: 12, marginTop: 4, fontFamily: "monospace" }}>
          Framework-specific questionnaires to identify gaps and generate findings
        </div>
      </div>

      {/* Overall stats */}
      <div style={{ ...CARD, display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 24, marginBottom: 24 }}>
        {[
          { label: "Frameworks",   val: totalFws,      color: C.blue },
          { label: "Total Questions", val: totalQs,    color: C.text },
          { label: "Answered",     val: totalAnswered, color: C.accent },
          { label: "Open Gaps",    val: totalGaps,     color: totalGaps > 0 ? C.red : C.muted },
        ].map(({ label, val, color }) => (
          <div key={label} style={{ textAlign: "center" }}>
            <div style={{ color, fontSize: 28, fontFamily: "monospace", fontWeight: 700 }}>{val}</div>
            <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Actions */}
      <div style={{ display: "flex", gap: 12, marginBottom: 28, flexWrap: "wrap", alignItems: "center" }}>
        <button onClick={handleSeed} disabled={seeding}
          style={{ background: `${C.blue}10`, border: `1px solid ${C.blue}40`, color: C.blue,
            padding: "8px 18px", borderRadius: 4, fontFamily: "monospace", fontSize: 11,
            fontWeight: 700, cursor: "pointer", opacity: seeding ? 0.6 : 1 }}>
          {seeding ? "Seeding..." : "Re-seed Question Templates"}
        </button>
        <button onClick={handleGenFindings} disabled={genning}
          style={{ background: `${C.orange}10`, border: `1px solid ${C.orange}40`, color: C.orange,
            padding: "8px 18px", borderRadius: 4, fontFamily: "monospace", fontSize: 11,
            fontWeight: 700, cursor: "pointer", opacity: genning ? 0.6 : 1 }}>
          {genning ? "Generating..." : "Auto-Generate Findings from Alerts"}
        </button>
        {seedMsg && <span style={{ color: seedMsg.includes("fail") ? C.red : C.accent,
          fontSize: 10, fontFamily: "monospace" }}>{seedMsg}</span>}
        {genMsg && <span style={{ color: genMsg.includes("fail") ? C.red : C.orange,
          fontSize: 10, fontFamily: "monospace" }}>{genMsg}</span>}
      </div>

      {/* Framework cards */}
      {loading ? (
        <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12, padding: 40 }}>Loading...</div>
      ) : frameworks.length === 0 ? (
        <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12, padding: 40 }}>
          No questionnaire templates found. Click "Re-seed Question Templates" to initialise.
        </div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 16 }}>
          {frameworks.map(fw => <FrameworkCard key={fw.framework} fw={fw} onOpen={onOpen} />)}
        </div>
      )}

      {/* Flow guide */}
      <div style={{ ...CARD, marginTop: 32 }}>
        <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px", fontFamily: "monospace",
          textTransform: "uppercase", marginBottom: 16 }}>Getting Started — Recommended Flow</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 16 }}>
          {[
            { step: "1", label: "Upload Policy Docs", desc: "Go to Policy Documents → create a collection per framework → upload your security policies.", color: C.blue },
            { step: "2", label: "Run Enrichment", desc: "Go to Live Alerts → Run Compliance Enrichment to tag existing alerts with MITRE/framework mappings.", color: C.orange },
            { step: "3", label: "Complete Assessments", desc: "Answer all questions below — NO answers create gap findings automatically.", color: C.purple },
            { step: "4", label: "Generate Findings", desc: 'Click "Auto-Generate Findings from Alerts" above to turn alert data into actionable findings.', color: C.accent },
            { step: "5", label: "Review & Act", desc: "Go to Findings to see BREACH / WARNING verdicts with specific remediation steps.", color: C.red },
            { step: "6", label: "Generate Report", desc: "Go to Reports → Generate a compliance report with scores, gaps, and remediation roadmap.", color: C.muted },
          ].map(({ step, label, desc, color }) => (
            <div key={step} style={{ padding: "14px 16px", borderRadius: 6,
              background: `${color}08`, border: `1px solid ${color}20` }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <span style={{ width: 20, height: 20, borderRadius: "50%", background: `${color}30`,
                  border: `1px solid ${color}60`, display: "flex", alignItems: "center",
                  justifyContent: "center", fontSize: 9, fontFamily: "monospace",
                  fontWeight: 700, color, flexShrink: 0 }}>{step}</span>
                <span style={{ color, fontSize: 10, fontFamily: "monospace",
                  fontWeight: 700, letterSpacing: "0.5px" }}>{label}</span>
              </div>
              <div style={{ color: C.muted, fontSize: 10, lineHeight: 1.5 }}>{desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Per-framework questionnaire ───────────────────────────────────────────────

function QuestionRow({ q, response, onSave, saving }) {
  const [val, setVal]     = useState(response?.response || "");
  const [notes, setNotes] = useState(response?.notes || "");
  const [open, setOpen]   = useState(false);
  const isDone = Boolean(response?.response);
  const sc     = response?.score ?? null;
  const statusColor = sc === null ? C.muted : sc >= 2 ? C.accent : sc === 1 ? C.orange : C.red;
  const statusLabel = sc === null ? "—" : sc >= 2 ? "Pass" : sc === 1 ? "Partial" : "Gap";

  const submit = () => {
    if (!val) return;
    onSave(q.question_id, val, notes);
  };

  return (
    <div style={{ borderBottom: `1px solid rgba(255,255,255,0.04)`, padding: "14px 0" }}>
      <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
        {/* Status dot */}
        <div style={{ width: 8, height: 8, borderRadius: "50%", background: statusColor,
          marginTop: 6, flexShrink: 0 }} />

        <div style={{ flex: 1 }}>
          {/* Question */}
          <div style={{ display: "flex", gap: 10, alignItems: "flex-start", cursor: "pointer" }}
            onClick={() => setOpen(o => !o)}>
            <div style={{ flex: 1 }}>
              <div style={{ color: C.text, fontSize: 12, lineHeight: 1.5, marginBottom: 4 }}>
                {q.question}
              </div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {q.control_ref && (
                  <span style={{ color: C.blue, fontSize: 9, fontFamily: "monospace",
                    background: `${C.blue}12`, padding: "1px 5px", borderRadius: 3 }}>
                    {q.control_ref}
                  </span>
                )}
                <span style={{ color: statusColor, fontSize: 9, fontFamily: "monospace",
                  background: `${statusColor}12`, padding: "1px 5px", borderRadius: 3 }}>
                  {statusLabel}
                </span>
                {q.weight === 3 && (
                  <span style={{ color: C.red, fontSize: 9, fontFamily: "monospace" }}>Critical</span>
                )}
              </div>
            </div>
            <span style={{ color: C.muted, fontSize: 11, flexShrink: 0, marginTop: 2 }}>
              {open ? "▲" : "▼"}
            </span>
          </div>

          {open && (
            <div style={{ marginTop: 12, paddingLeft: 0 }}>
              {/* Guidance */}
              {q.guidance && (
                <div style={{ color: C.muted, fontSize: 10, lineHeight: 1.6,
                  background: "rgba(255,255,255,0.02)", borderRadius: 4,
                  padding: "8px 12px", marginBottom: 12, fontFamily: "monospace",
                  borderLeft: `2px solid ${C.blue}30` }}>
                  <span style={{ color: C.blue, fontWeight: 700 }}>Guidance: </span>{q.guidance}
                </div>
              )}

              {/* Input */}
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
                          ? (opt === "yes" ? C.accent : opt === "no" ? C.red : C.orange)
                          : C.muted,
                        borderRadius: 4, padding: "6px 16px",
                        fontFamily: "monospace", fontSize: 11, fontWeight: 700,
                        cursor: "pointer", textTransform: "uppercase", letterSpacing: "0.5px",
                      }}>
                      {opt}
                    </button>
                  ))}
                </div>
              ) : q.question_type === "score_1_5" ? (
                <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
                  {[1,2,3,4,5].map(n => (
                    <button key={n} onClick={() => setVal(String(n))}
                      style={{
                        width: 36, height: 36,
                        background: val === String(n) ? `${C.blue}25` : "rgba(255,255,255,0.04)",
                        border: `1px solid ${val === String(n) ? C.blue : "rgba(255,255,255,0.1)"}`,
                        color: val === String(n) ? C.blue : C.muted,
                        borderRadius: 4, fontFamily: "monospace", fontSize: 13,
                        fontWeight: 700, cursor: "pointer",
                      }}>
                      {n}
                    </button>
                  ))}
                  <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                    alignSelf: "center", marginLeft: 4 }}>1=None · 5=Fully implemented</span>
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
                <textarea
                  value={val}
                  onChange={e => setVal(e.target.value)}
                  placeholder="Enter your response..."
                  rows={2}
                  style={{
                    width: "100%", background: "#0d1117",
                    border: `1px solid ${C.border}`, color: C.text,
                    borderRadius: 4, padding: "8px 10px", fontFamily: "monospace",
                    fontSize: 11, resize: "vertical", marginBottom: 8, boxSizing: "border-box",
                  }}
                />
              )}

              {/* Notes */}
              <input
                value={notes}
                onChange={e => setNotes(e.target.value)}
                placeholder="Notes / evidence reference (optional)..."
                style={{
                  width: "100%", background: "#0d1117",
                  border: `1px solid ${C.border}`, color: C.text,
                  borderRadius: 4, padding: "6px 10px", fontFamily: "monospace",
                  fontSize: 10, marginBottom: 10, boxSizing: "border-box",
                }}
              />

              <button
                onClick={submit}
                disabled={!val || saving}
                style={{
                  background: `${C.accent}15`, border: `1px solid ${C.accent}40`,
                  color: C.accent, borderRadius: 4, padding: "6px 16px",
                  fontFamily: "monospace", fontSize: 11, fontWeight: 700,
                  cursor: "pointer", opacity: !val || saving ? 0.5 : 1,
                }}>
                {saving ? "Saving..." : "Save Answer"}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function QuestionnaireForm({ framework, onBack }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving]   = useState({});
  const [section, setSection] = useState(null);
  const [genMsg, setGenMsg]   = useState(null);
  const [genning, setGenning] = useState(false);

  const color = FW_COLORS[framework] || C.blue;
  const label = FW_LABELS[framework] || framework.toUpperCase();

  const load = useCallback(() => {
    setLoading(true);
    fetch(`${API_BASE}/api/comp/questionnaire/${framework}`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setData(d); setLoading(false); })
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
        setGenMsg(`${r.created || 0} gap findings created, ${r.skipped || 0} already existed`);
      })
      .catch(e => setGenMsg(`Failed (${e})`))
      .finally(() => setGenning(false));
  };

  if (loading || !data) return (
    <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12, padding: 40 }}>Loading...</div>
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
      {/* Back + header */}
      <div style={{ marginBottom: 24 }}>
        <button onClick={onBack}
          style={{ background: "none", border: "none", color: C.muted, cursor: "pointer",
            fontFamily: "monospace", fontSize: 11, marginBottom: 12, padding: 0 }}>
          ← Back to Hub
        </button>
        <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px", fontFamily: "monospace",
          textTransform: "uppercase", marginBottom: 4 }}>COMPLIANCE ASSESSMENT</div>
        <h1 style={{ color: C.text, fontSize: 20, fontWeight: 700, margin: 0 }}>
          {label} Assessment
        </h1>
      </div>

      {/* Score banner */}
      <div style={{ ...CARD, display: "flex", gap: 32, alignItems: "center", marginBottom: 20,
        borderLeft: `3px solid ${color}` }}>
        <div>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
            textTransform: "uppercase", marginBottom: 4 }}>Assessment Score</div>
          <div style={{ display: "flex", alignItems: "flex-end", gap: 4 }}>
            <span style={{ color: scoreColor(score.score || 0), fontSize: 40,
              fontFamily: "monospace", fontWeight: 700, lineHeight: 1 }}>
              {Math.round(score.score || 0)}
            </span>
            <span style={{ color: scoreColor(score.score || 0), fontSize: 18,
              fontFamily: "monospace", marginBottom: 5 }}>%</span>
          </div>
        </div>
        <div style={{ flex: 1, borderLeft: `1px solid ${C.border}`, paddingLeft: 32,
          display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
          {[
            { label: "Total",    val: score.total || templates.length, color: C.text },
            { label: "Answered", val: answered,   color: C.accent },
            { label: "Gaps",     val: gaps,       color: gaps > 0 ? C.red : C.muted },
            { label: "Partial",  val: score.partial?.length || 0, color: C.orange },
          ].map(({ label, val, color: vc }) => (
            <div key={label} style={{ textAlign: "center" }}>
              <div style={{ color: vc, fontSize: 22, fontFamily: "monospace", fontWeight: 700 }}>{val}</div>
              <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>{label}</div>
            </div>
          ))}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <button onClick={handleGenFindings} disabled={genning}
            style={{ background: `${C.orange}10`, border: `1px solid ${C.orange}40`, color: C.orange,
              padding: "7px 14px", borderRadius: 4, fontFamily: "monospace", fontSize: 10,
              fontWeight: 700, cursor: "pointer", opacity: genning ? 0.6 : 1, whiteSpace: "nowrap" }}>
            {genning ? "Generating..." : "Generate Gap Findings"}
          </button>
          {genMsg && <span style={{ color: genMsg.includes("fail") ? C.red : C.orange,
            fontSize: 9, fontFamily: "monospace" }}>{genMsg}</span>}
        </div>
      </div>

      <div style={{ display: "flex", gap: 24 }}>
        {/* Section sidebar */}
        <div style={{ width: 200, flexShrink: 0 }}>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1px", fontFamily: "monospace",
            textTransform: "uppercase", marginBottom: 10 }}>Sections</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {sections.map(sec => {
              const secQs     = templates.filter(t => t.section === sec);
              const secDone   = secQs.filter(t => responses[t.question_id]).length;
              const secGaps   = secQs.filter(t => {
                const r = responses[t.question_id];
                return r && (r.score === 0);
              }).length;
              const isActive  = sec === activeSec;
              const isDone    = secDone === secQs.length;
              return (
                <button key={sec} onClick={() => setSection(sec)}
                  style={{
                    background: isActive ? `${color}15` : "rgba(255,255,255,0.02)",
                    border: `1px solid ${isActive ? `${color}40` : "rgba(255,255,255,0.05)"}`,
                    color: isActive ? color : C.muted,
                    borderRadius: 4, padding: "8px 12px", fontFamily: "monospace",
                    fontSize: 10, cursor: "pointer", textAlign: "left",
                  }}>
                  <div style={{ fontWeight: isActive ? 700 : 400, marginBottom: 3 }}>{sec}</div>
                  <div style={{ fontSize: 9, opacity: 0.7 }}>
                    {secDone}/{secQs.length}
                    {secGaps > 0 && <span style={{ color: C.red, marginLeft: 4 }}> · {secGaps} gap</span>}
                    {isDone && secGaps === 0 && <span style={{ color: C.accent, marginLeft: 4 }}> ✓</span>}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Questions */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1px", fontFamily: "monospace",
            textTransform: "uppercase", marginBottom: 12 }}>{activeSec}</div>
          <div>
            {visible.map(q => (
              <QuestionRow
                key={q.question_id}
                q={q}
                response={responses[q.question_id]}
                onSave={handleSave}
                saving={Boolean(saving[q.question_id])}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main export ───────────────────────────────────────────────────────────────

export function ComplianceAssessmentPage() {
  const [activeFramework, setActiveFramework] = useState(null);

  if (activeFramework) {
    return (
      <QuestionnaireForm
        framework={activeFramework}
        onBack={() => setActiveFramework(null)}
      />
    );
  }
  return <Hub onOpen={fw => setActiveFramework(fw)} />;
}
