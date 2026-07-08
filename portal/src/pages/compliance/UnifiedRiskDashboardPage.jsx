/**
 * UnifiedRiskDashboardPage.jsx — Unified Cyber + Enterprise Risk Dashboard (#15 + #20)
 * ======================================================================================
 * Two tabs:
 *   "Risk Overview"    — CSPI + compliance posture + resilience + top risks with financial impact
 *   "Governance Console" — All 9 frameworks organized by domain with score bars
 *
 * Pulls from:
 *   GET /api/benchmark/score     → CSPI
 *   GET /api/comp/dashboard      → framework scores + risks
 *   GET /api/comp/resilience-score → resilience
 *   GET /api/comp/predict        → portfolio trend
 *   GET /api/comp/control-validations → validator health
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

const FW_META = {
  nis2:      { label: "NIS2",      color: "#6378ff", domain: "cyber" },
  dora:      { label: "DORA",      color: "#ffd166", domain: "cyber" },
  nist_csf:  { label: "NIST CSF",  color: "#38bdf8", domain: "cyber" },
  iso27001:  { label: "ISO 27001", color: "#00e5c0", domain: "compliance" },
  soc2:      { label: "SOC 2",     color: "#ff6b6b", domain: "compliance" },
  pci_dss:   { label: "PCI DSS",   color: "#f97316", domain: "compliance" },
  gdpr:      { label: "GDPR",      color: "#8b5cf6", domain: "privacy" },
  eu_ai_act: { label: "EU AI Act", color: "#06b6d4", domain: "ai" },
  iso42001:  { label: "ISO 42001", color: "#10b981", domain: "ai" },
};

const DOMAINS = [
  { id: "cyber",      label: "Cyber Security",     icon: "🛡", color: C.blue },
  { id: "compliance", label: "Compliance",          icon: "✅", color: C.accent },
  { id: "privacy",    label: "Privacy",             icon: "🔐", color: C.purple },
  { id: "ai",         label: "AI Governance",       icon: "🤖", color: "#06b6d4" },
];

function scoreColor(s) {
  if (s == null) return C.muted;
  if (s >= 80) return C.accent;
  if (s >= 60) return C.orange;
  return C.red;
}

function ScoreDonut({ score, size = 90, label }) {
  const r = (size - 14) / 2, cx = size / 2, circ = 2 * Math.PI * r;
  const dash = ((score ?? 0) / 100) * circ;
  const color = scoreColor(score);
  return (
    <div style={{ textAlign: "center" }}>
      <div style={{ position: "relative", display: "inline-block" }}>
        <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
          <circle cx={cx} cy={cx} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={14} />
          <circle cx={cx} cy={cx} r={r} fill="none" stroke={score != null ? color : "rgba(255,255,255,0.06)"}
            strokeWidth={14} strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
            style={{ transition: "stroke-dasharray 1s ease" }} />
        </svg>
        <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column",
          alignItems: "center", justifyContent: "center" }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: score != null ? color : C.muted, fontFamily: "monospace" }}>
            {score != null ? `${Math.round(score)}%` : "—"}
          </div>
        </div>
      </div>
      <div style={{ fontSize: 10, color: C.muted, marginTop: 4, textTransform: "uppercase",
        letterSpacing: 0.7, maxWidth: size }}>{label}</div>
    </div>
  );
}

function ScoreBar({ label, score, color, sublabel }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
        <div>
          <span style={{ fontSize: 13, color: color || C.text, fontWeight: 500 }}>{label}</span>
          {sublabel && <span style={{ fontSize: 10, color: C.muted, marginLeft: 6 }}>{sublabel}</span>}
        </div>
        <span style={{ fontFamily: "monospace", color: scoreColor(score), fontSize: 13 }}>
          {score != null ? `${score.toFixed(1)}%` : "—"}
        </span>
      </div>
      <div style={{ height: 6, background: "rgba(255,255,255,0.06)", borderRadius: 3, overflow: "hidden" }}>
        <div style={{
          height: "100%", width: `${score ?? 0}%`,
          background: scoreColor(score), borderRadius: 3,
          transition: "width 1s ease",
        }} />
      </div>
    </div>
  );
}

function RiskRow({ risk }) {
  const sev  = risk.risk_score >= 20 ? "critical" : risk.risk_score >= 12 ? "high"
    : risk.risk_score >= 6 ? "medium" : "low";
  const sevC = { critical: C.red, high: C.orange, medium: C.blue, low: C.muted }[sev] || C.muted;

  return (
    <tr style={{ borderBottom: `1px solid rgba(255,255,255,0.04)` }}>
      <td style={{ padding: "9px 12px", color: C.text, fontSize: 13, maxWidth: 240 }}>
        <div style={{ fontWeight: 500 }}>{risk.title}</div>
        {risk.business_unit && <div style={{ fontSize: 11, color: C.muted }}>{risk.business_unit}</div>}
      </td>
      <td style={{ padding: "9px 12px" }}>
        <span style={{ color: sevC, fontSize: 11, fontWeight: 600, textTransform: "uppercase" }}>{sev}</span>
      </td>
      <td style={{ padding: "9px 12px", fontFamily: "monospace", fontSize: 12, color: C.muted }}>
        {risk.financial_impact_eur != null
          ? `€${(risk.financial_impact_eur / 1000).toFixed(0)}k`
          : risk.financial_impact || "—"}
      </td>
      <td style={{ padding: "9px 12px" }}>
        <span style={{ color: risk.status === "open" ? C.orange : C.accent, fontSize: 11 }}>
          {risk.status?.replace(/_/g, " ") || "—"}
        </span>
      </td>
    </tr>
  );
}

function ValidatorStatusRow({ v }) {
  const c = { pass: C.accent, fail: C.red, warning: C.orange, unknown: C.muted }[v.status] || C.muted;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 0",
      borderBottom: `1px solid rgba(255,255,255,0.04)` }}>
      <div style={{ width: 8, height: 8, borderRadius: "50%", background: c, flexShrink: 0 }} />
      <div style={{ flex: 1, fontSize: 12, color: C.text }}>{v.title}</div>
      <div style={{ fontSize: 11, color: C.muted }}>{v.category?.replace(/_/g," ")}</div>
      <div style={{ fontSize: 12, color: c, fontFamily: "monospace", width: 48, textAlign: "right" }}>
        {v.score != null ? `${v.score}%` : v.status}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function UnifiedRiskDashboardPage() {
  const [activeTab, setTab]       = useState("overview");
  const [cspi, setCspi]           = useState(null);
  const [dashboard, setDash]      = useState(null);
  const [resilience, setResil]    = useState(null);
  const [predictions, setPred]    = useState(null);
  const [validators, setValid]    = useState([]);
  const [loading, setLoading]     = useState(true);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [cspiR, dashR, resilR, predR, validR] = await Promise.allSettled([
        fetch(`${API_BASE}/api/benchmark/score`,              { credentials: "include" }).then(r => r.json()),
        fetch(`${API_BASE}/api/comp/dashboard`,               { credentials: "include" }).then(r => r.json()),
        fetch(`${API_BASE}/api/comp/resilience-score`,        { credentials: "include" }).then(r => r.json()),
        fetch(`${API_BASE}/api/comp/predict`,                 { credentials: "include" }).then(r => r.json()),
        fetch(`${API_BASE}/api/comp/control-validations`,     { credentials: "include" }).then(r => r.json()),
      ]);

      if (cspiR.status === "fulfilled")  setCspi(cspiR.value);
      if (dashR.status === "fulfilled")  setDash(dashR.value);
      if (resilR.status === "fulfilled") setResil(resilR.value);
      if (predR.status === "fulfilled")  setPred(predR.value);
      if (validR.status === "fulfilled") setValid(validR.value?.validations || []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  // Derived data
  const fwScores  = dashboard?.framework_scores || [];
  const topRisks  = (dashboard?.top_risks || []).slice(0, 8);
  const overallScore = fwScores.length
    ? fwScores.reduce((s, f) => s + (f.score || 0), 0) / fwScores.length
    : null;
  const cspiScore = cspi?.total_score ?? cspi?.score ?? null;
  const resilScore = resilience?.composite_score ?? null;

  // Scores by framework id
  const scoreMap = {};
  fwScores.forEach(f => { scoreMap[f.framework] = f.score; });

  // Validator health summary
  const validFail = validators.filter(v => v.status === "fail").length;
  const validWarn = validators.filter(v => v.status === "warning").length;

  // Prediction trend
  const predTrend = predictions?.overall_direction;

  return (
    <div style={{ padding: "28px 32px", background: C.bg, minHeight: "100vh", color: C.text, fontFamily: "system-ui, sans-serif" }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <div style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>Unified Risk Console</div>
          <div style={{ color: C.muted, fontSize: 13 }}>
            Cyber · Operational · Compliance · Privacy · AI governance — in a single view.
          </div>
        </div>
        <button onClick={loadAll}
          style={{ background: "rgba(255,255,255,0.05)", color: C.text, border: `1px solid ${C.border}`,
            borderRadius: 6, padding: "8px 16px", fontSize: 12, fontWeight: 600, cursor: "pointer" }}>
          Refresh
        </button>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 24, borderBottom: `1px solid ${C.border}` }}>
        {[
          { id: "overview",    label: "Risk Overview" },
          { id: "governance",  label: "Governance Console" },
        ].map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{
              background: "none", border: "none", padding: "9px 18px", cursor: "pointer",
              fontWeight: 500, fontSize: 14, color: activeTab === t.id ? C.accent : C.muted,
              borderBottom: activeTab === t.id ? `2px solid ${C.accent}` : "2px solid transparent",
            }}>
            {t.label}
          </button>
        ))}
      </div>

      {loading ? (
        <div style={{ color: C.muted, textAlign: "center", padding: 60, fontSize: 13 }}>Loading…</div>
      ) : activeTab === "overview" ? (

        // ── Risk Overview ────────────────────────────────────────────────────────
        <>
          {/* Top KPI row */}
          <div style={{ display: "flex", gap: 20, marginBottom: 24, flexWrap: "wrap", alignItems: "flex-start" }}>
            <ScoreDonut score={cspiScore}    label="Security Posture Index" size={96} />
            <ScoreDonut score={overallScore} label="Compliance Score"       size={96} />
            <ScoreDonut score={resilScore}   label="Cyber Resilience"       size={96} />
            <div style={{ ...CARD, flex: 1, minWidth: 220 }}>
              <div style={{ fontSize: 11, color: C.muted, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.7 }}>
                Portfolio Trend
              </div>
              <div style={{ fontSize: 24, fontWeight: 700, marginBottom: 4,
                color: predTrend === "improving" ? C.accent : predTrend === "declining" ? C.red : C.muted }}>
                {predTrend === "improving" ? "↑ Improving" : predTrend === "declining" ? "↓ Declining" : "→ Mixed"}
              </div>
              <div style={{ color: C.muted, fontSize: 12 }}>
                {predictions?.count_improving ?? "—"} improving · {predictions?.count_declining ?? "—"} declining
              </div>
            </div>
            <div style={{ ...CARD, minWidth: 160 }}>
              <div style={{ fontSize: 11, color: C.muted, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.7 }}>
                Control Validators
              </div>
              <div style={{ fontSize: 22, fontWeight: 700, color: validFail > 0 ? C.red : C.accent, fontFamily: "monospace" }}>
                {validFail} fail
              </div>
              <div style={{ color: C.orange, fontSize: 12 }}>{validWarn} warning</div>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>

            {/* Top Risks with Financial Impact */}
            <div style={CARD}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 14 }}>
                Top Risks — Financial Impact
              </div>
              {topRisks.length === 0 ? (
                <div style={{ color: C.muted, fontSize: 13 }}>No risks found. Add risks in the Risk Register.</div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                  <thead>
                    <tr style={{ color: C.muted, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.7,
                      borderBottom: `1px solid ${C.border}` }}>
                      {["Risk", "Severity", "Financial", "Status"].map(h => (
                        <th key={h} style={{ padding: "6px 12px", textAlign: "left" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {topRisks.map(r => <RiskRow key={r.id} risk={r} />)}
                  </tbody>
                </table>
              )}
            </div>

            {/* Control Validator Health */}
            <div style={CARD}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 14 }}>
                Technical Control Health
              </div>
              {validators.length === 0 ? (
                <div style={{ color: C.muted, fontSize: 13 }}>
                  No validations yet. Run POST /api/comp/control-validations/run to validate.
                </div>
              ) : (
                <div>
                  {validators.slice(0, 10).map(v => <ValidatorStatusRow key={v.validator_id} v={v} />)}
                  {validators.length > 10 && (
                    <div style={{ color: C.muted, fontSize: 11, marginTop: 8 }}>
                      +{validators.length - 10} more validators
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </>

      ) : (

        // ── Governance Console ────────────────────────────────────────────────────
        <>
          <div style={{ marginBottom: 16, color: C.muted, fontSize: 13 }}>
            All 9 GRC frameworks organized by governance domain. Click any framework to open its assessment.
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
            {DOMAINS.map(domain => {
              const fws = Object.entries(FW_META).filter(([, m]) => m.domain === domain.id);
              const domainScores = fws.map(([id]) => scoreMap[id]).filter(s => s != null);
              const avgScore = domainScores.length
                ? domainScores.reduce((a, b) => a + b, 0) / domainScores.length
                : null;

              return (
                <div key={domain.id} style={CARD}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <span style={{ fontSize: 20 }}>{domain.icon}</span>
                      <div>
                        <div style={{ fontWeight: 700, color: domain.color, fontSize: 14 }}>{domain.label}</div>
                        <div style={{ fontSize: 11, color: C.muted }}>{fws.length} framework{fws.length !== 1 ? "s" : ""}</div>
                      </div>
                    </div>
                    {avgScore !== null && (
                      <div style={{ textAlign: "right" }}>
                        <div style={{ fontSize: 22, fontWeight: 700, fontFamily: "monospace", color: scoreColor(avgScore) }}>
                          {avgScore.toFixed(1)}%
                        </div>
                        <div style={{ fontSize: 10, color: C.muted }}>domain avg</div>
                      </div>
                    )}
                  </div>

                  {fws.map(([id, meta]) => (
                    <ScoreBar
                      key={id}
                      label={meta.label}
                      score={scoreMap[id] ?? null}
                      color={meta.color}
                      sublabel={scoreMap[id] == null ? "no data" : null}
                    />
                  ))}

                  {/* Domain health indicator */}
                  <div style={{ marginTop: 12, padding: "8px 12px",
                    background: "rgba(255,255,255,0.02)", borderRadius: 6, fontSize: 12 }}>
                    {fws.map(([id, meta]) => {
                      const s = scoreMap[id];
                      const pred30 = predictions?.by_framework?.find(f => f.framework === id);
                      return (
                        <div key={id} style={{ display: "flex", justifyContent: "space-between",
                          marginBottom: 4, fontSize: 11 }}>
                          <span style={{ color: meta.color }}>{meta.label}</span>
                          <span style={{ color: C.muted }}>
                            {pred30?.trend === "improving" ? "↑ improving" :
                             pred30?.trend === "declining" ? "↓ declining" :
                             pred30?.trend === "stable"    ? "→ stable" : "—"}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Summary executive line */}
          <div style={{ ...CARD, marginTop: 20, display: "flex", gap: 32, flexWrap: "wrap" }}>
            <div style={{ fontSize: 13, color: C.muted }}>Frameworks deployed</div>
            <div style={{ fontFamily: "monospace", fontWeight: 700, color: C.text }}>
              {Object.keys(FW_META).length}
            </div>
            <div style={{ fontSize: 13, color: C.muted }}>Overall compliance</div>
            <div style={{ fontFamily: "monospace", fontWeight: 700, color: scoreColor(overallScore) }}>
              {overallScore != null ? `${overallScore.toFixed(1)}%` : "—"}
            </div>
            <div style={{ fontSize: 13, color: C.muted }}>Security posture index</div>
            <div style={{ fontFamily: "monospace", fontWeight: 700, color: scoreColor(cspiScore) }}>
              {cspiScore != null ? `${Math.round(cspiScore)}%` : "—"}
            </div>
            <div style={{ fontSize: 13, color: C.muted }}>Control validators failing</div>
            <div style={{ fontFamily: "monospace", fontWeight: 700, color: validFail > 0 ? C.red : C.accent }}>
              {validFail}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
