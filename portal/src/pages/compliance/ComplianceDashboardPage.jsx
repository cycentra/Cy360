/**
 * ComplianceDashboardPage.jsx
 * ============================
 * GRC Compliance posture overview.
 * Shows: framework posture score cards, active alerts widget, findings summary.
 */

import { useState, useEffect } from "react";
import { API_BASE } from "../../core/constants.js";

// ── Design tokens ────────────────────────────────────────────────────────────
const C = {
  bg:      "#090b10",
  surface: "#0d1117",
  border:  "rgba(255,255,255,0.07)",
  text:    "rgba(255,255,255,0.82)",
  muted:   "rgba(255,255,255,0.45)",
  accent:  "#00e5a0",
  red:     "#ff3b3b",
  orange:  "#ff8c00",
  blue:    "#4d9eff",
  purple:  "#b06eff",
};

const CARD = {
  background: "rgba(255,255,255,0.02)",
  border: `1px solid ${C.border}`,
  borderRadius: 8,
  padding: "20px 24px",
};

const FW_LABELS = {
  nis2:      "NIS2",
  dora:      "DORA",
  iso27001:  "ISO 27001",
  soc2:      "SOC 2",
  nist_csf:  "NIST CSF",
  pci_dss:   "PCI DSS",
};

function scoreColor(score) {
  if (score >= 80) return C.accent;
  if (score >= 60) return C.orange;
  return C.red;
}

function ScoreCard({ fw }) {
  const color = scoreColor(fw.score);
  const pct   = Math.round(fw.score);
  return (
    <div style={{ ...CARD, position: "relative", overflow: "hidden" }}>
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 3,
        background: `linear-gradient(90deg, ${color}80, ${color}20)` }} />
      <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
        fontFamily: "monospace", textTransform: "uppercase", marginBottom: 10 }}>
        {FW_LABELS[fw.framework] || fw.framework}
      </div>
      <div style={{ display: "flex", alignItems: "flex-end", gap: 8, marginBottom: 12 }}>
        <div style={{ color, fontSize: 42, fontFamily: "monospace", fontWeight: 700, lineHeight: 1 }}>
          {pct}
        </div>
        <div style={{ color, fontSize: 18, fontFamily: "monospace", marginBottom: 4 }}>%</div>
      </div>
      {/* Progress bar */}
      <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2, marginBottom: 12 }}>
        <div style={{ height: "100%", width: `${pct}%`, background: color,
          borderRadius: 2, transition: "width 1s ease" }} />
      </div>
      <div style={{ display: "flex", justifyContent: "space-between" }}>
        <div>
          <div style={{ color: C.accent, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>
            {fw.passing}
          </div>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>Passing</div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{ color: fw.failing > 0 ? C.red : C.muted, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>
            {fw.failing}
          </div>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>Failing</div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{ color: fw.critical_gaps > 0 ? C.red : C.muted, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>
            {fw.critical_gaps}
          </div>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>Crit Gaps</div>
        </div>
      </div>
    </div>
  );
}

function SeverityBadge({ sev }) {
  const colors = { critical: C.red, high: C.orange, medium: C.blue, low: C.muted, info: C.muted };
  const c = colors[sev] || C.muted;
  return (
    <span style={{ background: `${c}18`, color: c, border: `1px solid ${c}30`,
      fontSize: 9, fontFamily: "monospace", fontWeight: 700,
      padding: "2px 6px", borderRadius: 3, textTransform: "uppercase" }}>
      {sev}
    </span>
  );
}

export function ComplianceDashboardPage({ setActiveTab }) {
  const [summary, setSummary]   = useState(null);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);

  useEffect(() => {
    setLoading(true);
    fetch(`${API_BASE}/api/comp/dashboard`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setSummary(d); setLoading(false); })
      .catch(e => { setError(`Failed to load compliance data (${e})`); setLoading(false); });
  }, []);

  if (loading) return (
    <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12, padding: 40 }}>
      Loading compliance dashboard...
    </div>
  );
  if (error) return (
    <div style={{ color: C.red, fontFamily: "monospace", fontSize: 12, padding: 40 }}>{error}</div>
  );

  const scores   = summary?.framework_scores || [];
  const findSumm = summary?.findings_summary || {};
  const alerts   = summary?.active_alerts || 0;
  const overall  = summary?.overall_score || 0;

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px", fontFamily: "monospace",
          textTransform: "uppercase", marginBottom: 6 }}>
          SECURITY COMPLIANCE
        </div>
        <h1 style={{ color: C.text, fontSize: 22, fontWeight: 700, margin: 0 }}>
          GRC Compliance Dashboard
        </h1>
        <div style={{ color: C.muted, fontSize: 12, marginTop: 4, fontFamily: "monospace" }}>
          Overall posture score across all frameworks
        </div>
      </div>

      {/* Overall score hero */}
      <div style={{ ...CARD, display: "flex", alignItems: "center", gap: 32, marginBottom: 28 }}>
        <div>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
            fontFamily: "monospace", textTransform: "uppercase", marginBottom: 8 }}>
            Overall Compliance Posture
          </div>
          <div style={{ display: "flex", alignItems: "flex-end", gap: 6 }}>
            <span style={{ color: scoreColor(overall), fontSize: 64, fontFamily: "monospace",
              fontWeight: 700, lineHeight: 1 }}>
              {Math.round(overall)}
            </span>
            <span style={{ color: scoreColor(overall), fontSize: 28, fontFamily: "monospace",
              marginBottom: 8 }}>%</span>
          </div>
        </div>
        <div style={{ flex: 1, borderLeft: `1px solid ${C.border}`, paddingLeft: 32,
          display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 20 }}>
          <div>
            <div style={{ color: C.red, fontSize: 22, fontFamily: "monospace", fontWeight: 700 }}>
              {findSumm.critical || 0}
            </div>
            <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>Critical findings</div>
          </div>
          <div>
            <div style={{ color: C.orange, fontSize: 22, fontFamily: "monospace", fontWeight: 700 }}>
              {findSumm.high || 0}
            </div>
            <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>High findings</div>
          </div>
          <div>
            <div style={{ color: alerts > 0 ? C.orange : C.muted, fontSize: 22, fontFamily: "monospace", fontWeight: 700 }}>
              {alerts}
            </div>
            <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>Active alerts</div>
          </div>
        </div>
      </div>

      {/* Framework score cards */}
      <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px", fontFamily: "monospace",
        textTransform: "uppercase", marginBottom: 14 }}>
        Framework Scores
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 16, marginBottom: 28 }}>
        {scores.map(fw => <ScoreCard key={fw.framework} fw={fw} />)}
      </div>

      {/* Quick actions */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 12 }}>
        {[
          { label: "View Findings",    tab: "comp-findings",  color: C.red },
          { label: "Risk Register",    tab: "comp-risks",     color: C.orange },
          { label: "Live Alerts",      tab: "comp-alerts",    color: C.blue },
          { label: "Generate Report",  tab: "comp-reports",   color: C.purple },
          { label: "Policy Documents", tab: "comp-policy",    color: C.accent },
        ].map(({ label, tab, color }) => (
          <button key={tab} onClick={() => setActiveTab && setActiveTab(tab)}
            style={{ background: `${color}10`, border: `1px solid ${color}30`,
              color, borderRadius: 6, padding: "12px 18px", fontFamily: "monospace",
              fontSize: 11, fontWeight: 700, cursor: "pointer", textAlign: "left",
              letterSpacing: "0.8px", textTransform: "uppercase" }}>
            {label}
          </button>
        ))}
      </div>
    </div>
  );
}
