/**
 * ComplianceDashboardPage.jsx
 * ============================
 * GRC Compliance posture overview.
 * Data: alerts + incidents tables (compliance_* columns) — no cy_comp_alerts.
 */

import { useState, useEffect } from "react";
import { API_BASE } from "../../core/constants.js";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};

const CARD = {
  background: "rgba(255,255,255,0.02)",
  border: `1px solid ${C.border}`,
  borderRadius: 8,
  padding: "20px 24px",
};

const FW_LABELS = {
  nis2: "NIS2", dora: "DORA", iso27001: "ISO 27001",
  soc2: "SOC 2", nist_csf: "NIST CSF", pci_dss: "PCI DSS", avg: "GDPR/AVG",
};
const FW_COLORS = {
  nis2: "#6378ff", iso27001: "#00e5c0", dora: "#ffd166",
  soc2: "#ff6b6b", avg: "#a78bfa", nist_csf: "#38bdf8", pci_dss: "#f97316",
};

function scoreColor(score) {
  if (score >= 80) return C.accent;
  if (score >= 60) return C.orange;
  return C.red;
}

function ScoreCard({ fw }) {
  const color = scoreColor(fw.score);
  const pct   = Math.round(fw.score);
  const fwColor = FW_COLORS[fw.framework] || C.blue;
  return (
    <div style={{ ...CARD, position: "relative", overflow: "hidden" }}>
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 3,
        background: `linear-gradient(90deg, ${fwColor}80, ${fwColor}10)` }} />
      <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px",
        fontFamily: "monospace", textTransform: "uppercase", marginBottom: 10 }}>
        {FW_LABELS[fw.framework] || fw.framework}
      </div>
      <div style={{ display: "flex", alignItems: "flex-end", gap: 6, marginBottom: 10 }}>
        <div style={{ color, fontSize: 38, fontFamily: "monospace", fontWeight: 700, lineHeight: 1 }}>{pct}</div>
        <div style={{ color, fontSize: 16, fontFamily: "monospace", marginBottom: 3 }}>%</div>
      </div>
      <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2, marginBottom: 12 }}>
        <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: 2, transition: "width 1s ease" }} />
      </div>
      <div style={{ display: "flex", justifyContent: "space-between" }}>
        {[
          { label: "Passing",   val: fw.passing,       color: C.accent },
          { label: "Failing",   val: fw.failing,       color: fw.failing > 0 ? C.red : C.muted },
          { label: "Crit Gaps", val: fw.critical_gaps, color: fw.critical_gaps > 0 ? C.red : C.muted },
        ].map(({ label, val, color: vc }) => (
          <div key={label} style={{ textAlign: "center" }}>
            <div style={{ color: vc, fontSize: 13, fontFamily: "monospace", fontWeight: 700 }}>{val}</div>
            <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>{label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function AlertSeverityBar({ bySeverity }) {
  const total = Object.values(bySeverity).reduce((s, v) => s + v, 0);
  const items = [
    { key: "critical", label: "Critical", color: C.red },
    { key: "high",     label: "High",     color: C.orange },
    { key: "medium",   label: "Medium",   color: C.blue },
    { key: "low",      label: "Low",      color: C.muted },
  ];
  return (
    <div style={CARD}>
      <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px", fontFamily: "monospace", textTransform: "uppercase", marginBottom: 16 }}>
        Alert Severity Distribution (7 days)
      </div>
      <div style={{ display: "flex", gap: 4, height: 8, borderRadius: 4, overflow: "hidden", marginBottom: 16 }}>
        {items.map(({ key, color }) => {
          const cnt = bySeverity[key] || 0;
          const pct = total > 0 ? (cnt / total) * 100 : 0;
          return pct > 0 ? (
            <div key={key} style={{ width: `${pct}%`, background: color, minWidth: 2 }} title={`${key}: ${cnt}`} />
          ) : null;
        })}
        {total === 0 && <div style={{ width: "100%", background: "rgba(255,255,255,0.05)" }} />}
      </div>
      <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
        {items.map(({ key, label, color }) => (
          <div key={key} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: color }} />
            <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>{label}: </span>
            <span style={{ color: color, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>
              {bySeverity[key] || 0}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function FrameworkBreakdown({ breakdown }) {
  const entries = Object.entries(breakdown || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = entries.length > 0 ? entries[0][1] : 1;
  return (
    <div style={CARD}>
      <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px", fontFamily: "monospace", textTransform: "uppercase", marginBottom: 16 }}>
        Alerts by Framework (7 days)
      </div>
      {entries.length === 0 ? (
        <div style={{ color: "rgba(255,255,255,0.15)", fontSize: 11, fontFamily: "monospace" }}>
          No compliance alerts yet. Run enrichment from Live Alerts page.
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {entries.map(([fw, cnt]) => {
            const color = FW_COLORS[fw] || C.blue;
            return (
              <div key={fw}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ color, fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
                    {FW_LABELS[fw] || fw.toUpperCase()}
                  </span>
                  <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>{cnt}</span>
                </div>
                <div style={{ height: 4, background: "rgba(255,255,255,0.05)", borderRadius: 2 }}>
                  <div style={{ height: "100%", width: `${(cnt / max) * 100}%`, background: color, borderRadius: 2 }} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function RecentIncidents({ incidents }) {
  return (
    <div style={CARD}>
      <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px", fontFamily: "monospace", textTransform: "uppercase", marginBottom: 16 }}>
        Compliance-Breaching Incidents
      </div>
      {incidents.length === 0 ? (
        <div style={{ color: "rgba(255,255,255,0.15)", fontSize: 11, fontFamily: "monospace" }}>
          No compliance-tagged incidents found.
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {incidents.slice(0, 8).map(inc => {
            const sevColor = { critical: C.red, high: C.orange, medium: C.blue, low: C.muted }[inc.severity] || C.muted;
            return (
              <div key={inc.id} style={{ display: "flex", alignItems: "center", gap: 10,
                padding: "8px 10px", borderRadius: 4, background: "rgba(255,255,255,0.02)",
                border: `1px solid rgba(255,255,255,0.04)` }}>
                <span style={{ color: sevColor, fontFamily: "monospace", fontSize: 9, fontWeight: 700,
                  background: `${sevColor}15`, padding: "1px 5px", borderRadius: 3, textTransform: "uppercase",
                  whiteSpace: "nowrap" }}>
                  {inc.severity}
                </span>
                <span style={{ color: C.orange, fontFamily: "monospace", fontSize: 10, fontWeight: 700 }}>
                  {inc.id}
                </span>
                <div style={{ display: "flex", gap: 3, flexWrap: "wrap", flex: 1 }}>
                  {(inc.frameworks || []).slice(0, 3).map(fw => (
                    <span key={fw} style={{ fontSize: 8, color: FW_COLORS[fw] || C.blue,
                      background: `${FW_COLORS[fw] || C.blue}15`, border: `1px solid ${FW_COLORS[fw] || C.blue}30`,
                      padding: "1px 4px", borderRadius: 2, fontFamily: "monospace", fontWeight: 700 }}>
                      {fw.toUpperCase()}
                    </span>
                  ))}
                </div>
                <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", whiteSpace: "nowrap" }}>
                  {inc.alert_count} alerts
                </span>
                <span style={{ color: "rgba(255,255,255,0.15)", fontSize: 9, fontFamily: "monospace",
                  whiteSpace: "nowrap" }}>
                  {inc.status}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function ComplianceDashboardPage({ setActiveTab }) {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);

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

  const scores        = summary?.framework_scores    || [];
  const findSumm      = summary?.findings_summary    || {};
  const activeAlerts  = summary?.active_alerts       || 0;
  const breachInc     = summary?.breach_incidents    || 0;
  const overall       = summary?.overall_score       || 0;
  const bySeverity    = summary?.alert_by_severity   || {};
  const fwBreakdown   = summary?.framework_breakdown || {};
  const recentInc     = summary?.recent_incidents    || [];

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px", fontFamily: "monospace", textTransform: "uppercase", marginBottom: 6 }}>
          SECURITY COMPLIANCE
        </div>
        <h1 style={{ color: C.text, fontSize: 22, fontWeight: 700, margin: 0 }}>GRC Compliance Dashboard</h1>
        <div style={{ color: C.muted, fontSize: 12, marginTop: 4, fontFamily: "monospace" }}>
          Live posture derived from correlation engine alerts &amp; incidents
        </div>
      </div>

      {/* Overall score hero */}
      <div style={{ ...CARD, display: "flex", alignItems: "center", gap: 32, marginBottom: 24 }}>
        <div>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px", fontFamily: "monospace", textTransform: "uppercase", marginBottom: 8 }}>
            Overall Compliance Posture
          </div>
          <div style={{ display: "flex", alignItems: "flex-end", gap: 6 }}>
            <span style={{ color: scoreColor(overall), fontSize: 64, fontFamily: "monospace", fontWeight: 700, lineHeight: 1 }}>
              {Math.round(overall)}
            </span>
            <span style={{ color: scoreColor(overall), fontSize: 28, fontFamily: "monospace", marginBottom: 8 }}>%</span>
          </div>
        </div>
        <div style={{ flex: 1, borderLeft: `1px solid ${C.border}`, paddingLeft: 32,
          display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 20 }}>
          {[
            { label: "Active Alerts (7d)",  val: activeAlerts, color: activeAlerts > 50 ? C.red : C.orange },
            { label: "Breach Incidents",    val: breachInc,    color: breachInc > 0 ? C.red : C.muted },
            { label: "Critical Findings",   val: findSumm.critical || 0, color: (findSumm.critical || 0) > 0 ? C.red : C.muted },
            { label: "High Findings",       val: findSumm.high || 0,     color: (findSumm.high || 0) > 0 ? C.orange : C.muted },
          ].map(({ label, val, color }) => (
            <div key={label}>
              <div style={{ color, fontSize: 24, fontFamily: "monospace", fontWeight: 700 }}>{val}</div>
              <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Severity bar + Framework breakdown */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
        <AlertSeverityBar bySeverity={bySeverity} />
        <FrameworkBreakdown breakdown={fwBreakdown} />
      </div>

      {/* Framework score cards */}
      <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px", fontFamily: "monospace", textTransform: "uppercase", marginBottom: 14 }}>
        Framework Posture Scores
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 14, marginBottom: 24 }}>
        {scores.map(fw => <ScoreCard key={fw.framework} fw={fw} />)}
      </div>

      {/* Recent breaching incidents */}
      <div style={{ marginBottom: 24 }}>
        <RecentIncidents incidents={recentInc} />
      </div>

      {/* Quick actions */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 10 }}>
        {[
          { label: "Assessments",      tab: "comp-assessment", color: "#6378ff" },
          { label: "View Findings",    tab: "comp-findings",   color: C.red },
          { label: "Risk Register",    tab: "comp-risks",      color: C.orange },
          { label: "Live Alerts",      tab: "comp-alerts",     color: C.blue },
          { label: "Generate Report",  tab: "comp-reports",    color: C.purple },
          { label: "Policy Documents", tab: "comp-policy",     color: C.accent },
        ].map(({ label, tab, color }) => (
          <button key={tab} onClick={() => setActiveTab && setActiveTab(tab)}
            style={{
              background: `${color}10`, border: `1px solid ${color}30`,
              color, borderRadius: 6, padding: "10px 14px", fontFamily: "monospace",
              fontSize: 11, fontWeight: 700, cursor: "pointer", textAlign: "left",
              letterSpacing: "0.8px", textTransform: "uppercase",
            }}>
            {label}
          </button>
        ))}
      </div>
    </div>
  );
}
