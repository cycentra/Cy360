/**
 * src/pages/siem/SiemFeedPage.jsx
 * =================================
 * CySIEM Integration Feed — forwards Critical/High ASM alerts into SIEM.
 *
 * v2: Adds module tag, CVSS score, risk_score, source, full ISO timestamp,
 *     and per-alert filtering by severity level.
 */

import { useState } from "react";

export function SiemFeedPage({ data, installedModules }) {
  const alerts    = data?.cysiemAlerts || [];
  const [filter, setFilter] = useState("all");

  const filtered = alerts.filter(a =>
    filter === "all" || (filter === "critical" && a.level >= 12) || (filter === "high" && a.level >= 8 && a.level < 12)
  );

  const critCount = alerts.filter(a => a.level >= 12).length;
  const highCount = alerts.filter(a => a.level >= 8 && a.level < 12).length;

  const moduleLabels = {
    vuln_scanner: "Vuln Scanner", nuclei: "Nuclei", passive_osint: "OSINT",
    web_analysis: "Web", dns: "DNS", email_sec: "Email Security",
    cloud: "Cloud", supply_chain: "Supply Chain", dark_web: "Dark Web",
    social_eng: "Social Eng", mobile_api: "Mobile/API",
  };

  function fmtTs(ts) {
    if (!ts) return "—";
    const d = new Date(ts);
    return d.toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  return (
    <div>
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
          <h1 style={{ fontSize: 22, fontWeight: 700 }}>CySIEM Integration Feed</h1>
          <span style={{ background: "rgba(255,59,59,0.12)", color: "#ff3b3b", fontSize: 10, fontFamily: "monospace", padding: "3px 10px", borderRadius: 2, fontWeight: 700, letterSpacing: "1px" }}>LIVE BRIDGE</span>
        </div>
        <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13 }}>
          Critical/High ASM findings forwarded to CySIEM as security events.
        </p>
      </div>

      {/* Summary chips + filter */}
      {alerts.length > 0 && (
        <div style={{ display: "flex", gap: 10, marginBottom: 18, alignItems: "center", flexWrap: "wrap" }}>
          {[
            { id: "all",      label: `All  (${alerts.length})`,  color: "rgba(255,255,255,0.4)" },
            { id: "critical", label: `Critical (${critCount})`,   color: "#ff3b3b" },
            { id: "high",     label: `High (${highCount})`,        color: "#ff8c00" },
          ].map(f => (
            <button key={f.id} onClick={() => setFilter(f.id)}
              style={{ background: filter === f.id ? `${f.color}15` : "transparent",
                border: `1px solid ${filter === f.id ? f.color : "rgba(255,255,255,0.1)"}`,
                color: filter === f.id ? f.color : "rgba(255,255,255,0.4)",
                padding: "5px 12px", borderRadius: 3, fontSize: 11, fontFamily: "monospace", cursor: "pointer", fontWeight: filter === f.id ? 700 : 400 }}>
              {f.label}
            </button>
          ))}
          <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, fontFamily: "monospace", marginLeft: "auto" }}>
            {filtered.length} alert{filtered.length !== 1 ? "s" : ""} shown
          </span>
        </div>
      )}

      {alerts.length === 0 ? (
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "40px 24px", textAlign: "center" }}>
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, fontFamily: "monospace" }}>
            No critical or high findings to forward. Run a scan to populate this feed.
          </div>
        </div>
      ) : filtered.length === 0 ? (
        <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, fontFamily: "monospace", padding: "20px 0" }}>No alerts match the current filter.</div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {filtered.map((a, i) => {
            const lvlColor = a.level >= 12 ? "#ff3b3b" : "#ff8c00";
            const modLabel = moduleLabels[a.module] || a.module || "Unknown";
            return (
              <div key={i} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderLeft: `3px solid ${lvlColor}`, padding: "12px 16px", borderRadius: 2 }}>
                {/* Top row */}
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <span style={{ color: lvlColor, fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
                      LEVEL {a.level}
                    </span>
                    <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>·</span>
                    <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace" }}>{a.rule_id}</span>
                    {a.module && (
                      <span style={{ background: `${lvlColor}12`, color: lvlColor, fontSize: 9, fontFamily: "monospace", fontWeight: 700, padding: "1px 5px", borderRadius: 2 }}>
                        {modLabel}
                      </span>
                    )}
                  </div>
                  <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", flexShrink: 0 }}>
                    {fmtTs(a.ts)}
                  </span>
                </div>

                {/* Finding name */}
                <div style={{ color: "rgba(255,255,255,0.85)", fontSize: 13, fontWeight: 600, marginBottom: 4 }}>{a.description}</div>

                {/* Asset + scores */}
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, fontFamily: "monospace" }}>→ {a.asset}</span>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    {a.cvss != null && (
                      <span style={{ background: "rgba(255,140,0,0.1)", color: "#ff8c00", border: "1px solid rgba(255,140,0,0.25)", fontSize: 10, fontFamily: "monospace", fontWeight: 700, padding: "1px 6px", borderRadius: 2 }}>
                        CVSS {parseFloat(a.cvss).toFixed(1)}
                      </span>
                    )}
                    {a.risk_score != null && (
                      <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace" }}>
                        Risk {a.risk_score}/10
                      </span>
                    )}
                    {a.source && (
                      <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>
                        via {a.source}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
