/**
 * src/siem/SiemFeedPage.jsx
 * ==========================
 * Alert Feed — shows cySiemAlerts generated from Critical/High findings.
 */

import { useState } from "react";

function fmtDate(ts) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString("en-US", {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

const SEV_COLOR  = { Critical: "#ff3b3b", High: "#ff8c00", Medium: "#f5c518", Low: "#00e5a0" };
const SEV_BG     = { Critical: "rgba(255,59,59,0.08)", High: "rgba(255,140,0,0.08)", Medium: "rgba(245,197,24,0.08)", Low: "rgba(0,229,160,0.08)" };

export function SiemFeedPage({ data }) {
  const alerts  = data?.cysiemAlerts || [];
  const [filter, setFilter] = useState("All");
  const [expanded, setExpanded] = useState(null);

  const counts = {
    All:      alerts.length,
    Critical: alerts.filter(a => a.severity === "Critical").length,
    High:     alerts.filter(a => a.severity === "High").length,
  };

  const visible = filter === "All" ? alerts : alerts.filter(a => a.severity === filter);

  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 22 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: "white" }}>Alert Feed</h1>
          <p style={{ color: "rgba(255,255,255,0.62)", fontSize: 13, marginTop: 4 }}>
            {alerts.length} alert{alerts.length !== 1 ? "s" : ""} from latest scan
          </p>
        </div>

        {/* Filter buttons */}
        <div style={{ display: "flex", gap: 6 }}>
          {["All", "Critical", "High"].map(f => (
            <button key={f} onClick={() => setFilter(f)} style={{
              background: filter === f ? (f === "Critical" ? "rgba(255,59,59,0.15)" : f === "High" ? "rgba(255,140,0,0.15)" : "rgba(0,229,160,0.12)") : "rgba(255,255,255,0.03)",
              color:      filter === f ? (f === "Critical" ? "#ff3b3b" : f === "High" ? "#ff8c00" : "#00e5a0") : "rgba(255,255,255,0.4)",
              border:     `1px solid ${filter === f ? (f === "Critical" ? "rgba(255,59,59,0.4)" : f === "High" ? "rgba(255,140,0,0.4)" : "rgba(0,229,160,0.3)") : "rgba(255,255,255,0.08)"}`,
              borderRadius: 4, padding: "5px 12px", fontSize: 11, fontFamily: "monospace", fontWeight: 700, cursor: "pointer",
            }}>
              {f} <span style={{ opacity: 0.6 }}>({counts[f] ?? 0})</span>
            </button>
          ))}
        </div>
      </div>

      {alerts.length === 0 && (
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "48px 24px", textAlign: "center" }}>
          <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 13, fontFamily: "monospace" }}>
            No alerts — run a scan to populate the alert feed.
          </div>
        </div>
      )}

      {/* Alert list */}
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {visible.map((a, i) => {
          const sev    = a.severity || "High";
          const color  = SEV_COLOR[sev]  || "#ff8c00";
          const bg     = SEV_BG[sev]     || "rgba(255,140,0,0.08)";
          const isOpen = expanded === i;

          return (
            <div key={i}
              onClick={() => setExpanded(isOpen ? null : i)}
              style={{
                background: isOpen ? bg : "rgba(255,255,255,0.02)",
                border: `1px solid ${isOpen ? color + "30" : "rgba(255,255,255,0.07)"}`,
                borderLeft: `3px solid ${color}`,
                borderRadius: 5, padding: "12px 16px", cursor: "pointer",
                transition: "all 0.15s",
              }}>

              {/* Row */}
              <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
                {/* Severity badge */}
                <span style={{ background: bg, color, border: `1px solid ${color}30`, fontSize: 9, fontFamily: "monospace", fontWeight: 700, padding: "2px 7px", borderRadius: 2, flexShrink: 0, marginTop: 2 }}>
                  {sev.toUpperCase()}
                </span>

                {/* Main content */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ color: "rgba(255,255,255,0.85)", fontSize: 13, fontWeight: 600, lineHeight: 1.4 }}>
                    {a.title || a.description || "Security Alert"}
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 5 }}>
                    {a.host && (
                      <span style={{ color: "rgba(255,255,255,0.62)", fontSize: 10, fontFamily: "monospace" }}>
                        🖥 {a.host}
                      </span>
                    )}
                    {a.module && (
                      <span style={{ background: "rgba(255,255,255,0.05)", color: "rgba(255,255,255,0.65)", fontSize: 9, fontFamily: "monospace", padding: "1px 6px", borderRadius: 2 }}>
                        {a.module}
                      </span>
                    )}
                    {a.source && (
                      <span style={{ background: "rgba(255,255,255,0.04)", color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace", padding: "1px 6px", borderRadius: 2 }}>
                        {a.source}
                      </span>
                    )}
                    {a.cvss !== undefined && a.cvss !== null && (
                      <span style={{ background: "rgba(255,59,59,0.1)", color: "#ff6b6b", fontSize: 9, fontFamily: "monospace", fontWeight: 700, padding: "1px 6px", borderRadius: 2 }}>
                        CVSS {a.cvss}
                      </span>
                    )}
                    {a.risk_score !== undefined && a.risk_score !== null && (
                      <span style={{ background: "rgba(255,140,0,0.1)", color: "#ff8c00", fontSize: 9, fontFamily: "monospace", padding: "1px 6px", borderRadius: 2 }}>
                        Risk {a.risk_score}
                      </span>
                    )}
                  </div>
                </div>

                {/* Timestamp + chevron */}
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4, flexShrink: 0 }}>
                  <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 9, fontFamily: "monospace" }}>
                    {fmtDate(a.timestamp || a.discovered_at)}
                  </span>
                  <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 9 }}>{isOpen ? "▲" : "▼"}</span>
                </div>
              </div>

              {/* Expanded detail */}
              {isOpen && (
                <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid rgba(255,255,255,0.06)" }}>
                  {a.description && a.description !== a.title && (
                    <p style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, lineHeight: 1.6, marginBottom: 10 }}>{a.description}</p>
                  )}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: "6px 16px" }}>
                    {[
                      ["Port",         a.port],
                      ["CVE",          Array.isArray(a.cve_refs) ? a.cve_refs.join(", ") : a.cve_refs],
                      ["Template ID",  a.template_id],
                      ["Matched At",   a.matched_at],
                      ["Discovered",   fmtDate(a.discovered_at)],
                      ["EPSS",         a.epss !== undefined ? `${(a.epss * 100).toFixed(1)}%` : null],
                    ].filter(([,v]) => v).map(([label, value]) => (
                      <div key={label}>
                        <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace" }}>{label}: </span>
                        <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 10, fontFamily: "monospace" }}>{value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
