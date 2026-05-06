/**
 * SiemRiskScoresPage.jsx
 * Entity risk leaderboard — composite 0–100 scores for hosts and users.
 */

import { useState, useEffect } from "react";
import { siemApi, siemFetch } from "./siemApi";
import { SiemEngineStatus } from "./SiemEngineStatus";
import { RISK_CONFIG } from "../core/constants";

const LEVEL_THRESHOLDS = [
  { min: 75, label: "CRITICAL", color: "#ff3b3b", bg: "rgba(255,59,59,0.12)"  },
  { min: 50, label: "HIGH",     color: "#ff8c00", bg: "rgba(255,140,0,0.12)"  },
  { min: 25, label: "MEDIUM",   color: "#f5c518", bg: "rgba(245,197,24,0.12)" },
  { min: 0,  label: "LOW",      color: "#00e5a0", bg: "rgba(0,229,160,0.12)"  },
];

function levelFor(score) {
  return LEVEL_THRESHOLDS.find(t => score >= t.min) || LEVEL_THRESHOLDS[3];
}

function ScoreBar({ score }) {
  const lvl = levelFor(score);
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      <div style={{ flex: 1, height: 6, background: "rgba(255,255,255,0.08)", borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: `${score}%`, height: "100%", background: lvl.color,
          borderRadius: 3, transition: "width 0.5s ease" }} />
      </div>
      <span style={{ color: lvl.color, fontSize: 13, fontFamily: "monospace",
        fontWeight: 700, minWidth: 28, textAlign: "right" }}>{Math.round(score)}</span>
    </div>
  );
}

function TrendArrow({ trend }) {
  const cfg = {
    rising:   { sym: "↑", color: "#ff3b3b" },
    stable:   { sym: "→", color: "rgba(255,255,255,0.3)" },
    falling:  { sym: "↓", color: "#00e5a0" },
  }[trend] || { sym: "—", color: "rgba(255,255,255,0.2)" };
  return <span style={{ color: cfg.color, fontSize: 14 }}>{cfg.sym}</span>;
}

function BreakdownRow({ label, value, max, color }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
      <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 10, fontFamily: "monospace",
        width: 130, flexShrink: 0 }}>{label}</div>
      <div style={{ flex: 1, height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2, overflow: "hidden" }}>
        <div style={{ width: `${Math.min(100, (value / max) * 100)}%`, height: "100%",
          background: color, borderRadius: 2 }} />
      </div>
      <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, fontFamily: "monospace",
        minWidth: 24, textAlign: "right" }}>{Math.round(value)}</span>
    </div>
  );
}

const ENTITY_FILTERS = [
  { id: "all",      label: "All",      entityType: undefined, minScore: 0  },
  { id: "critical", label: "Critical", entityType: undefined, minScore: 75 },
  { id: "high",     label: "High",     entityType: undefined, minScore: 50 },
  { id: "hosts",    label: "Hosts",    entityType: "host",    minScore: 0  },
  { id: "users",    label: "Users",    entityType: "user",    minScore: 0  },
];

// ── Entity Risk Summary Charts ─────────────────────────────────────────────────

function RiskDistHistogram({ scores }) {
  const [hovered, setHovered] = useState(null);
  const buckets = Array.from({ length: 10 }, (_, i) => ({
    label: `${i * 10}–${i * 10 + 9}`,
    min: i * 10,
    count: 0,
    color: i >= 7 ? "#ff3b3b" : i >= 5 ? "#ff8c00" : i >= 2 ? "#f5c518" : "#00e5a0",
  }));
  scores.forEach(e => {
    const idx = Math.min(9, Math.floor(e.score / 10));
    buckets[idx].count++;
  });
  const maxCount = Math.max(...buckets.map(b => b.count), 1);

  return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
      borderRadius: 6, padding: "14px 16px" }}>
      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace",
        letterSpacing: "1.5px", marginBottom: 14 }}>SCORE DISTRIBUTION (0–100)</div>
      <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 72 }}>
        {buckets.map((b, i) => (
          <div key={b.label}
            onMouseEnter={() => setHovered(i)}
            onMouseLeave={() => setHovered(null)}
            title={`Score ${b.label}: ${b.count} entit${b.count !== 1 ? "ies" : "y"}`}
            style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center",
              gap: 2, cursor: b.count > 0 ? "default" : "default" }}>
            <div style={{ color: b.count > 0 ? b.color : "transparent", fontSize: 8,
              fontFamily: "monospace", fontWeight: 700 }}>
              {hovered === i && b.count > 0 ? b.count : ""}
            </div>
            <div style={{
              width: "100%",
              height: `${Math.max(3, (b.count / maxCount) * 56)}px`,
              background: b.count > 0 ? b.color : "rgba(255,255,255,0.06)",
              borderRadius: "2px 2px 0 0",
              opacity: b.count > 0 ? (hovered === null ? 0.8 : hovered === i ? 1 : 0.35) : 0.4,
              transition: "opacity 0.15s, height 0.4s ease",
            }} />
          </div>
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4 }}>
        {[0, 25, 50, 75, 100].map(v => (
          <span key={v} style={{ color: "rgba(255,255,255,0.2)", fontSize: 8, fontFamily: "monospace" }}>{v}</span>
        ))}
      </div>
    </div>
  );
}

function EntityTypeSplit({ scores }) {
  const hosts = scores.filter(e => e.entity_type === "host").length;
  const users = scores.filter(e => e.entity_type === "user").length;
  const total = scores.length;
  if (total === 0) return null;
  const hostPct = Math.round((hosts / total) * 100);
  const userPct = 100 - hostPct;

  return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
      borderRadius: 6, padding: "14px 16px" }}>
      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, fontFamily: "monospace",
        letterSpacing: "1.5px", marginBottom: 14 }}>ENTITY TYPE SPLIT</div>
      <div style={{ display: "flex", borderRadius: 3, overflow: "hidden", height: 14, marginBottom: 14 }}>
        {hosts > 0 && <div style={{ width: `${hostPct}%`, background: "#4d9eff",
          transition: "width 0.4s ease" }} title={`Hosts: ${hosts}`}/>}
        {users > 0 && <div style={{ width: `${userPct}%`, background: "#b36bff",
          transition: "width 0.4s ease" }} title={`Users: ${users}`}/>}
      </div>
      <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
        {[
          { label: "Hosts", count: hosts, pct: hostPct, color: "#4d9eff", icon: "🖥️" },
          { label: "Users", count: users, pct: userPct, color: "#b36bff", icon: "👤" },
        ].map(r => (
          <div key={r.label} style={{ display: "flex", alignItems: "center", gap: 7 }}>
            <span style={{ fontSize: 14 }}>{r.icon}</span>
            <div>
              <span style={{ color: r.color, fontSize: 18, fontFamily: "monospace",
                fontWeight: 700 }}>{r.count}</span>
              <span style={{ color: "rgba(255,255,255,0.65)", fontSize: 11,
                fontFamily: "monospace", marginLeft: 6 }}>{r.label}</span>
              <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 9,
                fontFamily: "monospace", marginLeft: 4 }}>{r.pct}%</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function SiemRiskScoresPage() {
  const [scores, setScores]           = useState([]);
  const [loading, setLoading]         = useState(true);
  const [activeFilter, setFilter]     = useState("all");
  const [expanded, setExpanded]       = useState(null);
  const [summaryScores, setSummaryScores] = useState([]); // unfiltered — drives charts

  const filter = ENTITY_FILTERS.find(f => f.id === activeFilter) || ENTITY_FILTERS[0];

  // Fetch all entities once for the summary charts (no filter, high limit)
  useEffect(() => {
    (async () => {
      const data = await siemFetch(siemApi.getRiskScores({ limit: 200 }));
      if (!data._offline && !data._error) setSummaryScores(Array.isArray(data) ? data : []);
    })();
  }, []);

  const fetchScores = async () => {
    const data = await siemFetch(
      siemApi.getRiskScores({ entity_type: filter.entityType, min_score: filter.minScore, limit: 100 })
    );
    if (!data._offline && !data._error) {
      setScores(Array.isArray(data) ? data : []);
    }
    setLoading(false);
  };

  useEffect(() => {
    setLoading(true);
    fetchScores();
    const t = setInterval(fetchScores, 60_000);
    return () => clearInterval(t);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeFilter]);

  return (
    <SiemEngineStatus>
      <div>
        <div style={{ marginBottom: 22 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: "white" }}>Risk Scores</h1>
            <span style={{ background: "rgba(255,140,0,0.12)", color: "#ff8c00", fontSize: 10,
              fontFamily: "monospace", padding: "3px 10px", borderRadius: 2, fontWeight: 700,
              letterSpacing: "1px" }}>ENTITY INTELLIGENCE</span>
          </div>
          <p style={{ color: "rgba(255,255,255,0.62)", fontSize: 13 }}>
            Composite 0–100 risk scores per host and user. Updated every 5 minutes by the correlation engine.
          </p>
        </div>

        {/* ── Entity Risk Summary ─────────────────────────────────────────── */}
        {summaryScores.length > 0 && (
          <div style={{ marginBottom: 24 }}>
            {/* Stat tiles */}
            <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
              {[
                { label: "Total Entities", value: summaryScores.length,                                           color: "rgba(255,255,255,0.85)" },
                { label: "Critical (≥75)", value: summaryScores.filter(e => e.score >= 75).length,                color: "#ff3b3b"                },
                { label: "High (50–74)",   value: summaryScores.filter(e => e.score >= 50 && e.score < 75).length,color: "#ff8c00"                },
                { label: "Medium (25–49)", value: summaryScores.filter(e => e.score >= 25 && e.score < 50).length,color: "#f5c518"                },
                { label: "Low (0–24)",     value: summaryScores.filter(e => e.score < 25).length,                 color: "#00e5a0"                },
              ].map(t => (
                <div key={t.label} style={{ background: "rgba(255,255,255,0.03)",
                  border: "1px solid rgba(255,255,255,0.07)", borderRadius: 5,
                  padding: "10px 16px", minWidth: 80 }}>
                  <div style={{ color: t.color, fontSize: 22, fontWeight: 700,
                    fontFamily: "monospace" }}>{t.value}</div>
                  <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10,
                    fontFamily: "monospace", marginTop: 2 }}>{t.label}</div>
                </div>
              ))}
            </div>

            {/* Charts row — 2 equal columns */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <RiskDistHistogram scores={summaryScores}/>
              <EntityTypeSplit scores={summaryScores}/>
            </div>
          </div>
        )}

        {/* Filter tabs */}
        <div style={{ display: "flex", gap: 6, marginBottom: 20, flexWrap: "wrap" }}>
          {ENTITY_FILTERS.map(f => (
            <button key={f.id} onClick={() => setFilter(f.id)}
              style={{ background: activeFilter === f.id ? "rgba(255,255,255,0.08)" : "rgba(255,255,255,0.03)",
                border: `1px solid ${activeFilter === f.id ? "rgba(255,255,255,0.2)" : "rgba(255,255,255,0.07)"}`,
                color: activeFilter === f.id ? "white" : "rgba(255,255,255,0.4)",
                padding: "7px 14px", borderRadius: 4, cursor: "pointer",
                fontSize: 12, fontFamily: "monospace", fontWeight: activeFilter === f.id ? 700 : 400 }}>
              {f.label}
            </button>
          ))}
        </div>

        {loading ? (
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 13, padding: "40px 0" }}>Loading risk scores…</div>
        ) : scores.length === 0 ? (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, padding: "40px 0", textAlign: "center" }}>
            No entities match this filter. Risk scores populate as alerts are processed.
          </div>
        ) : (
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 4, overflow: "hidden" }}>
            {scores.map((entity, idx) => {
              const lvl = levelFor(entity.score);
              const isExpanded = expanded === entity.entity_id;
              const bk = entity.breakdown || {};
              return (
                <div key={entity.entity_id}>
                  <div
                    onClick={() => setExpanded(isExpanded ? null : entity.entity_id)}
                    style={{ display: "grid", gridTemplateColumns: "28px 30px 200px 1fr 80px 60px",
                      gap: 12, padding: "13px 16px", cursor: "pointer",
                      borderBottom: `1px solid rgba(255,255,255,${isExpanded ? 0.1 : 0.04})`,
                      background: isExpanded ? "rgba(255,255,255,0.03)" : "transparent" }}>
                    <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 10,
                      fontFamily: "monospace", alignSelf: "center" }}>
                      {String(idx + 1).padStart(2, "0")}
                    </div>
                    <div style={{ alignSelf: "center", fontSize: 16 }}>
                      {entity.entity_type === "user" ? "👤" : "🖥️"}
                    </div>
                    <div style={{ alignSelf: "center" }}>
                      <div style={{ color: "white", fontSize: 13, fontWeight: 600,
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {entity.entity_name || entity.entity_id}
                      </div>
                      <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10,
                        fontFamily: "monospace", textTransform: "uppercase" }}>
                        {entity.entity_type}
                      </div>
                    </div>
                    <div style={{ alignSelf: "center" }}>
                      <ScoreBar score={entity.score} />
                    </div>
                    <div style={{ alignSelf: "center" }}>
                      <span style={{ background: lvl.bg, color: lvl.color,
                        border: `1px solid ${lvl.color}40`, fontSize: 10, fontWeight: 700,
                        fontFamily: "monospace", padding: "2px 8px", borderRadius: 2 }}>
                        {lvl.label}
                      </span>
                    </div>
                    <div style={{ alignSelf: "center", display: "flex", alignItems: "center",
                      gap: 6, justifyContent: "flex-end" }}>
                      <TrendArrow trend={entity.trend} />
                      <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 12 }}>
                        {isExpanded ? "▲" : "▼"}
                      </span>
                    </div>
                  </div>

                  {/* Breakdown row */}
                  {isExpanded && (
                    <div style={{ padding: "14px 16px 16px 76px",
                      background: "rgba(255,255,255,0.015)",
                      borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
                      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 10,
                        fontFamily: "monospace", letterSpacing: "1px", marginBottom: 10 }}>
                        SCORE BREAKDOWN
                      </div>
                      <BreakdownRow label="Alert Severity"    value={bk.alert_severity ?? 0}    max={35} color="#ff3b3b" />
                      <BreakdownRow label="Incident Severity" value={bk.incident_severity ?? 0} max={30} color="#ff8c00" />
                      <BreakdownRow label="UEBA Anomalies"    value={bk.ueba_anomalies ?? 0}    max={25} color="#f5c518" />
                      <BreakdownRow label="MISP IOC Hits"     value={bk.misp_ioc_hits ?? 0}     max={10} color="#b06eff" />
                      {entity.last_calculated && (
                        <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10,
                          fontFamily: "monospace", marginTop: 8 }}>
                          Last calculated: {new Date(entity.last_calculated).toLocaleString()}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </SiemEngineStatus>
  );
}
