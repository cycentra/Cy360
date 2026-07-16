import { useState, useEffect, useCallback } from "react";
import { siemApi, siemFetch } from "./siemApi";

// ─────────────────────────────────────────────────────────────────────────────
// Shared primitives (mirror InternalExposureDashboard style tokens)
// ─────────────────────────────────────────────────────────────────────────────

function Panel({ title, accent = "#00e5a0", badge, onViewAll, children, style = {} }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.025)",
      border: "1px solid rgba(255,255,255,0.07)",
      borderTop: `2px solid ${accent}`,
      borderRadius: 5, padding: "18px 22px",
      ...style,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, letterSpacing: "1.5px", textTransform: "uppercase", fontFamily: "monospace" }}>
          {title}
        </span>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {badge != null && (
            <span style={{ background: `${accent}18`, color: accent, fontSize: 10, fontFamily: "monospace", padding: "2px 8px", borderRadius: 2, fontWeight: 700 }}>
              {badge}
            </span>
          )}
          {onViewAll && (
            <button onClick={onViewAll}
              style={{ background: "none", border: "none", color: accent, fontSize: 10, fontFamily: "monospace", cursor: "pointer", opacity: 0.7 }}>
              View All ↗
            </button>
          )}
        </div>
      </div>
      {children}
    </div>
  );
}

function AnimCounter({ value = 0, duration = 900 }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let cur = 0;
    const step  = Math.max(1, Math.ceil(value / (duration / 16)));
    const timer = setInterval(() => {
      cur += step;
      if (cur >= value) { setDisplay(value); clearInterval(timer); }
      else setDisplay(cur);
    }, 16);
    return () => clearInterval(timer);
  }, [value]);
  return <>{display}</>;
}

function KpiCard({ label, value, accent = "#00e5a0", sub, icon }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.03)",
      border: "1px solid rgba(255,255,255,0.07)",
      borderTop: `2px solid ${accent}`,
      padding: "16px 20px",
      borderRadius: 4, flex: "1 1 130px", minWidth: 120,
    }}>
      {icon && <div style={{ fontSize: 18, marginBottom: 6 }}>{icon}</div>}
      <div style={{ color: accent, fontSize: 28, fontWeight: 800, fontFamily: "'Space Mono',monospace", lineHeight: 1 }}>
        <AnimCounter value={value} />
      </div>
      <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 10, letterSpacing: "1.5px", marginTop: 5, textTransform: "uppercase" }}>
        {label}
      </div>
      {sub && <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Severity + status helpers
// ─────────────────────────────────────────────────────────────────────────────

const SEV_COLOR = {
  critical: "#ff3b3b",
  high:     "#ff8c00",
  medium:   "#f5c518",
  low:      "rgba(255,255,255,0.35)",
};

const STATUS_COLOR = {
  open:          "#ff3b3b",
  in_review:     "#ff8c00",
  held:          "rgba(255,255,255,0.35)",
  closed:        "#00e5a0",
  false_positive:"rgba(255,255,255,0.25)",
  investigating: "#f5c518",
};

function SevBadge({ sev }) {
  const color = SEV_COLOR[sev] || "rgba(255,255,255,0.3)";
  return (
    <span style={{
      background: `${color}18`, color, border: `1px solid ${color}40`,
      borderRadius: 3, padding: "1px 7px", fontSize: 9,
      fontFamily: "monospace", fontWeight: 700, textTransform: "uppercase",
    }}>
      {sev || "—"}
    </span>
  );
}

function StatusBadge({ status }) {
  const color = STATUS_COLOR[status] || "rgba(255,255,255,0.3)";
  return (
    <span style={{
      background: `${color}18`, color, border: `1px solid ${color}40`,
      borderRadius: 3, padding: "1px 7px", fontSize: 9,
      fontFamily: "monospace", fontWeight: 700,
    }}>
      {(status || "—").replace(/_/g, " ").toUpperCase()}
    </span>
  );
}

function MitreTags({ tags = [] }) {
  if (!tags || tags.length === 0) return <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace" }}>—</span>;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
      {tags.slice(0, 4).map(t => (
        <span key={t} style={{
          background: "rgba(77,158,255,0.12)", color: "#4d9eff",
          border: "1px solid rgba(77,158,255,0.3)",
          borderRadius: 2, padding: "0 5px", fontSize: 9, fontFamily: "monospace",
        }}>{t}</span>
      ))}
      {tags.length > 4 && (
        <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 9, fontFamily: "monospace" }}>+{tags.length - 4}</span>
      )}
    </div>
  );
}

function FindingCountBadge({ count }) {
  const color = count > 0 ? "#ff3b3b" : "#00e5a0";
  return (
    <span style={{
      background: `${color}18`, color, border: `1px solid ${color}40`,
      borderRadius: 10, padding: "1px 9px", fontSize: 11,
      fontFamily: "'Space Mono',monospace", fontWeight: 800,
      minWidth: 26, textAlign: "center", display: "inline-block",
    }}>
      {count}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Hunt Rules table
// ─────────────────────────────────────────────────────────────────────────────

function HuntRulesTable({ rules, loading }) {
  if (loading) return <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>;
  if (!rules || rules.length === 0) {
    return <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, fontFamily: "monospace", padding: "10px 0" }}>No hunt rules loaded</div>;
  }

  const COL_WIDTHS = "50px 1fr 90px 1fr 70px 90px";

  return (
    <div>
      <div style={{
        display: "grid", gridTemplateColumns: COL_WIDTHS,
        gap: 10, padding: "4px 6px 8px",
        borderBottom: "1px solid rgba(255,255,255,0.06)",
      }}>
        {["Rule ID", "Name", "Severity", "MITRE", "Window", "Open"].map(h => (
          <span key={h} style={{ color: "rgba(255,255,255,0.45)", fontSize: 9, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "1px" }}>{h}</span>
        ))}
      </div>
      <div style={{ maxHeight: 320, overflowY: "auto" }}>
        {rules.map((rule, i) => (
          <div key={rule.id || i} style={{
            display: "grid", gridTemplateColumns: COL_WIDTHS,
            gap: 10, padding: "9px 6px", alignItems: "center",
            borderBottom: "1px solid rgba(255,255,255,0.03)",
            background: i % 2 !== 0 ? "rgba(255,255,255,0.01)" : "transparent",
          }}>
            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace" }}>
              {rule.id || "—"}
            </span>
            <div>
              <div style={{ color: "rgba(255,255,255,0.85)", fontSize: 11, fontFamily: "monospace", fontWeight: 600 }}>
                {rule.name || "Unnamed Rule"}
              </div>
              {rule.description && (
                <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 9, fontFamily: "monospace", marginTop: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                  {rule.description}
                </div>
              )}
            </div>
            <SevBadge sev={rule.severity} />
            <MitreTags tags={rule.mitre || []} />
            <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace" }}>
              {rule.window_hours != null ? `${rule.window_hours}h` : "—"}
            </span>
            <FindingCountBadge count={rule.open_findings || 0} />
          </div>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// AI Analysis panel
// ─────────────────────────────────────────────────────────────────────────────

function AiAnalysisPanel({ analysis, analyzing, onAnalyze }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 200 }}>
      <div style={{ marginBottom: 12 }}>
        <button
          onClick={onAnalyze}
          disabled={analyzing}
          style={{
            background: analyzing ? "rgba(176,110,255,0.05)" : "rgba(176,110,255,0.12)",
            border: "1px solid rgba(176,110,255,0.35)",
            color: analyzing ? "rgba(176,110,255,0.4)" : "#b06eff",
            borderRadius: 4, padding: "7px 16px", fontSize: 10,
            fontFamily: "monospace", fontWeight: 700, cursor: analyzing ? "not-allowed" : "pointer",
            letterSpacing: "0.5px", display: "flex", alignItems: "center", gap: 8,
          }}
        >
          {analyzing ? (
            <>
              <span style={{
                width: 10, height: 10, borderRadius: "50%",
                border: "2px solid rgba(176,110,255,0.3)",
                borderTopColor: "#b06eff",
                display: "inline-block",
                animation: "spin 0.7s linear infinite",
              }} />
              Analyzing…
            </>
          ) : "🧠 Analyze Findings"}
        </button>
      </div>

      {!analysis && !analyzing && (
        <div style={{
          flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
          color: "rgba(255,255,255,0.45)", fontSize: 11, fontFamily: "monospace",
          textAlign: "center", padding: "20px 0",
        }}>
          Run analysis to get CyMind AI insights<br />on current threat hunt findings
        </div>
      )}

      {analysis?._error && (
        <div style={{
          background: "rgba(255,59,59,0.06)", border: "1px solid rgba(255,59,59,0.2)",
          borderRadius: 4, padding: "10px 14px",
          color: "#ff3b3b", fontSize: 11, fontFamily: "monospace",
        }}>
          {analysis._error === "cymind_not_configured"
            ? "CyMind AI is not configured — set it up in Settings → AI Integrations."
            : `Analysis failed: ${analysis._error}`}
        </div>
      )}

      {analysis?.analysis && (
        <div style={{ flex: 1 }}>
          <pre style={{
            background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: 4, padding: "12px 14px", margin: 0,
            color: "rgba(255,255,255,0.75)", fontSize: 11, fontFamily: "monospace",
            whiteSpace: "pre-wrap", wordBreak: "break-word",
            maxHeight: 280, overflowY: "auto",
            lineHeight: 1.6,
          }}>
            {analysis.analysis}
          </pre>
          <div style={{ marginTop: 8, color: "rgba(255,255,255,0.45)", fontSize: 9, fontFamily: "monospace" }}>
            Model: {analysis.model || "—"} · Rules analyzed: {analysis.rules_analyzed ?? "—"} · Findings: {analysis.findings_analyzed ?? "—"}
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Active Hunt Findings table
// ─────────────────────────────────────────────────────────────────────────────

function HuntFindingsTable({ findings, loading, onViewIncidents }) {
  const [expandedId, setExpandedId] = useState(null);

  if (loading) return <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, fontFamily: "monospace" }}>Loading…</div>;
  if (!findings || findings.length === 0) {
    return (
      <div style={{ textAlign: "center", padding: "20px 0" }}>
        <div style={{ color: "#00e5a0", fontSize: 24, marginBottom: 8 }}>✓</div>
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, fontFamily: "monospace" }}>
          No active hunt findings — all clear
        </div>
      </div>
    );
  }

  const COL_WIDTHS = "120px 1fr 1fr 90px 1fr 120px 90px";

  return (
    <div>
      <div style={{
        display: "grid", gridTemplateColumns: COL_WIDTHS,
        gap: 10, padding: "4px 6px 8px",
        borderBottom: "1px solid rgba(255,255,255,0.06)",
      }}>
        {["Incident ID", "Rule", "Entity", "Severity", "MITRE", "First Seen", "Status"].map(h => (
          <span key={h} style={{ color: "rgba(255,255,255,0.45)", fontSize: 9, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "1px" }}>{h}</span>
        ))}
      </div>
      <div style={{ maxHeight: 380, overflowY: "auto" }}>
        {findings.map((f, i) => {
          const isExpanded = expandedId === (f.id || i);
          const ruleName = f.correlated_rules?.[0]?.rule_name || f.rule_name || "—";
          const entity   = f.entity || f.source_host || f.source_user || "—";
          const mitre    = f.mitre_ids || f.mitre_techniques || f.correlated_rules?.[0]?.mitre_ids || [];

          return (
            <div key={f.id || i}>
              <div
                onClick={() => setExpandedId(isExpanded ? null : (f.id || i))}
                style={{
                  display: "grid", gridTemplateColumns: COL_WIDTHS,
                  gap: 10, padding: "9px 6px", alignItems: "center",
                  borderBottom: "1px solid rgba(255,255,255,0.03)",
                  background: isExpanded ? "rgba(255,140,0,0.04)" : (i % 2 !== 0 ? "rgba(255,255,255,0.01)" : "transparent"),
                  cursor: "pointer",
                  transition: "background 0.15s",
                }}
                onMouseEnter={e => !isExpanded && (e.currentTarget.style.background = "rgba(255,255,255,0.03)")}
                onMouseLeave={e => !isExpanded && (e.currentTarget.style.background = i % 2 !== 0 ? "rgba(255,255,255,0.01)" : "transparent")}
              >
                <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, fontFamily: "monospace" }}>
                  {String(f.id || "—").slice(0, 12)}
                </span>
                <span style={{ color: "rgba(255,255,255,0.8)", fontSize: 11, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {ruleName}
                </span>
                <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 11, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {entity}
                </span>
                <SevBadge sev={f.severity} />
                <MitreTags tags={mitre} />
                <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace" }}>
                  {f.first_seen ? new Date(f.first_seen).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—"}
                </span>
                <StatusBadge status={f.status} />
              </div>
              {isExpanded && f.llm_summary && (
                <div style={{
                  background: "rgba(0,0,0,0.25)", borderBottom: "1px solid rgba(255,255,255,0.04)",
                  padding: "10px 16px",
                }}>
                  <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 9, fontFamily: "monospace", letterSpacing: "1px", marginBottom: 6 }}>AI SUMMARY</div>
                  <div style={{ color: "rgba(255,255,255,0.6)", fontSize: 11, fontFamily: "monospace", lineHeight: 1.6 }}>
                    {f.llm_summary}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
      <div style={{ marginTop: 12, display: "flex", justifyContent: "flex-end" }}>
        <button
          onClick={onViewIncidents}
          style={{
            background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.25)",
            color: "#ff3b3b", borderRadius: 3, padding: "5px 14px",
            fontSize: 10, fontFamily: "monospace", fontWeight: 700, cursor: "pointer",
          }}
        >
          View in Incidents ↗
        </button>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────

export function ThreatHuntingPage({ setActiveTab }) {
  const [rules,       setRules]       = useState([]);
  const [findings,    setFindings]    = useState([]);
  const [summary,     setSummary]     = useState(null);
  const [aiAnalysis,  setAiAnalysis]  = useState(null);
  const [loading,     setLoading]     = useState(true);
  const [analyzing,   setAnalyzing]   = useState(false);
  const [running,     setRunning]     = useState(false);
  const [runMsg,      setRunMsg]      = useState(null);
  const [offline,     setOffline]     = useState(false);
  const [lastRefresh, setLastRefresh] = useState(null);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    const [sumData, rulesData, findingsData] = await Promise.all([
      siemFetch(siemApi.getThreatHuntSummary()),
      siemFetch(siemApi.getThreatHuntRules()),
      siemFetch(siemApi.getThreatHuntFindings({ limit: 100 })),
    ]);

    if (sumData._offline || rulesData._offline) {
      setOffline(true);
      setLoading(false);
      return;
    }
    setOffline(false);
    if (!sumData._error)     setSummary(sumData);
    if (!rulesData._error)   setRules(Array.isArray(rulesData) ? rulesData : (rulesData.rules || []));
    if (!findingsData._error) setFindings(Array.isArray(findingsData) ? findingsData : (findingsData.incidents || findingsData.findings || []));
    setLoading(false);
    setLastRefresh(new Date());
  }, []);

  useEffect(() => {
    fetchAll();
    const t = setInterval(fetchAll, 60_000);
    return () => clearInterval(t);
  }, [fetchAll]);

  const handleRunHunt = async () => {
    setRunning(true);
    setRunMsg(null);
    const res = await siemFetch(siemApi.runThreatHunt());
    setRunning(false);
    if (res._error) {
      setRunMsg({ ok: false, text: res._error });
    } else {
      setRunMsg({ ok: true, text: res.message || "Hunt triggered successfully" });
      setTimeout(() => fetchAll(), 3000);
    }
    setTimeout(() => setRunMsg(null), 6000);
  };

  const handleAnalyze = async () => {
    setAnalyzing(true);
    const res = await siemFetch(siemApi.analyzeThreatHunt());
    setAnalyzing(false);
    setAiAnalysis(res);
  };

  return (
    <div>
      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes spin  { to{transform:rotate(360deg)} }
      `}</style>

      {/* ── Header ── */}
      <div style={{ marginBottom: 22 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: "white", margin: 0 }}>
            🎯 Threat Hunting
          </h1>
          <span style={{ background: "rgba(255,140,0,0.12)", color: "#ff8c00", border: "1px solid rgba(255,140,0,0.3)", fontSize: 10, fontFamily: "monospace", fontWeight: 700, padding: "2px 8px", borderRadius: 2, letterSpacing: "1px" }}>
            HUNT ENGINE
          </span>
          {!loading && !offline && (
            <span style={{ display: "flex", alignItems: "center", gap: 5, color: "#00e5a0", fontSize: 10, fontFamily: "monospace" }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#00e5a0", display: "inline-block", animation: "pulse 2s infinite" }} />
              LIVE
            </span>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 14, marginTop: 6, flexWrap: "wrap" }}>
          <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13, margin: 0 }}>
            Proactive hunt engine · 14 correlation rules · runs every 6 hours · on-demand via CyMind AI
          </p>
          <div style={{
            marginTop: 10, padding: "8px 14px",
            background: "rgba(255,140,0,0.05)", border: "1px solid rgba(255,140,0,0.15)",
            borderRadius: 4, fontSize: 11, color: "rgba(255,255,255,0.5)", lineHeight: 1.6,
          }}>
            <strong style={{ color: "#ff8c00" }}>This is the findings dashboard.</strong>{" "}
            It shows incidents raised by the hunt engine against SIEM data — you cannot author rules here.
            To create custom endpoint detection rules for a specific zero-day, go to{" "}
            <strong style={{ color: "rgba(255,255,255,0.75)" }}>Endpoint Defence → CyScan Rules</strong>.
          </div>
          {lastRefresh && (
            <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace" }}>
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button onClick={fetchAll}
            style={{ background: "rgba(0,229,160,0.08)", border: "1px solid rgba(0,229,160,0.2)", color: "#00e5a0", fontSize: 10, fontFamily: "monospace", padding: "3px 10px", borderRadius: 3, cursor: "pointer" }}>
            ↻ Refresh
          </button>
          <button
            onClick={handleRunHunt}
            disabled={running}
            style={{
              background: running ? "rgba(255,140,0,0.05)" : "rgba(255,140,0,0.12)",
              border: "1px solid rgba(255,140,0,0.35)",
              color: running ? "rgba(255,140,0,0.4)" : "#ff8c00",
              fontSize: 10, fontFamily: "monospace", fontWeight: 700,
              padding: "3px 12px", borderRadius: 3,
              cursor: running ? "not-allowed" : "pointer",
              display: "flex", alignItems: "center", gap: 6,
            }}
          >
            {running ? (
              <>
                <span style={{ width: 8, height: 8, borderRadius: "50%", border: "1.5px solid rgba(255,140,0,0.3)", borderTopColor: "#ff8c00", display: "inline-block", animation: "spin 0.7s linear infinite" }} />
                Running…
              </>
            ) : "▶ Run Hunt Now"}
          </button>
        </div>
        {runMsg && (
          <div style={{
            marginTop: 10, padding: "7px 14px", borderRadius: 3, fontSize: 11, fontFamily: "monospace",
            background: runMsg.ok ? "rgba(0,229,160,0.08)" : "rgba(255,59,59,0.08)",
            border: `1px solid ${runMsg.ok ? "rgba(0,229,160,0.25)" : "rgba(255,59,59,0.25)"}`,
            color: runMsg.ok ? "#00e5a0" : "#ff3b3b",
          }}>
            {runMsg.text}
          </div>
        )}
      </div>

      {offline && !loading && (
        <div style={{ background: "rgba(255,59,59,0.06)", border: "1px solid rgba(255,59,59,0.2)", borderRadius: 4, padding: "12px 18px", marginBottom: 18 }}>
          <span style={{ color: "#ff3b3b", fontSize: 11, fontFamily: "monospace" }}>
            ⚠ Threat hunt engine is offline — data unavailable
          </span>
        </div>
      )}

      {/* ── KPI Row ── */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
        <KpiCard label="Total Rules"     value={summary?.rules_total               ?? 0}  accent="#4d9eff"  icon="📋" />
        <KpiCard label="Active Findings" value={summary?.findings_open             ?? 0}  accent="#ff3b3b"  icon="🔴" sub="Requires attention" />
        <KpiCard label="Critical / High" value={summary?.findings_critical_high    ?? 0}  accent="#ff3b3b"  icon="⚡" sub="High-severity findings" />
        <KpiCard label="New (24h)"       value={summary?.findings_last_24h         ?? 0}  accent="#ff8c00"  icon="⏱" sub="Last 24 hours" />
        <KpiCard label="Rules Firing"    value={summary?.rules_with_open_findings  ?? 0}  accent="#4d9eff"  icon="🎯" sub="Rules with open findings" />
      </div>

      {/* ── Row 1: Hunt Rules + AI Analysis ── */}
      <div style={{ display: "grid", gridTemplateColumns: "3fr 2fr", gap: 14, marginBottom: 14 }}>
        <Panel title="Hunt Rules"
          accent="#ff8c00"
          badge={rules.length > 0 ? `${rules.length} RULES` : null}>
          <HuntRulesTable rules={rules} loading={loading} />
        </Panel>

        <Panel title="CyMind AI Analysis" accent="#b06eff">
          <AiAnalysisPanel
            analysis={aiAnalysis}
            analyzing={analyzing}
            onAnalyze={handleAnalyze}
          />
        </Panel>
      </div>

      {/* ── Row 2: Active Findings ── */}
      <div style={{ marginBottom: 14 }}>
        <Panel
          title="Active Hunt Findings"
          accent="#ff3b3b"
          badge={findings.length > 0 ? `${findings.length} FINDINGS` : null}
        >
          <HuntFindingsTable
            findings={findings}
            loading={loading}
            onViewIncidents={() => setActiveTab?.("siem-incidents")}
          />
        </Panel>
      </div>

      {/* ── Footer ── */}
      <div style={{ padding: "10px 0", color: "rgba(255,255,255,0.45)", fontSize: 9, fontFamily: "monospace", textAlign: "center" }}>
        Hunt engine refreshes every 60 s · Proactive rules run every 6 h · On-demand via CyMind AI
      </div>
    </div>
  );
}

export default ThreatHuntingPage;
