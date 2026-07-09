/**
 * HostDetailPanel.jsx
 * Full-screen overlay — 7-tab security profile for a single host.
 * Tabs: Overview · SCA · Vulnerabilities · FIM · Malware · MITRE · Compliance
 *
 * Each tab supports click-to-expand with:
 *   • Status buttons (persisted in tab-level statusMap while panel is open)
 *   • Manual "Analyze with AI" button (on-demand enrichment; results cached in tab)
 *   • "Open Case" button (opens a CyCases investigation via POST /api/cases)
 */

import { useState, useEffect, useCallback } from "react";

const API = "/api/siem";

const GRADE_COLOR = {
  "A+": "#00e5a0", A: "#00e5a0", B: "#4d9eff",
  C: "#ff8c00", D: "#ff3b3b", F: "#ff3b3b", "—": "#888",
};
const SEV_COLOR = {
  Critical: "#ff3b3b", High: "#ff8c00", Medium: "#ffcc00", Low: "#4d9eff",
  critical: "#ff3b3b", high: "#ff8c00", medium: "#ffcc00", low: "#4d9eff",
};
const STATUS_LABELS = {
  investigating: "Investigating",
  in_review:     "In Review",
  resolved:      "Resolved",
  false_positive:"False Positive",
};
const STATUS_COLORS = {
  investigating:  "#4d9eff",
  in_review:      "#ff8c00",
  resolved:       "#00e5a0",
  false_positive: "#888",
};
const TABS = ["Overview", "Inventory", "SCA", "Vulnerabilities", "FIM", "Malware", "MITRE", "Compliance"];

// Derive a stable string key for an item — must match the tab-level statusMap key.
function _deriveItemKey(itemType, item) {
  if (!item) return null;
  switch (itemType) {
    case "sca":          return item.id != null ? String(item.id) : item.title?.slice(0, 100) || null;
    case "vulnerability":return item.cve || null;
    case "alert":        return item.id != null ? String(item.id) : null;
    case "mitre":        return item.technique || item.mitre_id || null;
    case "compliance":   return item.requirement?.slice(0, 100) || item.title?.slice(0, 100) || null;
    default:             return null;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function Pill({ label, color = "#4d9eff" }) {
  return (
    <span style={{
      display: "inline-block", padding: "2px 7px", borderRadius: 3,
      background: `${color}18`, border: `1px solid ${color}40`,
      color, fontSize: 10, fontFamily: "monospace", marginRight: 4, marginBottom: 3,
    }}>{label}</span>
  );
}

function StatCard({ label, value, sub, color = "#4d9eff", wide = false }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)",
      borderRadius: 6, padding: "12px 16px",
      minWidth: wide ? 160 : 110, flex: wide ? "1 1 160px" : "0 0 110px",
    }}>
      <div style={{ fontSize: 10, color: "#888", marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700, color, fontFamily: "monospace" }}>{value ?? "—"}</div>
      {sub && <div style={{ fontSize: 10, color: "#888", marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

function ScoreBar({ score, color = "#4d9eff" }) {
  const pct = score != null ? Math.max(0, Math.min(100, score)) : 0;
  return (
    <div style={{ background: "rgba(255,255,255,0.06)", borderRadius: 2, height: 4, flex: 1 }}>
      <div style={{ width: `${pct}%`, height: "100%", background: color, transition: "width 0.4s" }} />
    </div>
  );
}

// ── EnrichmentPanel ───────────────────────────────────────────────────────────
/**
 * Props:
 *   agentId, hostName, itemType, item  — what to enrich
 *   onClose                            — collapse this panel
 *   initialStatus                      — restored from tab's statusMap
 *   onStatusChange(status)             — lift status up to tab
 *   cachedResult                       — previously fetched enrichment (or null)
 *   onEnrichResult(result)             — lift enrichment result up to tab for caching
 */
function EnrichmentPanel({
  agentId, hostName, itemType, item, itemKey, onClose,
  initialStatus, onStatusChange,
  cachedResult,  onEnrichResult,
}) {
  const [loading, setLoading]     = useState(false);
  const [result, setResult]       = useState(cachedResult || null);
  const [error, setError]         = useState(null);
  const [localStatus, setStatus]  = useState(initialStatus || null);

  function handleSetStatus(s) {
    const next = localStatus === s ? null : s;
    setStatus(next);
    onStatusChange?.(next);
    // Persist to backend (fire-and-forget)
    const resolvedKey = itemKey || _deriveItemKey(itemType, item);
    if (agentId && resolvedKey) {
      fetch(`${API}/hosts/${agentId}/item-statuses`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ item_type: itemType, item_key: resolvedKey, status: next }),
      }).catch(() => {});
    }
  }

  function doEnrich() {
    setLoading(true);
    setError(null);
    fetch(`${API}/hosts/${agentId}/enrich`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ item_type: itemType, item, host_name: hostName }),
    })
      .then(r => r.json())
      .then(d => {
        setResult(d);
        setLoading(false);
        onEnrichResult?.(d);
      })
      .catch(e => { setError(e.message); setLoading(false); });
  }


  const remLines = (result?.remediation || "")
    .split("\n")
    .map(l => l.replace(/^\s*\d+[\.\)]\s*/, "").trim())
    .filter(Boolean);

  const alreadyEnriched = result !== null;
  const enrichBtnLabel  = loading ? "Analyzing…"
    : alreadyEnriched   ? "✓ Analyzed"
    : "Analyze with AI";

  return (
    <div style={{
      margin: "0 -12px",
      borderTop: "1px solid rgba(0,229,160,0.18)",
      background: "rgba(0,229,160,0.025)",
      padding: "12px 16px 14px",
    }}>

      {/* ── Header row ── */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
        <span style={{ fontSize: 9, color: "#00e5a0", letterSpacing: "1.2px", fontFamily: "monospace" }}>
          ITEM ACTIONS
        </span>
        <button
          onClick={onClose}
          style={{ background: "none", border: "none", color: "#555", cursor: "pointer", fontSize: 14 }}>
          ✕
        </button>
      </div>

      {/* ── Status row ── */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
        <span style={{ fontSize: 10, color: "#666", marginRight: 2, flexShrink: 0 }}>Status:</span>
        {Object.entries(STATUS_LABELS).map(([s, label]) => {
          const active = localStatus === s;
          const col = STATUS_COLORS[s] || "#888";
          return (
            <button
              key={s}
              onClick={() => handleSetStatus(s)}
              style={{
                padding: "4px 10px", borderRadius: 3, cursor: "pointer",
                fontSize: 10, fontFamily: "monospace",
                background: active ? `${col}18` : "rgba(255,255,255,0.04)",
                border: active ? `1px solid ${col}60` : "1px solid rgba(255,255,255,0.1)",
                color: active ? col : "#666",
                transition: "all 0.15s",
              }}>
              {active ? "✓ " : ""}{label}
            </button>
          );
        })}
        {localStatus && (
          <Pill label={STATUS_LABELS[localStatus] || localStatus} color={STATUS_COLORS[localStatus] || "#888"} />
        )}
      </div>

      {/* ── Detection Detail (malware / rootcheck full log) ── */}
      {item?.full_log && (
        <div style={{
          background: "rgba(255,59,59,0.04)", border: "1px solid rgba(255,59,59,0.2)",
          borderRadius: 5, padding: "10px 12px", marginBottom: 10,
        }}>
          <div style={{ fontSize: 9, color: "#ff6b6b", letterSpacing: "1px", marginBottom: 6, fontFamily: "monospace" }}>
            DETECTION DETAIL
          </div>
          <div style={{ fontSize: 12, color: "#e8eaed", lineHeight: 1.6, fontFamily: "monospace", wordBreak: "break-word" }}>
            {item.full_log}
          </div>
        </div>
      )}

      {/* ── AI enrichment block ── */}
      <div style={{
        background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
        borderRadius: 5, padding: "10px 12px", marginBottom: 10,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: alreadyEnriched ? 10 : 0 }}>
          <span style={{ fontSize: 10, color: "#888", flex: 1 }}>
            {alreadyEnriched ? "AI ANALYSIS" : "AI + THREAT INTEL"}
          </span>
          <button
            onClick={doEnrich}
            disabled={loading || alreadyEnriched}
            style={{
              padding: "5px 12px", borderRadius: 3, cursor: alreadyEnriched ? "default" : "pointer",
              fontSize: 10, fontFamily: "monospace",
              background: alreadyEnriched ? "rgba(0,229,160,0.07)" : "rgba(77,158,255,0.1)",
              border: alreadyEnriched ? "1px solid rgba(0,229,160,0.25)" : "1px solid rgba(77,158,255,0.3)",
              color: alreadyEnriched ? "#00e5a0" : loading ? "#555" : "#4d9eff",
              opacity: loading ? 0.7 : 1,
            }}>
            {enrichBtnLabel}
          </button>
        </div>

        {loading && (
          <div style={{ color: "#888", fontSize: 11, padding: "4px 0" }}>Fetching AI analysis…</div>
        )}

        {error && (
          <div style={{ color: "#ff6b6b", fontSize: 11, marginTop: 6 }}>
            Enrichment failed: {error}
            <button
              onClick={doEnrich}
              style={{ marginLeft: 8, background: "none", border: "none", color: "#4d9eff", cursor: "pointer", fontSize: 11 }}>
              Retry
            </button>
          </div>
        )}

        {result && !loading && (
          <>
            {/* AI not configured */}
            {!result.ai_configured && (
              <div style={{
                background: "rgba(255,140,0,0.07)", border: "1px solid rgba(255,140,0,0.2)",
                borderRadius: 4, padding: "8px 10px", fontSize: 11, color: "#ff8c00", marginTop: 4,
              }}>
                ⚠ No AI provider configured. Go to{" "}
                <strong>System Settings → AI Config</strong> to set up CyMind, Anthropic, Gemini, or DeepSeek.
              </div>
            )}

            {/* AI call failed but was configured */}
            {result.ai_configured && !result.ai_available && result.ai_error && (
              <div style={{
                background: "rgba(255,59,59,0.07)", border: "1px solid rgba(255,59,59,0.2)",
                borderRadius: 4, padding: "8px 10px", fontSize: 11, color: "#ff6b6b", marginTop: 4,
              }}>
                AI call failed — {result.ai_error.startsWith("call_failed:") ? result.ai_error.slice(13) : result.ai_error}
                <button
                  onClick={doEnrich}
                  style={{ marginLeft: 8, background: "none", border: "none", color: "#4d9eff", cursor: "pointer", fontSize: 11 }}>
                  Retry
                </button>
              </div>
            )}

            {/* Explanation */}
            {result.explanation && (
              <div style={{ marginTop: 6 }}>
                <div style={{ fontSize: 10, color: "#888", marginBottom: 4 }}>ANALYST BRIEFING</div>
                <div style={{ fontSize: 12, color: "#e8eaed", lineHeight: 1.65 }}>{result.explanation}</div>
              </div>
            )}

            {/* Remediation steps */}
            {remLines.length > 0 && (
              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 10, color: "#888", marginBottom: 4 }}>REMEDIATION STEPS</div>
                <ol style={{ margin: 0, paddingLeft: 18, color: "#e8eaed", fontSize: 12, lineHeight: 1.7 }}>
                  {remLines.map((step, i) => <li key={i}>{step}</li>)}
                </ol>
              </div>
            )}

            {/* CyTIM TI hits (ti_hits from siem_proxy enrichment) */}
            {(result.ti_hits || result.misp_hits || []).length > 0 && (
              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 10, color: "#ff8c00", marginBottom: 5 }}>
                  ⚠ THREAT INTEL MATCHES ({(result.ti_hits || result.misp_hits).length} match{(result.ti_hits || result.misp_hits).length > 1 ? "es" : ""} via CyTIM)
                </div>
                {(result.ti_hits || result.misp_hits).map((hit, i) => (
                  <div key={i} style={{
                    background: "rgba(255,140,0,0.07)", border: "1px solid rgba(255,140,0,0.2)",
                    borderRadius: 4, padding: "5px 10px", marginBottom: 4, fontSize: 11,
                  }}>
                    <span style={{ color: "#ff8c00", fontFamily: "monospace" }}>{hit.ioc}</span>
                    <span style={{ color: "#888", marginLeft: 8 }}>[{hit.type}]</span>
                    {hit.comment && <span style={{ color: "#888", marginLeft: 8 }}>{hit.comment}</span>}
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>

      {/* ── Case note ── */}
      <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace",
        paddingTop: 4, lineHeight: 1.6 }}>
        🗂️ Cases are opened from{" "}
        <span style={{ color: "#4d9eff" }}>Active Incidents</span>{" "}
        when a SIEM alert correlates with this host finding.
      </div>
    </div>
  );
}

// ── Tab: Overview ─────────────────────────────────────────────────────────────

function OverviewTab({ detail }) {
  const { posture = {}, sca = {}, vulnerabilities = {}, siem = {}, mitre = {}, compliance = {} } = detail;
  const bd = posture.breakdown || {};
  const topMitre = (mitre.breakdown || []).slice(0, 5);
  const topInc   = (siem.active_incidents || []).slice(0, 3);

  return (
    <div>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 20 }}>
        <StatCard label="Posture Score" value={posture.score?.toFixed(0)} sub={`Grade ${posture.grade || "—"}`}
          color={GRADE_COLOR[posture.grade] || "#888"} wide />
        <StatCard label="SCA Pass Rate" value={sca.score?.toFixed(0)} sub={`${sca.passed}/${sca.total} checks`} color="#00e5a0" />
        <StatCard label="Critical CVEs"  value={vulnerabilities.critical} sub={`${vulnerabilities.high} High`} color="#ff3b3b" />
        <StatCard label="SIEM Risk"       value={siem.risk_score?.toFixed(0)} sub="/100" color={siem.risk_score > 70 ? "#ff3b3b" : "#ff8c00"} />
        <StatCard label="Open Incidents"  value={siem.incident_count} color={siem.incident_count > 0 ? "#ff8c00" : "#888"} />
      </div>

      {Object.keys(bd).length > 0 && (
        <div style={{
          background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 6, padding: "12px 16px", marginBottom: 20,
        }}>
          <div style={{ fontSize: 10, color: "#888", letterSpacing: "0.8px", marginBottom: 10 }}>POSTURE COMPONENTS</div>
          {Object.entries(bd).map(([k, v]) => {
            const label = { sca: "SCA Pass Rate", vuln: "Vulnerability", siem_risk: "SIEM Risk", fim_malware: "FIM / Malware", compliance: "Compliance" }[k] || k;
            const col = v >= 70 ? "#00e5a0" : v >= 50 ? "#ff8c00" : "#ff3b3b";
            return (
              <div key={k} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                <div style={{ width: 130, fontSize: 11, color: "#888" }}>{label}</div>
                <ScoreBar score={v} color={col} />
                <div style={{ width: 35, textAlign: "right", fontSize: 11, color: col, fontFamily: "monospace" }}>{v?.toFixed(0)}</div>
              </div>
            );
          })}
        </div>
      )}

      {topMitre.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 10, color: "#888", letterSpacing: "0.8px", marginBottom: 8 }}>MITRE ATT&CK (LAST 30 DAYS)</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {topMitre.map(t => (
              <div key={t.mitre_id} style={{
                background: "rgba(77,158,255,0.08)", border: "1px solid rgba(77,158,255,0.2)",
                borderRadius: 4, padding: "5px 10px",
              }}>
                <span style={{ color: "#4d9eff", fontFamily: "monospace", fontSize: 12 }}>{t.mitre_id}</span>
                {t.tactic && <span style={{ color: "#888", fontSize: 10, marginLeft: 6 }}>{t.tactic}</span>}
                <span style={{ color: "#888", fontSize: 10, marginLeft: 6 }}>×{t.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {topInc.length > 0 && (
        <div>
          <div style={{ fontSize: 10, color: "#888", letterSpacing: "0.8px", marginBottom: 8 }}>ACTIVE INCIDENTS</div>
          {topInc.map(inc => (
            <div key={inc.id} style={{
              background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
              borderRadius: 4, padding: "8px 12px", marginBottom: 6,
              display: "flex", alignItems: "center", gap: 10,
            }}>
              <span style={{ fontFamily: "monospace", fontSize: 10, color: "#888" }}>{inc.id}</span>
              <Pill label={inc.severity?.toUpperCase()} color={SEV_COLOR[inc.severity] || "#888"} />
              <span style={{ fontSize: 12, color: "#e8eaed", flex: 1 }}>{inc.summary?.slice(0, 80)}…</span>
              {inc.case_opened_at && <Pill label="🗂️ CASE" color="#b06eff" />}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Tab: SCA ──────────────────────────────────────────────────────────────────

function SCATab({ agentId, hostName }) {
  const [data, setData]         = useState(null);
  const [loading, setLoading]   = useState(true);
  const [filter, setFilter]     = useState("failed");
  const [page, setPage]         = useState(1);
  const [selectedId, setSelected] = useState(null);
  // Persistence across item clicks
  const [statusMap, setStatusMap]   = useState({});   // { checkId: statusString }
  const [enrichCache, setEnrichCache] = useState({}); // { checkId: enrichResult }
  const PER_PAGE = 50;

  useEffect(() => {
    setLoading(true);
    setSelected(null);
    const qs = new URLSearchParams({ result: filter, page: String(page), per_page: String(PER_PAGE) });
    fetch(`${API}/hosts/${agentId}/sca?${qs}`, { credentials: "include" })
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [agentId, filter, page]);

  // Load persisted analyst acknowledgements for SCA items
  useEffect(() => {
    fetch(`${API}/hosts/${agentId}/item-statuses`, { credentials: "include" })
      .then(r => r.json())
      .then(d => setStatusMap(d["sca"] || {}))
      .catch(() => {});
  }, [agentId]);

  if (loading) return <div style={{ padding: 30, color: "#888", textAlign: "center" }}>Loading SCA data…</div>;
  if (!data)   return <div style={{ padding: 30, color: "#ff6b6b" }}>Failed to load SCA data.</div>;

  const policies = data.policies || [];
  const checks   = data.checks   || [];
  const total    = data.total    || 0;

  return (
    <div>
      {data.source === "alerts_db" && (
        <div style={{
          background: "rgba(255,140,0,0.08)", border: "1px solid rgba(255,140,0,0.3)",
          borderRadius: 5, padding: "7px 12px", marginBottom: 12,
          fontSize: 11, color: "#ff8c00",
        }}>
          Showing historical SCA data from the alerts database — this agent may have re-enrolled under a new ID.
          Trigger a host refresh to consolidate duplicates.
        </div>
      )}
      {policies.length > 0 && (
        <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
          {policies.map(p => (
            <div key={p.policy_id} style={{
              background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
              borderRadius: 6, padding: "8px 12px", fontSize: 11,
            }}>
              <div style={{ color: "#e8eaed", marginBottom: 3 }}>{p.name || p.policy_id}</div>
              <div style={{ display: "flex", gap: 12 }}>
                <span style={{ color: "#00e5a0" }}>✓ {p.pass}</span>
                <span style={{ color: "#ff3b3b" }}>✗ {p.fail}</span>
                <span style={{ color: "#888" }}>? {p.error}</span>
                <span style={{ color: "#888" }}>Score: {p.score}%</span>
              </div>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: "flex", gap: 8, marginBottom: 12, alignItems: "center" }}>
        {["all", "failed", "passed", "not applicable"].map(f => (
          <button key={f} onClick={() => { setFilter(f); setPage(1); }}
            style={{
              background: filter === f ? "rgba(0,229,160,0.1)" : "rgba(255,255,255,0.04)",
              border: filter === f ? "1px solid rgba(0,229,160,0.4)" : "1px solid rgba(255,255,255,0.1)",
              color: filter === f ? "#00e5a0" : "#888",
              padding: "4px 10px", borderRadius: 4, fontSize: 11, cursor: "pointer",
            }}>
            {f === "all" ? "All" : f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
        <span style={{ marginLeft: "auto", fontSize: 11, color: "#888" }}>{total} checks</span>
      </div>

      <div style={{ background: "rgba(255,255,255,0.02)", borderRadius: 6, overflow: "hidden" }}>
        <div style={{
          display: "grid", gridTemplateColumns: "60px 1fr 100px 90px",
          padding: "6px 12px", fontSize: 10, color: "#888",
          background: "rgba(255,255,255,0.03)", borderBottom: "1px solid rgba(255,255,255,0.06)",
        }}>
          <div>ID</div><div>CHECK</div><div>RESULT</div><div>STATUS</div>
        </div>
        {checks.length === 0
          ? <div style={{ padding: 20, color: "#888", textAlign: "center", fontSize: 12 }}>No checks found.</div>
          : checks.map(c => {
            const key = String(c.id);
            const resultCol = c.result === "passed" ? "#00e5a0" : c.result === "failed" ? "#ff3b3b" : "#888";
            const isOpen = selectedId === key;
            const curStatus = statusMap[key];
            return (
              <div key={key} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <div
                  onClick={() => setSelected(isOpen ? null : key)}
                  style={{
                    display: "grid", gridTemplateColumns: "60px 1fr 100px 90px",
                    padding: "8px 12px", cursor: "pointer", fontSize: 12,
                    background: isOpen ? "rgba(0,229,160,0.04)" : "transparent",
                  }}>
                  <span style={{ color: "#888", fontFamily: "monospace" }}>{c.id}</span>
                  <span style={{ color: "#e8eaed" }}>{c.title}</span>
                  <span style={{ color: resultCol, textTransform: "uppercase", fontSize: 10 }}>{c.result}</span>
                  <span style={{ fontSize: 10, color: curStatus ? STATUS_COLORS[curStatus] : "#444" }}>
                    {curStatus ? STATUS_LABELS[curStatus] : "—"}
                  </span>
                </div>
                {isOpen && (
                  <EnrichmentPanel
                    agentId={agentId} hostName={hostName}
                    itemType="sca" item={c} itemKey={key}
                    onClose={() => setSelected(null)}
                    initialStatus={statusMap[key]}
                    onStatusChange={s => setStatusMap(prev => ({ ...prev, [key]: s }))}
                    cachedResult={enrichCache[key] || null}
                    onEnrichResult={r => setEnrichCache(prev => ({ ...prev, [key]: r }))}
                  />
                )}
              </div>
            );
          })}
      </div>

      {total > PER_PAGE && (
        <div style={{ display: "flex", justifyContent: "center", gap: 8, marginTop: 12 }}>
          <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", color: "#e8eaed", padding: "4px 10px", borderRadius: 3, cursor: "pointer" }}>←</button>
          <span style={{ fontSize: 11, color: "#888", padding: "5px 0" }}>Page {page}</span>
          <button disabled={page * PER_PAGE >= total} onClick={() => setPage(p => p + 1)}
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", color: "#e8eaed", padding: "4px 10px", borderRadius: 3, cursor: "pointer" }}>→</button>
        </div>
      )}
    </div>
  );
}

// ── Tab: Vulnerabilities ──────────────────────────────────────────────────────

function VulnerabilitiesTab({ agentId, hostName }) {
  const [data, setData]            = useState(null);
  const [loading, setLoading]      = useState(true);
  const [sevFilter, setSev]        = useState("");
  const [page, setPage]            = useState(1);
  const [selectedKey, setSelected] = useState(null);
  const [statusMap, setStatusMap]     = useState({});
  const [enrichCache, setEnrichCache] = useState({});
  const PER_PAGE = 100;

  useEffect(() => {
    setLoading(true);
    setSelected(null);
    const qs = new URLSearchParams({ page: String(page), per_page: String(PER_PAGE), ...(sevFilter ? { severity: sevFilter } : {}) });
    fetch(`${API}/hosts/${agentId}/vulnerabilities?${qs}`, { credentials: "include" })
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [agentId, sevFilter, page]);

  // Load persisted analyst acknowledgements for vulnerability items
  useEffect(() => {
    fetch(`${API}/hosts/${agentId}/item-statuses`, { credentials: "include" })
      .then(r => r.json())
      .then(d => setStatusMap(d["vulnerability"] || {}))
      .catch(() => {});
  }, [agentId]);

  if (loading) return <div style={{ padding: 30, color: "#888", textAlign: "center" }}>Loading vulnerabilities…</div>;
  if (!data)   return <div style={{ padding: 30, color: "#ff6b6b" }}>Failed to load vulnerabilities.</div>;

  const vulns = data.vulnerabilities || [];
  const total  = data.total || 0;
  const vulnNote = data.note || null;

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12, alignItems: "center" }}>
        {["", "Critical", "High", "Medium", "Low"].map(s => (
          <button key={s} onClick={() => { setSev(s); setPage(1); }}
            style={{
              background: sevFilter === s ? `${SEV_COLOR[s] || "rgba(255,255,255,0.15)"}20` : "rgba(255,255,255,0.04)",
              border: `1px solid ${sevFilter === s ? (SEV_COLOR[s] || "rgba(255,255,255,0.4)") : "rgba(255,255,255,0.1)"}`,
              color: sevFilter === s ? (SEV_COLOR[s] || "#e8eaed") : "#888",
              padding: "4px 10px", borderRadius: 4, fontSize: 11, cursor: "pointer",
            }}>{s || "All"}</button>
        ))}
        <span style={{ marginLeft: "auto", fontSize: 11, color: "#888" }}>{total} active CVEs</span>
      </div>

      <div style={{ background: "rgba(255,255,255,0.02)", borderRadius: 6, overflow: "hidden" }}>
        <div style={{
          display: "grid", gridTemplateColumns: "160px 60px 140px 1fr 90px",
          padding: "6px 12px", fontSize: 10, color: "#888",
          background: "rgba(255,255,255,0.03)", borderBottom: "1px solid rgba(255,255,255,0.06)",
        }}>
          <div>CVE</div><div>CVSS</div><div>PACKAGE</div><div>DESCRIPTION</div><div>STATUS</div>
        </div>
        {vulns.length === 0
          ? <div style={{ padding: 20, color: "#888", textAlign: "center" }}>
              {vulnNote
                ? <span style={{ color: "#f5c518", fontSize: 11, fontFamily: "monospace" }}>⚠ {vulnNote}</span>
                : "No active CVEs found."}
            </div>
          : vulns.map((v, i) => {
            const key = v.cve || String(i);
            const col = SEV_COLOR[v.severity] || "#888";
            const isOpen = selectedKey === key;
            const curStatus = statusMap[key];
            return (
              <div key={key} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <div
                  onClick={() => setSelected(isOpen ? null : key)}
                  style={{
                    display: "grid", gridTemplateColumns: "160px 60px 140px 1fr 90px",
                    padding: "8px 12px", fontSize: 11, alignItems: "start",
                    cursor: "pointer",
                    background: isOpen ? "rgba(255,140,0,0.04)" : "transparent",
                  }}>
                  <span style={{ color: col, fontFamily: "monospace" }}>{v.cve || "—"}</span>
                  <span style={{ color: col }}>{v.cvss || "—"}</span>
                  <span style={{ color: "#e8eaed" }}>{v.name || "—"} {v.version || ""}</span>
                  <span style={{ color: "#888" }}>{v.title || v.condition || "—"}</span>
                  <span style={{ fontSize: 10, color: curStatus ? STATUS_COLORS[curStatus] : "#444" }}>
                    {curStatus ? STATUS_LABELS[curStatus] : "—"}
                  </span>
                </div>
                {isOpen && (
                  <EnrichmentPanel
                    agentId={agentId} hostName={hostName}
                    itemType="vulnerability" itemKey={key}
                    item={{ ...v, package_name: v.name, package_version: v.version, cvss3_score: v.cvss }}
                    onClose={() => setSelected(null)}
                    initialStatus={statusMap[key]}
                    onStatusChange={s => setStatusMap(prev => ({ ...prev, [key]: s }))}
                    cachedResult={enrichCache[key] || null}
                    onEnrichResult={r => setEnrichCache(prev => ({ ...prev, [key]: r }))}
                  />
                )}
              </div>
            );
          })}
      </div>

      {total > PER_PAGE && (
        <div style={{ display: "flex", justifyContent: "center", gap: 8, marginTop: 12 }}>
          <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", color: "#e8eaed", padding: "4px 10px", borderRadius: 3, cursor: "pointer" }}>←</button>
          <span style={{ fontSize: 11, color: "#888", padding: "5px 0" }}>Page {page} of {Math.ceil(total / PER_PAGE)}</span>
          <button disabled={page * PER_PAGE >= total} onClick={() => setPage(p => p + 1)}
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", color: "#e8eaed", padding: "4px 10px", borderRadius: 3, cursor: "pointer" }}>→</button>
        </div>
      )}
    </div>
  );
}

// ── Tab: Alerts (FIM + Malware) ───────────────────────────────────────────────

function AlertsTab({ agentId, hostName, category, label }) {
  const [data, setData]            = useState(null);
  const [loading, setLoading]      = useState(true);
  const [page, setPage]            = useState(1);
  const [selectedKey, setSelected] = useState(null);
  const [statusMap, setStatusMap]     = useState({});
  const [enrichCache, setEnrichCache] = useState({});
  const PER_PAGE = 50;

  useEffect(() => {
    setLoading(true);
    setSelected(null);
    const qs = new URLSearchParams({ category, page: String(page), per_page: String(PER_PAGE) });
    fetch(`${API}/hosts/${agentId}/alerts?${qs}`, { credentials: "include" })
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [agentId, category, page]);

  // Load persisted analyst acknowledgements for alert items
  useEffect(() => {
    fetch(`${API}/hosts/${agentId}/item-statuses`, { credentials: "include" })
      .then(r => r.json())
      .then(d => setStatusMap(d["alert"] || {}))
      .catch(() => {});
  }, [agentId]);

  if (loading) return <div style={{ padding: 30, color: "#888", textAlign: "center" }}>Loading {label} events…</div>;
  if (!data)   return <div style={{ padding: 30, color: "#ff6b6b" }}>Failed to load {label} data.</div>;

  const alerts = data.alerts || [];
  const total  = data.total  || 0;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 10 }}>
        <span style={{ fontSize: 11, color: "#888" }}>{total} events (last 30 days)</span>
      </div>

      <div style={{ background: "rgba(255,255,255,0.02)", borderRadius: 6, overflow: "hidden" }}>
        <div style={{
          display: "grid", gridTemplateColumns: "140px 50px 1fr 120px 90px",
          padding: "6px 12px", fontSize: 10, color: "#888",
          background: "rgba(255,255,255,0.03)", borderBottom: "1px solid rgba(255,255,255,0.06)",
        }}>
          <div>TIMESTAMP</div><div>LEVEL</div><div>DESCRIPTION</div><div>FILE / USER</div><div>STATUS</div>
        </div>
        {alerts.length === 0
          ? <div style={{ padding: 20, color: "#888", textAlign: "center" }}>
              {category === "malware"
                ? <span>No malware / rootcheck detections in last 30 days.</span>
                : `No ${label} events in last 30 days.`}
            </div>
          : alerts.map((a, i) => {
            const key = a.id ? String(a.id) : `${category}-${i}`;
            const ts  = a.timestamp ? new Date(a.timestamp).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";
            const col = a.rule_level >= 12 ? "#ff3b3b" : a.rule_level >= 7 ? "#ff8c00" : "#888";
            const isOpen = selectedKey === key;
            const curStatus = statusMap[key];
            return (
              <div key={key} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <div
                  onClick={() => setSelected(isOpen ? null : key)}
                  style={{
                    display: "grid", gridTemplateColumns: "140px 50px 1fr 120px 90px",
                    padding: "7px 12px", fontSize: 11, alignItems: "start",
                    cursor: "pointer",
                    background: isOpen ? "rgba(255,140,0,0.04)" : "transparent",
                  }}>
                  <span style={{ color: "#888" }}>{ts}</span>
                  <span style={{ color: col, fontFamily: "monospace" }}>{a.rule_level}</span>
                  <span style={{ color: "#e8eaed" }}>{a.rule_desc || "—"}</span>
                  <span style={{ color: "#888", fontSize: 10, wordBreak: "break-all" }}>
                    {a.file_path ? a.file_path.slice(-30) : a.username || "—"}
                  </span>
                  <span style={{ fontSize: 10, color: curStatus ? STATUS_COLORS[curStatus] : "#444" }}>
                    {curStatus ? STATUS_LABELS[curStatus] : "—"}
                  </span>
                </div>
                {isOpen && (
                  <EnrichmentPanel
                    agentId={agentId} hostName={hostName}
                    itemType="alert" itemKey={key}
                    item={{ ...a, rule_description: a.rule_desc, description: a.rule_desc }}
                    onClose={() => setSelected(null)}
                    initialStatus={statusMap[key]}
                    onStatusChange={s => setStatusMap(prev => ({ ...prev, [key]: s }))}
                    cachedResult={enrichCache[key] || null}
                    onEnrichResult={r => setEnrichCache(prev => ({ ...prev, [key]: r }))}
                  />
                )}
              </div>
            );
          })}
      </div>

      {total > PER_PAGE && (
        <div style={{ display: "flex", justifyContent: "center", gap: 8, marginTop: 12 }}>
          <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", color: "#e8eaed", padding: "4px 10px", borderRadius: 3, cursor: "pointer" }}>←</button>
          <span style={{ fontSize: 11, color: "#888", padding: "5px 0" }}>Page {page}</span>
          <button disabled={page * PER_PAGE >= total} onClick={() => setPage(p => p + 1)}
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)", color: "#e8eaed", padding: "4px 10px", borderRadius: 3, cursor: "pointer" }}>→</button>
        </div>
      )}
    </div>
  );
}

// ── Tab: System Inventory ─────────────────────────────────────────────────────

function InventoryTab({ agentId }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [pkgSearch, setPkgSearch] = useState("");

  useEffect(() => {
    setLoading(true);
    fetch(`${API}/hosts/${agentId}/inventory`, { credentials: "include" })
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [agentId]);

  if (loading) return <div style={{ padding: 30, color: "#888", textAlign: "center" }}>Loading inventory…</div>;
  if (!data)   return <div style={{ padding: 30, color: "#ff6b6b" }}>Failed to load inventory.</div>;

  const agent = data.agent || {};
  const os    = data.os    || {};
  const hw    = data.hardware || {};
  const allPkgs = data.packages || [];

  const filtered = pkgSearch
    ? allPkgs.filter(p => p.name?.toLowerCase().includes(pkgSearch.toLowerCase()) ||
                          p.description?.toLowerCase().includes(pkgSearch.toLowerCase()))
    : allPkgs;

  const statusColor = agent.status === "active" ? "#00e5a0" : agent.status === "disconnected" ? "#ff8c00" : "#888";

  const fmtDate = iso => {
    if (!iso || iso.startsWith("9999")) return "—";
    try { return new Date(iso).toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" }); }
    catch { return iso; }
  };

  const fmtMB = kb => kb ? `${(kb / 1024).toFixed(0)} MB` : "—";

  return (
    <div>
      {/* ── Identity ── */}
      <div style={{ fontSize: 10, color: "#888", letterSpacing: "0.8px", marginBottom: 10 }}>AGENT IDENTITY</div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginBottom: 20 }}>
        {[
          { label: "STATUS",       value: <span style={{ color: statusColor, fontWeight: 700 }}>{(agent.status || "unknown").toUpperCase()}</span> },
          { label: "HOSTNAME",     value: os.hostname || agent.name || "—" },
          { label: "IP ADDRESS",   value: agent.ip || "—" },
          { label: "OS",           value: os.os_name ? `${os.os_name} ${os.os_major || ""}.${os.os_minor || ""}` : agent.os_version || "—" },
          { label: "PLATFORM",     value: agent.os_platform || "—" },
          { label: "ARCHITECTURE", value: os.architecture || "—" },
          { label: "KERNEL",       value: os.kernel_release ? os.kernel_release.slice(0, 30) : "—" },
          { label: "AGENT VERSION",value: agent.version || "—" },
          { label: "REGISTERED",   value: fmtDate(agent.date_add) },
          { label: "LAST KEEPALIVE", value: fmtDate(agent.last_keepalive), wide: true },
        ].map(({ label, value, wide }) => (
          <div key={label} style={{
            background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 5, padding: "10px 14px",
            minWidth: wide ? 200 : 130, flex: wide ? "1 1 200px" : "0 0 130px",
          }}>
            <div style={{ fontSize: 9, color: "#555", letterSpacing: "0.8px", marginBottom: 4 }}>{label}</div>
            <div style={{ fontSize: 12, color: "#e8eaed", fontFamily: "monospace", wordBreak: "break-all" }}>{value}</div>
          </div>
        ))}
      </div>

      {/* ── Hardware ── */}
      {hw.cpu_name && (
        <>
          <div style={{ fontSize: 10, color: "#888", letterSpacing: "0.8px", marginBottom: 10 }}>HARDWARE</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginBottom: 20 }}>
            {[
              { label: "CPU",       value: hw.cpu_name },
              { label: "CORES",     value: hw.cpu_cores ?? "—" },
              { label: "CPU SPEED", value: hw.cpu_mhz ? `${(hw.cpu_mhz / 1000).toFixed(1)} GHz` : "—" },
              { label: "RAM TOTAL", value: fmtMB(hw.ram_total) },
              { label: "RAM FREE",  value: fmtMB(hw.ram_free) },
              { label: "RAM USAGE", value: hw.ram_usage != null ? `${hw.ram_usage}%` : "—",
                color: hw.ram_usage > 85 ? "#ff3b3b" : hw.ram_usage > 70 ? "#ff8c00" : "#00e5a0" },
            ].map(({ label, value, color }) => (
              <div key={label} style={{
                background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
                borderRadius: 5, padding: "10px 14px", flex: label === "CPU" ? "1 1 200px" : "0 0 110px",
              }}>
                <div style={{ fontSize: 9, color: "#555", letterSpacing: "0.8px", marginBottom: 4 }}>{label}</div>
                <div style={{ fontSize: 12, color: color || "#e8eaed", fontFamily: "monospace" }}>{value}</div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* ── Packages ── */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
        <div style={{ fontSize: 10, color: "#888", letterSpacing: "0.8px" }}>
          INSTALLED PACKAGES{data.packages_total ? ` (${data.packages_total} total)` : ""}
        </div>
        <input
          value={pkgSearch}
          onChange={e => setPkgSearch(e.target.value)}
          placeholder="filter packages…"
          style={{
            marginLeft: "auto", background: "rgba(255,255,255,0.05)",
            border: "1px solid rgba(255,255,255,0.12)", borderRadius: 4,
            color: "#e8eaed", padding: "4px 10px", fontSize: 11, fontFamily: "monospace",
            outline: "none", width: 180,
          }}
        />
      </div>

      {filtered.length === 0
        ? <div style={{ padding: 20, color: "#888", textAlign: "center" }}>
            {allPkgs.length === 0 ? "Package inventory not available for this agent." : "No packages match filter."}
          </div>
        : (
          <div style={{ background: "rgba(255,255,255,0.02)", borderRadius: 6, overflow: "hidden" }}>
            <div style={{
              display: "grid", gridTemplateColumns: "180px 120px 60px 1fr 90px",
              padding: "6px 12px", fontSize: 10, color: "#888",
              background: "rgba(255,255,255,0.03)", borderBottom: "1px solid rgba(255,255,255,0.06)",
            }}>
              <div>PACKAGE</div><div>VERSION</div><div>SIZE</div><div>DESCRIPTION</div><div>ARCH</div>
            </div>
            {filtered.map((p, i) => (
              <div key={`${p.name}-${i}`} style={{
                display: "grid", gridTemplateColumns: "180px 120px 60px 1fr 90px",
                padding: "7px 12px", fontSize: 11, alignItems: "start",
                borderBottom: "1px solid rgba(255,255,255,0.03)",
                background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)",
              }}>
                <span style={{ color: "#4d9eff", fontFamily: "monospace" }}>{p.name || "—"}</span>
                <span style={{ color: "#e8eaed", fontFamily: "monospace", fontSize: 10 }}>{p.version || "—"}</span>
                <span style={{ color: "#888", fontSize: 10 }}>{p.size ? `${(p.size / 1024).toFixed(0)}k` : "—"}</span>
                <span style={{ color: "#888", fontSize: 10 }}>{p.description || "—"}</span>
                <span style={{ color: "#888", fontSize: 10 }}>{p.architecture || "—"}</span>
              </div>
            ))}
          </div>
        )
      }
    </div>
  );
}

// ── Tab: MITRE ────────────────────────────────────────────────────────────────

function MitreTab({ detail, agentId, hostName }) {
  const { mitre = {}, alerts_by_category = {} } = detail;
  const breakdown = mitre.breakdown || [];
  const [selectedId, setSelected]         = useState(null);
  const [statusMap, setStatusMap]         = useState({});
  const [enrichCache, setEnrichCache]     = useState({});

  // Load persisted analyst acknowledgements for MITRE techniques
  useEffect(() => {
    fetch(`${API}/hosts/${agentId}/item-statuses`, { credentials: "include" })
      .then(r => r.json())
      .then(d => setStatusMap(d["mitre"] || {}))
      .catch(() => {});
  }, [agentId]);

  return (
    <div>
      <div style={{ fontSize: 10, color: "#888", letterSpacing: "0.8px", marginBottom: 12 }}>
        TECHNIQUES OBSERVED ON THIS HOST (LAST 30 DAYS)
      </div>
      {breakdown.length === 0 ? (
        <div style={{ color: "#888", textAlign: "center", padding: 30 }}>No MITRE techniques observed.</div>
      ) : (
        <div style={{ background: "rgba(255,255,255,0.02)", borderRadius: 6, overflow: "hidden" }}>
          <div style={{
            display: "grid", gridTemplateColumns: "100px 1fr 60px 90px",
            padding: "6px 14px", fontSize: 10, color: "#888",
            background: "rgba(255,255,255,0.03)", borderBottom: "1px solid rgba(255,255,255,0.06)",
          }}>
            <div>TECHNIQUE</div><div>TACTIC</div><div>COUNT</div><div>STATUS</div>
          </div>
          {breakdown.map(t => {
            const key = t.mitre_id;
            const isOpen = selectedId === key;
            const curStatus = statusMap[key];
            return (
              <div key={key} style={{ borderBottom: "1px solid rgba(77,158,255,0.08)" }}>
                <div
                  onClick={() => setSelected(isOpen ? null : key)}
                  style={{
                    display: "grid", gridTemplateColumns: "100px 1fr 60px 90px",
                    padding: "8px 14px", cursor: "pointer", alignItems: "center",
                    background: isOpen ? "rgba(77,158,255,0.08)" : "rgba(77,158,255,0.03)",
                  }}>
                  <span style={{ color: "#4d9eff", fontFamily: "monospace", fontWeight: 700 }}>{t.mitre_id}</span>
                  <span style={{ color: "#888", fontSize: 11 }}>{t.tactic || "—"}</span>
                  <span style={{ color: "#4d9eff", fontFamily: "monospace", fontSize: 11 }}>×{t.count}</span>
                  <span style={{ fontSize: 10, color: curStatus ? STATUS_COLORS[curStatus] : "#444" }}>
                    {curStatus ? STATUS_LABELS[curStatus] : "—"}
                  </span>
                </div>
                {isOpen && (
                  <EnrichmentPanel
                    agentId={agentId} hostName={hostName}
                    itemType="mitre" itemKey={key}
                    item={{ technique: t.mitre_id, tactic: t.tactic, count: t.count }}
                    onClose={() => setSelected(null)}
                    initialStatus={statusMap[key]}
                    onStatusChange={s => setStatusMap(prev => ({ ...prev, [key]: s }))}
                    cachedResult={enrichCache[key] || null}
                    onEnrichResult={r => setEnrichCache(prev => ({ ...prev, [key]: r }))}
                  />
                )}
              </div>
            );
          })}
        </div>
      )}

      {Object.keys(alerts_by_category).length > 0 && (
        <div style={{ marginTop: 24 }}>
          <div style={{ fontSize: 10, color: "#888", letterSpacing: "0.8px", marginBottom: 10 }}>ALERT CATEGORIES (LAST 30 DAYS)</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {Object.entries(alerts_by_category).map(([cat, info]) => (
              <div key={cat} style={{
                background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)",
                borderRadius: 5, padding: "8px 12px", minWidth: 110,
              }}>
                <div style={{ fontSize: 10, color: "#888", marginBottom: 3, textTransform: "uppercase" }}>{cat}</div>
                <div style={{ fontSize: 18, fontWeight: 700, fontFamily: "monospace", color: "#e8eaed" }}>{info.count}</div>
                <div style={{ fontSize: 9, color: "#888" }}>max level {info.max_level}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Tab: Compliance ───────────────────────────────────────────────────────────

function ComplianceTab({ detail, agentId, hostName }) {
  const { sca = {}, compliance = {}, mitre = {} } = detail;
  const scaFailures = sca.recent_failures || [];
  const [selectedIdx, setSelected]        = useState(null);
  const [statusMap, setStatusMap]         = useState({});
  const [enrichCache, setEnrichCache]     = useState({});

  const FRAMEWORKS = [
    { key: "pci_dss",  label: "PCI DSS",     color: "#ff8c00" },
    { key: "gdpr",     label: "GDPR",        color: "#4d9eff" },
    { key: "hipaa",    label: "HIPAA",       color: "#b06eff" },
    { key: "nist_csf", label: "NIST CSF",    color: "#00e5a0" },
    { key: "tsc",      label: "TSC / SOC 2", color: "#ffcc00" },
    { key: "iso27001", label: "ISO 27001",   color: "#ff8c00" },
    { key: "nis2",     label: "NIS2",        color: "#4d9eff" },
  ];

  // Load persisted analyst acknowledgements for compliance items
  useEffect(() => {
    fetch(`${API}/hosts/${agentId}/item-statuses`, { credentials: "include" })
      .then(r => r.json())
      .then(d => setStatusMap(d["compliance"] || {}))
      .catch(() => {});
  }, [agentId]);

  return (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
        <div style={{
          background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 6, padding: "12px 16px", minWidth: 150,
        }}>
          <div style={{ fontSize: 10, color: "#888", marginBottom: 4 }}>COMPLIANCE SCORE</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: "#00e5a0", fontFamily: "monospace" }}>
            {compliance.score?.toFixed(0) ?? "—"}
          </div>
        </div>
        <div style={{
          background: "rgba(255,59,59,0.04)", border: "1px solid rgba(255,59,59,0.15)",
          borderRadius: 6, padding: "12px 16px", minWidth: 150,
        }}>
          <div style={{ fontSize: 10, color: "#888", marginBottom: 4 }}>SCA FAILURES</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: "#ff3b3b", fontFamily: "monospace" }}>
            {sca.failed ?? "—"}
          </div>
          <div style={{ fontSize: 10, color: "#888" }}>{sca.total} total checks</div>
        </div>
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 20 }}>
        {FRAMEWORKS.map(fw => {
          const hasGap = (sca.failed || 0) > 0;
          return (
            <div key={fw.key} style={{
              background: hasGap ? `${fw.color}12` : "rgba(255,255,255,0.02)",
              border: `1px solid ${hasGap ? fw.color + "40" : "rgba(255,255,255,0.08)"}`,
              borderRadius: 5, padding: "6px 12px",
            }}>
              <span style={{ color: hasGap ? fw.color : "#888", fontSize: 11 }}>{fw.label}</span>
              {hasGap && <span style={{ fontSize: 9, color: fw.color, marginLeft: 5 }}>⚠ gaps</span>}
            </div>
          );
        })}
      </div>

      {scaFailures.length > 0 && (
        <div>
          <div style={{ fontSize: 10, color: "#888", letterSpacing: "0.8px", marginBottom: 8 }}>
            RECENT SCA FAILURES — click a row to set status or analyze with AI
          </div>
          <div style={{ background: "rgba(255,255,255,0.02)", borderRadius: 6, overflow: "hidden" }}>
            <div style={{
              display: "grid", gridTemplateColumns: "1fr 90px",
              padding: "6px 12px", fontSize: 10, color: "#888",
              background: "rgba(255,255,255,0.03)", borderBottom: "1px solid rgba(255,255,255,0.06)",
            }}>
              <div>CHECK</div><div>STATUS</div>
            </div>
            {scaFailures.map((f, i) => {
              // Use title-based key (stable across reloads) instead of index+title
              const key = f.title ? f.title.slice(0, 100) : String(i);
              const isOpen = selectedIdx === i;
              const curStatus = statusMap[key];
              return (
                <div key={i} style={{ borderBottom: "1px solid rgba(255,59,59,0.08)" }}>
                  <div
                    onClick={() => setSelected(isOpen ? null : i)}
                    style={{
                      display: "grid", gridTemplateColumns: "1fr 90px",
                      padding: "8px 12px", cursor: "pointer",
                      background: isOpen ? "rgba(255,59,59,0.06)" : "transparent",
                    }}>
                    <div>
                      <div style={{ fontSize: 12, color: "#e8eaed", marginBottom: 2 }}>{f.title || "Unknown check"}</div>
                      {f.rationale && <div style={{ fontSize: 10, color: "#888" }}>{f.rationale}</div>}
                    </div>
                    <span style={{ fontSize: 10, color: curStatus ? STATUS_COLORS[curStatus] : "#444", alignSelf: "center" }}>
                      {curStatus ? STATUS_LABELS[curStatus] : "—"}
                    </span>
                  </div>
                  {isOpen && (
                    <EnrichmentPanel
                      agentId={agentId} hostName={hostName}
                      itemType="compliance" itemKey={key}
                      item={{ ...f, framework: f.policy_id, requirement: f.title, result: "failed", description: f.rationale }}
                      onClose={() => setSelected(null)}
                      initialStatus={statusMap[key]}
                      onStatusChange={s => setStatusMap(prev => ({ ...prev, [key]: s }))}
                      cachedResult={enrichCache[key] || null}
                      onEnrichResult={r => setEnrichCache(prev => ({ ...prev, [key]: r }))}
                    />
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Panel ────────────────────────────────────────────────────────────────

export function HostDetailPanel({ agentId, onClose }) {
  const [detail, setDetail]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [activeTab, setTab]   = useState("Overview");

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(`${API}/hosts/${agentId}`, { credentials: "include" })
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(d => { setDetail(d); setLoading(false); })
      .catch(e => { setError(e.message); setLoading(false); });
  }, [agentId]);

  const grade    = detail?.posture?.grade || "—";
  const gradeCol = GRADE_COLOR[grade] || "#888";
  const hostName = detail?.agent_name || agentId;

  return (
    <div
      onClick={e => e.target === e.currentTarget && onClose()}
      style={{
        position: "fixed", inset: 0, zIndex: 900,
        background: "rgba(0,0,0,0.75)", display: "flex", justifyContent: "flex-end",
      }}>
      <div style={{
        width: "min(920px, 96vw)", height: "100vh", overflowY: "auto",
        background: "#0d1117", borderLeft: "1px solid rgba(255,255,255,0.08)",
        display: "flex", flexDirection: "column", fontFamily: "monospace",
      }}>
        {/* Header */}
        <div style={{
          padding: "16px 20px 12px", borderBottom: "1px solid rgba(255,255,255,0.08)",
          display: "flex", alignItems: "flex-start", gap: 12,
        }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 10, color: "#888", letterSpacing: "1.5px", marginBottom: 3 }}>HOST SECURITY PROFILE</div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <h3 style={{ margin: 0, fontSize: 17, color: "#e8eaed", fontWeight: 600 }}>{hostName}</h3>
              {detail && (
                <>
                  <span style={{ fontSize: 11, color: "#888" }}>{detail.agent_ip || "—"}</span>
                  <span style={{ fontSize: 11, color: "#888" }}>{detail.os_platform || "—"} {detail.os_version || ""}</span>
                  <span style={{
                    fontSize: 9, padding: "2px 6px", borderRadius: 3,
                    background: detail.wazuh_status === "active" ? "rgba(0,229,160,0.1)" : "rgba(255,140,0,0.1)",
                    color: detail.wazuh_status === "active" ? "#00e5a0" : "#ff8c00",
                  }}>{(detail.wazuh_status || "unknown").toUpperCase()}</span>
                </>
              )}
            </div>
            {detail && (
              <div style={{ marginTop: 6, display: "flex", gap: 8, alignItems: "center" }}>
                <span style={{ fontSize: 10, color: "#888" }}>Posture:</span>
                <span style={{ fontFamily: "monospace", fontWeight: 700, color: gradeCol }}>
                  {detail.posture?.score?.toFixed(1) ?? "—"}
                </span>
                <span style={{
                  display: "inline-flex", alignItems: "center", justifyContent: "center",
                  width: 24, height: 24, borderRadius: 3,
                  background: `${gradeCol}18`, border: `1px solid ${gradeCol}55`,
                  color: gradeCol, fontWeight: 700, fontSize: 11,
                }}>{grade}</span>
                <span style={{ fontSize: 10, color: "#888" }}>SIEM Risk: {detail.siem?.risk_score?.toFixed(0) ?? "—"}/100</span>
                <span style={{ fontSize: 10, color: "#888" }}>ID: {agentId}</span>
              </div>
            )}
          </div>
          <button
            onClick={onClose}
            style={{
              background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.12)",
              color: "#888", width: 28, height: 28, borderRadius: 4,
              cursor: "pointer", fontSize: 14, display: "flex", alignItems: "center", justifyContent: "center",
            }}>×</button>
        </div>

        {/* Tabs */}
        <div style={{
          display: "flex", gap: 2, padding: "8px 20px 0",
          borderBottom: "1px solid rgba(255,255,255,0.08)", overflowX: "auto",
        }}>
          {TABS.map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              background: activeTab === t ? "rgba(0,229,160,0.08)" : "transparent",
              border: "none",
              borderBottom: activeTab === t ? "2px solid #00e5a0" : "2px solid transparent",
              color: activeTab === t ? "#00e5a0" : "#888",
              padding: "6px 14px", cursor: "pointer", fontSize: 11, fontFamily: "monospace",
              whiteSpace: "nowrap", transition: "color 0.15s",
            }}>{t}</button>
          ))}
        </div>

        {/* Content */}
        <div style={{ flex: 1, padding: "18px 20px", overflowY: "auto" }}>
          {loading && <div style={{ padding: 40, textAlign: "center", color: "#888" }}>Loading host profile…</div>}
          {error && (
            <div style={{
              background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.3)",
              borderRadius: 6, padding: "12px 16px", color: "#ff6b6b",
            }}>{error}</div>
          )}
          {detail && !loading && (
            <>
              {activeTab === "Overview"        && <OverviewTab detail={detail} />}
              {activeTab === "Inventory"       && <InventoryTab agentId={agentId} />}
              {activeTab === "SCA"             && <SCATab agentId={agentId} hostName={hostName} />}
              {activeTab === "Vulnerabilities" && <VulnerabilitiesTab agentId={agentId} hostName={hostName} />}
              {activeTab === "FIM"             && <AlertsTab agentId={agentId} hostName={hostName} category="fim"     label="FIM" />}
              {activeTab === "Malware"         && <AlertsTab agentId={agentId} hostName={hostName} category="malware" label="Malware" />}
              {activeTab === "MITRE"           && <MitreTab detail={detail} agentId={agentId} hostName={hostName} />}
              {activeTab === "Compliance"      && <ComplianceTab detail={detail} agentId={agentId} hostName={hostName} />}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
