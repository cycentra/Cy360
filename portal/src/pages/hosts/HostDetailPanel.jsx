/**
 * HostDetailPanel.jsx
 * Full-screen overlay with 7-tab security profile for a single host.
 * Tabs: Overview · SCA · Vulnerabilities · FIM · Malware · MITRE · Compliance
 *
 * Each tab supports click-to-enrich: clicking any row opens an AI + MISP
 * enrichment panel with explanation, remediation steps, and a Raise Ticket button.
 */

import { useState, useEffect } from "react";

const API = "/api/siem";

const GRADE_COLOR = {
  "A+": "#00e5a0", A: "#00e5a0", B: "#4d9eff",
  C: "#ff8c00", D: "#ff3b3b", F: "#ff3b3b", "—": "#888",
};
const SEV_COLOR = {
  Critical: "#ff3b3b", High: "#ff8c00", Medium: "#ffcc00", Low: "#4d9eff",
  critical: "#ff3b3b", high: "#ff8c00", medium: "#ffcc00", low: "#4d9eff",
};
const TABS = ["Overview", "SCA", "Vulnerabilities", "FIM", "Malware", "MITRE", "Compliance"];

// ── Sub-components ────────────────────────────────────────────────────────────

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
// Inline AI + MISP enrichment shown when a row is clicked.

function EnrichmentPanel({ agentId, hostName, itemType, item, onClose }) {
  const [loading, setLoading]     = useState(true);
  const [result, setResult]       = useState(null);
  const [error, setError]         = useState(null);
  const [ticketStatus, setTicket] = useState(null); // null | "loading" | {case_id,case_url} | "error"
  const [localStatus, setStatus]  = useState(item._localStatus || null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    setResult(null);
    fetch(`${API}/hosts/${agentId}/enrich`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ item_type: itemType, item, host_name: hostName }),
    })
      .then(r => r.json())
      .then(d => { setResult(d); setLoading(false); })
      .catch(e => { setError(e.message); setLoading(false); });
  }, [agentId, itemType, JSON.stringify(item)]);

  function raiseTicket() {
    if (!result) return;
    setTicket("loading");
    fetch(`${API}/hosts/${agentId}/raise-ticket`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        item_type: itemType, item, host_name: hostName,
        explanation: result.explanation, remediation: result.remediation,
      }),
    })
      .then(r => r.json())
      .then(d => setTicket(d.error ? "error" : d))
      .catch(() => setTicket("error"));
  }

  const remLines = (result?.remediation || "")
    .split("\n")
    .map(l => l.replace(/^\s*\d+[\.\)]\s*/, "").trim())
    .filter(Boolean);

  return (
    <div style={{
      margin: "0 -12px",
      borderTop: "1px solid rgba(0,229,160,0.2)",
      borderBottom: "1px solid rgba(0,229,160,0.2)",
      background: "rgba(0,229,160,0.03)",
      padding: "14px 16px",
    }}>
      {/* Header row */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
        <span style={{ fontSize: 10, color: "#00e5a0", letterSpacing: "1px", fontFamily: "monospace" }}>
          AI + THREAT INTEL ENRICHMENT
        </span>
        <button
          onClick={onClose}
          style={{ background: "none", border: "none", color: "#555", cursor: "pointer", fontSize: 14 }}>✕</button>
      </div>

      {loading && (
        <div style={{ color: "#888", fontSize: 11, padding: "8px 0" }}>Fetching AI analysis…</div>
      )}

      {error && (
        <div style={{ color: "#ff6b6b", fontSize: 11 }}>Failed to load enrichment: {error}</div>
      )}

      {result && !loading && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {/* AI Explanation */}
          {result.explanation ? (
            <div>
              <div style={{ fontSize: 10, color: "#888", letterSpacing: "0.8px", marginBottom: 6 }}>ANALYST BRIEFING</div>
              <div style={{ fontSize: 12, color: "#e8eaed", lineHeight: 1.6 }}>{result.explanation}</div>
            </div>
          ) : (
            <div style={{ fontSize: 11, color: "#555" }}>
              AI not configured — enable an AI provider in System Settings → AI Config.
            </div>
          )}

          {/* Remediation Steps */}
          {remLines.length > 0 && (
            <div>
              <div style={{ fontSize: 10, color: "#888", letterSpacing: "0.8px", marginBottom: 6 }}>REMEDIATION STEPS</div>
              <ol style={{ margin: 0, paddingLeft: 18, color: "#e8eaed", fontSize: 12, lineHeight: 1.7 }}>
                {remLines.map((step, i) => <li key={i}>{step}</li>)}
              </ol>
            </div>
          )}

          {/* MISP Hits */}
          {result.misp_hits?.length > 0 && (
            <div>
              <div style={{ fontSize: 10, color: "#ff8c00", letterSpacing: "0.8px", marginBottom: 6 }}>
                ⚠ MISP THREAT INTELLIGENCE ({result.misp_hits.length} match{result.misp_hits.length > 1 ? "es" : ""})
              </div>
              {result.misp_hits.map((hit, i) => (
                <div key={i} style={{
                  background: "rgba(255,140,0,0.07)", border: "1px solid rgba(255,140,0,0.2)",
                  borderRadius: 4, padding: "6px 10px", marginBottom: 5, fontSize: 11,
                }}>
                  <span style={{ color: "#ff8c00", fontFamily: "monospace" }}>{hit.ioc}</span>
                  <span style={{ color: "#888", marginLeft: 8 }}>[{hit.type}]</span>
                  {hit.comment && <span style={{ color: "#888", marginLeft: 8 }}>{hit.comment}</span>}
                  <Pill label={`Event #${hit.event_id}`} color="#ff8c00" />
                </div>
              ))}
            </div>
          )}

          {/* Actions row */}
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", paddingTop: 6, borderTop: "1px solid rgba(255,255,255,0.06)" }}>
            {/* Status buttons */}
            <div style={{ fontSize: 10, color: "#888", marginRight: 2 }}>Status:</div>
            {["investigating", "in_review", "resolved", "false_positive"].map(s => (
              <button
                key={s}
                onClick={() => setStatus(s)}
                style={{
                  padding: "4px 10px", borderRadius: 3, cursor: "pointer", fontSize: 10,
                  fontFamily: "monospace", textTransform: "uppercase",
                  background: localStatus === s ? "rgba(0,229,160,0.12)" : "rgba(255,255,255,0.04)",
                  border: localStatus === s ? "1px solid rgba(0,229,160,0.4)" : "1px solid rgba(255,255,255,0.1)",
                  color: localStatus === s ? "#00e5a0" : "#888",
                }}>
                {s.replace("_", " ")}
              </button>
            ))}

            {/* Raise Ticket button */}
            <button
              onClick={raiseTicket}
              disabled={ticketStatus === "loading" || (ticketStatus && ticketStatus !== "error")}
              style={{
                marginLeft: "auto", padding: "6px 14px", borderRadius: 4, cursor: "pointer",
                fontSize: 11, fontFamily: "monospace",
                background: ticketStatus && ticketStatus !== "error" && ticketStatus !== "loading"
                  ? "rgba(176,110,255,0.15)" : "rgba(77,158,255,0.1)",
                border: ticketStatus && ticketStatus !== "error" && ticketStatus !== "loading"
                  ? "1px solid rgba(176,110,255,0.4)" : "1px solid rgba(77,158,255,0.3)",
                color: ticketStatus && ticketStatus !== "error" && ticketStatus !== "loading"
                  ? "#b06eff" : "#4d9eff",
              }}>
              {ticketStatus === "loading" ? "Creating…"
                : ticketStatus === "error" ? "⚠ Ticket Failed"
                : ticketStatus?.case_id ? `✓ IRIS #${ticketStatus.case_id}`
                : "↗ Raise Ticket"}
            </button>

            {ticketStatus?.case_url && ticketStatus.case_url !== "error" && (
              <a
                href={ticketStatus.case_url} target="_blank" rel="noopener noreferrer"
                style={{ fontSize: 10, color: "#b06eff", textDecoration: "underline" }}>
                Open in CyIRIS →
              </a>
            )}
          </div>
        </div>
      )}
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
      {/* Posture score cards */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 20 }}>
        <StatCard
          label="Posture Score"
          value={posture.score?.toFixed(0)}
          sub={`Grade ${posture.grade || "—"}`}
          color={GRADE_COLOR[posture.grade] || "#888"}
          wide
        />
        <StatCard label="SCA Pass Rate" value={sca.score?.toFixed(0)} sub={`${sca.passed}/${sca.total} checks`} color="#00e5a0" />
        <StatCard label="Critical CVEs"  value={vulnerabilities.critical} sub={`${vulnerabilities.high} High`} color="#ff3b3b" />
        <StatCard label="SIEM Risk"       value={siem.risk_score?.toFixed(0)} sub="/100" color={siem.risk_score > 70 ? "#ff3b3b" : "#ff8c00"} />
        <StatCard label="Open Incidents"  value={siem.incident_count} color={siem.incident_count > 0 ? "#ff8c00" : "#888"} />
      </div>

      {/* Posture component breakdown */}
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

      {/* MITRE techniques */}
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

      {/* Active incidents */}
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
              {inc.iris_case_id && <Pill label={`IRIS #${inc.iris_case_id}`} color="#b06eff" />}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Tab: SCA ──────────────────────────────────────────────────────────────────

function SCATab({ agentId, hostName }) {
  const [data, setData]           = useState(null);
  const [loading, setLoading]     = useState(true);
  const [filter, setFilter]       = useState("failed");
  const [page, setPage]           = useState(1);
  const [selectedId, setSelected] = useState(null);
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

  if (loading) return <div style={{ padding: 30, color: "#888", textAlign: "center" }}>Loading SCA data…</div>;
  if (!data)   return <div style={{ padding: 30, color: "#ff6b6b" }}>Failed to load SCA data.</div>;

  const policies = data.policies || [];
  const checks   = data.checks   || [];
  const total    = data.total    || 0;

  return (
    <div>
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

      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        {["all", "failed", "passed", "not applicable"].map(f => (
          <button
            key={f}
            onClick={() => { setFilter(f); setPage(1); }}
            style={{
              background: filter === f ? "rgba(0,229,160,0.1)" : "rgba(255,255,255,0.04)",
              border: filter === f ? "1px solid rgba(0,229,160,0.4)" : "1px solid rgba(255,255,255,0.1)",
              color: filter === f ? "#00e5a0" : "#888",
              padding: "4px 10px", borderRadius: 4, fontSize: 11, cursor: "pointer",
            }}>
            {f === "all" ? "All" : f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
        <span style={{ marginLeft: "auto", fontSize: 11, color: "#888", padding: "4px 0" }}>{total} checks</span>
      </div>

      <div style={{ background: "rgba(255,255,255,0.02)", borderRadius: 6, overflow: "hidden" }}>
        <div style={{
          display: "grid", gridTemplateColumns: "60px 1fr 100px",
          padding: "6px 12px", fontSize: 10, color: "#888",
          background: "rgba(255,255,255,0.03)", borderBottom: "1px solid rgba(255,255,255,0.06)",
        }}>
          <div>ID</div><div>CHECK</div><div>RESULT</div>
        </div>
        {checks.length === 0
          ? <div style={{ padding: 20, color: "#888", textAlign: "center", fontSize: 12 }}>No checks found.</div>
          : checks.map(c => {
            const resultCol = c.result === "passed" ? "#00e5a0" : c.result === "failed" ? "#ff3b3b" : "#888";
            const isOpen = selectedId === c.id;
            return (
              <div key={c.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <div
                  onClick={() => setSelected(isOpen ? null : c.id)}
                  style={{
                    display: "grid", gridTemplateColumns: "60px 1fr 100px",
                    padding: "8px 12px", cursor: "pointer", fontSize: 12,
                    background: isOpen ? "rgba(0,229,160,0.04)" : "transparent",
                  }}>
                  <span style={{ color: "#888", fontFamily: "monospace" }}>{c.id}</span>
                  <span style={{ color: "#e8eaed" }}>{c.title}</span>
                  <span style={{ color: resultCol, textTransform: "uppercase", fontSize: 10 }}>{c.result}</span>
                </div>
                {isOpen && (
                  <EnrichmentPanel
                    agentId={agentId} hostName={hostName}
                    itemType="sca" item={c}
                    onClose={() => setSelected(null)}
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
  const [data, setData]           = useState(null);
  const [loading, setLoading]     = useState(true);
  const [sevFilter, setSev]       = useState("");
  const [page, setPage]           = useState(1);
  const [selectedIdx, setSelected] = useState(null);
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

  if (loading) return <div style={{ padding: 30, color: "#888", textAlign: "center" }}>Loading vulnerabilities…</div>;
  if (!data)   return <div style={{ padding: 30, color: "#ff6b6b" }}>Failed to load vulnerabilities.</div>;

  const vulns = data.vulnerabilities || [];
  const total  = data.total || 0;

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
          display: "grid", gridTemplateColumns: "160px 60px 140px 1fr",
          padding: "6px 12px", fontSize: 10, color: "#888",
          background: "rgba(255,255,255,0.03)", borderBottom: "1px solid rgba(255,255,255,0.06)",
        }}>
          <div>CVE</div><div>CVSS</div><div>PACKAGE</div><div>DESCRIPTION</div>
        </div>
        {vulns.length === 0
          ? <div style={{ padding: 20, color: "#888", textAlign: "center" }}>No active CVEs found.</div>
          : vulns.map((v, i) => {
            const col   = SEV_COLOR[v.severity] || "#888";
            const isOpen = selectedIdx === i;
            return (
              <div key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <div
                  onClick={() => setSelected(isOpen ? null : i)}
                  style={{
                    display: "grid", gridTemplateColumns: "160px 60px 140px 1fr",
                    padding: "8px 12px", fontSize: 11, alignItems: "start",
                    cursor: "pointer",
                    background: isOpen ? "rgba(255,140,0,0.04)" : "transparent",
                  }}>
                  <span style={{ color: col, fontFamily: "monospace" }}>{v.cve || "—"}</span>
                  <span style={{ color: col }}>{v.cvss || "—"}</span>
                  <span style={{ color: "#e8eaed" }}>{v.name || "—"} {v.version || ""}</span>
                  <span style={{ color: "#888" }}>{v.title || v.condition || "—"}</span>
                </div>
                {isOpen && (
                  <EnrichmentPanel
                    agentId={agentId} hostName={hostName}
                    itemType="vulnerability"
                    item={{ ...v, package_name: v.name, package_version: v.version, cvss3_score: v.cvss }}
                    onClose={() => setSelected(null)}
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

// ── Tab: Alerts (generic, used for FIM and Malware) ───────────────────────────

function AlertsTab({ agentId, hostName, category, label }) {
  const [data, setData]            = useState(null);
  const [loading, setLoading]      = useState(true);
  const [page, setPage]            = useState(1);
  const [selectedIdx, setSelected] = useState(null);
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
          display: "grid", gridTemplateColumns: "140px 50px 1fr 120px",
          padding: "6px 12px", fontSize: 10, color: "#888",
          background: "rgba(255,255,255,0.03)", borderBottom: "1px solid rgba(255,255,255,0.06)",
        }}>
          <div>TIMESTAMP</div><div>LEVEL</div><div>DESCRIPTION</div><div>FILE / USER</div>
        </div>
        {alerts.length === 0
          ? <div style={{ padding: 20, color: "#888", textAlign: "center" }}>No {label} events in last 30 days.</div>
          : alerts.map((a, i) => {
            const ts  = a.timestamp ? new Date(a.timestamp).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";
            const col = a.rule_level >= 12 ? "#ff3b3b" : a.rule_level >= 7 ? "#ff8c00" : "#888";
            const isOpen = selectedIdx === i;
            return (
              <div key={a.id || i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <div
                  onClick={() => setSelected(isOpen ? null : i)}
                  style={{
                    display: "grid", gridTemplateColumns: "140px 50px 1fr 120px",
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
                </div>
                {isOpen && (
                  <EnrichmentPanel
                    agentId={agentId} hostName={hostName}
                    itemType="alert"
                    item={{ ...a, rule_description: a.rule_desc, description: a.rule_desc }}
                    onClose={() => setSelected(null)}
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

// ── Tab: MITRE ────────────────────────────────────────────────────────────────

function MitreTab({ detail, agentId, hostName }) {
  const { mitre = {}, alerts_by_category = {} } = detail;
  const breakdown = mitre.breakdown || [];
  const [selectedId, setSelected] = useState(null);

  return (
    <div>
      <div style={{ fontSize: 10, color: "#888", letterSpacing: "0.8px", marginBottom: 12 }}>
        TECHNIQUES OBSERVED ON THIS HOST (LAST 30 DAYS)
      </div>
      {breakdown.length === 0 ? (
        <div style={{ color: "#888", textAlign: "center", padding: 30 }}>No MITRE techniques observed.</div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
          {breakdown.map(t => {
            const isOpen = selectedId === t.mitre_id;
            return (
              <div key={t.mitre_id} style={{ borderBottom: "1px solid rgba(77,158,255,0.08)" }}>
                <div
                  onClick={() => setSelected(isOpen ? null : t.mitre_id)}
                  style={{
                    display: "flex", alignItems: "center", gap: 12,
                    background: isOpen ? "rgba(77,158,255,0.08)" : "rgba(77,158,255,0.04)",
                    padding: "8px 14px", cursor: "pointer",
                  }}>
                  <span style={{ color: "#4d9eff", fontFamily: "monospace", fontWeight: 700, width: 90, flexShrink: 0 }}>{t.mitre_id}</span>
                  <span style={{ color: "#888", fontSize: 11, flex: 1 }}>{t.tactic || "—"}</span>
                  <span style={{
                    background: "rgba(77,158,255,0.12)", color: "#4d9eff",
                    fontFamily: "monospace", fontSize: 11, padding: "2px 8px", borderRadius: 3,
                  }}>×{t.count}</span>
                </div>
                {isOpen && (
                  <EnrichmentPanel
                    agentId={agentId} hostName={hostName}
                    itemType="mitre"
                    item={{ technique: t.mitre_id, tactic: t.tactic, count: t.count }}
                    onClose={() => setSelected(null)}
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
  const [selectedIdx, setSelected] = useState(null);

  const FRAMEWORKS = [
    { key: "pci_dss",  label: "PCI DSS",    color: "#ff8c00" },
    { key: "gdpr",     label: "GDPR",       color: "#4d9eff" },
    { key: "hipaa",    label: "HIPAA",      color: "#b06eff" },
    { key: "nist_csf", label: "NIST CSF",   color: "#00e5a0" },
    { key: "tsc",      label: "TSC / SOC 2",color: "#ffcc00" },
    { key: "iso27001", label: "ISO 27001",  color: "#ff8c00" },
    { key: "nis2",     label: "NIS2",       color: "#4d9eff" },
  ];

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
          <div style={{ fontSize: 10, color: "#888" }}>based on SCA pass rate</div>
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

      <div style={{
        background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
        borderRadius: 6, padding: "10px 14px", marginBottom: 20,
        fontSize: 11, color: "#888",
      }}>
        <span style={{ color: "#e8eaed" }}>Compliance impact:</span>{" "}
        SCA failures on this host map to controls across{" "}
        <span style={{ color: "#00e5a0" }}>PCI DSS Req 2.2</span>,{" "}
        <span style={{ color: "#b06eff" }}>HIPAA §164.312</span>,{" "}
        <span style={{ color: "#4d9eff" }}>NIST CM-6/CM-7</span>,{" "}
        and <span style={{ color: "#ffcc00" }}>TSC CC7.1/CC8.1</span>.
        MITRE techniques observed also contribute to framework control coverage gaps.
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 20 }}>
        {FRAMEWORKS.map(fw => {
          const hasGap = (sca.failed || 0) > 0 || (mitre.techniques || []).length > 0;
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
            RECENT SCA FAILURES (LAST 7 DAYS) — click any row for AI analysis
          </div>
          {scaFailures.map((f, i) => {
            const isOpen = selectedIdx === i;
            return (
              <div key={i} style={{ marginBottom: 6 }}>
                <div
                  onClick={() => setSelected(isOpen ? null : i)}
                  style={{
                    background: isOpen ? "rgba(255,59,59,0.08)" : "rgba(255,59,59,0.04)",
                    border: "1px solid rgba(255,59,59,0.12)",
                    borderRadius: isOpen ? "4px 4px 0 0" : 4,
                    padding: "8px 12px", cursor: "pointer",
                  }}>
                  <div style={{ fontSize: 12, color: "#e8eaed", marginBottom: 3 }}>{f.title || "Unknown check"}</div>
                  {f.rationale && <div style={{ fontSize: 10, color: "#888" }}>{f.rationale}</div>}
                  <div style={{ fontSize: 9, color: "#555", marginTop: 3 }}>
                    Policy: {f.policy_id || "—"} · {f.timestamp ? new Date(f.timestamp).toLocaleDateString() : "—"}
                  </div>
                </div>
                {isOpen && (
                  <div style={{ border: "1px solid rgba(255,59,59,0.12)", borderTop: "none", borderRadius: "0 0 4px 4px" }}>
                    <EnrichmentPanel
                      agentId={agentId} hostName={hostName}
                      itemType="compliance"
                      item={{ ...f, framework: f.policy_id, requirement: f.title, result: "failed", description: f.rationale }}
                      onClose={() => setSelected(null)}
                    />
                  </div>
                )}
              </div>
            );
          })}
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
    /* Backdrop */
    <div
      onClick={e => e.target === e.currentTarget && onClose()}
      style={{
        position: "fixed", inset: 0, zIndex: 900,
        background: "rgba(0,0,0,0.75)", display: "flex", justifyContent: "flex-end",
      }}>
      {/* Panel */}
      <div style={{
        width: "min(900px, 95vw)", height: "100vh", overflowY: "auto",
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
              <h3 style={{ margin: 0, fontSize: 17, color: "#e8eaed", fontWeight: 600 }}>
                {hostName}
              </h3>
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
            <button
              key={t}
              onClick={() => setTab(t)}
              style={{
                background: activeTab === t ? "rgba(0,229,160,0.08)" : "transparent",
                border: "none", borderBottom: activeTab === t ? "2px solid #00e5a0" : "2px solid transparent",
                color: activeTab === t ? "#00e5a0" : "#888",
                padding: "6px 14px", cursor: "pointer", fontSize: 11, fontFamily: "monospace",
                whiteSpace: "nowrap", transition: "color 0.15s",
              }}>
              {t}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div style={{ flex: 1, padding: "18px 20px", overflowY: "auto" }}>
          {loading && (
            <div style={{ padding: 40, textAlign: "center", color: "#888" }}>Loading host profile…</div>
          )}
          {error && (
            <div style={{
              background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.3)",
              borderRadius: 6, padding: "12px 16px", color: "#ff6b6b",
            }}>{error}</div>
          )}
          {detail && !loading && (
            <>
              {activeTab === "Overview"        && <OverviewTab detail={detail} />}
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
