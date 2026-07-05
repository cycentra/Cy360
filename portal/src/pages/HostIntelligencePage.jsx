/**
 * HostIntelligencePage.jsx
 * Merged "Host Inventory" + "Entity Risk" page.
 *
 * Top section: summary charts — grade donut, posture components, risk histogram.
 * Tab 1 (Hosts):   posture table with SCA/vuln/incident columns → HostDetailPanel.
 * Tab 2 (Risk):    entity risk leaderboard (hosts + users) from /api/siem/risk-scores.
 *
 * All data that existed in the two separate pages is preserved here.
 */

import { useState, useEffect, useCallback } from "react";
import { HostDetailPanel } from "./hosts/HostDetailPanel.jsx";
import { AgentGroupsTab } from "./hosts/AgentGroupsTab.jsx";
import { EndpointPoliciesTab } from "./hosts/EndpointPoliciesTab.jsx";
import { SensorDeploymentTab } from "./hosts/SensorDeploymentTab.jsx";
import { siemApi, siemFetch } from "../siem/siemApi";

const API = "/api/siem";

// ── Shared colour maps ─────────────────────────────────────────────────────────
const GRADE_COLOR = {
  "A+": "#00e5a0", A: "#00e5a0", B: "#4d9eff",
  C: "#ff8c00", D: "#ff3b3b", F: "#ff3b3b", "—": "#666",
};
const STATUS_COLOR = {
  active: "#00e5a0", disconnected: "#ff8c00",
  never_connected: "#555", unknown: "#555",
};
const TIER_COLOR = { 1: "#ff3b3b", 2: "#ff8c00", 3: "#555" };

const RISK_THRESHOLDS = [
  { min: 75, label: "CRITICAL", color: "#ff3b3b", bg: "rgba(255,59,59,0.12)"  },
  { min: 50, label: "HIGH",     color: "#ff8c00", bg: "rgba(255,140,0,0.12)"  },
  { min: 25, label: "MEDIUM",   color: "#f5c518", bg: "rgba(245,197,24,0.12)" },
  { min: 0,  label: "LOW",      color: "#00e5a0", bg: "rgba(0,229,160,0.12)"  },
];
const riskLevel = score => RISK_THRESHOLDS.find(t => score >= t.min) || RISK_THRESHOLDS[3];

// ── Tiny shared components ─────────────────────────────────────────────────────
function GradeBadge({ grade, size = 26 }) {
  const color = GRADE_COLOR[grade] || "#666";
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", justifyContent: "center",
      width: size, height: size, borderRadius: 4,
      background: `${color}18`, border: `1px solid ${color}44`,
      color, fontFamily: "monospace", fontWeight: 700, fontSize: size * 0.44,
    }}>{grade || "—"}</span>
  );
}

function Bar({ pct, color = "#4d9eff", h = 5 }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.06)", borderRadius: 2, height: h, overflow: "hidden" }}>
      <div style={{ width: `${Math.max(0, Math.min(100, pct || 0))}%`, height: "100%",
        background: color, transition: "width .4s" }} />
    </div>
  );
}

// ── SVG Donut chart ────────────────────────────────────────────────────────────
function DonutChart({ segments, size = 88, stroke = 18 }) {
  const cx = size / 2, cy = size / 2, r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const total = segments.reduce((s, g) => s + g.value, 0);
  if (!total) return (
    <svg width={size} height={size}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth={stroke} />
    </svg>
  );
  let offset = 0;
  return (
    <svg width={size} height={size}>
      {segments.map((seg, i) => {
        const pct = seg.value / total;
        const dash = `${pct * circ} ${circ}`;
        const rotate = `rotate(${offset * 360 - 90} ${cx} ${cy})`;
        offset += pct;
        return (
          <circle key={i} cx={cx} cy={cy} r={r} fill="none"
            stroke={seg.color} strokeWidth={stroke}
            strokeDasharray={dash} strokeDashoffset={0}
            transform={rotate} opacity={0.88}
          >
            <title>{seg.label}: {seg.value}</title>
          </circle>
        );
      })}
    </svg>
  );
}

// ── Summary charts row ─────────────────────────────────────────────────────────
function SummaryCharts({ hosts, posture, riskScores }) {
  const gradeGroups = {};
  hosts.forEach(h => {
    const g = h.posture_grade || "—";
    gradeGroups[g] = (gradeGroups[g] || 0) + 1;
  });
  const donutSegs = ["A+", "A", "B", "C", "D", "F"].map(g => ({
    label: g, value: gradeGroups[g] || 0, color: GRADE_COLOR[g],
  })).filter(s => s.value > 0);

  const compList = posture?.components
    ? Object.entries(posture.components).map(([k, v]) => ({
        label: { sca: "SCA", vuln: "Vulns", siem_risk: "SIEM Risk",
                 fim_malware: "FIM/Malware", compliance: "Compliance" }[k] || k,
        score: v.score ?? 0,
        color: v.score >= 70 ? "#00e5a0" : v.score >= 50 ? "#ff8c00" : "#ff3b3b",
      }))
    : [];

  const riskBuckets = Array.from({ length: 10 }, (_, i) => ({
    label: `${i * 10}–${i * 10 + 9}`, min: i * 10, count: 0,
    color: i >= 7 ? "#ff3b3b" : i >= 5 ? "#ff8c00" : i >= 2 ? "#f5c518" : "#00e5a0",
  }));
  riskScores.forEach(e => { riskBuckets[Math.min(9, Math.floor(e.score / 10))].count++; });
  const maxBucket = Math.max(...riskBuckets.map(b => b.count), 1);

  const score = posture?.score;
  const grade = posture?.grade;
  const gradeColor = GRADE_COLOR[grade] || "#888";

  return (
    <div style={{ display: "grid", gridTemplateColumns: "220px 1fr 1fr", gap: 12, marginBottom: 20 }}>

      {/* Panel 1: Posture score + grade donut */}
      <div style={{
        background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
        borderRadius: 8, padding: "14px 16px",
      }}>
        <div style={{ color: "#888", fontSize: 9, letterSpacing: "1.5px", marginBottom: 10 }}>
          INTERNAL POSTURE
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{ position: "relative", flexShrink: 0 }}>
            <DonutChart segments={donutSegs} size={88} stroke={18} />
            <div style={{
              position: "absolute", top: "50%", left: "50%",
              transform: "translate(-50%,-50%)",
              textAlign: "center", lineHeight: 1.1,
            }}>
              <div style={{ color: gradeColor, fontSize: 18, fontWeight: 700, fontFamily: "monospace" }}>
                {score != null ? score.toFixed(0) : "—"}
              </div>
              <div style={{ color: gradeColor, fontSize: 11, fontWeight: 700 }}>{grade || "—"}</div>
            </div>
          </div>
          <div style={{ flex: 1 }}>
            {donutSegs.map(s => (
              <div key={s.label} style={{ display: "flex", justifyContent: "space-between",
                marginBottom: 3, fontSize: 10 }}>
                <span style={{ color: s.color }}>Grade {s.label}</span>
                <span style={{ color: "#888", fontFamily: "monospace" }}>{s.value}</span>
              </div>
            ))}
            <div style={{ marginTop: 6, fontSize: 10, color: "#666" }}>
              {posture?.host_count?.total ?? 0} hosts ·{" "}
              <span style={{ color: "#00e5a0" }}>{posture?.host_count?.active ?? 0} active</span>
            </div>
          </div>
        </div>
      </div>

      {/* Panel 2: Posture component bars */}
      <div style={{
        background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
        borderRadius: 8, padding: "14px 16px",
      }}>
        <div style={{ color: "#888", fontSize: 9, letterSpacing: "1.5px", marginBottom: 12 }}>
          POSTURE COMPONENTS
        </div>
        {compList.map(c => (
          <div key={c.label} style={{ marginBottom: 8 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
              <span style={{ fontSize: 10, color: "#aaa" }}>{c.label}</span>
              <span style={{ fontSize: 10, color: c.color, fontFamily: "monospace" }}>{c.score.toFixed(0)}</span>
            </div>
            <Bar pct={c.score} color={c.color} h={5} />
          </div>
        ))}
      </div>

      {/* Panel 3: Risk score histogram */}
      <div style={{
        background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
        borderRadius: 8, padding: "14px 16px",
      }}>
        <div style={{ color: "#888", fontSize: 9, letterSpacing: "1.5px", marginBottom: 12 }}>
          RISK SCORE DISTRIBUTION
        </div>
        {riskScores.length === 0 ? (
          <div style={{ color: "#444", fontSize: 11, paddingTop: 20 }}>No risk data yet.</div>
        ) : (
          <>
            <div style={{ display: "flex", alignItems: "flex-end", gap: 3, height: 68 }}>
              {riskBuckets.map((b, i) => (
                <div key={i} title={`${b.label}: ${b.count}`}
                  style={{ flex: 1, display: "flex", flexDirection: "column",
                    alignItems: "center", gap: 2 }}>
                  <div style={{
                    width: "100%",
                    height: `${Math.max(3, (b.count / maxBucket) * 54)}px`,
                    background: b.count > 0 ? b.color : "rgba(255,255,255,0.05)",
                    borderRadius: "2px 2px 0 0", opacity: 0.85,
                    transition: "height .4s",
                  }} />
                </div>
              ))}
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4 }}>
              {[0, 25, 50, 75, 100].map(v => (
                <span key={v} style={{ color: "rgba(255,255,255,0.2)", fontSize: 8,
                  fontFamily: "monospace" }}>{v}</span>
              ))}
            </div>
            <div style={{ display: "flex", gap: 10, marginTop: 8, flexWrap: "wrap" }}>
              {[
                { label: "Critical", min: 75, color: "#ff3b3b" },
                { label: "High",     min: 50, color: "#ff8c00" },
                { label: "Med",      min: 25, color: "#f5c518" },
                { label: "Low",      min: 0,  color: "#00e5a0" },
              ].map(t => {
                const n = riskScores.filter(e => e.score >= t.min &&
                  (t.min === 0 ? true : e.score < [75,50,25,0][["Critical","High","Med","Low"].indexOf(t.label) - 1] || t.min === 75)).length;
                const cnt = t.min === 75 ? riskScores.filter(e=>e.score>=75).length
                  : t.min === 50 ? riskScores.filter(e=>e.score>=50&&e.score<75).length
                  : t.min === 25 ? riskScores.filter(e=>e.score>=25&&e.score<50).length
                  : riskScores.filter(e=>e.score<25).length;
                return (
                  <div key={t.label} style={{ fontSize: 9, color: "#888" }}>
                    <span style={{ color: t.color, fontFamily: "monospace",
                      fontWeight: 700 }}>{cnt}</span>{" "}{t.label}
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ── HOST POSTURE TABLE (tab 1) ─────────────────────────────────────────────────
function HostsTab({ hosts, loading, error, posture, onRefresh, refreshing, seeding,
                    statusFilter, setStatusFilter, sortBy, setSortBy,
                    search, setSearch, page, setPage, total, onSelectHost, onRemoveHost }) {
  const PER_PAGE = 50;
  const [removing, setRemoving] = useState(null);
  const filtered = search
    ? hosts.filter(h =>
        (h.agent_name || "").toLowerCase().includes(search.toLowerCase()) ||
        (h.agent_ip || "").includes(search)
      )
    : hosts;

  const handleRemove = async (e, host) => {
    e.stopPropagation();
    const isActive = host.wazuh_status === "active";
    const msg = isActive
      ? `FORCE REMOVE active agent "${host.agent_name || host.agent_id}"?\n\nThis will:\n• Immediately disconnect the agent\n• Delete it from Wazuh permanently\n• Purge its posture data\n\nUse this only for rogue or decommissioned endpoints. Cannot be undone.`
      : `Remove "${host.agent_name || host.agent_id}" from Wazuh and posture cache?\n\nThis cannot be undone.`;
    if (!window.confirm(msg)) return;
    setRemoving(host.agent_id);
    await onRemoveHost(host.agent_id);
    setRemoving(null);
  };

  return (
    <div>
      {/* Toolbar */}
      <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap", alignItems: "center" }}>
        <input
          placeholder="Search hostname or IP…"
          value={search} onChange={e => setSearch(e.target.value)}
          style={{
            background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
            color: "#e8eaed", padding: "5px 10px", borderRadius: 4,
            fontSize: 11, fontFamily: "monospace", width: 200,
          }}
        />
        <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
          style={{ background: "#13161d", border: "1px solid rgba(255,255,255,0.12)",
            color: "#e8eaed", padding: "5px 8px", borderRadius: 4, fontSize: 11 }}>
          <option value="all">All Statuses</option>
          <option value="active">Active</option>
          <option value="disconnected">Disconnected</option>
        </select>
        <select value={sortBy} onChange={e => { setSortBy(e.target.value); setPage(1); }}
          style={{ background: "#13161d", border: "1px solid rgba(255,255,255,0.12)",
            color: "#e8eaed", padding: "5px 8px", borderRadius: 4, fontSize: 11 }}>
          <option value="posture_score">Sort: Posture ↑</option>
          <option value="risk">Sort: Risk ↓</option>
          <option value="name">Sort: Name</option>
        </select>
        <button onClick={onRefresh} disabled={refreshing}
          style={{
            background: "rgba(0,229,160,0.08)", border: "1px solid rgba(0,229,160,0.25)",
            color: "#00e5a0", padding: "5px 12px", borderRadius: 4,
            fontFamily: "monospace", fontSize: 10, cursor: refreshing ? "not-allowed" : "pointer",
            opacity: refreshing ? 0.5 : 1,
          }}>
          {refreshing ? "Refreshing…" : "↻ Refresh Posture"}
        </button>
      </div>

      {error && (
        <div style={{
          background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.3)",
          borderRadius: 6, padding: "10px 14px", marginBottom: 12,
          color: "#ff6b6b", fontSize: 12,
        }}>{error}</div>
      )}

      <div style={{
        background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
        borderRadius: 8, overflow: "hidden",
      }}>
        <div style={{
          display: "grid",
          gridTemplateColumns: "28px 1fr 90px 56px 76px 60px 76px 96px 32px",
          gap: 8, padding: "8px 14px",
          background: "rgba(255,255,255,0.03)",
          borderBottom: "1px solid rgba(255,255,255,0.06)",
          fontSize: 10, color: "#666", letterSpacing: "0.8px",
        }}>
          <div />
          <div>HOST</div><div>POSTURE</div><div>GRADE</div>
          <div>RISK</div><div>VULNS</div><div>INCIDENTS</div><div>LAST SEEN</div><div />
        </div>

        {loading ? (
          <div style={{ padding: "40px 20px", textAlign: "center", color: "#666", fontSize: 12 }}>
            Loading hosts…
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: "40px 20px", textAlign: "center", color: "#666", fontSize: 12 }}>
            {search ? "No hosts match your search." : seeding ? (
              <span style={{ color: "#f5c518", fontFamily: "monospace" }}>
                ⏳ Populating host posture cache — this runs automatically and takes up to 60 s on first load. Checking every 8 s…
              </span>
            ) : "No hosts found — posture cache is empty. Click ↻ Refresh Posture to populate it."}
          </div>
        ) : (
          filtered.map(host => {
            const grade = host.posture_grade || "—";
            const gradeCol = GRADE_COLOR[grade] || "#666";
            const statusCol = STATUS_COLOR[host.wazuh_status] || "#555";
            const critVulns = (host.vuln_critical || 0) + (host.vuln_high || 0);
            const lastSeen = host.last_keepalive
              ? new Date(host.last_keepalive).toLocaleString("en-US",
                  { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
              : "—";
            const isRemoving = removing === host.agent_id;
            return (
              <div key={host.agent_id} onClick={() => !isRemoving && onSelectHost(host.agent_id)}
                style={{
                  display: "grid",
                  gridTemplateColumns: "28px 1fr 90px 56px 76px 60px 76px 96px 32px",
                  gap: 8, padding: "10px 14px", cursor: isRemoving ? "default" : "pointer",
                  borderBottom: "1px solid rgba(255,255,255,0.04)",
                  alignItems: "center", transition: "background 0.15s",
                  opacity: isRemoving ? 0.4 : 1,
                }}
                onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.03)"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                <div style={{ display: "flex", justifyContent: "center" }}>
                  <div style={{ width: 7, height: 7, borderRadius: "50%", background: statusCol }} />
                </div>
                <div>
                  <div style={{ fontSize: 13, color: "#e8eaed", fontWeight: 500 }}>
                    {host.agent_name || host.agent_id}
                    {host.asset_tier === 1 && (
                      <span style={{ marginLeft: 6, fontSize: 9, color: TIER_COLOR[1],
                        background: "rgba(255,59,59,0.1)", padding: "1px 5px", borderRadius: 3 }}>
                        CROWN JEWEL
                      </span>
                    )}
                    {host.asset_tier === 2 && (
                      <span style={{ marginLeft: 6, fontSize: 9, color: TIER_COLOR[2],
                        background: "rgba(255,140,0,0.1)", padding: "1px 5px", borderRadius: 3 }}>
                        BIZ CRITICAL
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: 10, color: "#666", marginTop: 1 }}>
                    {host.agent_ip || "—"} · {host.os_platform || "—"} · {host.agent_id}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: gradeCol,
                    fontFamily: "monospace", marginBottom: 3 }}>
                    {host.posture_score != null ? host.posture_score.toFixed(0) : "—"}
                  </div>
                  <Bar pct={host.posture_score || 0} color={gradeCol} />
                </div>
                <div><GradeBadge grade={grade} size={24} /></div>
                <div style={{ fontSize: 12, fontFamily: "monospace",
                  color: host.siem_risk > 70 ? "#ff3b3b" : host.siem_risk > 40 ? "#ff8c00" : "#00e5a0" }}>
                  {host.siem_risk != null ? host.siem_risk.toFixed(0) : "—"}
                </div>
                <div style={{ fontSize: 12, color: critVulns > 0 ? "#ff3b3b" : "#555" }}>
                  {critVulns > 0 ? `${critVulns} C/H` : "—"}
                </div>
                <div style={{ fontSize: 12, color: host.incident_count > 0 ? "#ff8c00" : "#555" }}>
                  {host.incident_count > 0 ? `${host.incident_count}` : "—"}
                </div>
                <div style={{ fontSize: 10, color: "#555" }}>{lastSeen}</div>
                <div style={{ display: "flex", justifyContent: "center" }}>
                  {host.agent_id !== "000" && (
                    <button
                      onClick={e => handleRemove(e, host)}
                      disabled={isRemoving}
                      title={host.wazuh_status === "active"
                        ? "Force remove active agent (rogue / decommissioned)"
                        : "Remove disconnected host from Wazuh and posture cache"}
                      style={{
                        background: "transparent",
                        border: host.wazuh_status === "active"
                          ? "1px solid rgba(255,140,0,0.35)"
                          : "1px solid rgba(255,59,59,0.3)",
                        borderRadius: 3,
                        color: host.wazuh_status === "active" ? "#ff8c00" : "#ff3b3b",
                        fontSize: 11, lineHeight: 1,
                        padding: "2px 5px", cursor: "pointer", opacity: isRemoving ? 0.4 : 0.5,
                      }}
                      onMouseEnter={e => e.currentTarget.style.opacity = "1"}
                      onMouseLeave={e => e.currentTarget.style.opacity = "0.5"}
                    >✕</button>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      {total > PER_PAGE && (
        <div style={{ display: "flex", justifyContent: "center", gap: 8, marginTop: 12 }}>
          <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
            style={{
              background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
              color: "#e8eaed", padding: "5px 12px", borderRadius: 4,
              cursor: page === 1 ? "not-allowed" : "pointer", opacity: page === 1 ? 0.4 : 1,
            }}>← Prev</button>
          <span style={{ fontSize: 11, color: "#666", padding: "6px 0" }}>
            Page {page} of {Math.ceil(total / PER_PAGE)} ({total} hosts)
          </span>
          <button disabled={page * PER_PAGE >= total} onClick={() => setPage(p => p + 1)}
            style={{
              background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
              color: "#e8eaed", padding: "5px 12px", borderRadius: 4,
              cursor: page * PER_PAGE >= total ? "not-allowed" : "pointer",
              opacity: page * PER_PAGE >= total ? 0.4 : 1,
            }}>Next →</button>
        </div>
      )}
    </div>
  );
}

// ── ENTITY RISK LEADERBOARD (tab 2) ───────────────────────────────────────────
const ENTITY_FILTERS = [
  { id: "all",      label: "All",      entityType: undefined, minScore: 0  },
  { id: "critical", label: "Critical", entityType: undefined, minScore: 75 },
  { id: "high",     label: "High",     entityType: undefined, minScore: 50 },
  { id: "hosts",    label: "Hosts",    entityType: "host",    minScore: 0  },
  { id: "users",    label: "Users",    entityType: "user",    minScore: 0  },
];

function BreakdownRow({ label, value, max, color }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, fontFamily: "monospace",
        width: 130, flexShrink: 0 }}>{label}</div>
      <div style={{ flex: 1, height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2, overflow: "hidden" }}>
        <div style={{ width: `${Math.min(100, (value / max) * 100)}%`, height: "100%",
          background: color, borderRadius: 2 }} />
      </div>
      <span style={{ color: "rgba(255,255,255,0.4)", fontSize: 10, fontFamily: "monospace",
        minWidth: 24, textAlign: "right" }}>{Math.round(value)}</span>
    </div>
  );
}

function RiskTab({ riskScores, loading }) {
  const [activeFilter, setFilter] = useState("all");
  const [expanded, setExpanded]   = useState(null);
  const filter = ENTITY_FILTERS.find(f => f.id === activeFilter) || ENTITY_FILTERS[0];

  const shown = riskScores.filter(e => {
    if (filter.entityType && e.entity_type !== filter.entityType) return false;
    if (e.score < filter.minScore) return false;
    return true;
  });

  return (
    <div>
      <div style={{ display: "flex", gap: 6, marginBottom: 16, flexWrap: "wrap" }}>
        {ENTITY_FILTERS.map(f => (
          <button key={f.id} onClick={() => setFilter(f.id)}
            style={{
              background: activeFilter === f.id ? "rgba(255,255,255,0.08)" : "rgba(255,255,255,0.03)",
              border: `1px solid ${activeFilter === f.id ? "rgba(255,255,255,0.18)" : "rgba(255,255,255,0.07)"}`,
              color: activeFilter === f.id ? "white" : "rgba(255,255,255,0.35)",
              padding: "6px 14px", borderRadius: 4, cursor: "pointer",
              fontSize: 12, fontFamily: "monospace",
              fontWeight: activeFilter === f.id ? 700 : 400,
            }}>{f.label}</button>
        ))}
      </div>

      {loading ? (
        <div style={{ color: "#555", fontSize: 12, padding: "40px 0" }}>Loading risk scores…</div>
      ) : shown.length === 0 ? (
        <div style={{ color: "#444", fontSize: 12, padding: "40px 0", textAlign: "center" }}>
          No entities match this filter.
        </div>
      ) : (
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 8, overflow: "hidden" }}>
          {shown.map((entity, idx) => {
            const lvl = riskLevel(entity.score);
            const isExp = expanded === entity.entity_id;
            const bk = entity.breakdown || {};
            return (
              <div key={entity.entity_id}>
                <div onClick={() => setExpanded(isExp ? null : entity.entity_id)}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "28px 28px 200px 1fr 80px 56px",
                    gap: 12, padding: "12px 16px", cursor: "pointer",
                    borderBottom: `1px solid rgba(255,255,255,${isExp ? 0.08 : 0.04})`,
                    background: isExp ? "rgba(255,255,255,0.025)" : "transparent",
                    alignItems: "center",
                  }}>
                  <div style={{ color: "#444", fontSize: 10, fontFamily: "monospace" }}>
                    {String(idx + 1).padStart(2, "0")}
                  </div>
                  <div style={{ fontSize: 16 }}>{entity.entity_type === "user" ? "👤" : "🖥️"}</div>
                  <div>
                    <div style={{ color: "white", fontSize: 13, fontWeight: 600,
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {entity.entity_name || entity.entity_id}
                    </div>
                    <div style={{ color: "#444", fontSize: 10, fontFamily: "monospace",
                      textTransform: "uppercase" }}>{entity.entity_type}</div>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div style={{ flex: 1, height: 6, background: "rgba(255,255,255,0.07)",
                      borderRadius: 3, overflow: "hidden" }}>
                      <div style={{ width: `${entity.score}%`, height: "100%",
                        background: lvl.color, borderRadius: 3, transition: "width .5s" }} />
                    </div>
                    <span style={{ color: lvl.color, fontSize: 13, fontFamily: "monospace",
                      fontWeight: 700, minWidth: 28, textAlign: "right" }}>
                      {Math.round(entity.score)}
                    </span>
                  </div>
                  <span style={{ background: lvl.bg, color: lvl.color,
                    border: `1px solid ${lvl.color}40`, fontSize: 10, fontWeight: 700,
                    fontFamily: "monospace", padding: "2px 8px", borderRadius: 2 }}>
                    {lvl.label}
                  </span>
                  <div style={{ display: "flex", alignItems: "center", gap: 6,
                    justifyContent: "flex-end" }}>
                    <span style={{ color: entity.trend === "rising" ? "#ff3b3b"
                      : entity.trend === "falling" ? "#00e5a0" : "#444", fontSize: 14 }}>
                      {entity.trend === "rising" ? "↑" : entity.trend === "falling" ? "↓" : "→"}
                    </span>
                    <span style={{ color: "#444", fontSize: 11 }}>{isExp ? "▲" : "▼"}</span>
                  </div>
                </div>
                {isExp && (
                  <div style={{ padding: "14px 16px 16px 72px",
                    background: "rgba(255,255,255,0.015)",
                    borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
                    <div style={{ color: "#555", fontSize: 10, fontFamily: "monospace",
                      letterSpacing: "1px", marginBottom: 10 }}>SCORE BREAKDOWN</div>
                    <BreakdownRow label="Alert Severity"    value={bk.alert_severity    ?? 0} max={35} color="#ff3b3b" />
                    <BreakdownRow label="Incident Severity" value={bk.incident_severity ?? 0} max={30} color="#ff8c00" />
                    <BreakdownRow label="UEBA Anomalies"    value={bk.ueba_anomalies    ?? 0} max={25} color="#f5c518" />
                    <BreakdownRow label="TI IOC Hits"       value={bk.misp_ioc_hits     ?? 0} max={10} color="#b06eff" />
                    {entity.last_calculated && (
                      <div style={{ color: "#444", fontSize: 10, fontFamily: "monospace", marginTop: 8 }}>
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
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────
export function HostIntelligencePage() {
  const [tab, setTab]                 = useState("hosts");
  // Hosts state
  const [hosts, setHosts]             = useState([]);
  const [posture, setPosture]         = useState(null);
  const [hostsLoading, setHostsLoad]  = useState(true);
  const [hostsError, setHostsErr]     = useState(null);
  const [selectedHost, setSelected]   = useState(null);
  const [statusFilter, setStatus]     = useState("all");
  const [sortBy, setSort]             = useState("posture_score");
  const [search, setSearch]           = useState("");
  const [page, setPage]               = useState(1);
  const [total, setTotal]             = useState(0);
  const [refreshing, setRefreshing]   = useState(false);
  // Seeding: true while waiting for the auto-triggered background refresh to populate data
  const [seeding, setSeeding]         = useState(false);
  // Risk state
  const [riskScores, setRiskScores]   = useState([]);
  const [riskLoading, setRiskLoad]    = useState(true);

  const loadHosts = useCallback(async () => {
    setHostsLoad(true);
    setHostsErr(null);
    try {
      const qs = new URLSearchParams({
        status: statusFilter, sort: sortBy,
        page: String(page), per_page: "50",
      });
      const res = await fetch(`${API}/hosts?${qs}`, { credentials: "include" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setHosts(data.hosts || []);
      setTotal(data.total || 0);
      if (data.internal_posture) setPosture(data.internal_posture);
      // If the cache came back empty the backend auto-triggered a refresh.
      // Poll every 8 s until hosts appear (max 10 attempts = 80 s).
      if ((data.hosts || []).length === 0 && statusFilter === "all") {
        setSeeding(true);
      } else {
        setSeeding(false);
      }
    } catch (e) {
      setHostsErr(e.message);
      setSeeding(false);
    } finally {
      setHostsLoad(false);
    }
  }, [statusFilter, sortBy, page]);

  const loadRisk = useCallback(async () => {
    setRiskLoad(true);
    const data = await siemFetch(siemApi.getRiskScores({ limit: 200 }));
    if (!data._offline && !data._error) setRiskScores(Array.isArray(data) ? data : []);
    setRiskLoad(false);
  }, []);

  useEffect(() => { loadHosts(); }, [loadHosts]);
  useEffect(() => { loadRisk(); }, [loadRisk]);

  // Poll while seeding — recheck every 8 s until hosts appear.
  useEffect(() => {
    if (!seeding) return;
    let attempts = 0;
    const poll = setInterval(async () => {
      attempts++;
      if (attempts > 15) { clearInterval(poll); setSeeding(false); return; }
      try {
        const qs = new URLSearchParams({ status: "all", sort: sortBy, page: "1", per_page: "50" });
        const res = await fetch(`${API}/hosts?${qs}`, { credentials: "include" });
        if (!res.ok) return;
        const data = await res.json();
        if ((data.hosts || []).length > 0) {
          setHosts(data.hosts);
          setTotal(data.total || 0);
          if (data.internal_posture) setPosture(data.internal_posture);
          setSeeding(false);
          clearInterval(poll);
        }
      } catch {}
    }, 8000);
    return () => clearInterval(poll);
  }, [seeding, sortBy]);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await fetch(`${API}/hosts/refresh`, { method: "POST", credentials: "include" });
      // Wait for background refresh to complete before reloading
      await new Promise(r => setTimeout(r, 5000));
      await loadHosts();
    } catch {}
    setRefreshing(false);
  };

  const handleRemoveHost = async (agentId) => {
    try {
      await fetch(`${API}/hosts/${agentId}`, { method: "DELETE", credentials: "include" });
      setHosts(prev => prev.filter(h => h.agent_id !== agentId));
      setTotal(prev => Math.max(0, prev - 1));
    } catch {}
  };

  return (
    <div style={{ color: "#e8eaed", fontFamily: "monospace" }}>
        {/* Header */}
        <div style={{ marginBottom: 18 }}>
          <div style={{ fontSize: 11, color: "#666", letterSpacing: "1.5px", marginBottom: 3 }}>
            INTERNAL EXPOSURE
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <h2 style={{ margin: 0, fontSize: 18, color: "#e8eaed", fontWeight: 600 }}>
              Host Intelligence
            </h2>
            <span style={{ background: "rgba(77,158,255,0.1)", color: "#4d9eff",
              fontSize: 10, padding: "2px 8px", borderRadius: 2, fontFamily: "monospace",
              fontWeight: 700, letterSpacing: "1px" }}>
              ENTITY INTELLIGENCE
            </span>
          </div>
        </div>

        {/* Charts summary (always visible, uses both data sets) */}
        <SummaryCharts hosts={hosts} posture={posture} riskScores={riskScores} />

        {/* Tab bar */}
        <div style={{ display: "flex", gap: 2, marginBottom: 18,
          borderBottom: "1px solid rgba(255,255,255,0.07)", paddingBottom: 0 }}>
          {[
            { id: "hosts",      label: "🖥  Hosts & Posture" },
            { id: "risk",       label: "⚡  Entity Risk Scores" },
            { id: "groups",     label: "⬡  Agent Groups" },
            { id: "policies",   label: "⚡  Response Playbooks" },
            { id: "deployment", label: "📡  Sensor Deployment" },
          ].map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              style={{
                background: "none",
                border: "none",
                borderBottom: tab === t.id
                  ? "2px solid #4d9eff" : "2px solid transparent",
                color: tab === t.id ? "#e8eaed" : "#666",
                padding: "8px 18px", cursor: "pointer",
                fontSize: 12, fontFamily: "monospace", fontWeight: tab === t.id ? 600 : 400,
                marginBottom: -1,
              }}>{t.label}</button>
          ))}
        </div>

        {/* Tab content */}
        {tab === "hosts" && (
          <HostsTab
            hosts={hosts} loading={hostsLoading} error={hostsError}
            posture={posture} onRefresh={handleRefresh} refreshing={refreshing}
            seeding={seeding}
            statusFilter={statusFilter} setStatusFilter={setStatus}
            sortBy={sortBy} setSortBy={setSort}
            search={search} setSearch={setSearch}
            page={page} setPage={setPage} total={total}
            onSelectHost={setSelected}
            onRemoveHost={handleRemoveHost}
          />
        )}
        {tab === "risk" && (
          <RiskTab riskScores={riskScores} loading={riskLoading} />
        )}
        {tab === "groups" && (
          <AgentGroupsTab />
        )}
        {tab === "policies" && (
          <EndpointPoliciesTab />
        )}
        {tab === "deployment" && (
          <SensorDeploymentTab />
        )}

        {/* Host detail panel */}
        {selectedHost && (
          <HostDetailPanel agentId={selectedHost} onClose={() => setSelected(null)} />
        )}
    </div>
  );
}
