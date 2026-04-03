/**
 * SiemUebaPage.jsx
 * UEBA baseline profiles and anomaly timeline.
 * Features: category grouping, smart filters, anomaly highlights, Top-20 activity view.
 */

import { useState, useEffect, useMemo } from "react";
import { siemApi, siemFetch } from "./siemApi";
import { SiemEngineStatus } from "./SiemEngineStatus";

// ── Constants ──────────────────────────────────────────────────────────────────

const ANOMALY_LABELS = {
  off_hours_login:          "Off-Hours Login",
  high_auth_fail_rate:      "Elevated Auth Failures",
  new_agent_access:         "New Host Access",
  multi_host_burst:         "Multi-Host Burst",
  svc_account_interactive:  "Service Account Interactive Session",
  privilege_escalation:     "Privilege Escalation",
  impossible_travel:        "Impossible Travel",
};

const ANOMALY_COLORS = {
  off_hours_login:          "#f5c518",
  high_auth_fail_rate:      "#ff8c00",
  new_agent_access:         "#4d9eff",
  multi_host_burst:         "#ff8c00",
  svc_account_interactive:  "#ff3b3b",
  privilege_escalation:     "#ff3b3b",
  impossible_travel:        "#ff3b3b",
};

const CATEGORY_META = {
  human:   { label: "Human User",    color: "#00e5a0", icon: "👤", description: "Interactive user — real person who logs in" },
  service: { label: "Service Acct",  color: "#4d9eff", icon: "⚙️",  description: "Application or infrastructure service account" },
  system:  { label: "System Acct",   color: "#888",    icon: "🖥️", description: "OS-level daemon or system account — not interactive" },
};

const FILTER_TABS = [
  { id: "all",         label: "All Users",       icon: "🗂️"  },
  { id: "anomaly",     label: "With Anomaly",    icon: "🔴"  },
  { id: "human",       label: "Human",           icon: "👤"  },
  { id: "service",     label: "Service",         icon: "⚙️"  },
  { id: "system",      label: "System",          icon: "🖥️" },
  { id: "top20",       label: "Top 20 Activity", icon: "📊"  },
];

// ── Sub-components ─────────────────────────────────────────────────────────────

function HoursGrid({ hours = [] }) {
  const hourSet = new Set(hours);
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(24, 1fr)", gap: 2 }}>
      {Array.from({ length: 24 }, (_, h) => (
        <div key={h} title={`${String(h).padStart(2, "0")}:00`}
          style={{ height: 16, borderRadius: 2,
            background: hourSet.has(h) ? "#00e5a0" : "rgba(255,255,255,0.06)" }} />
      ))}
      <div style={{ gridColumn: "1 / -1", display: "flex", justifyContent: "space-between",
        color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>
        <span>00</span><span>06</span><span>12</span><span>18</span><span>23</span>
      </div>
    </div>
  );
}

function CategoryBadge({ category, small = false }) {
  const meta = CATEGORY_META[category] || CATEGORY_META.human;
  return (
    <span title={meta.description} style={{
      background: `${meta.color}18`,
      color: meta.color,
      border: `1px solid ${meta.color}40`,
      fontSize: small ? 9 : 10,
      fontFamily: "monospace",
      padding: small ? "1px 5px" : "2px 7px",
      borderRadius: 2,
      fontWeight: 700,
      letterSpacing: "0.5px",
      whiteSpace: "nowrap",
    }}>
      {meta.icon} {meta.label}
    </span>
  );
}

function AnomalyBadge({ active, total }) {
  if (!active && !total) return null;
  return (
    <span style={{
      background: active > 0 ? "rgba(255,59,59,0.15)" : "rgba(255,255,255,0.05)",
      color: active > 0 ? "#ff3b3b" : "rgba(255,255,255,0.3)",
      border: `1px solid ${active > 0 ? "rgba(255,59,59,0.4)" : "rgba(255,255,255,0.1)"}`,
      fontSize: 9, fontFamily: "monospace", padding: "2px 6px", borderRadius: 2, fontWeight: 700,
    }}>
      {active > 0 ? `⚠ ${active} ACTIVE` : `${total} resolved`}
    </span>
  );
}

function UserProfile({ username }) {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    siemFetch(siemApi.getUebaUser(username)).then(data => {
      if (cancelled) return;
      if (!data._offline && !data._error) setProfile(data);
      setLoading(false);
    });
    return () => { cancelled = true; };
  }, [username]);

  if (loading) return (
    <div style={{ color: "rgba(255,255,255,0.3)", padding: 20 }}>Loading profile…</div>
  );
  if (!profile) return (
    <div style={{ color: "rgba(255,255,255,0.3)", padding: 20 }}>Profile not found.</div>
  );

  const { baseline, anomalies = [] } = profile;
  const activeAnomalies = anomalies.filter(a => !a.resolved);

  const byType = {};
  anomalies.forEach(a => {
    byType[a.anomaly_type] = (byType[a.anomaly_type] || 0) + (a.risk_contribution || 0);
  });
  const maxContrib = Math.max(...Object.values(byType), 1);

  return (
    <div>
      {/* Baseline stats */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 20 }}>
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 4, padding: "14px 16px" }}>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace",
            letterSpacing: "1px", marginBottom: 8 }}>TYPICAL WORKING HOURS</div>
          {baseline ? <HoursGrid hours={baseline.typical_hours || []} /> : (
            <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12 }}>No baseline yet</div>
          )}
        </div>
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 4, padding: "14px 16px" }}>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace",
            letterSpacing: "1px", marginBottom: 10 }}>BEHAVIOURAL BASELINE</div>
          {baseline ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {[
                { label: "Avg Daily Events", val: Math.round(baseline.avg_daily_events || 0) },
                { label: "Avg Fail Rate",    val: `${((baseline.avg_fail_rate || 0) * 100).toFixed(1)}%` },
                { label: "Typical Agents",   val: (baseline.typical_agents || []).length },
                { label: "Last Updated",     val: baseline.updated_at ? new Date(baseline.updated_at).toLocaleDateString() : "—" },
              ].map(({ label, val }) => (
                <div key={label} style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "rgba(255,255,255,0.4)", fontSize: 12 }}>{label}</span>
                  <span style={{ color: "white", fontSize: 12, fontFamily: "monospace" }}>{val}</span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12 }}>
              Building baseline… check back in 30 days.
            </div>
          )}
        </div>
      </div>

      {/* Anomaly type contribution chart */}
      {Object.keys(byType).length > 0 && (
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 4, padding: "14px 16px", marginBottom: 20 }}>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace",
            letterSpacing: "1px", marginBottom: 12 }}>RISK CONTRIBUTION BY ANOMALY TYPE</div>
          {Object.entries(byType).sort(([, a], [, b]) => b - a).map(([type, total]) => {
            const color = ANOMALY_COLORS[type] || "#888";
            return (
              <div key={type} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, width: 200, flexShrink: 0 }}>
                  {ANOMALY_LABELS[type] || type}
                </div>
                <div style={{ flex: 1, height: 6, background: "rgba(255,255,255,0.06)", borderRadius: 3 }}>
                  <div style={{ width: `${(total / maxContrib) * 100}%`, height: "100%",
                    background: color, borderRadius: 3 }} />
                </div>
                <span style={{ color, fontSize: 11, fontFamily: "monospace", minWidth: 28,
                  textAlign: "right" }}>+{total}</span>
              </div>
            );
          })}
        </div>
      )}

      {/* Anomaly timeline */}
      <div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace",
            letterSpacing: "1px" }}>ANOMALY TIMELINE</div>
          {activeAnomalies.length > 0 && (
            <span style={{ background: "rgba(255,59,59,0.12)", color: "#ff3b3b", fontSize: 10,
              fontFamily: "monospace", padding: "2px 8px", borderRadius: 2, fontWeight: 700 }}>
              {activeAnomalies.length} ACTIVE
            </span>
          )}
        </div>

        {anomalies.length === 0 ? (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, padding: "20px 0" }}>
            No anomalies detected for this user.
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {anomalies.slice(0, 50).map(a => {
              const color = ANOMALY_COLORS[a.anomaly_type] || "#888";
              return (
                <div key={a.id} style={{ display: "flex", gap: 12, padding: "10px 14px",
                  background: a.resolved ? "rgba(255,255,255,0.01)" : "rgba(255,255,255,0.03)",
                  border: `1px solid rgba(255,255,255,${a.resolved ? 0.04 : 0.07})`,
                  borderLeft: `3px solid ${a.resolved ? "rgba(255,255,255,0.08)" : color}`,
                  borderRadius: "0 4px 4px 0", opacity: a.resolved ? 0.5 : 1 }}>
                  <div style={{ minWidth: 80, color: "rgba(255,255,255,0.3)", fontSize: 10,
                    fontFamily: "monospace", flexShrink: 0 }}>
                    {a.detected_at ? new Date(a.detected_at).toLocaleDateString() : "—"}<br />
                    {a.detected_at ? new Date(a.detected_at).toLocaleTimeString() : ""}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
                      <span style={{ color, fontSize: 11, fontWeight: 700, fontFamily: "monospace" }}>
                        {ANOMALY_LABELS[a.anomaly_type] || a.anomaly_type}
                      </span>
                      <span style={{ background: `${color}20`, color, border: `1px solid ${color}40`,
                        fontSize: 9, fontFamily: "monospace", padding: "1px 6px", borderRadius: 2 }}>
                        +{a.risk_contribution}
                      </span>
                      {a.resolved && (
                        <span style={{ color: "#00e5a0", fontSize: 9, fontFamily: "monospace" }}>
                          ✓ RESOLVED
                        </span>
                      )}
                    </div>
                    <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 12 }}>{a.description}</div>
                    {a.incident_id && (
                      <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10,
                        fontFamily: "monospace", marginTop: 2 }}>
                        → Incident {a.incident_id}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

/** Collapsible group of users in the sidebar list */
function UserGroup({ title, icon, color, users, selected, onSelect, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen);

  if (users.length === 0) return null;
  return (
    <div style={{ marginBottom: 14 }}>
      <button onClick={() => setOpen(v => !v)}
        style={{ width: "100%", display: "flex", alignItems: "center", gap: 6,
          background: "none", border: "none", cursor: "pointer",
          color: "rgba(255,255,255,0.4)", padding: "4px 0", textAlign: "left" }}>
        <span style={{ fontSize: 10, fontFamily: "monospace", letterSpacing: "1px",
          color, flex: 1, fontWeight: 700 }}>
          {icon} {title.toUpperCase()} ({users.length})
        </span>
        <span style={{ fontSize: 10, color: "rgba(255,255,255,0.25)" }}>
          {open ? "▾" : "▸"}
        </span>
      </button>

      {open && (
        <div style={{ display: "flex", flexDirection: "column", gap: 3, marginTop: 4 }}>
          {users.map(u => {
            const isSelected = selected === u.username;
            return (
              <button key={u.username} onClick={() => onSelect(u.username)}
                style={{
                  background: isSelected ? "rgba(176,110,255,0.1)" : "rgba(255,255,255,0.01)",
                  border: `1px solid ${isSelected ? "rgba(176,110,255,0.4)" : "rgba(255,255,255,0.06)"}`,
                  borderRadius: 4, padding: "8px 10px", cursor: "pointer", textAlign: "left",
                  transition: "all 0.15s",
                }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
                  gap: 6, marginBottom: u.active_anomalies > 0 ? 4 : 0 }}>
                  <div style={{ color: "white", fontSize: 12,
                    fontWeight: isSelected ? 700 : 400, fontFamily: "monospace",
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
                    {u.username}
                  </div>
                  <AnomalyBadge active={u.active_anomalies} total={u.total_anomalies} />
                </div>
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <CategoryBadge category={u.category} small />
                  {u.avg_daily_events > 0 && (
                    <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 9,
                      fontFamily: "monospace" }}>
                      ~{Math.round(u.avg_daily_events)} evt/day
                    </span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

/** Compact summary strip of users with active anomalies — shown at top of main panel */
function AnomalyAlertStrip({ users, selected, onSelect }) {
  const atRisk = users.filter(u => u.active_anomalies > 0)
    .sort((a, b) => b.active_anomalies - a.active_anomalies);

  if (atRisk.length === 0) return null;

  return (
    <div style={{ background: "rgba(255,59,59,0.06)", border: "1px solid rgba(255,59,59,0.2)",
      borderRadius: 4, padding: "12px 16px", marginBottom: 20 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <span style={{ color: "#ff3b3b", fontSize: 11, fontFamily: "monospace",
          fontWeight: 700, letterSpacing: "1px" }}>⚠ USERS WITH ACTIVE ANOMALIES</span>
        <span style={{ background: "rgba(255,59,59,0.2)", color: "#ff3b3b",
          fontSize: 10, fontFamily: "monospace", padding: "1px 7px", borderRadius: 2,
          fontWeight: 700 }}>{atRisk.length}</span>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
        {atRisk.map(u => (
          <button key={u.username} onClick={() => onSelect(u.username)}
            style={{
              background: selected === u.username ? "rgba(255,59,59,0.18)" : "rgba(255,59,59,0.08)",
              border: `1px solid ${selected === u.username ? "rgba(255,59,59,0.6)" : "rgba(255,59,59,0.25)"}`,
              borderRadius: 4, padding: "6px 10px", cursor: "pointer",
              display: "flex", alignItems: "center", gap: 6,
            }}>
            <span style={{ color: "white", fontSize: 11, fontFamily: "monospace" }}>
              {u.username}
            </span>
            <span style={{ background: "rgba(255,59,59,0.25)", color: "#ff3b3b",
              fontSize: 9, fontFamily: "monospace", padding: "1px 5px", borderRadius: 2,
              fontWeight: 700 }}>
              {u.active_anomalies} ⚠
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}

// ── Summary stats bar ──────────────────────────────────────────────────────────
function StatBar({ users }) {
  const total   = users.length;
  const human   = users.filter(u => u.category === "human").length;
  const service = users.filter(u => u.category === "service").length;
  const system  = users.filter(u => u.category === "system").length;
  const atRisk  = users.filter(u => u.active_anomalies > 0).length;

  const stats = [
    { label: "Total",       val: total,   color: "rgba(255,255,255,0.5)" },
    { label: "Human",       val: human,   color: "#00e5a0" },
    { label: "Service",     val: service, color: "#4d9eff" },
    { label: "System",      val: system,  color: "#888" },
    { label: "With Anomaly",val: atRisk,  color: "#ff3b3b" },
  ];

  return (
    <div style={{ display: "flex", gap: 16, marginBottom: 16, flexWrap: "wrap" }}>
      {stats.map(({ label, val, color }) => (
        <div key={label} style={{ display: "flex", flexDirection: "column", alignItems: "center",
          background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
          borderRadius: 4, padding: "8px 14px", minWidth: 70 }}>
          <span style={{ color, fontSize: 18, fontWeight: 700, fontFamily: "monospace" }}>{val}</span>
          <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace",
            marginTop: 2, letterSpacing: "0.5px" }}>{label.toUpperCase()}</span>
        </div>
      ))}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────
export function SiemUebaPage() {
  const [users,    setUsers]    = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [search,   setSearch]   = useState("");
  const [selected, setSelected] = useState(null);
  const [activeTab, setActiveTab] = useState("all");

  useEffect(() => {
    siemFetch(siemApi.getUebaUsers()).then(data => {
      if (!data._offline && !data._error) {
        setUsers(Array.isArray(data) ? data : []);
      }
      setLoading(false);
    });
  }, []);

  // Apply search + tab filter, then split into groups
  const filtered = useMemo(() => {
    let list = users;

    // Search
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(u => u.username?.toLowerCase().includes(q));
    }

    // Tab filter
    if (activeTab === "anomaly") {
      list = list.filter(u => u.active_anomalies > 0);
    } else if (activeTab === "human") {
      list = list.filter(u => u.category === "human");
    } else if (activeTab === "service") {
      list = list.filter(u => u.category === "service");
    } else if (activeTab === "system") {
      list = list.filter(u => u.category === "system");
    } else if (activeTab === "top20") {
      list = [...list].sort((a, b) => b.avg_daily_events - a.avg_daily_events).slice(0, 20);
    }

    return list;
  }, [users, search, activeTab]);

  // Split by category for grouped view
  const grouped = useMemo(() => {
    const withAnomaly = filtered.filter(u => u.active_anomalies > 0)
      .sort((a, b) => b.active_anomalies - a.active_anomalies);
    const human   = filtered.filter(u => u.category === "human" && u.active_anomalies === 0)
      .sort((a, b) => b.avg_daily_events - a.avg_daily_events);
    const service = filtered.filter(u => u.category === "service" && u.active_anomalies === 0);
    const system  = filtered.filter(u => u.category === "system" && u.active_anomalies === 0);
    return { withAnomaly, human, service, system };
  }, [filtered]);

  const useGrouped = activeTab === "all" || activeTab === "anomaly";

  return (
    <SiemEngineStatus>
      <div>
        {/* Header */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: "white" }}>UEBA</h1>
            <span style={{ background: "rgba(176,110,255,0.12)", color: "#b06eff", fontSize: 10,
              fontFamily: "monospace", padding: "3px 10px", borderRadius: 2, fontWeight: 700,
              letterSpacing: "1px" }}>USER & ENTITY BEHAVIOUR</span>
          </div>
          <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13, margin: 0 }}>
            Rolling behavioural baselines per user. Human, service, and system accounts are
            automatically classified. Filter to find what matters.
          </p>
        </div>

        {/* Stats bar */}
        {!loading && <StatBar users={users} />}

        {/* Anomaly alert strip — shown in all/anomaly tabs */}
        {!loading && (activeTab === "all" || activeTab === "anomaly") && (
          <AnomalyAlertStrip users={users} selected={selected} onSelect={setSelected} />
        )}

        <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: 20, alignItems: "start" }}>
          {/* ── Left: filter + user list ── */}
          <div>
            {/* Search */}
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search users…"
              style={{ width: "100%", background: "rgba(255,255,255,0.05)",
                border: "1px solid rgba(255,255,255,0.12)", color: "white",
                padding: "8px 12px", borderRadius: 4, fontSize: 12, fontFamily: "monospace",
                marginBottom: 12, boxSizing: "border-box", outline: "none" }} />

            {/* Filter tabs */}
            <div style={{ display: "flex", flexDirection: "column", gap: 2, marginBottom: 16 }}>
              {FILTER_TABS.map(tab => {
                // Count badge per tab
                let count = 0;
                if (tab.id === "all")     count = users.length;
                else if (tab.id === "anomaly")  count = users.filter(u => u.active_anomalies > 0).length;
                else if (tab.id === "human")    count = users.filter(u => u.category === "human").length;
                else if (tab.id === "service")  count = users.filter(u => u.category === "service").length;
                else if (tab.id === "system")   count = users.filter(u => u.category === "system").length;
                else if (tab.id === "top20")    count = Math.min(users.length, 20);

                const isActive = activeTab === tab.id;
                return (
                  <button key={tab.id} onClick={() => { setActiveTab(tab.id); setSelected(null); }}
                    style={{
                      background: isActive ? "rgba(176,110,255,0.12)" : "rgba(255,255,255,0.02)",
                      border: `1px solid ${isActive ? "rgba(176,110,255,0.4)" : "rgba(255,255,255,0.06)"}`,
                      borderRadius: 4, padding: "8px 12px", cursor: "pointer",
                      display: "flex", alignItems: "center", gap: 8, textAlign: "left",
                    }}>
                    <span style={{ fontSize: 12 }}>{tab.icon}</span>
                    <span style={{ color: isActive ? "#b06eff" : "rgba(255,255,255,0.6)",
                      fontSize: 12, fontFamily: "monospace", flex: 1 }}>
                      {tab.label}
                    </span>
                    <span style={{ background: isActive ? "rgba(176,110,255,0.2)" : "rgba(255,255,255,0.05)",
                      color: isActive ? "#b06eff" : "rgba(255,255,255,0.3)",
                      fontSize: 10, fontFamily: "monospace", padding: "1px 6px", borderRadius: 2 }}>
                      {count}
                    </span>
                  </button>
                );
              })}
            </div>

            <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: 14 }}>
              {loading ? (
                <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, padding: "20px 0" }}>
                  Loading users…
                </div>
              ) : filtered.length === 0 ? (
                <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, padding: "20px 0" }}>
                  {search ? "No users match your search." : "No UEBA baselines yet."}
                </div>
              ) : useGrouped ? (
                <>
                  <UserGroup title="With Active Anomaly" icon="⚠" color="#ff3b3b"
                    users={grouped.withAnomaly} selected={selected} onSelect={setSelected}
                    defaultOpen={true} />
                  <UserGroup title="Human Users" icon="👤" color="#00e5a0"
                    users={grouped.human} selected={selected} onSelect={setSelected}
                    defaultOpen={grouped.human.length <= 20} />
                  <UserGroup title="Service Accounts" icon="⚙️" color="#4d9eff"
                    users={grouped.service} selected={selected} onSelect={setSelected}
                    defaultOpen={false} />
                  <UserGroup title="System Accounts" icon="🖥️" color="#888"
                    users={grouped.system} selected={selected} onSelect={setSelected}
                    defaultOpen={false} />
                </>
              ) : (
                /* Flat list for single-category or top20 views */
                <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                  {filtered.map(u => {
                    const isSelected = selected === u.username;
                    return (
                      <button key={u.username} onClick={() => setSelected(u.username)}
                        style={{
                          background: isSelected ? "rgba(176,110,255,0.1)" : "rgba(255,255,255,0.01)",
                          border: `1px solid ${isSelected ? "rgba(176,110,255,0.4)" : "rgba(255,255,255,0.06)"}`,
                          borderRadius: 4, padding: "8px 10px", cursor: "pointer", textAlign: "left",
                        }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
                          gap: 6, marginBottom: 4 }}>
                          <span style={{ color: "white", fontSize: 12, fontFamily: "monospace",
                            fontWeight: isSelected ? 700 : 400, overflow: "hidden",
                            textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
                            {u.username}
                          </span>
                          <AnomalyBadge active={u.active_anomalies} total={u.total_anomalies} />
                        </div>
                        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                          <CategoryBadge category={u.category} small />
                          {u.avg_daily_events > 0 && activeTab === "top20" && (
                            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 9,
                              fontFamily: "monospace" }}>
                              ~{Math.round(u.avg_daily_events)} evt/day
                            </span>
                          )}
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* ── Right: profile panel ── */}
          <div>
            {!selected ? (
              <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, padding: "40px 0",
                textAlign: "center" }}>
                <div style={{ fontSize: 32, marginBottom: 12 }}>👤</div>
                Select a user from the list to view their UEBA profile, behavioural baseline,
                and anomaly timeline.
              </div>
            ) : (
              <div>
                {/* Profile header */}
                {(() => {
                  const u = users.find(x => x.username === selected);
                  return (
                    <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20,
                      padding: "14px 16px",
                      background: "rgba(255,255,255,0.02)",
                      border: "1px solid rgba(255,255,255,0.08)", borderRadius: 4 }}>
                      <span style={{ fontSize: 22 }}>
                        {u ? CATEGORY_META[u.category]?.icon : "👤"}
                      </span>
                      <div style={{ flex: 1 }}>
                        <div style={{ color: "white", fontSize: 16, fontWeight: 700,
                          fontFamily: "monospace", marginBottom: 4 }}>
                          {selected}
                        </div>
                        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                          {u && <CategoryBadge category={u.category} />}
                          {u && u.active_anomalies > 0 && (
                            <AnomalyBadge active={u.active_anomalies} total={u.total_anomalies} />
                          )}
                          {u && (
                            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 11 }}>
                              {u.description}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })()}
                <UserProfile username={selected} />
              </div>
            )}
          </div>
        </div>
      </div>
    </SiemEngineStatus>
  );
}
