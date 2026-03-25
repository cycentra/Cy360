/**
 * SiemUebaPage.jsx
 * UEBA baseline profiles and anomaly timeline.
 * Shows per-user behavioural baselines and detected anomalies.
 */

import { useState, useEffect } from "react";
import { siemApi, siemFetch } from "./siemApi";
import { SiemEngineStatus } from "./SiemEngineStatus";

const ANOMALY_LABELS = {
  off_hours_login:       "Off-Hours Login",
  high_auth_fail_rate:   "Elevated Auth Failures",
  new_agent_access:      "New Host Access",
  multi_host_burst:      "Multi-Host Burst",
  svc_account_interactive: "Service Account Interactive Session",
  privilege_escalation:  "Privilege Escalation",
  impossible_travel:     "Impossible Travel",
};

const ANOMALY_COLORS = {
  off_hours_login:        "#f5c518",
  high_auth_fail_rate:    "#ff8c00",
  new_agent_access:       "#4d9eff",
  multi_host_burst:       "#ff8c00",
  svc_account_interactive:"#ff3b3b",
  privilege_escalation:   "#ff3b3b",
  impossible_travel:      "#ff3b3b",
};

// 24-hour heat grid for typical_hours
function HoursGrid({ hours = [] }) {
  const hourSet = new Set(hours);
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(24, 1fr)", gap: 2 }}>
      {Array.from({ length: 24 }, (_, h) => (
        <div key={h} title={`${String(h).padStart(2,"0")}:00`}
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

// User profile panel
function UserProfile({ username }) {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    siemFetch(siemApi.getUebaUser(username)).then(data => {
      if (!data._offline && !data._error) setProfile(data);
      setLoading(false);
    });
  }, [username]);

  if (loading) return (
    <div style={{ color: "rgba(255,255,255,0.3)", padding: 20 }}>Loading profile…</div>
  );
  if (!profile) return (
    <div style={{ color: "rgba(255,255,255,0.3)", padding: 20 }}>Profile not found.</div>
  );

  const { baseline, anomalies = [] } = profile;
  const activeAnomalies = anomalies.filter(a => !a.resolved);

  // Group anomaly contributions by type for mini chart
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
              Building baseline… check back in {30} days.
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
          {Object.entries(byType).sort(([,a],[,b]) => b - a).map(([type, total]) => {
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
                    {a.detected_at ? new Date(a.detected_at).toLocaleDateString() : "—"}<br/>
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
                    <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 12 }}>
                      {a.description}
                    </div>
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

// ── Main page ──────────────────────────────────────────────────────────────────
export function SiemUebaPage() {
  const [users, setUsers]       = useState([]);
  const [loading, setLoading]   = useState(true);
  const [search, setSearch]     = useState("");
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    siemFetch(siemApi.getUebaUsers()).then(data => {
      if (!data._offline && !data._error) {
        setUsers(Array.isArray(data) ? data : []);
      }
      setLoading(false);
    });
  }, []);

  const filtered = users.filter(u =>
    !search || u.username?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <SiemEngineStatus>
      <div>
        <div style={{ marginBottom: 22 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: "white" }}>UEBA</h1>
            <span style={{ background: "rgba(176,110,255,0.12)", color: "#b06eff", fontSize: 10,
              fontFamily: "monospace", padding: "3px 10px", borderRadius: 2, fontWeight: 700,
              letterSpacing: "1px" }}>USER & ENTITY BEHAVIOUR</span>
          </div>
          <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13 }}>
            Rolling behavioural baselines per user. 7 anomaly detectors with risk contributions.
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "240px 1fr", gap: 20, alignItems: "start" }}>
          {/* User list */}
          <div>
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search users…"
              style={{ width: "100%", background: "rgba(255,255,255,0.05)",
                border: "1px solid rgba(255,255,255,0.12)", color: "white",
                padding: "8px 12px", borderRadius: 4, fontSize: 12, fontFamily: "monospace",
                marginBottom: 10, boxSizing: "border-box", outline: "none" }} />

            {loading ? (
              <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, padding: "20px 0" }}>
                Loading users…
              </div>
            ) : filtered.length === 0 ? (
              <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, padding: "20px 0" }}>
                No UEBA baselines yet.
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {filtered.map(u => (
                  <button key={u.username} onClick={() => setSelected(u.username)}
                    style={{ background: selected === u.username ? "rgba(176,110,255,0.1)" : "rgba(255,255,255,0.02)",
                      border: `1px solid ${selected === u.username ? "rgba(176,110,255,0.4)" : "rgba(255,255,255,0.07)"}`,
                      borderRadius: 4, padding: "9px 12px", cursor: "pointer", textAlign: "left" }}>
                    <div style={{ color: "white", fontSize: 12, fontWeight: selected === u.username ? 700 : 400 }}>
                      {u.username}
                    </div>
                    {u.updated_at && (
                      <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace",
                        marginTop: 2 }}>
                        Updated {new Date(u.updated_at).toLocaleDateString()}
                      </div>
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Profile panel */}
          <div>
            {!selected ? (
              <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, padding: "40px 0" }}>
                Select a user to view their UEBA profile.
              </div>
            ) : (
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
                  <span style={{ fontSize: 18 }}>👤</span>
                  <div style={{ color: "white", fontSize: 16, fontWeight: 700 }}>{selected}</div>
                </div>
                <UserProfile username={selected} />
              </div>
            )}
          </div>
        </div>
      </div>
    </SiemEngineStatus>
  );
}
