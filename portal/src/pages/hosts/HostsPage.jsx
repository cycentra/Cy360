/**
 * HostsPage.jsx
 * Host Inventory — lists all Wazuh-connected hosts with posture scores.
 * Internal Security Posture banner at the top aggregates all host scores.
 * Clicking a host opens HostDetailPanel for full SCA/vuln/MITRE/compliance profile.
 */

import { useState, useEffect, useCallback } from "react";
import { HostDetailPanel } from "./HostDetailPanel.jsx";

const API = "/api/siem";

const GRADE_COLOR = {
  "A+": "#00e5a0", A: "#00e5a0", B: "#4d9eff",
  C: "#ff8c00", D: "#ff3b3b", F: "#ff3b3b", "—": "#888",
};
const STATUS_COLOR = {
  active: "#00e5a0", disconnected: "#ff8c00",
  never_connected: "#888", unknown: "#888",
};
const TIER_LABEL = { 1: "Crown Jewel", 2: "Business Critical", 3: "Standard" };
const TIER_COLOR = { 1: "#ff3b3b", 2: "#ff8c00", 3: "#888" };

function GradeBadge({ grade, size = 28 }) {
  const color = GRADE_COLOR[grade] || "#888";
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", justifyContent: "center",
      width: size, height: size, borderRadius: 4,
      background: `${color}18`, border: `1px solid ${color}55`,
      color, fontFamily: "monospace", fontWeight: 700,
      fontSize: size * 0.45,
    }}>{grade || "—"}</span>
  );
}

function ScoreBar({ score, max = 100, color = "#4d9eff", height = 4 }) {
  const pct = score != null ? Math.max(0, Math.min(100, (score / max) * 100)) : 0;
  return (
    <div style={{ background: "rgba(255,255,255,0.06)", borderRadius: 2, height, overflow: "hidden" }}>
      <div style={{ width: `${pct}%`, height: "100%", background: color, transition: "width 0.4s" }} />
    </div>
  );
}

function InternalPostureBanner({ posture, onRefresh, refreshing }) {
  if (!posture) return null;
  const { score, grade, components = {}, host_count = {}, worst_hosts = [] } = posture;
  const gradeColor = GRADE_COLOR[grade] || "#888";

  return (
    <div style={{
      background: "rgba(0,229,160,0.04)", border: "1px solid rgba(0,229,160,0.15)",
      borderRadius: 8, padding: "16px 20px", marginBottom: 20,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12, flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
          <span style={{ color: "#888", fontSize: 11, letterSpacing: "1.5px" }}>INTERNAL SECURITY POSTURE</span>
          <span style={{ color: gradeColor, fontSize: 28, fontWeight: 700, fontFamily: "monospace" }}>
            {score != null ? score.toFixed(1) : "—"}
          </span>
          <GradeBadge grade={grade} size={32} />
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 16, fontSize: 11, color: "#888" }}>
          <span>{host_count.total ?? "—"} hosts total</span>
          <span style={{ color: "#00e5a0" }}>{host_count.active ?? "—"} active</span>
          {host_count.critical_grade > 0 && (
            <span style={{ color: "#ff3b3b" }}>{host_count.critical_grade} critical-grade</span>
          )}
          <button
            onClick={onRefresh} disabled={refreshing}
            style={{
              background: "rgba(0,229,160,0.08)", border: "1px solid rgba(0,229,160,0.25)",
              color: "#00e5a0", padding: "3px 10px", borderRadius: 3,
              fontFamily: "monospace", fontSize: 10, cursor: refreshing ? "not-allowed" : "pointer",
              opacity: refreshing ? 0.5 : 1,
            }}>
            {refreshing ? "Refreshing…" : "↻ Refresh"}
          </button>
        </div>
      </div>

      {/* Component breakdown */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        {Object.entries(components).map(([k, v]) => {
          const label = { sca: "SCA", vuln: "Vulns", siem_risk: "SIEM Risk", fim_malware: "FIM/Malware", compliance: "Compliance" }[k] || k;
          const c = v.score != null ? v.score : 50;
          const col = c >= 70 ? "#00e5a0" : c >= 50 ? "#ff8c00" : "#ff3b3b";
          return (
            <div key={k} style={{ minWidth: 100 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                <span style={{ fontSize: 10, color: "#888" }}>{label}</span>
                <span style={{ fontSize: 10, color: col, fontFamily: "monospace" }}>{c.toFixed(0)}</span>
              </div>
              <ScoreBar score={c} color={col} />
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function HostsPage() {
  const [hosts, setHosts]               = useState([]);
  const [posture, setPosture]           = useState(null);
  const [loading, setLoading]           = useState(true);
  const [error, setError]               = useState(null);
  const [selectedHost, setSelectedHost] = useState(null);
  const [statusFilter, setStatusFilter] = useState("all");
  const [sortBy, setSortBy]             = useState("posture_score");
  const [search, setSearch]             = useState("");
  const [page, setPage]                 = useState(1);
  const [total, setTotal]               = useState(0);
  const [refreshing, setRefreshing]     = useState(false);
  const PER_PAGE = 50;

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const qs = new URLSearchParams({
        status: statusFilter, sort: sortBy,
        page: String(page), per_page: String(PER_PAGE),
      });
      const res = await fetch(`${API}/hosts?${qs}`, { credentials: "include" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setHosts(data.hosts || []);
      setTotal(data.total || 0);
      if (data.internal_posture) setPosture(data.internal_posture);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [statusFilter, sortBy, page]);

  useEffect(() => { load(); }, [load]);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await fetch(`${API}/hosts/refresh`, { method: "POST", credentials: "include" });
      await load();
    } catch {}
    setRefreshing(false);
  };

  const filtered = search
    ? hosts.filter(h =>
        (h.agent_name || "").toLowerCase().includes(search.toLowerCase()) ||
        (h.agent_ip || "").includes(search)
      )
    : hosts;

  return (
    <div style={{ color: "#e8eaed", fontFamily: "monospace" }}>
      {/* Page header */}
      <div style={{ display: "flex", alignItems: "center", marginBottom: 16, gap: 12, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontSize: 11, color: "#888", letterSpacing: "1.5px", marginBottom: 2 }}>INTERNAL EXPOSURE</div>
          <h2 style={{ margin: 0, fontSize: 18, color: "#e8eaed", fontWeight: 600 }}>Host Inventory</h2>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 8, flexWrap: "wrap" }}>
          {/* Search */}
          <input
            placeholder="Search hostname or IP…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
              color: "#e8eaed", padding: "5px 10px", borderRadius: 4, fontSize: 11,
              fontFamily: "monospace", width: 200,
            }}
          />
          {/* Status filter */}
          <select
            value={statusFilter}
            onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
            style={{
              background: "#13161d", border: "1px solid rgba(255,255,255,0.12)",
              color: "#e8eaed", padding: "5px 8px", borderRadius: 4, fontSize: 11,
            }}>
            <option value="all">All Statuses</option>
            <option value="active">Active</option>
            <option value="disconnected">Disconnected</option>
          </select>
          {/* Sort */}
          <select
            value={sortBy}
            onChange={e => { setSortBy(e.target.value); setPage(1); }}
            style={{
              background: "#13161d", border: "1px solid rgba(255,255,255,0.12)",
              color: "#e8eaed", padding: "5px 8px", borderRadius: 4, fontSize: 11,
            }}>
            <option value="posture_score">Sort: Posture ↑</option>
            <option value="risk">Sort: Risk ↓</option>
            <option value="name">Sort: Name</option>
          </select>
        </div>
      </div>

      {/* Internal Posture Banner */}
      <InternalPostureBanner posture={posture} onRefresh={handleRefresh} refreshing={refreshing} />

      {/* Error */}
      {error && (
        <div style={{
          background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.3)",
          borderRadius: 6, padding: "10px 14px", marginBottom: 14,
          color: "#ff6b6b", fontSize: 12,
        }}>
          {error}
        </div>
      )}

      {/* Host table */}
      <div style={{
        background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
        borderRadius: 8, overflow: "hidden",
      }}>
        {/* Table header */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "32px 1fr 90px 60px 80px 70px 80px 100px",
          gap: 8, padding: "8px 14px",
          background: "rgba(255,255,255,0.03)",
          borderBottom: "1px solid rgba(255,255,255,0.06)",
          fontSize: 10, color: "#888", letterSpacing: "0.8px",
        }}>
          <div />
          <div>HOST</div>
          <div>POSTURE</div>
          <div>GRADE</div>
          <div>RISK</div>
          <div>VULNS</div>
          <div>INCIDENTS</div>
          <div>LAST SEEN</div>
        </div>

        {loading ? (
          <div style={{ padding: "40px 20px", textAlign: "center", color: "#888", fontSize: 12 }}>
            Loading hosts…
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: "40px 20px", textAlign: "center", color: "#888", fontSize: 12 }}>
            {search ? "No hosts match your search." : "No hosts found — ensure Wazuh agents are connected."}
          </div>
        ) : (
          filtered.map(host => {
            const grade = host.posture_grade || "—";
            const gradeCol = GRADE_COLOR[grade] || "#888";
            const statusCol = STATUS_COLOR[host.wazuh_status] || "#888";
            const critVulns = (host.vuln_critical || 0) + (host.vuln_high || 0);
            const lastSeen = host.last_keepalive
              ? new Date(host.last_keepalive).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
              : "—";

            return (
              <div
                key={host.agent_id}
                onClick={() => setSelectedHost(host.agent_id)}
                style={{
                  display: "grid",
                  gridTemplateColumns: "32px 1fr 90px 60px 80px 70px 80px 100px",
                  gap: 8, padding: "10px 14px",
                  borderBottom: "1px solid rgba(255,255,255,0.04)",
                  cursor: "pointer", transition: "background 0.15s",
                  alignItems: "center",
                }}
                onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.03)"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                {/* Status dot */}
                <div style={{ display: "flex", justifyContent: "center" }}>
                  <div style={{ width: 8, height: 8, borderRadius: "50%", background: statusCol }} />
                </div>

                {/* Host info */}
                <div>
                  <div style={{ fontSize: 13, color: "#e8eaed", fontWeight: 500 }}>
                    {host.agent_name || host.agent_id}
                    {host.asset_tier === 1 && <span style={{ marginLeft: 6, fontSize: 9, color: TIER_COLOR[1], background: "rgba(255,59,59,0.1)", padding: "1px 5px", borderRadius: 3 }}>CROWN JEWEL</span>}
                    {host.asset_tier === 2 && <span style={{ marginLeft: 6, fontSize: 9, color: TIER_COLOR[2], background: "rgba(255,140,0,0.1)", padding: "1px 5px", borderRadius: 3 }}>BIZ CRITICAL</span>}
                  </div>
                  <div style={{ fontSize: 10, color: "#888", marginTop: 1 }}>
                    {host.agent_ip || "—"} · {host.os_platform || "—"} · ID: {host.agent_id}
                  </div>
                </div>

                {/* Posture score + bar */}
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                    <span style={{ fontSize: 13, fontWeight: 600, color: gradeCol, fontFamily: "monospace" }}>
                      {host.posture_score != null ? host.posture_score.toFixed(0) : "—"}
                    </span>
                  </div>
                  <ScoreBar score={host.posture_score || 0} color={gradeCol} />
                </div>

                {/* Grade badge */}
                <div><GradeBadge grade={grade} size={26} /></div>

                {/* SIEM risk */}
                <div style={{ fontSize: 12, color: host.siem_risk > 70 ? "#ff3b3b" : host.siem_risk > 40 ? "#ff8c00" : "#00e5a0" }}>
                  {host.siem_risk != null ? host.siem_risk.toFixed(0) : "—"}
                  <span style={{ fontSize: 10, color: "#888" }}>/100</span>
                </div>

                {/* Critical vulns */}
                <div style={{ fontSize: 12, color: critVulns > 0 ? "#ff3b3b" : "#888" }}>
                  {critVulns > 0 ? `${critVulns} C/H` : "—"}
                </div>

                {/* Incidents */}
                <div style={{ fontSize: 12, color: host.incident_count > 0 ? "#ff8c00" : "#888" }}>
                  {host.incident_count > 0 ? `${host.incident_count} open` : "—"}
                </div>

                {/* Last seen */}
                <div style={{ fontSize: 10, color: "#888" }}>{lastSeen}</div>
              </div>
            );
          })
        )}
      </div>

      {/* Pagination */}
      {total > PER_PAGE && (
        <div style={{ display: "flex", justifyContent: "center", gap: 8, marginTop: 14 }}>
          <button
            disabled={page === 1}
            onClick={() => setPage(p => p - 1)}
            style={{
              background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
              color: "#e8eaed", padding: "5px 12px", borderRadius: 4,
              cursor: page === 1 ? "not-allowed" : "pointer", opacity: page === 1 ? 0.4 : 1,
            }}>← Prev</button>
          <span style={{ fontSize: 11, color: "#888", padding: "6px 0" }}>
            Page {page} of {Math.ceil(total / PER_PAGE)} ({total} hosts)
          </span>
          <button
            disabled={page * PER_PAGE >= total}
            onClick={() => setPage(p => p + 1)}
            style={{
              background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
              color: "#e8eaed", padding: "5px 12px", borderRadius: 4,
              cursor: page * PER_PAGE >= total ? "not-allowed" : "pointer",
              opacity: page * PER_PAGE >= total ? 0.4 : 1,
            }}>Next →</button>
        </div>
      )}

      {/* Host Detail Panel */}
      {selectedHost && (
        <HostDetailPanel
          agentId={selectedHost}
          onClose={() => setSelectedHost(null)}
        />
      )}
    </div>
  );
}
