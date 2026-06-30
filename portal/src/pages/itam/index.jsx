/**
 * pages/itam/index.jsx — ITAM Coverage Dashboard
 *
 * Unified view of all network assets, EDR/SIEM coverage gaps,
 * IoT device count, Shadow AI open findings, and Network Zones.
 * Tabs: All Assets | Uncovered | EDR Covered | Network Zones
 */
import React, { useEffect, useState, useCallback, useRef } from "react";

const BG      = "#0a0e1a";
const CARD_BG = "rgba(255,255,255,0.03)";
const BORDER  = "1px solid rgba(255,255,255,0.07)";
const ACCENT  = "#00e5a0";

const ASSET_TYPE_COLORS = {
  workstation:       "#4d9eff",
  laptop:            "#4d9eff",
  server:            "#f5c518",
  domain_controller: "#ff3b3b",
  database:          "#ff8c00",
  api_gateway:       "#b06eff",
  jump_server:       "#ff3b3b",
  ci_cd_node:        "#b06eff",
  iot_device:        "#f5c518",
  network_device:    "#00c4ff",
  camera:            "#9b59b6",
  printer:           "#95a5a6",
  smart_device:      "#1abc9c",
  industrial:        "#e74c3c",
  hvac_bms:          "#e67e22",
  unknown:           "#555",
};

const SOURCE_LABEL = {
  manual:     "Manual",
  arp_report: "ARP",
  nmap:       "Scan",
  edr_agent:  "EDR",
  siem_agent: "SIEM",
  aws:        "AWS",
  azure:      "Azure",
  mdns:       "mDNS",
  snmp:       "SNMP",
  cloud:      "Cloud",
};

const SOURCE_COLOR = {
  manual:     "#9aa0b0",
  arp_report: "#00c4ff",
  nmap:       "#f5c518",
  edr_agent:  "#00e5a0",
  siem_agent: "#4d9eff",
  aws:        "#ff9900",
  azure:      "#0089d6",
  mdns:       "#b06eff",
  snmp:       "#e67e22",
  cloud:      "#1abc9c",
};

function KpiCard({ label, value, sub, color, bg }) {
  return (
    <div style={{
      background: bg || CARD_BG, border: BORDER, borderRadius: 12,
      padding: "16px 20px", flex: "1 1 120px", minWidth: 110,
      borderTop: `3px solid ${color}`,
    }}>
      <div style={{ fontSize: 28, fontWeight: 800, color }}>{value ?? "—"}</div>
      <div style={{ fontSize: 11, color: "#666", marginTop: 3 }}>{label}</div>
      {sub && <div style={{ fontSize: 10, color: "#444", marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

function CoverageBar({ pct }) {
  const color = pct >= 80 ? ACCENT : pct >= 50 ? "#f5c518" : "#ff3b3b";
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
        <span style={{ fontSize: 11, color: "#666" }}>EDR Coverage</span>
        <span style={{ fontSize: 13, fontWeight: 700, color }}>{pct}%</span>
      </div>
      <div style={{ height: 8, background: "rgba(255,255,255,0.06)", borderRadius: 4, overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${Math.min(pct, 100)}%`, background: color, borderRadius: 4, transition: "width 0.6s ease" }}/>
      </div>
    </div>
  );
}

function Badge({ label, color }) {
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 4,
      background: `${color}22`, color, letterSpacing: 0.5,
    }}>{label}</span>
  );
}

// ── Scan Settings Panel ───────────────────────────────────────────────────────


function AssetTable({ assets, loading, onViewAsset }) {
  if (loading) return <div style={{ color: "#555", padding: 32, textAlign: "center" }}>Loading…</div>;
  if (!assets.length) return <div style={{ color: "#555", padding: 32, textAlign: "center" }}>No assets found.</div>;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
        <thead>
          <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
            {["IP Address", "Hostname", "Vendor", "Type", "EDR", "SIEM", "Source", "Vulns", "Last Seen"].map(h => (
              <th key={h} style={{ textAlign: "left", padding: "8px 12px", color: "#555", fontWeight: 600, fontSize: 10, letterSpacing: 0.5 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {assets.map((a, i) => (
            <tr key={a.id || i}
              onClick={() => a.id && onViewAsset && onViewAsset(a.id)}
              style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", cursor: a.id ? "pointer" : "default" }}
              onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.025)"}
              onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
              <td style={{ padding: "9px 12px", fontFamily: "monospace", color: ACCENT }}>{a.ip_address}</td>
              <td style={{ padding: "9px 12px", color: "#c0c8d8" }}>{a.hostname || "—"}</td>
              <td style={{ padding: "9px 12px", color: "#9aa0b0" }}>{a.vendor || "—"}</td>
              <td style={{ padding: "9px 12px" }}>
                <Badge label={(a.asset_type || "unknown").replace(/_/g, " ")}
                       color={ASSET_TYPE_COLORS[a.asset_type] || "#555"} />
              </td>
              <td style={{ padding: "9px 12px" }}>
                {a.edr_agent_id
                  ? <Badge label="EDR" color={ACCENT}/>
                  : <span style={{ color: "#333", fontSize: 10 }}>—</span>}
              </td>
              <td style={{ padding: "9px 12px" }}>
                {a.siem_agent_id
                  ? <Badge label="SIEM" color="#4d9eff"/>
                  : <span style={{ color: "#333", fontSize: 10 }}>—</span>}
              </td>
              <td style={{ padding: "9px 12px" }}>
                {(() => {
                  const src = a.source && a.source !== "manual"
                    ? a.source
                    : (a.discovery_source || a.source || "manual");
                  return (
                    <Badge label={SOURCE_LABEL[src] || src}
                           color={SOURCE_COLOR[src] || "#555"}/>
                  );
                })()}
              </td>
              <td style={{ padding: "9px 12px" }}>
                {a.vuln_count > 0
                  ? <span style={{ fontWeight: 700, color: a.highest_cve_severity === "critical" ? "#ff3b3b" : a.highest_cve_severity === "high" ? "#ff8c00" : "#f5c518" }}>
                      {a.vuln_count} {a.highest_cve_severity}
                    </span>
                  : <span style={{ color: "#333", fontSize: 10 }}>—</span>}
              </td>
              <td style={{ padding: "9px 12px", color: "#555", fontSize: 11 }}>
                {a.last_seen ? new Date(a.last_seen).toLocaleString() : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Network Zones Tab ─────────────────────────────────────────────────────────

function ZoneApproveModal({ suggestion, onClose, onApproved }) {
  const [zoneName, setZoneName] = useState("");
  const [notes,    setNotes]    = useState("");
  const [saving,   setSaving]   = useState(false);
  const [err,      setErr]      = useState("");

  const submit = async () => {
    if (!zoneName.trim()) { setErr("Zone name is required"); return; }
    setSaving(true); setErr("");
    try {
      const r = await fetch(`/api/itam/network-zones/suggestions/${suggestion.id}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ zone_name: zoneName.trim(), notes }),
      });
      const d = await r.json();
      if (!r.ok) { setErr(d.error || "Failed"); setSaving(false); return; }
      onApproved();
    } catch { setErr("Network error"); setSaving(false); }
  };

  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 9999,
    }}>
      <div style={{
        background: "#12182b", border: BORDER, borderRadius: 12,
        padding: 28, maxWidth: 460, width: "90%",
      }}>
        <div style={{ fontSize: 15, fontWeight: 700, color: "#e8eaf0", marginBottom: 6 }}>
          Approve Network Zone
        </div>
        <div style={{ fontSize: 11, color: "#555", marginBottom: 18 }}>
          Subnet: <span style={{ color: ACCENT, fontFamily: "monospace" }}>{suggestion.subnet_prefix}</span>
          &nbsp;·&nbsp;Gateway MAC: <span style={{ color: "#b06eff", fontFamily: "monospace" }}>{suggestion.gateway_mac}</span>
          &nbsp;·&nbsp;{suggestion.agent_count} reporting agents
        </div>
        {suggestion.case_id && suggestion.case_id !== "pending" && (
          <div style={{ fontSize: 11, color: "#f5c518", marginBottom: 14,
            background: "#f5c51814", border: "1px solid #f5c51844",
            borderRadius: 6, padding: "6px 10px" }}>
            CyCase raised: <span style={{ fontFamily: "monospace" }}>{suggestion.case_id.slice(0, 8)}…</span>
          </div>
        )}
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 11, color: "#555", marginBottom: 4 }}>Zone Name *</div>
          <input
            value={zoneName} onChange={e => setZoneName(e.target.value)}
            placeholder="e.g. London HQ, NYC Office, Corporate VPN"
            style={{
              width: "100%", background: CARD_BG, border: BORDER, borderRadius: 6,
              padding: "7px 10px", fontSize: 12, color: "#c0c8d8", outline: "none",
              boxSizing: "border-box",
            }}
          />
        </div>
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, color: "#555", marginBottom: 4 }}>Notes (optional)</div>
          <input
            value={notes} onChange={e => setNotes(e.target.value)}
            placeholder="Office location, network owner…"
            style={{
              width: "100%", background: CARD_BG, border: BORDER, borderRadius: 6,
              padding: "7px 10px", fontSize: 12, color: "#c0c8d8", outline: "none",
              boxSizing: "border-box",
            }}
          />
        </div>
        {err && <div style={{ fontSize: 11, color: "#ff3b3b", marginBottom: 10 }}>{err}</div>}
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button onClick={onClose} style={{
            border: BORDER, borderRadius: 6, padding: "6px 16px",
            background: "transparent", color: "#9aa0b0", cursor: "pointer", fontSize: 12,
          }}>Cancel</button>
          <button onClick={submit} disabled={saving} style={{
            border: "none", borderRadius: 6, padding: "6px 16px",
            background: ACCENT, color: "#0a0e1a", fontWeight: 700, cursor: saving ? "not-allowed" : "pointer", fontSize: 12,
          }}>{saving ? "Approving…" : "Approve Zone"}</button>
        </div>
      </div>
    </div>
  );
}

function NetworkZonesTab() {
  const [zones,       setZones]       = useState([]);
  const [suggestions, setSuggestions] = useState([]);
  const [stats,       setStats]       = useState(null);
  const [loading,     setLoading]     = useState(true);
  const [approveModal,setApproveModal]= useState(null);
  const [msg,         setMsg]         = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [zRes, sRes, stRes] = await Promise.all([
        fetch("/api/itam/network-zones"),
        fetch("/api/itam/network-zones/suggestions?status=pending"),
        fetch("/api/itam/network-zones/stats"),
      ]);
      if (zRes.ok)  setZones((await zRes.json()).zones || []);
      if (sRes.ok)  setSuggestions((await sRes.json()).suggestions || []);
      if (stRes.ok) setStats(await stRes.json());
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const reject = async (sug) => {
    const r = await fetch(`/api/itam/network-zones/suggestions/${sug.id}/reject`, { method: "POST" });
    if (r.ok) { setMsg("Suggestion rejected"); load(); }
  };

  const deleteZone = async (zone) => {
    if (!window.confirm(`Delete zone "${zone.zone_name}"? ARP discovery will revert to untrusted for this subnet.`)) return;
    const r = await fetch(`/api/itam/network-zones/${zone.id}`, { method: "DELETE" });
    if (r.ok) { setMsg(`Zone "${zone.zone_name}" deleted`); load(); }
  };

  if (loading) return <div style={{ color: "#555", padding: 40, textAlign: "center" }}>Loading…</div>;

  return (
    <div>
      {/* Stats bar */}
      {stats && (
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
          {[
            { label: "Approved Zones",    value: stats.approved_zones,    color: ACCENT },
            { label: "Pending Approval",  value: stats.pending_approval,  color: "#f5c518" },
            { label: "Agents ARP Active", value: stats.agents_arp_active, color: "#00e5a0" },
            { label: "Agents ARP Blocked",value: stats.agents_arp_blocked,color: "#ff3b3b" },
          ].map(({ label, value, color }) => (
            <div key={label} style={{
              background: CARD_BG, border: BORDER, borderRadius: 10,
              padding: "12px 18px", flex: "1 1 120px",
            }}>
              <div style={{ fontSize: 24, fontWeight: 800, color }}>{value ?? 0}</div>
              <div style={{ fontSize: 11, color: "#555", marginTop: 2 }}>{label}</div>
            </div>
          ))}
        </div>
      )}

      {msg && (
        <div style={{ marginBottom: 14, padding: "8px 14px", borderRadius: 6, fontSize: 12,
          background: "rgba(0,229,160,0.1)", border: `1px solid ${ACCENT}44`, color: ACCENT }}>
          {msg}
        </div>
      )}

      {/* Pending suggestions panel */}
      {suggestions.length > 0 && (
        <div style={{ background: "rgba(245,197,24,0.05)", border: "1px solid #f5c51844",
          borderRadius: 12, padding: 20, marginBottom: 24 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
            <span style={{ fontSize: 14 }}>⏳</span>
            <span style={{ fontWeight: 700, color: "#f5c518", fontSize: 13 }}>
              Pending Admin Approval ({suggestions.length})
            </span>
            <span style={{ fontSize: 11, color: "#666" }}>— CyCase raised for each</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {suggestions.map(s => (
              <div key={s.id} style={{
                background: CARD_BG, border: BORDER, borderRadius: 8,
                padding: "14px 16px", display: "flex", alignItems: "center",
                gap: 16, flexWrap: "wrap",
              }}>
                <div style={{ flex: 1, minWidth: 200 }}>
                  <div style={{ fontFamily: "monospace", fontSize: 13, color: ACCENT }}>{s.subnet_prefix}</div>
                  <div style={{ fontSize: 11, color: "#9aa0b0", marginTop: 3 }}>
                    GW MAC: <span style={{ fontFamily: "monospace", color: "#b06eff" }}>{s.gateway_mac}</span>
                    {s.gateway_ip && <span style={{ color: "#555" }}> ({s.gateway_ip})</span>}
                  </div>
                </div>
                <div style={{ minWidth: 80 }}>
                  <div style={{ fontSize: 11, color: "#555" }}>Agents</div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: "#f5c518" }}>{s.agent_count}</div>
                </div>
                {s.case_id && s.case_id !== "pending" && (
                  <div style={{ minWidth: 120 }}>
                    <div style={{ fontSize: 10, color: "#555" }}>CyCase</div>
                    <div style={{ fontSize: 11, fontFamily: "monospace", color: "#f5c518" }}>
                      {s.case_id.slice(0, 8)}…
                    </div>
                  </div>
                )}
                <div style={{ fontSize: 11, color: "#555" }}>
                  {new Date(s.created_at).toLocaleDateString()}
                </div>
                <div style={{ display: "flex", gap: 6 }}>
                  <button onClick={() => setApproveModal(s)} style={{
                    border: `1px solid ${ACCENT}44`, borderRadius: 6, padding: "5px 12px",
                    background: `${ACCENT}18`, color: ACCENT, fontSize: 11, fontWeight: 700, cursor: "pointer",
                  }}>Approve</button>
                  <button onClick={() => reject(s)} style={{
                    border: "1px solid #ff3b3b44", borderRadius: 6, padding: "5px 12px",
                    background: "rgba(255,59,59,0.08)", color: "#ff3b3b", fontSize: 11, fontWeight: 700, cursor: "pointer",
                  }}>Reject</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {suggestions.length === 0 && (
        <div style={{ background: "rgba(0,229,160,0.04)", border: `1px solid ${ACCENT}22`,
          borderRadius: 8, padding: "12px 16px", marginBottom: 20, fontSize: 12, color: "#555" }}>
          No pending zone suggestions — all discovered networks are either approved or rejected.
        </div>
      )}

      {/* Approved zones table */}
      <div style={{ background: CARD_BG, border: BORDER, borderRadius: 12, overflow: "hidden", marginBottom: 20 }}>
        <div style={{ padding: "14px 18px", borderBottom: BORDER, fontSize: 12,
          fontWeight: 700, color: "#555", letterSpacing: 0.5 }}>
          APPROVED ZONES — ARP DISCOVERY ENABLED
        </div>
        {zones.filter(z => z.status === "approved").length === 0 ? (
          <div style={{ padding: 32, textAlign: "center", color: "#444", fontSize: 12 }}>
            No approved zones yet. Approve a pending suggestion above, or create one manually.
          </div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: BORDER }}>
                {["Zone Name", "Trusted CIDRs", "Gateway MACs", "Active Agents", "Source", "Approved By", "Actions"].map(h => (
                  <th key={h} style={{ textAlign: "left", padding: "8px 14px",
                    color: "#555", fontWeight: 600, fontSize: 10, letterSpacing: 0.5 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {zones.filter(z => z.status === "approved").map(z => {
                const gws = Array.isArray(z.trusted_gateways)
                  ? z.trusted_gateways
                  : (typeof z.trusted_gateways === "string" ? JSON.parse(z.trusted_gateways || "[]") : []);
                const allMacs = gws.flatMap(g => g.macs || []);
                return (
                  <tr key={z.id}
                    style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}
                    onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.025)"}
                    onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                    <td style={{ padding: "10px 14px", fontWeight: 700, color: "#e8eaf0" }}>
                      {z.zone_name}
                    </td>
                    <td style={{ padding: "10px 14px" }}>
                      {(z.trusted_cidrs || []).map(c => (
                        <div key={c} style={{ fontFamily: "monospace", color: ACCENT, fontSize: 11 }}>{c}</div>
                      ))}
                    </td>
                    <td style={{ padding: "10px 14px" }}>
                      {allMacs.length === 0
                        ? <span style={{ color: "#444", fontSize: 11 }}>VPN / CIDR only</span>
                        : allMacs.map(m => (
                            <div key={m} style={{ fontFamily: "monospace", color: "#b06eff", fontSize: 11 }}>{m}</div>
                          ))}
                    </td>
                    <td style={{ padding: "10px 14px", color: z.live_agent_count > 0 ? "#00e5a0" : "#555",
                      fontWeight: 700, fontSize: 14 }}>
                      {z.live_agent_count ?? 0}
                    </td>
                    <td style={{ padding: "10px 14px" }}>
                      <span style={{
                        fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 4,
                        background: z.auto_discovered ? "rgba(176,110,255,0.15)" : "rgba(0,229,160,0.1)",
                        color: z.auto_discovered ? "#b06eff" : ACCENT,
                      }}>{z.auto_discovered ? "AUTO" : "MANUAL"}</span>
                    </td>
                    <td style={{ padding: "10px 14px", color: "#9aa0b0", fontSize: 11 }}>
                      {z.approved_by || "—"}
                    </td>
                    <td style={{ padding: "10px 14px" }}>
                      <button onClick={() => deleteZone(z)} style={{
                        border: "1px solid #ff3b3b44", borderRadius: 5, padding: "3px 10px",
                        background: "transparent", color: "#ff3b3b", fontSize: 11, cursor: "pointer",
                      }}>Delete</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div style={{ fontSize: 11, color: "#444", lineHeight: 1.7 }}>
        <strong style={{ color: "#666" }}>How it works:</strong>{" "}
        CyEDR agents report their default gateway MAC on every heartbeat. When 3+ agents on the same
        subnet share a gateway, a suggestion is auto-created and a CyCase is raised. Approving a
        suggestion adds the subnet + gateway MAC to this list and enables ARP asset discovery for
        those endpoints. Agents on untrusted networks (home/hotel/cafe) skip ARP collection automatically.
      </div>

      {approveModal && (
        <ZoneApproveModal
          suggestion={approveModal}
          onClose={() => setApproveModal(null)}
          onApproved={() => { setApproveModal(null); setMsg("Zone approved — ARP discovery enabled"); load(); }}
        />
      )}
    </div>
  );
}

export default function ItamCoveragePage({ onViewAsset, user }) {
  const [coverage,         setCoverage]         = useState(null);
  const [assets,           setAssets]           = useState([]);
  const [total,            setTotal]            = useState(0);
  const [page,             setPage]             = useState(1);
  const [tab,              setTab]              = useState("all");
  const [search,           setSearch]           = useState("");
  const [loading,          setLoading]          = useState(true);
  const [importing,        setImporting]        = useState(false);
  const [scanning,         setScanning]         = useState(false);
  const [importResult,     setImportResult]     = useState(null);
  const [scanMsg,          setScanMsg]          = useState("");
  const [configuredSubnet, setConfiguredSubnet] = useState("");
  // Load configured subnet silently so scan button can use it
  useEffect(() => {
    fetch("/api/itam/settings").then(r => r.ok ? r.json() : null).then(d => {
      if (d?.scan_subnet) setConfiguredSubnet(d.scan_subnet);
    }).catch(() => {});
  }, []);

  const PER_PAGE = 50;

  const loadCoverage = async () => {
    try {
      const r = await fetch("/api/itam/coverage");
      if (r.ok) setCoverage(await r.json());
    } catch {}
  };

  const loadAssets = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams({ page, per_page: PER_PAGE });
    if (tab === "uncovered") params.set("covered", "no");
    if (tab === "edr")       params.set("covered", "edr");
    if (tab === "iot")       params.set("asset_type", "iot_device");
    if (search)              params.set("q", search);
    try {
      const r = await fetch(`/api/itam/assets?${params}`);
      if (r.ok) { const d = await r.json(); setAssets(d.assets || []); setTotal(d.total || 0); }
    } catch {}
    setLoading(false);
  }, [tab, page, search]);

  useEffect(() => { loadCoverage(); }, []);
  useEffect(() => { setPage(1); }, [tab, search]);
  useEffect(() => { loadAssets(); }, [loadAssets]);

  const handleImport = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImporting(true); setImportResult(null);
    const fd = new FormData(); fd.append("file", file);
    try {
      const r = await fetch("/api/itam/assets/import", { method: "POST", body: fd });
      const d = await r.json();
      setImportResult(r.ok ? `Imported ${d.imported} assets` : (d.error || "Import failed"));
      if (r.ok) { loadCoverage(); loadAssets(); }
    } catch { setImportResult("Network error"); }
    setImporting(false);
    e.target.value = "";
  };

  const handleScan = async () => {
    setScanning(true); setScanMsg("");
    try {
      const body = configuredSubnet ? { subnet: configuredSubnet } : {};
      const r = await fetch("/api/itam/assets/scan", { method: "POST",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const d = await r.json();
      setScanMsg(r.ok ? `Scan started for ${d.subnet}` : (d.error || "Scan failed"));
      if (r.ok) setTimeout(() => { loadCoverage(); loadAssets(); }, 8000);
    } catch { setScanMsg("Network error"); }
    setScanning(false);
  };

  const cov = coverage;

  return (
    <div style={{ color: "#e8eaf0" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 20 }}>🗂️</span>
            <h2 style={{ margin: 0, fontSize: 20, fontWeight: 700 }}>Asset Coverage Dashboard</h2>
            <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: 1.5, color: ACCENT,
              border: `1px solid ${ACCENT}44`, padding: "2px 8px", borderRadius: 4 }}>ITAM</span>
          </div>
          <div style={{ fontSize: 12, color: "#555", marginTop: 4 }}>
            Network asset inventory — EDR coverage, IoT registry, Shadow AI exposure
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <label style={{
            border: `1px solid rgba(255,255,255,0.12)`, borderRadius: 6,
            padding: "6px 14px", fontSize: 11, fontWeight: 600, color: ACCENT,
            cursor: "pointer", background: "rgba(0,229,160,0.06)",
          }}>
            {importing ? "Importing…" : "⬆ Import CMDB"}
            <input type="file" accept=".csv" style={{ display: "none" }} onChange={handleImport}/>
          </label>
          <button onClick={handleScan} disabled={scanning} style={{
            border: `1px solid rgba(255,255,255,0.12)`, borderRadius: 6,
            padding: "6px 14px", fontSize: 11, fontWeight: 600, color: "#4d9eff",
            cursor: scanning ? "not-allowed" : "pointer", background: "rgba(77,158,255,0.06)",
          }}>
            {scanning ? "Scanning…" : "🔍 Subnet Scan"}
          </button>
        </div>
      </div>

      {/* Status messages */}
      {importResult && (
        <div style={{ marginBottom: 16, padding: "8px 14px", borderRadius: 6,
          background: importResult.startsWith("Imported") ? "rgba(0,229,160,0.1)" : "rgba(255,59,59,0.1)",
          border: `1px solid ${importResult.startsWith("Imported") ? ACCENT : "#ff3b3b"}44`,
          fontSize: 12, color: importResult.startsWith("Imported") ? ACCENT : "#ff3b3b" }}>
          {importResult}
        </div>
      )}
      {scanMsg && (
        <div style={{ marginBottom: 16, padding: "8px 14px", borderRadius: 6,
          background: scanMsg.includes("failed") || scanMsg.includes("error") ? "rgba(255,59,59,0.1)" : "rgba(77,158,255,0.1)",
          border: `1px solid ${scanMsg.includes("failed") || scanMsg.includes("error") ? "#ff3b3b" : "#4d9eff"}44`,
          fontSize: 12, color: scanMsg.includes("failed") || scanMsg.includes("error") ? "#ff3b3b" : "#4d9eff" }}>
          {scanMsg}
        </div>
      )}

      {/* KPI Row */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
        <KpiCard label="Total Assets" value={cov?.total_network_assets ?? 0} color={ACCENT}/>
        <KpiCard label="EDR Covered" value={cov?.edr_covered ?? 0}
          sub={cov ? `${cov.coverage_pct}%` : ""} color="#00e5a0"/>
        <KpiCard label="SIEM Covered" value={cov?.siem_covered ?? 0} color="#4d9eff"/>
        <KpiCard label="Uncovered" value={cov?.uncovered ?? 0} color="#ff3b3b"/>
        <KpiCard label="IoT Devices" value={cov?.iot_devices ?? 0} color="#f5c518"/>
        <KpiCard label="Shadow AI" value={cov?.shadow_ai_open ?? 0}
          sub="open findings" color={cov?.shadow_ai_open > 0 ? "#b06eff" : "#555"}/>
        <div
          onClick={() => setTab("zones")}
          style={{ cursor: "pointer" }}>
          <KpiCard label="Network Zones" value={cov?.pending_zones ?? "→"}
            sub="click to manage" color="#b06eff"/>
        </div>
      </div>

      {/* Coverage bar */}
      {cov && (
        <div style={{ background: CARD_BG, border: BORDER, borderRadius: 12, padding: "16px 20px", marginBottom: 24 }}>
          <CoverageBar pct={cov.coverage_pct || 0}/>
          <div style={{ display: "flex", gap: 24, marginTop: 12, flexWrap: "wrap" }}>
            {Object.entries(cov.sources || {}).map(([src, n]) => (
              <div key={src} style={{ fontSize: 11, display: "flex", alignItems: "center", gap: 4 }}>
                <span style={{
                  display: "inline-block", width: 6, height: 6, borderRadius: "50%",
                  background: SOURCE_COLOR[src] || "#555",
                }}/>
                <span style={{ color: "#666" }}>{SOURCE_LABEL[src] || src}</span>
                <span style={{ color: "#9aa0b0", fontWeight: 700 }}>{n}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Asset type breakdown */}
      {cov?.breakdown && Object.keys(cov.breakdown).length > 0 && (
        <div style={{ background: CARD_BG, border: BORDER, borderRadius: 12, padding: "16px 20px", marginBottom: 24 }}>
          <div style={{ fontSize: 11, color: "#555", fontWeight: 600, marginBottom: 12, letterSpacing: 0.5 }}>BREAKDOWN BY ASSET TYPE</div>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            {Object.entries(cov.breakdown).map(([type, counts]) => (
              <div key={type} style={{
                background: "rgba(255,255,255,0.03)", border: BORDER, borderRadius: 8,
                padding: "10px 14px", minWidth: 120,
                borderLeft: `3px solid ${ASSET_TYPE_COLORS[type] || "#555"}`,
              }}>
                <div style={{ fontSize: 10, color: "#555", marginBottom: 4 }}>{type.replace(/_/g, " ").toUpperCase()}</div>
                <div style={{ fontSize: 18, fontWeight: 700, color: ASSET_TYPE_COLORS[type] || "#888" }}>{counts.total}</div>
                <div style={{ fontSize: 10, color: "#444", marginTop: 2 }}>
                  EDR: {counts.edr_covered} · SIEM: {counts.siem_covered}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tabs + search */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
        <div style={{ display: "flex", gap: 4 }}>
          {[
            { id: "all",       label: "All Assets" },
            { id: "uncovered", label: `Uncovered (${cov?.uncovered ?? 0})` },
            { id: "edr",       label: `EDR Covered (${cov?.edr_covered ?? 0})` },
            { id: "zones",     label: "🌐 Network Zones" },
          ].map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              border: tab === t.id ? `1px solid ${t.id === "zones" ? "#b06eff" : ACCENT}` : BORDER,
              borderRadius: 6, padding: "6px 14px", fontSize: 11, fontWeight: 600,
              background: tab === t.id ? (t.id === "zones" ? "#b06eff18" : `${ACCENT}18`) : "transparent",
              color: tab === t.id ? (t.id === "zones" ? "#b06eff" : ACCENT) : "#666", cursor: "pointer",
            }}>{t.label}</button>
          ))}
        </div>
        {tab !== "zones" && (
          <input
            value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search IP, hostname, vendor…"
            style={{
              background: CARD_BG, border: BORDER, borderRadius: 6,
              padding: "6px 12px", fontSize: 12, color: "#c0c8d8",
              outline: "none", width: 220,
            }}
          />
        )}
      </div>

      {/* Network Zones tab */}
      {tab === "zones" && <NetworkZonesTab />}

      {/* Asset table (all non-zones tabs) */}
      {tab !== "zones" && (
        <div style={{ background: CARD_BG, border: BORDER, borderRadius: 12, overflow: "hidden" }}>
          <AssetTable assets={assets} loading={loading} onViewAsset={onViewAsset}/>
          {total > PER_PAGE && (
            <div style={{ display: "flex", justifyContent: "center", gap: 8, padding: 16 }}>
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                style={{ border: BORDER, borderRadius: 6, padding: "4px 12px", background: "transparent",
                  color: page === 1 ? "#333" : "#9aa0b0", cursor: page === 1 ? "not-allowed" : "pointer" }}>
                ← Prev
              </button>
              <span style={{ color: "#555", fontSize: 11, alignSelf: "center" }}>
                Page {page} of {Math.ceil(total / PER_PAGE)}
              </span>
              <button onClick={() => setPage(p => p + 1)} disabled={page >= Math.ceil(total / PER_PAGE)}
                style={{ border: BORDER, borderRadius: 6, padding: "4px 12px", background: "transparent",
                  color: page >= Math.ceil(total / PER_PAGE) ? "#333" : "#9aa0b0",
                  cursor: page >= Math.ceil(total / PER_PAGE) ? "not-allowed" : "pointer" }}>
                Next →
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
