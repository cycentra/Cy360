/**
 * pages/itam/IotRegistryPage.jsx — IoT Device Registry
 *
 * Displays discovered IoT, OT, and unmanaged network devices.
 * Risk-scored by OUI vendor, open ports, telnet, default creds.
 */
import React, { useEffect, useState, useCallback } from "react";

const CARD_BG = "rgba(255,255,255,0.03)";
const BORDER  = "1px solid rgba(255,255,255,0.07)";
const ACCENT  = "#00e5a0";

const RISK_COLOR = (score) => {
  if (score >= 75) return "#ff3b3b";
  if (score >= 50) return "#ff8c00";
  if (score >= 25) return "#f5c518";
  return ACCENT;
};

const RISK_LABEL = (score) => {
  if (score >= 75) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 25) return "MEDIUM";
  return "LOW";
};

const CATEGORY_ICONS = {
  camera:         "📷",
  printer:        "🖨️",
  network_device: "🔀",
  smart_device:   "💡",
  hvac_bms:       "🌡️",
  industrial:     "⚙️",
  embedded:       "🔧",
  iot_device:     "📡",
  unknown:        "❓",
};

function RiskBadge({ score }) {
  const color = RISK_COLOR(score);
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <div style={{ width: 8, height: 8, borderRadius: "50%", background: color, boxShadow: `0 0 6px ${color}` }}/>
      <span style={{ fontSize: 10, fontWeight: 700, color, letterSpacing: 0.5 }}>{RISK_LABEL(score)}</span>
      <span style={{ fontSize: 11, color, fontWeight: 700 }}>{score}</span>
    </div>
  );
}

function KpiCard({ label, value, color }) {
  return (
    <div style={{ background: CARD_BG, border: BORDER, borderRadius: 10, padding: "14px 18px",
      flex: "1 1 100px", minWidth: 100, borderTop: `3px solid ${color}` }}>
      <div style={{ fontSize: 24, fontWeight: 800, color }}>{value}</div>
      <div style={{ fontSize: 11, color: "#555", marginTop: 2 }}>{label}</div>
    </div>
  );
}

export default function IotRegistryPage() {
  const [devices,          setDevices]          = useState([]);
  const [summary,          setSummary]          = useState(null);
  const [total,            setTotal]            = useState(0);
  const [page,             setPage]             = useState(1);
  const [riskMin,          setRiskMin]          = useState(0);
  const [scanning,         setScanning]         = useState(false);
  const [scanMsg,          setScanMsg]          = useState("");
  const [scanMode,         setScanMode]         = useState("");  // "probe" | "local" | ""
  const [loading,          setLoading]          = useState(true);
  const [selected,         setSelected]         = useState(null);
  const [configuredSubnet, setConfiguredSubnet] = useState("");
  const [probes,           setProbes]           = useState([]);  // active probe agents

  const PER_PAGE = 50;

  const loadSummary = async () => {
    try {
      const r = await fetch("/api/itam/iot/risk-summary");
      if (r.ok) setSummary(await r.json());
    } catch {}
  };

  const loadDevices = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams({ page, per_page: PER_PAGE });
    if (riskMin) params.set("risk_min", riskMin);
    try {
      const r = await fetch(`/api/itam/iot?${params}`);
      if (r.ok) { const d = await r.json(); setDevices(d.devices || []); setTotal(d.total || 0); }
    } catch {}
    setLoading(false);
  }, [page, riskMin]);

  const loadSettings = async () => {
    try {
      const r = await fetch("/api/itam/settings");
      if (r.ok) { const d = await r.json(); setConfiguredSubnet(d.scan_subnet || ""); }
    } catch {}
  };

  const loadProbes = async () => {
    try {
      const r = await fetch("/api/itam/probe/status");
      if (r.ok) { const d = await r.json(); setProbes(d.probes || []); }
    } catch {}
  };

  useEffect(() => { loadSummary(); loadSettings(); loadProbes(); }, []);
  useEffect(() => { loadDevices(); }, [loadDevices]);

  const handleScan = async () => {
    setScanning(true); setScanMsg(""); setScanMode("");
    try {
      const body = configuredSubnet ? { subnet: configuredSubnet } : {};
      const r = await fetch("/api/itam/iot/scan", { method: "POST",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const d = await r.json();
      if (r.ok) {
        setScanMode(d.mode || "local");
        if (d.mode === "probe") {
          setScanMsg(`Scan dispatched to probe agent "${d.probe_agent}" for ${d.subnet}`);
        } else {
          setScanMsg(`IoT scan started for ${d.subnet}${d.warning ? " — ⚠ " + d.warning : ""}`);
        }
        setTimeout(() => { loadSummary(); loadDevices(); }, 12000);
      } else {
        setScanMsg(d.error || "Scan failed");
      }
    } catch { setScanMsg("Network error"); }
    setScanning(false);
  };

  return (
    <div style={{ color: "#e8eaf0" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 20 }}>📡</span>
            <h2 style={{ margin: 0, fontSize: 20, fontWeight: 700 }}>IoT Device Registry</h2>
            <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: 1.5, color: "#f5c518",
              border: "1px solid #f5c51844", padding: "2px 8px", borderRadius: 4 }}>UNMANAGED</span>
          </div>
          <div style={{ fontSize: 12, color: "#555", marginTop: 4 }}>
            Non-agent devices discovered via network scanning and ARP — cameras, printers, HVAC, OT
          </div>
        </div>
        <button onClick={handleScan} disabled={scanning} style={{
          border: "1px solid rgba(255,255,255,0.12)", borderRadius: 6,
          padding: "6px 14px", fontSize: 11, fontWeight: 600, color: "#f5c518",
          cursor: scanning ? "not-allowed" : "pointer", background: "rgba(245,197,24,0.06)",
        }}>
          {scanning ? "Scanning…" : "🔍 Run IoT Scan"}
        </button>
      </div>

      {/* Network Probe status banner */}
      {probes.length > 0 ? (
        <div style={{ marginBottom: 12, padding: "8px 14px", borderRadius: 6,
          background: "rgba(0,212,255,0.06)", border: "1px solid rgba(0,212,255,0.25)",
          fontSize: 12, color: "#00d4ff", display: "flex", alignItems: "center", gap: 8 }}>
          <span>📡</span>
          <span>
            <strong>Network Probe active</strong> — IoT scan runs from{" "}
            <strong>{probes.map(p => p.hostname || p.agent_id).join(", ")}</strong>{" "}
            inside your LAN. NAT/firewall is transparent.
          </span>
          {probes[0]?.probe_last_scan && (
            <span style={{ color: "#555", marginLeft: "auto", whiteSpace: "nowrap" }}>
              Last scan: {new Date(probes[0].probe_last_scan).toLocaleString()}
            </span>
          )}
        </div>
      ) : (
        <div style={{ marginBottom: 12, padding: "8px 14px", borderRadius: 6,
          background: "rgba(245,197,24,0.06)", border: "1px solid rgba(245,197,24,0.25)",
          fontSize: 12, color: "#f5c518" }}>
          <strong>No Network Probe configured.</strong>{" "}
          Scans run from the cloud server and will fail for private subnets behind NAT/firewall.
          Go to <strong>Endpoint Defence &gt; Policies</strong> and create a{" "}
          <strong>Network Probe</strong> policy, then assign it to one agent on this network.
        </div>
      )}

      {!configuredSubnet && (
        <div style={{ marginBottom: 14, padding: "8px 14px", borderRadius: 6,
          background: "rgba(255,140,0,0.08)", border: "1px solid #ff8c0044",
          fontSize: 12, color: "#ff8c00" }}>
          ⚠ No subnet configured — go to <strong>Asset Coverage &gt; Scan Settings</strong> to set your network CIDR before scanning.
        </div>
      )}
      {configuredSubnet && (
        <div style={{ marginBottom: 14, padding: "6px 12px", borderRadius: 6,
          background: "rgba(0,229,160,0.06)", border: "1px solid rgba(0,229,160,0.2)",
          fontSize: 11, color: "#9aa0b0", display: "inline-flex", alignItems: "center", gap: 6 }}>
          Scanning subnet: <span style={{ fontFamily: "monospace", color: ACCENT }}>{configuredSubnet}</span>
          <span style={{ color: "#555", fontSize: 10 }}>— edit in Asset Coverage &gt; Scan Settings</span>
        </div>
      )}
      {scanMsg && (() => {
        const isErr  = scanMsg.includes("failed") || scanMsg.includes("error");
        const isProbe = scanMode === "probe";
        const bg     = isErr ? "rgba(255,59,59,0.1)" : isProbe ? "rgba(0,212,255,0.08)" : "rgba(245,197,24,0.1)";
        const clr    = isErr ? "#ff3b3b" : isProbe ? "#00d4ff" : "#f5c518";
        return (
          <div style={{ marginBottom: 16, marginTop: configuredSubnet ? 8 : 0, padding: "8px 14px",
            borderRadius: 6, background: bg, border: `1px solid ${clr}44`, fontSize: 12, color: clr }}>
            {scanMsg}
          </div>
        );
      })()}

      {/* KPI row */}
      {summary && (
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
          <KpiCard label="Total IoT Devices" value={summary.total || 0} color="#f5c518"/>
          <KpiCard label="Critical Risk"      value={summary.critical || 0} color="#ff3b3b"/>
          <KpiCard label="High Risk"          value={summary.high || 0}     color="#ff8c00"/>
          <KpiCard label="Medium Risk"        value={summary.medium || 0}   color="#f5c518"/>
          <KpiCard label="Default Creds"      value={summary.default_creds || 0} color="#ff3b3b"/>
        </div>
      )}

      {/* Category breakdown */}
      {summary?.by_category && Object.keys(summary.by_category).length > 0 && (
        <div style={{ background: CARD_BG, border: BORDER, borderRadius: 12, padding: "14px 18px", marginBottom: 24 }}>
          <div style={{ fontSize: 10, color: "#555", fontWeight: 600, letterSpacing: 0.5, marginBottom: 10 }}>BY DEVICE CATEGORY</div>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            {Object.entries(summary.by_category).map(([cat, n]) => (
              <div key={cat} style={{ background: "rgba(255,255,255,0.03)", border: BORDER, borderRadius: 8, padding: "8px 12px" }}>
                <span style={{ marginRight: 6 }}>{CATEGORY_ICONS[cat] || "📡"}</span>
                <span style={{ fontSize: 12, color: "#9aa0b0" }}>{cat.replace(/_/g, " ")}</span>
                <span style={{ fontSize: 14, fontWeight: 700, color: "#e8eaf0", marginLeft: 8 }}>{n}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Risk filter + table */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
        <span style={{ fontSize: 11, color: "#555" }}>Min Risk Score:</span>
        {[0, 25, 50, 75].map(r => (
          <button key={r} onClick={() => setRiskMin(r)} style={{
            border: riskMin === r ? `1px solid ${RISK_COLOR(r || 1)}` : BORDER,
            borderRadius: 6, padding: "4px 12px", fontSize: 11,
            background: riskMin === r ? `${RISK_COLOR(r || 1)}18` : "transparent",
            color: riskMin === r ? RISK_COLOR(r || 1) : "#555", cursor: "pointer",
          }}>
            {r === 0 ? "All" : `≥${r}`}
          </button>
        ))}
      </div>

      <div style={{ background: CARD_BG, border: BORDER, borderRadius: 12, overflow: "hidden" }}>
        {loading
          ? <div style={{ padding: 32, textAlign: "center", color: "#555" }}>Loading…</div>
          : devices.length === 0
          ? <div style={{ padding: 32, textAlign: "center", color: "#555" }}>
              No IoT devices found. Run a subnet scan or import CMDB to populate the registry.
            </div>
          : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
                    {["", "IP", "Vendor", "Category", "Open Ports", "Risk", "Default Creds", "Last Seen"].map(h => (
                      <th key={h} style={{ padding: "8px 12px", textAlign: "left", color: "#555", fontSize: 10, fontWeight: 600, letterSpacing: 0.5 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d, i) => (
                    <tr key={d.id || i}
                      onClick={() => setSelected(selected?.id === d.id ? null : d)}
                      style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", cursor: "pointer" }}
                      onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.025)"}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                      <td style={{ padding: "9px 12px", fontSize: 16 }}>{CATEGORY_ICONS[d.device_category] || "📡"}</td>
                      <td style={{ padding: "9px 12px", fontFamily: "monospace", color: "#f5c518" }}>{d.ip_address}</td>
                      <td style={{ padding: "9px 12px", color: "#9aa0b0" }}>{d.vendor || "Unknown"}</td>
                      <td style={{ padding: "9px 12px", color: "#c0c8d8" }}>{(d.device_category || "unknown").replace(/_/g, " ")}</td>
                      <td style={{ padding: "9px 12px", color: "#555", fontSize: 11 }}>
                        {(d.open_ports || []).length > 0
                          ? (d.open_ports || []).map(p => p.port).join(", ")
                          : "—"}
                      </td>
                      <td style={{ padding: "9px 12px" }}><RiskBadge score={d.risk_score || 0}/></td>
                      <td style={{ padding: "9px 12px" }}>
                        {d.default_creds_risk
                          ? <span style={{ fontSize: 10, fontWeight: 700, color: "#ff3b3b" }}>⚠ YES</span>
                          : <span style={{ color: "#333", fontSize: 10 }}>—</span>}
                      </td>
                      <td style={{ padding: "9px 12px", color: "#555", fontSize: 11 }}>
                        {d.last_seen ? new Date(d.last_seen).toLocaleDateString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        }
      </div>

      {/* Risk factor detail panel */}
      {selected && (
        <div style={{ marginTop: 12, background: CARD_BG, border: `1px solid ${RISK_COLOR(selected.risk_score || 0)}44`,
          borderRadius: 12, padding: "16px 20px" }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: "#e8eaf0", marginBottom: 10 }}>
            {CATEGORY_ICONS[selected.device_category] || "📡"} {selected.ip_address} — Risk Factors
          </div>
          {(selected.risk_factors || []).length > 0
            ? (selected.risk_factors || []).map((f, i) => (
                <div key={i} style={{ fontSize: 12, color: "#9aa0b0", padding: "4px 0",
                  borderBottom: i < selected.risk_factors.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none" }}>
                  ⚠ {f}
                </div>
              ))
            : <div style={{ color: "#555", fontSize: 12 }}>No specific risk factors recorded.</div>
          }
          {selected.notes && (
            <div style={{ marginTop: 10, fontSize: 12, color: "#666", fontStyle: "italic" }}>{selected.notes}</div>
          )}
        </div>
      )}

      {total > PER_PAGE && (
        <div style={{ display: "flex", justifyContent: "center", gap: 8, padding: 16 }}>
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
            style={{ border: BORDER, borderRadius: 6, padding: "4px 12px", background: "transparent",
              color: page === 1 ? "#333" : "#9aa0b0", cursor: page === 1 ? "not-allowed" : "pointer" }}>← Prev</button>
          <span style={{ color: "#555", fontSize: 11, alignSelf: "center" }}>Page {page} of {Math.ceil(total / PER_PAGE)}</span>
          <button onClick={() => setPage(p => p + 1)} disabled={page >= Math.ceil(total / PER_PAGE)}
            style={{ border: BORDER, borderRadius: 6, padding: "4px 12px", background: "transparent",
              color: page >= Math.ceil(total / PER_PAGE) ? "#333" : "#9aa0b0",
              cursor: page >= Math.ceil(total / PER_PAGE) ? "not-allowed" : "pointer" }}>Next →</button>
        </div>
      )}
    </div>
  );
}
