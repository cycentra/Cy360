/**
 * pages/itam/index.jsx — ITAM Coverage Dashboard
 *
 * Unified view of all network assets, EDR/SIEM coverage gaps,
 * IoT device count, and Shadow AI open findings.
 * Tabs: All Assets | Uncovered | IoT Devices | Shadow AI
 */
import React, { useEffect, useState, useCallback } from "react";

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
  manual:     "CMDB",
  arp_report: "ARP",
  nmap:       "Scan",
  edr_agent:  "EDR",
  siem_agent: "SIEM",
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
                <Badge label={SOURCE_LABEL[a.source] || a.source} color="#555"/>
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

export default function ItamCoveragePage({ onViewAsset }) {
  const [coverage,      setCoverage]      = useState(null);
  const [assets,        setAssets]        = useState([]);
  const [total,         setTotal]         = useState(0);
  const [page,          setPage]          = useState(1);
  const [tab,           setTab]           = useState("all");
  const [search,        setSearch]        = useState("");
  const [loading,       setLoading]       = useState(true);
  const [importing,     setImporting]     = useState(false);
  const [scanning,      setScanning]      = useState(false);
  const [importResult,  setImportResult]  = useState(null);
  const [scanMsg,       setScanMsg]       = useState("");

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
      const r = await fetch("/api/itam/assets/scan", { method: "POST",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify({}) });
      const d = await r.json();
      setScanMsg(r.ok ? `Scan started for ${d.subnet || "configured subnet"}` : (d.error || "Scan failed"));
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
          background: "rgba(77,158,255,0.1)", border: "1px solid #4d9eff44",
          fontSize: 12, color: "#4d9eff" }}>{scanMsg}</div>
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
      </div>

      {/* Coverage bar */}
      {cov && (
        <div style={{ background: CARD_BG, border: BORDER, borderRadius: 12, padding: "16px 20px", marginBottom: 24 }}>
          <CoverageBar pct={cov.coverage_pct || 0}/>
          <div style={{ display: "flex", gap: 24, marginTop: 12, flexWrap: "wrap" }}>
            {Object.entries(cov.sources || {}).map(([src, n]) => (
              <div key={src} style={{ fontSize: 11 }}>
                <span style={{ color: "#555" }}>{SOURCE_LABEL[src] || src}: </span>
                <span style={{ color: "#9aa0b0", fontWeight: 600 }}>{n}</span>
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
          ].map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              border: tab === t.id ? `1px solid ${ACCENT}` : BORDER,
              borderRadius: 6, padding: "6px 14px", fontSize: 11, fontWeight: 600,
              background: tab === t.id ? `${ACCENT}18` : "transparent",
              color: tab === t.id ? ACCENT : "#666", cursor: "pointer",
            }}>{t.label}</button>
          ))}
        </div>
        <input
          value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search IP, hostname, vendor…"
          style={{
            background: CARD_BG, border: BORDER, borderRadius: 6,
            padding: "6px 12px", fontSize: 12, color: "#c0c8d8",
            outline: "none", width: 220,
          }}
        />
      </div>

      {/* Asset table */}
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
    </div>
  );
}
