/**
 * pages/itam/AssetDetailPage.jsx — Per-asset deep inventory detail
 *
 * Shows hardware, OS, software inventory with CVE counts,
 * running services, and local users collected via agentless SSH/WinRM.
 */
import React, { useEffect, useState, useCallback } from "react";

const CARD_BG = "rgba(255,255,255,0.03)";
const BORDER  = "1px solid rgba(255,255,255,0.07)";
const ACCENT  = "#00e5a0";

const SEV_COLOR = { critical: "#ff3b3b", high: "#ff8c00", medium: "#f5c518", low: ACCENT, none: "#333" };

function SevBadge({ sev }) {
  const c = SEV_COLOR[sev] || "#555";
  if (sev === "none" || !sev) return null;
  return (
    <span style={{ fontSize: 9, fontWeight: 700, color: c, border: `1px solid ${c}44`,
      padding: "2px 6px", borderRadius: 4, letterSpacing: 0.5, textTransform: "uppercase" }}>
      {sev}
    </span>
  );
}

function Section({ title, children, icon }) {
  return (
    <div style={{ background: CARD_BG, border: BORDER, borderRadius: 12, padding: "14px 18px", marginBottom: 14 }}>
      <div style={{ fontSize: 10, fontWeight: 600, color: "#555", letterSpacing: 0.5, marginBottom: 10 }}>
        {icon && <span style={{ marginRight: 6 }}>{icon}</span>}{title}
      </div>
      {children}
    </div>
  );
}

function HwPill({ label, value }) {
  if (!value) return null;
  return (
    <div style={{ background: "rgba(255,255,255,0.04)", border: BORDER, borderRadius: 8,
      padding: "8px 14px", display: "inline-flex", flexDirection: "column", gap: 2 }}>
      <div style={{ fontSize: 10, color: "#555" }}>{label}</div>
      <div style={{ fontSize: 13, fontWeight: 700, color: "#e8eaf0" }}>{value}</div>
    </div>
  );
}

export default function AssetDetailPage({ assetId, onBack }) {
  const [detail,    setDetail]    = useState(null);
  const [software,  setSoftware]  = useState([]);
  const [swTotal,   setSwTotal]   = useState(0);
  const [swPage,    setSwPage]    = useState(1);
  const [sevFlt,    setSevFlt]    = useState("");
  const [scanning,  setScanning]  = useState(false);
  const [snmpScan,  setSnmpScan]  = useState(false);
  const [scanMsg,   setScanMsg]   = useState("");
  const [enriching, setEnriching] = useState(false);
  const [scanStatus,setScanStatus]= useState(null);
  const [exploitIntel, setExploitIntel] = useState(null);
  const [loading,   setLoading]   = useState(true);

  const PER_PAGE = 50;

  const loadDetail = async () => {
    try {
      const r = await fetch(`/api/itam/assets/${assetId}/detail`);
      if (r.ok) setDetail(await r.json());
    } catch {}
    setLoading(false);
  };

  const loadScanStatus = async () => {
    try {
      const r = await fetch(`/api/itam/assets/${assetId}/scan-status`);
      if (r.ok) setScanStatus(await r.json());
    } catch {}
  };

  const loadExploitIntel = async () => {
    try {
      const r = await fetch(`/api/itam/assets/${assetId}/exploit-intel`);
      if (r.ok) setExploitIntel(await r.json());
    } catch {}
  };

  const loadSoftware = useCallback(async () => {
    const params = new URLSearchParams({ page: swPage, per_page: PER_PAGE });
    if (sevFlt) params.set("severity", sevFlt);
    try {
      const r = await fetch(`/api/itam/assets/${assetId}/software?${params}`);
      if (r.ok) { const d = await r.json(); setSoftware(d.software || []); setSwTotal(d.total || 0); }
    } catch {}
  }, [assetId, swPage, sevFlt]);

  useEffect(() => { loadDetail(); loadScanStatus(); loadExploitIntel(); }, [assetId]);
  useEffect(() => { loadSoftware(); }, [loadSoftware]);

  const triggerDeepScan = async () => {
    setScanning(true); setScanMsg("");
    try {
      const r = await fetch(`/api/itam/assets/${assetId}/deep-scan`, { method: "POST",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify({}) });
      const d = await r.json();
      if (r.ok && d.mode === "probe") {
        setScanMsg(`Deep scan dispatched to Network Probe (${d.probe_agent}) — results appear in ~60s`);
        setTimeout(() => { loadDetail(); loadSoftware(); }, 70000);
      } else if (r.ok) {
        setScanMsg("Deep scan started — results appear in ~60s");
        setTimeout(() => { loadDetail(); loadSoftware(); }, 65000);
      } else {
        setScanMsg(d.error || "Scan failed");
      }
    } catch { setScanMsg("Network error"); }
    setScanning(false);
  };

  const triggerEnrich = async () => {
    setEnriching(true);
    try {
      const r = await fetch(`/api/itam/assets/${assetId}/enrich-cves`, { method: "POST" });
      const d = await r.json();
      setScanMsg(r.ok ? "CVE enrichment started — NVD rate limit: ~50 packages/30s with API key" : (d.error || "Failed"));
      if (r.ok) setTimeout(() => { loadSoftware(); loadExploitIntel(); }, 45000);
    } catch { setScanMsg("Network error"); }
    setEnriching(false);
  };

  const triggerSnmpScan = async () => {
    setSnmpScan(true); setScanMsg("");
    try {
      const r = await fetch(`/api/itam/assets/${assetId}/snmp-scan`, { method: "POST",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify({}) });
      const d = await r.json();
      setScanMsg(r.ok ? "SNMP scan started — results in ~10s" : (d.error || "SNMP scan failed"));
      if (r.ok) setTimeout(() => { loadDetail(); loadScanStatus(); }, 12000);
    } catch { setScanMsg("Network error"); }
    setSnmpScan(false);
  };

  if (loading) return <div style={{ color: "#555", padding: 32, textAlign: "center" }}>Loading…</div>;

  const hw = detail?.hardware_info || {};
  const os = detail?.os_info || {};
  const services = detail?.services || [];
  const users = detail?.local_users || [];
  const sw = detail?.software || {};

  return (
    <div style={{ color: "#e8eaf0" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <button onClick={onBack} style={{
            border: BORDER, borderRadius: 6, padding: "5px 12px", background: "transparent",
            color: "#9aa0b0", fontSize: 12, cursor: "pointer" }}>← Back</button>
          <div>
            <div style={{ fontSize: 18, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}>
              {detail?.hostname || detail?.ip_address}
              {scanStatus?.scan_status && scanStatus.scan_status !== "idle" && (
                <span style={{
                  fontSize: 9, fontWeight: 700, padding: "2px 7px", borderRadius: 4,
                  background: scanStatus.scan_status === "ok" ? `${ACCENT}18`
                            : scanStatus.scan_status === "error" ? "rgba(255,59,59,0.14)"
                            : "rgba(245,197,24,0.14)",
                  color: scanStatus.scan_status === "ok" ? ACCENT
                       : scanStatus.scan_status === "error" ? "#ff3b3b" : "#f5c518",
                  border: `1px solid ${scanStatus.scan_status === "ok" ? ACCENT
                            : scanStatus.scan_status === "error" ? "#ff3b3b" : "#f5c518"}44`,
                  letterSpacing: 0.5, textTransform: "uppercase",
                }}>{scanStatus.scan_status}</span>
              )}
            </div>
            <div style={{ fontSize: 11, color: "#555", fontFamily: "monospace" }}>
              {detail?.ip_address} · Last deep scan: {detail?.last_deep_scan
                ? new Date(detail.last_deep_scan).toLocaleString() : "Never"}
            </div>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button onClick={triggerDeepScan} disabled={scanning} style={{
            border: `1px solid ${ACCENT}44`, borderRadius: 6, padding: "6px 14px",
            fontSize: 11, fontWeight: 600, color: ACCENT, background: `${ACCENT}08`,
            cursor: scanning ? "not-allowed" : "pointer" }}>
            {scanning ? "Scanning…" : "🔍 Deep Scan (SSH/WinRM)"}
          </button>
          <button onClick={triggerSnmpScan} disabled={snmpScan} style={{
            border: "1px solid #7c82ff44", borderRadius: 6, padding: "6px 14px",
            fontSize: 11, fontWeight: 600, color: "#7c82ff", background: "rgba(124,130,255,0.06)",
            cursor: snmpScan ? "not-allowed" : "pointer" }}>
            {snmpScan ? "Polling…" : "📡 SNMP Scan"}
          </button>
          {sw.total > 0 && (
            <button onClick={triggerEnrich} disabled={enriching} style={{
              border: "1px solid #f5c51844", borderRadius: 6, padding: "6px 14px",
              fontSize: 11, fontWeight: 600, color: "#f5c518", background: "rgba(245,197,24,0.06)",
              cursor: enriching ? "not-allowed" : "pointer" }}>
              {enriching ? "Enriching…" : "🔎 Enrich CVEs (NVD)"}
            </button>
          )}
        </div>
      </div>

      {scanMsg && (
        <div style={{ marginBottom: 14, padding: "8px 14px", borderRadius: 6,
          background: "rgba(0,229,160,0.08)", border: `1px solid ${ACCENT}33`,
          fontSize: 12, color: ACCENT }}>{scanMsg}</div>
      )}

      {scanStatus?.scan_status === "error" && scanStatus?.scan_error && (
        <div style={{ marginBottom: 14, padding: "10px 16px", borderRadius: 8,
          background: "rgba(255,59,59,0.08)", border: "1px solid #ff3b3b44",
          fontSize: 12, color: "#ff3b3b" }}>
          <strong>Last scan error:</strong> {scanStatus.scan_error}
        </div>
      )}

      {!detail?.last_deep_scan ? (
        <div style={{ background: CARD_BG, border: "1px solid #f5c51844", borderRadius: 12,
          padding: "24px 20px", textAlign: "center", marginBottom: 14 }}>
          <div style={{ fontSize: 32, marginBottom: 8 }}>🔍</div>
          <div style={{ fontSize: 13, color: "#9aa0b0", marginBottom: 4 }}>
            No deep inventory data yet.
          </div>
          <div style={{ fontSize: 11, color: "#555", lineHeight: 1.6 }}>
            Set credentials in your deployment environment, then click <strong>Deep Scan</strong> above.<br/>
            <span style={{ fontFamily: "monospace", color: "#9aa0b0" }}>
              ITAM_SSH_USERNAME / ITAM_SSH_PASSWORD / ITAM_SSH_KEY_PATH
            </span><br/>
            <span style={{ fontFamily: "monospace", color: "#9aa0b0" }}>
              ITAM_WINRM_USERNAME / ITAM_WINRM_PASSWORD
            </span><br/>
            Or pass credentials directly in the POST body to <code style={{ color: "#f5c518" }}>/api/itam/assets/&#123;id&#125;/deep-scan</code>.
          </div>
        </div>
      ) : (
        <>
          {/* Software vulnerability summary */}
          {(sw.total > 0) && (
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
              {[
                { label: "Total Packages", value: sw.total, color: "#9aa0b0" },
                { label: "Critical CVEs", value: sw.critical, color: "#ff3b3b" },
                { label: "High CVEs",     value: sw.high,     color: "#ff8c00" },
                { label: "Medium CVEs",   value: sw.medium,   color: "#f5c518" },
                { label: "Low CVEs",      value: sw.low,      color: ACCENT },
              ].map(({ label, value, color }) => (
                <div key={label} style={{ background: CARD_BG, border: BORDER, borderRadius: 10,
                  padding: "10px 16px", flex: "1 1 80px", borderTop: `3px solid ${color}` }}>
                  <div style={{ fontSize: 20, fontWeight: 800, color }}>{value}</div>
                  <div style={{ fontSize: 10, color: "#555" }}>{label}</div>
                </div>
              ))}
            </div>
          )}

          {/* KEV risk banner */}
          {exploitIntel?.kev_count > 0 && (
            <div style={{ marginBottom: 14, padding: "10px 16px", borderRadius: 8,
              background: "rgba(255,59,59,0.08)", border: "1px solid #ff3b3b44",
              display: "flex", alignItems: "center", gap: 12 }}>
              <span style={{ fontSize: 20 }}>🚨</span>
              <div>
                <div style={{ fontSize: 12, fontWeight: 700, color: "#ff3b3b" }}>
                  {exploitIntel.kev_count} Known Exploited Vulnerabilities (CISA KEV)
                  {exploitIntel.ransomware_risk && <span style={{ marginLeft: 8, fontSize: 10,
                    color: "#ff8c00", border: "1px solid #ff8c0044", padding: "1px 6px", borderRadius: 4 }}>
                    Ransomware Risk
                  </span>}
                </div>
                <div style={{ fontSize: 11, color: "#9aa0b0", marginTop: 2 }}>
                  Affected: {exploitIntel.kev_packages?.slice(0, 5).join(", ")}
                  {exploitIntel.kev_packages?.length > 5 ? ` +${exploitIntel.kev_packages.length - 5} more` : ""}
                </div>
              </div>
              {exploitIntel.highest_epss > 0 && (
                <div style={{ marginLeft: "auto", textAlign: "right" }}>
                  <div style={{ fontSize: 18, fontWeight: 800, color: "#ff8c00" }}>
                    {(exploitIntel.highest_epss * 100).toFixed(1)}%
                  </div>
                  <div style={{ fontSize: 10, color: "#555" }}>Highest EPSS</div>
                </div>
              )}
            </div>
          )}

          {/* OS + Hardware */}
          <Section title="OS & HARDWARE" icon="🖥️">
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
              {os.NAME && <HwPill label="OS" value={`${os.NAME} ${os.VERSION_ID || ""}`}/>}
              {hw.cpu_model && <HwPill label="CPU" value={`${hw.cpu_cores || "?"} cores — ${hw.cpu_model.trim()}`}/>}
              {hw.mem_mb && <HwPill label="RAM" value={`${Math.round(hw.mem_mb / 1024)} GB`}/>}
              {hw.disk_gb && <HwPill label="Disk (/)" value={`${hw.disk_gb} GB`}/>}
            </div>
          </Section>

          {/* Services + Users side by side */}
          <div style={{ display: "flex", gap: 14, marginBottom: 0 }}>
            {services.length > 0 && (
              <Section title="RUNNING SERVICES" icon="⚙️">
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                  {services.slice(0, 30).map((s, i) => (
                    <span key={i} style={{ fontSize: 10, color: "#9aa0b0", background: "rgba(255,255,255,0.04)",
                      border: BORDER, borderRadius: 4, padding: "2px 8px", fontFamily: "monospace" }}>{s}</span>
                  ))}
                  {services.length > 30 && <span style={{ fontSize: 10, color: "#555" }}>+{services.length - 30} more</span>}
                </div>
              </Section>
            )}
            {users.length > 0 && (
              <Section title="LOCAL USERS" icon="👤">
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                  {users.map((u, i) => (
                    <span key={i} style={{ fontSize: 11, color: "#c0c8d8", background: "rgba(255,255,255,0.04)",
                      border: BORDER, borderRadius: 4, padding: "2px 8px", fontFamily: "monospace" }}>{u}</span>
                  ))}
                </div>
              </Section>
            )}
          </div>
        </>
      )}

      {/* Software inventory table */}
      {detail?.last_deep_scan && (
        <>
          <div style={{ fontSize: 10, fontWeight: 600, color: "#555", letterSpacing: 0.5, margin: "14px 0 8px" }}>
            SOFTWARE INVENTORY ({swTotal} packages)
          </div>

          <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
            {["", "critical", "high", "medium", "low"].map(s => (
              <button key={s} onClick={() => { setSevFlt(s); setSwPage(1); }} style={{
                border: sevFlt === s ? `1px solid ${SEV_COLOR[s] || "#9aa0b0"}` : BORDER,
                borderRadius: 6, padding: "3px 10px", fontSize: 10, fontWeight: 600,
                background: sevFlt === s ? `${(SEV_COLOR[s] || "#9aa0b0")}18` : "transparent",
                color: sevFlt === s ? (SEV_COLOR[s] || "#9aa0b0") : "#555",
                cursor: "pointer", textTransform: "capitalize",
              }}>{s || "All"}</button>
            ))}
          </div>

          <div style={{ background: CARD_BG, border: BORDER, borderRadius: 12, overflow: "hidden" }}>
            {software.length === 0
              ? <div style={{ padding: 24, textAlign: "center", color: "#555", fontSize: 12 }}>
                  {sevFlt ? `No ${sevFlt} vulnerabilities found.` : "No software inventory yet — run a deep scan first."}
                </div>
              : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
                        {["Package", "Version", "Vendor", "Manager", "CVEs", "Severity", "EPSS", "KEV"].map(h => (
                          <th key={h} style={{ padding: "7px 12px", textAlign: "left", color: "#555", fontSize: 10, fontWeight: 600 }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {software.map((pkg, i) => (
                        <tr key={pkg.id || i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}
                          onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.025)"}
                          onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                          <td style={{ padding: "7px 12px", fontWeight: 600, color: "#e8eaf0" }}>{pkg.name}</td>
                          <td style={{ padding: "7px 12px", color: "#9aa0b0", fontFamily: "monospace", fontSize: 11 }}>{pkg.version || "—"}</td>
                          <td style={{ padding: "7px 12px", color: "#666", fontSize: 11 }}>{pkg.vendor || "—"}</td>
                          <td style={{ padding: "7px 12px", color: "#555", fontSize: 10 }}>
                            <span style={{ border: BORDER, borderRadius: 4, padding: "1px 6px" }}>{pkg.package_manager || "—"}</span>
                          </td>
                          <td style={{ padding: "7px 12px", color: pkg.cve_count > 0 ? "#ff8c00" : "#555", fontWeight: pkg.cve_count > 0 ? 700 : 400 }}>
                            {pkg.cve_count || 0}
                          </td>
                          <td style={{ padding: "7px 12px" }}><SevBadge sev={pkg.highest_severity}/></td>
                          <td style={{ padding: "7px 12px", fontSize: 11, color: pkg.epss_score > 0.5 ? "#ff3b3b" : pkg.epss_score > 0.1 ? "#ff8c00" : "#555" }}>
                            {pkg.epss_score ? `${(pkg.epss_score * 100).toFixed(1)}%` : "—"}
                          </td>
                          <td style={{ padding: "7px 12px" }}>
                            {pkg.is_kev && (
                              <span style={{ fontSize: 9, fontWeight: 700, color: "#ff3b3b",
                                border: "1px solid #ff3b3b44", padding: "1px 5px", borderRadius: 4 }}>KEV</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )
            }
          </div>

          {swTotal > PER_PAGE && (
            <div style={{ display: "flex", justifyContent: "center", gap: 8, padding: 12 }}>
              <button onClick={() => setSwPage(p => Math.max(1, p - 1))} disabled={swPage === 1}
                style={{ border: BORDER, borderRadius: 6, padding: "4px 12px", background: "transparent",
                  color: swPage === 1 ? "#333" : "#9aa0b0", cursor: swPage === 1 ? "not-allowed" : "pointer" }}>← Prev</button>
              <span style={{ color: "#555", fontSize: 11, alignSelf: "center" }}>{swPage} / {Math.ceil(swTotal / PER_PAGE)}</span>
              <button onClick={() => setSwPage(p => p + 1)} disabled={swPage >= Math.ceil(swTotal / PER_PAGE)}
                style={{ border: BORDER, borderRadius: 6, padding: "4px 12px", background: "transparent",
                  color: swPage >= Math.ceil(swTotal / PER_PAGE) ? "#333" : "#9aa0b0",
                  cursor: swPage >= Math.ceil(swTotal / PER_PAGE) ? "not-allowed" : "pointer" }}>Next →</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
