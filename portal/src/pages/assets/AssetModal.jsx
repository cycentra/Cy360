/**
 * src/pages/assets/AssetModal.jsx
 */

import { RISK_CONFIG, STATUS_CONFIG } from '../../core/constants.js';

function Badge({ risk }) {
  const cfg = RISK_CONFIG[risk] || RISK_CONFIG.low;
  return <span style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40`, fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px", fontFamily: "monospace", padding: "2px 8px", borderRadius: "2px" }}>{cfg.label}</span>;
}

function formatDate(dateStr) {
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

export function AssetModal({ asset, onClose, onStatusChange }) {
  if (!asset) return null;
  const cfg  = RISK_CONFIG[asset.risk] || RISK_CONFIG.low;
  const days = asset.cert_days ?? null;

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)", zIndex: 100, display: "flex", justifyContent: "flex-end" }} onClick={onClose}>
      <div style={{ width: "min(600px,95vw)", height: "100vh", background: "#0d1117", borderLeft: "1px solid rgba(255,255,255,0.08)", overflowY: "auto" }} onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div style={{ padding: "20px 24px", borderBottom: "1px solid rgba(255,255,255,0.07)", display: "flex", justifyContent: "space-between", alignItems: "flex-start", position: "sticky", top: 0, background: "#0d1117", zIndex: 10 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
              <Badge risk={asset.risk}/>
              <span style={{ color: "white", fontFamily: "monospace", fontSize: 14, fontWeight: 700 }}>{asset.host}</span>
            </div>
            <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 11 }}>{asset.type} · {asset.ip}</div>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "rgba(255,255,255,0.4)", cursor: "pointer", fontSize: 20, padding: 4 }}>×</button>
        </div>

        <div style={{ padding: "20px 24px" }}>
          {/* Cert info */}
          {days !== null && (
            <div style={{ background: days < 0 ? "rgba(255,59,59,0.08)" : days < 30 ? "rgba(255,140,0,0.08)" : "rgba(0,229,160,0.08)", border: `1px solid ${days < 0 ? "rgba(255,59,59,0.3)" : days < 30 ? "rgba(255,140,0,0.3)" : "rgba(0,229,160,0.2)"}`, borderRadius: 4, padding: "10px 14px", marginBottom: 20 }}>
              <div style={{ color: days < 0 ? "#ff3b3b" : days < 30 ? "#ff8c00" : "#00e5a0", fontSize: 12, fontWeight: 600 }}>
                SSL Certificate: {days < 0 ? "EXPIRED" : `${days} days remaining`}
              </div>
              {asset.cert_expiry && <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 11, marginTop: 2 }}>Expires {formatDate(asset.cert_expiry)}</div>}
            </div>
          )}

          {/* Subdomain Intel */}
          {asset.type === "Subdomain" && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, letterSpacing: "1px", textTransform: "uppercase", marginBottom: 10, fontFamily: "monospace" }}>Subdomain Intel</div>
              <div style={{ display: "flex", flexDirection: "column" }}>
                {/* DNS Status */}
                <div style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                  <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, fontFamily: "monospace" }}>DNS Status</span>
                  <span style={{ color: asset.live ? "#00e5a0" : "rgba(255,255,255,0.3)", fontSize: 12, fontWeight: 700 }}>
                    {asset.live === true ? "● LIVE" : asset.live === false ? "○ Not Resolving" : "—"}
                  </span>
                </div>
                {/* Change */}
                {asset.change && (
                  <div style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                    <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, fontFamily: "monospace" }}>Change</span>
                    <span style={{ color: asset.is_new ? "#ff8c00" : "rgba(255,255,255,0.5)", fontSize: 12, fontFamily: "monospace", textTransform: "uppercase" }}>{asset.change}</span>
                  </div>
                )}
                {/* Resolved IP */}
                {asset.ip && asset.ip !== "—" && (
                  <div style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                    <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, fontFamily: "monospace" }}>Resolved IP</span>
                    <span style={{ color: "rgba(255,255,255,0.7)", fontSize: 12, fontFamily: "monospace" }}>{asset.ip}</span>
                  </div>
                )}
                {/* CNAME */}
                {asset.cname && (
                  <div style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                    <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, fontFamily: "monospace" }}>CNAME</span>
                    <span style={{ color: "rgba(255,255,255,0.7)", fontSize: 12, fontFamily: "monospace" }}>{asset.cname}</span>
                  </div>
                )}
                {/* Discovery sources */}
                {asset.sources?.length > 0 && (
                  <div style={{ padding: "8px 0" }}>
                    <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace", marginBottom: 6 }}>DISCOVERED VIA</div>
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                      {asset.sources.map(s => (
                        <span key={s} style={{ background: "rgba(0,229,160,0.06)", color: "#00e5a0", border: "1px solid rgba(0,229,160,0.2)", fontSize: 10, fontFamily: "monospace", padding: "2px 7px", borderRadius: 2 }}>{s}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Vulnerabilities */}
          {asset.vulnerabilities?.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, letterSpacing: "1px", textTransform: "uppercase", marginBottom: 10, fontFamily: "monospace" }}>
                Vulnerabilities ({asset.vulnerabilities.length})
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {asset.vulnerabilities.map((v, i) => {
                  const vc = RISK_CONFIG[v.severity?.toLowerCase()] || RISK_CONFIG.low;
                  return (
                    <div key={i} style={{ background: "rgba(255,255,255,0.02)", border: `1px solid ${vc.color}20`, borderLeft: `3px solid ${vc.color}`, padding: "10px 14px", borderRadius: 2 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                        <span style={{ color: "white", fontSize: 12, fontWeight: 600 }}>{v.vulnerability}</span>
                        <Badge risk={v.severity?.toLowerCase()}/>
                      </div>
                      <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, marginBottom: 6 }}>{v.description}</div>
                      {v.recommendation && <div style={{ color: "#00e5a0", fontSize: 11 }}>✓ {v.recommendation}</div>}
                      {v.module && <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace", marginTop: 4 }}>Module: {v.module}</div>}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Status update */}
          <div>
            <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, letterSpacing: "1px", textTransform: "uppercase", marginBottom: 10, fontFamily: "monospace" }}>Update Status</div>
            <div style={{ display: "flex", gap: 8 }}>
              {["open", "in-review", "resolved"].map(s => (
                <button key={s} onClick={() => { onStatusChange(asset.id, s); onClose(); }}
                  style={{ padding: "8px 16px", borderRadius: 3, border: `1px solid ${STATUS_CONFIG[s].color}40`, background: asset.status === s ? `${STATUS_CONFIG[s].color}20` : "transparent", color: STATUS_CONFIG[s].color, fontFamily: "monospace", fontSize: 11, letterSpacing: "1px", cursor: "pointer", textTransform: "uppercase", fontWeight: asset.status === s ? 700 : 400 }}>
                  {s}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
