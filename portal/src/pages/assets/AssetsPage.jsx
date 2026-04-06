/**
 * src/pages/assets/AssetsPage.jsx
 */

import { RISK_CONFIG, STATUS_CONFIG } from '../../core/constants.js';
import { WorldMapWidget } from './WorldMapWidget.jsx';

function Badge({ risk }) {
  const cfg = RISK_CONFIG[risk] || RISK_CONFIG.low;
  return <span style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40`, fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px", fontFamily: "monospace", padding: "2px 8px", borderRadius: "2px" }}>{cfg.label}</span>;
}

function StatusBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.open;
  return (
    <span style={{ color: cfg.color, fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px", fontFamily: "monospace", display: "flex", alignItems: "center", gap: 5 }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: cfg.color, display: "inline-block", boxShadow: `0 0 6px ${cfg.color}` }}/>
      {cfg.label}
    </span>
  );
}

export function AssetsPage({ assets, setSelectedAsset, setShowImport }) {
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700 }}>Asset Inventory</h1>
          <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13, marginTop: 4 }}>
            {assets.length} asset{assets.length !== 1 ? "s" : ""} discovered
          </p>
        </div>
        <button onClick={() => setShowImport(true)} style={{ background: "rgba(0,229,160,0.08)", color: "#00e5a0", border: "1px solid rgba(0,229,160,0.25)", padding: "8px 18px", borderRadius: 4, fontFamily: "monospace", fontSize: 11, cursor: "pointer" }}>
          Import Scan
        </button>
      </div>

      <WorldMapWidget assets={assets} />

      <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 4, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "110px 1fr 120px 160px 140px 90px 110px", padding: "10px 20px", borderBottom: "1px solid rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.3)", fontSize: 10, letterSpacing: "1.2px", textTransform: "uppercase", fontFamily: "monospace" }}>
          <span>Risk</span><span>Host</span><span>IP</span><span>Type</span><span>Ports</span><span>Findings</span><span>Status</span>
        </div>

        {assets.length === 0 && (
          <div style={{ padding: "32px 20px", textAlign: "center", color: "rgba(255,255,255,0.2)", fontFamily: "monospace" }}>
            No assets — import a scan or launch a new one
          </div>
        )}

        {assets.map((a, i) => (
          <div key={a.id} className="asset-row" onClick={() => setSelectedAsset(a)}
            style={{ display: "grid", gridTemplateColumns: "110px 1fr 120px 160px 140px 90px 110px", padding: "13px 20px", borderBottom: "1px solid rgba(255,255,255,0.04)", background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)", alignItems: "center" }}>
            <span><Badge risk={a.risk}/></span>
            <div>
              <div style={{ color: "white", fontFamily: "monospace", fontSize: 12 }}>{a.host}</div>
              <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, marginTop: 2 }}>{a.owner}</div>
              {a.subdomains?.length > 0 && <div style={{ color: "rgba(0,229,160,0.4)", fontSize: 10, marginTop: 1 }}>{a.subdomains.length} subdomains</div>}
            </div>
            <span style={{ color: "rgba(255,255,255,0.5)", fontFamily: "monospace", fontSize: 11 }}>{a.ip}</span>
            <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 12 }}>{a.type}</span>
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {(a.ports || []).slice(0, 4).map(p => <span key={p} style={{ color: "#00e5a0", fontSize: 10, fontFamily: "monospace" }}>:{p}</span>)}
              {(a.ports?.length || 0) > 4 && <span style={{ color: "rgba(0,229,160,0.4)", fontSize: 10, fontFamily: "monospace" }}>+{a.ports.length - 4}</span>}
              {(!a.ports || a.ports.length === 0) && <span style={{ color: "rgba(255,255,255,0.2)", fontFamily: "monospace", fontSize: 11 }}>—</span>}
            </div>
            <span style={{ color: (a.vulnerabilities?.length || 0) > 0 ? "#ff3b3b" : "rgba(255,255,255,0.25)", fontFamily: "monospace", fontSize: 12, fontWeight: (a.vulnerabilities?.length || 0) > 0 ? 700 : 400 }}>
              {(a.vulnerabilities?.length || 0) > 0 ? `▲ ${a.vulnerabilities.length}` : "—"}
            </span>
            <StatusBadge status={a.status}/>
          </div>
        ))}
      </div>
    </div>
  );
}
