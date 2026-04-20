/**
 * src/pages/assets/AssetsPage.jsx
 */

import { useState, useEffect } from 'react';
import { RISK_CONFIG, STATUS_CONFIG, STATUS_TRANSITIONS } from '../../core/constants.js';
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

function AssetTransitionModal({ show, assetHost, toStatus, comment, onChange, onCancel, onConfirm, error, busy }) {
  if (!show) return null;
  const cfg = STATUS_CONFIG[toStatus] || { color: "#888", label: toStatus };
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 4000, background: "rgba(0,0,0,0.7)",
      display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: "#0d1117", border: `1px solid ${cfg.color}50`,
        borderRadius: 6, padding: 24, width: 420, maxWidth: "95vw" }}>
        <div style={{ color: cfg.color, fontFamily: "monospace", fontSize: 12, fontWeight: 700,
          marginBottom: 4, letterSpacing: "1px" }}>
          TRANSITION TO: {cfg.label}
        </div>
        <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, marginBottom: 10 }}>
          Asset: <span style={{ color: "rgba(255,255,255,0.6)", fontFamily: "monospace" }}>{assetHost}</span>
        </div>
        <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, marginBottom: 8 }}>
          A comment is required for audit trail.
        </div>
        <textarea value={comment} onChange={e => onChange(e.target.value)}
          placeholder="Describe the reason for this status change…"
          rows={4}
          style={{ width: "100%", background: "rgba(255,255,255,0.04)",
            border: `1px solid ${error ? "#ff3b3b" : "rgba(255,255,255,0.12)"}`,
            borderRadius: 4, color: "rgba(255,255,255,0.8)", fontSize: 12,
            fontFamily: "monospace", padding: "8px 10px", resize: "vertical",
            boxSizing: "border-box" }} />
        {error && <div style={{ color: "#ff6464", fontSize: 11, fontFamily: "monospace", marginTop: 4 }}>{error}</div>}
        <div style={{ display: "flex", gap: 8, marginTop: 14, justifyContent: "flex-end" }}>
          <button onClick={onCancel} style={{ background: "none", border: "1px solid rgba(255,255,255,0.1)",
            color: "rgba(255,255,255,0.4)", padding: "6px 14px", borderRadius: 3,
            fontFamily: "monospace", fontSize: 11, cursor: "pointer" }}>Cancel</button>
          <button onClick={onConfirm} disabled={busy}
            style={{ background: `${cfg.color}20`, border: `1px solid ${cfg.color}50`,
              color: cfg.color, padding: "6px 16px", borderRadius: 3,
              fontFamily: "monospace", fontSize: 12, fontWeight: 700, cursor: busy ? "wait" : "pointer" }}>
            {busy ? "Saving…" : "Confirm"}
          </button>
        </div>
      </div>
    </div>
  );
}

export function AssetsPage({ assets, setSelectedAsset, setShowImport }) {
  // Status overrides from /api/asm/statuses (keyed by asset host)
  const [assetStatuses, setAssetStatuses] = useState({});
  const [txModal,   setTxModal]   = useState({ show: false, assetId: null, assetHost: null, toStatus: null });
  const [txComment, setTxComment] = useState("");
  const [txErr,     setTxErr]     = useState("");
  const [txBusy,    setTxBusy]    = useState(false);

  useEffect(() => {
    fetch("/api/asm/statuses", { credentials: "include" })
      .then(r => r.ok ? r.json() : {})
      .then(d => setAssetStatuses(d.assets || {}))
      .catch(() => {});
  }, []);

  const openTransition = (assetId, assetHost, toStatus, e) => {
    e.stopPropagation();
    setTxModal({ show: true, assetId, assetHost, toStatus });
    setTxComment("");
    setTxErr("");
  };
  const closeTransition = () => setTxModal({ show: false, assetId: null, assetHost: null, toStatus: null });

  const confirmTransition = async () => {
    if (!txComment.trim()) { setTxErr("A comment is required."); return; }
    setTxBusy(true);
    try {
      const r = await fetch(`/api/asm/assets/${encodeURIComponent(txModal.assetId)}/status`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ to_status: txModal.toStatus, comment: txComment }),
      });
      if (!r.ok) {
        const b = await r.json().catch(() => ({}));
        setTxErr(b.error || `HTTP ${r.status}`);
      } else {
        setAssetStatuses(prev => ({ ...prev, [txModal.assetId]: txModal.toStatus }));
        closeTransition();
      }
    } catch {
      setTxErr("Network error.");
    }
    setTxBusy(false);
  };

  return (
    <div>
      <AssetTransitionModal
        show={txModal.show}
        assetHost={txModal.assetHost}
        toStatus={txModal.toStatus}
        comment={txComment}
        onChange={setTxComment}
        onCancel={closeTransition}
        onConfirm={confirmTransition}
        error={txErr}
        busy={txBusy}
      />

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
        <div style={{ display: "grid", gridTemplateColumns: "110px 1fr 120px 160px 140px 90px 150px", padding: "10px 20px", borderBottom: "1px solid rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.3)", fontSize: 10, letterSpacing: "1.2px", textTransform: "uppercase", fontFamily: "monospace" }}>
          <span>Risk</span><span>Host</span><span>IP</span><span>Type</span><span>Ports</span><span>Findings</span><span>Status</span>
        </div>

        {assets.length === 0 && (
          <div style={{ padding: "32px 20px", textAlign: "center", color: "rgba(255,255,255,0.2)", fontFamily: "monospace" }}>
            No assets — import a scan or launch a new one
          </div>
        )}

        {assets.map((a, i) => {
          const assetId  = a.host;
          const curStat  = assetStatuses[assetId] || a.status || "open";
          const targets  = STATUS_TRANSITIONS[curStat] || [];
          const statCfg  = STATUS_CONFIG[curStat] || STATUS_CONFIG.open;
          return (
            <div key={a.id} className="asset-row" onClick={() => setSelectedAsset(a)}
              style={{ display: "grid", gridTemplateColumns: "110px 1fr 120px 160px 140px 90px 150px", padding: "13px 20px", borderBottom: "1px solid rgba(255,255,255,0.04)", background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)", alignItems: "center" }}>
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
              {/* Clickable status cell with transition buttons */}
              <div onClick={e => e.stopPropagation()} style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <span style={{ color: statCfg.color, fontSize: "10px", fontWeight: 700,
                  letterSpacing: "1.5px", fontFamily: "monospace", display: "flex",
                  alignItems: "center", gap: 5 }}>
                  <span style={{ width: 6, height: 6, borderRadius: "50%", background: statCfg.color,
                    display: "inline-block", boxShadow: `0 0 6px ${statCfg.color}` }}/>
                  {statCfg.label}
                </span>
                {targets.length > 0 && (
                  <div style={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
                    {targets.map(t => {
                      const tc = STATUS_CONFIG[t] || { color: "#888", label: t };
                      return (
                        <button key={t}
                          onClick={e => openTransition(assetId, a.host, t, e)}
                          style={{ background: `${tc.color}12`, border: `1px solid ${tc.color}35`,
                            color: tc.color, fontSize: 8, fontFamily: "monospace", fontWeight: 700,
                            padding: "1px 5px", borderRadius: 2, cursor: "pointer", whiteSpace: "nowrap" }}>
                          → {tc.label}
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
