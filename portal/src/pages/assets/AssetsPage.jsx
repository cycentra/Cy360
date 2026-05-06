/**
 * src/pages/assets/AssetsPage.jsx
 *
 * Asset Inventory table with right-side slide-out detail panel.
 * - Row shows single active-state badge (no inline transition buttons)
 * - Clicking a row opens AssetDrawer with full detail + status lifecycle
 */

import { useState, useEffect } from 'react';
import { RISK_CONFIG, STATUS_CONFIG, STATUS_TRANSITIONS } from '../../core/constants.js';
import { WorldMapWidget } from './WorldMapWidget.jsx';

function Badge({ risk }) {
  const cfg = RISK_CONFIG[risk] || RISK_CONFIG.low;
  return <span style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40`, fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px", fontFamily: "monospace", padding: "2px 8px", borderRadius: "2px" }}>{cfg.label}</span>;
}

// Single active-state indicator (dot + label, no dropdown)
function StatusBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.new;
  return (
    <span style={{ color: cfg.color, fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px",
      fontFamily: "monospace", display: "flex", alignItems: "center", gap: 5 }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: cfg.color,
        display: "inline-block", boxShadow: `0 0 6px ${cfg.color}` }}/>
      {cfg.label}
    </span>
  );
}

// ── Status sub-panel (second slide-out, zIndex 3002) ─────────────────────────

function AssetStatusPanel({ asset, status, onClose, onStatusChange }) {
  const [txTarget,  setTxTarget]  = useState(null);
  const [txComment, setTxComment] = useState("");
  const [txErr,     setTxErr]     = useState("");
  const [txBusy,    setTxBusy]    = useState(false);

  const rawStat  = status || asset.asset_state || "new";
  const curStat  = (typeof rawStat === "object" ? rawStat?.state : rawStat) || "new";
  const targets  = STATUS_TRANSITIONS[curStat] || [];
  const statCfg  = STATUS_CONFIG[curStat] || STATUS_CONFIG.new;
  const assetId  = asset.host;

  const startTx  = (t) => { setTxTarget(t); setTxComment(""); setTxErr(""); };
  const cancelTx = () => setTxTarget(null);

  const confirmTx = async () => {
    if (!txComment.trim()) { setTxErr("A comment is required."); return; }
    setTxBusy(true);
    try {
      const r = await fetch(`/api/asm/assets/${encodeURIComponent(assetId)}/state`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ to_state: txTarget, comment: txComment }),
      });
      if (!r.ok) {
        const b = await r.json().catch(() => ({}));
        setTxErr(b.error || `HTTP ${r.status}`);
      } else {
        onStatusChange(assetId, txTarget);
        setTxTarget(null);
        onClose();
      }
    } catch { setTxErr("Network error."); }
    setTxBusy(false);
  };

  return (
    <div style={{
      position: "fixed", top: 0, right: 480, bottom: 0, zIndex: 3002,
      width: 340, background: "#0b0f1c",
      borderLeft: `2px solid ${statCfg.color}50`,
      display: "flex", flexDirection: "column",
      boxShadow: "-12px 0 32px rgba(0,0,0,0.6)",
      overflow: "hidden",
    }}>
      {/* Header */}
      <div style={{
        padding: "16px 18px 12px", flexShrink: 0,
        borderBottom: `1px solid ${statCfg.color}20`,
        background: `${statCfg.color}06`,
      }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace",
              letterSpacing: "1.5px", marginBottom: 4 }}>UPDATE ASSET STATE</div>
            <div style={{ color: "rgba(255,255,255,0.8)", fontSize: 13,
              fontFamily: "monospace", fontWeight: 700 }}>{asset.host}</div>
          </div>
          <button onClick={onClose} style={{
            background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)",
            color: "rgba(255,255,255,0.5)", width: 28, height: 28, borderRadius: 4,
            cursor: "pointer", fontSize: 14, display: "flex", alignItems: "center", justifyContent: "center",
          }}>✕</button>
        </div>
      </div>

      {/* Body */}
      <div style={{ flex: 1, overflowY: "auto", padding: "18px" }}>
        {/* Current state */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16 }}>
          <span style={{ color: "rgba(255,255,255,0.4)", fontSize: 11 }}>Current:</span>
          <span style={{
            background: `${statCfg.color}18`, color: statCfg.color,
            border: `1px solid ${statCfg.color}50`, fontSize: 11, fontWeight: 700,
            fontFamily: "monospace", padding: "3px 10px", borderRadius: 3,
          }}>{statCfg.label}</span>
        </div>

        {txTarget ? (
          <div>
            <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 10,
              fontFamily: "monospace", marginBottom: 6 }}>
              Transitioning to:{" "}
              <span style={{ color: STATUS_CONFIG[txTarget]?.color || "#888", fontWeight: 700 }}>
                {STATUS_CONFIG[txTarget]?.label || txTarget}
              </span>
            </div>
            <textarea value={txComment} onChange={e => setTxComment(e.target.value)}
              placeholder="Reason for this status change (required for audit trail)…"
              rows={4}
              style={{
                width: "100%", boxSizing: "border-box",
                background: "rgba(255,255,255,0.03)",
                border: `1px solid ${txErr ? "#ff3b3b" : "rgba(255,255,255,0.1)"}`,
                borderRadius: 3, color: "rgba(255,255,255,0.8)", fontSize: 12,
                fontFamily: "monospace", padding: "8px 10px", resize: "vertical",
              }} />
            {txErr && <div style={{ color: "#ff6464", fontSize: 11, fontFamily: "monospace", marginTop: 4 }}>{txErr}</div>}
            <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
              <button onClick={cancelTx} style={{
                background: "none", border: "1px solid rgba(255,255,255,0.1)",
                color: "rgba(255,255,255,0.4)", padding: "5px 12px", borderRadius: 3,
                fontFamily: "monospace", fontSize: 11, cursor: "pointer",
              }}>Cancel</button>
              <button onClick={confirmTx} disabled={txBusy} style={{
                background: `${STATUS_CONFIG[txTarget]?.color || "#888"}20`,
                border: `1px solid ${STATUS_CONFIG[txTarget]?.color || "#888"}50`,
                color: STATUS_CONFIG[txTarget]?.color || "#888",
                padding: "5px 14px", borderRadius: 3, fontFamily: "monospace",
                fontSize: 12, fontWeight: 700, cursor: txBusy ? "wait" : "pointer",
              }}>{txBusy ? "Saving…" : "Confirm"}</button>
            </div>
          </div>
        ) : (
          targets.length > 0 ? (
            <div>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9,
                fontFamily: "monospace", letterSpacing: "1px", marginBottom: 8 }}>TRANSITION TO</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {targets.map(t => {
                  const tc = STATUS_CONFIG[t] || { color: "#888", label: t };
                  return (
                    <button key={t} onClick={() => startTx(t)} style={{
                      background: `${tc.color}08`, border: `1px solid ${tc.color}35`,
                      color: tc.color, fontSize: 11, fontFamily: "monospace", fontWeight: 700,
                      padding: "9px 14px", borderRadius: 3, cursor: "pointer", textAlign: "left",
                    }}>→ {tc.label}</button>
                  );
                })}
              </div>
            </div>
          ) : (
            <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 11,
              fontFamily: "monospace" }}>No transitions available.</div>
          )
        )}
      </div>
    </div>
  );
}

// ── Asset confidence + automated status suggestion ────────────────────────────
// open → investigating : critical risk OR any critical vuln OR (high risk + high vulns)
// investigating → in_review : ≥3 critical vulns OR ≥5 high vulns

function computeAssetConfidence(asset) {
  const RISK_CONF = { critical: 95, high: 75, medium: 50, low: 25 };
  const base  = RISK_CONF[asset.risk] ?? 30;
  const vulns = asset.vulnerabilities || [];
  const boost = Math.min(20, vulns.filter(v => v.severity === "Critical").length * 5 +
                              vulns.filter(v => v.severity === "High").length * 2);
  return Math.min(100, base + boost);
}

function computeAssetAutoStatus(asset, curStat) {
  const vulns     = asset.vulnerabilities || [];
  const critCount = vulns.filter(v => v.severity === "Critical").length;
  const highCount = vulns.filter(v => v.severity === "High").length;
  const conf      = computeAssetConfidence(asset);
  // Suggest under_review for new assets with high-risk findings
  if (curStat === "new") {
    if (asset.risk === "critical" || critCount > 0 || conf >= 75)
      return { to: "under_review", reason: `Risk ${(asset.risk || "—").toUpperCase()}  •  ${critCount} Critical  •  ${highCount} High  •  Confidence ${conf}` };
  }
  return null;
}

function AssetAutoStatusBanner({ autoSug, onApply, busy }) {
  if (!autoSug) return null;
  const tc = STATUS_CONFIG[autoSug.to] || { color: "#888", label: autoSug.to };
  return (
    <div style={{
      background: `${tc.color}08`, border: `1px solid ${tc.color}35`,
      borderRadius: 4, padding: "9px 12px",
      display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap",
    }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ color: tc.color, fontSize: 9, fontFamily: "monospace",
          fontWeight: 700, letterSpacing: "1px", marginBottom: 2 }}>AUTO-STATUS SUGGESTION</div>
        <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10 }}>{autoSug.reason}</div>
      </div>
      <div style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
        <span style={{ background: `${tc.color}18`, color: tc.color,
          border: `1px solid ${tc.color}40`, fontSize: 10,
          fontFamily: "monospace", fontWeight: 700, padding: "2px 8px", borderRadius: 2 }}>
          → {tc.label}
        </span>
        <button onClick={onApply} disabled={busy} style={{
          background: `${tc.color}15`, border: `1px solid ${tc.color}50`, color: tc.color,
          fontSize: 10, fontFamily: "monospace", fontWeight: 700,
          padding: "4px 10px", borderRadius: 3, cursor: busy ? "wait" : "pointer",
        }}>{busy ? "Applying…" : "Apply"}</button>
      </div>
    </div>
  );
}

// ── Asset detail slide-out panel ──────────────────────────────────────────────

function AssetDrawer({ asset, status, onClose, onStatusChange }) {
  const [showStatusPanel, setShowStatusPanel] = useState(false);
  const [autoBusy,        setAutoBusy]        = useState(false);
  const [autoErr,         setAutoErr]         = useState("");

  if (!asset) return null;

  const a        = asset;
  const riskCfg  = RISK_CONFIG[a.risk] || RISK_CONFIG.low;
  // status prop is a plain state string (e.g. "baseline") from AssetsPage.assetStatuses
  const rawStat  = status || a.asset_state || "new";
  const curStat  = (typeof rawStat === "object" ? rawStat?.state : rawStat) || "new";
  const statCfg  = STATUS_CONFIG[curStat] || STATUS_CONFIG.new;
  const prevAudit = typeof rawStat === "object" ? (rawStat?.audit_log || []) : [];

  const vulns     = a.vulnerabilities || [];
  const critCount = vulns.filter(v => v.severity === "Critical").length;
  const highCount = vulns.filter(v => v.severity === "High").length;
  const autoSug   = computeAssetAutoStatus(a, curStat);

  const handleAutoApply = async () => {
    if (!autoSug) return;
    setAutoBusy(true); setAutoErr("");
    try {
      const r = await fetch(`/api/asm/assets/${encodeURIComponent(a.host)}/state`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ to_state: autoSug.to, comment: `Auto-applied — ${autoSug.reason}` }),
      });
      if (!r.ok) { const b = await r.json().catch(() => ({})); setAutoErr(b.error || `HTTP ${r.status}`); }
      else { onStatusChange(a.host, autoSug.to); }
    } catch { setAutoErr("Network error."); }
    setAutoBusy(false);
  };

  return (
    <>
      {/* Backdrop */}
      <div onClick={onClose} style={{
        position: "fixed", inset: 0, zIndex: 3000, background: "rgba(0,0,0,0.55)",
      }} />

      {/* Status sub-panel — second slide-out */}
      {showStatusPanel && (
        <AssetStatusPanel
          asset={a}
          status={status}
          onClose={() => setShowStatusPanel(false)}
          onStatusChange={onStatusChange}
        />
      )}

      {/* Panel */}
      <div style={{
        position: "fixed", top: 0, right: 0, bottom: 0, zIndex: 3001,
        width: 480, background: "#0a0e1a",
        borderLeft: `2px solid ${riskCfg.color}40`,
        display: "flex", flexDirection: "column",
        boxShadow: `-16px 0 40px rgba(0,0,0,0.6)`,
        overflow: "hidden",
      }}>
        {/* Header */}
        <div style={{
          padding: "18px 20px 14px",
          borderBottom: `1px solid ${riskCfg.color}25`,
          background: `${riskCfg.color}06`,
          flexShrink: 0,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div style={{ flex: 1, minWidth: 0, marginRight: 12 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
                <Badge risk={a.risk} />
                <StatusBadge status={curStat} />
              </div>
              <div style={{ color: "rgba(255,255,255,0.9)", fontSize: 15, fontWeight: 700, fontFamily: "monospace" }}>
                {a.host}
              </div>
              {a.owner && <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, marginTop: 2 }}>{a.owner}</div>}
            </div>
            <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
              <button onClick={() => setShowStatusPanel(s => !s)} style={{
                background: showStatusPanel ? `${statCfg.color}18` : "rgba(255,255,255,0.04)",
                border: `1px solid ${showStatusPanel ? statCfg.color + "50" : "rgba(255,255,255,0.1)"}`,
                color: showStatusPanel ? statCfg.color : "rgba(255,255,255,0.45)",
                fontSize: 9, fontFamily: "monospace", fontWeight: 700,
                padding: "4px 9px", borderRadius: 3, cursor: "pointer",
                letterSpacing: "0.8px",
            }}>UPDATE STATE</button>
              <button onClick={onClose} style={{
                background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)",
                color: "rgba(255,255,255,0.5)", width: 28, height: 28, borderRadius: 4,
                cursor: "pointer", fontSize: 14,
                display: "flex", alignItems: "center", justifyContent: "center",
              }}>✕</button>
            </div>
          </div>
        </div>

        {/* Scrollable body */}
        <div style={{ flex: 1, overflowY: "auto", padding: "18px 20px", display: "flex", flexDirection: "column", gap: 18 }}>

          {/* Status lifecycle — auto-suggestion + current state */}
          <div style={{ background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.08)",
            borderRadius: 5, padding: "14px 16px" }}>
            <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace",
              letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 10 }}>Asset State</div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: autoSug ? 10 : 0 }}>
              <span style={{ color: "rgba(255,255,255,0.4)", fontSize: 11 }}>Current:</span>
              <span style={{ background: `${statCfg.color}18`, color: statCfg.color,
                border: `1px solid ${statCfg.color}50`, fontSize: 11, fontWeight: 700,
                fontFamily: "monospace", padding: "3px 10px", borderRadius: 3 }}>{statCfg.label}</span>
            </div>
            {autoSug && <AssetAutoStatusBanner autoSug={autoSug} onApply={handleAutoApply} busy={autoBusy} />}
            {autoErr && <div style={{ color: "#ff6464", fontSize: 10, fontFamily: "monospace", marginTop: 4 }}>{autoErr}</div>}
          </div>

          {/* Core details */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            {[
              { label: "IP ADDRESS",   val: typeof a.ip === "string" ? a.ip : String(a.ip || "—") },
              { label: "TYPE",         val: a.type },
              { label: "PORTS",        val: (a.ports || []).map(p => `:${p}`).join("  ") || "—" },
              { label: "SUBDOMAINS",   val: a.subdomains?.length > 0 ? `${a.subdomains.length} discovered` : "—" },
              { label: "FIRST SEEN",   val: a.first_seen ? new Date(a.first_seen).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }) : null },
              { label: "LAST SEEN",    val: a.last_seen  ? new Date(a.last_seen).toLocaleDateString("en-US",  { month: "short", day: "numeric", year: "numeric" }) : null },
            ].map(({ label, val }) => val && (
              <div key={label}>
                <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace",
                  letterSpacing: "1px", marginBottom: 3 }}>{label}</div>
                <div style={{ color: "rgba(255,255,255,0.7)", fontSize: 12, fontFamily: "monospace" }}>{val}</div>
              </div>
            ))}
          </div>

          {/* Subdomains list */}
          {a.subdomains?.length > 0 && (
            <div>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace",
                letterSpacing: "1px", marginBottom: 6 }}>SUBDOMAINS</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                {a.subdomains.slice(0, 20).map((s, i) => (
                  <span key={i} style={{ background: "rgba(0,229,160,0.06)", color: "rgba(0,229,160,0.6)",
                    border: "1px solid rgba(0,229,160,0.15)", fontSize: 10, fontFamily: "monospace",
                    padding: "2px 8px", borderRadius: 2 }}>{s}</span>
                ))}
                {a.subdomains.length > 20 && <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>+{a.subdomains.length - 20} more</span>}
              </div>
            </div>
          )}

          {/* Vulnerabilities — DashboardPage row layout ─────────────── */}
          {vulns.length > 0 && (
            <div>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace",
                letterSpacing: "1px", marginBottom: 8 }}>FINDINGS ({vulns.length})</div>
              <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
                {critCount > 0 && <span style={{ background: "rgba(255,59,59,0.1)", color: "#ff3b3b", border: "1px solid rgba(255,59,59,0.3)", fontSize: 10, fontFamily: "monospace", fontWeight: 700, padding: "2px 8px", borderRadius: 2 }}>▲ {critCount} CRITICAL</span>}
                {highCount > 0 && <span style={{ background: "rgba(255,140,0,0.1)", color: "#ff8c00", border: "1px solid rgba(255,140,0,0.3)", fontSize: 10, fontFamily: "monospace", fontWeight: 700, padding: "2px 8px", borderRadius: 2 }}>▲ {highCount} HIGH</span>}
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {vulns.slice(0, 10).map((v, i) => {
                  const vc = RISK_CONFIG[v.severity?.toLowerCase()] || RISK_CONFIG.low;
                  return (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 10,
                      padding: "9px 12px", background: "rgba(255,255,255,0.02)", borderRadius: 3,
                      border: `1px solid ${vc.color}12`, borderLeft: `3px solid ${vc.color}` }}>
                      <Badge risk={v.severity?.toLowerCase()} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ color: "white", fontSize: 12, fontWeight: 600,
                          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {typeof v.vulnerability === "string" ? v.vulnerability : String(v.vulnerability || "—")}
                        </div>
                        {v.description && (
                          <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, marginTop: 1,
                            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {typeof v.description === "string" ? v.description : String(v.description)}
                          </div>
                        )}
                      </div>
                      <div style={{ flexShrink: 0, textAlign: "right" }}>
                        {v.module && <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>{typeof v.module === "string" ? v.module : String(v.module)}</div>}
                        {v.cvss   && <div style={{ color: "rgba(255,140,0,0.6)", fontSize: 10, fontFamily: "monospace", fontWeight: 700, marginTop: 1 }}>CVSS {v.cvss}</div>}
                      </div>
                      <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, flexShrink: 0 }}>↗</span>
                    </div>
                  );
                })}
                {vulns.length > 10 && <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>+{vulns.length - 10} more findings</div>}
              </div>
            </div>
          )}

          {/* ── Rich asset context sections ─── (SSL, DNS, HTTP, etc.) ── */}

          {/* SSL / TLS */}
          {a.ssl_detail && (
            <div style={{ background: "rgba(176,110,255,0.04)", border: "1px solid rgba(176,110,255,0.15)", borderRadius: 4, padding: "10px 12px" }}>
              <div style={{ color: "#b06eff", fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginBottom: 6 }}>SSL / TLS</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px 12px" }}>
                {[{label:"Protocol",val:a.ssl_detail.protocol},{label:"Cipher",val:a.ssl_detail.cipher},{label:"Expiry",val:a.ssl_detail.cert_expiry},{label:"Days Left",val:a.cert_days!=null?`${a.cert_days}d`:null}].filter(r=>r.val).map((r,i)=>(
                  <div key={i}>
                    <div style={{color:"rgba(255,255,255,0.25)",fontSize:9,fontFamily:"monospace"}}>{r.label}</div>
                    <div style={{color:"rgba(176,110,255,0.8)",fontSize:10,fontFamily:"monospace"}}>{r.val}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* DNS */}
          {(a.dns_ips?.length > 0 || a.dns_records?.length > 0) && (
            <div style={{ background: "rgba(0,229,160,0.03)", border: "1px solid rgba(0,229,160,0.12)", borderRadius: 4, padding: "10px 12px" }}>
              <div style={{ color: "#00e5a0", fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginBottom: 6 }}>DNS RESOLUTION</div>
              {a.dns_ips?.length > 0 && (
                <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 4 }}>
                  {a.dns_ips.slice(0, 6).map((ip, i) => (
                    <span key={i} style={{ background: "rgba(0,229,160,0.07)", color: "rgba(0,229,160,0.7)", border: "1px solid rgba(0,229,160,0.2)", fontSize: 9, fontFamily: "monospace", padding: "1px 6px", borderRadius: 2 }}>
                      {typeof ip === "string" ? ip : ip?.ip || String(ip)}
                    </span>
                  ))}
                </div>
              )}
              {a.dns_records?.length > 0 && a.dns_records.slice(0, 4).map((r, i) => (
                <div key={i} style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace" }}>{typeof r === "string" ? r : `${r.type} ${r.value}`}</div>
              ))}
            </div>
          )}

          {/* HTTP Analysis */}
          {(a.http_analysis || a.exposed_paths?.length > 0) && (
            <div style={{ background: "rgba(77,158,255,0.04)", border: "1px solid rgba(77,158,255,0.15)", borderRadius: 4, padding: "10px 12px" }}>
              <div style={{ color: "#4d9eff", fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginBottom: 6 }}>HTTP ANALYSIS</div>
              {a.http_analysis?.server && <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 10, fontFamily: "monospace", marginBottom: 4 }}>Server: {a.http_analysis.server}</div>}
              {a.http_analysis?.technologies?.length > 0 && (
                <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 6 }}>
                  {a.http_analysis.technologies.slice(0, 8).map((t, i) => (
                    <span key={i} style={{ background: "rgba(77,158,255,0.08)", color: "rgba(77,158,255,0.7)", border: "1px solid rgba(77,158,255,0.2)", fontSize: 9, fontFamily: "monospace", padding: "1px 5px", borderRadius: 2 }}>{t}</span>
                  ))}
                </div>
              )}
              {a.exposed_paths?.length > 0 && (
                <div>
                  <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace", marginBottom: 3 }}>EXPOSED PATHS ({a.exposed_paths.length})</div>
                  {a.exposed_paths.slice(0, 5).map((p, i) => {
                    const pathStr = typeof p === "string" ? p : (p.path || p.url || String(p));
                    const sev     = typeof p === "object" ? p.severity : null;
                    const st      = typeof p === "object" ? p.status   : null;
                    const sevCfg  = sev ? (RISK_CONFIG[sev.toLowerCase()] || null) : null;
                    return (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 2 }}>
                        <span style={{ color: "rgba(255,140,0,0.7)", fontSize: 10, fontFamily: "monospace", flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>{pathStr}</span>
                        {sevCfg && <span style={{ color: sevCfg.color, fontSize: 9, fontFamily: "monospace", fontWeight: 700, flexShrink: 0 }}>{sevCfg.label}</span>}
                        {st && <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace", flexShrink: 0 }}>{st}</span>}
                      </div>
                    );
                  })}
                  {a.exposed_paths.length > 5 && <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace" }}>+{a.exposed_paths.length - 5} more</div>}
                </div>
              )}
            </div>
          )}

          {/* API Endpoints */}
          {a.api_endpoints?.length > 0 && (
            <div style={{ background: "rgba(0,229,160,0.03)", border: "1px solid rgba(0,229,160,0.12)", borderRadius: 4, padding: "10px 12px" }}>
              <div style={{ color: "#00e5a0", fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginBottom: 6 }}>API ENDPOINTS ({a.api_endpoints.length})</div>
              {a.api_endpoints.slice(0, 6).map((ep, i) => (
                <div key={i} style={{ color: "rgba(255,255,255,0.4)", fontSize: 10, fontFamily: "monospace", marginBottom: 2 }}>
                  {typeof ep === "string" ? ep : (ep.url || ep.path || ep.endpoint || String(ep))}
                </div>
              ))}
              {a.api_endpoints.length > 6 && <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace" }}>+{a.api_endpoints.length - 6} more</div>}
            </div>
          )}

          {/* JS Secrets */}
          {a.js_secrets?.length > 0 && (
            <div style={{ background: "rgba(255,59,59,0.04)", border: "1px solid rgba(255,59,59,0.18)", borderRadius: 4, padding: "10px 12px" }}>
              <div style={{ color: "#ff3b3b", fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginBottom: 6 }}>JS SECRETS ({a.js_secrets.length})</div>
              {a.js_secrets.slice(0, 5).map((s, i) => (
                <div key={i} style={{ color: "rgba(255,100,100,0.7)", fontSize: 10, fontFamily: "monospace", marginBottom: 2 }}>{typeof s === "string" ? s : (s.type || s.key || JSON.stringify(s))}</div>
              ))}
            </div>
          )}

          {/* Cloud Data */}
          {a.cloud_data && Object.keys(a.cloud_data).length > 0 && (
            <div style={{ background: "rgba(245,197,24,0.03)", border: "1px solid rgba(245,197,24,0.15)", borderRadius: 4, padding: "10px 12px" }}>
              <div style={{ color: "#f5c518", fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginBottom: 6 }}>CLOUD EXPOSURE</div>
              {Object.entries(a.cloud_data).slice(0, 4).map(([k, v], i) => (
                <div key={i} style={{ display: "flex", gap: 8, marginBottom: 2 }}>
                  <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace", minWidth: 80 }}>{k}</span>
                  <span style={{ color: "rgba(245,197,24,0.7)", fontSize: 10, fontFamily: "monospace" }}>{typeof v === "object" ? JSON.stringify(v) : String(v)}</span>
                </div>
              ))}
            </div>
          )}

          {/* Supply Chain */}
          {a.supply_chain && Object.keys(a.supply_chain).length > 0 && (
            <div style={{ background: "rgba(255,140,0,0.03)", border: "1px solid rgba(255,140,0,0.15)", borderRadius: 4, padding: "10px 12px" }}>
              <div style={{ color: "#ff8c00", fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginBottom: 6 }}>SUPPLY CHAIN RISK</div>
              {Object.entries(a.supply_chain).slice(0, 4).map(([k, v], i) => (
                <div key={i} style={{ display: "flex", gap: 8, marginBottom: 2 }}>
                  <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace", minWidth: 90 }}>{k.replace(/_/g, " ")}</span>
                  <span style={{ color: "rgba(255,140,0,0.7)", fontSize: 10, fontFamily: "monospace" }}>{typeof v === "object" ? JSON.stringify(v) : String(v)}</span>
                </div>
              ))}
            </div>
          )}

          {/* Social Engineering */}
          {a.social_eng && Object.keys(a.social_eng).length > 0 && (
            <div style={{ background: "rgba(255,59,59,0.03)", border: "1px solid rgba(255,59,59,0.12)", borderRadius: 4, padding: "10px 12px" }}>
              <div style={{ color: "#ff3b3b", fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginBottom: 6 }}>SOCIAL ENGINEERING EXPOSURE</div>
              {Object.entries(a.social_eng).slice(0, 4).map(([k, v], i) => (
                <div key={i} style={{ display: "flex", gap: 8, marginBottom: 2 }}>
                  <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace", minWidth: 90 }}>{k.replace(/_/g, " ")}</span>
                  <span style={{ color: "rgba(255,100,100,0.7)", fontSize: 10, fontFamily: "monospace" }}>{typeof v === "object" ? JSON.stringify(v) : String(v)}</span>
                </div>
              ))}
            </div>
          )}

          {/* IP Enrichment (ASN, Org, Geo) — from first DNS IP object */}
          {a.dns_ips?.length > 0 && typeof a.dns_ips[0] === "object" &&
           (a.dns_ips[0].org || a.dns_ips[0].asn || a.dns_ips[0].country) && (
            <div style={{ background: "rgba(0,229,160,0.03)", border: "1px solid rgba(0,229,160,0.12)", borderRadius: 4, padding: "10px 12px" }}>
              <div style={{ color: "#00e5a0", fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginBottom: 6 }}>IP ENRICHMENT</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px 12px" }}>
                {[
                  { label: "ASN",     val: a.dns_ips[0].asn },
                  { label: "ORG",     val: a.dns_ips[0].org },
                  { label: "Country", val: a.dns_ips[0].country },
                  { label: "City",    val: a.dns_ips[0].city },
                ].filter(r => r.val).map((r, i) => (
                  <div key={i}>
                    <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace" }}>{r.label}</div>
                    <div style={{ color: "rgba(0,229,160,0.7)", fontSize: 10, fontFamily: "monospace" }}>{r.val}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* WHOIS */}
          {a.whois_full && Object.keys(a.whois_full).length > 0 && (
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 4, padding: "10px 12px" }}>
              <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginBottom: 6 }}>WHOIS</div>
              {Object.entries(a.whois_full).filter(([,v]) => v).slice(0, 6).map(([k, v], i) => (
                <div key={i} style={{ display: "flex", gap: 8, marginBottom: 2 }}>
                  <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace", minWidth: 100 }}>{k.replace(/_/g, " ")}</span>
                  <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace" }}>{String(v)}</span>
                </div>
              ))}
            </div>
          )}

          {/* OSINT Data */}
          {a.osint_data && Object.keys(a.osint_data).length > 0 && (
            <div style={{ background: "rgba(176,110,255,0.03)", border: "1px solid rgba(176,110,255,0.15)", borderRadius: 4, padding: "10px 12px" }}>
              <div style={{ color: "#b06eff", fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginBottom: 6 }}>OSINT DATA</div>
              {Object.entries(a.osint_data)
                .filter(([, v]) => v != null && (Array.isArray(v) ? v.length > 0 : true))
                .slice(0, 6).map(([k, v], i) => (
                <div key={i} style={{ display: "flex", gap: 8, marginBottom: 2 }}>
                  <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace", minWidth: 110 }}>{k.replace(/_/g, " ")}</span>
                  <span style={{ color: "rgba(176,110,255,0.7)", fontSize: 10, fontFamily: "monospace" }}>
                    {Array.isArray(v) ? `${v.length} items` : typeof v === "object" ? JSON.stringify(v).slice(0, 60) : String(v)}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Mobile / API Analysis */}
          {a.mobile_api && Object.keys(a.mobile_api).length > 0 && (
            <div style={{ background: "rgba(245,197,24,0.03)", border: "1px solid rgba(245,197,24,0.15)", borderRadius: 4, padding: "10px 12px" }}>
              <div style={{ color: "#f5c518", fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginBottom: 6 }}>MOBILE / API</div>
              {Object.entries(a.mobile_api)
                .filter(([, v]) => v != null && (Array.isArray(v) ? v.length > 0 : true))
                .slice(0, 5).map(([k, v], i) => (
                <div key={i} style={{ display: "flex", gap: 8, marginBottom: 2 }}>
                  <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace", minWidth: 110 }}>{k.replace(/_/g, " ")}</span>
                  <span style={{ color: "rgba(245,197,24,0.7)", fontSize: 10, fontFamily: "monospace" }}>
                    {Array.isArray(v) ? `${v.length} entries` : typeof v === "object" ? JSON.stringify(v).slice(0, 60) : String(v)}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* PQC Readiness */}
          {a.pqc_data && Object.keys(a.pqc_data).length > 0 && (
            <div style={{ background: "rgba(77,158,255,0.03)", border: "1px solid rgba(77,158,255,0.15)", borderRadius: 4, padding: "10px 12px" }}>
              <div style={{ color: "#4d9eff", fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginBottom: 6 }}>PQC READINESS</div>
              {Object.entries(a.pqc_data)
                .filter(([, v]) => v != null)
                .slice(0, 5).map(([k, v], i) => (
                <div key={i} style={{ display: "flex", gap: 8, marginBottom: 2 }}>
                  <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace", minWidth: 110 }}>{k.replace(/_/g, " ")}</span>
                  <span style={{ color: "rgba(77,158,255,0.7)", fontSize: 10, fontFamily: "monospace" }}>
                    {typeof v === "boolean" ? (v ? "Yes" : "No") : typeof v === "object" ? JSON.stringify(v).slice(0, 60) : String(v)}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* ── Audit trail ──────────────────────────────────────────────── */}
          {prevAudit.length > 0 && (
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
              borderRadius: 5, padding: "14px 16px" }}>
              <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace",
                letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 10 }}>
                Audit Trail ({prevAudit.length})
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {[...prevAudit].reverse().map((e, i) => {
                  const fc = STATUS_CONFIG[e.from_state] || { color: "#888", label: e.from_state };
                  const tc = STATUS_CONFIG[e.to_state]   || { color: "#888", label: e.to_state };
                  return (
                    <div key={i} style={{ borderLeft: `2px solid ${tc.color}40`, paddingLeft: 10 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                        <span style={{ color: fc.color, fontSize: 9, fontFamily: "monospace", fontWeight: 700 }}>{fc.label}</span>
                        <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 9 }}>→</span>
                        <span style={{ color: tc.color, fontSize: 9, fontFamily: "monospace", fontWeight: 700 }}>{tc.label}</span>
                        {e.actor && <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace" }}>• {e.actor}</span>}
                        {e.created_at && <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace", marginLeft: "auto" }}>{new Date(e.created_at).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</span>}
                      </div>
                      {e.comment && <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, marginTop: 3, lineHeight: 1.4 }}>{e.comment}</div>}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

        </div>
      </div>
    </>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

const GRID_COLS = "90px 1fr 105px 130px 110px 72px 110px 24px";

export function AssetsPage({ assets, setSelectedAsset, setShowImport }) {
  const [assetStatuses,   setAssetStatuses]   = useState({});
  const [activeAsset,     setActiveAsset]     = useState(null);
  const [discoveryFilter, setDiscoveryFilter] = useState(null); // null | "new" | "dropped" | "existing"
  const [sortField,  setSortField]  = useState("risk");
  const [sortDir,    setSortDir]    = useState("asc");
  const [pageSize,   setPageSize]   = useState(50);
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    fetch("/api/asm/statuses", { credentials: "include" })
      .then(r => r.ok ? r.json() : {})
      .then(d => {
        // Backend returns asset_states as { version, baseline, assets: { host: {state,...} } }
        const raw = d.asset_states || {};
        setAssetStatuses(raw.assets || raw);
      })
      .catch(() => {});
  }, []);

  const handleStatusChange = (assetId, newStatus) =>
    setAssetStatuses(prev => ({ ...prev, [assetId]: newStatus }));

  const openDrawer  = (a, e) => { e.stopPropagation(); setActiveAsset(a); };
  const closeDrawer = () => setActiveAsset(null);

  // Resolve the analyst-set lifecycle state for any asset.
  // assetStatuses entries can be a string (from handleStatusChange) or
  // an object { state, audit_log, ... } (loaded from /api/asm/statuses).
  const getResolvedState = (a) => {
    const entry = assetStatuses[a.host];
    if (typeof entry === "object" && entry !== null) return entry.state || a.asset_state || "new";
    return entry || a.asset_state || (a.change === "persisted" ? "baseline" : "new");
  };

  // Discovery predicates for alert banners (scanner-driven, not analyst state)
  const isNew     = a => a.is_new === true || a.change === "new" || a.change === "appeared";
  const isDropped = a => a.change === "disappeared";

  const newCount      = assets.filter(isNew).length;
  const droppedCount  = assets.filter(isDropped).length;

  // State counts (analyst lifecycle states — used for filter pills)
  const stateCounts = Object.fromEntries(
    ["new", "baseline", "under_review", "ignored", "dropped"].map(k => [k, assets.filter(a => getResolvedState(a) === k).length])
  );

  // Filter by analyst lifecycle state (discoveryFilter holds state key or null)
  const filteredAssets = discoveryFilter ? assets.filter(a => getResolvedState(a) === discoveryFilter) : assets;

  const toggleFilter = key => { setDiscoveryFilter(f => f === key ? null : key); setCurrentPage(1); };

  const ASSET_RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  const handleSort = (col) => {
    if (sortField === col) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortField(col); setSortDir("asc"); }
    setCurrentPage(1);
  };
  const getAssetFieldVal = (a, field) => {
    switch (field) {
      case "risk":      return ASSET_RISK_ORDER[a.risk] ?? 4;
      case "host":      return (a.host || "").toLowerCase();
      case "ip":        return (a.ip || "").toLowerCase();
      case "type":      return (a.type || "").toLowerCase();
      case "ports":     return (a.ports || []).length;
      case "findings":  return (a.vulnerabilities || []).length;
      case "discovery": return (a.change || "").toLowerCase();
      case "status":    return getResolvedState(a).toLowerCase();
      default: return 0;
    }
  };
  const sortedAssets = [...filteredAssets].sort((a, b) => {
    const va = getAssetFieldVal(a, sortField), vb = getAssetFieldVal(b, sortField);
    const cmp = typeof va === "number" ? va - vb : (va < vb ? -1 : va > vb ? 1 : 0);
    return sortDir === "asc" ? cmp : -cmp;
  });
  const totalPages = Math.max(1, Math.ceil(sortedAssets.length / pageSize));
  const pagedAssets = sortedAssets.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  return (
    <div>
      {activeAsset && (
        <AssetDrawer
          asset={activeAsset}
          status={assetStatuses[activeAsset.host]}
          onClose={closeDrawer}
          onStatusChange={handleStatusChange}
        />
      )}

      {/* Page header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
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

      {/* ── Discovery Alert Banner ─────────────────────────────────────────── */}
      {(newCount > 0 || droppedCount > 0) && (
        <div style={{ display: "flex", gap: 12, marginBottom: 14, flexWrap: "wrap" }}>
          {newCount > 0 && (
            <div style={{
              flex: 1, minWidth: 240,
              background: "rgba(0,229,160,0.04)", border: "1px solid rgba(0,229,160,0.22)",
              borderLeft: "3px solid #00e5a0", borderRadius: 5, padding: "11px 16px",
              display: "flex", alignItems: "center", gap: 14,
            }}>
              <div style={{ color: "#00e5a0", fontSize: 24, fontWeight: 700, fontFamily: "monospace", flexShrink: 0, lineHeight: 1 }}>{newCount}</div>
              <div style={{ flex: 1 }}>
                <div style={{ color: "#00e5a0", fontSize: 11, fontWeight: 700, fontFamily: "monospace", letterSpacing: "0.8px" }}>
                  NEW ASSET{newCount !== 1 ? "S" : ""} DETECTED
                </div>
                <div style={{ color: "rgba(255,255,255,0.38)", fontSize: 10, marginTop: 2 }}>
                  Not present in previous scan — verify ownership and exposure
                </div>
              </div>
              <button onClick={() => toggleFilter("new")} style={{
                background: discoveryFilter === "new" ? "rgba(0,229,160,0.18)" : "rgba(0,229,160,0.06)",
                border: "1px solid rgba(0,229,160,0.3)", color: "#00e5a0",
                fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "0.8px",
                padding: "4px 10px", borderRadius: 3, cursor: "pointer", whiteSpace: "nowrap", flexShrink: 0,
              }}>{discoveryFilter === "new" ? "CLEAR" : "SHOW ONLY"}</button>
            </div>
          )}
          {droppedCount > 0 && (
            <div style={{
              flex: 1, minWidth: 240,
              background: "rgba(255,140,0,0.04)", border: "1px solid rgba(255,140,0,0.28)",
              borderLeft: "3px solid #ff8c00", borderRadius: 5, padding: "11px 16px",
              display: "flex", alignItems: "center", gap: 14,
            }}>
              <div style={{ color: "#ff8c00", fontSize: 24, fontWeight: 700, fontFamily: "monospace", flexShrink: 0, lineHeight: 1 }}>{droppedCount}</div>
              <div style={{ flex: 1 }}>
                <div style={{ color: "#ff8c00", fontSize: 11, fontWeight: 700, fontFamily: "monospace", letterSpacing: "0.8px" }}>
                  ASSET{droppedCount !== 1 ? "S" : ""} DROPPED FROM SCAN
                </div>
                <div style={{ color: "rgba(255,255,255,0.38)", fontSize: 10, marginTop: 2 }}>
                  Was reachable last scan — now missing. Investigate immediately.
                </div>
              </div>
              <button onClick={() => toggleFilter("dropped")} style={{
                background: discoveryFilter === "dropped" ? "rgba(255,140,0,0.18)" : "rgba(255,140,0,0.06)",
                border: "1px solid rgba(255,140,0,0.32)", color: "#ff8c00",
                fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "0.8px",
                padding: "4px 10px", borderRadius: 3, cursor: "pointer", whiteSpace: "nowrap", flexShrink: 0,
              }}>{discoveryFilter === "dropped" ? "CLEAR" : "SHOW ONLY"}</button>
            </div>
          )}
        </div>
      )}

      {/* ── Filter pills ───────────────────────────────────────────────────── */}
      {assets.length > 0 && (
        <div style={{ display: "flex", gap: 6, marginBottom: 16, alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 9, fontFamily: "monospace", fontWeight: 700, letterSpacing: "1px", marginRight: 4 }}>FILTER:</span>
          {[
            { key: null,           label: `ALL  ${assets.length}`,                       color: "#ffffff" },
            { key: "new",          label: `NEW  ${stateCounts.new}`,                     color: "#00e5a0" },
            { key: "baseline",     label: `BASELINE  ${stateCounts.baseline}`,           color: "#4d9eff" },
            { key: "under_review", label: `UNDER REVIEW  ${stateCounts.under_review}`,   color: "#f5c518" },
            { key: "ignored",      label: `IGNORED  ${stateCounts.ignored}`,             color: "#888888" },
            { key: "dropped",      label: `DROPPED  ${stateCounts.dropped}`,             color: "#ff8c00" },
          ].map(({ key, label, color }) => (
            <button key={String(key)} onClick={() => toggleFilter(key)} style={{
              background: discoveryFilter === key ? `${color}20` : "rgba(255,255,255,0.06)",
              border: `1px solid ${discoveryFilter === key ? color + "70" : "rgba(255,255,255,0.2)"}`,
              color: discoveryFilter === key ? color : "rgba(255,255,255,0.65)",
              fontSize: 9, fontFamily: "monospace", fontWeight: 700,
              padding: "5px 12px", borderRadius: 3, cursor: "pointer", letterSpacing: "0.8px",
            }}>{label}</button>
          ))}
          <div style={{ marginLeft: "auto" }}>
            <select value={pageSize} onChange={e => { setPageSize(Number(e.target.value)); setCurrentPage(1); }}
              style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
                color: "white", padding: "5px 10px", borderRadius: 4, fontSize: 11, fontFamily: "monospace" }}>
              {[50, 100, 250].map(n => <option key={n} value={n}>{n} / page</option>)}
            </select>
          </div>
        </div>
      )}

      <WorldMapWidget assets={assets} />

      <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 4, overflow: "hidden" }}>
        {/* Column header */}
        {(() => {
          const COL_KEY = { "Risk": "risk", "Host": "host", "IP": "ip", "Type": "type",
            "Ports": "ports", "Findings": "findings", "State": "status", "": null };
          return (
            <div style={{ display: "grid", gridTemplateColumns: GRID_COLS, padding: "10px 20px",
              borderBottom: "1px solid rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.01)" }}>
              {Object.entries(COL_KEY).map(([h, key]) => {
                const active = key && sortField === key;
                return (
                  <span key={h} onClick={() => key && handleSort(key)}
                    style={{ color: active ? "rgba(255,255,255,0.7)" : "rgba(255,255,255,0.3)",
                      fontSize: 10, letterSpacing: "1.2px", textTransform: "uppercase", fontFamily: "monospace",
                      cursor: key ? "pointer" : "default", display: "flex", alignItems: "center",
                      gap: 3, userSelect: "none" }}>
                    {h}
                    {key && <span style={{ fontSize: 13, opacity: active ? 1 : 0.4, lineHeight: 1 }}>
                      {active ? (sortDir === "asc" ? "↑" : "↓") : "↕"}
                    </span>}
                  </span>
                );
              })}
            </div>
          );
        })()}

        {sortedAssets.length === 0 && (
          <div style={{ padding: "32px 20px", textAlign: "center", color: "rgba(255,255,255,0.2)", fontFamily: "monospace" }}>
            {discoveryFilter ? `No ${discoveryFilter} assets in this scan` : "No assets — import a scan or launch a new one"}
          </div>
        )}

        {pagedAssets.map((a, i) => {
          const curStat  = getResolvedState(a);
          const isActive = activeAsset?.host === a.host;
          const _new     = isNew(a);
          const _dropped = isDropped(a);

          return (
            <div key={a.id}
              onClick={(e) => openDrawer(a, e)}
              style={{
                display: "grid",
                gridTemplateColumns: GRID_COLS,
                padding: "13px 20px", gap: 8,
                borderBottom: "1px solid rgba(255,255,255,0.04)",
                borderLeft: _dropped ? "3px solid rgba(255,140,0,0.55)"
                          : _new     ? "3px solid rgba(0,229,160,0.4)"
                          : "3px solid transparent",
                background: isActive  ? "rgba(255,255,255,0.04)"
                          : _dropped  ? "rgba(255,140,0,0.025)"
                          : _new      ? "rgba(0,229,160,0.018)"
                          : i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)",
                alignItems: "center", cursor: "pointer", transition: "background 0.1s",
              }}>
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

              <StatusBadge status={curStat} />
              <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 12, textAlign: "center" }}>↗</span>
            </div>
          );
        })}

        {/* Pagination controls */}
        {totalPages > 1 && (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
            padding: "10px 20px", borderTop: "1px solid rgba(255,255,255,0.06)",
            background: "rgba(255,255,255,0.01)" }}>
            <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace" }}>
              {(currentPage - 1) * pageSize + 1}–{Math.min(currentPage * pageSize, sortedAssets.length)} of {sortedAssets.length}
            </span>
            <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
              <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1}
                style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)",
                  color: currentPage === 1 ? "rgba(255,255,255,0.15)" : "rgba(255,255,255,0.5)",
                  padding: "3px 10px", borderRadius: 3, cursor: currentPage === 1 ? "default" : "pointer",
                  fontSize: 11, fontFamily: "monospace" }}>‹ Prev</button>
              {Array.from({ length: totalPages }, (_, i) => i + 1)
                .filter(p => p === 1 || p === totalPages || Math.abs(p - currentPage) <= 1)
                .reduce((acc, p, idx, arr) => { if (idx > 0 && p - arr[idx - 1] > 1) acc.push("…"); acc.push(p); return acc; }, [])
                .map((p, i) => typeof p === "string" ? (
                  <span key={`ell-${i}`} style={{ color: "rgba(255,255,255,0.2)", fontSize: 11, padding: "0 2px" }}>…</span>
                ) : (
                  <button key={p} onClick={() => setCurrentPage(p)}
                    style={{ background: p === currentPage ? "rgba(0,229,160,0.12)" : "rgba(255,255,255,0.04)",
                      border: `1px solid ${p === currentPage ? "rgba(0,229,160,0.4)" : "rgba(255,255,255,0.1)"}`,
                      color: p === currentPage ? "#00e5a0" : "rgba(255,255,255,0.4)",
                      padding: "3px 8px", borderRadius: 3, cursor: "pointer",
                      fontSize: 11, fontFamily: "monospace", minWidth: 28 }}>{p}</button>
                ))}
              <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages}
                style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)",
                  color: currentPage === totalPages ? "rgba(255,255,255,0.15)" : "rgba(255,255,255,0.5)",
                  padding: "3px 10px", borderRadius: 3, cursor: currentPage === totalPages ? "default" : "pointer",
                  fontSize: 11, fontFamily: "monospace" }}>Next ›</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

