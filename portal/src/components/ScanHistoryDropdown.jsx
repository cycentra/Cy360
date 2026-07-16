import { useState } from "react";

const typeColor = { deep: "#b06eff", standard: "#00e5a0", passive: "#4d9eff" };
const typeLabel = { deep: "DEEP", standard: "STD", passive: "PASS" };

function fmtDate(ts) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function ScanHistoryDropdown({ scanHistory, selectedScanId, onSelect, historyLoading }) {
  const [open, setOpen] = useState(false);

  if (!scanHistory || scanHistory.length === 0) return null;

  const current = scanHistory.find(s => s.scan_id === selectedScanId) || scanHistory[0];

  return (
    <div style={{ position: "relative" }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          display: "flex", alignItems: "center", gap: 6,
          background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.10)",
          borderRadius: 4, padding: "5px 10px", cursor: "pointer", color: "white",
        }}>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="rgba(0,229,160,0.8)" strokeWidth="2">
          <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
        </svg>
        <span style={{ color: "rgba(255,255,255,0.7)", fontSize: 10, fontFamily: "monospace" }}>
          {historyLoading ? "…" : fmtDate(current?.last_scan)}
        </span>
        {current?.scan_type && (
          <span style={{ background: `${typeColor[current.scan_type] || "#00e5a0"}18`, color: typeColor[current.scan_type] || "#00e5a0", fontSize: 9, fontFamily: "monospace", fontWeight: 700, padding: "1px 5px", borderRadius: 2 }}>
            {typeLabel[current.scan_type] || current.scan_type.toUpperCase()}
          </span>
        )}
        <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 9 }}>{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div onClick={() => setOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 200 }}>
          <div
            onClick={e => e.stopPropagation()}
            style={{
              position: "absolute", top: 38, right: 0,
              background: "#0d1117", border: "1px solid rgba(255,255,255,0.12)",
              borderRadius: 6, width: 380, boxShadow: "0 8px 32px rgba(0,0,0,0.6)",
              zIndex: 201, overflow: "hidden",
            }}>
            <div style={{ padding: "10px 14px", borderBottom: "1px solid rgba(255,255,255,0.06)", display: "flex", alignItems: "center", gap: 8 }}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#00e5a0" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
              </svg>
              <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, fontFamily: "monospace", letterSpacing: "1.5px", textTransform: "uppercase" }}>
                Scan Timeline · Last {scanHistory.length}
              </span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 60px 60px 60px", padding: "6px 14px", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
              {["Date / Domain", "Type", "Findings", "Subdomains"].map(h => (
                <span key={h} style={{ color: "rgba(255,255,255,0.45)", fontSize: 9, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "1px" }}>{h}</span>
              ))}
            </div>
            <div style={{ maxHeight: 400, overflowY: "auto" }}>
              {scanHistory.map((s, i) => {
                const isSelected = s.scan_id === selectedScanId;
                const tc = typeColor[s.scan_type] || "#00e5a0";
                const tl = typeLabel[s.scan_type] || (s.scan_type || "").toUpperCase().slice(0, 4);
                const crit = s.critical || 0;
                const high = s.high || 0;
                return (
                  <div
                    key={s.scan_id}
                    onClick={() => { onSelect(s.scan_id); setOpen(false); }}
                    style={{
                      display: "grid", gridTemplateColumns: "1fr 60px 60px 60px",
                      padding: "10px 14px", cursor: "pointer",
                      background: isSelected ? "rgba(0,229,160,0.06)" : i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)",
                      borderLeft: isSelected ? "2px solid #00e5a0" : "2px solid transparent",
                      borderBottom: "1px solid rgba(255,255,255,0.03)", transition: "background 0.15s",
                    }}
                    onMouseEnter={e => !isSelected && (e.currentTarget.style.background = "rgba(255,255,255,0.04)")}
                    onMouseLeave={e => !isSelected && (e.currentTarget.style.background = i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)")}
                  >
                    <div>
                      <div style={{ color: isSelected ? "#00e5a0" : "rgba(255,255,255,0.75)", fontSize: 11, fontFamily: "monospace", fontWeight: isSelected ? 700 : 400 }}>
                        {fmtDate(s.last_scan)}
                        {isSelected && <span style={{ color: "#00e5a0", fontSize: 9, marginLeft: 5 }}>● ACTIVE</span>}
                      </div>
                      <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", marginTop: 2 }}>{s.domain || "—"}</div>
                    </div>
                    <div>
                      <span style={{ background: `${tc}18`, color: tc, fontSize: 9, fontFamily: "monospace", fontWeight: 700, padding: "2px 5px", borderRadius: 2 }}>{tl}</span>
                    </div>
                    <div>
                      <span style={{ color: crit > 0 ? "#ff3b3b" : high > 0 ? "#ff8c00" : "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace", fontWeight: (crit + high) > 0 ? 700 : 400 }}>
                        {s.total_findings || 0}
                      </span>
                      {crit > 0 && <span style={{ color: "#ff3b3b", fontSize: 9, fontFamily: "monospace", marginLeft: 3 }}>▲{crit}</span>}
                    </div>
                    <div>
                      <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, fontFamily: "monospace" }}>{s.subdomains || 0}</span>
                    </div>
                  </div>
                );
              })}
            </div>
            <div style={{ padding: "8px 14px", borderTop: "1px solid rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.45)", fontSize: 9, fontFamily: "monospace" }}>
              Click any row to load that scan's results
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
