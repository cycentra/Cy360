/**
 * src/pages/assets/ImportModal.jsx
 */

import { useState } from "react";

export function ImportModal({ onClose, onImport }) {
  const [text, setText] = useState("");
  const [err,  setErr]  = useState("");

  const handle = () => {
    try {
      onImport(JSON.parse(text));
      onClose();
    } catch (e) {
      setErr("Invalid JSON: " + e.message);
    }
  };

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)" }} onClick={onClose}>
      <div style={{ background: "#0d0f14", border: "1px solid rgba(0,229,160,0.2)", borderTop: "2px solid #00e5a0", borderRadius: 6, padding: 32, width: "min(560px,95vw)" }} onClick={e => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <span style={{ color: "white", fontFamily: "monospace", fontSize: 14, fontWeight: 700 }}>IMPORT SCAN JSON</span>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "rgba(255,255,255,0.4)", cursor: "pointer", fontSize: 20 }}>×</button>
        </div>
        <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 11, marginBottom: 12 }}>
          Paste output from <code style={{ color: "#00e5a0" }}>cycentra_scan.py</code>
        </div>
        <textarea value={text} onChange={e => { setText(e.target.value); setErr(""); }}
          placeholder="Paste your CyCentra scan JSON here..."
          style={{ width: "100%", height: 220, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)", color: "#00e5a0", fontFamily: "monospace", fontSize: 12, padding: 14, borderRadius: 3, outline: "none", resize: "vertical", boxSizing: "border-box" }}/>
        {err && <div style={{ color: "#ff3b3b", fontSize: 11, fontFamily: "monospace", marginTop: 8 }}>{err}</div>}
        <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
          <button onClick={handle} style={{ background: "#00e5a0", color: "#0d0f14", fontFamily: "monospace", fontWeight: 700, fontSize: 12, letterSpacing: "1px", padding: "10px 24px", border: "none", borderRadius: 3, cursor: "pointer", textTransform: "uppercase" }}>
            Import & Apply
          </button>
          <button onClick={onClose} style={{ background: "transparent", color: "rgba(255,255,255,0.4)", fontFamily: "monospace", fontSize: 12, padding: "10px 20px", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 3, cursor: "pointer" }}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
