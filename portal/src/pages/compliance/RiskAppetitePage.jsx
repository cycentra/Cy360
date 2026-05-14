/**
 * RiskAppetitePage.jsx
 * =====================
 * Risk tolerance thresholds per category/label, and display of risks
 * currently exceeding their tolerance level.
 */

import { useState, useEffect } from "react";
import { API_BASE } from "../../core/constants.js";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};

export function RiskAppetitePage() {
  const [data, setData]         = useState(null);
  const [loading, setLoading]   = useState(true);
  const [editing, setEditing]   = useState(false);
  const [thresholds, setThresholds] = useState({ low: 4, medium: 9, high: 19 });
  const [saving, setSaving]     = useState(false);
  const [saveMsg, setSaveMsg]   = useState(null);

  const load = () => {
    setLoading(true);
    fetch(`${API_BASE}/api/comp/appetite`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        setData(d);
        setThresholds(d.appetite_thresholds || { low: 4, medium: 9, high: 19 });
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleSave = () => {
    setSaving(true); setSaveMsg(null);
    fetch(`${API_BASE}/api/comp/appetite`, {
      method: "PUT", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(thresholds),
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setData(d); setSaveMsg("Saved"); setEditing(false); })
      .catch(e => setSaveMsg(`Failed: ${e}`))
      .finally(() => setSaving(false));
  };

  const inp = {
    background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
    borderRadius: 4, color: C.text, fontFamily: "monospace", fontSize: 13,
    padding: "7px 10px", width: 80, outline: "none",
  };

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px", fontFamily: "monospace",
          textTransform: "uppercase", marginBottom: 4 }}>SECURITY COMPLIANCE</div>
        <h1 style={{ color: C.text, fontSize: 20, fontWeight: 700, margin: 0 }}>Risk Appetite</h1>
        <div style={{ color: C.muted, fontSize: 11, marginTop: 4, fontFamily: "monospace" }}>
          Define organisational tolerance thresholds for each risk level.
        </div>
      </div>

      {/* Thresholds card */}
      <div style={{ background: "#0d1117", border: `1px solid ${C.border}`, borderRadius: 8,
        padding: "20px 24px", marginBottom: 24 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
          marginBottom: 20 }}>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px", fontFamily: "monospace",
            textTransform: "uppercase" }}>Appetite Thresholds (Risk Score 1-25)</div>
          {!editing ? (
            <button onClick={() => setEditing(true)}
              style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
                color: C.accent, padding: "6px 14px", borderRadius: 4, fontFamily: "monospace",
                fontSize: 11, fontWeight: 700, cursor: "pointer" }}>
              Edit Thresholds
            </button>
          ) : (
            <div style={{ display: "flex", gap: 8 }}>
              <button onClick={() => { setEditing(false); setThresholds(data?.appetite_thresholds || thresholds); }}
                style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
                  color: C.muted, padding: "6px 14px", borderRadius: 4, fontFamily: "monospace",
                  fontSize: 11, cursor: "pointer" }}>Cancel</button>
              <button onClick={handleSave} disabled={saving}
                style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
                  color: C.accent, padding: "6px 14px", borderRadius: 4, fontFamily: "monospace",
                  fontSize: 11, fontWeight: 700, cursor: "pointer", opacity: saving ? 0.6 : 1 }}>
                {saving ? "Saving..." : "Save"}
              </button>
            </div>
          )}
        </div>
        {saveMsg && <div style={{ color: saveMsg.includes("Failed") ? C.red : C.accent,
          fontSize: 10, fontFamily: "monospace", marginBottom: 12 }}>{saveMsg}</div>}

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 24 }}>
          {[
            { label: "Low tolerance", key: "low", color: C.accent,
              desc: "Risks below this score are within appetite" },
            { label: "Medium tolerance", key: "medium", color: C.orange,
              desc: "Risks at this level need monitoring" },
            { label: "High tolerance", key: "high", color: C.red,
              desc: "Risks above this score exceed appetite" },
          ].map(({ label, key, color, desc }) => (
            <div key={key}>
              <div style={{ color, fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px",
                textTransform: "uppercase", marginBottom: 8 }}>{label}</div>
              {editing ? (
                <input type="number" min={1} max={25} style={inp}
                  value={thresholds[key] || 0}
                  onChange={e => setThresholds(t => ({ ...t, [key]: +e.target.value }))} />
              ) : (
                <div style={{ color, fontSize: 36, fontFamily: "monospace", fontWeight: 700 }}>
                  {loading ? "—" : thresholds[key]}
                </div>
              )}
              <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace", marginTop: 6 }}>
                {desc}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Risks exceeding appetite */}
      {!loading && data && (
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
            <div style={{ color: C.muted, fontSize: 9, letterSpacing: "1.5px", fontFamily: "monospace",
              textTransform: "uppercase" }}>Risks Exceeding Appetite</div>
            <span style={{ background: "rgba(255,59,59,0.15)", color: C.red, fontSize: 11,
              fontFamily: "monospace", fontWeight: 700, padding: "2px 8px", borderRadius: 3 }}>
              {data.exceeding_appetite || 0}
            </span>
          </div>
          {(data.risks_exceeding || []).length === 0 ? (
            <div style={{ color: C.accent, fontFamily: "monospace", fontSize: 12,
              background: "rgba(0,229,160,0.04)", border: `1px solid rgba(0,229,160,0.15)`,
              borderRadius: 6, padding: "16px 20px" }}>
              All risks are within appetite thresholds.
            </div>
          ) : (
            <div style={{ background: "#0d1117", border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                    {["Risk", "Category", "Score", "Appetite", "Treatment"].map(h => (
                      <th key={h} style={{ padding: "10px 14px", textAlign: "left",
                        color: C.muted, fontSize: 9, fontFamily: "monospace",
                        letterSpacing: "1px", textTransform: "uppercase" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.risks_exceeding.map((r, i) => (
                    <tr key={r.id} style={{ borderBottom: `1px solid rgba(255,255,255,0.03)`,
                      background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)" }}>
                      <td style={{ padding: "10px 14px", color: C.text, fontSize: 12 }}>{r.title}</td>
                      <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10, fontFamily: "monospace" }}>{r.category}</td>
                      <td style={{ padding: "10px 14px" }}>
                        <span style={{ color: C.red, fontFamily: "monospace", fontWeight: 700, fontSize: 13 }}>
                          {r.risk_score}/25
                        </span>
                      </td>
                      <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase" }}>{r.appetite}</td>
                      <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase" }}>{r.treatment}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
