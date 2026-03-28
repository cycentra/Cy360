/**
 * src/pages/siem/SiemFeedPage.jsx
 * =================================
 * CySIEM Integration Feed — forwards Critical/High ASM alerts into SIEM.
 * Extracted from the inline CySIEMFeedPage function in App.jsx.
 */

export function SiemFeedPage({ data, installedModules }) {
  const alerts = data?.cysiemAlerts || [];

  return (
    <div>
      <div style={{ marginBottom: 22 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
          <h1 style={{ fontSize: 22, fontWeight: 700 }}>CySIEM Integration Feed</h1>
          <span style={{ background: "rgba(255,59,59,0.12)", color: "#ff3b3b", fontSize: 10, fontFamily: "monospace", padding: "3px 10px", borderRadius: 2, fontWeight: 700, letterSpacing: "1px" }}>LIVE BRIDGE</span>
        </div>
        <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13 }}>
          Critical/High ASM findings forwarded to CySIEM as security events.
        </p>
      </div>

      {alerts.length === 0 ? (
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: "40px 24px", textAlign: "center" }}>
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 13, fontFamily: "monospace" }}>
            No critical or high findings to forward. Run a scan to populate this feed.
          </div>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {alerts.map((a, i) => {
            const lvlColor = a.level >= 12 ? "#ff3b3b" : a.level >= 8 ? "#ff8c00" : "#f5c518";
            return (
              <div key={i} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderLeft: `3px solid ${lvlColor}`, padding: "10px 14px", borderRadius: 2 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                  <span style={{ color: lvlColor, fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
                    LEVEL {a.level} · {a.rule_id}
                  </span>
                  <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace" }}>
                    {new Date(a.ts).toLocaleTimeString()}
                  </span>
                </div>
                <div style={{ color: "rgba(255,255,255,0.8)", fontSize: 12 }}>{a.description}</div>
                <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, fontFamily: "monospace", marginTop: 4 }}>→ {a.asset}</div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
