/**
 * SiemEngineStatus.jsx
 * Wraps any CySIEM Intelligence page with an availability check.
 * If the correlation engine is unreachable, shows EngineOfflineBanner
 * instead of the page content — no crashes, no blank screens.
 */

import { useState, useEffect } from "react";
import { siemApi } from "./siemApi";

export function SiemEngineStatus({ children }) {
  const [status, setStatus] = useState("checking"); // "checking" | "online" | "offline"

  const check = async () => {
    setStatus("checking");
    try {
      const r = await siemApi.getHealth();
      setStatus(r.ok ? "online" : "offline");
    } catch {
      setStatus("offline");
    }
  };

  useEffect(() => { check(); }, []);

  if (status === "checking") {
    return (
      <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "40px 0",
        color: "rgba(255,255,255,0.4)", fontSize: 13 }}>
        <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#f5c518",
          animation: "pulse 1.5s infinite", display: "inline-block" }} />
        Checking CySIEM Correlation Engine…
      </div>
    );
  }

  if (status === "offline") {
    return <EngineOfflineBanner onRetry={check} />;
  }

  return children;
}

function EngineOfflineBanner({ onRetry }) {
  return (
    <div style={{ padding: "32px 0" }}>
      <div style={{ background: "rgba(245,197,24,0.06)", border: "1px solid rgba(245,197,24,0.25)",
        borderLeft: "4px solid #f5c518", borderRadius: 6, padding: "28px 32px", maxWidth: 680 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <span style={{ fontSize: 22 }}>⚠️</span>
          <div>
            <div style={{ color: "#f5c518", fontWeight: 700, fontSize: 15, fontFamily: "monospace" }}>
              CORRELATION ENGINE OFFLINE
            </div>
            <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, marginTop: 2 }}>
              The CySIEM Correlation Engine is not responding
            </div>
          </div>
        </div>

        <div style={{ color: "rgba(255,255,255,0.6)", fontSize: 13, lineHeight: 1.8, marginBottom: 20 }}>
          The engine provides incident grouping, UEBA, and risk scoring. To start it:
        </div>

        <div style={{ background: "rgba(0,0,0,0.4)", borderRadius: 4, padding: "14px 18px",
          fontFamily: "monospace", fontSize: 12, color: "#00e5a0", marginBottom: 20 }}>
          <div style={{ color: "rgba(255,255,255,0.3)", marginBottom: 6 }}># On your server:</div>
          <div>cd /opt/cycentra/cysiemstack</div>
          <div>docker compose up -d</div>
          <div style={{ marginTop: 8, color: "rgba(255,255,255,0.3)" }}># Watch startup logs:</div>
          <div>docker compose logs -f correlation-engine</div>
        </div>

        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button onClick={onRetry}
            style={{ background: "rgba(0,229,160,0.12)", border: "1px solid rgba(0,229,160,0.4)",
              color: "#00e5a0", padding: "9px 18px", borderRadius: 4, cursor: "pointer",
              fontSize: 13, fontFamily: "monospace", fontWeight: 700 }}>
            ↻ Retry Connection
          </button>
          <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 12, alignSelf: "center" }}>
            All other portal features are unaffected.
          </div>
        </div>
      </div>
    </div>
  );
}
