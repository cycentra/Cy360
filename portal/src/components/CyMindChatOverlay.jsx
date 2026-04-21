/**
 * CyMindChatOverlay.jsx
 * Slide-in iframe overlay that loads the CyMind chat interface.
 * Rendered by App.jsx for analyst/admin users only.
 *
 * The iframe always loads /cymind/ — a reverse-proxy location injected into the
 * CyCentra nginx server block by routes.py when the admin configures a CyMind URL.
 * This eliminates mixed-content browser blocks (iframe serves from the same HTTPS
 * origin as the portal) and avoids direct cross-origin access to Server B.
 *
 * Props:
 *   onClose — callback to hide the overlay
 */

import { useState, useEffect } from "react";
import { API_BASE } from "../core/constants.js";

// ── Inline keyframe injection (runs once) ─────────────────────────────────────
const _STYLE_ID = "cymind-overlay-styles";
if (!document.getElementById(_STYLE_ID)) {
  const s = document.createElement("style");
  s.id = _STYLE_ID;
  s.textContent = `
    @keyframes cymindSlideIn  { from { transform: translateY(100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
    @keyframes cymindSlideOut { from { transform: translateY(0);    opacity: 1; } to { transform: translateY(100%); opacity: 0; } }
    .cymind-overlay-enter { animation: cymindSlideIn  0.3s cubic-bezier(0.16,1,0.3,1) forwards; }
    .cymind-overlay-exit  { animation: cymindSlideOut 0.25s ease-in forwards; }
  `;
  document.head.appendChild(s);
}

// ── Component ─────────────────────────────────────────────────────────────────
export function CyMindChatOverlay({ onClose }) {
  const [exiting,   setExiting]   = useState(false);
  const [frameUrl,  setFrameUrl]  = useState(null);
  const [loadError, setLoadError] = useState(null);

  // Verify integration is configured, then load via local nginx proxy path
  useEffect(() => {
    fetch(`${API_BASE}/api/system/cymind`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (d?.cymindUrl) {
          // Always proxy through nginx /cymind/ — same HTTPS origin, no mixed-content
          setFrameUrl("/cymind/");
        } else {
          setLoadError("CyMind URL not configured. Go to System Settings → CyMind to set it up.");
        }
      })
      .catch(() => setLoadError("Could not load CyMind configuration."));
  }, []);

  const handleClose = () => {
    setExiting(true);
    setTimeout(onClose, 240);
  };

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={handleClose}
        style={{
          position: "fixed", inset: 0, zIndex: 900,
          background: "rgba(0,0,0,0.45)", backdropFilter: "blur(3px)",
        }}
      />

      {/* Overlay panel */}
      <div
        className={exiting ? "cymind-overlay-exit" : "cymind-overlay-enter"}
        style={{
          position: "fixed", bottom: 0, right: 24,
          width: "min(480px, calc(100vw - 48px))",
          height: "min(680px, calc(100vh - 80px))",
          zIndex: 901,
          display: "flex", flexDirection: "column",
          background: "#0d1117",
          border: "1px solid rgba(0,229,160,0.25)",
          borderBottom: "none",
          borderRadius: "10px 10px 0 0",
          boxShadow: "0 -8px 40px rgba(0,0,0,0.7), 0 0 0 1px rgba(0,229,160,0.08)",
          overflow: "hidden",
        }}
      >
        {/* Title bar */}
        <div style={{
          height: 44, display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "0 14px 0 16px", flexShrink: 0,
          background: "rgba(0,229,160,0.06)",
          borderBottom: "1px solid rgba(0,229,160,0.15)",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {/* CyMind icon */}
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00e5a0" strokeWidth="1.8">
              <path d="M12 2a7 7 0 0 1 7 7c0 3.5-2.5 6.4-5.8 7.7L12 22l-1.2-5.3C7.5 15.4 5 12.5 5 9a7 7 0 0 1 7-7z"/>
              <circle cx="12" cy="9" r="2.5" fill="rgba(0,229,160,0.3)" stroke="#00e5a0" strokeWidth="1.5"/>
            </svg>
            <span style={{ color: "#00e5a0", fontFamily: "monospace", fontSize: 12, fontWeight: 700, letterSpacing: "1.5px" }}>
              CYMIND
            </span>
            <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace" }}>
              AI Security Assistant
            </span>
          </div>
          <button
            onClick={handleClose}
            title="Close"
            style={{
              background: "transparent", border: "none", cursor: "pointer",
              color: "rgba(255,255,255,0.4)", padding: 4, borderRadius: 4,
              display: "flex", alignItems: "center",
            }}
            onMouseEnter={e => e.currentTarget.style.color = "rgba(255,255,255,0.8)"}
            onMouseLeave={e => e.currentTarget.style.color = "rgba(255,255,255,0.4)"}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>

        {/* Content area */}
        <div style={{ flex: 1, position: "relative", overflow: "hidden" }}>
          {loadError && (
            <div style={{
              position: "absolute", inset: 0, display: "flex", flexDirection: "column",
              alignItems: "center", justifyContent: "center", gap: 12, padding: 24,
            }}>
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.2)" strokeWidth="1.5">
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
              <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 12, fontFamily: "monospace", textAlign: "center", lineHeight: 1.7 }}>
                {loadError}
              </div>
            </div>
          )}

          {!loadError && !frameUrl && (
            <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
              <div style={{ color: "rgba(0,229,160,0.6)", fontFamily: "monospace", fontSize: 11 }}>Loading…</div>
            </div>
          )}

          {frameUrl && (
            <iframe
              src={frameUrl}
              title="CyMind AI Assistant"
              style={{ width: "100%", height: "100%", border: "none", display: "block" }}
              allow="clipboard-write"
              sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
            />
          )}
        </div>
      </div>
    </>
  );
}
