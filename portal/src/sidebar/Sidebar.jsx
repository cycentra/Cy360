/**
 * src/sidebar/Sidebar.jsx
 * ========================
 * Renders the left navigation sidebar from navConfig sections.
 */

import { buildNavSections } from './navConfig.jsx';

export function Sidebar({ activeTab, setActiveTab, installedModules, data, scanTime, allowedPages }) {
  const sections = buildNavSections({ installedModules, data });

  const isPageAllowed = (itemId) => {
    if (!allowedPages) return true; // null = unrestricted (admin)
    return allowedPages.includes(itemId);
  };

  return (
    <div style={{
      width: 220, background: "rgba(10,12,18,0.95)",
      borderRight: "1px solid rgba(255,255,255,0.05)",
      display: "flex", flexDirection: "column", flexShrink: 0,
    }}>
      {/* Nav items */}
      <div style={{ flex: 1, overflowY: "auto", padding: "12px 8px" }}>
        {sections.map(sec => {
          const visibleItems = sec.items.filter(item => isPageAllowed(item.id));
          if (visibleItems.length === 0) return null;
          return (
          <div key={sec.section} style={{ marginBottom: 20 }}>
            <div style={{
              color: "rgba(255,255,255,0.45)", fontSize: 9,
              fontFamily: "monospace", letterSpacing: "1.8px", fontWeight: 700,
              padding: "0 10px", marginBottom: 4,
            }}>
              {sec.section}
            </div>

            {visibleItems.map(item => {
              const active = activeTab === item.id;
              const accent = item.accent || "#00e5a0";

              if (item.externalUrl) {
                return (
                  <button key={item.id} className="side-item"
                    onClick={() => {
                      window.history.pushState({ from: "portal" }, "", window.location.pathname);
                      window.location.href = item.externalUrl;
                    }}
                    style={{
                      width: "100%", display: "flex", alignItems: "center", gap: 10,
                      padding: "9px 10px", borderRadius: 6, marginBottom: 2,
                      border: "none", background: "transparent",
                      color: "rgba(255,255,255,0.5)", cursor: "pointer", textAlign: "left",
                    }}>
                    <span style={{ flexShrink: 0, opacity: 0.7 }}>{item.icon}</span>
                    <span style={{ fontSize: 13, fontWeight: 500, flex: 1 }}>{item.label}</span>
                    <svg style={{ opacity: 0.3 }} width="10" height="10" viewBox="0 0 24 24"
                      fill="none" stroke="currentColor" strokeWidth="2.5">
                      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                      <polyline points="15 3 21 3 21 9"/>
                      <line x1="10" y1="14" x2="21" y2="3"/>
                    </svg>
                  </button>
                );
              }

              return (
                <button key={item.id} className="side-item"
                  onClick={() => setActiveTab(item.id)}
                  style={{
                    width: "100%", display: "flex", alignItems: "center", gap: 10,
                    padding: "9px 10px", borderRadius: 6, marginBottom: 2,
                    border: "none",
                    background:  active ? `${accent}14` : "transparent",
                    color:       active ? accent : "rgba(255,255,255,0.5)",
                    cursor: "pointer", textAlign: "left",
                    boxShadow: active ? `inset 2px 0 0 ${accent}` : "none",
                  }}>
                  <span style={{ flexShrink: 0, color: active ? accent : "rgba(255,255,255,0.35)" }}>
                    {item.icon}
                  </span>
                  <span style={{ fontSize: 13, fontWeight: active ? 600 : 400, flex: 1 }}>
                    {item.label}
                  </span>
                  {item.badge > 0 && (
                    <span style={{
                      background:  active ? accent : "rgba(255,255,255,0.1)",
                      color:       active ? "#0d0f14" : "rgba(255,255,255,0.5)",
                      fontSize: 9, fontWeight: 700, fontFamily: "monospace",
                      padding: "1px 6px", borderRadius: 10, flexShrink: 0,
                    }}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
          );
        })}
      </div>

      {/* Footer — last scan info */}
      <div style={{ padding: "12px 16px", borderTop: "1px solid rgba(255,255,255,0.05)" }}>
        {data ? (
          <div>
            <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 9, fontFamily: "monospace", letterSpacing: "1px", marginBottom: 3 }}>
              LAST SCAN
            </div>
            <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace" }}>
              {data.meta?.domain}
            </div>
            <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 9, marginTop: 2 }}>
              {scanTime}
            </div>
          </div>
        ) : (
          <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace" }}>
            No scan loaded
          </div>
        )}
      </div>
    </div>
  );
}
