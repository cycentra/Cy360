import { Component } from "react";
import { clearNonEssentialCache } from '../core/auth.js';

export class PageErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { err: null }; }
  static getDerivedStateFromError(e) { return { err: e }; }
  componentDidCatch(e, info) { console.error("[PageErrorBoundary]", e, info); }
  render() {
    if (this.state.err) {
      const handleClearReload = () => {
        try { clearNonEssentialCache(); } catch {}
        window.location.reload();
      };
      return (
        <div style={{ padding: "40px 32px", color: "rgba(255,255,255,0.55)", fontFamily: "monospace" }}>
          <div style={{ color: "#ff3b3b", fontSize: 11, letterSpacing: "1.5px", marginBottom: 12 }}>RENDER ERROR</div>
          <div style={{ fontSize: 12, marginBottom: 16 }}>{String(this.state.err)}</div>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button onClick={() => this.setState({ err: null })}
              style={{ background: "rgba(0,229,160,0.08)", border: "1px solid rgba(0,229,160,0.25)",
                color: "#00e5a0", padding: "6px 16px", borderRadius: 3, fontFamily: "monospace",
                fontSize: 11, cursor: "pointer" }}>
              Retry
            </button>
            <button onClick={handleClearReload}
              style={{ background: "rgba(255,140,0,0.08)", border: "1px solid rgba(255,140,0,0.3)",
                color: "#ff8c00", padding: "6px 16px", borderRadius: 3, fontFamily: "monospace",
                fontSize: 11, cursor: "pointer" }}>
              Clear Cache &amp; Reload
            </button>
          </div>
          <div style={{ marginTop: 12, fontSize: 10, color: "rgba(255,255,255,0.55)" }}>
            "Clear Cache &amp; Reload" removes cached module data, AI settings, and asset statuses — your account and scan data are not affected.
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
