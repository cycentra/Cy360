/**
 * App.jsx — CyCentra 360 Portal v4.4
 * Layout shell + page router.
 *
 * v4.4: Adds ScanHistoryDropdown in topbar for timeline selection (last 15 scans).
 */

import { useState, Component } from "react";
import { clearNonEssentialCache } from './core/auth.js';

// ── Error Boundary — prevents any page render crash from blanking the whole app ─
class PageErrorBoundary extends Component {
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
import { CYSCAN_URL } from './core/constants.js';
import { clearSSOToken } from './core/auth.js';
import { useAppState } from './hooks/useAppState.js';
import { Sidebar } from './sidebar/Sidebar.jsx';

import { SiemIncidentsPage } from './siem/SiemIncidentsPage';
import { SiemRiskScoresPage } from './siem/SiemRiskScoresPage';
import { SiemUebaPage }       from './siem/SiemUebaPage';
import { InternalExposureDashboard } from './siem/InternalExposureDashboard';

import { LoginPage }         from './pages/login/LoginPage.jsx';
import { ScanPage }          from './pages/scan/ScanPage.jsx';
import { DashboardPage }     from './pages/dashboard/DashboardPage.jsx';
import { AssetsPage }        from './pages/assets/AssetsPage.jsx';
import { VulnerabilityPage } from './pages/vulnerabilities/VulnerabilityPage.jsx';
import { MarketplacePage }   from './pages/marketplace/MarketplacePage.jsx';
import { SystemSettingsPage } from './pages/settings/SystemSettingsPage.jsx';
import { AssetModal }        from './pages/assets/AssetModal.jsx';
import { ImportModal }       from './pages/assets/ImportModal.jsx';
import { CyMindChatOverlay } from './components/CyMindChatOverlay.jsx';
import { AuditTrailPage }         from './pages/audit/AuditTrailPage.jsx';
import { BenchmarkPage }          from './pages/benchmark/BenchmarkPage.jsx';
import { PlatformExtensionsPage } from './pages/platform-extensions/index.jsx';

// ── Security Compliance (GRC) pages ──────────────────────────────────────────
import { ComplianceDashboardPage }  from './pages/compliance/ComplianceDashboardPage.jsx';
import { ComplianceLiveAlertsPage } from './pages/compliance/ComplianceLiveAlertsPage.jsx';
import { RiskRegisterPage, RiskHeatmapPage, RiskAppetitePage } from './pages/compliance/RiskRegisterPage.jsx';
import { ComplianceFindingsPage }   from './pages/compliance/ComplianceFindingsPage.jsx';
import { ComplianceReportsPage }    from './pages/compliance/ComplianceReportsPage.jsx';
import { PolicyDocumentsPage }      from './pages/compliance/PolicyDocumentsPage.jsx';
import { ComplianceAssessmentPage } from './pages/compliance/ComplianceAssessmentPage.jsx';

// ── Scan History Dropdown ─────────────────────────────────────────────────────

function ScanHistoryDropdown({ scanHistory, selectedScanId, onSelect, historyLoading }) {
  const [open, setOpen] = useState(false);

  if (!scanHistory || scanHistory.length === 0) return null;

  const current = scanHistory.find(s => s.scan_id === selectedScanId) || scanHistory[0];

  const typeColor = { deep: "#b06eff", standard: "#00e5a0", passive: "#4d9eff" };
  const typeLabel = { deep: "DEEP", standard: "STD", passive: "PASS" };

  function fmtDate(ts) {
    if (!ts) return "—";
    return new Date(ts).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  return (
    <div style={{ position: "relative" }}>
      {/* Trigger button */}
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

      {/* Dropdown panel */}
      {open && (
        <div
          onClick={() => setOpen(false)}
          style={{ position: "fixed", inset: 0, zIndex: 200 }}>
          <div
            onClick={e => e.stopPropagation()}
            style={{
              position: "absolute", top: 38, right: 0,
              background: "#0d1117", border: "1px solid rgba(255,255,255,0.12)",
              borderRadius: 6, width: 380, boxShadow: "0 8px 32px rgba(0,0,0,0.6)",
              zIndex: 201, overflow: "hidden",
            }}>
            {/* Header */}
            <div style={{ padding: "10px 14px", borderBottom: "1px solid rgba(255,255,255,0.06)", display: "flex", alignItems: "center", gap: 8 }}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#00e5a0" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
              </svg>
              <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, fontFamily: "monospace", letterSpacing: "1.5px", textTransform: "uppercase" }}>
                Scan Timeline · Last {scanHistory.length}
              </span>
            </div>

            {/* Column headers */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 60px 60px 60px", padding: "6px 14px", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
              {["Date / Domain", "Type", "Findings", "Subdomains"].map(h => (
                <span key={h} style={{ color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "1px" }}>{h}</span>
              ))}
            </div>

            {/* Scan rows */}
            <div style={{ maxHeight: 400, overflowY: "auto" }}>
              {scanHistory.map((s, i) => {
                const isSelected = s.scan_id === selectedScanId;
                const tc   = typeColor[s.scan_type] || "#00e5a0";
                const tl   = typeLabel[s.scan_type]  || (s.scan_type || "").toUpperCase().slice(0, 4);
                const crit = s.critical  || 0;
                const high = s.high      || 0;
                return (
                  <div
                    key={s.scan_id}
                    onClick={() => { onSelect(s.scan_id); setOpen(false); }}
                    style={{
                      display: "grid", gridTemplateColumns: "1fr 60px 60px 60px",
                      padding: "10px 14px", cursor: "pointer",
                      background: isSelected ? "rgba(0,229,160,0.06)" : i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)",
                      borderLeft: isSelected ? "2px solid #00e5a0" : "2px solid transparent",
                      borderBottom: "1px solid rgba(255,255,255,0.03)",
                      transition: "background 0.15s",
                    }}
                    onMouseEnter={e => !isSelected && (e.currentTarget.style.background = "rgba(255,255,255,0.04)")}
                    onMouseLeave={e => !isSelected && (e.currentTarget.style.background = i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)")}
                  >
                    {/* Date + domain */}
                    <div>
                      <div style={{ color: isSelected ? "#00e5a0" : "rgba(255,255,255,0.75)", fontSize: 11, fontFamily: "monospace", fontWeight: isSelected ? 700 : 400 }}>
                        {fmtDate(s.last_scan)}
                        {isSelected && <span style={{ color: "#00e5a0", fontSize: 9, marginLeft: 5 }}>● ACTIVE</span>}
                      </div>
                      <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", marginTop: 2 }}>
                        {s.domain || "—"}
                      </div>
                    </div>
                    {/* Scan type */}
                    <div>
                      <span style={{ background: `${tc}18`, color: tc, fontSize: 9, fontFamily: "monospace", fontWeight: 700, padding: "2px 5px", borderRadius: 2 }}>
                        {tl}
                      </span>
                    </div>
                    {/* Findings */}
                    <div>
                      <span style={{ color: crit > 0 ? "#ff3b3b" : high > 0 ? "#ff8c00" : "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace", fontWeight: (crit + high) > 0 ? 700 : 400 }}>
                        {s.total_findings || 0}
                      </span>
                      {crit > 0 && <span style={{ color: "#ff3b3b", fontSize: 9, fontFamily: "monospace", marginLeft: 3 }}>▲{crit}</span>}
                    </div>
                    {/* Subdomains */}
                    <div>
                      <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, fontFamily: "monospace" }}>
                        {s.subdomains || 0}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Footer hint */}
            <div style={{ padding: "8px 14px", borderTop: "1px solid rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.2)", fontSize: 9, fontFamily: "monospace" }}>
              Click any row to load that scan's results
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────

export default function App() {
  const {
    user, authReady, data, assets, activeTab, selectedAsset, showImport,
    installedModules, stats, scanTime,
    scanHistory, selectedScanId, historyLoading,
    setActiveTab, setSelectedAsset, setShowImport,
    handleImport, handleStatusChange, handleInstallModule,
    handleUninstallModule, handleScanComplete,
    handleScanSelect,
  } = useAppState();

  const [showCyMind, setShowCyMind] = useState(false);

  if (!authReady) return null;
  if (!user) return <LoginPage />;

  const canUseCyMind = user?.role === "analyst" || user?.role === "admin";

  const handleLogout = () => {
    clearSSOToken();
    window.location.href = `${CYSCAN_URL}/auth/logout?provider=${encodeURIComponent(user.provider || "google")}`;
  };

  return (
    <div style={{ height:"100vh", display:"flex", flexDirection:"column" }}>

      {/* ── Top bar ──────────────────────────────────────────────────────── */}
      <div style={{ height:52, background:"rgba(10,12,18,0.98)", borderBottom:"1px solid rgba(255,255,255,0.06)",
        display:"flex", alignItems:"center", justifyContent:"space-between",
        padding:"0 20px 0 0", position:"sticky", top:0, zIndex:60, backdropFilter:"blur(16px)", flexShrink:0 }}>

        {/* Logo */}
        <div style={{ width:220, display:"flex", alignItems:"center", gap:10, padding:"0 20px" }}>
          <svg width="22" height="22" viewBox="0 0 24 24" style={{ animation:"hexPulse 4s ease-in-out infinite", flexShrink:0 }}>
            <polygon points="12,2 22,8 22,16 12,22 2,16 2,8" fill="none" stroke="#00e5a0" strokeWidth="1.5"/>
            <polygon points="12,6 18,10 18,14 12,18 6,14 6,10" fill="rgba(0,229,160,0.12)" stroke="#00e5a0" strokeWidth="0.75"/>
            <circle cx="12" cy="12" r="2" fill="#00e5a0"/>
          </svg>
          <div>
            <div style={{ color:"white", fontFamily:"'Space Mono',monospace", fontSize:13, fontWeight:700, letterSpacing:"2px", lineHeight:1.1 }}>
              CY<span style={{ color:"#00e5a0" }}>CENTRA</span>
            </div>
            <div style={{ color:"#00e5a0", fontFamily:"'Space Mono',monospace", fontSize:8, letterSpacing:"4px", opacity:0.6, marginTop:1 }}>360°</div>
          </div>
        </div>

        {/* Right side */}
        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          {/* Scan History Dropdown — shows when scan data is loaded */}
          {data && (
            <ScanHistoryDropdown
              scanHistory={scanHistory}
              selectedScanId={selectedScanId}
              onSelect={handleScanSelect}
              historyLoading={historyLoading}
            />
          )}

          {/* Live scan domain */}
          {data && (
            <div style={{ display:"flex", alignItems:"center", gap:5 }}>
              <span style={{ width:5, height:5, borderRadius:"50%", background:"#00e5a0", display:"inline-block", animation:"pulse 2s infinite", boxShadow:"0 0 6px #00e5a0" }}/>
              <span style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace" }}>{data.meta?.domain?.toUpperCase()}</span>
            </div>
          )}

          {/* Import button */}
          <button onClick={() => setShowImport(true)}
            style={{ background:"rgba(0,229,160,0.08)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.25)",
              padding:"5px 12px", borderRadius:20, fontSize:11, fontFamily:"monospace", cursor:"pointer", fontWeight:700,
              display:"flex", alignItems:"center", gap:5 }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            Import
          </button>

          <div style={{ width:1, height:24, background:"rgba(255,255,255,0.08)" }}/>

          {/* User + logout */}
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <div style={{ width:28, height:28, borderRadius:"50%", background:"rgba(0,229,160,0.12)",
              border:"1.5px solid rgba(0,229,160,0.3)", display:"flex", alignItems:"center", justifyContent:"center",
              color:"#00e5a0", fontFamily:"monospace", fontSize:10, fontWeight:700 }}>
              {user.avatar}
            </div>
            <div style={{ lineHeight:1.3 }}>
              <div style={{ color:"rgba(255,255,255,0.75)", fontSize:12, fontWeight:600 }}>{user.name}</div>
              <div style={{ color:"rgba(255,255,255,0.25)", fontSize:9, fontFamily:"monospace" }}>{user.provider?.toUpperCase()} SSO</div>
            </div>
            <button onClick={handleLogout}
              style={{ background:"transparent", color:"rgba(255,255,255,0.25)", border:"none",
                padding:"4px 6px", borderRadius:3, fontSize:10, fontFamily:"monospace", cursor:"pointer" }}
              title="Sign out">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
                <polyline points="16 17 21 12 16 7"/>
                <line x1="21" y1="12" x2="9" y2="12"/>
              </svg>
            </button>
          </div>
        </div>
      </div>

      {/* ── Body ─────────────────────────────────────────────────────────── */}
      <div style={{ flex:1, display:"flex", overflow:"hidden" }}>

        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          installedModules={installedModules}
          data={data}
          scanTime={scanTime}
          user={user}
        />

        {/* Page content */}
        <div style={{ flex:1, overflowY:"auto", background:"#090b10",
          backgroundImage:"radial-gradient(ellipse at 20% 30%, rgba(0,229,160,0.025) 0%, transparent 50%), radial-gradient(ellipse at 80% 10%, rgba(0,120,255,0.03) 0%, transparent 50%)" }}>
          <PageErrorBoundary>
          <div style={{ padding:"28px 32px", animation:"fadeIn 0.35s ease", maxWidth:1300, margin:"0 auto" }}>

            {activeTab==="scan"           && <ScanPage user={user} onScanComplete={handleScanComplete}/>}
            {activeTab==="dashboard"      && <DashboardPage assets={assets} data={data} stats={stats} installedModules={installedModules} setActiveTab={setActiveTab} setSelectedAsset={setSelectedAsset} setShowImport={setShowImport}/>}
            {activeTab==="assets"         && <AssetsPage assets={assets} setSelectedAsset={setSelectedAsset} setShowImport={setShowImport}/>}
            {activeTab==="vulns"          && <VulnerabilityPage assets={assets} scanHistory={scanHistory} selectedScanId={selectedScanId} onScanSelect={handleScanSelect}/>}
            {activeTab==="siem-incidents" && <SiemIncidentsPage/>}
            {activeTab==="siem-risk"      && <SiemRiskScoresPage/>}
            {activeTab==="siem-ueba"      && <SiemUebaPage/>}
            {activeTab==="internal-dashboard" && <InternalExposureDashboard setActiveTab={setActiveTab}/>}
            {activeTab==="marketplace"    && <MarketplacePage user={user} installedModules={installedModules} onInstall={handleInstallModule} onUninstall={handleUninstallModule}/>}
            {activeTab==="benchmark"            && <BenchmarkPage />}
            {activeTab==="system-settings"     && <SystemSettingsPage />}
            {activeTab==="audit-trail"         && <AuditTrailPage />}
            {activeTab==="platform-extensions" && <PlatformExtensionsPage installedModules={installedModules} onInstall={handleInstallModule} onUninstall={handleUninstallModule}/>}

            {/* ── Security Compliance (GRC) ─────────────────────────────── */}
            {activeTab==="comp-dashboard"   && <ComplianceDashboardPage setActiveTab={setActiveTab}/>}
            {activeTab==="comp-assessment"  && <ComplianceAssessmentPage/>}
            {activeTab==="comp-findings"    && <ComplianceFindingsPage/>}
            {activeTab==="comp-risks"       && <RiskRegisterPage setActiveTab={setActiveTab}/>}
            {activeTab==="comp-heatmap"     && <RiskHeatmapPage/>}
            {activeTab==="comp-appetite"    && <RiskAppetitePage/>}
            {activeTab==="comp-reports"     && <ComplianceReportsPage/>}
            {activeTab==="comp-policy"      && <PolicyDocumentsPage/>}

          </div>
          </PageErrorBoundary>
        </div>
      </div>

      {selectedAsset && <AssetModal asset={selectedAsset} onClose={()=>setSelectedAsset(null)} onStatusChange={handleStatusChange}/>}
      {showImport    && <ImportModal onClose={()=>setShowImport(false)} onImport={handleImport}/>}

      {/* ── CyMind FAB — analyst / admin only ──────────────────────────── */}
      {canUseCyMind && !showCyMind && (
        <button
          onClick={() => setShowCyMind(true)}
          title="Open CyMind AI Assistant"
          style={{
            position: "fixed", bottom: 28, right: 28, zIndex: 800,
            width: 52, height: 52, borderRadius: "50%", border: "none", cursor: "pointer",
            background: "linear-gradient(135deg, rgba(0,229,160,0.9), rgba(0,180,130,0.9))",
            boxShadow: "0 4px 20px rgba(0,229,160,0.4), 0 2px 8px rgba(0,0,0,0.5)",
            display: "flex", alignItems: "center", justifyContent: "center",
            transition: "transform 0.15s, box-shadow 0.15s",
          }}
          onMouseEnter={e => { e.currentTarget.style.transform = "scale(1.08)"; e.currentTarget.style.boxShadow = "0 6px 28px rgba(0,229,160,0.55), 0 3px 10px rgba(0,0,0,0.5)"; }}
          onMouseLeave={e => { e.currentTarget.style.transform = "scale(1)";    e.currentTarget.style.boxShadow = "0 4px 20px rgba(0,229,160,0.4), 0 2px 8px rgba(0,0,0,0.5)"; }}
        >
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="rgba(5,15,12,0.9)" strokeWidth="2">
            <path d="M12 2a7 7 0 0 1 7 7c0 3.5-2.5 6.4-5.8 7.7L12 22l-1.2-5.3C7.5 15.4 5 12.5 5 9a7 7 0 0 1 7-7z"/>
            <circle cx="12" cy="9" r="2" fill="rgba(5,15,12,0.5)" stroke="rgba(5,15,12,0.9)" strokeWidth="1.5"/>
          </svg>
        </button>
      )}

      {/* CyMind chat overlay */}
      {canUseCyMind && showCyMind && (
        <CyMindChatOverlay onClose={() => setShowCyMind(false)} />
      )}
    </div>
  );
}
