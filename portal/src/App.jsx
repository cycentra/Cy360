/**
 * App.jsx — CyCentra 360 Portal v4.3
 * Layout shell + page router.
 * Fix: logout now calls clearSSOToken() then redirects to CYSCAN_URL/auth/logout
 * matching original behaviour exactly.
 */

import { AI_PROVIDERS } from './registry/aiProviders.js';
import { CYSCAN_URL } from './core/constants.js';
import { clearSSOToken } from './core/auth.js';
import { useAppState } from './hooks/useAppState.js';
import { Sidebar } from './sidebar/Sidebar.jsx';

import { SiemIncidentsPage } from './siem/SiemIncidentsPage';
import { SiemRiskScoresPage } from './siem/SiemRiskScoresPage';
import { SiemUebaPage }       from './siem/SiemUebaPage';

import { LoginPage }         from './pages/login/LoginPage.jsx';
import { ScanPage }          from './pages/scan/ScanPage.jsx';
import { DashboardPage }     from './pages/dashboard/DashboardPage.jsx';
import { AssetsPage }        from './pages/assets/AssetsPage.jsx';
import { VulnerabilityPage } from './pages/vulnerabilities/VulnerabilityPage.jsx';
import { SiemFeedPage }      from './pages/siem/SiemFeedPage.jsx';
import { PlatformPage }      from './pages/platform/PlatformPage.jsx';
import { AISettingsPage }    from './pages/ai/AISettingsPage.jsx';
import { UseCasesPage }      from './pages/usecases/UseCasesPage.jsx';
import { SystemSettingsPage } from './pages/settings/SystemSettingsPage.jsx';
import { AssetModal }        from './pages/assets/AssetModal.jsx';
import { ImportModal }       from './pages/assets/ImportModal.jsx';

export default function App() {
  const {
    user, authReady, data, assets, activeTab, selectedAsset, showImport,
    installedModules, aiConfig, stats, scanTime,
    setActiveTab, setSelectedAsset, setShowImport,
    handleImport, handleStatusChange, handleInstallModule,
    handleUninstallModule, handleSaveAIConfig, handleScanComplete,
  } = useAppState();

  if (!authReady) return null;
  if (!user) return <LoginPage />;

  // Original logout: clear local token first, then hit the backend logout endpoint
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
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          {/* Active AI provider chip */}
          <div style={{ display:"flex", alignItems:"center", gap:5, padding:"3px 9px",
            background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:20 }}>
            <span style={{ fontSize:11 }}>{AI_PROVIDERS[aiConfig.provider]?.icon}</span>
            <span style={{ color:AI_PROVIDERS[aiConfig.provider]?.color, fontSize:10, fontFamily:"monospace", fontWeight:700 }}>
              {AI_PROVIDERS[aiConfig.provider]?.name}
            </span>
          </div>

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
            {/* Logout — icon button matching original */}
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
        />

        {/* Page content */}
        <div style={{ flex:1, overflowY:"auto", background:"#090b10",
          backgroundImage:"radial-gradient(ellipse at 20% 30%, rgba(0,229,160,0.025) 0%, transparent 50%), radial-gradient(ellipse at 80% 10%, rgba(0,120,255,0.03) 0%, transparent 50%)" }}>
          <div style={{ padding:"28px 32px", animation:"fadeIn 0.35s ease", maxWidth:1300, margin:"0 auto" }}>

            {activeTab==="scan"           && <ScanPage user={user} onScanComplete={handleScanComplete}/>}
            {activeTab==="dashboard"      && <DashboardPage assets={assets} data={data} stats={stats} installedModules={installedModules} setActiveTab={setActiveTab} setSelectedAsset={setSelectedAsset} setShowImport={setShowImport}/>}
            {activeTab==="assets"         && <AssetsPage assets={assets} setSelectedAsset={setSelectedAsset} setShowImport={setShowImport}/>}
            {activeTab==="vulns"          && <VulnerabilityPage assets={assets}/>}
            {activeTab==="cysiemfeed"     && <SiemFeedPage data={data} installedModules={installedModules}/>}
            {activeTab==="siem-incidents" && <SiemIncidentsPage/>}
            {activeTab==="siem-risk"      && <SiemRiskScoresPage/>}
            {activeTab==="siem-ueba"      && <SiemUebaPage/>}
            {activeTab==="usecases"       && <UseCasesPage/>}
            {activeTab==="platform"       && <PlatformPage installedModules={installedModules} onInstall={handleInstallModule} onUninstall={handleUninstallModule}/>}
            {activeTab==="ai-settings"    && <AISettingsPage aiConfig={aiConfig} onSave={handleSaveAIConfig}/>}
            {activeTab==="system-settings" && <SystemSettingsPage />}

          </div>
        </div>
      </div>

      {selectedAsset && <AssetModal asset={selectedAsset} onClose={()=>setSelectedAsset(null)} onStatusChange={handleStatusChange}/>}
      {showImport    && <ImportModal onClose={()=>setShowImport(false)} onImport={handleImport}/>}
    </div>
  );
}
