/**
 * App.jsx — CyCentra 360 Portal v4.4
 * Layout shell + page router.
 */

import { useState, useEffect } from "react";
import { useAppState } from './hooks/useAppState.js';
import { Sidebar } from './sidebar/Sidebar.jsx';
import { PageErrorBoundary } from './components/PageErrorBoundary.jsx';
import { AppTopBar } from './components/AppTopBar.jsx';
import { AppRouter } from './components/AppRouter.jsx';
import { AssetModal } from './pages/assets/AssetModal.jsx';
import { ImportModal } from './pages/assets/ImportModal.jsx';
import { CyMindChatOverlay } from './components/CyMindChatOverlay.jsx';
import { LicenseBanner } from './components/LicenseBanner.jsx';
import { LoginPage } from './pages/login/LoginPage.jsx';

export default function App() {
  const {
    user, authReady, data, assets, activeTab, selectedAsset, showImport,
    installedModules, stats, scanTime,
    scanHistory, selectedScanId, historyLoading,
    allowedPages,
    setActiveTab, setSelectedAsset, setShowImport,
    handleImport, handleStatusChange, handleInstallModule,
    handleUninstallModule, handleScanComplete, handleScanSelect,
  } = useAppState();

  const [showCyMind,        setShowCyMind]        = useState(false);
  const [casesIncidentId,   setCasesIncidentId]   = useState(null);
  const [selectedEdrAgent,  setSelectedEdrAgent]  = useState(null);
  const [selectedItamAsset, setSelectedItamAsset] = useState(null);

  useEffect(() => {
    if (!allowedPages) return;
    if (!allowedPages.includes(activeTab)) {
      setActiveTab(allowedPages.length > 0 ? allowedPages[0] : "dashboard");
    }
  }, [allowedPages]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!authReady) return (
    <div style={{ height:"100vh", display:"flex", alignItems:"center", justifyContent:"center", background:"#090b10" }}>
      <div style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:16 }}>
        <svg width="32" height="32" viewBox="0 0 24 24" style={{ animation:"hexPulse 1.5s ease-in-out infinite" }}>
          <polygon points="12,2 22,8 22,16 12,22 2,16 2,8" fill="none" stroke="#00e5a0" strokeWidth="1.5"/>
          <polygon points="12,6 18,10 18,14 12,18 6,14 6,10" fill="rgba(0,229,160,0.12)" stroke="#00e5a0" strokeWidth="0.75"/>
          <circle cx="12" cy="12" r="2" fill="#00e5a0"/>
        </svg>
        <div style={{ color:"rgba(255,255,255,0.25)", fontSize:11, fontFamily:"monospace", letterSpacing:"1.5px" }}>LOADING</div>
      </div>
    </div>
  );
  if (!user) return <LoginPage />;

  const canUseCyMind = user?.role === "analyst" || user?.role === "admin";

  return (
    <div style={{ height:"100vh", display:"flex", flexDirection:"column" }}>
      <AppTopBar user={user} data={data} scanHistory={scanHistory} selectedScanId={selectedScanId}
        onScanSelect={handleScanSelect} historyLoading={historyLoading}
        onImport={() => setShowImport(true)}/>
      <LicenseBanner />
      <div style={{ flex:1, display:"flex", overflow:"hidden" }}>
        <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} installedModules={installedModules}
          data={data} scanTime={scanTime} user={user} allowedPages={allowedPages}/>
        <div style={{ flex:1, overflowY:"auto", background:"#090b10",
          backgroundImage:"radial-gradient(ellipse at 20% 30%, rgba(0,229,160,0.025) 0%, transparent 50%), radial-gradient(ellipse at 80% 10%, rgba(0,120,255,0.03) 0%, transparent 50%)" }}>
          <PageErrorBoundary>
            <div style={{ padding:"28px 32px", animation:"fadeIn 0.35s ease", maxWidth:1300, margin:"0 auto" }}>
              <AppRouter activeTab={activeTab} user={user} assets={assets} data={data} stats={stats}
                installedModules={installedModules} scanHistory={scanHistory} selectedScanId={selectedScanId}
                onScanSelect={handleScanSelect} onScanComplete={handleScanComplete}
                setActiveTab={setActiveTab} setSelectedAsset={setSelectedAsset} setShowImport={setShowImport}
                onInstallModule={handleInstallModule} onUninstallModule={handleUninstallModule}
                casesIncidentId={casesIncidentId} setCasesIncidentId={setCasesIncidentId}
                selectedEdrAgent={selectedEdrAgent} setSelectedEdrAgent={setSelectedEdrAgent}
                selectedItamAsset={selectedItamAsset} setSelectedItamAsset={setSelectedItamAsset}/>
            </div>
          </PageErrorBoundary>
        </div>
      </div>

      {selectedAsset && <AssetModal asset={selectedAsset} onClose={()=>setSelectedAsset(null)} onStatusChange={handleStatusChange}/>}
      {showImport    && <ImportModal onClose={()=>setShowImport(false)} onImport={handleImport}/>}

      {canUseCyMind && !showCyMind && (
        <button onClick={() => setShowCyMind(true)} title="Open CyMind AI Assistant"
          style={{ position:"fixed", bottom:28, right:28, zIndex:800, width:52, height:52, borderRadius:"50%", border:"none", cursor:"pointer",
            background:"linear-gradient(135deg, rgba(0,229,160,0.9), rgba(0,180,130,0.9))",
            boxShadow:"0 4px 20px rgba(0,229,160,0.4), 0 2px 8px rgba(0,0,0,0.5)",
            display:"flex", alignItems:"center", justifyContent:"center", transition:"transform 0.15s, box-shadow 0.15s" }}
          onMouseEnter={e => { e.currentTarget.style.transform="scale(1.08)"; e.currentTarget.style.boxShadow="0 6px 28px rgba(0,229,160,0.55), 0 3px 10px rgba(0,0,0,0.5)"; }}
          onMouseLeave={e => { e.currentTarget.style.transform="scale(1)"; e.currentTarget.style.boxShadow="0 4px 20px rgba(0,229,160,0.4), 0 2px 8px rgba(0,0,0,0.5)"; }}>
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="rgba(5,15,12,0.9)" strokeWidth="2">
            <path d="M12 2a7 7 0 0 1 7 7c0 3.5-2.5 6.4-5.8 7.7L12 22l-1.2-5.3C7.5 15.4 5 12.5 5 9a7 7 0 0 1 7-7z"/>
            <circle cx="12" cy="9" r="2" fill="rgba(5,15,12,0.5)" stroke="rgba(5,15,12,0.9)" strokeWidth="1.5"/>
          </svg>
        </button>
      )}
      {canUseCyMind && showCyMind && <CyMindChatOverlay onClose={() => setShowCyMind(false)}/>}
    </div>
  );
}
