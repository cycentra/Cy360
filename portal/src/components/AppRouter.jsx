import { SiemIncidentsPage }           from '../siem/SiemIncidentsPage';
import CasesListPage                    from '../pages/cases/CasesListPage.jsx';
import CaseDetailPage                   from '../pages/cases/CaseDetailPage.jsx';
import { HostIntelligencePage }         from '../pages/HostIntelligencePage.jsx';
import { SiemUebaPage }                 from '../siem/SiemUebaPage';
import { InternalExposureDashboard }    from '../siem/InternalExposureDashboard';
import { ThreatHuntingPage }            from '../siem/ThreatHuntingPage';
import { ScanPage }                     from '../pages/scan/ScanPage.jsx';
import { DashboardPage }                from '../pages/dashboard/DashboardPage.jsx';
import { AssetsPage }                   from '../pages/assets/AssetsPage.jsx';
import { VulnerabilityPage }            from '../pages/vulnerabilities/VulnerabilityPage.jsx';
import { MarketplacePage }              from '../pages/marketplace/MarketplacePage.jsx';
import { SystemSettingsPage }           from '../pages/settings/SystemSettingsPage.jsx';
import { AuditTrailPage }               from '../pages/audit/AuditTrailPage.jsx';
import { BenchmarkPage }                from '../pages/benchmark/BenchmarkPage.jsx';
import { PlatformExtensionsPage }       from '../pages/platform-extensions/index.jsx';
import { ComplianceDashboardPage }      from '../pages/compliance/ComplianceDashboardPage.jsx';
import { RiskRegisterPage, RiskHeatmapPage, RiskAppetitePage } from '../pages/compliance/RiskRegisterPage.jsx';
import { ComplianceFindingsPage }       from '../pages/compliance/ComplianceFindingsPage.jsx';
import { ComplianceReportsPage }        from '../pages/compliance/ComplianceReportsPage.jsx';
import { PolicyDocumentsPage }          from '../pages/compliance/PolicyDocumentsPage.jsx';
import { ComplianceAssessmentPage }     from '../pages/compliance/ComplianceAssessmentPage.jsx';
import IntegrationHealthPage            from '../pages/integrations/index.jsx';
import EdrFleetPage                     from '../pages/edr/index.jsx';
import EdrDetectionsPage                from '../pages/edr/EdrDetectionsPage.jsx';
import EdrResponsePage                  from '../pages/edr/EdrResponsePage.jsx';
import EdrPoliciesPage                  from '../pages/edr/EdrPoliciesPage.jsx';
import EdrAgentInstallerPage            from '../pages/edr/EdrAgentInstallerPage.jsx';
import EdrEndpointDetailPage            from '../pages/edr/EdrEndpointDetailPage.jsx';
import EdrYaraRulesPage                 from '../pages/edr/EdrYaraRulesPage.jsx';

export function AppRouter({ activeTab, user, assets, data, stats, installedModules,
  scanHistory, selectedScanId, onScanSelect, onScanComplete,
  setActiveTab, setSelectedAsset, setShowImport,
  onInstallModule, onUninstallModule,
  casesIncidentId, setCasesIncidentId, selectedEdrAgent, setSelectedEdrAgent }) {

  const nav = (tab, opts) => {
    if (tab === "cases" && opts?.incidentId) { setCasesIncidentId(opts.incidentId); setActiveTab("cases-detail"); }
    else setActiveTab(tab);
  };

  return (
    <>
      {activeTab==="scan"           && <ScanPage user={user} onScanComplete={onScanComplete}/>}
      {activeTab==="dashboard"      && <DashboardPage assets={assets} data={data} stats={stats} installedModules={installedModules} setActiveTab={setActiveTab} setSelectedAsset={setSelectedAsset} setShowImport={setShowImport}/>}
      {activeTab==="assets"         && <AssetsPage assets={assets} setSelectedAsset={setSelectedAsset} setShowImport={setShowImport}/>}
      {activeTab==="vulns"          && <VulnerabilityPage assets={assets} scanHistory={scanHistory} selectedScanId={selectedScanId} onScanSelect={onScanSelect}/>}
      {activeTab==="siem-incidents"   && <SiemIncidentsPage onOpenCase={id => { setCasesIncidentId(id); setActiveTab("cases-detail"); }}/>}
      {activeTab==="cases"            && <CasesListPage onOpenCase={id => { setCasesIncidentId(id); setActiveTab("cases-detail"); }}/>}
      {activeTab==="cases-detail"     && <CaseDetailPage incidentId={casesIncidentId} onBack={() => setActiveTab("cases")}/>}
      {activeTab==="siem-risk"        && <HostIntelligencePage/>}
      {activeTab==="siem-ueba"        && <SiemUebaPage/>}
      {activeTab==="internal-dashboard" && <InternalExposureDashboard setActiveTab={setActiveTab}/>}
      {activeTab==="threat-hunting"   && <ThreatHuntingPage setActiveTab={setActiveTab}/>}
      {activeTab==="host-inventory"   && <HostIntelligencePage/>}
      {activeTab==="marketplace"    && <MarketplacePage user={user} installedModules={installedModules} onInstall={onInstallModule} onUninstall={onUninstallModule}/>}
      {activeTab==="benchmark"            && <BenchmarkPage/>}
      {activeTab==="system-settings"     && <SystemSettingsPage/>}
      {activeTab==="audit-trail"         && <AuditTrailPage/>}
      {activeTab==="platform-extensions" && <PlatformExtensionsPage installedModules={installedModules} onInstall={onInstallModule} onUninstall={onUninstallModule}/>}
      {activeTab==="comp-dashboard"   && <ComplianceDashboardPage setActiveTab={setActiveTab}/>}
      {activeTab==="comp-assessment"  && <ComplianceAssessmentPage/>}
      {activeTab==="comp-findings"    && <ComplianceFindingsPage/>}
      {activeTab==="comp-risks"       && <RiskRegisterPage setActiveTab={setActiveTab}/>}
      {activeTab==="comp-heatmap"     && <RiskHeatmapPage/>}
      {activeTab==="comp-appetite"    && <RiskAppetitePage/>}
      {activeTab==="comp-reports"     && <ComplianceReportsPage/>}
      {activeTab==="comp-policy"      && <PolicyDocumentsPage/>}
      {activeTab==="integration-health" && <IntegrationHealthPage onNavigate={nav}/>}
      {activeTab==="edr-fleet"      && <EdrFleetPage onViewDetail={id => { setSelectedEdrAgent(id); setActiveTab("edr-endpoint-detail"); }}/>}
      {activeTab==="edr-detections" && <EdrDetectionsPage/>}
      {activeTab==="edr-response"   && <EdrResponsePage/>}
      {activeTab==="edr-policies"   && <EdrPoliciesPage/>}
      {activeTab==="edr-installer"  && <EdrAgentInstallerPage/>}
      {activeTab==="edr-yara-rules" && <EdrYaraRulesPage/>}
      {activeTab==="edr-endpoint-detail" && <EdrEndpointDetailPage agentId={selectedEdrAgent}/>}
    </>
  );
}
