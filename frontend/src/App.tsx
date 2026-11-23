import { useState, useEffect, useCallback, useRef } from 'react';
import {
  ApplicationResponse,
  BulkUpdateVulnsRequest,
  ConfigureAuthRequest,
  CreateApplicationRequest,
  DashboardSummary,
  RemediationStatus,
  ScanResponse,
  TriggerScanRequest,
  VulnerabilityDetail,
  VulnerabilitySummary,
  ScanProgressEvent,
  ScanCompletedEvent,
  ScanFailedEvent,
  UserProfile,
} from './types';
import { api } from './services/api';
import {
  ScanWebSocketClient,
  WsConnectionStatus,
} from './services/websocket';

// Layout & Components
import { Sidebar, NavTab } from './components/layout/Sidebar';
import { Titlebar, NotificationItem } from './components/layout/Titlebar';
import { ActiveScanBanner } from './components/scans/ActiveScanBanner';
import { RegisterAppModal } from './components/apps/RegisterAppModal';
import { ConfigureAuthModal } from './components/apps/ConfigureAuthModal';
import { TriggerScanModal } from './components/scans/TriggerScanModal';
import { DiffViewModal } from './components/scans/DiffViewModal';
import { AlertTriangle, RefreshCw } from 'lucide-react';

// Pages
import { DashboardPage } from './pages/DashboardPage';
import { ApplicationsPage } from './pages/ApplicationsPage';
import { ScansPage } from './pages/ScansPage';
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage';
import { ReportsPage } from './pages/ReportsPage';

import './App.css';

export function App() {
  // Navigation & View State
  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');
  const [mockMode, setMockMode] = useState<boolean>(api.getMockMode());
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isBackendUnreachable, setIsBackendUnreachable] = useState(false);

  // Core Data
  const [applications, setApplications] = useState<ApplicationResponse[]>([]);
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilitySummary[]>([]);
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummary | null>(null);
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);

  // Active Scan & WebSocket State
  const [activeScan, setActiveScan] = useState<ScanResponse | null>(null);
  const [activeScanPhase, setActiveScanPhase] = useState<string>('Initializing Scanner...');
  const [activeScanAlerts, setActiveScanAlerts] = useState<number>(0);
  const [wsStatus, setWsStatus] = useState<WsConnectionStatus>('disconnected');
  const wsClientRef = useRef<ScanWebSocketClient | null>(null);

  // Notifications
  const [notifications, setNotifications] = useState<NotificationItem[]>([
    {
      id: 'notif_init_1',
      type: 'info',
      title: 'AppSec Workbench Ready',
      message: 'Client initialized. Connecting to API server on 127.0.0.1:8000.',
      time: 'Just now',
      read: false,
    },
  ]);

  // Modal Visibility State
  const [isRegisterAppOpen, setIsRegisterAppOpen] = useState(false);
  const [isTriggerScanOpen, setIsTriggerScanOpen] = useState(false);
  const [triggerSelectedAppId, setTriggerSelectedAppId] = useState<string | undefined>(undefined);
  const [selectedAppForAuth, setSelectedAppForAuth] = useState<ApplicationResponse | null>(null);
  const [isDiffModalOpen, setIsDiffModalOpen] = useState(false);
  const [diffBaseId, setDiffBaseId] = useState<string | undefined>(undefined);
  const [diffTargetId, setDiffTargetId] = useState<string | undefined>(undefined);

  // Vulnerability Detail Drawer
  const [selectedVulnDetail, setSelectedVulnDetail] = useState<VulnerabilityDetail | null>(null);
  const [isCancellingScanId, setIsCancellingScanId] = useState<string | null>(null);

  // Helper to add a notification
  const addNotification = useCallback(
    (type: 'info' | 'success' | 'warning' | 'error', title: string, message: string) => {
      const item: NotificationItem = {
        id: `notif_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
        type,
        title,
        message,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        read: false,
      };
      setNotifications((prev) => [item, ...prev.slice(0, 19)]);
    },
    []
  );

  // Load all data
  const loadAllData = useCallback(async () => {
    try {
      setIsRefreshing(true);

      // Check backend health before fetching
      const conn = await api.getConnectionStatus();
      if (!conn.connected && !api.getMockMode()) {
        setIsBackendUnreachable(true);
        setApplications([]);
        setScans([]);
        setDashboardSummary({
          total_applications: 0,
          average_risk_score: 0.0,
          total_vulnerabilities: 0,
          vulnerabilities: [],
          severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          owasp_breakdown: [],
          sla_compliance: {
            critical_within_sla: 0,
            critical_breached: 0,
            high_within_sla: 0,
            high_breached: 0,
            overall_compliance_rate: 0.0,
          },
          active_scans_count: 0,
        });
        setVulnerabilities([]);
        setActiveScan(null);
        return;
      }

      // Ensure authenticated before loading protected data
      await api.ensureAuthenticated();

      const [appsRes, scansRes, summaryRes, vulnsRes] = await Promise.all([
        api.listApps(),
        api.listGlobalScans(),
        api.getDashboardSummary(),
        api.listVulns({ per_page: 100 }),
      ]);

      setApplications(appsRes);
      setScans(scansRes);
      setDashboardSummary(summaryRes);
      setVulnerabilities(vulnsRes.items);
      setIsBackendUnreachable(false);

      api.getMe().then(setUserProfile).catch(() => {});

      // Check if there is an active running scan
      const running = scansRes.find(
        (s: ScanResponse) =>
          s.status === 'active_scanning' ||
          s.status === 'spidering' ||
          s.status === 'queued' ||
          s.status === 'ingesting'
      );
      if (running) {
        setActiveScan(running);
      }
    } catch (err: any) {
      console.warn('Error loading backend data from 127.0.0.1:8000:', err);
      const isUp = await api.checkHealth();
      if (!isUp && !api.getMockMode()) {
        setIsBackendUnreachable(true);
      }
      setApplications([]);
      setScans([]);
      setDashboardSummary({
        total_applications: 0,
        average_risk_score: 0.0,
        total_vulnerabilities: 0,
        vulnerabilities: [],
        severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        owasp_breakdown: [],
        sla_compliance: {
          critical_within_sla: 0,
          critical_breached: 0,
          high_within_sla: 0,
          high_breached: 0,
          overall_compliance_rate: 0.0,
        },
        active_scans_count: 0,
      });
      setVulnerabilities([]);
      setActiveScan(null);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    loadAllData();
  }, [loadAllData]);

  // Initialize and manage WebSocket connection
  useEffect(() => {
    const ws = new ScanWebSocketClient();
    wsClientRef.current = ws;

    ws.onStatusChange((status: WsConnectionStatus) => {
      setWsStatus(status);
    });

    ws.onScanProgress((data: ScanProgressEvent) => {
      setActiveScanPhase(data.current_phase);
      setActiveScanAlerts(data.alerts_found_so_far);
      setActiveScan((prev) => {
        if (!prev) return null;
        return {
          ...prev,
          status: data.status,
          progress_percent: data.progress_percent,
        };
      });
    });

    ws.onScanCompleted((data: ScanCompletedEvent) => {
      addNotification(
        'success',
        'Security Scan Completed',
        `Scan ${data.scan_id.substring(0, 8)} finished with risk score ${data.overall_risk_score.toFixed(1)}.`
      );
      setActiveScan(null);
      loadAllData();
    });

    ws.onScanFailed((data: ScanFailedEvent) => {
      addNotification(
        'error',
        'Security Scan Failed',
        `Scan ${data.scan_id.substring(0, 8)} aborted: ${data.reason}`
      );
      setActiveScan(null);
      loadAllData();
    });

    // If there is an active scan, connect to it
    if (activeScan && (activeScan.status === 'active_scanning' || activeScan.status === 'spidering')) {
      ws.connect(activeScan.id);
    } else {
      ws.connectNotifications();
    }

    return () => {
      ws.disconnect();
    };
  }, [activeScan?.id, addNotification, loadAllData]);

  // Mock mode toggle
  const handleToggleMockMode = () => {
    const nextMode = !mockMode;
    api.setMockMode(nextMode);
    setMockMode(nextMode);
    addNotification(
      'info',
      nextMode ? 'Offline Mock Mode Enabled' : 'Live REST Backend Connected',
      nextMode
        ? 'Using in-memory fixtures for standalone operation.'
        : 'Connecting to live API endpoints.'
    );
    loadAllData();
  };

  // Actions: Register Application
  const handleCreateApp = async (appData: CreateApplicationRequest) => {
    const newApp = await api.createApp(appData);
    setApplications((prev) => [newApp, ...prev]);
    addNotification(
      'success',
      'Target Application Registered',
      `${newApp.name} (${newApp.base_url}) added to inventory with certified authorization.`
    );
    await loadAllData();
  };

  // Actions: Configure App Auth
  const handleConfigureAuth = async (appId: string, config: ConfigureAuthRequest) => {
    await api.configureAppAuth(appId, config);
    setApplications((prev) =>
      prev.map((a) => (a.id === appId ? { ...a, has_auth_configured: true } : a))
    );
    const app = applications.find((a) => a.id === appId);
    addNotification(
      'success',
      'Authentication Profile Configured',
      `Encrypted ${config.auth_type} credentials bound to ${app?.name || 'application'}.`
    );
  };

  // Actions: Delete App
  const handleDeleteApp = async (appId: string) => {
    const app = applications.find((a) => a.id === appId);
    if (!window.confirm(`Are you sure you want to delete ${app?.name || 'this application'}?`)) {
      return;
    }
    await api.deleteApp(appId);
    setApplications((prev) => prev.filter((a) => a.id !== appId));
    addNotification('info', 'Target Removed', `Target application and history deleted.`);
  };

  // Actions: Trigger Scan
  const handleTriggerScan = async (appId: string, req: TriggerScanRequest) => {
    const targetApp = applications.find((a) => a.id === appId);
    const newScan = await api.triggerAppScan(appId, req);
    setScans((prev) => [newScan, ...prev]);
    setActiveScan(newScan);
    setActiveScanPhase('Crawling & Spidering endpoints...');
    setActiveScanAlerts(0);

    // Connect WebSocket
    if (wsClientRef.current) {
      wsClientRef.current.connect(newScan.id);
    }

    addNotification(
      'info',
      'Security Assessment Launched',
      `ZAP ${req.scan_type.replace(/_/g, ' ')} scan queued for ${targetApp?.name || 'target'}.`
    );
    setActiveTab('scans');
  };

  // Actions: Cancel Scan
  const handleCancelScan = async (scanId: string) => {
    try {
      setIsCancellingScanId(scanId);
      const aborted = await api.cancelScan(scanId);
      setScans((prev) => prev.map((s) => (s.id === scanId ? aborted : s)));
      if (activeScan?.id === scanId) {
        setActiveScan(null);
      }
      addNotification('warning', 'Scan Aborted', `Scan ${scanId.substring(0, 8)} was stopped.`);
    } catch (err: any) {
      addNotification('error', 'Abort Failed', err.message || 'Could not cancel scan.');
    } finally {
      setIsCancellingScanId(null);
    }
  };

  // Actions: Select Vuln Detail
  const handleSelectVuln = async (vulnId: string) => {
    try {
      const detail = await api.getVuln(vulnId);
      setSelectedVulnDetail(detail);
    } catch (err: any) {
      console.error('Failed to load vuln detail:', err);
    }
  };

  // Actions: Update Vuln Status
  const handleUpdateVulnStatus = async (
    vulnId: string,
    newStatus: RemediationStatus,
    comment?: string
  ) => {
    const updated = await api.updateVuln(vulnId, {
      status: newStatus,
      comment,
    });
    setSelectedVulnDetail(updated);
    setVulnerabilities((prev) =>
      prev.map((v) => (v.id === vulnId ? { ...v, status: newStatus } : v))
    );
    addNotification(
      'info',
      'Triage Status Updated',
      `Finding status changed to ${newStatus.replace(/_/g, ' ')}.`
    );
    loadAllData();
  };

  // Actions: Bulk Update
  const handleBulkUpdate = async (req: BulkUpdateVulnsRequest) => {
    const res = await api.bulkUpdateVulns(req);
    addNotification(
      'success',
      'Batch Triage Applied',
      `Updated ${res.updated_count} findings to ${req.status?.replace(/_/g, ' ')}.`
    );
    await loadAllData();
  };

  // Actions: Download Scan PDF
  const handleDownloadScanPdf = async (scanId: string) => {
    try {
      const blob = await api.downloadScanPdf(scanId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `AppSec_Report_${scanId.substring(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      addNotification('success', 'PDF Report Generated', `Downloaded Typst security report.`);
    } catch (err: any) {
      addNotification('error', 'Export Failed', err.message || 'Could not compile report.');
    }
  };

  // Active target app name for active scan banner
  const activeApp = activeScan
    ? applications.find((a) => a.id === activeScan.application_id)
    : null;

  return (
    <div className="app-layout">
      {/* 1. Left Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={(tab) => {
          setActiveTab(tab);
          setSelectedVulnDetail(null);
        }}
        mockMode={mockMode}
        onToggleMockMode={handleToggleMockMode}
        openVulnsCount={vulnerabilities.filter((v) => v.status === 'open' || v.status === 'in_progress').length}
        activeScansCount={scans.filter((s) => s.status === 'active_scanning' || s.status === 'spidering').length}
        userProfile={userProfile}
      />

      {/* 2. Main Content Canvas */}
      <div className="main-content">
        {/* Titlebar with Live Socket Indicator & Notifications */}
        <Titlebar
          activeTab={activeTab}
          wsStatus={wsStatus}
          notifications={notifications}
          onClearNotifications={() => setNotifications([])}
          onOpenTriggerScan={() => {
            setTriggerSelectedAppId(applications[0]?.id);
            setIsTriggerScanOpen(true);
          }}
          onOpenRegisterApp={() => setIsRegisterAppOpen(true)}
          onRefreshData={loadAllData}
          isRefreshing={isRefreshing}
        />

        {/* Persistent Top Banner when Backend is Unreachable */}
        {isBackendUnreachable && (
          <div className="backend-disconnected-banner">
            <div className="flex items-center gap-2">
              <AlertTriangle size={15} className="text-amber-700 flex-shrink-0" />
              <span className="font-semibold text-amber-900">Backend Disconnected:</span>
              <span className="text-amber-800">
                Unable to reach API server at 127.0.0.1:8000. Values reflect empty/default state.
              </span>
            </div>
            <button
              type="button"
              onClick={loadAllData}
              disabled={isRefreshing}
              className="btn btn-secondary btn-sm"
              title="Retry connection to 127.0.0.1:8000"
            >
              <RefreshCw size={12} className={isRefreshing ? 'animate-spin' : ''} />
              <span>Retry Connection</span>
            </button>
          </div>
        )}

        {/* Live Active Scan Progress Banner */}
        <ActiveScanBanner
          activeScan={activeScan}
          applicationName={activeApp?.name || 'Target Application'}
          currentPhase={activeScanPhase}
          alertsFound={activeScanAlerts}
          onCancelScan={handleCancelScan}
          isCancelling={isCancellingScanId === activeScan?.id}
        />

        {/* Dynamic Page Views */}
        <main className="page-body">
          {activeTab === 'dashboard' && (
            <DashboardPage
              summary={dashboardSummary}
              applications={applications}
              vulnerabilities={vulnerabilities}
              recentScans={scans}
              isBackendUnreachable={isBackendUnreachable}
              onNavigateToTab={(tab) => setActiveTab(tab)}
              onSelectVuln={handleSelectVuln}
              onOpenTriggerScan={(appId) => {
                setTriggerSelectedAppId(appId || applications[0]?.id);
                setIsTriggerScanOpen(true);
              }}
            />
          )}

          {activeTab === 'apps' && (
            <ApplicationsPage
              applications={applications}
              isBackendUnreachable={isBackendUnreachable}
              onOpenRegisterModal={() => setIsRegisterAppOpen(true)}
              onOpenTriggerScanModal={(appId) => {
                setTriggerSelectedAppId(appId);
                setIsTriggerScanOpen(true);
              }}
              onOpenConfigureAuthModal={(app) => setSelectedAppForAuth(app)}
              onDeleteApplication={handleDeleteApp}
              onSelectApplication={(appId) => {
                setTriggerSelectedAppId(appId);
                setActiveTab('scans');
              }}
            />
          )}

          {activeTab === 'scans' && (
            <ScansPage
              scans={scans}
              applications={applications}
              isBackendUnreachable={isBackendUnreachable}
              onOpenTriggerScan={() => {
                setTriggerSelectedAppId(applications[0]?.id);
                setIsTriggerScanOpen(true);
              }}
              onOpenDiffModal={(base, target) => {
                setDiffBaseId(base);
                setDiffTargetId(target);
                setIsDiffModalOpen(true);
              }}
              onCancelScan={handleCancelScan}
              onDownloadPdf={handleDownloadScanPdf}
              onSelectScanFindings={() => {
                setActiveTab('vulns');
              }}
              isCancellingId={isCancellingScanId}
            />
          )}

          {activeTab === 'vulns' && (
            <VulnerabilitiesPage
              vulnerabilities={vulnerabilities}
              applications={applications}
              selectedVulnDetail={selectedVulnDetail}
              isBackendUnreachable={isBackendUnreachable}
              onSelectVuln={handleSelectVuln}
              onCloseDrawer={() => setSelectedVulnDetail(null)}
              onUpdateVulnStatus={handleUpdateVulnStatus}
              onBulkUpdate={handleBulkUpdate}
              isLoading={isRefreshing}
            />
          )}

          {activeTab === 'reports' && (
            <ReportsPage applications={applications} scans={scans} />
          )}
        </main>
      </div>

      {/* Modals */}
      <RegisterAppModal
        isOpen={isRegisterAppOpen}
        onClose={() => setIsRegisterAppOpen(false)}
        onSubmit={handleCreateApp}
      />

      <ConfigureAuthModal
        isOpen={Boolean(selectedAppForAuth)}
        application={selectedAppForAuth}
        onClose={() => setSelectedAppForAuth(null)}
        onSubmit={handleConfigureAuth}
      />

      <TriggerScanModal
        isOpen={isTriggerScanOpen}
        applications={applications}
        selectedAppId={triggerSelectedAppId}
        onClose={() => setIsTriggerScanOpen(false)}
        onSubmit={handleTriggerScan}
      />

      <DiffViewModal
        isOpen={isDiffModalOpen}
        onClose={() => setIsDiffModalOpen(false)}
        scans={scans}
        initialBaseId={diffBaseId}
        initialTargetId={diffTargetId}
        onSelectVuln={(id) => {
          setIsDiffModalOpen(false);
          handleSelectVuln(id);
        }}
      />
    </div>
  );
}

export default App;
