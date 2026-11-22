import React, { useState } from 'react';
import { ApplicationResponse, ScanResponse } from '../types';
import {
  Play,
  GitCompare,
  Activity,
  Download,
  StopCircle,
  Copy,
  Check,
} from 'lucide-react';
import { StatusBadge } from '../components/common/Badges';

export interface ScansPageProps {
  scans: ScanResponse[];
  applications: ApplicationResponse[];
  isBackendUnreachable?: boolean;
  onOpenTriggerScan: () => void;
  onOpenDiffModal: (baseScanId?: string, targetScanId?: string) => void;
  onCancelScan: (scanId: string) => Promise<void>;
  onDownloadPdf: (scanId: string) => void;
  onSelectScanFindings?: (scanId: string) => void;
  isCancellingId?: string | null;
}

export const ScansPage: React.FC<ScansPageProps> = ({
  scans,
  applications,
  isBackendUnreachable = false,
  onOpenTriggerScan,
  onOpenDiffModal,
  onCancelScan,
  onDownloadPdf,
  isCancellingId = null,
}) => {
  const [filterAppId, setFilterAppId] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const getAppName = (appId: string) => {
    const app = applications.find((a) => a.id === appId);
    return app ? app.name : 'Target App';
  };

  const getAppBaseUrl = (appId: string) => {
    const app = applications.find((a) => a.id === appId);
    return app ? app.base_url : '';
  };

  const filteredScans = scans.filter((s) => {
    const matchesApp = filterAppId === 'all' || s.application_id === filterAppId;
    const matchesStatus = filterStatus === 'all' || s.status === filterStatus;
    return matchesApp && matchesStatus;
  });

  const copyScanId = (id: string) => {
    navigator.clipboard.writeText(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="page-container">
      {/* Toolbar */}
      <div className="toolbar-box">
        <div className="toolbar-left">
          {/* App Filter */}
          <div className="filter-item">
            <label className="filter-label" htmlFor="scan-app-select">
              Application:
            </label>
            <select
              id="scan-app-select"
              value={filterAppId}
              onChange={(e) => setFilterAppId(e.target.value)}
              className="form-select form-select-sm"
            >
              <option value="all">All Applications</option>
              {applications.map((app) => (
                <option key={app.id} value={app.id}>
                  {app.name}
                </option>
              ))}
            </select>
          </div>

          {/* Status Filter */}
          <div className="filter-item">
            <label className="filter-label" htmlFor="scan-status-select">
              Status:
            </label>
            <select
              id="scan-status-select"
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="form-select form-select-sm"
            >
              <option value="all">All Statuses</option>
              <option value="queued">Queued</option>
              <option value="spidering">Spidering</option>
              <option value="active_scanning">Active Scanning</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="cancelled">Cancelled</option>
            </select>
          </div>
        </div>

        <div className="toolbar-right">
          {/* Diff comparison button */}
          <button
            type="button"
            onClick={() => onOpenDiffModal()}
            className="btn btn-secondary"
            title="Compare two scan assessments for regression"
          >
            <GitCompare size={14} />
            <span>Compare Scans (N vs N-1 Diff)</span>
          </button>

          {/* Launch scan */}
          <button
            type="button"
            onClick={onOpenTriggerScan}
            className="btn btn-primary"
          >
            <Play size={14} />
            <span>Launch Scan</span>
          </button>
        </div>
      </div>

      {/* Scans Table Card */}
      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">Security Assessment History</h3>
            <p className="card-subtitle">
              Showing {filteredScans.length} executions across registered targets
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500">
            Real-time ZAP Engine
          </span>
        </div>

        <div className="card-body p-0">
          {filteredScans.length === 0 ? (
            <div className="empty-state-box">
              <Activity size={32} className="text-slate-300 mb-2" />
              <p className="text-slate-600 font-medium">
                {isBackendUnreachable
                  ? 'Backend not connected — unable to reach 127.0.0.1:8000'
                  : 'No scan history recorded'}
              </p>
              <p className="text-slate-400 text-xs mt-1">
                {isBackendUnreachable
                  ? 'Please ensure the API server is running on 127.0.0.1:8000 or enable Offline Mock mode.'
                  : 'Launch a security scan against an authorized target.'}
              </p>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Scan Reference</th>
                    <th>Target Application</th>
                    <th>Scan Profile</th>
                    <th>Execution Status</th>
                    <th>Findings Breakdown</th>
                    <th>Risk Score</th>
                    <th>Duration</th>
                    <th>Executed At</th>
                    <th className="text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredScans.map((scan) => {
                    const isRunning =
                      scan.status === 'active_scanning' ||
                      scan.status === 'spidering' ||
                      scan.status === 'queued' ||
                      scan.status === 'ingesting';

                    const durationMin = scan.duration_seconds
                      ? `${Math.floor(scan.duration_seconds / 60)}m ${scan.duration_seconds % 60}s`
                      : isRunning
                      ? 'In progress'
                      : 'N/A';

                    return (
                      <tr key={scan.id}>
                        {/* Scan ID & Copy */}
                        <td>
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-xs font-semibold text-slate-900">
                              {scan.id.substring(0, 8)}...
                            </span>
                            <button
                              type="button"
                              onClick={() => copyScanId(scan.id)}
                              className="text-slate-400 hover:text-slate-600"
                              title="Copy full UUID"
                            >
                              {copiedId === scan.id ? (
                                <Check size={11} className="text-emerald-600" />
                              ) : (
                                <Copy size={11} />
                              )}
                            </button>
                          </div>
                        </td>

                        {/* Application */}
                        <td>
                          <div className="font-semibold text-slate-900 text-xs">
                            {getAppName(scan.application_id)}
                          </div>
                          <div className="text-xs font-mono text-slate-500">
                            {getAppBaseUrl(scan.application_id)}
                          </div>
                        </td>

                        {/* Scan Type */}
                        <td>
                          <span className="font-mono text-xs text-slate-700 capitalize">
                            {scan.scan_type.replace(/_/g, ' ')}
                          </span>
                        </td>

                        {/* Status & Live Progress */}
                        <td>
                          <div className="flex flex-col gap-1">
                            <StatusBadge status={scan.status} size="sm" />
                            {isRunning && (
                              <div className="w-24 bg-slate-100 h-1.5 rounded overflow-hidden">
                                <div
                                  className="bg-slate-900 h-full transition-all"
                                  style={{ width: `${scan.progress_percent}%` }}
                                />
                              </div>
                            )}
                          </div>
                        </td>

                        {/* Severity Breakdown */}
                        <td>
                          <div className="flex gap-1 flex-wrap">
                            {scan.severity_counts?.critical > 0 && (
                              <span className="badge badge-critical-bg badge-critical-text badge-sm font-mono tabular-nums">
                                {scan.severity_counts.critical}C
                              </span>
                            )}
                            {scan.severity_counts?.high > 0 && (
                              <span className="badge badge-high-bg badge-high-text badge-sm font-mono tabular-nums">
                                {scan.severity_counts.high}H
                              </span>
                            )}
                            {scan.severity_counts?.medium > 0 && (
                              <span className="badge badge-medium-bg badge-medium-text badge-sm font-mono tabular-nums">
                                {scan.severity_counts.medium}M
                              </span>
                            )}
                            {scan.severity_counts?.low > 0 && (
                              <span className="badge badge-low-bg badge-low-text badge-sm font-mono tabular-nums">
                                {scan.severity_counts.low}L
                              </span>
                            )}
                            {scan.severity_counts?.critical === 0 &&
                              scan.severity_counts?.high === 0 && (
                                <span className="text-xs text-slate-400 font-mono">0 High/Crit</span>
                              )}
                          </div>
                        </td>

                        {/* Risk Score */}
                        <td>
                          <span className="font-mono font-bold text-xs tabular-nums text-slate-900">
                            {scan.overall_risk_score.toFixed(1)}
                          </span>
                        </td>

                        {/* Duration */}
                        <td className="text-xs font-mono text-slate-600 tabular-nums">
                          {durationMin}
                        </td>

                        {/* Executed At */}
                        <td className="text-xs font-mono text-slate-600">
                          {scan.started_at ? (
                            new Date(scan.started_at).toLocaleString([], {
                              dateStyle: 'short',
                              timeStyle: 'short',
                            })
                          ) : (
                            <span className="text-slate-400">Queued</span>
                          )}
                        </td>

                        {/* Actions */}
                        <td className="text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            {isRunning ? (
                              <button
                                type="button"
                                onClick={() => onCancelScan(scan.id)}
                                disabled={isCancellingId === scan.id}
                                className="btn btn-danger-outline btn-sm"
                                title="Abort active scan"
                              >
                                <StopCircle size={13} />
                                <span>{isCancellingId === scan.id ? 'Aborting...' : 'Abort'}</span>
                              </button>
                            ) : (
                              <>
                                <button
                                  type="button"
                                  onClick={() => onOpenDiffModal(undefined, scan.id)}
                                  className="btn-icon-sm"
                                  title="Compare with baseline (Scan N vs N-1)"
                                >
                                  <GitCompare size={13} />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => onDownloadPdf(scan.id)}
                                  className="btn-icon-sm"
                                  title="Download Typst PDF Report"
                                >
                                  <Download size={13} />
                                </button>
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
