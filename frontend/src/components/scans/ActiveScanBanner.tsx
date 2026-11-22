import React from 'react';
import { ScanResponse } from '../../types';
import { Activity, StopCircle, AlertTriangle } from 'lucide-react';

export interface ActiveScanBannerProps {
  activeScan: ScanResponse | null;
  applicationName?: string;
  currentPhase?: string;
  alertsFound?: number;
  onCancelScan: (scanId: string) => void;
  isCancelling?: boolean;
}

export const ActiveScanBanner: React.FC<ActiveScanBannerProps> = ({
  activeScan,
  applicationName = 'Target Application',
  currentPhase = 'Active Scanning Target',
  alertsFound = 0,
  onCancelScan,
  isCancelling = false,
}) => {
  if (!activeScan) return null;

  const isRunning =
    activeScan.status === 'active_scanning' ||
    activeScan.status === 'spidering' ||
    activeScan.status === 'queued' ||
    activeScan.status === 'ingesting';

  if (!isRunning) return null;

  const percent = activeScan.progress_percent ?? 0;

  return (
    <div className="active-scan-banner">
      <div className="banner-left">
        <div className="banner-indicator">
          <Activity size={18} className="animate-spin-slow text-slate-800" />
        </div>
        <div className="banner-details">
          <div className="banner-header">
            <span className="banner-tag">ACTIVE ASSESSMENT RUNNING</span>
            <span className="banner-target">{applicationName}</span>
            <span className="banner-scan-type">
              {activeScan.scan_type.replace(/_/g, ' ')}
            </span>
          </div>
          <div className="banner-phase">
            <span className="phase-label">Phase:</span>
            <span className="phase-text font-mono text-xs">{currentPhase}</span>
          </div>
        </div>
      </div>

      <div className="banner-center">
        <div className="progress-bar-container">
          <div className="progress-meta">
            <span className="text-xs text-slate-600 font-medium">Scan Progress</span>
            <span className="text-xs font-mono font-bold text-slate-900 tabular-nums">
              {percent}%
            </span>
          </div>
          <div className="progress-track">
            <div
              className="progress-fill"
              style={{ width: `${Math.min(100, Math.max(0, percent))}%` }}
            />
          </div>
        </div>

        <div className="banner-stats">
          <div className="stat-item" title="Alerts discovered so far">
            <AlertTriangle size={13} className="text-amber-600" />
            <span className="stat-label">Findings Found:</span>
            <span className="stat-value tabular-nums font-mono font-semibold">
              {alertsFound || (activeScan.severity_counts?.critical || 0) + (activeScan.severity_counts?.high || 0)}
            </span>
          </div>
        </div>
      </div>

      <div className="banner-right">
        <button
          type="button"
          onClick={() => onCancelScan(activeScan.id)}
          disabled={isCancelling}
          className="btn btn-danger-outline btn-sm"
          title="Abort active scan execution"
        >
          <StopCircle size={14} />
          <span>{isCancelling ? 'Aborting...' : 'Abort Scan'}</span>
        </button>
      </div>
    </div>
  );
};
