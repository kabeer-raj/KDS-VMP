import React, { useState } from 'react';
import {
  ApplicationResponse,
  ScanType,
  TriggerScanRequest,
} from '../../types';
import {
  X,
  Play,
  Shield,
  ShieldAlert,
  AlertTriangle,
} from 'lucide-react';

export interface TriggerScanModalProps {
  isOpen: boolean;
  applications: ApplicationResponse[];
  selectedAppId?: string;
  onClose: () => void;
  onSubmit: (appId: string, request: TriggerScanRequest) => Promise<void>;
}

export const TriggerScanModal: React.FC<TriggerScanModalProps> = ({
  isOpen,
  applications,
  selectedAppId,
  onClose,
  onSubmit,
}) => {
  const [appId, setAppId] = useState<string>(
    selectedAppId || (applications.length > 0 ? applications[0].id : '')
  );
  const [scanType, setScanType] = useState<ScanType>('full_active');
  const [maxDuration, setMaxDuration] = useState<number>(45);
  const [headerKey, setHeaderKey] = useState<string>('X-Scan-Origin');
  const [headerVal, setHeaderVal] = useState<string>('AppSec-Authorized-Scan');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const currentApp = applications.find((a) => a.id === appId) || applications[0];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (!appId) {
      setErrorMsg('Please select a target application.');
      return;
    }

    if (currentApp && !currentApp.is_authorized) {
      setErrorMsg('This target is flagged as UNAUTHORIZED. Scans cannot be executed without verified authorization.');
      return;
    }

    try {
      setIsSubmitting(true);
      const customHeaders: Record<string, string> = {};
      if (headerKey.trim() && headerVal.trim()) {
        customHeaders[headerKey.trim()] = headerVal.trim();
      }

      await onSubmit(appId, {
        scan_type: scanType,
        max_duration_minutes: maxDuration > 0 ? maxDuration : 30,
        custom_headers: Object.keys(customHeaders).length > 0 ? customHeaders : undefined,
      });

      onClose();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to trigger scan assessment.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const scanTypeDescriptions: Record<
    ScanType,
    { title: string; desc: string; tag: string }
  > = {
    baseline_passive: {
      title: 'Baseline Passive',
      desc: 'Non-intrusive traffic analysis and spidering. Zero malicious payloads dispatched.',
      tag: 'Safe for Prod',
    },
    full_active: {
      title: 'Full Active Attack',
      desc: 'Complete penetration fuzzing (SQLi, XSS, SSRF, RCE, Path Traversal) via ZAP engine.',
      tag: 'Deep Coverage',
    },
    api_openapi: {
      title: 'OpenAPI / REST Schema',
      desc: 'Parses OpenAPI/Swagger schemas and executes boundary fuzzing on all documented routes.',
      tag: 'API Fuzzing',
    },
    spa_ajax: {
      title: 'SPA Ajax Spider',
      desc: 'Headless Chromium crawler executing DOM interactions for React/Vue/Angular apps.',
      tag: 'Heavy Crawler',
    },
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-container modal-lg">
        {/* Header */}
        <div className="modal-header">
          <div className="modal-title-wrapper">
            <Play size={18} className="text-slate-900" />
            <h2 className="modal-title">Launch Security Assessment</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="modal-close-btn"
            title="Close"
          >
            <X size={16} />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="modal-body-form">
          {errorMsg && (
            <div className="alert-banner alert-banner-danger">
              <AlertTriangle size={15} />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Select Target Application */}
          <div className="form-group">
            <label className="form-label" htmlFor="target-app">
              Target Application
            </label>
            <select
              id="target-app"
              value={appId}
              onChange={(e) => setAppId(e.target.value)}
              className="form-select"
            >
              {applications.map((app) => (
                <option key={app.id} value={app.id}>
                  {app.name} ({app.base_url}) - [{app.environment.toUpperCase()}]
                </option>
              ))}
            </select>
            {currentApp && (
              <div className="target-summary-row mt-2">
                <span className="text-xs text-slate-500">Authorization:</span>
                {currentApp.is_authorized ? (
                  <span className="text-xs text-emerald-700 font-medium flex items-center gap-1">
                    <Shield size={12} /> Certified Authorized
                  </span>
                ) : (
                  <span className="text-xs text-rose-700 font-medium flex items-center gap-1">
                    <ShieldAlert size={12} /> Unauthorized Target
                  </span>
                )}
                <span className="text-slate-300">|</span>
                <span className="text-xs text-slate-500">Auth Profile:</span>
                <span className="text-xs text-slate-700 font-mono">
                  {currentApp.has_auth_configured ? 'Configured' : 'None (Unauthenticated)'}
                </span>
              </div>
            )}
          </div>

          {/* Scan Type Selection Cards */}
          <div className="form-group">
            <label className="form-label">Assessment Profile</label>
            <div className="scan-type-grid">
              {(
                [
                  'baseline_passive',
                  'full_active',
                  'api_openapi',
                  'spa_ajax',
                ] as ScanType[]
              ).map((type) => {
                const info = scanTypeDescriptions[type];
                const isSelected = scanType === type;
                return (
                  <div
                    key={type}
                    onClick={() => setScanType(type)}
                    className={`scan-type-card ${isSelected ? 'selected' : ''}`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="scan-type-title">{info.title}</span>
                      <span className="scan-type-tag">{info.tag}</span>
                    </div>
                    <p className="scan-type-desc">{info.desc}</p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Duration & Headers */}
          <div className="form-grid">
            <div className="form-group col-span-1">
              <label className="form-label" htmlFor="max-duration">
                Max Execution Window (Minutes)
              </label>
              <div className="flex items-center gap-2">
                <input
                  id="max-duration"
                  type="number"
                  min="5"
                  max="240"
                  value={maxDuration}
                  onChange={(e) => setMaxDuration(Number(e.target.value))}
                  className="form-input font-mono text-xs w-28"
                />
                <span className="text-xs text-slate-500">
                  Worker auto-aborts if exceeded.
                </span>
              </div>
            </div>

            <div className="form-group col-span-1">
              <label className="form-label">Custom Audit Headers</label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={headerKey}
                  onChange={(e) => setHeaderKey(e.target.value)}
                  placeholder="Header Name"
                  className="form-input font-mono text-xs"
                />
                <input
                  type="text"
                  value={headerVal}
                  onChange={(e) => setHeaderVal(e.target.value)}
                  placeholder="Header Value"
                  className="form-input font-mono text-xs"
                />
              </div>
            </div>
          </div>

          {/* Footer */}
          <div className="modal-footer">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="btn btn-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !currentApp?.is_authorized}
              className="btn btn-primary"
            >
              <Play size={14} />
              <span>{isSubmitting ? 'Starting...' : 'Trigger Scan Job'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
