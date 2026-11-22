import React, { useState, useMemo } from 'react';
import { ApplicationResponse } from '../types';
import {
  Plus,
  Search,
  Play,
  Key,
  ExternalLink,
  Trash2,
  Lock,
  Unlock,
  Layers,
} from 'lucide-react';
import {
  AuthBadge,
  CriticalityBadge,
  EnvironmentBadge,
} from '../components/common/Badges';

export interface ApplicationsPageProps {
  applications: ApplicationResponse[];
  isBackendUnreachable?: boolean;
  onOpenRegisterModal: () => void;
  onOpenTriggerScanModal: (appId: string) => void;
  onOpenConfigureAuthModal: (app: ApplicationResponse) => void;
  onDeleteApplication: (appId: string) => Promise<void>;
  onSelectApplication: (appId: string) => void;
}

export const ApplicationsPage: React.FC<ApplicationsPageProps> = ({
  applications,
  isBackendUnreachable = false,
  onOpenRegisterModal,
  onOpenTriggerScanModal,
  onOpenConfigureAuthModal,
  onDeleteApplication,
  onSelectApplication,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEnv, setSelectedEnv] = useState<string>('all');
  const [selectedCrit, setSelectedCrit] = useState<string>('all');

  const filteredApps = useMemo(() => {
    return applications.filter((app) => {
      const matchesSearch =
        app.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        app.base_url.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (app.team_name && app.team_name.toLowerCase().includes(searchQuery.toLowerCase()));

      const matchesEnv = selectedEnv === 'all' || app.environment === selectedEnv;
      const matchesCrit = selectedCrit === 'all' || app.criticality === selectedCrit;

      return matchesSearch && matchesEnv && matchesCrit;
    });
  }, [applications, searchQuery, selectedEnv, selectedCrit]);

  return (
    <div className="page-container">
      {/* Action and Filter Toolbar */}
      <div className="toolbar-box">
        <div className="toolbar-left">
          {/* Search Box */}
          <div className="search-input-wrapper">
            <Search size={15} className="search-icon" />
            <input
              type="text"
              placeholder="Filter by target name, domain URL, or team..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="toolbar-search-input"
            />
          </div>

          {/* Environment Filter */}
          <div className="filter-item">
            <label className="filter-label" htmlFor="env-select">
              Environment:
            </label>
            <select
              id="env-select"
              value={selectedEnv}
              onChange={(e) => setSelectedEnv(e.target.value)}
              className="form-select form-select-sm"
            >
              <option value="all">All Environments</option>
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Development</option>
              <option value="qa">QA</option>
            </select>
          </div>

          {/* Criticality Filter */}
          <div className="filter-item">
            <label className="filter-label" htmlFor="crit-select">
              Criticality:
            </label>
            <select
              id="crit-select"
              value={selectedCrit}
              onChange={(e) => setSelectedCrit(e.target.value)}
              className="form-select form-select-sm"
            >
              <option value="all">All Tiers</option>
              <option value="critical">Tier 1 - Critical</option>
              <option value="high">Tier 2 - High</option>
              <option value="medium">Tier 3 - Medium</option>
              <option value="low">Tier 4 - Low</option>
            </select>
          </div>
        </div>

        <div className="toolbar-right">
          <button
            type="button"
            onClick={onOpenRegisterModal}
            className="btn btn-primary"
          >
            <Plus size={14} />
            <span>Register Application</span>
          </button>
        </div>
      </div>

      {/* Target Applications Table */}
      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">Authorized Target Applications</h3>
            <p className="card-subtitle">
              Showing {filteredApps.length} of {applications.length} registered targets
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500">
            Rules of Engagement Enforced
          </span>
        </div>

        <div className="card-body p-0">
          {filteredApps.length === 0 ? (
            <div className="empty-state-box">
              <Layers size={32} className="text-slate-300 mb-2" />
              <p className="text-slate-600 font-medium">
                {isBackendUnreachable
                  ? 'Backend not connected — unable to reach 127.0.0.1:8000'
                  : 'No target applications found'}
              </p>
              <p className="text-slate-400 text-xs mt-1">
                {isBackendUnreachable
                  ? 'Please ensure the API server is running on 127.0.0.1:8000 or enable Offline Mock mode.'
                  : 'Try adjusting your search filters or click "Register Application".'}
              </p>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Target Application</th>
                    <th>Environment</th>
                    <th>Criticality</th>
                    <th>Authorization</th>
                    <th>Auth Config</th>
                    <th>Risk Score</th>
                    <th>Open Findings</th>
                    <th>Last Scanned</th>
                    <th className="text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredApps.map((app) => (
                    <tr key={app.id} onClick={() => onSelectApplication(app.id)} className="cursor-pointer">
                      {/* Name & URL */}
                      <td>
                        <div className="font-semibold text-slate-900 text-xs">
                          {app.name}
                        </div>
                        <div className="flex items-center gap-1.5 text-xs font-mono text-slate-500 mt-0.5">
                          <span>{app.base_url}</span>
                          <a
                            href={app.base_url}
                            target="_blank"
                            rel="noreferrer"
                            onClick={(e) => e.stopPropagation()}
                            className="text-slate-400 hover:text-slate-600"
                            title="Open URL in browser"
                          >
                            <ExternalLink size={11} />
                          </a>
                        </div>
                        {app.team_name && (
                          <div className="text-xs text-slate-400 mt-0.5">
                            Team: {app.team_name}
                          </div>
                        )}
                      </td>

                      {/* Environment */}
                      <td>
                        <EnvironmentBadge environment={app.environment} size="sm" />
                      </td>

                      {/* Criticality */}
                      <td>
                        <CriticalityBadge criticality={app.criticality} size="sm" />
                      </td>

                      {/* Authorization Status */}
                      <td>
                        <AuthBadge isAuthorized={app.is_authorized} size="sm" />
                      </td>

                      {/* Auth Profile Status */}
                      <td>
                        {app.has_auth_configured ? (
                          <span className="badge badge-emerald-soft badge-sm font-mono flex items-center gap-1 w-fit">
                            <Lock size={11} /> Configured
                          </span>
                        ) : (
                          <span className="badge badge-slate-soft badge-sm font-mono flex items-center gap-1 w-fit text-slate-500">
                            <Unlock size={11} /> Unauthed
                          </span>
                        )}
                      </td>

                      {/* Risk Score */}
                      <td>
                        <span className="font-mono font-bold text-xs tabular-nums text-slate-900">
                          {app.latest_risk_score.toFixed(1)}
                        </span>
                      </td>

                      {/* Open Findings Counts */}
                      <td>
                        <div className="flex gap-1 flex-wrap">
                          {app.open_counts.critical > 0 && (
                            <span className="badge badge-critical-bg badge-critical-text badge-sm font-mono tabular-nums">
                              {app.open_counts.critical}C
                            </span>
                          )}
                          {app.open_counts.high > 0 && (
                            <span className="badge badge-high-bg badge-high-text badge-sm font-mono tabular-nums">
                              {app.open_counts.high}H
                            </span>
                          )}
                          {app.open_counts.medium > 0 && (
                            <span className="badge badge-medium-bg badge-medium-text badge-sm font-mono tabular-nums">
                              {app.open_counts.medium}M
                            </span>
                          )}
                          {app.open_counts.critical === 0 &&
                            app.open_counts.high === 0 &&
                            app.open_counts.medium === 0 && (
                              <span className="text-xs text-slate-400 font-mono">0 Open</span>
                            )}
                        </div>
                      </td>

                      {/* Last Scanned */}
                      <td className="text-xs font-mono text-slate-600">
                        {app.last_scanned_at ? (
                          new Date(app.last_scanned_at).toLocaleDateString()
                        ) : (
                          <span className="text-slate-400">Never</span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => onOpenConfigureAuthModal(app)}
                            className="btn-icon-sm"
                            title="Configure ZAP Scanner Auth credentials"
                          >
                            <Key size={13} />
                          </button>
                          <button
                            type="button"
                            onClick={() => onOpenTriggerScanModal(app.id)}
                            disabled={!app.is_authorized}
                            className="btn btn-secondary btn-sm"
                            title={app.is_authorized ? 'Launch scan assessment' : 'Target unauthorized'}
                          >
                            <Play size={12} />
                            <span>Scan</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => onDeleteApplication(app.id)}
                            className="btn-icon-sm text-slate-400 hover:text-rose-600"
                            title="Delete Target Application"
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
