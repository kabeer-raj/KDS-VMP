import React, { useState, useMemo } from 'react';
import {
  ApplicationResponse,
  BulkUpdateVulnsRequest,
  RemediationStatus,
  VulnerabilityDetail,
  VulnerabilitySummary,
} from '../types';
import {
  Search,
  CheckSquare,
  Square,
  ShieldAlert,
  ArrowUpDown,
} from 'lucide-react';
import {
  SeverityBadge,
  StatusBadge,
} from '../components/common/Badges';
import { VulnDetailDrawer } from '../components/vulns/VulnDetailDrawer';

export interface VulnerabilitiesPageProps {
  vulnerabilities: VulnerabilitySummary[];
  applications: ApplicationResponse[];
  selectedVulnDetail: VulnerabilityDetail | null;
  isBackendUnreachable?: boolean;
  onSelectVuln: (vulnId: string) => void;
  onCloseDrawer: () => void;
  onUpdateVulnStatus: (
    vulnId: string,
    newStatus: RemediationStatus,
    comment?: string
  ) => Promise<void>;
  onBulkUpdate: (req: BulkUpdateVulnsRequest) => Promise<void>;
  isLoading?: boolean;
}

export const VulnerabilitiesPage: React.FC<VulnerabilitiesPageProps> = ({
  vulnerabilities,
  applications,
  selectedVulnDetail,
  isBackendUnreachable = false,
  onSelectVuln,
  onCloseDrawer,
  onUpdateVulnStatus,
  onBulkUpdate,
  isLoading = false,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [selectedAppId, setSelectedAppId] = useState<string>('all');

  // Multi-select for bulk triage
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkStatus, setBulkStatus] = useState<RemediationStatus>('resolved');
  const [bulkComment, setBulkComment] = useState('');
  const [isBulkSubmitting, setIsBulkSubmitting] = useState(false);

  // Sorting
  const [sortField, setSortField] = useState<'cvss_score' | 'last_seen_at' | 'seen_count'>('cvss_score');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const getAppName = (appId: string) => {
    const app = applications.find((a) => a.id === appId);
    return app ? app.name : 'Application';
  };

  const filteredVulns = useMemo(() => {
    return vulnerabilities
      .filter((v) => {
        const matchesSearch =
          v.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
          v.normalized_path.toLowerCase().includes(searchQuery.toLowerCase()) ||
          v.owasp_category.toLowerCase().includes(searchQuery.toLowerCase()) ||
          (v.cwe_id && `cwe-${v.cwe_id}`.toLowerCase().includes(searchQuery.toLowerCase()));

        const matchesSeverity =
          selectedSeverity === 'all' || v.severity === selectedSeverity;
        const matchesStatus =
          selectedStatus === 'all' || v.status === selectedStatus;
        const matchesApp =
          selectedAppId === 'all' || v.application_id === selectedAppId;

        return matchesSearch && matchesSeverity && matchesStatus && matchesApp;
      })
      .sort((a, b) => {
        let diff = 0;
        if (sortField === 'cvss_score') {
          diff = a.cvss_score - b.cvss_score;
        } else if (sortField === 'seen_count') {
          diff = a.seen_count - b.seen_count;
        } else if (sortField === 'last_seen_at') {
          diff = new Date(a.last_seen_at).getTime() - new Date(b.last_seen_at).getTime();
        }
        return sortOrder === 'desc' ? -diff : diff;
      });
  }, [
    vulnerabilities,
    searchQuery,
    selectedSeverity,
    selectedStatus,
    selectedAppId,
    sortField,
    sortOrder,
  ]);

  const toggleSelectAll = () => {
    if (selectedIds.size === filteredVulns.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filteredVulns.map((v) => v.id)));
    }
  };

  const toggleSelectOne = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const next = new Set(selectedIds);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    setSelectedIds(next);
  };

  const handleBulkSubmit = async () => {
    if (selectedIds.size === 0) return;
    try {
      setIsBulkSubmitting(true);
      await onBulkUpdate({
        vuln_ids: Array.from(selectedIds),
        status: bulkStatus,
        comment: bulkComment.trim() || undefined,
      });
      setSelectedIds(new Set());
      setBulkComment('');
    } catch (err) {
      console.error('Bulk update failed:', err);
    } finally {
      setIsBulkSubmitting(false);
    }
  };

  const handleSort = (field: 'cvss_score' | 'last_seen_at' | 'seen_count') => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  return (
    <div className="page-container">
      {/* Search & Filter Toolbar */}
      <div className="toolbar-box">
        <div className="toolbar-left flex-wrap">
          {/* Search box */}
          <div className="search-input-wrapper">
            <Search size={15} className="search-icon" />
            <input
              type="text"
              placeholder="Search findings, CWE, normalized path..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="toolbar-search-input"
            />
          </div>

          {/* Severity Filter */}
          <div className="filter-item">
            <label className="filter-label" htmlFor="filter-sev">
              Severity:
            </label>
            <select
              id="filter-sev"
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="form-select form-select-sm"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>

          {/* Status Filter */}
          <div className="filter-item">
            <label className="filter-label" htmlFor="filter-stat">
              Status:
            </label>
            <select
              id="filter-stat"
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="form-select form-select-sm"
            >
              <option value="all">All Statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="verified_fixed">Verified Fixed</option>
              <option value="false_positive">False Positive</option>
              <option value="risk_accepted">Risk Accepted</option>
              <option value="regressed">Regressed</option>
            </select>
          </div>

          {/* Target App Filter */}
          <div className="filter-item">
            <label className="filter-label" htmlFor="filter-app">
              Application:
            </label>
            <select
              id="filter-app"
              value={selectedAppId}
              onChange={(e) => setSelectedAppId(e.target.value)}
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
        </div>

        <div className="toolbar-right">
          <span className="text-xs font-mono text-slate-500 tabular-nums">
            {filteredVulns.length} findings matching filter
          </span>
        </div>
      </div>

      {/* Bulk Triage Action Bar (Appears when 1+ findings are checked) */}
      {selectedIds.size > 0 && (
        <div className="bulk-action-bar">
          <div className="flex items-center gap-3">
            <span className="bulk-badge font-mono tabular-nums">
              {selectedIds.size} SELECTED
            </span>
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-600 font-medium">Batch Transition:</span>
              <select
                value={bulkStatus}
                onChange={(e) => setBulkStatus(e.target.value as RemediationStatus)}
                className="form-select form-select-sm w-44"
              >
                <option value="resolved">Mark Resolved</option>
                <option value="verified_fixed">Mark Verified Fixed</option>
                <option value="false_positive">Mark False Positive</option>
                <option value="risk_accepted">Mark Risk Accepted</option>
                <option value="in_progress">Mark In Progress</option>
                <option value="open">Reopen</option>
              </select>
              <input
                type="text"
                placeholder="Bulk audit comment..."
                value={bulkComment}
                onChange={(e) => setBulkComment(e.target.value)}
                className="form-input form-input-sm text-xs w-64"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setSelectedIds(new Set())}
              className="btn btn-secondary btn-sm"
            >
              Deselect All
            </button>
            <button
              type="button"
              onClick={handleBulkSubmit}
              disabled={isBulkSubmitting}
              className="btn btn-primary btn-sm"
            >
              {isBulkSubmitting ? 'Applying...' : 'Apply Bulk Triage'}
            </button>
          </div>
        </div>
      )}

      {/* Findings Table Card */}
      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">Vulnerability Findings Registry</h3>
            <p className="card-subtitle">
              Interactive triage, AST fingerprint correlation & HTTP evidence inspection
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500">
            OWASP 2021 & CVSS 3.1
          </span>
        </div>

        <div className="card-body p-0">
          {isLoading ? (
            <div className="py-12 text-center text-slate-400 text-xs">
              Loading vulnerability findings...
            </div>
          ) : filteredVulns.length === 0 ? (
            <div className="empty-state-box">
              <ShieldAlert size={32} className="text-slate-300 mb-2" />
              <p className="text-slate-600 font-medium">
                {isBackendUnreachable
                  ? 'Backend not connected — unable to reach 127.0.0.1:8000'
                  : 'No vulnerabilities found'}
              </p>
              <p className="text-slate-400 text-xs mt-1">
                {isBackendUnreachable
                  ? 'Please ensure the API server is running on 127.0.0.1:8000 or enable Offline Mock mode.'
                  : 'No findings match the current filter criteria.'}
              </p>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th className="w-8">
                      <button
                        type="button"
                        onClick={toggleSelectAll}
                        className="text-slate-400 hover:text-slate-700 mt-1"
                        title="Select / Deselect all"
                      >
                        {selectedIds.size > 0 && selectedIds.size === filteredVulns.length ? (
                          <CheckSquare size={14} className="text-slate-900" />
                        ) : (
                          <Square size={14} />
                        )}
                      </button>
                    </th>
                    <th>Severity</th>
                    <th>Vulnerability Finding</th>
                    <th>Target Application</th>
                    <th>OWASP Category</th>
                    <th
                      onClick={() => handleSort('cvss_score')}
                      className="cursor-pointer select-none"
                    >
                      <div className="flex items-center gap-1">
                        <span>CVSS</span>
                        <ArrowUpDown size={11} className="text-slate-400" />
                      </div>
                    </th>
                    <th>Affected Endpoint</th>
                    <th
                      onClick={() => handleSort('seen_count')}
                      className="cursor-pointer select-none"
                    >
                      <div className="flex items-center gap-1">
                        <span>Seen</span>
                        <ArrowUpDown size={11} className="text-slate-400" />
                      </div>
                    </th>
                    <th>Status</th>
                    <th className="text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredVulns.map((v) => {
                    const isSelected = selectedIds.has(v.id);
                    return (
                      <tr
                        key={v.id}
                        onClick={() => onSelectVuln(v.id)}
                        className={`cursor-pointer ${isSelected ? 'row-selected' : ''}`}
                      >
                        {/* Checkbox */}
                        <td onClick={(e) => toggleSelectOne(v.id, e)}>
                          <button
                            type="button"
                            className="text-slate-400 hover:text-slate-700 mt-1"
                          >
                            {isSelected ? (
                              <CheckSquare size={14} className="text-slate-900" />
                            ) : (
                              <Square size={14} />
                            )}
                          </button>
                        </td>

                        {/* Severity */}
                        <td>
                          <SeverityBadge severity={v.severity} size="sm" />
                        </td>

                        {/* Finding Title & CWE */}
                        <td>
                          <div className="font-semibold text-slate-900 text-xs">
                            {v.title}
                          </div>
                          <div className="text-xs font-mono text-slate-500 mt-0.5">
                            {v.cwe_id ? `CWE-${v.cwe_id}` : 'General Flaw'}
                          </div>
                        </td>

                        {/* Target App */}
                        <td>
                          <div className="text-xs font-medium text-slate-800">
                            {getAppName(v.application_id)}
                          </div>
                        </td>

                        {/* OWASP */}
                        <td>
                          <span className="font-mono text-xs text-slate-600">
                            {v.owasp_category.split('-')[0] || v.owasp_category}
                          </span>
                        </td>

                        {/* CVSS Score */}
                        <td>
                          <span className="font-mono font-bold text-xs tabular-nums text-slate-900">
                            {v.cvss_score.toFixed(1)}
                          </span>
                        </td>

                        {/* Endpoint */}
                        <td>
                          <div className="font-mono text-xs text-slate-700">
                            <span className="font-bold text-slate-900">{v.http_method}</span>{' '}
                            <span>{v.normalized_path}</span>
                          </div>
                          {v.affected_param && (
                            <div className="text-xs font-mono text-slate-400 mt-0.5">
                              param: {v.affected_param}
                            </div>
                          )}
                        </td>

                        {/* Seen Count */}
                        <td className="font-mono text-xs text-slate-600 tabular-nums">
                          {v.seen_count}x
                        </td>

                        {/* Status */}
                        <td>
                          <StatusBadge status={v.status} size="sm" />
                        </td>

                        {/* Action */}
                        <td className="text-right" onClick={(e) => e.stopPropagation()}>
                          <button
                            type="button"
                            onClick={() => onSelectVuln(v.id)}
                            className="btn-text-sm"
                          >
                            Triage
                          </button>
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

      {/* Slide-over Detail Drawer */}
      <VulnDetailDrawer
        isOpen={Boolean(selectedVulnDetail)}
        vuln={selectedVulnDetail}
        onClose={onCloseDrawer}
        onStatusChange={onUpdateVulnStatus}
        applicationName={
          selectedVulnDetail ? getAppName(selectedVulnDetail.application_id) : undefined
        }
      />
    </div>
  );
};
