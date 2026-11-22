import React, { useState, useEffect } from 'react';
import {
  RemediationAuditLogResponse,
  RemediationStatus,
  VulnerabilityDetail,
} from '../../types';
import {
  SeverityBadge,
  StatusBadge,
  DiffBadge,
} from '../common/Badges';
import {
  X,
  Terminal,
  Send,
  ExternalLink,
  Copy,
  Check,
  ArrowRight,
  MessageSquare,
} from 'lucide-react';
import { api } from '../../services/api';

export interface VulnDetailDrawerProps {
  isOpen: boolean;
  vuln: VulnerabilityDetail | null;
  onClose: () => void;
  onStatusChange: (vulnId: string, newStatus: RemediationStatus, comment?: string) => Promise<void>;
  applicationName?: string;
}

export const VulnDetailDrawer: React.FC<VulnDetailDrawerProps> = ({
  isOpen,
  vuln,
  onClose,
  onStatusChange,
  applicationName = 'Application',
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'audit'>('overview');
  const [selectedStatus, setSelectedStatus] = useState<RemediationStatus>('open');
  const [statusComment, setStatusComment] = useState('');
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [newCommentText, setNewCommentText] = useState('');
  const [auditLogs, setAuditLogs] = useState<RemediationAuditLogResponse[]>([]);
  const [isLoadingLogs, setIsLoadingLogs] = useState(false);
  const [copiedPayload, setCopiedPayload] = useState(false);

  useEffect(() => {
    if (vuln) {
      setSelectedStatus(vuln.status);
      loadAuditLogs(vuln.id);
    }
  }, [vuln]);

  const loadAuditLogs = async (id: string) => {
    try {
      setIsLoadingLogs(true);
      const logs = await api.getVulnHistory(id);
      setAuditLogs(logs);
    } catch (err) {
      console.error('Failed to load audit logs:', err);
    } finally {
      setIsLoadingLogs(false);
    }
  };

  if (!isOpen || !vuln) return null;

  const handleStatusSubmit = async () => {
    if (selectedStatus === vuln.status && !statusComment.trim()) return;
    try {
      setIsUpdatingStatus(true);
      await onStatusChange(vuln.id, selectedStatus, statusComment.trim() || undefined);
      setStatusComment('');
      await loadAuditLogs(vuln.id);
    } catch (err) {
      console.error('Failed to change status:', err);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCommentText.trim()) return;
    try {
      const added = await api.addVulnComment(vuln.id, newCommentText.trim());
      setNewCommentText('');
      setAuditLogs((prev) => [added, ...prev]);
    } catch (err) {
      console.error('Failed to add comment:', err);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  const evidence = vuln.latest_evidence;

  return (
    <div className="drawer-backdrop">
      <div className="drawer-panel">
        {/* Drawer Header */}
        <div className="drawer-header">
          <div className="drawer-title-area">
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <SeverityBadge severity={vuln.severity} />
              <StatusBadge status={vuln.status} />
              <span className="cvss-pill font-mono tabular-nums">
                CVSS {vuln.cvss_score.toFixed(1)}
              </span>
              <span className="text-xs text-slate-500 font-mono">
                {applicationName}
              </span>
            </div>
            <h2 className="drawer-title">{vuln.title}</h2>
            <div className="drawer-subtitle font-mono text-xs text-slate-600">
              <span className="font-semibold text-slate-800">{vuln.http_method}</span>{' '}
              <span>{vuln.normalized_path}</span>
              {vuln.affected_param && (
                <span className="param-tag">param: {vuln.affected_param}</span>
              )}
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="drawer-close-btn"
            title="Close Drawer"
          >
            <X size={18} />
          </button>
        </div>

        {/* Quick Triage Bar */}
        <div className="drawer-triage-bar">
          <div className="flex items-center gap-2 flex-1">
            <span className="text-xs text-slate-600 font-medium">Triage Status:</span>
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value as RemediationStatus)}
              className="form-select form-select-sm w-44"
            >
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="verified_fixed">Verified Fixed</option>
              <option value="false_positive">False Positive</option>
              <option value="risk_accepted">Risk Accepted</option>
            </select>
            <input
              type="text"
              placeholder="Optional audit comment..."
              value={statusComment}
              onChange={(e) => setStatusComment(e.target.value)}
              className="form-input form-input-sm flex-1 text-xs"
            />
          </div>
          <button
            type="button"
            onClick={handleStatusSubmit}
            disabled={isUpdatingStatus || (selectedStatus === vuln.status && !statusComment.trim())}
            className="btn btn-primary btn-sm"
          >
            {isUpdatingStatus ? 'Updating...' : 'Update'}
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="drawer-tabs">
          <button
            type="button"
            onClick={() => setActiveTab('overview')}
            className={`drawer-tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
          >
            Overview & Solution
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('evidence')}
            className={`drawer-tab-btn ${activeTab === 'evidence' ? 'active' : ''}`}
          >
            HTTP Evidence & Diffs
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('audit')}
            className={`drawer-tab-btn ${activeTab === 'audit' ? 'active' : ''}`}
          >
            Remediation Audit ({auditLogs.length})
          </button>
        </div>

        {/* Tab Content Body */}
        <div className="drawer-body">
          {activeTab === 'overview' && (
            <div className="drawer-content-stack">
              {/* Metadata Key-Value Grid */}
              <div className="meta-grid">
                <div className="meta-item">
                  <span className="meta-label">OWASP Category</span>
                  <span className="meta-value font-mono">{vuln.owasp_category}</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">CWE Identifier</span>
                  <span className="meta-value font-mono">
                    {vuln.cwe_id ? `CWE-${vuln.cwe_id}` : 'None'}
                  </span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">CVSS Vector</span>
                  <span className="meta-value font-mono text-xs truncate" title={vuln.cvss_vector || 'N/A'}>
                    {vuln.cvss_vector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'}
                  </span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">ZAP Plugin ID</span>
                  <span className="meta-value font-mono">{vuln.zap_plugin_id || '40018'}</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Times Observed</span>
                  <span className="meta-value font-mono tabular-nums">{vuln.seen_count} scans</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">First Discovered</span>
                  <span className="meta-value text-xs font-mono">
                    {new Date(vuln.first_seen_at).toLocaleDateString()}
                  </span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Last Discovered</span>
                  <span className="meta-value text-xs font-mono">
                    {new Date(vuln.last_seen_at).toLocaleDateString()}
                  </span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Remediation SLA</span>
                  <span className="meta-value text-xs font-mono text-amber-700">
                    {vuln.due_date ? new Date(vuln.due_date).toLocaleDateString() : 'Due in 7 days'}
                  </span>
                </div>
              </div>

              {/* Description Section */}
              <div className="detail-section">
                <h4 className="detail-section-title">Vulnerability Description</h4>
                <div className="prose-box text-sm text-slate-700 leading-relaxed">
                  {vuln.description}
                </div>
              </div>

              {/* Solution Section */}
              <div className="detail-section">
                <h4 className="detail-section-title">Remediation Guidance</h4>
                <div className="solution-box text-sm text-slate-800 leading-relaxed">
                  {vuln.solution}
                </div>
              </div>

              {/* References */}
              {vuln.reference_urls && vuln.reference_urls.length > 0 && (
                <div className="detail-section">
                  <h4 className="detail-section-title">Security Advisories & References</h4>
                  <ul className="reference-list">
                    {vuln.reference_urls.map((url, idx) => (
                      <li key={idx} className="reference-item">
                        <a
                          href={url}
                          target="_blank"
                          rel="noreferrer"
                          className="ref-link flex items-center gap-1.5"
                        >
                          <ExternalLink size={12} />
                          <span className="truncate">{url}</span>
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="drawer-content-stack">
              {evidence ? (
                <>
                  {/* Diff Classification State */}
                  <div className="flex items-center justify-between p-3 bg-slate-50 border border-slate-200 rounded-md">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium text-slate-600">Scan Regression Status:</span>
                      <DiffBadge state={evidence.diff_state} />
                    </div>
                    <span className="text-xs font-mono text-slate-500">
                      Scan Ref: {evidence.scan_id.substring(0, 8)}...
                    </span>
                  </div>

                  {/* Attack Payload */}
                  {evidence.attack_payload && (
                    <div className="detail-section">
                      <div className="flex items-center justify-between mb-1.5">
                        <h4 className="detail-section-title mb-0">Dispatched Attack Payload</h4>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(evidence.attack_payload || '')}
                          className="btn-text-sm"
                        >
                          {copiedPayload ? <Check size={12} /> : <Copy size={12} />}
                          <span>{copiedPayload ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <div className="terminal-box">
                        <code className="text-rose-700">{evidence.attack_payload}</code>
                      </div>
                    </div>
                  )}

                  {/* Evidence Snippet */}
                  {evidence.evidence_snippet && (
                    <div className="detail-section">
                      <h4 className="detail-section-title">Triggered Evidence Snippet</h4>
                      <div className="terminal-box bg-amber-50/50 border-amber-200">
                        <code className="text-amber-900">{evidence.evidence_snippet}</code>
                      </div>
                    </div>
                  )}

                  {/* Raw Request Headers */}
                  <div className="detail-section">
                    <h4 className="detail-section-title">Raw HTTP Request Header</h4>
                    <div className="terminal-box max-h-48 overflow-y-auto">
                      <pre className="text-slate-800 text-xs font-mono">
                        {evidence.raw_request_header ||
                          `${vuln.http_method} ${vuln.normalized_path} HTTP/1.1\nHost: target.corp.internal\nUser-Agent: Mozilla/5.0 (AppSec ZAP Scanner)\nAccept: */*\nX-Scan-Origin: Authorized-SecOps\n`}
                      </pre>
                    </div>
                  </div>

                  {/* Raw Response Headers */}
                  <div className="detail-section">
                    <h4 className="detail-section-title">Raw HTTP Response Header</h4>
                    <div className="terminal-box max-h-48 overflow-y-auto">
                      <pre className="text-slate-800 text-xs font-mono">
                        {evidence.raw_response_header ||
                          `HTTP/1.1 500 Internal Server Error\nDate: Sun, 22 Nov 2026 10:40:00 GMT\nContent-Type: text/html; charset=utf-8\nServer: Microsoft-IIS/10.0\nX-Powered-By: ASP.NET\n\nSyntax error in SQL query near \'1=1\'`}
                      </pre>
                    </div>
                  </div>
                </>
              ) : (
                <div className="empty-evidence-box">
                  <Terminal size={32} className="text-slate-300 mb-2" />
                  <p className="text-slate-500 text-sm">No raw HTTP evidence captured for this finding.</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'audit' && (
            <div className="drawer-content-stack">
              {/* Add Comment Form */}
              <form onSubmit={handleAddComment} className="comment-form-box">
                <label className="text-xs font-semibold text-slate-700 mb-1 block">
                  Add Triage Note or Verification Comment
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    required
                    placeholder="e.g., Validated fix in staging build #412..."
                    value={newCommentText}
                    onChange={(e) => setNewCommentText(e.target.value)}
                    className="form-input text-xs flex-1"
                  />
                  <button type="submit" className="btn btn-secondary btn-sm">
                    <Send size={13} />
                    <span>Post</span>
                  </button>
                </div>
              </form>

              {/* Audit Trail Timeline */}
              <div className="audit-timeline">
                <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
                  Immutable Remediation History
                </div>
                {isLoadingLogs ? (
                  <div className="text-xs text-slate-500 py-4 text-center">Loading audit log...</div>
                ) : auditLogs.length === 0 ? (
                  <div className="text-xs text-slate-400 py-4 text-center">No audit records logged yet.</div>
                ) : (
                  <div className="timeline-items">
                    {auditLogs.map((log) => (
                      <div key={log.id} className="timeline-item">
                        <div className="timeline-dot" />
                        <div className="timeline-content">
                          <div className="timeline-header">
                            <span className="timeline-action">{log.action_type.replace(/_/g, ' ')}</span>
                            <span className="timeline-time">
                              {new Date(log.created_at).toLocaleString()}
                            </span>
                          </div>
                          {log.old_status && log.new_status && (
                            <div className="timeline-transition">
                              <StatusBadge status={log.old_status} size="sm" />
                              <ArrowRight size={12} className="text-slate-400" />
                              <StatusBadge status={log.new_status} size="sm" />
                            </div>
                          )}
                          {log.comment && (
                            <div className="timeline-comment">
                              <MessageSquare size={12} className="text-slate-400 inline mr-1" />
                              <span>{log.comment}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
