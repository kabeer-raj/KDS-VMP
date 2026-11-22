import React from 'react';
import {
  ApplicationResponse,
  DashboardSummary,
  ScanResponse,
  VulnerabilitySummary,
} from '../types';
import {
  ShieldCheck,
  Layers,
  ChevronRight,
} from 'lucide-react';
import { SeverityBadge, StatusBadge } from '../components/common/Badges';

export interface DashboardPageProps {
  summary: DashboardSummary | null;
  applications: ApplicationResponse[];
  vulnerabilities?: VulnerabilitySummary[];
  recentScans: ScanResponse[];
  isBackendUnreachable?: boolean;
  onNavigateToTab: (tab: 'dashboard' | 'apps' | 'scans' | 'vulns' | 'reports') => void;
  onSelectVuln: (vulnId: string) => void;
  onOpenTriggerScan?: (appId?: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  summary,
  applications,
  vulnerabilities = [],
  recentScans,
  isBackendUnreachable = false,
  onNavigateToTab,
  onSelectVuln,
}) => {
  // Real defaults: strictly 0 / 0.0 when backend is disconnected or total is 0
  const avgRisk = summary?.average_risk_score ?? 0.0;
  const totalApps = summary?.total_applications ?? applications.length;
  const totalVulns = summary?.total_vulnerabilities ?? vulnerabilities.length;

  // Dynamic severity counts - strictly 0 if no findings exist
  const severityCounts = summary?.severity_counts ?? {
    critical: vulnerabilities.filter((v) => v.severity === 'critical').length,
    high: vulnerabilities.filter((v) => v.severity === 'high').length,
    medium: vulnerabilities.filter((v) => v.severity === 'medium').length,
    low: vulnerabilities.filter((v) => v.severity === 'low').length,
    info: vulnerabilities.filter((v) => v.severity === 'info').length,
  };

  // SLA compliance defaults strictly to 0.0 when not present
  const sla = summary?.sla_compliance ?? {
    critical_within_sla: 0,
    critical_breached: 0,
    high_within_sla: 0,
    high_breached: 0,
    overall_compliance_rate: 0.0,
  };

  // OWASP data defaults strictly to empty array
  const owaspData = summary?.owasp_breakdown ?? [];

  const topVulns = (summary?.vulnerabilities || vulnerabilities || []).slice(0, 5);

  return (
    <div className="page-container">
      {/* 1. Executive Top Metrics Row */}
      <section className="metrics-grid">
        {/* Global Average Risk Score */}
        <div className="card metric-card">
          <div className="metric-header">
            <span className="metric-title">GLOBAL RISK SCORE</span>
            <span className="metric-pill font-mono">0-10 CVSS Scale</span>
          </div>
          <div className="metric-body">
            <div className="metric-primary-val font-mono tabular-nums text-slate-900">
              {avgRisk.toFixed(1)}
              <span className="text-xs text-slate-400 font-normal"> / 10.0</span>
            </div>
            <div className="risk-level-indicator">
              <span
                className={`risk-indicator-badge ${
                  avgRisk >= 7
                    ? 'badge-critical-bg badge-critical-text'
                    : avgRisk >= 4
                    ? 'badge-amber'
                    : avgRisk > 0
                    ? 'badge-emerald'
                    : 'badge-slate'
                }`}
              >
                {avgRisk >= 7
                  ? 'High Risk Exposure'
                  : avgRisk >= 4
                  ? 'Moderate Posture'
                  : avgRisk > 0
                  ? 'Low Risk'
                  : 'Zero Risk'}
              </span>
            </div>
          </div>
          <div className="metric-footer text-xs text-slate-500">
            {totalApps > 0
              ? `Weighted across ${totalApps} registered target applications`
              : 'No applications registered'}
          </div>
        </div>

        {/* Total Applications */}
        <div className="card metric-card">
          <div className="metric-header">
            <span className="metric-title">TARGET APPLICATIONS</span>
            <Layers size={14} className="text-slate-400" />
          </div>
          <div className="metric-body">
            <div className="metric-primary-val font-mono tabular-nums text-slate-900">
              {totalApps}
            </div>
            <div className="flex gap-1.5 text-xs text-slate-600 font-mono">
              <span className="px-1.5 py-0.5 bg-slate-100 rounded border border-slate-200">
                {applications.filter((a) => a.environment === 'production').length} Prod
              </span>
              <span className="px-1.5 py-0.5 bg-slate-100 rounded border border-slate-200">
                {applications.filter((a) => a.environment === 'staging').length} Staging
              </span>
            </div>
          </div>
          <div className="metric-footer text-xs text-slate-500">
            {applications.filter((a) => a.is_authorized).length} Certified Authorized Targets
          </div>
        </div>

        {/* Total Vulnerabilities Breakdown */}
        <div className="card metric-card metric-card-wide">
          <div className="metric-header">
            <span className="metric-title">ACTIVE VULNERABILITY EXPOSURE</span>
            <span className="text-xs font-mono text-slate-500 tabular-nums">
              {totalVulns} Total Findings
            </span>
          </div>

          {/* Fully Responsive Severity Strip - Zero text overlap */}
          <div className="vuln-severity-strip">
            <div className="severity-metric-pill bg-rose-50 border-rose-200">
              <span className="severity-metric-label text-rose-800">CRITICAL</span>
              <span className="severity-metric-value text-rose-700">
                {severityCounts.critical}
              </span>
            </div>
            <div className="severity-metric-pill bg-amber-50 border-amber-200">
              <span className="severity-metric-label text-amber-800">HIGH</span>
              <span className="severity-metric-value text-amber-700">
                {severityCounts.high}
              </span>
            </div>
            <div className="severity-metric-pill bg-yellow-50 border-yellow-200">
              <span className="severity-metric-label text-yellow-800">MEDIUM</span>
              <span className="severity-metric-value text-yellow-700">
                {severityCounts.medium}
              </span>
            </div>
            <div className="severity-metric-pill bg-emerald-50 border-emerald-200">
              <span className="severity-metric-label text-emerald-800">LOW</span>
              <span className="severity-metric-value text-emerald-700">
                {severityCounts.low}
              </span>
            </div>
            <div className="severity-metric-pill bg-slate-50 border-slate-200">
              <span className="severity-metric-label text-slate-700">INFO</span>
              <span className="severity-metric-value text-slate-600">
                {severityCounts.info}
              </span>
            </div>
          </div>

          <div className="metric-footer flex items-center justify-between text-xs text-slate-500">
            <span>
              {totalVulns > 0
                ? 'Critical & High findings require immediate remediation'
                : 'No open findings detected'}
            </span>
            <button
              type="button"
              onClick={() => onNavigateToTab('vulns')}
              className="text-slate-900 font-medium hover:underline inline-flex items-center gap-1"
            >
              Open Triage <ChevronRight size={12} />
            </button>
          </div>
        </div>
      </section>

      {/* 2. Middle Row: OWASP Top 10 Breakdown & SLA Compliance */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* OWASP Top 10 Breakdown */}
        <div className="card col-span-1 lg:col-span-2">
          <div className="card-header">
            <div>
              <h3 className="card-title">OWASP Top 10 (2021) Distribution</h3>
              <p className="card-subtitle">
                Category frequency and proportion of identified vulnerabilities
              </p>
            </div>
            <span className="text-xs font-mono text-slate-500">AST/DAST Analysis</span>
          </div>

          <div className="card-body">
            {owaspData.length === 0 ? (
              <div className="empty-state-box py-8">
                <ShieldCheck size={28} className="text-slate-300 mb-2" />
                <p className="text-slate-600 font-medium text-xs">
                  No OWASP vulnerability data available
                </p>
                <p className="text-slate-400 text-xs mt-0.5">
                  {isBackendUnreachable
                    ? 'Backend not connected — unable to reach 127.0.0.1:8000'
                    : 'Run a security assessment to populate OWASP Top 10 metrics.'}
                </p>
              </div>
            ) : (
              <div className="owasp-list">
                {owaspData.map((item, idx) => (
                  <div key={idx} className="owasp-row">
                    <div className="owasp-label-group">
                      <span className="owasp-cat-name font-mono text-xs text-slate-800">
                        {item.category}
                      </span>
                      <span className="owasp-count font-mono text-xs font-semibold text-slate-900 tabular-nums">
                        {item.count} findings ({item.percentage}%)
                      </span>
                    </div>
                    <div className="owasp-bar-track">
                      <div
                        className="owasp-bar-fill"
                        style={{ width: `${Math.min(100, Math.max(5, item.percentage))}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* SLA Compliance Widget */}
        <div className="card col-span-1">
          <div className="card-header">
            <div>
              <h3 className="card-title">Remediation SLA Compliance</h3>
              <p className="card-subtitle">Policy target tracking</p>
            </div>
            <ShieldCheck size={16} className="text-emerald-700" />
          </div>

          <div className="card-body flex flex-col justify-between">
            <div className="sla-rate-box">
              <div className="sla-rate-number font-mono tabular-nums text-slate-900">
                {sla.overall_compliance_rate.toFixed(1)}%
              </div>
              <div className="text-xs text-slate-500 font-medium">
                Overall On-Time Compliance Rate
              </div>
            </div>

            <div className="sla-breakdown-list">
              {/* Critical SLA */}
              <div className="sla-item">
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="font-semibold text-slate-800">Critical SLA (7 Days)</span>
                  <span className="font-mono tabular-nums text-slate-600">
                    {sla.critical_within_sla} On-Track / {sla.critical_breached} Breached
                  </span>
                </div>
                <div className="w-full bg-slate-100 h-1.5 rounded overflow-hidden">
                  <div
                    className="bg-rose-600 h-full"
                    style={{
                      width: `${
                        sla.critical_within_sla + sla.critical_breached > 0
                          ? (sla.critical_within_sla /
                              (sla.critical_within_sla + sla.critical_breached)) *
                            100
                          : 0
                      }%`,
                    }}
                  />
                </div>
              </div>

              {/* High SLA */}
              <div className="sla-item">
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="font-semibold text-slate-800">High SLA (14 Days)</span>
                  <span className="font-mono tabular-nums text-slate-600">
                    {sla.high_within_sla} On-Track / {sla.high_breached} Breached
                  </span>
                </div>
                <div className="w-full bg-slate-100 h-1.5 rounded overflow-hidden">
                  <div
                    className="bg-amber-600 h-full"
                    style={{
                      width: `${
                        sla.high_within_sla + sla.high_breached > 0
                          ? (sla.high_within_sla / (sla.high_within_sla + sla.high_breached)) *
                            100
                          : 0
                      }%`,
                    }}
                  />
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between text-xs">
              <span className="text-slate-500">
                {sla.critical_breached + sla.high_breached} SLA Breaches Active
              </span>
              <button
                type="button"
                onClick={() => onNavigateToTab('vulns')}
                className="text-slate-800 font-medium hover:underline inline-flex items-center gap-1"
              >
                View SLA <ChevronRight size={12} />
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* 3. Bottom Row: High Priority Findings & Recent Assessments */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Critical Unresolved Findings */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Highest Risk Unresolved Findings</h3>
              <p className="card-subtitle">Requiring immediate engineering remediation</p>
            </div>
            <button
              type="button"
              onClick={() => onNavigateToTab('vulns')}
              className="text-xs text-slate-800 font-medium hover:underline inline-flex items-center gap-1"
            >
              All Vulns <ChevronRight size={12} />
            </button>
          </div>

          <div className="card-body p-0">
            {topVulns.length === 0 ? (
              <div className="p-8 text-center text-slate-400 text-xs">
                {isBackendUnreachable
                  ? 'Backend not connected — unable to reach 127.0.0.1:8000'
                  : 'No open findings recorded. All security checks pass!'}
              </div>
            ) : (
              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Finding</th>
                      <th>CVSS</th>
                      <th>Status</th>
                      <th className="text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topVulns.map((v) => (
                      <tr key={v.id} onClick={() => onSelectVuln(v.id)} className="cursor-pointer">
                        <td>
                          <SeverityBadge severity={v.severity} size="sm" />
                        </td>
                        <td>
                          <div className="font-semibold text-slate-900 text-xs truncate max-w-xs">
                            {v.title}
                          </div>
                          <div className="font-mono text-xs text-slate-500">
                            {v.http_method} {v.normalized_path}
                          </div>
                        </td>
                        <td>
                          <span className="font-mono font-bold text-xs tabular-nums text-slate-800">
                            {v.cvss_score.toFixed(1)}
                          </span>
                        </td>
                        <td>
                          <StatusBadge status={v.status} size="sm" />
                        </td>
                        <td className="text-right">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectVuln(v.id);
                            }}
                            className="btn-text-sm"
                          >
                            Triage
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Recent Scan History */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Recent Security Assessments</h3>
              <p className="card-subtitle">Automated crawler and active fuzzing runs</p>
            </div>
            <button
              type="button"
              onClick={() => onNavigateToTab('scans')}
              className="text-xs text-slate-800 font-medium hover:underline inline-flex items-center gap-1"
            >
              All Scans <ChevronRight size={12} />
            </button>
          </div>

          <div className="card-body p-0">
            {recentScans.length === 0 ? (
              <div className="p-8 text-center text-slate-400 text-xs">
                {isBackendUnreachable
                  ? 'Backend not connected — unable to reach 127.0.0.1:8000'
                  : 'No scan history recorded. Click "Launch Scan" to start an assessment.'}
              </div>
            ) : (
              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Scan ID</th>
                      <th>Profile</th>
                      <th>Status</th>
                      <th>Findings</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentScans.slice(0, 5).map((scan) => (
                      <tr key={scan.id}>
                        <td className="font-mono text-xs text-slate-700">
                          {scan.id.substring(0, 8)}...
                        </td>
                        <td className="font-mono text-xs capitalize text-slate-600">
                          {scan.scan_type.replace(/_/g, ' ')}
                        </td>
                        <td>
                          <StatusBadge status={scan.status} size="sm" />
                        </td>
                        <td>
                          <div className="flex gap-1">
                            {scan.severity_counts?.critical > 0 && (
                              <span className="badge badge-critical-bg badge-critical-text badge-sm font-mono">
                                {scan.severity_counts.critical}C
                              </span>
                            )}
                            {scan.severity_counts?.high > 0 && (
                              <span className="badge badge-high-bg badge-high-text badge-sm font-mono">
                                {scan.severity_counts.high}H
                              </span>
                            )}
                            {scan.severity_counts?.critical === 0 &&
                              scan.severity_counts?.high === 0 && (
                                <span className="text-xs text-slate-400 font-mono">Clean</span>
                              )}
                          </div>
                        </td>
                        <td>
                          <span className="font-mono text-xs font-semibold tabular-nums text-slate-800">
                            {scan.overall_risk_score.toFixed(1)}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
};
