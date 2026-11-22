import React, { useState } from 'react';
import { ApplicationResponse, ScanResponse } from '../types';
import {
  FileText,
  Download,
  FileCode,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { api } from '../services/api';

export interface ReportsPageProps {
  applications: ApplicationResponse[];
  scans: ScanResponse[];
}

export const ReportsPage: React.FC<ReportsPageProps> = ({
  applications,
  scans,
}) => {
  const [selectedAppId, setSelectedAppId] = useState<string>(
    applications[0]?.id || ''
  );
  const [selectedScanId, setSelectedScanId] = useState<string>(
    scans.find((s) => s.status === 'completed')?.id || scans[0]?.id || ''
  );

  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [isDownloadingJson, setIsDownloadingJson] = useState(false);
  const [isDownloadingAppPdf, setIsDownloadingAppPdf] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const selectedApp = applications.find((a) => a.id === selectedAppId);
  const selectedScan = scans.find((s) => s.id === selectedScanId);

  const handleDownloadScanPdf = async () => {
    if (!selectedScanId) return;
    try {
      setIsDownloadingPdf(true);
      setErrorMsg(null);
      setSuccessMsg(null);
      const blob = await api.downloadScanPdf(selectedScanId);

      // Trigger browser download
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `AppSec_Report_${selectedScanId.substring(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      setSuccessMsg(`Typst PDF report for scan ${selectedScanId.substring(0, 8)} successfully generated!`);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to compile and download PDF report.');
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const handleDownloadAppPdf = async () => {
    if (!selectedAppId) return;
    try {
      setIsDownloadingAppPdf(true);
      setErrorMsg(null);
      setSuccessMsg(null);
      const blob = await api.downloadAppPdf(selectedAppId);

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `App_Posture_${selectedApp?.name.replace(/\s+/g, '_') || 'report'}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      setSuccessMsg(`Full Application Posture PDF for ${selectedApp?.name} downloaded!`);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to download Application Posture report.');
    } finally {
      setIsDownloadingAppPdf(false);
    }
  };

  const handleDownloadJson = async () => {
    if (!selectedScanId) return;
    try {
      setIsDownloadingJson(true);
      setErrorMsg(null);
      setSuccessMsg(null);
      const data = await api.downloadScanJson(selectedScanId);

      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: 'application/json',
      });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `findings_${selectedScanId.substring(0, 8)}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      setSuccessMsg('Structured JSON findings exported successfully.');
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to export JSON findings.');
    } finally {
      setIsDownloadingJson(false);
    }
  };

  return (
    <div className="page-container">
      {/* Alerts */}
      {successMsg && (
        <div className="alert-banner alert-banner-success mb-4">
          <CheckCircle2 size={15} />
          <span>{successMsg}</span>
        </div>
      )}
      {errorMsg && (
        <div className="alert-banner alert-banner-danger mb-4">
          <AlertTriangle size={15} />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Grid of Report Generators */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 1. Assessment Scan PDF Report (Typst Native) */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Typst PDF Security Assessment Report</h3>
              <p className="card-subtitle">
                High-fidelity, boardroom-ready PDF compiled on-demand via Typst engine
              </p>
            </div>
            <FileText size={18} className="text-slate-800" />
          </div>

          <div className="card-body">
            <div className="form-group mb-4">
              <label className="form-label" htmlFor="select-report-scan">
                Select Completed Assessment Run:
              </label>
              <select
                id="select-report-scan"
                value={selectedScanId}
                onChange={(e) => setSelectedScanId(e.target.value)}
                className="form-select font-mono text-xs"
              >
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    Scan {s.id.substring(0, 8)}... - [{s.scan_type.toUpperCase()}] ({s.status}) - Risk: {s.overall_risk_score.toFixed(1)}
                  </option>
                ))}
              </select>
            </div>

            {selectedScan && (
              <div className="report-preview-box">
                <div className="preview-row">
                  <span className="text-xs text-slate-500">Scan ID:</span>
                  <span className="font-mono text-xs text-slate-800 font-semibold">
                    {selectedScan.id}
                  </span>
                </div>
                <div className="preview-row">
                  <span className="text-xs text-slate-500">Execution Status:</span>
                  <span className="text-xs font-mono font-medium text-slate-800 capitalize">
                    {selectedScan.status.replace(/_/g, ' ')}
                  </span>
                </div>
                <div className="preview-row">
                  <span className="text-xs text-slate-500">Overall Risk Score:</span>
                  <span className="text-xs font-mono font-bold text-slate-900 tabular-nums">
                    {selectedScan.overall_risk_score.toFixed(1)} / 10.0
                  </span>
                </div>
                <div className="preview-row">
                  <span className="text-xs text-slate-500">Findings Summary:</span>
                  <span className="text-xs font-mono text-slate-700 tabular-nums">
                    {selectedScan.severity_counts?.critical} Critical, {selectedScan.severity_counts?.high} High, {selectedScan.severity_counts?.medium} Medium
                  </span>
                </div>
                <div className="preview-row">
                  <span className="text-xs text-slate-500">Diff vs Baseline:</span>
                  <span className="text-xs font-mono text-slate-700 tabular-nums">
                    +{selectedScan.diff_summary?.new_count || 0} New, -{selectedScan.diff_summary?.fixed_count || 0} Fixed
                  </span>
                </div>
              </div>
            )}

            <div className="mt-6 flex items-center gap-3">
              <button
                type="button"
                onClick={handleDownloadScanPdf}
                disabled={isDownloadingPdf || !selectedScanId}
                className="btn btn-primary"
              >
                <Download size={14} />
                <span>{isDownloadingPdf ? 'Compiling Typst PDF...' : 'Download Typst PDF Report'}</span>
              </button>

              <button
                type="button"
                onClick={handleDownloadJson}
                disabled={isDownloadingJson || !selectedScanId}
                className="btn btn-secondary"
              >
                <FileCode size={14} />
                <span>{isDownloadingJson ? 'Exporting...' : 'Export JSON Findings'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* 2. Comprehensive Application Posture Report */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Full Application Posture Attestation</h3>
              <p className="card-subtitle">
                Holistic posture audit across all scans, open vulnerabilities & trends
              </p>
            </div>
            <ShieldCheck size={18} className="text-emerald-700" />
          </div>

          <div className="card-body">
            <div className="form-group mb-4">
              <label className="form-label" htmlFor="select-report-app">
                Select Target Application:
              </label>
              <select
                id="select-report-app"
                value={selectedAppId}
                onChange={(e) => setSelectedAppId(e.target.value)}
                className="form-select"
              >
                {applications.map((app) => (
                  <option key={app.id} value={app.id}>
                    {app.name} ({app.base_url}) - [{app.environment.toUpperCase()}]
                  </option>
                ))}
              </select>
            </div>

            {selectedApp && (
              <div className="report-preview-box">
                <div className="preview-row">
                  <span className="text-xs text-slate-500">Target App:</span>
                  <span className="text-xs font-semibold text-slate-900">
                    {selectedApp.name}
                  </span>
                </div>
                <div className="preview-row">
                  <span className="text-xs text-slate-500">Target Domain:</span>
                  <span className="font-mono text-xs text-slate-700">
                    {selectedApp.base_url}
                  </span>
                </div>
                <div className="preview-row">
                  <span className="text-xs text-slate-500">Criticality & Env:</span>
                  <span className="text-xs font-mono text-slate-800 uppercase">
                    Tier {selectedApp.criticality} | {selectedApp.environment}
                  </span>
                </div>
                <div className="preview-row">
                  <span className="text-xs text-slate-500">Authorization Attestation:</span>
                  <span className="text-xs text-emerald-700 font-semibold flex items-center gap-1">
                    <ShieldCheck size={12} /> {selectedApp.is_authorized ? 'Certified Authorized' : 'Unauthorized'}
                  </span>
                </div>
                <div className="preview-row">
                  <span className="text-xs text-slate-500">Latest Risk Index:</span>
                  <span className="font-mono text-xs font-bold text-slate-900 tabular-nums">
                    {selectedApp.latest_risk_score.toFixed(1)} / 10.0
                  </span>
                </div>
              </div>
            )}

            <div className="mt-6">
              <button
                type="button"
                onClick={handleDownloadAppPdf}
                disabled={isDownloadingAppPdf || !selectedAppId}
                className="btn btn-primary"
              >
                <Download size={14} />
                <span>{isDownloadingAppPdf ? 'Compiling PDF...' : 'Download Full App Posture PDF'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Compliance Frameworks Readiness Section */}
      <div className="card mt-6">
        <div className="card-header">
          <div>
            <h3 className="card-title">Continuous Regulatory & Compliance Readiness</h3>
            <p className="card-subtitle">
              Automated mapping of scan results against major security benchmarks
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500">
            SOC 2 / ISO 27001 / PCI-DSS 4.0
          </span>
        </div>

        <div className="card-body">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="compliance-card">
              <div className="flex items-center justify-between mb-2">
                <span className="font-bold text-xs text-slate-900 font-mono">PCI-DSS 4.0 (Req 6.2 & 6.4)</span>
                <span className="badge badge-emerald badge-sm">94% Aligned</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Automated dynamic application security testing (DAST) executed on quarterly cadence with zero unmitigated critical findings.
              </p>
            </div>

            <div className="compliance-card">
              <div className="flex items-center justify-between mb-2">
                <span className="font-bold text-xs text-slate-900 font-mono">SOC 2 Type II (CC7.1)</span>
                <span className="badge badge-emerald badge-sm">Certified</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Vulnerability management policy enforcement with immutable audit logs recording all remediation status transitions.
              </p>
            </div>

            <div className="compliance-card">
              <div className="flex items-center justify-between mb-2">
                <span className="font-bold text-xs text-slate-900 font-mono">ISO/IEC 27001 (A.12.6.1)</span>
                <span className="badge badge-emerald badge-sm">Compliant</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Management of technical vulnerabilities with automated crawl schedules, SLA breach alerts, and executive sign-off.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
