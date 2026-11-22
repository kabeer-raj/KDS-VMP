import React, { useState, useEffect } from 'react';
import {
  ScanComparisonResponse,
  ScanResponse,
} from '../../types';
import {
  X,
  GitCompare,
  TrendingDown,
  TrendingUp,
  PlusCircle,
  MinusCircle,
  Clock,
  RotateCcw,
  AlertTriangle,
  ArrowRight,
} from 'lucide-react';
import { api } from '../../services/api';

export interface DiffViewModalProps {
  isOpen: boolean;
  onClose: () => void;
  scans: ScanResponse[];
  initialBaseId?: string;
  initialTargetId?: string;
  onSelectVuln?: (vulnId: string) => void;
}

export const DiffViewModal: React.FC<DiffViewModalProps> = ({
  isOpen,
  onClose,
  scans,
  initialBaseId,
  initialTargetId,
}) => {
  const [baseScanId, setBaseScanId] = useState<string>(initialBaseId || (scans[1]?.id ?? scans[0]?.id ?? ''));
  const [targetScanId, setTargetScanId] = useState<string>(initialTargetId || (scans[0]?.id ?? ''));
  const [comparison, setComparison] = useState<ScanComparisonResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && baseScanId && targetScanId) {
      handleCompare();
    }
  }, [isOpen, baseScanId, targetScanId]);

  const handleCompare = async () => {
    if (!baseScanId || !targetScanId) return;
    try {
      setIsLoading(true);
      setErrorMsg(null);
      const res = await api.compareScans(baseScanId, targetScanId);
      setComparison(res);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to compare scans');
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  const diff = comparison?.diff_summary;
  const isRiskImproved = diff ? diff.risk_score_delta <= 0 : true;

  return (
    <div className="modal-backdrop">
      <div className="modal-container modal-xl">
        {/* Header */}
        <div className="modal-header">
          <div className="modal-title-wrapper">
            <GitCompare size={18} className="text-slate-900" />
            <h2 className="modal-title">Differential Security Analysis (Scan N vs N-1)</h2>
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

        {/* Scan Selector Bar */}
        <div className="diff-selector-bar">
          <div className="diff-select-group">
            <span className="diff-select-label">Base Scan (N-1 Baseline):</span>
            <select
              value={baseScanId}
              onChange={(e) => setBaseScanId(e.target.value)}
              className="form-select form-select-sm font-mono text-xs"
            >
              {scans.map((s, idx) => (
                <option key={s.id} value={s.id}>
                  Scan #{scans.length - idx}: {s.id.substring(0, 8)}... ({new Date(s.started_at || '').toLocaleDateString()}) - Risk {s.overall_risk_score.toFixed(1)}
                </option>
              ))}
            </select>
          </div>

          <div className="diff-arrow">
            <ArrowRight size={18} className="text-slate-400" />
          </div>

          <div className="diff-select-group">
            <span className="diff-select-label">Target Scan (N Current):</span>
            <select
              value={targetScanId}
              onChange={(e) => setTargetScanId(e.target.value)}
              className="form-select form-select-sm font-mono text-xs"
            >
              {scans.map((s, idx) => (
                <option key={s.id} value={s.id}>
                  Scan #{scans.length - idx}: {s.id.substring(0, 8)}... ({new Date(s.started_at || '').toLocaleDateString()}) - Risk {s.overall_risk_score.toFixed(1)}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Modal Body */}
        <div className="modal-body-scroll">
          {errorMsg && (
            <div className="alert-banner alert-banner-danger mb-4">
              <AlertTriangle size={15} />
              <span>{errorMsg}</span>
            </div>
          )}

          {isLoading ? (
            <div className="py-12 text-center text-slate-500 text-sm">
              Calculating differential AST & vulnerability signatures...
            </div>
          ) : diff ? (
            <div className="diff-results-stack">
              {/* Diff Metric Cards */}
              <div className="diff-cards-grid">
                {/* New Findings */}
                <div className="diff-metric-card border-rose-200 bg-rose-50/50">
                  <div className="diff-card-header">
                    <span className="text-xs font-semibold text-rose-800 flex items-center gap-1.5">
                      <PlusCircle size={14} className="text-rose-600" />
                      NEW VULNERABILITIES
                    </span>
                  </div>
                  <div className="diff-card-value text-rose-700 font-mono tabular-nums">
                    +{diff.new_count}
                  </div>
                  <div className="diff-card-desc text-rose-600">
                    Discovered for the first time in target scan
                  </div>
                </div>

                {/* Fixed Findings */}
                <div className="diff-metric-card border-emerald-200 bg-emerald-50/50">
                  <div className="diff-card-header">
                    <span className="text-xs font-semibold text-emerald-800 flex items-center gap-1.5">
                      <MinusCircle size={14} className="text-emerald-600" />
                      REMEDIATED / FIXED
                    </span>
                  </div>
                  <div className="diff-card-value text-emerald-700 font-mono tabular-nums">
                    -{diff.fixed_count}
                  </div>
                  <div className="diff-card-desc text-emerald-600">
                    No longer detected on target endpoints
                  </div>
                </div>

                {/* Persistent Findings */}
                <div className="diff-metric-card border-slate-200 bg-slate-50">
                  <div className="diff-card-header">
                    <span className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                      <Clock size={14} className="text-slate-500" />
                      PERSISTENT
                    </span>
                  </div>
                  <div className="diff-card-value text-slate-800 font-mono tabular-nums">
                    {diff.persistent_count}
                  </div>
                  <div className="diff-card-desc text-slate-500">
                    Ongoing unresolved vulnerabilities
                  </div>
                </div>

                {/* Regressed Findings */}
                <div className="diff-metric-card border-amber-200 bg-amber-50/50">
                  <div className="diff-card-header">
                    <span className="text-xs font-semibold text-amber-800 flex items-center gap-1.5">
                      <RotateCcw size={14} className="text-amber-600" />
                      REGRESSED
                    </span>
                  </div>
                  <div className="diff-card-value text-amber-700 font-mono tabular-nums">
                    +{diff.regressed_count}
                  </div>
                  <div className="diff-card-desc text-amber-600">
                    Previously resolved but reintroduced
                  </div>
                </div>

                {/* Risk Delta */}
                <div
                  className={`diff-metric-card ${
                    isRiskImproved
                      ? 'border-emerald-200 bg-emerald-50/30'
                      : 'border-rose-200 bg-rose-50/30'
                  }`}
                >
                  <div className="diff-card-header">
                    <span
                      className={`text-xs font-semibold flex items-center gap-1.5 ${
                        isRiskImproved ? 'text-emerald-800' : 'text-rose-800'
                      }`}
                    >
                      {isRiskImproved ? (
                        <TrendingDown size={14} className="text-emerald-600" />
                      ) : (
                        <TrendingUp size={14} className="text-rose-600" />
                      )}
                      RISK SCORE DELTA
                    </span>
                  </div>
                  <div
                    className={`diff-card-value font-mono tabular-nums ${
                      isRiskImproved ? 'text-emerald-700' : 'text-rose-700'
                    }`}
                  >
                    {diff.risk_score_delta > 0
                      ? `+${diff.risk_score_delta.toFixed(1)}`
                      : diff.risk_score_delta.toFixed(1)}
                  </div>
                  <div
                    className={`diff-card-desc ${
                      isRiskImproved ? 'text-emerald-600' : 'text-rose-600'
                    }`}
                  >
                    {isRiskImproved
                      ? 'Posture improved since baseline'
                      : 'Posture deteriorated due to new flaws'}
                  </div>
                </div>
              </div>

              {/* Explanatory summary text */}
              <div className="diff-summary-banner">
                <div className="text-xs text-slate-700 leading-relaxed">
                  Compared baseline scan <code>{baseScanId.substring(0, 8)}</code> against target scan{' '}
                  <code>{targetScanId.substring(0, 8)}</code>. The differential engine identified{' '}
                  <strong>{diff.new_count} new vulnerabilities</strong>, while confirming that{' '}
                  <strong>{diff.fixed_count} findings were verified fixed</strong>.{' '}
                  {diff.regressed_count > 0 && (
                    <span className="text-amber-800 font-medium">
                      Notice: {diff.regressed_count} findings regressed back into open state.
                    </span>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-slate-400 text-sm">
              Select two scans above to evaluate regression diff.
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="modal-footer">
          <button type="button" onClick={onClose} className="btn btn-secondary">
            Close Diff View
          </button>
        </div>
      </div>
    </div>
  );
};
