import React, { useState } from 'react';
import { CreateApplicationRequest, AppEnvironment, AppCriticality } from '../../types';
import { X, ShieldCheck, AlertTriangle, Globe } from 'lucide-react';

export interface RegisterAppModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (appData: CreateApplicationRequest) => Promise<void>;
}

export const RegisterAppModal: React.FC<RegisterAppModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
}) => {
  const [name, setName] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [description, setDescription] = useState('');
  const [environment, setEnvironment] = useState<AppEnvironment>('production');
  const [criticality, setCriticality] = useState<AppCriticality>('high');
  const [teamName, setTeamName] = useState('SecOps Core');
  const [includeRegexes, setIncludeRegexes] = useState('^https://.*');
  const [excludeRegexes, setExcludeRegexes] = useState('.*/logout$, .*/delete$');
  const [cronSchedule, setCronSchedule] = useState('0 2 * * 1'); // Weekly Monday 2 AM
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (!baseUrl.trim()) {
      setErrorMsg('Target Base URL is required.');
      return;
    }

    if (!isAuthorized) {
      setErrorMsg('You must certify explicit scanning authorization before registering this target.');
      return;
    }

    try {
      setIsSubmitting(true);
      const includes = includeRegexes
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean);
      const excludes = excludeRegexes
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean);

      await onSubmit({
        name: name.trim(),
        base_url: baseUrl.trim(),
        description: description.trim() || undefined,
        environment,
        criticality,
        team_name: teamName.trim() || undefined,
        include_regexes: includes.length ? includes : undefined,
        exclude_regexes: excludes.length ? excludes : undefined,
        cron_schedule: cronSchedule.trim() || undefined,
        is_authorized: true,
      });

      onClose();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to register target application.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-container modal-lg">
        {/* Modal Header */}
        <div className="modal-header">
          <div className="modal-title-wrapper">
            <Globe size={18} className="text-slate-800" />
            <h2 className="modal-title">Register Target Web Application</h2>
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

        {/* Modal Body */}
        <form onSubmit={handleSubmit} className="modal-body-form">
          {errorMsg && (
            <div className="alert-banner alert-banner-danger">
              <AlertTriangle size={15} />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="form-grid">
            {/* App Name */}
            <div className="form-group col-span-1">
              <label className="form-label" htmlFor="app-name">
                Application Name <span className="text-rose-500">*</span>
              </label>
              <input
                id="app-name"
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g., Customer Portal API"
                className="form-input"
              />
            </div>

            {/* Target URL */}
            <div className="form-group col-span-1">
              <label className="form-label" htmlFor="app-url">
                Base URL <span className="text-rose-500">*</span>
              </label>
              <input
                id="app-url"
                type="url"
                required
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="https://app.corp.internal"
                className="form-input font-mono text-xs"
              />
            </div>

            {/* Environment */}
            <div className="form-group col-span-1">
              <label className="form-label" htmlFor="app-env">
                Environment
              </label>
              <select
                id="app-env"
                value={environment}
                onChange={(e) => setEnvironment(e.target.value as AppEnvironment)}
                className="form-select"
              >
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
                <option value="qa">QA</option>
              </select>
            </div>

            {/* Criticality */}
            <div className="form-group col-span-1">
              <label className="form-label" htmlFor="app-crit">
                Business Criticality
              </label>
              <select
                id="app-crit"
                value={criticality}
                onChange={(e) => setCriticality(e.target.value as AppCriticality)}
                className="form-select"
              >
                <option value="critical">Tier 1 - Critical</option>
                <option value="high">Tier 2 - High</option>
                <option value="medium">Tier 3 - Medium</option>
                <option value="low">Tier 4 - Low</option>
              </select>
            </div>

            {/* Team Name */}
            <div className="form-group col-span-2">
              <label className="form-label" htmlFor="app-team">
                Owning Engineering Team
              </label>
              <input
                id="app-team"
                type="text"
                value={teamName}
                onChange={(e) => setTeamName(e.target.value)}
                placeholder="SecOps, Payments Core, Growth SRE"
                className="form-input"
              />
            </div>

            {/* Description */}
            <div className="form-group col-span-2">
              <label className="form-label" htmlFor="app-desc">
                Description
              </label>
              <textarea
                id="app-desc"
                rows={2}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Target architecture overview, sensitive endpoints, or notes..."
                className="form-textarea"
              />
            </div>

            {/* Scope Include Regexes */}
            <div className="form-group col-span-1">
              <label className="form-label" htmlFor="app-includes">
                In-Scope URL Regexes (one per line)
              </label>
              <textarea
                id="app-includes"
                rows={2}
                value={includeRegexes}
                onChange={(e) => setIncludeRegexes(e.target.value)}
                placeholder="^https://api\.corp\.internal/v1/.*"
                className="form-textarea font-mono text-xs"
              />
            </div>

            {/* Scope Exclude Regexes */}
            <div className="form-group col-span-1">
              <label className="form-label" htmlFor="app-excludes">
                Out-of-Scope Regexes (Blacklist / Destructive)
              </label>
              <textarea
                id="app-excludes"
                rows={2}
                value={excludeRegexes}
                onChange={(e) => setExcludeRegexes(e.target.value)}
                placeholder=".*/logout$, .*/reset-db$"
                className="form-textarea font-mono text-xs"
              />
            </div>

            {/* Cron Schedule */}
            <div className="form-group col-span-2">
              <label className="form-label" htmlFor="app-cron">
                Automated Cadence (Cron Expression)
              </label>
              <input
                id="app-cron"
                type="text"
                value={cronSchedule}
                onChange={(e) => setCronSchedule(e.target.value)}
                placeholder="0 2 * * 1 (Weekly on Monday 02:00 UTC)"
                className="form-input font-mono text-xs"
              />
            </div>
          </div>

          {/* Explicit Authorization Flag Checkbox */}
          <div className="authorization-cert-box">
            <div className="flex items-start gap-3">
              <input
                type="checkbox"
                id="auth-cert-check"
                checked={isAuthorized}
                onChange={(e) => setIsAuthorized(e.target.checked)}
                className="auth-checkbox mt-1"
              />
              <label htmlFor="auth-cert-check" className="auth-cert-label">
                <span className="font-semibold text-slate-900 block mb-1 flex items-center gap-1.5">
                  <ShieldCheck size={16} className="text-emerald-700" />
                  Explicit Authorization Certification (RFC-Compliance & Rules of Engagement)
                </span>
                <span className="text-xs text-slate-600 leading-relaxed block">
                  I certify and attest that I possess explicit, written authorization from the system owner to perform active security scans, payload injection, and crawler spidering against this target. Unauthorized testing without explicit permission is strictly prohibited.
                </span>
              </label>
            </div>
          </div>

          {/* Modal Actions */}
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
              disabled={isSubmitting || !isAuthorized}
              className="btn btn-primary"
            >
              <ShieldCheck size={14} />
              <span>{isSubmitting ? 'Registering...' : 'Register Application'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
