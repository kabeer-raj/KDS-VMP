import React, { useState } from 'react';
import { ApplicationResponse, ConfigureAuthRequest } from '../../types';
import { X, Lock, Key, AlertCircle } from 'lucide-react';

export interface ConfigureAuthModalProps {
  isOpen: boolean;
  application: ApplicationResponse | null;
  onClose: () => void;
  onSubmit: (appId: string, config: ConfigureAuthRequest) => Promise<void>;
}

export const ConfigureAuthModal: React.FC<ConfigureAuthModalProps> = ({
  isOpen,
  application,
  onClose,
  onSubmit,
}) => {
  const [authType, setAuthType] = useState('bearer_token');
  const [token, setToken] = useState('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.kds_sample_token');
  const [headerName, setHeaderName] = useState('Authorization');
  const [headerValue, setHeaderValue] = useState('Bearer eyJhbGci...');
  const [cookieHeader, setCookieHeader] = useState('session_id=kds_sess_9a8b7c6d5e; path=/;');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen || !application) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    let authData: Record<string, unknown> = {};
    if (authType === 'bearer_token') {
      authData = { token: token.trim() };
    } else if (authType === 'custom_headers') {
      authData = { headers: { [headerName.trim()]: headerValue.trim() } };
    } else if (authType === 'cookie_session') {
      authData = { cookie: cookieHeader.trim() };
    } else {
      authData = { type: authType, raw: token.trim() };
    }

    try {
      setIsSubmitting(true);
      await onSubmit(application.id, {
        auth_type: authType,
        auth_data: authData,
      });
      onClose();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to update authentication profile.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-container modal-md">
        <div className="modal-header">
          <div className="modal-title-wrapper">
            <Lock size={18} className="text-slate-800" />
            <h2 className="modal-title">Configure Scanner Authentication</h2>
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

        <form onSubmit={handleSubmit} className="modal-body-form">
          <div className="target-context-box">
            <span className="text-xs text-slate-500">Target Application:</span>
            <div className="font-semibold text-slate-900">{application.name}</div>
            <div className="text-xs font-mono text-slate-600">{application.base_url}</div>
          </div>

          {errorMsg && (
            <div className="alert-banner alert-banner-danger">
              <AlertCircle size={15} />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="form-group">
            <label className="form-label" htmlFor="auth-scheme">
              Authentication Scheme
            </label>
            <select
              id="auth-scheme"
              value={authType}
              onChange={(e) => setAuthType(e.target.value)}
              className="form-select"
            >
              <option value="bearer_token">Bearer Token (JWT / OAuth2)</option>
              <option value="cookie_session">Session Cookie Injection</option>
              <option value="custom_headers">Custom Header (API Key / HMAC)</option>
              <option value="basic_auth">HTTP Basic Authentication</option>
            </select>
          </div>

          {authType === 'bearer_token' && (
            <div className="form-group">
              <label className="form-label" htmlFor="bearer-token">
                Bearer Token (JWT payload)
              </label>
              <textarea
                id="bearer-token"
                rows={3}
                required
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="eyJhbGciOiJIUzI1NiIs..."
                className="form-textarea font-mono text-xs"
              />
              <span className="form-help">
                Token will be injected as <code>Authorization: Bearer &lt;token&gt;</code> on all crawler and attack requests.
              </span>
            </div>
          )}

          {authType === 'cookie_session' && (
            <div className="form-group">
              <label className="form-label" htmlFor="cookie-header">
                Cookie String
              </label>
              <textarea
                id="cookie-header"
                rows={2}
                required
                value={cookieHeader}
                onChange={(e) => setCookieHeader(e.target.value)}
                placeholder="sessionid=abc123xyz; secure; HttpOnly"
                className="form-textarea font-mono text-xs"
              />
            </div>
          )}

          {authType === 'custom_headers' && (
            <div className="form-grid">
              <div className="form-group col-span-1">
                <label className="form-label" htmlFor="hdr-name">
                  Header Name
                </label>
                <input
                  id="hdr-name"
                  type="text"
                  required
                  value={headerName}
                  onChange={(e) => setHeaderName(e.target.value)}
                  placeholder="X-API-Key"
                  className="form-input font-mono text-xs"
                />
              </div>
              <div className="form-group col-span-1">
                <label className="form-label" htmlFor="hdr-val">
                  Header Value
                </label>
                <input
                  id="hdr-val"
                  type="text"
                  required
                  value={headerValue}
                  onChange={(e) => setHeaderValue(e.target.value)}
                  placeholder="live_sec_key_..."
                  className="form-input font-mono text-xs"
                />
              </div>
            </div>
          )}

          <div className="notice-box">
            <Lock size={14} className="text-slate-600 mt-0.5" />
            <span className="text-xs text-slate-600">
              Authentication credentials are encrypted using AES-256-GCM before dispatch to the scanner worker.
            </span>
          </div>

          <div className="modal-footer">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="btn btn-secondary"
            >
              Cancel
            </button>
            <button type="submit" disabled={isSubmitting} className="btn btn-primary">
              <Key size={14} />
              <span>{isSubmitting ? 'Saving...' : 'Save Configuration'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
