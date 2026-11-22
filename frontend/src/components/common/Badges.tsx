import React from 'react';
import {
  AppCriticality,
  AppEnvironment,
  DiffClassification,
  RemediationStatus,
  ScanStatus,
  SeverityLevel,
} from '../../types';
import {
  ShieldAlert,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  Clock,
  Activity,
  ShieldCheck,
  RotateCcw,
  PlusCircle,
  MinusCircle,
  HelpCircle,
} from 'lucide-react';

export interface SeverityBadgeProps {
  severity: SeverityLevel;
  showIcon?: boolean;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  showIcon = true,
  size = 'md',
}) => {
  const norm = (severity || 'info').toLowerCase() as SeverityLevel;

  const config: Record<
    SeverityLevel,
    { label: string; bg: string; text: string; border: string; icon: React.ReactNode }
  > = {
    critical: {
      label: 'Critical',
      bg: 'badge-critical-bg',
      text: 'badge-critical-text',
      border: 'badge-critical-border',
      icon: <ShieldAlert className="badge-icon" size={size === 'sm' ? 12 : 13} />,
    },
    high: {
      label: 'High',
      bg: 'badge-high-bg',
      text: 'badge-high-text',
      border: 'badge-high-border',
      icon: <AlertTriangle className="badge-icon" size={size === 'sm' ? 12 : 13} />,
    },
    medium: {
      label: 'Medium',
      bg: 'badge-medium-bg',
      text: 'badge-medium-text',
      border: 'badge-medium-border',
      icon: <AlertTriangle className="badge-icon" size={size === 'sm' ? 12 : 13} />,
    },
    low: {
      label: 'Low',
      bg: 'badge-low-bg',
      text: 'badge-low-text',
      border: 'badge-low-border',
      icon: <Info className="badge-icon" size={size === 'sm' ? 12 : 13} />,
    },
    info: {
      label: 'Info',
      bg: 'badge-info-bg',
      text: 'badge-info-text',
      border: 'badge-info-border',
      icon: <Info className="badge-icon" size={size === 'sm' ? 12 : 13} />,
    },
  };

  const item = config[norm] || config.info;
  const sizeClass = size === 'sm' ? 'badge-sm' : 'badge-md';

  return (
    <span className={`badge ${item.bg} ${item.text} ${item.border} ${sizeClass}`}>
      {showIcon && item.icon}
      <span className="badge-label">{item.label}</span>
    </span>
  );
};

export interface StatusBadgeProps {
  status: RemediationStatus | ScanStatus | string;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md' }) => {
  const norm = (status || '').toLowerCase();

  let label = norm.replace(/_/g, ' ');
  let className = 'badge-slate';
  let icon: React.ReactNode = <Clock size={12} />;

  switch (norm) {
    case 'open':
      label = 'Open';
      className = 'badge-rose';
      icon = <AlertTriangle size={12} />;
      break;
    case 'in_progress':
      label = 'In Progress';
      className = 'badge-amber';
      icon = <Activity size={12} />;
      break;
    case 'false_positive':
      label = 'False Positive';
      className = 'badge-slate';
      icon = <HelpCircle size={12} />;
      break;
    case 'risk_accepted':
      label = 'Risk Accepted';
      className = 'badge-yellow';
      icon = <ShieldCheck size={12} />;
      break;
    case 'resolved':
      label = 'Resolved';
      className = 'badge-emerald';
      icon = <CheckCircle2 size={12} />;
      break;
    case 'verified_fixed':
      label = 'Verified Fixed';
      className = 'badge-emerald';
      icon = <CheckCircle2 size={12} />;
      break;
    case 'regressed':
      label = 'Regressed';
      className = 'badge-rose';
      icon = <RotateCcw size={12} />;
      break;
    case 'queued':
      label = 'Queued';
      className = 'badge-slate';
      icon = <Clock size={12} />;
      break;
    case 'spidering':
      label = 'Spidering';
      className = 'badge-blue';
      icon = <Activity className="animate-spin-slow" size={12} />;
      break;
    case 'active_scanning':
      label = 'Active Scanning';
      className = 'badge-indigo';
      icon = <Activity className="animate-pulse" size={12} />;
      break;
    case 'ingesting':
      label = 'Ingesting';
      className = 'badge-blue';
      icon = <Activity size={12} />;
      break;
    case 'completed':
      label = 'Completed';
      className = 'badge-emerald';
      icon = <CheckCircle2 size={12} />;
      break;
    case 'failed':
      label = 'Failed';
      className = 'badge-rose';
      icon = <XCircle size={12} />;
      break;
    case 'cancelled':
      label = 'Cancelled';
      className = 'badge-slate';
      icon = <XCircle size={12} />;
      break;
  }

  const sizeClass = size === 'sm' ? 'badge-sm' : 'badge-md';

  return (
    <span className={`badge ${className} ${sizeClass}`}>
      {icon}
      <span className="badge-label">{label}</span>
    </span>
  );
};

export interface DiffBadgeProps {
  state: DiffClassification | 'fixed' | string;
  size?: 'sm' | 'md';
}

export const DiffBadge: React.FC<DiffBadgeProps> = ({ state, size = 'md' }) => {
  const norm = (state || '').toLowerCase();
  let label = norm.toUpperCase();
  let className = 'badge-slate';
  let icon = null;

  switch (norm) {
    case 'new':
      label = 'NEW';
      className = 'badge-rose';
      icon = <PlusCircle size={11} />;
      break;
    case 'persistent':
      label = 'PERSISTENT';
      className = 'badge-slate';
      icon = <Clock size={11} />;
      break;
    case 'fixed':
      label = 'FIXED';
      className = 'badge-emerald';
      icon = <MinusCircle size={11} />;
      break;
    case 'regressed':
      label = 'REGRESSED';
      className = 'badge-amber';
      icon = <RotateCcw size={11} />;
      break;
  }

  const sizeClass = size === 'sm' ? 'badge-sm' : 'badge-md';
  return (
    <span className={`badge ${className} ${sizeClass} font-mono font-medium tracking-wide`}>
      {icon}
      <span>{label}</span>
    </span>
  );
};

export interface AuthBadgeProps {
  isAuthorized: boolean;
  size?: 'sm' | 'md';
}

export const AuthBadge: React.FC<AuthBadgeProps> = ({ isAuthorized, size = 'md' }) => {
  const sizeClass = size === 'sm' ? 'badge-sm' : 'badge-md';
  if (isAuthorized) {
    return (
      <span className={`badge badge-emerald ${sizeClass}`}>
        <ShieldCheck size={12} />
        <span>Authorized</span>
      </span>
    );
  }
  return (
    <span className={`badge badge-rose ${sizeClass}`}>
      <ShieldAlert size={12} />
      <span>Unauthorized</span>
    </span>
  );
};

export interface EnvironmentBadgeProps {
  environment: AppEnvironment | string;
  size?: 'sm' | 'md';
}

export const EnvironmentBadge: React.FC<EnvironmentBadgeProps> = ({ environment, size = 'md' }) => {
  const env = (environment || '').toLowerCase();
  let className = 'badge-slate';
  switch (env) {
    case 'production':
      className = 'badge-rose-soft';
      break;
    case 'staging':
      className = 'badge-amber-soft';
      break;
    case 'development':
      className = 'badge-blue-soft';
      break;
    case 'qa':
      className = 'badge-purple-soft';
      break;
  }
  const sizeClass = size === 'sm' ? 'badge-sm' : 'badge-md';
  return (
    <span className={`badge ${className} ${sizeClass} font-mono uppercase text-xs`}>
      <span>{env}</span>
    </span>
  );
};

export interface CriticalityBadgeProps {
  criticality: AppCriticality | string;
  size?: 'sm' | 'md';
}

export const CriticalityBadge: React.FC<CriticalityBadgeProps> = ({ criticality, size = 'md' }) => {
  const crit = (criticality || '').toLowerCase();
  let className = 'badge-slate';
  switch (crit) {
    case 'critical':
      className = 'badge-critical-bg badge-critical-text badge-critical-border';
      break;
    case 'high':
      className = 'badge-high-bg badge-high-text badge-high-border';
      break;
    case 'medium':
      className = 'badge-medium-bg badge-medium-text badge-medium-border';
      break;
    case 'low':
      className = 'badge-low-bg badge-low-text badge-low-border';
      break;
  }
  const sizeClass = size === 'sm' ? 'badge-sm' : 'badge-md';
  return (
    <span className={`badge ${className} ${sizeClass} capitalize`}>
      <span>{crit}</span>
    </span>
  );
};

