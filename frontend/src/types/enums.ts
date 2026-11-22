/**
 * Core Enums matching backend/crates/shared-types/src/enums.rs
 * and docs/api_routes_dto_schemas_specification.txt
 */

export type UserRole =
  | 'admin'
  | 'security_engineer'
  | 'developer'
  | 'auditor';

export type AppEnvironment =
  | 'production'
  | 'staging'
  | 'development'
  | 'qa';

export type AppCriticality =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low';

export type ScanType =
  | 'baseline_passive'
  | 'full_active'
  | 'api_openapi'
  | 'spa_ajax';

export type ScanStatus =
  | 'queued'
  | 'spidering'
  | 'active_scanning'
  | 'ingesting'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type SeverityLevel =
  | 'info'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical';

export type RemediationStatus =
  | 'open'
  | 'in_progress'
  | 'false_positive'
  | 'risk_accepted'
  | 'resolved'
  | 'verified_fixed'
  | 'regressed';

export type DiffClassification =
  | 'new'
  | 'persistent'
  | 'regressed';

/**
 * Display labels and ordering helpers for UI rendering
 */
export const USER_ROLES: readonly UserRole[] = [
  'admin',
  'security_engineer',
  'developer',
  'auditor',
] as const;

export const APP_ENVIRONMENTS: readonly AppEnvironment[] = [
  'production',
  'staging',
  'development',
  'qa',
] as const;

export const APP_CRITICALITIES: readonly AppCriticality[] = [
  'critical',
  'high',
  'medium',
  'low',
] as const;

export const SCAN_TYPES: readonly ScanType[] = [
  'baseline_passive',
  'full_active',
  'api_openapi',
  'spa_ajax',
] as const;

export const SCAN_STATUSES: readonly ScanStatus[] = [
  'queued',
  'spidering',
  'active_scanning',
  'ingesting',
  'completed',
  'failed',
  'cancelled',
] as const;

export const SEVERITY_LEVELS: readonly SeverityLevel[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
] as const;

export const REMEDIATION_STATUSES: readonly RemediationStatus[] = [
  'open',
  'in_progress',
  'false_positive',
  'risk_accepted',
  'resolved',
  'verified_fixed',
  'regressed',
] as const;

export const DIFF_CLASSIFICATIONS: readonly DiffClassification[] = [
  'new',
  'persistent',
  'regressed',
] as const;

export const SEVERITY_RANK: Record<SeverityLevel, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export const SEVERITY_LABELS: Record<SeverityLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export const REMEDIATION_LABELS: Record<RemediationStatus, string> = {
  open: 'Open',
  in_progress: 'In Progress',
  false_positive: 'False Positive',
  risk_accepted: 'Risk Accepted',
  resolved: 'Resolved',
  verified_fixed: 'Verified Fixed',
  regressed: 'Regressed',
};

export const SCAN_STATUS_LABELS: Record<ScanStatus, string> = {
  queued: 'Queued',
  spidering: 'Spidering',
  active_scanning: 'Active Scanning',
  ingesting: 'Ingesting Results',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

export const SCAN_TYPE_LABELS: Record<ScanType, string> = {
  baseline_passive: 'Baseline Passive',
  full_active: 'Full Active',
  api_openapi: 'OpenAPI Spec Scan',
  spa_ajax: 'SPA AJAX Spider',
};

export const APP_CRITICALITY_LABELS: Record<AppCriticality, string> = {
  critical: 'Tier 1 - Critical',
  high: 'Tier 2 - High',
  medium: 'Tier 3 - Medium',
  low: 'Tier 4 - Low',
};

export const APP_ENV_LABELS: Record<AppEnvironment, string> = {
  production: 'Production',
  staging: 'Staging',
  development: 'Development',
  qa: 'QA',
};
