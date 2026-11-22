import { AppCriticality, AppEnvironment } from './enums';

/**
 * Application Inventory DTOs
 * matching backend/crates/shared-types/src/app.rs
 */

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface CreateApplicationRequest {
  name: string;
  description?: string | null;
  base_url: string;
  environment: AppEnvironment;
  criticality: AppCriticality;
  team_name?: string | null;
  include_regexes?: string[];
  exclude_regexes?: string[];
  cron_schedule?: string | null;
  is_authorized: boolean; // Must be true to pass server validation
}

export interface UpdateApplicationRequest {
  name?: string;
  description?: string | null;
  environment?: AppEnvironment;
  criticality?: AppCriticality;
  team_name?: string | null;
  include_regexes?: string[];
  exclude_regexes?: string[];
  cron_schedule?: string | null;
}

export interface ConfigureAuthRequest {
  auth_type: string;
  auth_data: Record<string, unknown>;
}

export interface ApplicationResponse {
  id: string;
  name: string;
  description: string | null;
  base_url: string;
  environment: AppEnvironment;
  criticality: AppCriticality;
  owner_id: string | null;
  team_name: string | null;
  include_regexes: string[];
  exclude_regexes: string[];
  has_auth_configured: boolean;
  cron_schedule: string | null;
  is_authorized: boolean;
  latest_risk_score: number;
  last_scanned_at: string | null;
  open_counts: SeverityCounts;
  created_at: string;
}

/** Convenience alias */
export type Application = ApplicationResponse;

export interface AppTrendPoint {
  timestamp: string;
  scan_id: string | null;
  risk_score: number;
  severity_counts: SeverityCounts;
}

export interface AppTrendsResponse {
  app_id: string;
  data_points: AppTrendPoint[];
}
