import { ScanStatus, ScanType } from './enums';
import { SeverityCounts } from './app';

/**
 * Scan & Diff DTOs
 * matching backend/crates/shared-types/src/scan.rs
 */

export interface TriggerScanRequest {
  scan_type: ScanType;
  max_duration_minutes?: number | null;
  custom_headers?: Record<string, string> | null;
}

export interface ScanDiffSummary {
  previous_scan_id: string | null;
  new_count: number;
  persistent_count: number;
  fixed_count: number;
  regressed_count: number;
  risk_score_delta: number;
}

export interface ScanResponse {
  id: string;
  application_id: string;
  scan_type: ScanType;
  status: ScanStatus;
  progress_percent: number;
  severity_counts: SeverityCounts;
  diff_summary: ScanDiffSummary;
  overall_risk_score: number;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  error_message: string | null;
}

/** Convenience alias */
export type Scan = ScanResponse;

export interface ScanComparisonResponse {
  base_scan_id: string;
  target_scan_id: string;
  diff_summary: ScanDiffSummary;
}
