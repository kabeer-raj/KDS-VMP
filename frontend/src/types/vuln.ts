import { DiffClassification, RemediationStatus, SeverityLevel } from './enums';

/**
 * Vulnerability & Remediation DTOs
 * matching backend/crates/shared-types/src/vuln.rs
 */

export interface HttpEvidence {
  scan_id: string;
  diff_state: DiffClassification;
  attack_payload: string | null;
  evidence_snippet: string | null;
  raw_request_header: string | null;
  raw_response_header: string | null;
}

export interface VulnerabilitySummary {
  id: string;
  application_id: string;
  fingerprint: string;
  title: string;
  owasp_category: string;
  cwe_id: number | null;
  severity: SeverityLevel;
  cvss_score: number;
  status: RemediationStatus;
  http_method: string;
  normalized_path: string;
  affected_param: string | null;
  assigned_to: string | null;
  seen_count: number;
  last_seen_at: string;
}

export interface VulnerabilityDetail extends VulnerabilitySummary {
  zap_plugin_id: string;
  wasc_id: number | null;
  cvss_vector: string | null;
  confidence: string;
  affected_url: string;
  description: string;
  solution: string;
  reference_urls: string[];
  due_date: string | null;
  latest_evidence: HttpEvidence | null;
  first_seen_at: string;
  resolved_at: string | null;
}

/** Convenience alias */
export type Vulnerability = VulnerabilityDetail;

export interface UpdateVulnerabilityRequest {
  status?: RemediationStatus;
  severity?: SeverityLevel;
  assigned_to?: string | null;
  due_date?: string | null;
  comment?: string;
}

export interface BulkUpdateVulnsRequest {
  vuln_ids: string[];
  status?: RemediationStatus;
  severity?: SeverityLevel;
  assigned_to?: string | null;
  comment?: string;
}

export interface BulkUpdateResponse {
  updated_count: number;
}

export interface AddCommentRequest {
  comment: string;
}

export interface RemediationAuditLogResponse {
  id: string;
  vulnerability_id: string;
  actor_id: string | null;
  scan_id: string | null;
  action_type: string;
  old_status: RemediationStatus | null;
  new_status: RemediationStatus | null;
  comment: string | null;
  created_at: string;
}

export interface VulnFilterParams {
  app_id?: string;
  application_id?: string;
  severity?: SeverityLevel;
  status?: RemediationStatus;
  owasp_category?: string;
  assigned_to?: string;
  search?: string;
  sort_by?: string;
  order?: 'asc' | 'desc';
  page?: number;
  per_page?: number;
}
