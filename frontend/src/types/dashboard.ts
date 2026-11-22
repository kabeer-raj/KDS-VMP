import { SeverityCounts } from './app';
import { VulnerabilitySummary } from './vuln';

/**
 * Dashboard & Executive Metrics
 * matching backend/crates/api-server/src/routes/reports.rs and documentation
 */

export interface OwaspBreakdownItem {
  category: string;
  count: number;
  percentage: number;
}

export interface SlaCompliance {
  critical_within_sla: number;
  critical_breached: number;
  high_within_sla: number;
  high_breached: number;
  overall_compliance_rate: number; // percentage 0-100
}

export interface DashboardSummary {
  total_applications: number;
  average_risk_score: number;
  total_vulnerabilities: number;
  vulnerabilities: VulnerabilitySummary[];
  severity_counts?: SeverityCounts;
  owasp_breakdown?: OwaspBreakdownItem[];
  sla_compliance?: SlaCompliance;
  active_scans_count?: number;
}
