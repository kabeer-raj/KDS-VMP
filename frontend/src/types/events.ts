import { ScanStatus } from './enums';
import { SeverityCounts } from './app';

/**
 * WebSocket Real-Time Event Payloads
 * matching backend/crates/shared-types/src/events.rs
 */

export interface ScanProgressEvent {
  scan_id: string;
  application_id: string;
  status: ScanStatus;
  progress_percent: number;
  current_phase: string;
  alerts_found_so_far: number;
}

export interface ScanCompletedEvent {
  scan_id: string;
  application_id: string;
  severity_counts: SeverityCounts;
  overall_risk_score: number;
}

export interface ScanFailedEvent {
  scan_id: string;
  application_id: string;
  reason: string;
}

export type WsServerEvent =
  | { event: 'scan_progress'; data: ScanProgressEvent }
  | { event: 'scan_completed'; data: ScanCompletedEvent }
  | { event: 'scan_failed'; data: ScanFailedEvent };
