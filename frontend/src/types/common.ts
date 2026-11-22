/**
 * Common API error envelope and pagination types
 * matching backend/crates/shared-types/src/common.rs
 */

export interface ErrorDetail {
  code: string;
  message: string;
  request_id: string;
}

export interface ErrorEnvelope {
  error: ErrorDetail;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}
