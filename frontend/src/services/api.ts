import {
  AddCommentRequest,
  ApiKeyResponse,
  ApplicationResponse,
  AppTrendsResponse,
  BulkUpdateResponse,
  BulkUpdateVulnsRequest,
  ConfigureAuthRequest,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  CreateApplicationRequest,
  DashboardSummary,
  ErrorEnvelope,
  LoginRequest,
  PaginatedResponse,
  RemediationAuditLogResponse,
  ScanComparisonResponse,
  ScanResponse,
  TokenResponse,
  TriggerScanRequest,
  UpdateApplicationRequest,
  UpdateVulnerabilityRequest,
  UserProfile,
  VulnerabilityDetail,
  VulnerabilitySummary,
  VulnFilterParams,
} from '../types';

import * as mockService from './mockData';

/**
 * Standard typed API Error containing ErrorEnvelope details
 */
export class ApiError extends Error {
  public status: number;
  public code: string;
  public requestId?: string;
  public envelope?: ErrorEnvelope;

  constructor(status: number, message: string, code = 'API_ERROR', requestId?: string, envelope?: ErrorEnvelope) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.envelope = envelope;
  }
}

// Storage keys
const TOKEN_KEY = 'kds_vmp_access_token';
const REFRESH_TOKEN_KEY = 'kds_vmp_refresh_token';
const API_KEY_KEY = 'kds_vmp_api_key';
const MOCK_MODE_KEY = 'kds_vmp_mock_mode';

class ApiClient {
  private baseUrl: string;
  private isMockEnabled: boolean;
  private isRefreshing = false;
  private refreshSubscribers: Array<(token: string) => void> = [];

  constructor() {
    this.baseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api/v1';
    // Mock fallback is strictly disabled by default (no simulated fallback data)
    this.isMockEnabled = localStorage.getItem(MOCK_MODE_KEY) === 'true';
  }

  /**
   * Ping backend health check to verify connectivity to 127.0.0.1:8000
   */
  public async checkHealth(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);
      const baseOrigin = this.baseUrl.replace(/\/api\/v1\/?$/, '');
      const res = await fetch(`${baseOrigin}/api/v1/healthz`, {
        method: 'GET',
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      return res.ok;
    } catch {
      return false;
    }
  }

  /**
   * Expose connection status check for UI headers and banners
   */
  public async getConnectionStatus(): Promise<{ connected: boolean; host: string; message: string }> {
    const isUp = await this.checkHealth();
    return {
      connected: isUp,
      host: '127.0.0.1:8000',
      message: isUp
        ? 'Connected to API server at 127.0.0.1:8000'
        : 'Backend Disconnected: Unable to reach API server at 127.0.0.1:8000. Values reflect empty/default state.',
    };
  }

  public setBaseUrl(url: string) {
    this.baseUrl = url.replace(/\/+$/, '');
  }

  public getBaseUrl(): string {
    return this.baseUrl;
  }

  public setMockMode(enabled: boolean) {
    this.isMockEnabled = enabled;
    localStorage.setItem(MOCK_MODE_KEY, String(enabled));
  }

  public getMockMode(): boolean {
    return this.isMockEnabled;
  }

  public getAccessToken(): string | null {
    return localStorage.getItem(TOKEN_KEY);
  }

  public setAccessToken(token: string) {
    localStorage.setItem(TOKEN_KEY, token);
  }

  public getRefreshToken(): string | null {
    return localStorage.getItem(REFRESH_TOKEN_KEY);
  }

  public setRefreshToken(token: string) {
    localStorage.setItem(REFRESH_TOKEN_KEY, token);
  }

  public clearTokens() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  }

  public getApiKey(): string | null {
    return localStorage.getItem(API_KEY_KEY);
  }

  public setApiKey(key: string) {
    localStorage.setItem(API_KEY_KEY, key);
  }

  public clearApiKey() {
    localStorage.removeItem(API_KEY_KEY);
  }

  /**
   * Automatically ensure an authenticated session exists with the backend.
   * If no token or API key is set, automatically logs in using default admin credentials.
   */
  public async ensureAuthenticated(): Promise<boolean> {
    if (this.isMockEnabled) return true;
    if (this.getAccessToken() || this.getApiKey()) return true;

    try {
      const baseOrigin = this.baseUrl.replace(/\/api\/v1\/?$/, '');
      const loginUrl = `${baseOrigin}/api/v1/auth/login`;
      const res = await fetch(loginUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          email: 'admin@kds.local',
          password: 'AdminSecret123!',
        }),
      });

      if (res.ok) {
        const data = (await res.json()) as TokenResponse;
        if (data.access_token) {
          this.setAccessToken(data.access_token);
        }
        if (data.refresh_token) {
          this.setRefreshToken(data.refresh_token);
        }
        return true;
      }
      return false;
    } catch (err) {
      console.warn('Auto-login with default credentials failed:', err);
      return false;
    }
  }

  /**
   * Core request dispatcher with automatic JWT/API-Key headers,
   * 401 token refresh flow, and network-error mock fallback.
   */
  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
    retryOnAuthFailure = true
  ): Promise<T> {
    if (this.isMockEnabled) {
      return this.handleMockFallback<T>(endpoint, options);
    }

    const url = endpoint.startsWith('http')
      ? endpoint
      : `${this.baseUrl}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;

    const headers: Record<string, string> = {
      Accept: 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (!(options.body instanceof FormData) && !headers['Content-Type'] && options.method !== 'GET') {
      headers['Content-Type'] = 'application/json';
    }

    let token = this.getAccessToken();
    let apiKey = this.getApiKey();

    if (!token && !apiKey && !endpoint.includes('/auth/login') && !endpoint.includes('/healthz')) {
      await this.ensureAuthenticated();
      token = this.getAccessToken();
      apiKey = this.getApiKey();
    }

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    } else if (apiKey) {
      headers['X-API-Key'] = apiKey;
    }

    try {
      const response = await fetch(url, { ...options, headers });

      // Handle 401 unauthorized & refresh token or re-auth
      if (response.status === 401 && retryOnAuthFailure) {
        if (this.getRefreshToken()) {
          const refreshedToken = await this.performTokenRefresh();
          if (refreshedToken) {
            headers['Authorization'] = `Bearer ${refreshedToken}`;
            const retryRes = await fetch(url, { ...options, headers });
            return this.processResponse<T>(retryRes);
          }
        }
        if (!endpoint.includes('/auth/login')) {
          this.clearTokens();
          const autoLoggedIn = await this.ensureAuthenticated();
          if (autoLoggedIn && this.getAccessToken()) {
            headers['Authorization'] = `Bearer ${this.getAccessToken()}`;
            const retryRes = await fetch(url, { ...options, headers });
            return this.processResponse<T>(retryRes);
          }
        }
      }

      return await this.processResponse<T>(response);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        throw err;
      }
      const msg = err instanceof Error ? err.message : 'Network error';
      throw new ApiError(
        0,
        `Backend not connected — unable to reach 127.0.0.1:8000 (${msg})`,
        'BACKEND_DISCONNECTED'
      );
    }
  }

  private async processResponse<T>(response: Response): Promise<T> {
    if (!response.ok) {
      let code = 'HTTP_' + response.status;
      let message = response.statusText || 'An unexpected error occurred';
      let requestId: string | undefined;
      let envelope: ErrorEnvelope | undefined;

      try {
        const json = await response.json();
        if (json && json.error) {
          envelope = json as ErrorEnvelope;
          code = json.error.code || code;
          message = json.error.message || message;
          requestId = json.error.request_id;
        } else if (json && json.message) {
          message = json.message;
        }
      } catch {
        // Response was not JSON
      }

      throw new ApiError(response.status, message, code, requestId, envelope);
    }

    if (response.status === 204) {
      return {} as T;
    }

    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/pdf') || contentType.includes('application/octet-stream')) {
      return (await response.blob()) as unknown as T;
    }

    return (await response.json()) as T;
  }

  private async performTokenRefresh(): Promise<string | null> {
    const refresh = this.getRefreshToken();
    if (!refresh) {
      this.clearTokens();
      return null;
    }

    if (this.isRefreshing) {
      return new Promise((resolve) => {
        this.refreshSubscribers.push((newToken: string) => resolve(newToken));
      });
    }

    this.isRefreshing = true;
    try {
      const res = await fetch(`${this.baseUrl}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refresh }),
      });

      if (!res.ok) {
        this.clearTokens();
        return null;
      }

      const data: TokenResponse = await res.json();
      this.setAccessToken(data.access_token);
      this.setRefreshToken(data.refresh_token);

      this.refreshSubscribers.forEach((cb) => cb(data.access_token));
      this.refreshSubscribers = [];
      return data.access_token;
    } catch {
      this.clearTokens();
      return null;
    } finally {
      this.isRefreshing = false;
    }
  }

  /**
   * Standalone mock fallback implementation
   */
  private handleMockFallback<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const method = (options.method || 'GET').toUpperCase();
    const cleanEndpoint = endpoint.split('?')[0];

    // Auth endpoints
    if (cleanEndpoint === '/auth/login' && method === 'POST') {
      const resp: TokenResponse = {
        access_token: 'mock_jwt_access_token_secops',
        refresh_token: 'mock_jwt_refresh_token_secops',
        token_type: 'Bearer',
        expires_in: 900,
        user: mockService.MOCK_CURRENT_USER,
      };
      this.setAccessToken(resp.access_token);
      this.setRefreshToken(resp.refresh_token);
      return Promise.resolve(resp as unknown as T);
    }

    if (cleanEndpoint === '/auth/refresh' && method === 'POST') {
      const resp: TokenResponse = {
        access_token: 'mock_jwt_access_token_refreshed',
        refresh_token: 'mock_jwt_refresh_token_refreshed',
        token_type: 'Bearer',
        expires_in: 900,
        user: mockService.MOCK_CURRENT_USER,
      };
      this.setAccessToken(resp.access_token);
      this.setRefreshToken(resp.refresh_token);
      return Promise.resolve(resp as unknown as T);
    }

    if (cleanEndpoint === '/auth/me') {
      return Promise.resolve(mockService.MOCK_CURRENT_USER as unknown as T);
    }

    if (cleanEndpoint === '/auth/logout') {
      this.clearTokens();
      return Promise.resolve({} as T);
    }

    if ((cleanEndpoint === '/auth/api-keys' || cleanEndpoint === '/auth/keys') && method === 'GET') {
      return Promise.resolve(mockService.getMockApiKeys() as unknown as T);
    }

    if ((cleanEndpoint === '/auth/api-keys' || cleanEndpoint === '/auth/keys') && method === 'POST') {
      const body = options.body ? JSON.parse(options.body as string) : {};
      return Promise.resolve(mockService.createMockApiKey(body) as unknown as T);
    }

    if ((cleanEndpoint.startsWith('/auth/api-keys/') || cleanEndpoint.startsWith('/auth/keys/')) && method === 'DELETE') {
      const id = cleanEndpoint.split('/').pop() || '';
      mockService.deleteMockApiKey(id);
      return Promise.resolve({} as T);
    }

    // Apps endpoints
    if (cleanEndpoint === '/apps' && method === 'GET') {
      return Promise.resolve(mockService.getMockApps() as unknown as T);
    }

    if (cleanEndpoint === '/apps' && method === 'POST') {
      const body = options.body ? JSON.parse(options.body as string) : {};
      return Promise.resolve(mockService.createMockApp(body) as unknown as T);
    }

    const appMatch = cleanEndpoint.match(/^\/apps\/([^/]+)$/);
    if (appMatch) {
      const appId = appMatch[1];
      if (method === 'GET') {
        const app = mockService.getMockApp(appId);
        if (!app) return Promise.reject(new ApiError(404, 'Application not found', 'APPLICATION_NOT_FOUND'));
        return Promise.resolve(app as unknown as T);
      }
      if (method === 'PATCH' || method === 'PUT') {
        const body = options.body ? JSON.parse(options.body as string) : {};
        return Promise.resolve(mockService.updateMockApp(appId, body) as unknown as T);
      }
      if (method === 'DELETE') {
        mockService.deleteMockApp(appId);
        return Promise.resolve({} as T);
      }
    }

    const appAuthMatch = cleanEndpoint.match(/^\/apps\/([^/]+)\/auth$/);
    if (appAuthMatch && (method === 'PUT' || method === 'POST')) {
      mockService.configureMockAppAuth(appAuthMatch[1]);
      return Promise.resolve({ success: true } as unknown as T);
    }

    const appTrendsMatch = cleanEndpoint.match(/^\/apps\/([^/]+)\/trends$/);
    if (appTrendsMatch && method === 'GET') {
      return Promise.resolve(mockService.getMockAppTrends(appTrendsMatch[1]) as unknown as T);
    }

    // Scans endpoints
    const appScansMatch = cleanEndpoint.match(/^\/apps\/([^/]+)\/scans$/);
    if (appScansMatch) {
      const appId = appScansMatch[1];
      if (method === 'GET') {
        return Promise.resolve(mockService.getMockScans(appId) as unknown as T);
      }
      if (method === 'POST') {
        const body = options.body ? JSON.parse(options.body as string) : { scan_type: 'full_active' };
        return Promise.resolve(mockService.triggerMockScan(appId, body) as unknown as T);
      }
    }

    if (cleanEndpoint === '/scans' && method === 'GET') {
      return Promise.resolve(mockService.getMockScans() as unknown as T);
    }

    if (cleanEndpoint === '/scans' && method === 'POST') {
      const body = options.body ? JSON.parse(options.body as string) : {};
      const appId = body.application_id || body.app_id || '11111111-1111-1111-1111-111111111111';
      return Promise.resolve(mockService.triggerMockScan(appId, body) as unknown as T);
    }

    if (cleanEndpoint === '/scans/diff' || cleanEndpoint === '/scans/compare') {
      const baseId = 's0000002-0000-0000-0000-000000000002';
      const targetId = 's0000001-0000-0000-0000-000000000001';
      return Promise.resolve(mockService.compareMockScans(baseId, targetId) as unknown as T);
    }

    const scanCancelMatch = cleanEndpoint.match(/^\/scans\/([^/]+)\/cancel$/);
    if (scanCancelMatch && method === 'POST') {
      return Promise.resolve(mockService.cancelMockScan(scanCancelMatch[1]) as unknown as T);
    }

    const scanFindingsMatch = cleanEndpoint.match(/^\/scans\/([^/]+)\/(findings|report)$/);
    if (scanFindingsMatch && method === 'GET') {
      const vulns = mockService.getMockVulns({ app_id: '11111111-1111-1111-1111-111111111111' });
      return Promise.resolve(vulns as unknown as T);
    }

    const scanMatch = cleanEndpoint.match(/^\/scans\/([^/]+)$/);
    if (scanMatch && method === 'GET') {
      const scan = mockService.getMockScan(scanMatch[1]);
      if (!scan) return Promise.reject(new ApiError(404, 'Scan not found', 'SCAN_NOT_FOUND'));
      return Promise.resolve(scan as unknown as T);
    }

    // Vulnerabilities endpoints
    if ((cleanEndpoint === '/vulns' || cleanEndpoint === '/vulnerabilities') && method === 'GET') {
      return Promise.resolve(mockService.getMockVulns() as unknown as T);
    }

    if ((cleanEndpoint === '/vulns/bulk-update' || cleanEndpoint === '/vulnerabilities/bulk-update') && method === 'POST') {
      const body = options.body ? JSON.parse(options.body as string) : {};
      const count = mockService.bulkUpdateMockVulns(body.vuln_ids || [], body.status, body.comment);
      return Promise.resolve({ updated_count: count } as unknown as T);
    }

    const vulnHistoryMatch = cleanEndpoint.match(/^\/(?:vulns|vulnerabilities)\/([^/]+)\/history$/);
    if (vulnHistoryMatch && method === 'GET') {
      return Promise.resolve(mockService.getMockVulnHistory(vulnHistoryMatch[1]) as unknown as T);
    }

    const vulnCommentMatch = cleanEndpoint.match(/^\/(?:vulns|vulnerabilities)\/([^/]+)\/comments$/);
    if (vulnCommentMatch && method === 'POST') {
      const body = options.body ? JSON.parse(options.body as string) : { comment: '' };
      return Promise.resolve(mockService.addMockVulnComment(vulnCommentMatch[1], body.comment) as unknown as T);
    }

    const vulnMatch = cleanEndpoint.match(/^\/(?:vulns|vulnerabilities)\/([^/]+)$/);
    if (vulnMatch) {
      const vulnId = vulnMatch[1];
      if (method === 'GET') {
        const vuln = mockService.getMockVuln(vulnId);
        if (!vuln) return Promise.reject(new ApiError(404, 'Vulnerability not found', 'VULNERABILITY_NOT_FOUND'));
        return Promise.resolve(vuln as unknown as T);
      }
      if (method === 'PATCH') {
        const body = options.body ? JSON.parse(options.body as string) : {};
        return Promise.resolve(mockService.updateMockVuln(vulnId, body) as unknown as T);
      }
    }

    // Dashboard endpoint
    if (cleanEndpoint === '/dashboard/summary') {
      return Promise.resolve(mockService.getMockDashboardSummary() as unknown as T);
    }

    // Report downloads
    if (cleanEndpoint.includes('/reports/')) {
      const dummyPdfBlob = new Blob(['%PDF-1.5 Mock AppSec Security Assessment Report generated by KDS-VMP'], {
        type: 'application/pdf',
      });
      return Promise.resolve(dummyPdfBlob as unknown as T);
    }

    // Fallback response
    return Promise.resolve({} as T);
  }

  // ============================================================================
  // 1. AUTHENTICATION & API KEYS
  // ============================================================================

  public async login(credentials: LoginRequest): Promise<TokenResponse> {
    const data = await this.request<TokenResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
    this.setAccessToken(data.access_token);
    this.setRefreshToken(data.refresh_token);
    return data;
  }

  public async refreshToken(refreshToken?: string): Promise<TokenResponse> {
    const token = refreshToken || this.getRefreshToken();
    if (!token) throw new ApiError(400, 'No refresh token available', 'NO_REFRESH_TOKEN');
    const data = await this.request<TokenResponse>('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: token }),
    }, false);
    this.setAccessToken(data.access_token);
    this.setRefreshToken(data.refresh_token);
    return data;
  }

  public async logout(): Promise<void> {
    try {
      await this.request<void>('/auth/logout', { method: 'POST' });
    } finally {
      this.clearTokens();
    }
  }

  public async getMe(): Promise<UserProfile> {
    return this.request<UserProfile>('/auth/me');
  }

  public async listApiKeys(): Promise<ApiKeyResponse[]> {
    return this.request<ApiKeyResponse[]>('/auth/api-keys');
  }

  public async createApiKey(data: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
    return this.request<CreateApiKeyResponse>('/auth/api-keys', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  public async deleteApiKey(keyId: string): Promise<void> {
    await this.request<void>(`/auth/api-keys/${keyId}`, { method: 'DELETE' });
  }

  // ============================================================================
  // 2. WEB APPLICATION INVENTORY
  // ============================================================================

  public async listApps(environment?: string): Promise<ApplicationResponse[]> {
    const query = environment ? `?environment=${encodeURIComponent(environment)}` : '';
    return this.request<ApplicationResponse[]>(`/apps${query}`);
  }

  public async createApp(data: CreateApplicationRequest): Promise<ApplicationResponse> {
    return this.request<ApplicationResponse>('/apps', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  public async getApp(appId: string): Promise<ApplicationResponse> {
    return this.request<ApplicationResponse>(`/apps/${appId}`);
  }

  public async updateApp(appId: string, data: UpdateApplicationRequest): Promise<ApplicationResponse> {
    return this.request<ApplicationResponse>(`/apps/${appId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  public async deleteApp(appId: string): Promise<void> {
    await this.request<void>(`/apps/${appId}`, { method: 'DELETE' });
  }

  public async configureAppAuth(appId: string, data: ConfigureAuthRequest): Promise<void> {
    await this.request<void>(`/apps/${appId}/auth`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  public async getAppTrends(appId: string): Promise<AppTrendsResponse> {
    return this.request<AppTrendsResponse>(`/apps/${appId}/trends`);
  }

  // ============================================================================
  // 3. SECURITY ASSESSMENTS / SCANS
  // ============================================================================

  public async triggerAppScan(appId: string, data: TriggerScanRequest): Promise<ScanResponse> {
    return this.request<ScanResponse>(`/apps/${appId}/scans`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  public async triggerGlobalScan(
    data: { application_id: string } & TriggerScanRequest
  ): Promise<ScanResponse> {
    return this.request<ScanResponse>('/scans', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  public async listAppScans(appId: string): Promise<ScanResponse[]> {
    return this.request<ScanResponse[]>(`/apps/${appId}/scans`);
  }

  public async listGlobalScans(): Promise<ScanResponse[]> {
    return this.request<ScanResponse[]>('/scans');
  }

  public async getScan(scanId: string): Promise<ScanResponse> {
    return this.request<ScanResponse>(`/scans/${scanId}`);
  }

  public async cancelScan(scanId: string): Promise<ScanResponse> {
    return this.request<ScanResponse>(`/scans/${scanId}/cancel`, {
      method: 'POST',
    });
  }

  public async getScanFindings(
    scanId: string
  ): Promise<PaginatedResponse<VulnerabilitySummary> | VulnerabilitySummary[]> {
    return this.request<PaginatedResponse<VulnerabilitySummary> | VulnerabilitySummary[]>(
      `/scans/${scanId}/findings`
    );
  }

  public async compareScans(
    baseScanId: string,
    targetScanId: string
  ): Promise<ScanComparisonResponse> {
    return this.request<ScanComparisonResponse>(
      `/scans/compare?base=${encodeURIComponent(baseScanId)}&target=${encodeURIComponent(targetScanId)}`
    );
  }

  // ============================================================================
  // 4. VULNERABILITY MANAGEMENT & TRIAGE
  // ============================================================================

  public async listVulns(params?: VulnFilterParams): Promise<PaginatedResponse<VulnerabilitySummary>> {
    const q = new URLSearchParams();
    if (params) {
      if (params.app_id) q.set('app_id', params.app_id);
      if (params.application_id) q.set('app_id', params.application_id);
      if (params.severity) q.set('severity', params.severity);
      if (params.status) q.set('status', params.status);
      if (params.owasp_category) q.set('owasp_category', params.owasp_category);
      if (params.assigned_to) q.set('assigned_to', params.assigned_to);
      if (params.search) q.set('search', params.search);
      if (params.sort_by) q.set('sort_by', params.sort_by);
      if (params.order) q.set('order', params.order);
      if (params.page) q.set('page', String(params.page));
      if (params.per_page) q.set('per_page', String(params.per_page));
    }
    const queryString = q.toString() ? `?${q.toString()}` : '';
    return this.request<PaginatedResponse<VulnerabilitySummary>>(`/vulns${queryString}`);
  }

  public async getVuln(vulnId: string): Promise<VulnerabilityDetail> {
    return this.request<VulnerabilityDetail>(`/vulns/${vulnId}`);
  }

  public async updateVuln(
    vulnId: string,
    data: UpdateVulnerabilityRequest
  ): Promise<VulnerabilityDetail> {
    return this.request<VulnerabilityDetail>(`/vulns/${vulnId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  public async bulkUpdateVulns(data: BulkUpdateVulnsRequest): Promise<BulkUpdateResponse> {
    return this.request<BulkUpdateResponse>('/vulns/bulk-update', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  public async getVulnHistory(vulnId: string): Promise<RemediationAuditLogResponse[]> {
    return this.request<RemediationAuditLogResponse[]>(`/vulns/${vulnId}/history`);
  }

  public async addVulnComment(
    vulnId: string,
    comment: string | AddCommentRequest
  ): Promise<RemediationAuditLogResponse> {
    const payload = typeof comment === 'string' ? { comment } : comment;
    return this.request<RemediationAuditLogResponse>(`/vulns/${vulnId}/comments`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // ============================================================================
  // 5. EXECUTIVE REPORTING & DASHBOARD
  // ============================================================================

  public async getDashboardSummary(): Promise<DashboardSummary> {
    return this.request<DashboardSummary>('/dashboard/summary');
  }

  public async downloadScanPdf(scanId: string): Promise<Blob> {
    return this.request<Blob>(`/reports/scans/${scanId}/pdf`, {
      headers: { Accept: 'application/pdf' },
    });
  }

  public async downloadScanJson(scanId: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(`/reports/${scanId}/json`);
  }

  public async downloadAppPdf(appId: string): Promise<Blob> {
    return this.request<Blob>(`/reports/apps/${appId}/pdf`, {
      headers: { Accept: 'application/pdf' },
    });
  }
}

export const api = new ApiClient();
export default api;
