-- Enable cryptographic UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 3.1 CUSTOM ENUM TYPES (Mapped to Rust `crates/shared-types`)
-- ============================================================================

CREATE TYPE user_role AS ENUM (
    'admin',
    'security_engineer',
    'developer',
    'auditor'
);

CREATE TYPE app_environment AS ENUM (
    'production',
    'staging',
    'development',
    'qa'
);

CREATE TYPE app_criticality AS ENUM (
    'critical',
    'high',
    'medium',
    'low'
);

CREATE TYPE scan_type AS ENUM (
    'baseline_passive',
    'full_active',
    'api_openapi',
    'spa_ajax'
);

CREATE TYPE scan_status AS ENUM (
    'queued',
    'spidering',
    'active_scanning',
    'ingesting',
    'completed',
    'failed',
    'cancelled'
);

CREATE TYPE severity_level AS ENUM (
    'info',
    'low',
    'medium',
    'high',
    'critical'
);

CREATE TYPE remediation_status AS ENUM (
    'open',
    'in_progress',
    'false_positive',
    'risk_accepted',
    'resolved',
    'verified_fixed',
    'regressed'
);

CREATE TYPE diff_classification AS ENUM (
    'new',
    'persistent',
    'regressed'
);

-- ============================================================================
-- 3.2 USERS & AUTHENTICATION
-- ============================================================================

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) NOT NULL UNIQUE,
    full_name       VARCHAR(150) NOT NULL,
    password_hash   TEXT NOT NULL,
    role            user_role NOT NULL DEFAULT 'developer',
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            VARCHAR(100) NOT NULL,
    key_prefix      VARCHAR(12) NOT NULL,
    key_hash        TEXT NOT NULL UNIQUE,
    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- 3.3 WEB APPLICATION INVENTORY
-- ============================================================================

CREATE TABLE applications (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(150) NOT NULL,
    description         TEXT,
    base_url            TEXT NOT NULL,
    environment         app_environment NOT NULL DEFAULT 'staging',
    criticality         app_criticality NOT NULL DEFAULT 'medium',
    owner_id            UUID REFERENCES users(id) ON DELETE SET NULL,
    team_name           VARCHAR(100),

    -- Scope & OWASP ZAP Configuration
    include_regexes     TEXT[] NOT NULL DEFAULT '{}',
    exclude_regexes     TEXT[] NOT NULL DEFAULT '{}',
    auth_config_enc     BYTEA,          -- Encrypted session headers/cookies/login script
    cron_schedule       VARCHAR(64),    -- Optional cron expression for recurring scans
    is_authorized       BOOLEAN NOT NULL DEFAULT FALSE, -- Explicit permission attestation

    -- Cached Risk Summary (Updated on scan completion)
    latest_risk_score   NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    last_scanned_at     TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_applications_owner ON applications(owner_id);
CREATE INDEX idx_applications_env ON applications(environment);

-- ============================================================================
-- 3.4 SECURITY ASSESSMENTS (SCAN RUNS)
-- ============================================================================

CREATE TABLE scans (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id          UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    triggered_by            UUID REFERENCES users(id) ON DELETE SET NULL,
    previous_scan_id        UUID REFERENCES scans(id) ON DELETE SET NULL,

    scan_type               scan_type NOT NULL DEFAULT 'full_active',
    status                  scan_status NOT NULL DEFAULT 'queued',
    progress_percent        SMALLINT NOT NULL DEFAULT 0 CHECK (progress_percent BETWEEN 0 AND 100),
    zap_context_name        VARCHAR(120),
    zap_scan_id             VARCHAR(64),
    error_message           TEXT,

    -- Point-in-time Aggregated Metrics (For fast trend & PDF report generation)
    total_findings          INTEGER NOT NULL DEFAULT 0,
    critical_count          INTEGER NOT NULL DEFAULT 0,
    high_count              INTEGER NOT NULL DEFAULT 0,
    medium_count            INTEGER NOT NULL DEFAULT 0,
    low_count               INTEGER NOT NULL DEFAULT 0,
    info_count              INTEGER NOT NULL DEFAULT 0,

    -- Diff Summary vs `previous_scan_id`
    new_findings_count      INTEGER NOT NULL DEFAULT 0,
    fixed_findings_count    INTEGER NOT NULL DEFAULT 0,
    regressed_count         INTEGER NOT NULL DEFAULT 0,
    overall_risk_score      NUMERIC(5,2) NOT NULL DEFAULT 0.00,

    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    duration_seconds        INTEGER,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scans_app_created ON scans(application_id, created_at DESC);
CREATE INDEX idx_scans_status ON scans(status);

-- ============================================================================
-- 3.5 CANONICAL DEDUPLICATED VULNERABILITIES
-- ============================================================================

CREATE TABLE vulnerabilities (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id      UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,

    -- Deterministic SHA-256(app_id + zap_plugin_id + normalized_path + param + method)
    fingerprint         CHAR(64) NOT NULL,

    -- Classification & Standards Mapping
    zap_plugin_id       VARCHAR(32) NOT NULL,
    title               VARCHAR(255) NOT NULL,
    cwe_id              INTEGER,
    wasc_id             INTEGER,
    owasp_category      VARCHAR(64) NOT NULL,   -- e.g., 'A03:2021-Injection'

    -- Risk & CVSS Scoring
    severity            severity_level NOT NULL,
    cvss_score          NUMERIC(3,1) NOT NULL CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    cvss_vector         VARCHAR(128),
    confidence          VARCHAR(32) NOT NULL,   -- e.g., 'High', 'Medium', 'Low'

    -- Technical Location Details
    http_method         VARCHAR(16) NOT NULL,
    affected_url        TEXT NOT NULL,
    normalized_path     TEXT NOT NULL,
    affected_param      VARCHAR(255),

    -- Detailed Descriptions & Remediation Guidance
    description         TEXT NOT NULL,
    solution            TEXT NOT NULL,
    reference_urls      TEXT[] NOT NULL DEFAULT '{}',

    -- Remediation & Lifecycle Management
    status              remediation_status NOT NULL DEFAULT 'open',
    assigned_to         UUID REFERENCES users(id) ON DELETE SET NULL,
    due_date            TIMESTAMPTZ,

    -- Temporal Tracking Across Scans
    first_seen_scan_id  UUID REFERENCES scans(id) ON DELETE SET NULL,
    last_seen_scan_id   UUID REFERENCES scans(id) ON DELETE SET NULL,
    seen_count          INTEGER NOT NULL DEFAULT 1,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Enforces deduplication per target application
    CONSTRAINT uq_vuln_app_fingerprint UNIQUE (application_id, fingerprint)
);

CREATE INDEX idx_vulns_app_status ON vulnerabilities(application_id, status);
CREATE INDEX idx_vulns_severity_cvss ON vulnerabilities(severity, cvss_score DESC);
CREATE INDEX idx_vulns_owasp ON vulnerabilities(owasp_category);
CREATE INDEX idx_vulns_assigned ON vulnerabilities(assigned_to);

-- ============================================================================
-- 3.6 SCAN FINDINGS SNAPSHOT (JUNCTION FOR DIFFING & EVIDENCE)
-- ============================================================================

CREATE TABLE scan_findings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id             UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vulnerability_id    UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,

    diff_state          diff_classification NOT NULL,
    severity_at_scan    severity_level NOT NULL,
    cvss_at_scan        NUMERIC(3,1) NOT NULL,

    -- Raw HTTP Request/Response Evidence for this specific scan execution
    attack_payload      TEXT,
    evidence_snippet    TEXT,
    raw_request_header  TEXT,
    raw_response_header TEXT,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_scan_vuln UNIQUE (scan_id, vulnerability_id)
);

CREATE INDEX idx_scan_findings_scan ON scan_findings(scan_id);
CREATE INDEX idx_scan_findings_vuln ON scan_findings(vulnerability_id);

-- ============================================================================
-- 3.7 REMEDIATION AUDIT LOGS & TRIAGE COMMENTS
-- ============================================================================

CREATE TABLE remediation_audit_logs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vulnerability_id    UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    actor_id            UUID REFERENCES users(id) ON DELETE SET NULL,
    scan_id             UUID REFERENCES scans(id) ON DELETE SET NULL, -- Set if auto-verified by scan

    action_type         VARCHAR(50) NOT NULL, -- 'status_change', 'assigned', 'severity_override', 'comment'
    old_status          remediation_status,
    new_status          remediation_status,
    comment             TEXT,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_vuln_created ON remediation_audit_logs(vulnerability_id, created_at DESC);

-- ============================================================================
-- 3.8 AUTOMATIC `updated_at` TRIGGER
-- ============================================================================

CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_timestamp_users
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();

CREATE TRIGGER set_timestamp_applications
    BEFORE UPDATE ON applications
    FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();

CREATE TRIGGER set_timestamp_vulnerabilities
    BEFORE UPDATE ON vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();
