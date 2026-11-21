# E2E Test Infra: KDS Web Application Vulnerability Management Platform

## Test Philosophy
- **Requirement-Driven & Opaque-Box**: All test scenarios and assertions are derived directly from `ORIGINAL_REQUEST.md` and user-facing specifications in `docs/` (`api_routes_dto_schemas_specification.txt`, `postgresql_database_schema_specification.txt`, `rust_backend_architecture_specification.txt`).
- **Zero-Service Self-Contained Execution**: The test suite exercises the system through the Axum HTTP & WebSocket service interface (`tower::Service::oneshot`) using in-memory repository adapters and in-memory event buses. It requires ZERO live external services (no running PostgreSQL instance, no Redis server, no OWASP ZAP daemon).
- **Systematic 4-Tier Methodology**:
  - **Tier 1 - Feature Coverage**: Happy-path equivalence classes for every feature (≥5 tests per feature).
  - **Tier 2 - Boundary & Corner Cases**: Edge cases, invalid payloads, overflows, nulls, missing fields, format violations, negative RBAC tests (≥5 tests per feature).
  - **Tier 3 - Cross-Feature Combinations**: Pairwise and sequential multi-feature interactions (auth + app + scan + diffing + triage).
  - **Tier 4 - Real-World Application Scenarios**: Multi-step, end-to-end security workflows simulating real SecOps & developer operations.

## Test Runner & Execution Commands
- **Full E2E Suite Command**:
  ```bash
  cargo test --test e2e -- --nocapture
  ```
- **Tier-Specific Execution**:
  ```bash
  cargo test --test e2e tier1_ -- --nocapture
  cargo test --test e2e tier2_ -- --nocapture
  cargo test --test e2e tier3_ -- --nocapture
  cargo test --test e2e tier4_ -- --nocapture
  ```
- **Pass/Fail Semantics**: All test functions return `Result<(), anyhow::Error>` or assert directly. Exit code 0 indicates 100% test pass.

## Directory Layout
```
tests/e2e/
├── common/
│   ├── mod.rs                # Shared test harness, in-memory AppState builder, router init
│   ├── client.rs             # tower::Service HTTP client helper (GET, POST, PATCH, PUT, DELETE)
│   ├── auth_helpers.rs       # Token generation, user seeding, admin/dev/auditor session helpers
│   ├── mock_zap.rs           # Mock ZAP scanner driver emitting realistic alerts
│   └── assertions.rs         # Error envelope and JSON schema assert macros
├── tier1_feature_coverage/
│   ├── mod.rs
│   ├── auth_tests.rs         # Login, refresh, logout, me, api-keys (F25-27, 30-31)
│   ├── app_tests.rs          # App CRUD, auth config, trends (F2, 32-34)
│   ├── scan_tests.rs         # Trigger, status, cancel, findings, diff, WS (F3, 5, 35-39, 48-49)
│   ├── vuln_tests.rs         # Search, detail, triage, bulk, history, comments (F4, 40-45)
│   └── report_dashboard_tests.rs # Dashboard summary, PDF reports (F46-47)
├── tier2_boundary_corner/
│   ├── mod.rs
│   ├── invalid_auth_rbac_tests.rs  # Expired JWT, tampered signature, invalid role access, malformed keys
│   ├── app_validation_tests.rs     # Bad URLs, duplicate names, negative criticality, oversized metadata
│   ├── scan_edge_tests.rs          # Scan non-existent app, cancel finished scan, empty alerts, malformed regex
│   └── vuln_triage_edge_tests.rs   # Invalid status transitions, false positive justification missing, bulk limit
├── tier3_cross_feature/
│   ├── mod.rs
│   ├── auth_app_scan_flow.rs       # RBAC scoped scans, app deletion with active scans, key rotation
│   ├── scan_diff_triage_flow.rs    # Scan 1 -> triage -> Scan 2 -> auto-verification & regression handling
│   └── vuln_dashboard_sync.rs      # Triage state change immediately reflected in dashboard metrics
└── tier4_real_world/
    ├── mod.rs
    ├── secops_scan_triage_cycle.rs # End-to-end audit: onboard app -> active scan -> triage vulns -> export PDF
    ├── dev_fix_regression_cycle.rs # Developer fixes vuln -> re-scan -> verified fixed -> new commit regresses
    └── multi_tenant_isolation.rs   # Cross-application data boundary & permission enforcement
```

## Feature Inventory & Test Matrix
| # | Feature | Scope / Requirement | Tier 1 | Tier 2 | Tier 3 | Tier 4 |
|---|---------|---------------------|:------:|:------:|:------:|:------:|
| 1 | Custom Enums | DB matching enums & serialization | 5 | 5 | ✓ | ✓ |
| 2 | Application DTOs | Request/Response validation | 5 | 5 | ✓ | ✓ |
| 3 | Scan DTOs | Trigger, status, diff DTOs | 5 | 5 | ✓ | ✓ |
| 4 | Vulnerability DTOs | Summary, detail, triage DTOs | 5 | 5 | ✓ | ✓ |
| 5 | WebSocket Events | Progress and completion event framing | 5 | 5 | ✓ | ✓ |
| 6 | CVSS Types | Vector representation & metric structures | 5 | 5 | ✓ | ✓ |
| 7 | OWASP Top 10 Classifier | CWE & plugin ID mapping | 5 | 5 | ✓ | ✓ |
| 8 | CVSS Scoring Engine | Base score formula calculation | 5 | 5 | ✓ | ✓ |
| 9 | Risk Priority Weighter | Environment & criticality weighting | 5 | 5 | ✓ | ✓ |
| 10 | SHA-256 Deduplicator | Deterministic fingerprinting | 5 | 5 | ✓ | ✓ |
| 11 | URL Path Normalizer | RFC 3986 URL path normalization | 5 | 5 | ✓ | ✓ |
| 12 | Scan Diff Engine | State machine (NEW, PERSISTENT, FIXED, REGRESSED) | 5 | 5 | ✓ | ✓ |
| 13 | SQLx Migrations / Schema | Table constraints & enums verification | 5 | 5 | ✓ | ✓ |
| 14 | App Repository Port | CRUD & trends in-memory & DB contracts | 5 | 5 | ✓ | ✓ |
| 15 | Scan Repository Port | Lifecycle & findings persistence | 5 | 5 | ✓ | ✓ |
| 16 | Vuln Repository Port | Triage, bulk update, comments | 5 | 5 | ✓ | ✓ |
| 17 | Audit Log Repository | Append-only event history | 5 | 5 | ✓ | ✓ |
| 18 | User & API Key Repository | User authentication & hashed keys | 5 | 5 | ✓ | ✓ |
| 19 | ZAP Context Configuration | Target URL, regex scope, auth headers | 5 | 5 | ✓ | ✓ |
| 20 | ZAP Spider Trigger | Spider initiation & progress polling | 5 | 5 | ✓ | ✓ |
| 21 | ZAP Active Scanner | Active scan trigger & progress | 5 | 5 | ✓ | ✓ |
| 22 | ZAP Alert JSON Parser | Parsing alerts into domain models | 5 | 5 | ✓ | ✓ |
| 23 | PDF Report Generator | Typst / PDF byte stream rendering | 5 | 5 | ✓ | ✓ |
| 24 | Pub/Sub Adapter | In-memory broadcast & channel dispatch | 5 | 5 | ✓ | ✓ |
| 25 | JWT Authentication | Bearer token validation & claim injection | 5 | 5 | ✓ | ✓ |
| 26 | API Key Middleware | SHA-256 key header authentication | 5 | 5 | ✓ | ✓ |
| 27 | RBAC Authorization | Admin, SecEng, Developer, Auditor gates | 5 | 5 | ✓ | ✓ |
| 28 | Standard Error Envelope | RFC 7807-like uniform error envelope | 5 | 5 | ✓ | ✓ |
| 29 | CORS & Tracing Middleware | Security headers & request tracing | 5 | 5 | ✓ | ✓ |
| 30 | Auth REST Endpoints | /auth/login, /refresh, /logout, /me | 5 | 5 | ✓ | ✓ |
| 31 | API Key REST Endpoints | /auth/api-keys (GET, POST, DELETE) | 5 | 5 | ✓ | ✓ |
| 32 | App Inventory CRUD | /apps (GET, POST, GET :id, PATCH, DELETE) | 5 | 5 | ✓ | ✓ |
| 33 | App Auth Config | PUT /apps/:id/auth | 5 | 5 | ✓ | ✓ |
| 34 | App Historical Trends | GET /apps/:id/trends | 5 | 5 | ✓ | ✓ |
| 35 | Trigger Scan Endpoint | POST /apps/:id/scans (202 Accepted) | 5 | 5 | ✓ | ✓ |
| 36 | Scan History & Status | GET /apps/:id/scans, GET /scans/:id | 5 | 5 | ✓ | ✓ |
| 37 | Cancel Scan Endpoint | POST /scans/:id/cancel | 5 | 5 | ✓ | ✓ |
| 38 | Scan Findings List | GET /scans/:id/findings | 5 | 5 | ✓ | ✓ |
| 39 | Scan Comparison Endpoint| GET /scans/compare?base=&target= | 5 | 5 | ✓ | ✓ |
| 40 | Vuln Search & Filter | GET /vulns with query params & pagination | 5 | 5 | ✓ | ✓ |
| 41 | Vuln Detail Endpoint | GET /vulns/:id with evidence | 5 | 5 | ✓ | ✓ |
| 42 | Vuln Triage Endpoint | PATCH /vulns/:id status & severity | 5 | 5 | ✓ | ✓ |
| 43 | Bulk Vuln Update | POST /vulns/bulk-update | 5 | 5 | ✓ | ✓ |
| 44 | Vuln Remediation History| GET /vulns/:id/history | 5 | 5 | ✓ | ✓ |
| 45 | Add Triage Comment | POST /vulns/:id/comments | 5 | 5 | ✓ | ✓ |
| 46 | Dashboard Summary | GET /dashboard/summary | 5 | 5 | ✓ | ✓ |
| 47 | PDF Export Endpoints | GET /reports/scans/:id/pdf & /apps/:id/pdf | 5 | 5 | ✓ | ✓ |
| 48 | Live Scan Progress WS | WS /ws/v1/scans/:id?token= | 5 | 5 | ✓ | ✓ |
| 49 | Global Notifications WS | WS /ws/v1/notifications?token= | 5 | 5 | ✓ | ✓ |
| 50 | Scan Job Queue | Job enqueue/dequeue execution | 5 | 5 | ✓ | ✓ |
| 51 | ZAP Lifecycle Engine | Full pipeline execution lifecycle | 5 | 5 | ✓ | ✓ |
| 52 | Live Progress Reporting | Progress polling & pubsub broadcast | 5 | 5 | ✓ | ✓ |
| 53 | Ingestion & Diff Pipeline| Ingest -> Fingerprint -> Diff -> Persist | 5 | 5 | ✓ | ✓ |
| 54 | Atomic Persistence | Atomic transaction commit | 5 | 5 | ✓ | ✓ |
| 55 | Cron Scheduled Scans | Cron schedule parsing & dispatch | 5 | 5 | ✓ | ✓ |

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Description |
|---|----------|--------------------|-------------|
| 1 | Full SecOps Onboarding & Audit | F25, 27, 30, 32, 33, 35, 36, 38, 41, 42, 46, 47 | User logs in as Admin, creates app with auth headers, triggers scan, inspects findings, triages high severity vuln, views updated dashboard, and downloads PDF report. |
| 2 | Developer Triage & Remediation Verification | F27, 30, 35, 36, 38, 39, 42, 44, 45, 53 | Developer marks vuln as `InReview` with comments; subsequent scan verifies fix, diff engine transitions state to `Fixed`, remediation history captures timeline. |
| 3 | Regression Detection & Alerting | F10, 12, 35, 36, 39, 42, 53, 54 | Previously `Fixed` vulnerability reappears in a subsequent scan; diff engine detects regression and flags status as `Regressed` with updated severity. |
| 4 | API Key Automated CI/CD Pipeline | F26, 27, 31, 32, 35, 36, 38, 39 | CI/CD pipeline triggers scan using `X-API-Key`, polls status until completion, compares against baseline scan, and evaluates pass/fail quality gate based on severity counts. |
| 5 | RBAC & Multi-Role Isolation | F25, 27, 30, 32, 35, 42 | Auditor attempts triage (forbidden 403); Developer attempts app deletion (forbidden 403); Security Engineer triages vulns (200 OK); Admin manages users and API keys (200 OK). |

## Coverage Thresholds
- **Tier 1 (Feature Coverage)**: ≥5 test cases per feature (55 features × 5 = ≥275 test cases).
- **Tier 2 (Boundary & Corner Cases)**: ≥5 test cases per feature (55 features × 5 = ≥275 test cases).
- **Tier 3 (Cross-Feature Combinations)**: ≥55 pairwise and flow test cases.
- **Tier 4 (Real-World Application Scenarios)**: ≥5 realistic multi-feature workflow test cases.
- **Total Suite Minimum**: ≥610 test cases executed without live database or external services.
