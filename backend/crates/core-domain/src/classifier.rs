//! OWASP Top 10 (2021) Classifier
//!
//! Maps Common Weakness Enumeration (CWE) IDs and OWASP ZAP Plugin IDs
//! to standardized OWASP Top 10 (2021) categories, with deterministic fallback
//! to `A05:2021-Security Misconfiguration`.

pub const A01_BROKEN_ACCESS_CONTROL: &str = "A01:2021-Broken Access Control";
pub const A02_CRYPTOGRAPHIC_FAILURES: &str = "A02:2021-Cryptographic Failures";
pub const A03_INJECTION: &str = "A03:2021-Injection";
pub const A04_INSECURE_DESIGN: &str = "A04:2021-Insecure Design";
pub const A05_SECURITY_MISCONFIGURATION: &str = "A05:2021-Security Misconfiguration";
pub const A06_VULNERABLE_AND_OUTDATED_COMPONENTS: &str = "A06:2021-Vulnerable and Outdated Components";
pub const A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES: &str =
    "A07:2021-Identification and Authentication Failures";
pub const A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES: &str =
    "A08:2021-Software and Data Integrity Failures";
pub const A09_SECURITY_LOGGING_AND_MONITORING_FAILURES: &str =
    "A09:2021-Security Logging and Monitoring Failures";
pub const A10_SSRF: &str = "A10:2021-Server-Side Request Forgery (SSRF)";

/// Static mapping of CWE IDs to OWASP Top 10 (2021) categories.
pub static CWE_MAPPINGS: &[(i32, &str)] = &[
    // A01:2021 - Broken Access Control
    (22, A01_BROKEN_ACCESS_CONTROL),    // Path Traversal
    (23, A01_BROKEN_ACCESS_CONTROL),    // Relative Path Traversal
    (35, A01_BROKEN_ACCESS_CONTROL),    // Path Traversal: '.../...//'
    (59, A01_BROKEN_ACCESS_CONTROL),    // Improper Link Resolution Before File Access
    (200, A01_BROKEN_ACCESS_CONTROL),   // Exposure of Sensitive Information
    (201, A01_BROKEN_ACCESS_CONTROL),   // Insertion of Sensitive Info into Sent Data
    (219, A01_BROKEN_ACCESS_CONTROL),   // Sensitive Data Under Web Root
    (264, A01_BROKEN_ACCESS_CONTROL),   // Permissions, Privileges, and Access Controls
    (275, A01_BROKEN_ACCESS_CONTROL),   // Permission Issues
    (276, A01_BROKEN_ACCESS_CONTROL),   // Incorrect Default Permissions
    (284, A01_BROKEN_ACCESS_CONTROL),   // Improper Access Control
    (285, A01_BROKEN_ACCESS_CONTROL),   // Improper Authorization
    (352, A01_BROKEN_ACCESS_CONTROL),   // Cross-Site Request Forgery (CSRF)
    (359, A01_BROKEN_ACCESS_CONTROL),   // Exposure of Private Personal Information
    (377, A01_BROKEN_ACCESS_CONTROL),   // Insecure Temporary File
    (402, A01_BROKEN_ACCESS_CONTROL),   // Transmission of Private Resources into a New Sphere
    (425, A01_BROKEN_ACCESS_CONTROL),   // Direct Request ('Forced Browsing')
    (441, A01_BROKEN_ACCESS_CONTROL),   // Unintended Proxy or Intermediary
    (497, A01_BROKEN_ACCESS_CONTROL),   // Exposure of System Data to an Unauthorized Control Sphere
    (538, A01_BROKEN_ACCESS_CONTROL),   // Insertion of Sensitive Info into External File
    (540, A01_BROKEN_ACCESS_CONTROL),   // Inclusion of Sensitive Info in Source Code
    (548, A01_BROKEN_ACCESS_CONTROL),   // Exposure of Directory Listing
    (552, A01_BROKEN_ACCESS_CONTROL),   // Files or Directories Accessible to External Parties
    (566, A01_BROKEN_ACCESS_CONTROL),   // Authorization Bypass Through User-Controlled SQL Primary Key
    (601, A01_BROKEN_ACCESS_CONTROL),   // URL Redirection to Untrusted Site ('Open Redirect')
    (639, A01_BROKEN_ACCESS_CONTROL),   // Authorization Bypass Through User-Controlled Key (IDOR)
    (651, A01_BROKEN_ACCESS_CONTROL),   // Information Exposure Through Zone Exchange
    (668, A01_BROKEN_ACCESS_CONTROL),   // Exposure of Resource to Wrong Sphere
    (706, A01_BROKEN_ACCESS_CONTROL),   // Use of Incorrectly-Resolved Name or Reference
    (732, A01_BROKEN_ACCESS_CONTROL),   // Incorrect Permission Assignment for Critical Resource
    (862, A01_BROKEN_ACCESS_CONTROL),   // Missing Authorization
    (863, A01_BROKEN_ACCESS_CONTROL),   // Incorrect Authorization
    (913, A01_BROKEN_ACCESS_CONTROL),   // Improper Control of Dynamically-Managed Code Resources
    (922, A01_BROKEN_ACCESS_CONTROL),   // Insecure Storage of Sensitive Data
    (1275, A01_BROKEN_ACCESS_CONTROL),  // Sensitive Cookie with Improper SameSite Attribute

    // A02:2021 - Cryptographic Failures
    (261, A02_CRYPTOGRAPHIC_FAILURES),  // Weak Encoding for Password
    (296, A02_CRYPTOGRAPHIC_FAILURES),  // Improper Certificate Chain Following
    (310, A02_CRYPTOGRAPHIC_FAILURES),  // Cryptographic Issues
    (319, A02_CRYPTOGRAPHIC_FAILURES),  // Cleartext Transmission of Sensitive Information
    (321, A02_CRYPTOGRAPHIC_FAILURES),  // Use of Hard-coded Cryptographic Key
    (322, A02_CRYPTOGRAPHIC_FAILURES),  // Key Exchange without Entity Authentication
    (323, A02_CRYPTOGRAPHIC_FAILURES),  // Reusing a Nonce, Key Pair
    (324, A02_CRYPTOGRAPHIC_FAILURES),  // Expired Key
    (325, A02_CRYPTOGRAPHIC_FAILURES),  // Missing Required Cryptographic Step
    (326, A02_CRYPTOGRAPHIC_FAILURES),  // Inadequate Encryption Strength
    (327, A02_CRYPTOGRAPHIC_FAILURES),  // Broken or Risky Cryptographic Algorithm
    (328, A02_CRYPTOGRAPHIC_FAILURES),  // Use of Weak Hash
    (329, A02_CRYPTOGRAPHIC_FAILURES),  // Not Using Random IV with CBC Mode
    (330, A02_CRYPTOGRAPHIC_FAILURES),  // Insufficiently Random Values
    (331, A02_CRYPTOGRAPHIC_FAILURES),  // Insufficient Entropy
    (335, A02_CRYPTOGRAPHIC_FAILURES),  // PRNG Seed Issues
    (336, A02_CRYPTOGRAPHIC_FAILURES),  // Same PRNG Seed
    (337, A02_CRYPTOGRAPHIC_FAILURES),  // Predictable PRNG Seed
    (338, A02_CRYPTOGRAPHIC_FAILURES),  // Cryptographically Weak PRNG
    (340, A02_CRYPTOGRAPHIC_FAILURES),  // Generation of Predictable Numbers or Identifiers
    (347, A02_CRYPTOGRAPHIC_FAILURES),  // Improper Verification of Cryptographic Signature
    (523, A02_CRYPTOGRAPHIC_FAILURES),  // Unencrypted Transport of Confidential Information
    (757, A02_CRYPTOGRAPHIC_FAILURES),  // Selection of Less-Secure Algorithm ('Downgrade')
    (759, A02_CRYPTOGRAPHIC_FAILURES),  // Use of a One-Way Hash without a Salt
    (760, A02_CRYPTOGRAPHIC_FAILURES),  // Use of a One-Way Hash with a Predictable Salt
    (780, A02_CRYPTOGRAPHIC_FAILURES),  // Use of RSA Algorithm without OAEP
    (818, A02_CRYPTOGRAPHIC_FAILURES),  // Insufficiently Protected Credentials
    (916, A02_CRYPTOGRAPHIC_FAILURES),  // Use of Password Hash With Insufficient Computational Effort

    // A03:2021 - Injection
    (20, A03_INJECTION),                // Improper Input Validation
    (74, A03_INJECTION),                // Injection (Generic)
    (77, A03_INJECTION),                // Command Injection
    (78, A03_INJECTION),                // OS Command Injection
    (79, A03_INJECTION),                // Cross-Site Scripting (XSS)
    (80, A03_INJECTION),                // Basic XSS
    (83, A03_INJECTION),                // Script in Attributes XSS
    (87, A03_INJECTION),                // Alternate XSS Syntax
    (88, A03_INJECTION),                // Argument Injection
    (89, A03_INJECTION),                // SQL Injection
    (90, A03_INJECTION),                // LDAP Injection
    (91, A03_INJECTION),                // XML Injection / XPath Injection
    (93, A03_INJECTION),                // CRLF Injection
    (94, A03_INJECTION),                // Code Injection
    (95, A03_INJECTION),                // Eval Injection
    (96, A03_INJECTION),                // Static Code Injection
    (97, A03_INJECTION),                // Server-Side Includes (SSI) Injection
    (98, A03_INJECTION),                // PHP Remote File Inclusion
    (99, A03_INJECTION),                // Resource Injection
    (113, A03_INJECTION),               // HTTP Response Splitting
    (116, A03_INJECTION),               // Improper Encoding or Escaping of Output
    (138, A03_INJECTION),               // Improper Neutralization of Special Elements
    (184, A03_INJECTION),               // Incomplete Blacklist
    (470, A03_INJECTION),               // Use of Externally-Controlled Input to Select Classes
    (471, A03_INJECTION),               // Modification of Assumed-Immutable Data (MAID)
    (506, A03_INJECTION),               // Embedded Malicious Code
    (564, A03_INJECTION),               // SQL Injection: Hibernate
    (610, A03_INJECTION),               // Externally Controlled Reference to Resource
    (643, A03_INJECTION),               // XPath Injection
    (644, A03_INJECTION),               // Improper Neutralization of HTTP Headers for Scripting
    (652, A03_INJECTION),               // XQuery Injection
    (917, A03_INJECTION),               // Expression Language (EL) Injection
    (1336, A03_INJECTION),              // Improper Neutralization of Special Elements in Template Engine

    // A04:2021 - Insecure Design
    (73, A04_INSECURE_DESIGN),          // External Control of File Name or Path
    (183, A04_INSECURE_DESIGN),         // Permissive Whitelist
    (209, A04_INSECURE_DESIGN),         // Error Message Sensitive Information
    (213, A04_INSECURE_DESIGN),         // Exposure of Sensitive Information Through Metadata
    (235, A04_INSECURE_DESIGN),         // Handling of Extra Parameters
    (256, A04_INSECURE_DESIGN),         // Unprotected Storage of Credentials
    (257, A04_INSECURE_DESIGN),         // Storing Passwords in Recoverable Format
    (266, A04_INSECURE_DESIGN),         // Incorrect Privilege Assignment
    (267, A04_INSECURE_DESIGN),         // Privilege Defined With Unsafe Actions
    (269, A04_INSECURE_DESIGN),         // Improper Privilege Management
    (280, A04_INSECURE_DESIGN),         // Improper Handling of Insufficient Permissions
    (311, A04_INSECURE_DESIGN),         // Missing Encryption of Sensitive Data
    (312, A04_INSECURE_DESIGN),         // Cleartext Storage of Sensitive Information
    (313, A04_INSECURE_DESIGN),         // Cleartext Storage in File
    (316, A04_INSECURE_DESIGN),         // Cleartext Storage in Memory
    (419, A04_INSECURE_DESIGN),         // Unprotected Primary Channel
    (430, A04_INSECURE_DESIGN),         // Deployment of Wrong Handler
    (434, A04_INSECURE_DESIGN),         // Unrestricted File Upload
    (444, A04_INSECURE_DESIGN),         // Inconsistent HTTP Parsing (Request Smuggling)
    (451, A04_INSECURE_DESIGN),         // UI Redressing (Clickjacking)
    (472, A04_INSECURE_DESIGN),         // Parameter Pollution
    (501, A04_INSECURE_DESIGN),         // Trust Boundary Violation
    (522, A04_INSECURE_DESIGN),         // Insufficiently Protected Credentials
    (525, A04_INSECURE_DESIGN),         // Use of Web Browser Cache for Sensitive Data
    (539, A04_INSECURE_DESIGN),         // Information Exposure Through Persistent Cookie
    (579, A04_INSECURE_DESIGN),         // Non-serializable Object in Session
    (598, A04_INSECURE_DESIGN),         // Information Disclosure in GET Request
    (602, A04_INSECURE_DESIGN),         // Client-Side Security Enforcement
    (642, A04_INSECURE_DESIGN),         // External Control of Critical State Data
    (646, A04_INSECURE_DESIGN),         // Reliance on File-Based File Upload
    (650, A04_INSECURE_DESIGN),         // Trusting HTTP Permission Methods on System Level
    (653, A04_INSECURE_DESIGN),         // Improper Isolation or Compartmentalization
    (656, A04_INSECURE_DESIGN),         // Reliance on Security Through Obscurity
    (657, A04_INSECURE_DESIGN),         // Violation of Secure Design Principles
    (799, A04_INSECURE_DESIGN),         // Improper Control of Interaction Frequency
    (807, A04_INSECURE_DESIGN),         // Reliance on Untrusted Inputs in Security Decision
    (840, A04_INSECURE_DESIGN),         // Business Logic Errors
    (841, A04_INSECURE_DESIGN),         // Improper Enforcement of Behavioral Workflow
    (927, A04_INSECURE_DESIGN),         // Use of Implicit Intent for Sensitive Communication
    (1021, A04_INSECURE_DESIGN),        // Improper Restriction of Rendered UI (Clickjacking)
    (1173, A04_INSECURE_DESIGN),        // Improper Use of Validation Framework

    // A05:2021 - Security Misconfiguration
    (2, A05_SECURITY_MISCONFIGURATION), // Environment Misconfiguration
    (11, A05_SECURITY_MISCONFIGURATION),// ASP.NET Misconfiguration
    (13, A05_SECURITY_MISCONFIGURATION),// ASP.NET Misconfiguration: Password in Config
    (15, A05_SECURITY_MISCONFIGURATION),// External Configuration of Critical Parameters
    (16, A05_SECURITY_MISCONFIGURATION),// Configuration (Generic)
    (260, A05_SECURITY_MISCONFIGURATION),// Password in Configuration File
    (315, A05_SECURITY_MISCONFIGURATION),// Cleartext Storage of Sensitive Info in Cookie
    (520, A05_SECURITY_MISCONFIGURATION),// .NET Misconfiguration: Use of Impersonation
    (526, A05_SECURITY_MISCONFIGURATION),// Exposure of Sensitive Info Through Environmental Variables
    (537, A05_SECURITY_MISCONFIGURATION),// Java Runtime Error Information Disclosure
    (541, A05_SECURITY_MISCONFIGURATION),// Sensitive Information in Include File
    (547, A05_SECURITY_MISCONFIGURATION),// Hardcoded Security-relevant Constants
    (611, A05_SECURITY_MISCONFIGURATION),// Improper Restriction of XML External Entity Reference (XXE)
    (614, A05_SECURITY_MISCONFIGURATION),// Sensitive Cookie in HTTPS Without Secure Flag
    (756, A05_SECURITY_MISCONFIGURATION),// Missing Custom Error Page
    (776, A05_SECURITY_MISCONFIGURATION),// Improper Restriction of Recursive XML Entity Expansion
    (942, A05_SECURITY_MISCONFIGURATION),// Overly Permissive CORS Policy
    (1004, A05_SECURITY_MISCONFIGURATION),// Sensitive Cookie Without HttpOnly Flag
    (1032, A05_SECURITY_MISCONFIGURATION),// Security Alert Not Monitored
    (1174, A05_SECURITY_MISCONFIGURATION),// ASP.NET ValidateRequest Disabled
    (1299, A05_SECURITY_MISCONFIGURATION),// Missing Protection Mechanism for Alternate Hardware Interface

    // A06:2021 - Vulnerable and Outdated Components
    (937, A06_VULNERABLE_AND_OUTDATED_COMPONENTS),  // Using Components with Known Vulnerabilities
    (1026, A06_VULNERABLE_AND_OUTDATED_COMPONENTS), // Weaknesses in Third-Party Components
    (1035, A06_VULNERABLE_AND_OUTDATED_COMPONENTS), // Enclosure of Vulnerable Third Party
    (1104, A06_VULNERABLE_AND_OUTDATED_COMPONENTS), // Use of Unmaintained Third Party Components

    // A07:2021 - Identification and Authentication Failures
    (255, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Credentials Management
    (259, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Use of Hard-coded Password
    (287, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Improper Authentication
    (288, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Authentication Bypass Using Alternate Path
    (290, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Authentication Bypass by Spoofing
    (294, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Authentication Bypass by Capture-replay
    (295, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Improper Certificate Validation
    (297, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Improper Hostname Validation in Certificate
    (300, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Channel Accessible by Non-Endpoint
    (302, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Authentication Bypass by Assumed-Immutable Data
    (304, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Missing Critical Step in Authentication
    (306, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Missing Authentication for Critical Function
    (307, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Improper Restriction of Excessive Attempts
    (346, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Origin Validation Error
    (384, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Session Fixation
    (521, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Weak Password Requirements
    (613, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Insufficient Session Expiration
    (620, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Unverified Password Reset
    (640, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Weak Password Recovery Mechanism
    (798, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Use of Hard-coded Credentials
    (940, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Improper Verification of Source Digest
    (1216, A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES),// Locking Model Error

    // A08:2021 - Software and Data Integrity Failures
    (345, A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES), // Insufficient Verification of Data Authenticity
    (353, A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES), // Missing Support for Integrity Check
    (426, A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES), // Untrusted Search Path
    (494, A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES), // Download of Code Without Integrity Check
    (502, A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES), // Deserialization of Untrusted Data
    (565, A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES), // Reliance on Cookies without Integrity Checking
    (784, A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES), // Reliance on Cookies in Stateless Protocol
    (829, A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES), // Inclusion of Functionality from Untrusted Sphere
    (830, A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES), // Inclusion of Web Functionality from Untrusted Source
    (915, A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES), // Improper Dynamic Modification of Object Attributes

    // A09:2021 - Security Logging and Monitoring Failures
    (117, A09_SECURITY_LOGGING_AND_MONITORING_FAILURES), // Improper Output Neutralization for Logs
    (223, A09_SECURITY_LOGGING_AND_MONITORING_FAILURES), // Omission of Security-relevant Information
    (532, A09_SECURITY_LOGGING_AND_MONITORING_FAILURES), // Insertion of Sensitive Information into Log File
    (778, A09_SECURITY_LOGGING_AND_MONITORING_FAILURES), // Insufficient Logging
    (779, A09_SECURITY_LOGGING_AND_MONITORING_FAILURES), // Logging of Excessive Data

    // A10:2021 - Server-Side Request Forgery (SSRF)
    (918, A10_SSRF),     // Server-Side Request Forgery (SSRF)
];

/// Static mapping of ZAP Alert Plugin IDs to OWASP Top 10 (2021) categories.
pub static ZAP_PLUGIN_MAPPINGS: &[(&str, &str)] = &[
    // A01:2021 - Broken Access Control
    ("0", A01_BROKEN_ACCESS_CONTROL),       // Directory Browsing
    ("10045", A01_BROKEN_ACCESS_CONTROL),   // Source Code Disclosure - /WEB-INF
    ("10058", A01_BROKEN_ACCESS_CONTROL),   // GET for POST
    ("10095", A01_BROKEN_ACCESS_CONTROL),   // Backup File Disclosure
    ("10202", A01_BROKEN_ACCESS_CONTROL),   // Absence of Anti-CSRF Tokens
    ("40008", A01_BROKEN_ACCESS_CONTROL),   // Parameter Tampering
    ("40011", A01_BROKEN_ACCESS_CONTROL),   // Relative Path Traversal
    ("40026", A01_BROKEN_ACCESS_CONTROL),   // Cross Site Scripting (DOM Based) / Client Access
    ("40028", A01_BROKEN_ACCESS_CONTROL),   // Open Redirect
    ("40035", A01_BROKEN_ACCESS_CONTROL),   // Hidden File Finder

    // A02:2021 - Cryptographic Failures
    ("10011", A02_CRYPTOGRAPHIC_FAILURES),  // Cookie Without Secure Flag
    ("10023", A02_CRYPTOGRAPHIC_FAILURES),  // Debug Error Messages / Information Exposure
    ("10024", A02_CRYPTOGRAPHIC_FAILURES),  // Sensitive Information in URL
    ("10025", A02_CRYPTOGRAPHIC_FAILURES),  // Sensitive Information in Referrer
    ("10035", A02_CRYPTOGRAPHIC_FAILURES),  // Strict-Transport-Security Header Not Set
    ("10036", A02_CRYPTOGRAPHIC_FAILURES),  // Server Leaks Information via "Server" Header
    ("10041", A02_CRYPTOGRAPHIC_FAILURES),  // HTTP to HTTPS Insecure Transition
    ("10042", A02_CRYPTOGRAPHIC_FAILURES),  // HTTPS to HTTP Insecure Transition
    ("10044", A02_CRYPTOGRAPHIC_FAILURES),  // Big Redirect Detected
    ("10108", A02_CRYPTOGRAPHIC_FAILURES),  // Reverse Tabnabbing
    ("20019", A02_CRYPTOGRAPHIC_FAILURES),  // External Redirect
    ("90011", A02_CRYPTOGRAPHIC_FAILURES),  // Weak Hash Algorithm

    // A03:2021 - Injection
    ("40003", A03_INJECTION),               // CR-LF Injection
    ("40009", A03_INJECTION),               // Server Side Code Injection
    ("40012", A03_INJECTION),               // Cross Site Scripting (Reflected)
    ("40014", A03_INJECTION),               // Cross Site Scripting (Persistent)
    ("40016", A03_INJECTION),               // Cross Site Scripting (Persistent) - Prime
    ("40017", A03_INJECTION),               // Cross Site Scripting (Persistent) - Spider
    ("40018", A03_INJECTION),               // SQL Injection (Hypersonic / Time Based)
    ("40019", A03_INJECTION),               // SQL Injection - MySQL
    ("40020", A03_INJECTION),               // SQL Injection - Hypersonic SQL
    ("40021", A03_INJECTION),               // SQL Injection - Oracle
    ("40022", A03_INJECTION),               // SQL Injection - PostgreSQL
    ("40024", A03_INJECTION),               // SQL Injection - SQLite
    ("40027", A03_INJECTION),               // SQL Injection - MsSQL
    ("90018", A03_INJECTION),               // Advanced SQL Injection
    ("90019", A03_INJECTION),               // Server Side Code Injection
    ("90020", A03_INJECTION),               // Remote OS Command Injection
    ("90021", A03_INJECTION),               // XPath Injection

    // A04:2021 - Insecure Design
    ("10020", A04_INSECURE_DESIGN),         // Anti-clickjacking Header (X-Frame-Options)
    ("40029", A04_INSECURE_DESIGN),         // Trace.axd Information Disclosure
    ("40038", A04_INSECURE_DESIGN),         // Banned HTTP Methods

    // A05:2021 - Security Misconfiguration
    ("10010", A05_SECURITY_MISCONFIGURATION), // Cookie No HttpOnly Flag
    ("10015", A05_SECURITY_MISCONFIGURATION), // Incomplete Cache-Control
    ("10017", A05_SECURITY_MISCONFIGURATION), // Cross-Domain JavaScript Source File Inclusion
    ("10019", A05_SECURITY_MISCONFIGURATION), // Content-Type Header Missing
    ("10021", A05_SECURITY_MISCONFIGURATION), // X-Content-Type-Options Header Missing
    ("10027", A05_SECURITY_MISCONFIGURATION), // Information Disclosure - Suspicious Comments
    ("10032", A05_SECURITY_MISCONFIGURATION), // Viewstate without MAC
    ("10037", A05_SECURITY_MISCONFIGURATION), // Server Leaks Version via Server Header
    ("10038", A05_SECURITY_MISCONFIGURATION), // Content Security Policy (CSP) Header Not Set
    ("10049", A05_SECURITY_MISCONFIGURATION), // Content-Type Header Missing
    ("10054", A05_SECURITY_MISCONFIGURATION), // Cookie without SameSite Attribute
    ("10055", A05_SECURITY_MISCONFIGURATION), // CSP: Wildcard Directive
    ("10056", A05_SECURITY_MISCONFIGURATION), // X-Debug-Token Information Leak
    ("10062", A05_SECURITY_MISCONFIGURATION), // PII Disclosure
    ("90022", A05_SECURITY_MISCONFIGURATION), // Application Error Disclosure
    ("90028", A05_SECURITY_MISCONFIGURATION), // Insecure HTTP Method

    // A06:2021 - Vulnerable and Outdated Components
    ("10003", A06_VULNERABLE_AND_OUTDATED_COMPONENTS), // Vulnerable JS Library (Retire.js)
    ("10052", A06_VULNERABLE_AND_OUTDATED_COMPONENTS), // Outdated Component (Apache Struts)
    ("90033", A06_VULNERABLE_AND_OUTDATED_COMPONENTS), // Vulnerable Third Party Libraries

    // A07:2021 - Identification and Authentication Failures
    ("10057", A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Username Hash Found
    ("40013", A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Session Fixation
    ("40015", A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Password Field With Autocomplete
    ("90030", A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES), // Weak Authentication Method

    // A08:2021 - Software and Data Integrity Failures
    ("10098", A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES), // Cross-Domain Misconfiguration
    ("90025", A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES), // Insecure Deserialization
    ("90026", A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES), // Subresource Integrity (SRI) Missing

    // A09:2021 - Security Logging and Monitoring Failures
    ("10099", A09_SECURITY_LOGGING_AND_MONITORING_FAILURES), // Insufficient Logging / Log Injection

    // A10:2021 - Server-Side Request Forgery (SSRF)
    ("40034", A10_SSRF),                                    // Server Side Request Forgery (SSRF)
    ("40046", A10_SSRF),                                    // Server Side Request Forgery (SSRF)
    ("90034", A10_SSRF),                                    // Cloud Metadata Attack / SSRF
];

/// Classify a finding into an OWASP Top 10 (2021) category.
///
/// Precedence:
/// 1. `cwe_id` (if present and recognized).
/// 2. `zap_plugin_id` (trimmed, if recognized).
/// 3. Fallback to `A05:2021-Security Misconfiguration`.
pub fn classify_owasp(cwe_id: Option<i32>, zap_plugin_id: &str) -> &'static str {
    // 1. Primary: Evaluate CWE ID if present
    if let Some(cwe) = cwe_id {
        for &(id, category) in CWE_MAPPINGS {
            if id == cwe {
                return category;
            }
        }
    }

    // 2. Secondary: Evaluate ZAP Plugin ID (trimmed)
    let clean_plugin = zap_plugin_id.trim();
    if !clean_plugin.is_empty() {
        for &(id, category) in ZAP_PLUGIN_MAPPINGS {
            if id == clean_plugin {
                return category;
            }
        }
    }

    // 3. Fallback: Security Misconfiguration
    A05_SECURITY_MISCONFIGURATION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_canonical_format() {
        assert_eq!(A01_BROKEN_ACCESS_CONTROL, "A01:2021-Broken Access Control");
        assert_eq!(A02_CRYPTOGRAPHIC_FAILURES, "A02:2021-Cryptographic Failures");
        assert_eq!(A03_INJECTION, "A03:2021-Injection");
        assert_eq!(A04_INSECURE_DESIGN, "A04:2021-Insecure Design");
        assert_eq!(A05_SECURITY_MISCONFIGURATION, "A05:2021-Security Misconfiguration");
        assert_eq!(A06_VULNERABLE_AND_OUTDATED_COMPONENTS, "A06:2021-Vulnerable and Outdated Components");
        assert_eq!(A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES, "A07:2021-Identification and Authentication Failures");
        assert_eq!(A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES, "A08:2021-Software and Data Integrity Failures");
        assert_eq!(A09_SECURITY_LOGGING_AND_MONITORING_FAILURES, "A09:2021-Security Logging and Monitoring Failures");
        assert_eq!(A10_SSRF, "A10:2021-Server-Side Request Forgery (SSRF)");
    }

    #[test]
    fn test_classify_all_owasp_cwe_mappings() {
        // A01
        assert_eq!(classify_owasp(Some(22), ""), A01_BROKEN_ACCESS_CONTROL);
        assert_eq!(classify_owasp(Some(352), ""), A01_BROKEN_ACCESS_CONTROL);
        assert_eq!(classify_owasp(Some(639), ""), A01_BROKEN_ACCESS_CONTROL);

        // A02
        assert_eq!(classify_owasp(Some(319), ""), A02_CRYPTOGRAPHIC_FAILURES);
        assert_eq!(classify_owasp(Some(327), ""), A02_CRYPTOGRAPHIC_FAILURES);

        // A03
        assert_eq!(classify_owasp(Some(89), ""), A03_INJECTION);
        assert_eq!(classify_owasp(Some(79), ""), A03_INJECTION);
        assert_eq!(classify_owasp(Some(78), ""), A03_INJECTION);

        // A04
        assert_eq!(classify_owasp(Some(451), ""), A04_INSECURE_DESIGN);
        assert_eq!(classify_owasp(Some(1021), ""), A04_INSECURE_DESIGN);

        // A05
        assert_eq!(classify_owasp(Some(942), ""), A05_SECURITY_MISCONFIGURATION);
        assert_eq!(classify_owasp(Some(611), ""), A05_SECURITY_MISCONFIGURATION);

        // A06
        assert_eq!(classify_owasp(Some(937), ""), A06_VULNERABLE_AND_OUTDATED_COMPONENTS);
        assert_eq!(classify_owasp(Some(1035), ""), A06_VULNERABLE_AND_OUTDATED_COMPONENTS);

        // A07
        assert_eq!(classify_owasp(Some(287), ""), A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES);
        assert_eq!(classify_owasp(Some(384), ""), A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES);

        // A08
        assert_eq!(classify_owasp(Some(502), ""), A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES);
        assert_eq!(classify_owasp(Some(353), ""), A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES);

        // A09
        assert_eq!(classify_owasp(Some(117), ""), A09_SECURITY_LOGGING_AND_MONITORING_FAILURES);
        assert_eq!(classify_owasp(Some(778), ""), A09_SECURITY_LOGGING_AND_MONITORING_FAILURES);

        // A10
        assert_eq!(classify_owasp(Some(918), ""), A10_SSRF);
    }

    #[test]
    fn test_classify_all_owasp_zap_plugin_mappings() {
        assert_eq!(classify_owasp(None, "0"), A01_BROKEN_ACCESS_CONTROL);
        assert_eq!(classify_owasp(None, "10202"), A01_BROKEN_ACCESS_CONTROL);
        assert_eq!(classify_owasp(None, "10035"), A02_CRYPTOGRAPHIC_FAILURES);
        assert_eq!(classify_owasp(None, "40018"), A03_INJECTION);
        assert_eq!(classify_owasp(None, "40012"), A03_INJECTION);
        assert_eq!(classify_owasp(None, "10020"), A04_INSECURE_DESIGN);
        assert_eq!(classify_owasp(None, "10038"), A05_SECURITY_MISCONFIGURATION);
        assert_eq!(classify_owasp(None, "10003"), A06_VULNERABLE_AND_OUTDATED_COMPONENTS);
        assert_eq!(classify_owasp(None, "40013"), A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES);
        assert_eq!(classify_owasp(None, "90025"), A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES);
        assert_eq!(classify_owasp(None, "10099"), A09_SECURITY_LOGGING_AND_MONITORING_FAILURES);
        assert_eq!(classify_owasp(None, "40046"), A10_SSRF);
    }

    #[test]
    fn test_classify_cwe_precedence_over_plugin() {
        // CWE 89 is SQLi (A03), plugin 10038 is CSP (A05)
        // CWE must take precedence!
        assert_eq!(classify_owasp(Some(89), "10038"), A03_INJECTION);
    }

    #[test]
    fn test_classify_fallback_to_plugin_when_cwe_unknown() {
        // CWE 999999 is unknown, plugin 40018 is SQLi (A03)
        assert_eq!(classify_owasp(Some(999999), "40018"), A03_INJECTION);
    }

    #[test]
    fn test_classify_fallback_to_a05_default() {
        // Unknown CWE and unknown plugin
        assert_eq!(classify_owasp(None, "unknown_9999"), A05_SECURITY_MISCONFIGURATION);
        assert_eq!(classify_owasp(Some(-1), "nonexistent"), A05_SECURITY_MISCONFIGURATION);
        assert_eq!(classify_owasp(None, ""), A05_SECURITY_MISCONFIGURATION);
    }

    #[test]
    fn test_classify_whitespace_trimming() {
        assert_eq!(classify_owasp(None, "  40012  "), A03_INJECTION);
        assert_eq!(classify_owasp(None, "\t10038\n"), A05_SECURITY_MISCONFIGURATION);
    }
}
