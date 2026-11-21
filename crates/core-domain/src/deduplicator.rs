//! URL Path Normalizer & Deterministic Finding Deduplicator
//!
//! Implements RFC 3986 URL path normalization and deterministic SHA-256
//! finding fingerprinting based on canonical `(app_id, zap_plugin_id, normalized_path, param, method)`.

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Decode a 2-digit hex string into a byte if valid hex.
fn hex_to_byte(h1: u8, h2: u8) -> Option<u8> {
    let d1 = match h1 {
        b'0'..=b'9' => h1 - b'0',
        b'a'..=b'f' => h1 - b'a' + 10,
        b'A'..=b'F' => h1 - b'A' + 10,
        _ => return None,
    };
    let d2 = match h2 {
        b'0'..=b'9' => h2 - b'0',
        b'a'..=b'f' => h2 - b'a' + 10,
        b'A'..=b'F' => h2 - b'A' + 10,
        _ => return None,
    };
    Some((d1 << 4) | d2)
}

/// Checks if byte is an RFC 3986 unreserved character:
/// ALPHA (%41-%5A, %61-%7A), DIGIT (%30-%39), hyphen (%2D), period (%2E),
/// underscore (%5F), or tilde (%7E).
fn is_unreserved(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
}

/// Normalizes percent-encoded octets in a path string according to RFC 3986 §6.2.2.2.
/// Decodes unreserved characters and uppercases remaining percent-encoded triplets.
fn normalize_percent_encoding(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = Vec::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'%' && i + 2 < len {
            if let Some(decoded) = hex_to_byte(bytes[i + 1], bytes[i + 2]) {
                if is_unreserved(decoded) {
                    out.push(decoded);
                } else {
                    out.push(b'%');
                    out.push(bytes[i + 1].to_ascii_uppercase());
                    out.push(bytes[i + 2].to_ascii_uppercase());
                }
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// Normalize a raw URL or path string according to RFC 3986 §5.2.4 and §6.2.
///
/// Steps:
/// 1. Trims whitespace. Returns `"/"` if empty.
/// 2. Strips protocol/scheme (`http://`, `https://`, etc.) and authority/host.
/// 3. Truncates query strings (`?...`) and hash fragments (`#...`).
/// 4. Normalizes percent encoding (decodes unreserved characters, capitalizes hex).
/// 5. Resolves dot segments (`.` and `..`) with root clamping.
/// 6. Collapses redundant slashes and strips trailing slashes (except for `"/"`).
pub fn normalize_url_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "/".to_string();
    }

    // 1. Strip scheme and authority if present
    let path_candidate = if let Some(scheme_pos) = trimmed.find("://") {
        let after_scheme = &trimmed[scheme_pos + 3..];
        if let Some(slash_pos) = after_scheme.find('/') {
            &after_scheme[slash_pos..]
        } else if let Some(delim_pos) = after_scheme.find(['?', '#']) {
            &after_scheme[delim_pos..]
        } else {
            "/"
        }
    } else if let Some(after_slash) = trimmed.strip_prefix("//") {
        if let Some(slash_pos) = after_slash.find('/') {
            &after_slash[slash_pos..]
        } else if let Some(delim_pos) = after_slash.find(['?', '#']) {
            &after_slash[delim_pos..]
        } else {
            "/"
        }
    } else {
        trimmed
    };

    // 2. Truncate query and fragment
    let without_query = match path_candidate.find(['?', '#']) {
        Some(pos) => &path_candidate[..pos],
        None => path_candidate,
    };

    // 3. Normalize percent-encoding
    let decoded = normalize_percent_encoding(without_query);

    // 4. Dot-segment resolution (RFC 3986 §5.2.4)
    let mut stack: Vec<&str> = Vec::new();
    for segment in decoded.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        } else if segment == ".." {
            stack.pop();
        } else {
            stack.push(segment);
        }
    }

    if stack.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", stack.join("/"))
    }
}

/// Generates a deterministic 64-character lowercase hexadecimal SHA-256 fingerprint
/// representing a vulnerability finding identity across scans.
///
/// Pre-image format:
/// `{app_id}:{zap_plugin_id}:{normalized_path}:{param_name}:{method}`
pub fn generate_fingerprint(
    app_id: &Uuid,
    zap_plugin_id: &str,
    raw_url_or_path: &str,
    param_name: Option<&str>,
    method: &str,
) -> String {
    let normalized_path = normalize_url_path(raw_url_or_path);
    let clean_plugin = zap_plugin_id.trim();
    let clean_param = param_name.unwrap_or("").trim();
    let clean_method = method.trim().to_uppercase();

    let payload = format!(
        "{}:{}:{}:{}:{}",
        app_id, clean_plugin, normalized_path, clean_param, clean_method
    );

    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let result = hasher.finalize();
    format!("{:064x}", result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_full_url() {
        assert_eq!(
            normalize_url_path("https://app.example.com:8443/api/v1/users"),
            "/api/v1/users"
        );
        assert_eq!(
            normalize_url_path("http://localhost:3000/dashboard"),
            "/dashboard"
        );
    }

    #[test]
    fn test_normalize_query_and_fragment() {
        assert_eq!(
            normalize_url_path("/search?query=xss&sort=asc#results"),
            "/search"
        );
        assert_eq!(
            normalize_url_path("https://example.com/items?page=1#top"),
            "/items"
        );
        assert_eq!(
            normalize_url_path("https://example.com?page=1#top"),
            "/"
        );
    }

    #[test]
    fn test_normalize_dot_segments() {
        assert_eq!(normalize_url_path("/a/b/../c/./d"), "/a/c/d");
        assert_eq!(
            normalize_url_path("/api/v1/../../images/./logo.png"),
            "/images/logo.png"
        );
        assert_eq!(normalize_url_path("/../../../admin"), "/admin");
        assert_eq!(normalize_url_path("a/b/c/../../d"), "/a/d");
    }

    #[test]
    fn test_normalize_slashes() {
        assert_eq!(
            normalize_url_path("////api///v1////users//"),
            "/api/v1/users"
        );
        assert_eq!(
            normalize_url_path("https://example.com////api///v1//users//"),
            "/api/v1/users"
        );
    }

    #[test]
    fn test_normalize_root() {
        assert_eq!(normalize_url_path(""), "/");
        assert_eq!(normalize_url_path("   "), "/");
        assert_eq!(normalize_url_path("/"), "/");
        assert_eq!(normalize_url_path("https://example.com"), "/");
        assert_eq!(normalize_url_path("https://example.com/"), "/");
        assert_eq!(normalize_url_path("//example.com"), "/");
        assert_eq!(normalize_url_path("//example.com/"), "/");
    }

    #[test]
    fn test_normalize_percent_encoding() {
        // %7E -> ~, %41%42%43 -> ABC
        assert_eq!(
            normalize_url_path("/api/%7Euser/%41%42%43"),
            "/api/~user/ABC"
        );
        // %2f -> %2F (reserved char, hex uppercase)
        assert_eq!(
            normalize_url_path("/path/%2fname"),
            "/path/%2Fname"
        );
    }

    #[test]
    fn test_normalize_complex_traversal_with_query_fragment() {
        assert_eq!(
            normalize_url_path("https://example.com:8443/api/v1/../../static/./images/../style.css?v=2#top"),
            "/static/style.css"
        );
    }

    #[test]
    fn test_generate_fingerprint_deterministic() {
        let app_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let fp1 = generate_fingerprint(&app_id, "40018", "/api/v1/users", Some("id"), "GET");
        let fp2 = generate_fingerprint(&app_id, "40018", "/api/v1/users", Some("id"), "GET");
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64);
        assert!(fp1.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn test_generate_fingerprint_param_none_vs_empty() {
        let app_id = Uuid::new_v4();
        let fp_none = generate_fingerprint(&app_id, "10038", "/login", None, "POST");
        let fp_empty = generate_fingerprint(&app_id, "10038", "/login", Some(""), "POST");
        let fp_spaces = generate_fingerprint(&app_id, "10038", "/login", Some("   "), "POST");
        assert_eq!(fp_none, fp_empty);
        assert_eq!(fp_none, fp_spaces);
    }

    #[test]
    fn test_generate_fingerprint_case_insensitive_method() {
        let app_id = Uuid::new_v4();
        let fp_lower = generate_fingerprint(&app_id, "40012", "/search", Some("q"), "get");
        let fp_upper = generate_fingerprint(&app_id, "40012", "/search", Some("q"), "GET");
        assert_eq!(fp_lower, fp_upper);
    }

    #[test]
    fn test_generate_fingerprint_url_trailing_slash_insensitivity() {
        let app_id = Uuid::new_v4();
        let fp1 = generate_fingerprint(&app_id, "40018", "https://example.com/api/v1/users", Some("id"), "POST");
        let fp2 = generate_fingerprint(&app_id, "40018", "https://example.com/api/v1/users/", Some("id"), "POST");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_generate_fingerprint_collision_resistance() {
        let app_id1 = Uuid::new_v4();
        let app_id2 = Uuid::new_v4();
        let fp1 = generate_fingerprint(&app_id1, "40018", "/api/v1/users", Some("id"), "GET");
        let fp2 = generate_fingerprint(&app_id2, "40018", "/api/v1/users", Some("id"), "GET");
        let fp3 = generate_fingerprint(&app_id1, "40019", "/api/v1/users", Some("id"), "GET");
        let fp4 = generate_fingerprint(&app_id1, "40018", "/api/v1/users", Some("name"), "GET");
        let fp5 = generate_fingerprint(&app_id1, "40018", "/api/v1/users", Some("id"), "POST");

        assert_ne!(fp1, fp2);
        assert_ne!(fp1, fp3);
        assert_ne!(fp1, fp4);
        assert_ne!(fp1, fp5);
    }
}
