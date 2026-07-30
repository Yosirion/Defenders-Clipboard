//! Unit tests for `api.rs`. Being a child module (`api::tests`) it can reach
//! private helpers (`is_ipv4`, `is_hash_like`, ...) via `use super::*`, unlike
//! the black-box integration tests under `tests/` which only see `pub` items.
use super::*;

// =====================================================================
// classify_indicator — end-to-end classification
// =====================================================================

// --- IPv4 ---
#[test]
fn classifies_public_ipv4_as_ip() {
    assert_eq!(classify_indicator("8.8.8.8"), IndicatorType::Ip);
}

#[test]
fn classifies_private_ipv4_as_internal() {
    assert_eq!(classify_indicator("192.168.1.10"), IndicatorType::InternalIp);
    assert_eq!(classify_indicator("10.0.0.1"), IndicatorType::InternalIp);
    assert_eq!(classify_indicator("172.16.5.5"), IndicatorType::InternalIp);
}

#[test]
fn classifies_loopback_ipv4_as_internal() {
    assert_eq!(classify_indicator("127.0.0.1"), IndicatorType::InternalIp);
}

#[test]
fn rejects_out_of_range_ipv4_octets() {
    // 999 is not a valid octet, so this must NOT be classified as an IP.
    assert_ne!(classify_indicator("999.1.1.1"), IndicatorType::Ip);
    assert_ne!(classify_indicator("999.1.1.1"), IndicatorType::InternalIp);
}

#[test]
fn rejects_ipv4_with_leading_zero_as_ip() {
    // "01" is not the canonical decimal form of the octet -> is_ipv4 must reject it.
    assert_ne!(classify_indicator("192.168.001.1"), IndicatorType::Ip);
    assert_ne!(classify_indicator("192.168.001.1"), IndicatorType::InternalIp);
}

// --- IPv6 ---
#[test]
fn classifies_public_ipv6_as_ip() {
    assert_eq!(classify_indicator("2001:4860:4860::8888"), IndicatorType::Ip);
}

#[test]
fn classifies_loopback_ipv6_as_internal() {
    assert_eq!(classify_indicator("::1"), IndicatorType::InternalIp);
}

#[test]
fn classifies_unspecified_ipv6_as_internal() {
    assert_eq!(classify_indicator("::"), IndicatorType::InternalIp);
}

#[test]
fn classifies_unique_local_ipv6_as_internal() {
    assert_eq!(classify_indicator("fc00::1"), IndicatorType::InternalIp);
    assert_eq!(classify_indicator("fd12:3456:789a::1"), IndicatorType::InternalIp);
}

#[test]
fn classifies_link_local_ipv6_as_internal() {
    assert_eq!(classify_indicator("fe80::1"), IndicatorType::InternalIp);
}

// --- Hashes ---
#[test]
fn classifies_md5_sha1_sha256_as_hash() {
    assert_eq!(classify_indicator(&"a".repeat(32)), IndicatorType::Hash);
    assert_eq!(classify_indicator(&"a".repeat(40)), IndicatorType::Hash);
    assert_eq!(classify_indicator(&"a".repeat(64)), IndicatorType::Hash);
}

#[test]
fn rejects_non_hex_string_of_hash_length_as_hash() {
    assert_ne!(classify_indicator(&"z".repeat(32)), IndicatorType::Hash);
}

#[test]
fn rejects_wrong_length_hex_string_as_hash() {
    // 33 hex chars: one off from a valid MD5 length.
    assert_ne!(classify_indicator(&"a".repeat(33)), IndicatorType::Hash);
}

// --- Domains & URLs ---
#[test]
fn classifies_domain() {
    assert_eq!(classify_indicator("evil-domain.com"), IndicatorType::Domain);
}

#[test]
fn classifies_url_with_scheme() {
    assert_eq!(classify_indicator("https://evil-domain.com/payload.exe"), IndicatorType::Url);
}

#[test]
fn classifies_ftp_url_with_scheme() {
    assert_eq!(classify_indicator("ftp://files.evil-domain.com/a.zip"), IndicatorType::Url);
}

#[test]
fn classifies_url_missing_scheme_as_url_fallback() {
    assert_eq!(classify_indicator("evil-domain.com/login.php"), IndicatorType::Url);
}

#[test]
fn classifies_empty_or_unknown_as_unknown() {
    assert_eq!(classify_indicator(""), IndicatorType::Unknown);
    assert_eq!(classify_indicator("   "), IndicatorType::Unknown);
    assert_eq!(classify_indicator("just some random text"), IndicatorType::Unknown);
}

// =====================================================================
// Private helper functions
// =====================================================================

#[test]
fn is_ipv4_accepts_valid_dotted_quad() {
    assert!(is_ipv4("1.2.3.4"));
    assert!(is_ipv4("255.255.255.255"));
    assert!(is_ipv4("0.0.0.0"));
}

#[test]
fn is_ipv4_rejects_wrong_segment_count() {
    assert!(!is_ipv4("1.2.3"));
    assert!(!is_ipv4("1.2.3.4.5"));
}

#[test]
fn is_ipv4_rejects_leading_zeros_and_empty_segments() {
    assert!(!is_ipv4("01.2.3.4"));
    assert!(!is_ipv4("1..3.4"));
}

#[test]
fn is_hash_like_accepts_only_exact_hex_lengths() {
    assert!(is_hash_like(&"f".repeat(32)));
    assert!(is_hash_like(&"f".repeat(40)));
    assert!(is_hash_like(&"f".repeat(64)));
    assert!(!is_hash_like(&"f".repeat(31)));
    assert!(!is_hash_like(&"g".repeat(32))); // 'g' is not a hex digit
}

#[test]
fn is_domain_like_validates_charset_and_shape() {
    assert!(is_domain_like("sub.evil-domain.com"));
    assert!(!is_domain_like("no dots here"));
    assert!(!is_domain_like("has a space.com"));
    assert!(!is_domain_like("user@domain.com"));
    assert!(!is_domain_like("nodothere"));
}

#[test]
fn is_ipv6_internal_flags_loopback_unspecified_ula_and_link_local() {
    assert!(is_ipv6_internal(&"::1".parse().unwrap()));
    assert!(is_ipv6_internal(&"::".parse().unwrap()));
    assert!(is_ipv6_internal(&"fc00::1".parse().unwrap()));
    assert!(is_ipv6_internal(&"fd00::1".parse().unwrap()));
    assert!(is_ipv6_internal(&"fe80::1".parse().unwrap()));
}

#[test]
fn is_ipv6_internal_does_not_flag_public_addresses() {
    assert!(!is_ipv6_internal(&"2001:4860:4860::8888".parse().unwrap()));
    // fe00:: is one bit short of the fe80::/10 link-local range -> must be public.
    assert!(!is_ipv6_internal(&"fe00::1".parse().unwrap()));
}

// =====================================================================
// vt_lookup / abuseipdb_lookup — only the pure, network-free early-return
// branches are exercised here; hitting the real APIs would make the test
// suite flaky/offline-hostile.
// =====================================================================

#[test]
fn vt_lookup_rejects_missing_api_key_without_network_call() {
    let result = vt_lookup("8.8.8.8", IndicatorType::Ip, "");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing API Key"));
}

#[test]
fn vt_lookup_refuses_internal_ip_without_network_call() {
    let result = vt_lookup("127.0.0.1", IndicatorType::InternalIp, "dummy-key");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("no public data"));
}

#[test]
fn vt_lookup_refuses_unknown_indicator_without_network_call() {
    let result = vt_lookup("garbage", IndicatorType::Unknown, "dummy-key");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Unknown indicator type"));
}

#[test]
fn abuseipdb_lookup_rejects_missing_api_key() {
    assert!(abuseipdb_lookup("8.8.8.8", "").is_err());
}

#[test]
fn abuseipdb_lookup_rejects_too_short_api_key() {
    // AbuseIPDB keys are much longer than 10 chars; this is a cheap sanity guard.
    assert!(abuseipdb_lookup("8.8.8.8", "short").is_err());
}

// =====================================================================
// In-memory result cache — pre-seeded directly (bypassing the network) so
// the test stays offline-safe while still proving the cache short-circuits
// `vt_lookup`/`abuseipdb_lookup` before they ever build an HTTP request.
// TEST-NET-3 (203.0.113.0/24, RFC 5737) addresses are used as harmless,
// collision-free placeholders.
// =====================================================================

#[test]
fn vt_lookup_serves_cached_result_without_network_call() {
    let cache_key = format!("{:?}:{}", IndicatorType::Ip, "203.0.113.5");
    vt_cache().lock().unwrap().insert(cache_key, VtStatus::Clean(0, 70));

    let result = vt_lookup("203.0.113.5", IndicatorType::Ip, "dummy-key");
    assert_eq!(result, Ok(VtStatus::Clean(0, 70)));
}

#[test]
fn abuseipdb_lookup_serves_cached_result_without_network_call() {
    abuse_cache().lock().unwrap().insert("203.0.113.7".to_string(), AbuseStatus::Malicious(100));

    let result = abuseipdb_lookup("203.0.113.7", "dummy-key-1234567890");
    assert_eq!(result, Ok(AbuseStatus::Malicious(100)));
}
