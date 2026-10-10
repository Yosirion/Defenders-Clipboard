//! Unit tests for `transformers.rs`, split into its own file next to the
//! module it tests (`transformers::tests`). Broader, cross-module workflows
//! belong in `tests/` (integration tests) instead.
use super::*;

fn text_of(result: Option<TransformerResult>) -> String {
    match result {
        Some(TransformerResult::Text(s)) => s,
        other => panic!("expected TransformerResult::Text, got {:?}", other.is_some()),
    }
}

fn browser_url_of(result: Option<TransformerResult>) -> String {
    match result {
        Some(TransformerResult::OpenBrowser(url)) => url,
        other => panic!("expected TransformerResult::OpenBrowser, got {:?}", other.is_some()),
    }
}

fn error_of(result: Option<TransformerResult>) -> String {
    match result {
        Some(TransformerResult::ApiError(msg)) => msg,
        other => panic!("expected TransformerResult::ApiError, got {:?}", other.is_some()),
    }
}

// =====================================================================
// Smart Fang
// =====================================================================
#[test]
fn smart_fang_defangs_url_and_email() {
    let out = text_of(SmartFangTransformer.transform_text("https://evil.com/a@b.com", None, None));
    assert_eq!(out, "hxxps[:]//evil[.]com/a[at]b[.]com");
}

#[test]
fn smart_fang_defangs_the_scheme_colon_too() {
    let out = text_of(SmartFangTransformer.transform_text("http://evil.com", None, None));
    assert_eq!(out, "hxxp[:]//evil[.]com");
}

#[test]
fn smart_fang_refangs_defanged_input() {
    let out = text_of(SmartFangTransformer.transform_text("hxxps://evil[.]com", None, None));
    assert_eq!(out, "https://evil.com");
}

#[test]
fn smart_fang_refangs_bracketed_colon_form() {
    // The current defang output brackets the scheme colon; refang must undo that too.
    let out = text_of(SmartFangTransformer.transform_text("hxxps[:]//evil[.]com", None, None));
    assert_eq!(out, "https://evil.com");
}

#[test]
fn smart_fang_round_trip_is_idempotent_free() {
    let original = "https://evil.com";
    let defanged = text_of(SmartFangTransformer.transform_text(original, None, None));
    let refanged = text_of(SmartFangTransformer.transform_text(&defanged, None, None));
    assert_eq!(refanged, original);
}

#[test]
fn smart_fang_ignores_plain_text_without_iocs() {
    assert!(SmartFangTransformer.transform_text("just some plain text", None, None).is_none());
}

#[test]
fn smart_fang_force_defang_is_directly_callable() {
    assert_eq!(SmartFangTransformer::force_defang("a.b@c.com"), "a[.]b[at]c[.]com");
    assert_eq!(SmartFangTransformer::force_defang("http://a.com"), "hxxp[:]//a[.]com");
}

#[test]
fn smart_fang_label_says_defang_for_armed_iocs() {
    assert_eq!(SmartFangTransformer.short_name_for_text("http://evil-domain.com"), "Defang");
    assert_eq!(SmartFangTransformer.short_name_for_text("evil-domain.com"), "Defang");
    assert_eq!(SmartFangTransformer.short_name_for_text("user@evil-domain.com"), "Defang");
}

#[test]
fn smart_fang_label_says_refang_for_defanged_iocs() {
    assert_eq!(SmartFangTransformer.short_name_for_text("hxxp[:]//evil-domain[.]com"), "Refang");
}

#[test]
fn smart_fang_label_falls_back_to_neutral_name_without_iocs() {
    assert_eq!(SmartFangTransformer.short_name_for_text("just some plain text"), "Fang");
}

#[test]
fn smart_fang_label_always_matches_what_the_click_does() {
    // The label is derived from the same evaluation the click runs, so they can't drift apart.
    for input in ["http://a.com", "hxxp[:]//a[.]com", "plain text", "a@b.com", "x[.]y"] {
        let label = SmartFangTransformer.short_name_for_text(input).into_owned();
        let result = SmartFangTransformer.transform_text(input, None, None);
        match label.as_str() {
            "Defang" => assert_eq!(text_of(result), SmartFangTransformer::force_defang(input)),
            "Refang" => assert_eq!(text_of(result), SmartFangTransformer::force_refang(input)),
            _ => assert!(result.is_none(), "neutral label but click did something for {input:?}"),
        }
    }
}

#[test]
fn other_transformers_keep_their_static_label() {
    assert_eq!(UrlDecodeTransformer.short_name_for_text("anything%20here"), "URL Dec");
}

// =====================================================================
// Unwrap Safe Links
// =====================================================================
#[test]
fn safelink_unwrap_cleans_a_wrapped_url() {
    let wrapped = "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil-domain.com%2Fa&data=x";
    assert_eq!(text_of(SafeLinkUnwrapTransformer.transform_text(wrapped, None, None)), "https://evil-domain.com/a");
}

#[test]
fn safelink_unwrap_is_only_offered_when_a_wrapped_link_is_present() {
    let wrapped = "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil-domain.com%2Fa&data=x";
    assert!(SafeLinkUnwrapTransformer.is_applicable_to_text(wrapped));
    assert!(!SafeLinkUnwrapTransformer.is_applicable_to_text("https://evil-domain.com/a"));
    assert!(!SafeLinkUnwrapTransformer.is_applicable_to_text("plain text"));
}

#[test]
fn safelink_unwrap_returns_none_when_nothing_to_unwrap() {
    assert!(SafeLinkUnwrapTransformer.transform_text("https://evil-domain.com/a", None, None).is_none());
}

#[test]
fn safelink_unwrap_works_locally_and_is_not_an_external_lookup() {
    assert!(!SafeLinkUnwrapTransformer.requires_external_lookup());
}

// =====================================================================
// URL Decode
// =====================================================================
#[test]
fn url_decode_handles_encoded_chars() {
    let out = text_of(UrlDecodeTransformer.transform_text("hello%20world%21", None, None));
    assert_eq!(out, "hello world!");
}

#[test]
fn url_decode_ignores_strings_without_percent() {
    assert!(UrlDecodeTransformer.transform_text("hello world", None, None).is_none());
}

// =====================================================================
// Base64 Decode
// =====================================================================
#[test]
fn base64_decode_utf8() {
    // "hello world" -> base64
    let out = text_of(Base64DecodeTransformer.transform_text("aGVsbG8gd29ybGQ=", None, None));
    assert_eq!(out, "hello world");
}

#[test]
fn base64_decode_utf16le_powershell_payload() {
    // UTF-16LE encoding of "hi" is 68 00 69 00 -> base64 "aABpAA=="
    let out = text_of(Base64DecodeTransformer.transform_text("aABpAA==", None, None));
    assert_eq!(out, "hi");
}

#[test]
fn base64_decode_rejects_invalid_input() {
    assert!(Base64DecodeTransformer.transform_text("not valid base64!!", None, None).is_none());
    assert!(Base64DecodeTransformer.transform_text("", None, None).is_none());
}

#[test]
fn base64_decode_rejects_length_not_multiple_of_four() {
    assert!(Base64DecodeTransformer.transform_text("abcde", None, None).is_none());
}

// =====================================================================
// Hex Decode
// =====================================================================
#[test]
fn hex_decode_with_0x_prefix_and_spaces() {
    // "hi" = 0x68 0x69
    let out = text_of(HexDecodeTransformer.transform_text("0x68 0x69", None, None));
    assert_eq!(out, "hi");
}

#[test]
fn hex_decode_with_backslash_x_and_commas() {
    let out = text_of(HexDecodeTransformer.transform_text("\\x68,\\x69", None, None));
    assert_eq!(out, "hi");
}

#[test]
fn hex_decode_rejects_odd_length_or_non_hex() {
    assert!(HexDecodeTransformer.transform_text("abc", None, None).is_none());
    assert!(HexDecodeTransformer.transform_text("zzzz", None, None).is_none());
}

// =====================================================================
// Extract IOCs (Ninja Extractor)
// =====================================================================
#[test]
fn ninja_extractor_pulls_ip_domain_and_hash() {
    let input = "Beacon to 8.8.8.8 and evil-domain.com, hash aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let out = text_of(NinjaExtractorTransformer.transform_text(input, None, None));
    assert!(out.contains("8.8.8.8"));
    assert!(out.contains("evil-domain.com"));
    assert!(out.contains(&"a".repeat(32)));
}

#[test]
fn ninja_extractor_pulls_url_and_avoids_duplicate_bare_domain() {
    let input = "Payload at https://evil-domain.com/drop.exe served the malware";
    let out = text_of(NinjaExtractorTransformer.transform_text(input, None, None));
    assert!(out.contains("https://evil-domain.com/drop.exe"));
    // The bare domain must not be extracted again since it's already inside the URL.
    let occurrences = out.matches("evil-domain.com").count();
    assert_eq!(occurrences, 1);
}

#[test]
fn ninja_extractor_deduplicates_and_ignores_single_clean_ioc() {
    // A single, already-clean IOC copied verbatim should yield no extraction (nothing to add).
    assert!(NinjaExtractorTransformer.transform_text("8.8.8.8", None, None).is_none());
}

#[test]
fn ninja_extractor_ignores_too_short_input() {
    assert!(NinjaExtractorTransformer.transform_text("short", None, None).is_none());
}

#[test]
fn ninja_extractor_pulls_public_and_internal_ipv6() {
    let input = "beacon to 2001:4860:4860::8888 from internal fe80::1 host";
    let out = text_of(NinjaExtractorTransformer.transform_text(input, None, None));
    assert!(out.contains("2001:4860:4860::8888"));
    assert!(out.contains("fe80::1"));
}

#[test]
fn ninja_extractor_ignores_ipv6_looking_noise() {
    // A Windows drive letter must never be mistaken for an IPv6 address.
    let input = "dropped payload at C:\\Users\\victim\\AppData\\evil.exe, not a real address";
    let out = NinjaExtractorTransformer.transform_text(input, None, None);
    if let Some(TransformerResult::Text(s)) = out {
        assert!(!s.contains("C:"));
    }
}

#[test]
fn ninja_extractor_pulls_domain_with_modern_tld() {
    let input = "phishing kit hosted at login-verify.security-update.shop for credential theft";
    let out = text_of(NinjaExtractorTransformer.transform_text(input, None, None));
    assert!(out.contains("login-verify.security-update.shop"));
}

// =====================================================================
// QR Decode
// =====================================================================
#[test]
fn qr_decode_declares_image_only_support() {
    assert!(!QrDecodeTransformer.supports_text());
    assert!(QrDecodeTransformer.supports_image());
    assert_eq!(QrDecodeTransformer.button_width(), 75.0);
}

#[test]
fn qr_decode_returns_none_for_image_without_qr_code() {
    let width = 20usize;
    let height = 20usize;
    let rgba = vec![255u8; width * height * 4]; // plain white square, no QR grid
    assert!(QrDecodeTransformer.transform_image(width, height, &rgba, None, None).is_none());
}

#[test]
fn qr_decode_returns_none_for_malformed_buffer() {
    // Buffer length doesn't match width*height*4 -> RgbaImage::from_raw fails.
    let bogus = vec![0u8; 3];
    assert!(QrDecodeTransformer.transform_image(20, 20, &bogus, None, None).is_none());
}

// =====================================================================
// API transformers — only the network-free branches (missing key /
// unsupported indicator) are exercised, to keep the suite offline-safe.
// =====================================================================
#[test]
fn virustotal_api_transformer_requires_external_lookup_and_supports_almost_everything() {
    assert!(VirusTotalApiTransformer.requires_external_lookup());
    assert!(VirusTotalApiTransformer.is_supported_indicator(&IndicatorType::Ip));
    assert!(VirusTotalApiTransformer.is_supported_indicator(&IndicatorType::InternalIp));
    assert!(!VirusTotalApiTransformer.is_supported_indicator(&IndicatorType::Unknown));
}

#[test]
fn virustotal_api_transformer_without_key_reports_error_not_network_call() {
    let msg = error_of(VirusTotalApiTransformer.transform_text("8.8.8.8", None, None));
    assert!(msg.contains("Missing VT API Key"));
}

#[test]
fn virustotal_api_transformer_skips_unknown_and_internal_indicators() {
    assert!(VirusTotalApiTransformer.transform_text("just text", None, None).is_none());
    assert!(VirusTotalApiTransformer.transform_text("127.0.0.1", None, None).is_none());
}

#[test]
fn abuseipdb_api_transformer_only_supports_ip() {
    assert!(AbuseIpDbApiTransformer.requires_external_lookup());
    assert!(AbuseIpDbApiTransformer.is_supported_indicator(&IndicatorType::Ip));
    assert!(!AbuseIpDbApiTransformer.is_supported_indicator(&IndicatorType::Domain));
}

#[test]
fn abuseipdb_api_transformer_without_key_reports_error_for_ip_but_ignores_non_ip() {
    let msg = error_of(AbuseIpDbApiTransformer.transform_text("8.8.8.8", None, None));
    assert!(msg.contains("Missing AbuseIPDB Key"));
    assert!(AbuseIpDbApiTransformer.transform_text("evil-domain.com", None, None).is_none());
}

// =====================================================================
// Web pivot transformers — pure string/URL building, fully testable
// without any network access.
// =====================================================================
#[test]
fn virustotal_web_transformer_builds_search_link_and_blocks_internal_ip() {
    let url = browser_url_of(VirusTotalWebTransformer.transform_text("8.8.8.8", None, None));
    assert!(url.starts_with("https://www.virustotal.com/gui/search/"));
    assert!(url.contains("8.8.8.8"));
    assert!(VirusTotalWebTransformer.transform_text("127.0.0.1", None, None).is_none());
}

#[test]
fn virustotal_web_transformer_refuses_urls() {
    // VT's URL search results page is behind a JS bot-check a plain link can't pass;
    // URL lookups must go through the "API VirusTotal" tool instead.
    assert!(!VirusTotalWebTransformer.is_supported_indicator(&IndicatorType::Url));
    assert!(VirusTotalWebTransformer.transform_text("https://evil-domain.com/a", None, None).is_none());
}

#[test]
fn abuseipdb_web_transformer_only_fires_on_ip() {
    let url = browser_url_of(AbuseIpDbWebTransformer.transform_text("1.2.3.4", None, None));
    assert!(url.starts_with("https://www.abuseipdb.com/check/"));
    assert!(AbuseIpDbWebTransformer.transform_text("evil-domain.com", None, None).is_none());
}

#[test]
fn whois_transformer_supports_ip_and_domain_only() {
    assert!(WhoisTransformer.is_supported_indicator(&IndicatorType::Ip));
    assert!(WhoisTransformer.is_supported_indicator(&IndicatorType::Domain));
    assert!(!WhoisTransformer.is_supported_indicator(&IndicatorType::Hash));

    let url = browser_url_of(WhoisTransformer.transform_text("evil-domain.com", None, None));
    assert!(url.starts_with("https://whois.domaintools.com/"));
    assert!(WhoisTransformer.transform_text(&"a".repeat(32), None, None).is_none());
}

#[test]
fn urlscan_transformer_extracts_host_from_dirty_url() {
    let url = browser_url_of(
        UrlScanTransformer.transform_text("http://evil-domain.com/a/b?x=1", None, None),
    );
    // Only the host must end up in the search query, not the full path/query string.
    assert!(url.contains("evil-domain.com"));
    assert!(!url.contains("%2Fa%2Fb")); // encoded "/a/b" must not be present
}

#[test]
fn urlscan_transformer_uses_domain_directly_when_not_a_url() {
    let url = browser_url_of(UrlScanTransformer.transform_text("evil-domain.com", None, None));
    assert!(url.contains("evil-domain.com"));
}

#[test]
fn urlscan_transformer_ignores_hashes() {
    assert!(UrlScanTransformer.transform_text(&"a".repeat(64), None, None).is_none());
}

// =====================================================================
// TransformationManager factory
// =====================================================================
#[test]
fn transformation_manager_registers_exactly_thirteen_transformers() {
    let mgr = TransformationManager::new();
    assert_eq!(mgr.transformers.len(), 13);
}
