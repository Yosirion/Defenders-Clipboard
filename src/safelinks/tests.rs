//! Unit tests for `safelinks.rs`.
use super::*;

// =====================================================================
// One test per supported service
// =====================================================================
#[test]
fn unwraps_microsoft_safelinks() {
    let wrapped = "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil-domain.com%2Flogin%3Fa%3D1%26b%3D2&data=05%7C02%7Cuser%40corp.com%7Cabc&sdata=XYZ%3D&reserved=0";
    assert_eq!(unwrap_url(wrapped).as_deref(), Some("https://evil-domain.com/login?a=1&b=2"));
}

#[test]
fn unwraps_proofpoint_v1() {
    let wrapped = "https://urldefense.proofpoint.com/v1/url?u=http%3A%2F%2Fevil-domain.com%2Fa&k=abc";
    assert_eq!(unwrap_url(wrapped).as_deref(), Some("http://evil-domain.com/a"));
}

#[test]
fn unwraps_proofpoint_v2() {
    // '_' is '/', "-3A" is ':', "-2D" is a literal '-'.
    let wrapped = "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil-2Ddomain.com_a-3Fx-3D1&d=DwMF&c=abc&r=1";
    assert_eq!(unwrap_url(wrapped).as_deref(), Some("https://evil-domain.com/a?x=1"));
}

#[test]
fn unwraps_proofpoint_v3_without_placeholders() {
    let wrapped = "https://urldefense.com/v3/__https://evil-domain.com/a?x=1__;!!AbC123$";
    assert_eq!(unwrap_url(wrapped).as_deref(), Some("https://evil-domain.com/a?x=1"));
}

#[test]
fn unwraps_proofpoint_v3_with_placeholders() {
    // The base64 segment "JQ" is "%", which the '*' stands for.
    let wrapped = "https://urldefense.com/v3/__https://evil-domain.com/a*20b__;JQ!!AbC123$";
    assert_eq!(unwrap_url(wrapped).as_deref(), Some("https://evil-domain.com/a%20b"));
}

#[test]
fn refuses_to_guess_when_proofpoint_v3_placeholders_do_not_match() {
    // Two '*' but only one replacement char: better no answer than a wrong one.
    let wrapped = "https://urldefense.com/v3/__https://evil-domain.com/a**b__;JQ!!AbC123$";
    assert_eq!(unwrap_url(wrapped), None);
}

#[test]
fn unwraps_barracuda() {
    let wrapped = "https://linkprotect.cudasvc.com/url?a=https%3a%2f%2fevil-domain.com%2fa&c=E,1,abc&typo=1";
    assert_eq!(unwrap_url(wrapped).as_deref(), Some("https://evil-domain.com/a"));
}

#[test]
fn unwraps_check_point() {
    let wrapped = "https://protect.checkpoint.com/v2/___https://evil-domain.com/a/b.html___.YXAzOnByb2Q6YQ";
    assert_eq!(unwrap_url(wrapped).as_deref(), Some("https://evil-domain.com/a/b.html"));
}

#[test]
fn unwraps_cisco() {
    let wrapped = "https://secure-web.cisco.com/1AbC_dEf-123/https%3A%2F%2Fevil-domain.com%2Fa%3Fx%3D1";
    assert_eq!(unwrap_url(wrapped).as_deref(), Some("https://evil-domain.com/a?x=1"));
}

#[test]
fn unwraps_sophos() {
    let wrapped = "https://eu-west-1.protection.sophos.com/?d=evil-domain.com&u=aHR0cHM6Ly9ldmlsLWRvbWFpbi5jb20vYQ==&i=abc&t=def&h=ghi";
    assert_eq!(unwrap_url(wrapped).as_deref(), Some("https://evil-domain.com/a"));
}

// =====================================================================
// Things that must be left alone
// =====================================================================
#[test]
fn ignores_urls_from_unsupported_or_normal_sites() {
    assert_eq!(unwrap_url("https://evil-domain.com/a"), None);
    // Mimecast uses an opaque server-side token: nothing to recover offline.
    assert_eq!(unwrap_url("https://protect-us.mimecast.com/s/abcDEF123"), None);
}

#[test]
fn rejects_wrapped_values_that_are_not_urls() {
    let wrapped = "https://nam12.safelinks.protection.outlook.com/?url=javascript%3Aalert(1)&data=x";
    assert_eq!(unwrap_url(wrapped), None);
}

#[test]
fn returns_none_for_garbage() {
    assert_eq!(unwrap_url("not a url"), None);
    assert_eq!(unwrap_url(""), None);
}

// =====================================================================
// Nesting and free text
// =====================================================================
#[test]
fn unwrap_fully_peels_nested_layers() {
    let proofpoint = "https://urldefense.proofpoint.com/v1/url?u=http%3A%2F%2Fevil-domain.com%2Fa&k=abc";
    let encoded = urlencoding::encode(proofpoint);
    let nested = format!("https://nam12.safelinks.protection.outlook.com/?url={encoded}&data=x");

    assert_eq!(unwrap_url(&nested).as_deref(), Some(proofpoint));
    assert_eq!(unwrap_fully(&nested).as_deref(), Some("http://evil-domain.com/a"));
}

#[test]
fn unwrap_all_replaces_links_inside_text_and_keeps_the_rest() {
    let text = "Please check https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil-domain.com%2Fa&data=x. Thanks!";
    assert_eq!(
        unwrap_all(text).as_deref(),
        Some("Please check https://evil-domain.com/a. Thanks!")
    );
}

#[test]
fn unwrap_all_handles_several_links_and_leaves_normal_ones() {
    let text = "a https://linkprotect.cudasvc.com/url?a=https%3a%2f%2fone.com%2f&c=E b https://keep.com/x c https://secure-web.cisco.com/tok/https%3A%2F%2Ftwo.com%2F";
    assert_eq!(
        unwrap_all(text).as_deref(),
        Some("a https://one.com/ b https://keep.com/x c https://two.com/")
    );
}

#[test]
fn unwrap_all_returns_none_when_nothing_to_clean() {
    assert_eq!(unwrap_all("just https://evil-domain.com/a and text"), None);
    assert_eq!(unwrap_all(""), None);
}

#[test]
fn contains_wrapped_matches_unwrap_all() {
    assert!(contains_wrapped("https://linkprotect.cudasvc.com/url?a=https%3a%2f%2fone.com%2f&c=E"));
    assert!(!contains_wrapped("https://one.com/"));
}
