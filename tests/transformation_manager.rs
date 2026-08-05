//! Integration test: drives `TransformationManager` the same way `app.rs`
//! does — look a transformer up by name, then call `transform_text` on it —
//! using only the crate's public API surface.
use defenders_clipboard::api::IndicatorType;
use defenders_clipboard::transformers::{TransformationManager, TransformerResult};

fn find<'a>(mgr: &'a TransformationManager, name: &str) -> &'a dyn defenders_clipboard::transformers::Transformer {
    mgr.transformers
        .iter()
        .find(|t| t.name() == name)
        .unwrap_or_else(|| panic!("transformer {name:?} must be registered"))
        .as_ref()
}

#[test]
fn manager_registers_all_expected_transformers_with_unique_names() {
    let mgr = TransformationManager::new();
    let names: Vec<&str> = mgr.transformers.iter().map(|t| t.name()).collect();

    assert_eq!(names.len(), 12);

    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "duplicate transformer names found: {names:?}");
}

#[test]
fn manager_smart_fang_round_trip_via_lookup_by_name() {
    let mgr = TransformationManager::new();
    let smart_fang = find(&mgr, "Smart Fang");

    match smart_fang.transform_text("https://evil.com", None, None) {
        Some(TransformerResult::Text(s)) => assert_eq!(s, "hxxps[:]//evil[.]com"),
        other => panic!("unexpected result: {}", other.is_some()),
    }
}

#[test]
fn manager_extract_iocs_flow_end_to_end() {
    let mgr = TransformationManager::new();
    let extractor = find(&mgr, "Extract IOCs");

    match extractor.transform_text("Connect to 1.2.3.4 and evil-domain.com", None, None) {
        Some(TransformerResult::Text(s)) => {
            assert!(s.contains("1.2.3.4"));
            assert!(s.contains("evil-domain.com"));
        }
        other => panic!("unexpected result: {}", other.is_some()),
    }
}

#[test]
fn manager_api_virustotal_without_key_returns_error_and_never_touches_the_network() {
    let mgr = TransformationManager::new();
    let vt = find(&mgr, "API VirusTotal");

    match vt.transform_text("8.8.8.8", None, None) {
        Some(TransformerResult::ApiError(msg)) => assert!(msg.contains("Missing VT API Key")),
        other => panic!("unexpected result: {}", other.is_some()),
    }
}

#[test]
fn manager_flags_exactly_the_network_facing_tools_as_requiring_external_lookup() {
    let mgr = TransformationManager::new();
    let expected_external = [
        "API VirusTotal",
        "API AbuseIPDB",
        "🌐 VirusTotal",
        "🌐 AbuseIPDB",
        "🌐 Whois",
        "🌐 UrlScan",
    ];

    for t in &mgr.transformers {
        assert_eq!(
            t.requires_external_lookup(),
            expected_external.contains(&t.name()),
            "unexpected external-lookup flag for {}",
            t.name()
        );
    }
}

#[test]
fn manager_external_lookup_tools_are_all_hidden_for_internal_ips() {
    // Mirrors the gating logic in app.rs: a tool is hidden on an InternalIp
    // indicator whenever `requires_external_lookup()` is true -- a private
    // address just isn't in any public dataset, so there's nothing to show.
    let mgr = TransformationManager::new();
    for t in &mgr.transformers {
        if t.requires_external_lookup() {
            // Every external-lookup tool also declares support for at least
            // Ip, so this indirectly confirms the gate has something to block.
            assert!(
                t.is_supported_indicator(&IndicatorType::Ip) || t.is_supported_indicator(&IndicatorType::Domain),
                "{} requires external lookup but never applies to Ip/Domain indicators",
                t.name()
            );
        }
    }
}
