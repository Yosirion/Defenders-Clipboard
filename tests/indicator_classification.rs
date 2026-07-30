//! Integration test: exercises only the crate's public API (`defenders_clipboard::api`),
//! the way any external caller (or `app.rs`) would use it.
use defenders_clipboard::api::{classify_indicator, IndicatorType};

#[test]
fn classifies_common_soc_indicators_end_to_end() {
    let cases = [
        ("8.8.8.8", IndicatorType::Ip),
        ("192.168.1.1", IndicatorType::InternalIp),
        ("::1", IndicatorType::InternalIp),
        ("fe80::1", IndicatorType::InternalIp),
        ("2001:4860:4860::8888", IndicatorType::Ip),
        ("evil-domain.com", IndicatorType::Domain),
        ("https://evil-domain.com/a", IndicatorType::Url),
        (&"a".repeat(64), IndicatorType::Hash),
        ("not an indicator at all", IndicatorType::Unknown),
    ];

    for (input, expected) in cases {
        assert_eq!(classify_indicator(input), expected, "input: {input:?}");
    }
}
