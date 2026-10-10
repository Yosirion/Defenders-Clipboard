use std::borrow::Cow;
use std::net::Ipv6Addr;
use std::sync::OnceLock;

use base64::Engine;
use regex::Regex;
use image::{DynamicImage, RgbaImage};

// Import the status enums from the `api` module
use crate::api::{VtStatus, AbuseStatus, IndicatorType};

/// Defines the outcome produced by a Transformer module.
pub enum TransformerResult {
    /// Returns a processed string to be copied to the clipboard (e.g., Defanged URL).
    Text(String),
    /// Commands the application to open a specific URL in the default web browser.
    OpenBrowser(String),
    /// Emits the result of an asynchronous VirusTotal API call.
    ApiVtResult(VtStatus),
    /// Emits the result of an asynchronous AbuseIPDB API call.
    ApiAbuseResult(AbuseStatus),
    /// Triggers an error notification (e.g., Missing API keys, network down).
    ApiError(String),
}

/// The core interface for all parsing, decoding, and OSINT modules.
/// Implements Strategy Pattern to allow dynamic execution of tools.
pub trait Transformer: Send + Sync {
    /// The display name of the tool (used in Settings and UI tooltips).
    fn name(&self) -> &str;
    
    /// The shortened name to fit inside the UI buttons.
    fn short_name(&self) -> &str;
    
    /// Processes plain text. Returns `Some` if applicable, `None` otherwise.
    fn transform_text(&self, _input: &str,_vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> { None }

    /// Processes raw RGBA image pixels. Returns `Some` if applicable, `None` otherwise.
    fn transform_image(&self, _width: usize, _height: usize, _rgba: &[u8], _vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> { None }

    /// Returns `true` if the transformer can handle text payloads.
    fn supports_text(&self) -> bool { true }
    
    /// Returns `true` if the transformer can handle image payloads.
    fn supports_image(&self) -> bool { false }

    // ==========================================
    // --- DYNAMIC UI CONFIGURATION ---
    // ==========================================

    /// Specifies the width of the button in the UI. 
    /// Default is 60.0. Overridden for longer labels (e.g., Web Links).
    fn button_width(&self) -> f32 { 60.0 }

    /// Determines if this tool should be displayed for a specific Indicator Type.
    /// Default is true for everything. OSINT tools override this to hide themselves 
    /// if the indicator is irrelevant (e.g., hiding Whois for Hashes).
    fn is_supported_indicator(&self, _indicator: &IndicatorType) -> bool { true }

    /// Content-aware visibility for text payloads: return `false` to hide the button
    /// for this specific text (e.g. "Unwrap" only makes sense if a safe link is present).
    fn is_applicable_to_text(&self, _input: &str) -> bool { true }

    /// Button label for a given text payload. Defaults to `short_name`; override it when
    /// the label should reflect what a click will do (e.g. Fang -> Defang / Refang).
    fn short_name_for_text(&self, _input: &str) -> Cow<'_, str> { Cow::Borrowed(self.short_name()) }

    /// Whether this tool needs to query an external, public data source.
    /// Internal/private IP indicators are hidden from these tools not to
    /// prevent a leak, but because a private address simply isn't present
    /// in any public dataset -- there would be nothing useful to look up.
    fn requires_external_lookup(&self) -> bool { false }
}

/// Factory that holds and initializes all available Transformer modules.
pub struct TransformationManager {
    pub transformers: Vec<Box<dyn Transformer>>,
}

impl TransformationManager {
    pub fn new() -> Self {
        Self {
            transformers: vec![
                // Data Modifiers & Decoders
                Box::new(SmartFangTransformer),
                Box::new(SafeLinkUnwrapTransformer),
                Box::new(UrlDecodeTransformer),
                Box::new(Base64DecodeTransformer),
                Box::new(HexDecodeTransformer),
                Box::new(NinjaExtractorTransformer),
                Box::new(QrDecodeTransformer),
                
                // API Query Tools
                Box::new(VirusTotalApiTransformer),
                Box::new(AbuseIpDbApiTransformer),
                
                // Web Pivot Tools (OSINT Links)
                Box::new(VirusTotalWebTransformer),
                Box::new(AbuseIpDbWebTransformer),
                Box::new(WhoisTransformer),
                Box::new(UrlScanTransformer),
            ],
        }
    }
}

// ==========================================
// 1. SMART FANG (Toggles between Defang & Refang)
// ==========================================
pub struct SmartFangTransformer;

/// What a click on the Fang button will do for a given text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FangAction {
    /// The text holds active (armed) IoCs: they will be defanged.
    Defang,
    /// The text is already defanged: it will be re-armed.
    Refang,
}

impl SmartFangTransformer {
    /// Universally defangs a string, making it safe to click.
    pub fn force_defang(input: &str) -> String {
        let defanged_http = input
            .replace("http://", "hxxp://")
            .replace("https://", "hxxps://")
            .replace("HTTP://", "HXXP://")
            .replace("HTTPS://", "HXXPS://");

        let mut out = String::with_capacity(defanged_http.len() + 10);
        for ch in defanged_http.chars() {
            match ch {
                '.' => out.push_str("[.]"),
                '@' => out.push_str("[at]"),
                ':' => out.push_str("[:]"),
                _ => out.push(ch),
            }
        }
        out
    }

    /// Re-arms a defanged string (the reverse of `force_defang`, plus other common conventions).
    pub fn force_refang(input: &str) -> String {
        // Strip bracket obfuscation FIRST so the scheme-word swap below (which
        // matches on a literal "://") can still find it once ":" is unbracketed.
        let mut refanged = input.replace("[:]", ":")
                                .replace("[.]", ".")
                                .replace("(.)", ".")
                                .replace("{.}", ".");

        refanged = refanged.replace("hxxps://", "https://")
                           .replace("hxxp://", "http://")
                           .replace("HXXPS://", "HTTPS://")
                           .replace("HXXP://", "HTTP://")
                           .replace("h**ps://", "https://")
                           .replace("h**p://", "http://");

        refanged.replace("[at]", "@")
                .replace("[AT]", "@")
                .replace("(at)", "@")
                .replace("(AT)", "@")
                .replace("{@}", "@")
                .replace("[@]", "@")
    }

    fn looks_defanged(input: &str) -> bool {
        let lower = input.to_lowercase();
        lower.contains("hxxp")
            || input.contains("[.]")
            || input.contains("(.)")
            || input.contains("{.}")
            || lower.contains("[at]")
            || lower.contains("(at)")
            || lower.contains("{@}")
            || input.contains("[@]")
    }

    /// Decides what the button would do for `input`, and the resulting text.
    /// `None` when there is nothing to change (no IoC-looking content).
    pub fn evaluate(input: &str) -> Option<(FangAction, String)> {
        if Self::looks_defanged(input) {
            // Re-arm the IOC for SIEM queries
            let refanged = Self::force_refang(input);
            return (refanged != input).then_some((FangAction::Refang, refanged));
        }

        // Text is active: only worth defanging if it can hold an IoC.
        if !input.contains('.') && !input.contains('@') && !input.to_lowercase().contains("http") {
            return None;
        }
        let defanged = Self::force_defang(input);
        (defanged != input).then_some((FangAction::Defang, defanged))
    }
}

impl Transformer for SmartFangTransformer {
    fn name(&self) -> &str { "Smart Fang" }
    fn short_name(&self) -> &str { "Fang" }

    // The button says what it will do: "Defang" on armed IoCs, "Refang" on defanged
    // ones, and the neutral "Fang" when there is nothing to change.
    fn short_name_for_text(&self, input: &str) -> Cow<'_, str> {
        match Self::evaluate(input) {
            Some((FangAction::Defang, _)) => Cow::Borrowed("Defang"),
            Some((FangAction::Refang, _)) => Cow::Borrowed("Refang"),
            None => Cow::Borrowed(self.short_name()),
        }
    }

    fn transform_text(&self, input: &str,_vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> {
        Self::evaluate(input).map(|(_, text)| TransformerResult::Text(text))
    }
}

// ==========================================
// 1b. SAFE LINK UNWRAP (Microsoft Safe Links, Proofpoint, ...)
// ==========================================
pub struct SafeLinkUnwrapTransformer;
impl Transformer for SafeLinkUnwrapTransformer {
    fn name(&self) -> &str { "Unwrap Safe Links" }
    fn short_name(&self) -> &str { "Unwrap" }

    // Only offered when the text actually holds a link we know how to unwrap.
    fn is_applicable_to_text(&self, input: &str) -> bool {
        crate::safelinks::contains_wrapped(input)
    }

    fn transform_text(&self, input: &str,_vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> {
        crate::safelinks::unwrap_all(input).map(TransformerResult::Text)
    }
}

// ==========================================
// 2. URL DECODE (%20 -> Space)
// ==========================================
pub struct UrlDecodeTransformer;
impl Transformer for UrlDecodeTransformer {
    fn name(&self) -> &str { "URL Decode" }
    fn short_name(&self) -> &str { "URL Dec" }
    
    fn transform_text(&self, input: &str,_vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> {
        if !input.contains('%') { return None; }
        
        match urlencoding::decode(input) {
            Ok(decoded) if decoded != input => Some(TransformerResult::Text(decoded.into_owned())),
            _ => None,
        }
    }
}

// ==========================================
// 3. BASE64 DECODE (With Smart UTF-16LE detection for PowerShell)
// ==========================================
pub struct Base64DecodeTransformer;
impl Transformer for Base64DecodeTransformer {
    fn name(&self) -> &str { "Base64 Decode" }
    fn short_name(&self) -> &str { "B64 Dec" }
    
    fn transform_text(&self, input: &str,_vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> {
        let trimmed = input.trim();
        if trimmed.is_empty() || trimmed.len() % 4 != 0 { return None; }
        
        let bytes = match base64::engine::general_purpose::STANDARD.decode(trimmed) {
            Ok(b) => b,
            Err(_) => return None,
        };

        // Try UTF-16LE (Obfuscated PowerShell Payloads contain alternating null bytes)
        if bytes.contains(&0) && bytes.len() % 2 == 0 {
            let u16_chars: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            
            if let Ok(utf16_str) = String::from_utf16(&u16_chars) {
                if !utf16_str.is_empty() && utf16_str != input {
                    return Some(TransformerResult::Text(utf16_str)); 
                }
            }
        }

        // Standard UTF-8 fallback
        if let Ok(utf8_str) = String::from_utf8(bytes) {
            // Prevent returning strings full of null bytes if the payload was actually binary
            if !utf8_str.contains('\0') && !utf8_str.is_empty() && utf8_str != input {
                return Some(TransformerResult::Text(utf8_str));
            }
        }
        None
    }
}

// ==========================================
// 4. HEX DECODE (Removes 0x, \x, spaces and decodes)
// ==========================================
pub struct HexDecodeTransformer;
impl Transformer for HexDecodeTransformer {
    fn name(&self) -> &str { "Hex Decode" }
    fn short_name(&self) -> &str { "Hex Dec" }
    
    fn transform_text(&self, input: &str,_vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> {
        // Strip common hex formatting characters often found in shellcode or logs
        let cleaned: String = input
            .replace("0x", "").replace("0X", "")
            .replace("\\x", "").replace("\\X", "")
            .replace(',', "").replace(' ', "")
            .replace('\n', "").replace('\r', "");

        if cleaned.is_empty() || cleaned.len() % 2 != 0 { return None; }
        if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) { return None; }

        let mut bytes = Vec::with_capacity(cleaned.len() / 2);
        for i in (0..cleaned.len()).step_by(2) {
            let byte_str = &cleaned[i..i + 2];
            if let Ok(byte) = u8::from_str_radix(byte_str, 16) {
                bytes.push(byte);
            } else { return None; }
        }

        if let Ok(utf8_str) = String::from_utf8(bytes) {
            if !utf8_str.contains('\0') && !utf8_str.is_empty() && utf8_str != input {
                return Some(TransformerResult::Text(utf8_str));
            }
        }
        None
    }
}

// ==========================================
// 5. NINJA EXTRACTOR (Extracts all IPs, Domains, URLs, Hashes)
// ==========================================

// Regexes are compiled once and reused across calls (same pattern as
// `get_client()` in api.rs) instead of recompiling them on every click.
static RE_IPV4: OnceLock<Regex> = OnceLock::new();
static RE_IPV6_CANDIDATE: OnceLock<Regex> = OnceLock::new();
static RE_URL: OnceLock<Regex> = OnceLock::new();
static RE_DOMAIN: OnceLock<Regex> = OnceLock::new();
static RE_HASH: OnceLock<Regex> = OnceLock::new();

fn re_ipv4() -> &'static Regex {
    RE_IPV4.get_or_init(|| Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap())
}

// Broad candidate pattern (hex groups + colons); every match is then
// validated with a real `Ipv6Addr` parse before being trusted, so this only
// needs to be a superset of valid IPv6 syntax, not a precise grammar.
fn re_ipv6_candidate() -> &'static Regex {
    RE_IPV6_CANDIDATE.get_or_init(|| Regex::new(r"(?i)[0-9a-f:]{2,45}").unwrap())
}

fn re_url() -> &'static Regex {
    RE_URL.get_or_init(|| Regex::new(r"(?i)\b(?:https?|ftp)://[-A-Z0-9+&@#/%?=~_|!:,.;]*[-A-Z0-9+&@#/%=~_|]").unwrap())
}

// Widened TLD list vs. the original 13 entries, to catch gTLDs commonly
// abused for phishing/C2 infrastructure. Deliberately NOT a fully generic
// "any 2-24 letter suffix" pattern: that would also match file extensions
// routinely present in the same pasted logs (evil.exe, payload.dll, ...).
fn re_domain() -> &'static Regex {
    RE_DOMAIN.get_or_init(|| Regex::new(concat!(
        r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+",
        r"(?:com|net|org|io|co|me|tv|cc|us|uk|ru|cn|xyz|top|club|shop|site|online|",
        r"live|link|click|work|biz|info|icu|buzz|monster|host|store|website|fun|",
        r"vip|win|bid|stream|download|men|party|review|trade|loan|gq|ml|cf|ga|tk|",
        r"pw|su|app|dev|page|cloud|email)\b",
    )).unwrap())
}

fn re_hash() -> &'static Regex {
    RE_HASH.get_or_init(|| Regex::new(r"(?i)\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b").unwrap())
}

pub struct NinjaExtractorTransformer;
impl Transformer for NinjaExtractorTransformer {
    fn name(&self) -> &str { "Extract IOCs" }
    fn short_name(&self) -> &str { "Ninja Ext" }

    fn transform_text(&self, input: &str,_vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> {
        if input.len() < 7 { return None; }

        let mut extracted_iocs = Vec::new();

        // 1. Extract Valid IPv4 Addresses
        for cap in re_ipv4().find_iter(input) {
            let ip_str = cap.as_str();
            let kind = crate::api::classify_indicator(ip_str);
            // Include internal IPs in extraction just in case they are relevant for logging
            if kind == crate::api::IndicatorType::Ip || kind == crate::api::IndicatorType::InternalIp {
                extracted_iocs.push(ip_str.to_string());
            }
        }

        // 1b. Extract Valid IPv6 Addresses (candidate regex + real parse to reject noise)
        for cap in re_ipv6_candidate().find_iter(input) {
            let candidate = cap.as_str();
            if !candidate.contains(':') { continue; } // pure hex runs are handled by the hash regex
            if candidate.parse::<Ipv6Addr>().is_err() { continue; }

            let kind = crate::api::classify_indicator(candidate);
            if kind == crate::api::IndicatorType::Ip || kind == crate::api::IndicatorType::InternalIp {
                extracted_iocs.push(candidate.to_string());
            }
        }

        // 2. Extract URLs & Hashes
        for cap in re_url().find_iter(input) { extracted_iocs.push(cap.as_str().to_string()); }
        for cap in re_hash().find_iter(input) { extracted_iocs.push(cap.as_str().to_string()); }

        // 3. Extract Domains
        for cap in re_domain().find_iter(input) {
            let domain = cap.as_str();
            // Avoid extracting a bare domain if it's already part of a captured URL
            let is_already_in_url = extracted_iocs.iter().any(|existing| existing.contains(domain));
            if !is_already_in_url {
                extracted_iocs.push(domain.to_string());
            }
        }

        // Deduplication (Maintains the original occurrence order from the raw log)
        let mut unique_iocs = Vec::new();
        for ioc in extracted_iocs {
            if !unique_iocs.iter().any(|existing| existing == &ioc) {
                unique_iocs.push(ioc);
            }
        }

        // Return None if nothing was extracted or if the user copied a single, already-clean IOC
        if unique_iocs.is_empty() || (unique_iocs.len() == 1 && unique_iocs[0] == input.trim()) {
            return None;
        }

        Some(TransformerResult::Text(unique_iocs.join("\n")))
    }
}

// ==========================================
// 6. QR DECODER (Extracts text from images)
// ==========================================
pub struct QrDecodeTransformer;
impl Transformer for QrDecodeTransformer {
    fn name(&self) -> &str { "QR Decode" }
    fn short_name(&self) -> &str { "QR" }
    fn supports_text(&self) -> bool { false }
    fn supports_image(&self) -> bool { true }
    
    // Override width to accommodate the label nicely
    fn button_width(&self) -> f32 { 75.0 }

    fn transform_image(&self, width: usize, height: usize, rgba_bytes: &[u8], _vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> {
        // Convert raw RGBA pixels to Grayscale (Luma8) required by the rqrr crate
        if let Some(rgba_img) = RgbaImage::from_raw(width as u32, height as u32, rgba_bytes.to_vec()) {
            let dyn_img = DynamicImage::ImageRgba8(rgba_img);
            let gray_img = dyn_img.into_luma8();
            
            let mut qr_img = rqrr::PreparedImage::prepare(gray_img);
            let grids = qr_img.detect_grids();
            
            if !grids.is_empty() {
                if let Ok((_, content)) = grids[0].decode() {
                    if !content.is_empty() {
                        return Some(TransformerResult::Text(content));
                    }
                }
            }
        }
        None
    }
}

// ==========================================
// 7. VIRUSTOTAL API LOOKUP
// ==========================================
pub struct VirusTotalApiTransformer;
impl Transformer for VirusTotalApiTransformer {
    fn name(&self) -> &str { "API VirusTotal" }
    fn short_name(&self) -> &str { "VT" }
    fn requires_external_lookup(&self) -> bool { true } // queries the public VirusTotal API
    
    fn is_supported_indicator(&self, indicator: &IndicatorType) -> bool {
        *indicator != IndicatorType::Unknown
    }
    
    fn transform_text(&self, input: &str,_vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> {
        let kind = crate::api::classify_indicator(input);
        if kind != crate::api::IndicatorType::Unknown && kind != crate::api::IndicatorType::InternalIp {
            // Performs synchronous HTTP request (UI must spawn a thread before calling this!)
            if let Some(key) = _vt_key {
                match crate::api::vt_lookup(input, kind, key) {
                    Ok(status) => return Some(TransformerResult::ApiVtResult(status)),
                    Err(e) => return Some(TransformerResult::ApiError(e)),
                }
            } else {
                return Some(TransformerResult::ApiError("Missing VT API Key!".to_string()));
            }
        }
        None
    }
}

// ==========================================
// 8. ABUSEIPDB API LOOKUP
// ==========================================
pub struct AbuseIpDbApiTransformer;
impl Transformer for AbuseIpDbApiTransformer {
    fn name(&self) -> &str { "API AbuseIPDB" }
    fn short_name(&self) -> &str { "Abuse" }
    fn requires_external_lookup(&self) -> bool { true } // queries the public AbuseIPDB API
    
    fn is_supported_indicator(&self, indicator: &IndicatorType) -> bool {
        *indicator == IndicatorType::Ip
    }
    
    fn transform_text(&self, input: &str,_vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> {
        let kind = crate::api::classify_indicator(input);
        if kind == crate::api::IndicatorType::Ip {
            if let Some(key) = _abuse_key {
                match crate::api::abuseipdb_lookup(input, key) {
                    Ok(status) => return Some(TransformerResult::ApiAbuseResult(status)),
                    Err(e) => return Some(TransformerResult::ApiError(e)),
                }
            } else {
                return Some(TransformerResult::ApiError("Missing AbuseIPDB Key!".to_string()));
            }
        }
        None
    }
}

// ==========================================
// 9. VIRUSTOTAL WEB PIVOT
// ==========================================
pub struct VirusTotalWebTransformer;
impl Transformer for VirusTotalWebTransformer {
    fn name(&self) -> &str { "🌐 VirusTotal" }
    fn short_name(&self) -> &str { "🌐 VT" }
    fn button_width(&self) -> f32 { 70.0 }
    fn requires_external_lookup(&self) -> bool { true } // pivots to the public VirusTotal website

    // VirusTotal's URL search results page is gated behind a JS bot-check that a
    // plain browser pivot can't pass (unlike its hash/domain/IP search pages).
    // URL indicators can still be checked via the "API VirusTotal" tool instead.
    fn is_supported_indicator(&self, indicator: &IndicatorType) -> bool {
        *indicator != IndicatorType::Unknown && *indicator != IndicatorType::Url
    }

    fn transform_text(&self, input: &str,_vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> {
        let kind = crate::api::classify_indicator(input);
        if kind != crate::api::IndicatorType::Unknown
            && kind != crate::api::IndicatorType::InternalIp
            && kind != crate::api::IndicatorType::Url
        {
            let encoded = urlencoding::encode(input);
            return Some(TransformerResult::OpenBrowser(format!("https://www.virustotal.com/gui/search/{}", encoded)));
        }
        None
    }
}

// ==========================================
// 10. ABUSEIPDB WEB PIVOT 
// ==========================================
pub struct AbuseIpDbWebTransformer;
impl Transformer for AbuseIpDbWebTransformer {
    fn name(&self) -> &str { "🌐 AbuseIPDB" }
    fn short_name(&self) -> &str { "🌐 Abuse" }
    fn button_width(&self) -> f32 { 75.0 }
    fn requires_external_lookup(&self) -> bool { true } // pivots to the public AbuseIPDB website
    
    fn is_supported_indicator(&self, indicator: &IndicatorType) -> bool {
        *indicator == IndicatorType::Ip
    }
    
    fn transform_text(&self, input: &str,_vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> {
        let kind = crate::api::classify_indicator(input);
        if kind == crate::api::IndicatorType::Ip {
            let encoded = urlencoding::encode(input);
            return Some(TransformerResult::OpenBrowser(format!("https://www.abuseipdb.com/check/{}", encoded)));
        }
        None
    }
}

// ==========================================
// 11. WHOIS WEB PIVOT (DomainTools)
// ==========================================
pub struct WhoisTransformer;
impl Transformer for WhoisTransformer {
    fn name(&self) -> &str { "🌐 Whois" }
    fn short_name(&self) -> &str { "🌐 Whois" }
    fn button_width(&self) -> f32 { 75.0 }
    fn requires_external_lookup(&self) -> bool { true } // queries the public Whois database
    
    fn is_supported_indicator(&self, indicator: &IndicatorType) -> bool {
        matches!(indicator, IndicatorType::Ip | IndicatorType::Domain)
    }
    
    fn transform_text(&self, input: &str,_vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> {
        let kind = crate::api::classify_indicator(input);
        if matches!(kind, crate::api::IndicatorType::Ip | crate::api::IndicatorType::Domain) {
            let encoded = urlencoding::encode(input);
            return Some(TransformerResult::OpenBrowser(format!("https://whois.domaintools.com/{}", encoded)));
        }
        None
    }
}

// ==========================================
// 12. URLSCAN WEB PIVOT
// ==========================================
pub struct UrlScanTransformer;
impl Transformer for UrlScanTransformer {
    fn name(&self) -> &str { "🌐 UrlScan" }
    fn short_name(&self) -> &str { "🌐 Scan" }
    fn button_width(&self) -> f32 { 75.0 }
    fn requires_external_lookup(&self) -> bool { true } // queries the public UrlScan.io database
    
    fn is_supported_indicator(&self, indicator: &IndicatorType) -> bool {
        matches!(indicator, IndicatorType::Ip | IndicatorType::Domain | IndicatorType::Url)
    }
    
    fn transform_text(&self, input: &str,_vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> {
        let kind = crate::api::classify_indicator(input);
        
        if matches!(kind, crate::api::IndicatorType::Ip | crate::api::IndicatorType::Domain | crate::api::IndicatorType::Url) {
            
            // Smart Logic: If it's a full URL, we extract just the Host/Domain to perform a broader search.
            let search_target = if kind == crate::api::IndicatorType::Url {
                // Manual fallback for "dirty" URLs (e.g., google.com/path without http://)
                // We strip the protocol prefix and get everything before the first slash or question mark
                let clean = input.trim_start_matches("http://").trim_start_matches("https://").trim_start_matches("ftp://");
                clean.split('/').next().unwrap_or(clean).split('?').next().unwrap_or(clean).to_string()
            } else {
                // It's already a clean Domain or IP
                input.to_string()
            };

            let encoded = urlencoding::encode(&search_target);
            return Some(TransformerResult::OpenBrowser(format!("https://urlscan.io/search/#{}", encoded)));
        }
        None
    }
}

#[cfg(test)]
mod tests;
