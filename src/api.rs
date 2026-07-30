use std::sync::{Mutex, OnceLock};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::Deserialize;

/// Defines the nature of the copied indicator to route it to the correct API endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndicatorType { Hash, Domain, Url, Ip, InternalIp, Unknown }

/// The parsed maliciousness level returned by VirusTotal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VtStatus { 
    Clean(u64, u64),      // (malicious, total)
    Suspicious(u64, u64), // (malicious, total)
    Malicious(u64, u64),  // (malicious, total)
    Unknown 
}

/// The parsed maliciousness level returned by AbuseIPDB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbuseStatus {
    Clean(u8),      // Confidence score: 0
    Suspicious(u8), // Confidence score: 1-99
    Malicious(u8),  // Confidence score: 100
}

// Global, thread-safe HTTP client with connection pooling to drastically improve speed.
static HTTP_CLIENT: OnceLock<Client> = OnceLock::new();

fn get_client() -> &'static Client {
    HTTP_CLIENT.get_or_init(|| {
        Client::builder()
            .timeout(std::time::Duration::from_secs(10)) // Prevent infinite hangs
            .build()
            .expect("Failed to create HTTP client")
    })
}

// In-memory, per-session result caches. Re-querying the same indicator twice
// (e.g. the analyst clicks the same button again) is served from here instead
// of burning API quota (VirusTotal's free tier allows only 4 requests/min).
static VT_CACHE: OnceLock<Mutex<HashMap<String, VtStatus>>> = OnceLock::new();
static ABUSE_CACHE: OnceLock<Mutex<HashMap<String, AbuseStatus>>> = OnceLock::new();

fn vt_cache() -> &'static Mutex<HashMap<String, VtStatus>> {
    VT_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn abuse_cache() -> &'static Mutex<HashMap<String, AbuseStatus>> {
    ABUSE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Analyzes a string to determine if it's an IP, Hash, Domain, or URL.
pub fn classify_indicator(input: &str) -> IndicatorType {
    let trimmed = input.trim();
    if trimmed.is_empty() { return IndicatorType::Unknown; }

    if trimmed.starts_with("http://") || trimmed.starts_with("https://") || trimmed.starts_with("ftp://") { 
        return IndicatorType::Url; 
    }
    
    // Detect IPv4 addresses and flag private/internal ones (RFC 1918): querying a
    // private address against public threat intel would never return anything useful.
    if is_ipv4(trimmed) {
        if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
            if ip.is_private() || ip.is_loopback() || ip.is_link_local() {
                return IndicatorType::InternalIp;
            }
        }
        return IndicatorType::Ip;
    }

    // Detect IPv6 addresses and flag private/internal ones (loopback, unspecified,
    // Unique Local Address fc00::/7, link-local fe80::/10) for the same reason as IPv4.
    if let Ok(ip6) = trimmed.parse::<Ipv6Addr>() {
        if is_ipv6_internal(&ip6) {
            return IndicatorType::InternalIp;
        }
        return IndicatorType::Ip;
    }

    if is_hash_like(trimmed) { return IndicatorType::Hash; }
    if is_domain_like(trimmed) { return IndicatorType::Domain; }

    // Fallback: Detect URLs missing the http:// prefix (e.g., evil.com/login.php)
    if !trimmed.contains(' ') && trimmed.contains('.') && (trimmed.contains('/') || trimmed.contains('?')) {
        return IndicatorType::Url;
    }
    IndicatorType::Unknown
}

fn is_hash_like(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<_> = s.split('.').collect();
    if parts.len() != 4 { return false; }
    for part in parts {
        if part.is_empty() || part.len() > 3 { return false; }
        if !part.chars().all(|c| c.is_ascii_digit()) { return false; }
        if let Ok(n) = part.parse::<u8>() {
            if n.to_string().as_str() != part { return false; }
        } else { return false; }
    }
    true
}

/// Checks whether an IPv6 address is non-routable/internal: loopback (::1),
/// unspecified (::), Unique Local Address (fc00::/7) or link-local (fe80::/10).
fn is_ipv6_internal(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() { return true; }

    let octets = ip.octets();
    // Unique Local Address: fc00::/7 (first byte is 0xfc or 0xfd)
    if (octets[0] & 0xfe) == 0xfc { return true; }
    // Link-local: fe80::/10
    if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 { return true; }

    false
}

fn is_domain_like(s: &str) -> bool {
    if !s.contains('.') || s.contains(' ') || s.contains('@') { return false; }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

// --- JSON Deserialization Structs for VirusTotal ---
#[allow(dead_code)] 
#[derive(Debug, Default, Deserialize)]
struct LastAnalysisStats { 
    malicious: Option<u64>, 
    suspicious: Option<u64>, 
    harmless: Option<u64>, 
    undetected: Option<u64>,
    timeout: Option<u64> 
}
#[derive(Debug, Default, Deserialize)]
struct AttributesWrapper { last_analysis_stats: LastAnalysisStats }
#[derive(Debug, Default, Deserialize)]
struct DataWrapper { attributes: AttributesWrapper }
#[derive(Debug, Deserialize)]
struct VtResponse { data: DataWrapper }

// --- JSON Deserialization Structs for AbuseIPDB ---
#[derive(Debug, Deserialize)]
struct AbuseData { 
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: u8 
}

#[derive(Debug, Deserialize)]
struct AbuseResponse { 
    data: AbuseData 
}

/// Performs a synchronous API call to VirusTotal.
pub fn vt_lookup(indicator: &str, kind: IndicatorType, api_key: &str) -> Result<VtStatus, String> {
    if api_key.is_empty() {
        return Err("Missing API Key (Set it in the Settings menu!)".to_string());
    }

    let client = get_client();
    let base = "https://www.virustotal.com/api/v3";

    let url = match kind {
        IndicatorType::Hash => format!("{base}/files/{indicator}"),
        IndicatorType::Domain => format!("{base}/domains/{indicator}"),
        IndicatorType::Ip => format!("{base}/ip_addresses/{indicator}"),
        IndicatorType::Url => {
            let encoded = URL_SAFE_NO_PAD.encode(indicator);
            format!("{base}/urls/{encoded}")
        }
        IndicatorType::InternalIp => return Err("Internal IP: no public data to query.".to_string()),
        IndicatorType::Unknown => return Err("Unknown indicator type".to_string()),
    };

    let cache_key = format!("{kind:?}:{indicator}");
    if let Some(cached) = vt_cache().lock().unwrap().get(&cache_key) {
        return Ok(*cached);
    }

    let resp = client.get(&url).header("x-apikey", api_key).send()
        .map_err(|e| format!("Network Error: {e}"))?;

    if resp.status() == StatusCode::NOT_FOUND {
        vt_cache().lock().unwrap().insert(cache_key, VtStatus::Unknown);
        return Ok(VtStatus::Unknown);
    }
    if resp.status() == StatusCode::TOO_MANY_REQUESTS { return Err("VirusTotal quota exceeded (429)".to_string()); }
    if !resp.status().is_success() { return Err(format!("API Error: {}", resp.status())); }

    let vt: VtResponse = resp.json().map_err(|_| "JSON parsing error".to_string())?;
    let stats = vt.data.attributes.last_analysis_stats;

    let malicious = stats.malicious.unwrap_or(0);
    let suspicious = stats.suspicious.unwrap_or(0);
    let harmless = stats.harmless.unwrap_or(0);
    let undetected = stats.undetected.unwrap_or(0);
    let timeout = stats.timeout.unwrap_or(0);

    // Calculate total engines
    let total = malicious + suspicious + harmless + undetected + timeout;

    let status = if malicious > 0 { VtStatus::Malicious(malicious, total) }
        else if suspicious > 0 { VtStatus::Suspicious(suspicious, total) }
        else { VtStatus::Clean(0, total) };

    vt_cache().lock().unwrap().insert(cache_key, status);
    Ok(status)
}

/// Performs a synchronous API call to AbuseIPDB.
pub fn abuseipdb_lookup(ip: &str, api_key: &str) -> Result<AbuseStatus, String> {
    if api_key.is_empty() || api_key.len() < 10 {
        return Err("Missing AbuseIPDB API Key!".to_string());
    }

    if let Some(cached) = abuse_cache().lock().unwrap().get(ip) {
        return Ok(*cached);
    }

    let client = get_client();
    let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90", ip);

        let resp = client.get(&url)
        .header("Key", api_key)
        .header("Accept", "application/json")
        // AbuseIPDB blocking protection sometimes requires a User-Agent
        .header("User-Agent", "DefendersClipboard/1.0")
        .send()
        .map_err(|e| format!("Network Error: {e}"))?;

    if resp.status() == StatusCode::TOO_MANY_REQUESTS { return Err("AbuseIPDB quota exceeded".to_string()); }
    if !resp.status().is_success() { return Err(format!("AbuseIPDB API Error: {}", resp.status())); }

    let abuse: AbuseResponse = resp.json().map_err(|_| "JSON parsing error".to_string())?;
    let score = abuse.data.abuse_confidence_score;

    let status = if score == 0 { AbuseStatus::Clean(score) }
        else if score == 100 { AbuseStatus::Malicious(score) }
        else { AbuseStatus::Suspicious(score) };

    abuse_cache().lock().unwrap().insert(ip.to_string(), status);
    Ok(status)
}

#[cfg(test)]
mod tests;