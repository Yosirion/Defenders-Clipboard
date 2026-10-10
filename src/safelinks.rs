//! Unwraps "safe link" / click-time-protection URLs back to the original destination.
//!
//! Only formats whose original URL is embedded in the link itself (plain, percent-
//! encoded or base64) can be recovered offline. Services that wrap links in an opaque
//! server-side token (e.g. Mimecast) or in a compressed blob (e.g. Forcepoint) are not
//! supported: they can only be resolved by the vendor's own service.

use std::sync::OnceLock;

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use regex::Regex;
use url::Url;

/// Max wrapping layers peeled off a single link (a safe link can wrap another one).
const MAX_NESTING: usize = 5;

/// Lowercase substrings that cheaply tell whether a text *might* hold a wrapped link,
/// so the (per-frame) UI check can bail out before doing any URL parsing.
const MARKERS: [&str; 6] = [
    "safelinks.protection",
    "urldefense.",
    "cudasvc.com",
    "checkpoint.com",
    "secure-web.cisco.com",
    "protection.sophos.com",
];

// Tolerant decoders: wrapped links often drop the '=' padding.
const B64_STANDARD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);
const B64_URL_SAFE: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

static RE_URL: OnceLock<Regex> = OnceLock::new();

fn re_url() -> &'static Regex {
    RE_URL.get_or_init(|| Regex::new(r#"(?i)\bhttps?://[^\s<>"']+"#).unwrap())
}

/// Cheap pre-check used before any parsing.
fn has_known_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    MARKERS.iter().any(|m| lower.contains(m))
}

fn query_param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs().find(|(k, _)| k == name).map(|(_, v)| v.into_owned())
}

fn looks_like_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://")
}

/// Proofpoint v2 encoding: '_' stands for '/', and "-XX" is a percent-escape.
fn proofpoint_v2_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let hex = |b: u8| (b as char).to_digit(16);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'_' => {
                out.push(b'/');
                i += 1;
            }
            b'-' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                }
                _ => {
                    out.push(b'-');
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Proofpoint v3: `/v3/__<url>__;<base64 of the chars replaced by '*'>!!<id>$`.
/// Works on the raw string because the embedded URL's own '?' would otherwise be
/// parsed as the start of the outer query string.
fn proofpoint_v3(raw: &str) -> Option<String> {
    let rest = raw.split_once("/v3/__")?.1;
    let (inner, tail) = rest.split_once("__;")?;
    if !inner.contains('*') {
        return Some(inner.to_string());
    }

    // Each '*' stands for one ASCII char listed (base64) before the "!!" separator.
    // If the counts don't line up the format isn't what we expect: refuse to guess.
    let b64 = tail.split("!!").next()?.trim_end_matches('=');
    let replaced = B64_STANDARD.decode(b64).or_else(|_| B64_URL_SAFE.decode(b64)).ok()?;
    if !replaced.is_ascii() || replaced.len() != inner.matches('*').count() {
        return None;
    }

    let mut replacements = replaced.into_iter();
    let mut out = String::with_capacity(inner.len());
    for c in inner.chars() {
        if c == '*' {
            out.push(replacements.next()? as char);
        } else {
            out.push(c);
        }
    }
    Some(out)
}

fn proofpoint(raw: &str, url: &Url) -> Option<String> {
    let path = url.path();
    if path.starts_with("/v3/") {
        proofpoint_v3(raw)
    } else if path.starts_with("/v2/") {
        query_param(url, "u").map(|u| proofpoint_v2_decode(&u))
    } else if path.starts_with("/v1/") {
        query_param(url, "u")
    } else {
        None
    }
}

/// Check Point / Avanan: `/v2/___<url>___.<token>`.
fn checkpoint(raw: &str) -> Option<String> {
    let rest = raw.split_once("/v2/___")?.1;
    let (inner, _token) = rest.split_once("___.")?;
    Some(inner.to_string())
}

/// Cisco Secure Email: `/<token>/<percent-encoded url>`.
fn cisco(url: &Url) -> Option<String> {
    let path = url.path().trim_start_matches('/');
    let (_token, encoded) = path.split_once('/')?;
    let mut decoded = urlencoding::decode(encoded).ok()?.into_owned();
    if let Some(q) = url.query() {
        decoded.push('?');
        decoded.push_str(q);
    }
    Some(decoded)
}

/// Sophos: `?u=<base64 of the url>`.
fn sophos(url: &Url) -> Option<String> {
    let b64 = query_param(url, "u")?;
    let b64 = b64.trim_end_matches('=');
    let bytes = B64_URL_SAFE.decode(b64).or_else(|_| B64_STANDARD.decode(b64)).ok()?;
    String::from_utf8(bytes).ok()
}

/// Removes ONE layer of wrapping from `raw`, if it is a link from a supported service.
pub fn unwrap_url(raw: &str) -> Option<String> {
    let url = Url::parse(raw.trim()).ok()?;
    let host = url.host_str()?.to_ascii_lowercase();

    let inner = if host.starts_with("safelinks.protection.") || host.contains(".safelinks.protection.") {
        query_param(&url, "url")
    } else if host.starts_with("urldefense.") {
        proofpoint(raw.trim(), &url)
    } else if host == "linkprotect.cudasvc.com" {
        query_param(&url, "a")
    } else if host.starts_with("protect") && host.ends_with("checkpoint.com") {
        checkpoint(raw.trim())
    } else if host == "secure-web.cisco.com" {
        cisco(&url)
    } else if host == "protection.sophos.com" || host.ends_with(".protection.sophos.com") {
        sophos(&url)
    } else {
        None
    }?;

    looks_like_url(&inner).then_some(inner)
}

/// Peels off every wrapping layer (a safe link may wrap another one).
pub fn unwrap_fully(raw: &str) -> Option<String> {
    let mut current = unwrap_url(raw)?;
    for _ in 1..MAX_NESTING {
        match unwrap_url(&current) {
            Some(next) => current = next,
            None => break,
        }
    }
    Some(current)
}

/// Replaces every supported wrapped link inside `text` with its original URL, leaving
/// the surrounding text untouched. `None` when there was nothing to unwrap.
pub fn unwrap_all(text: &str) -> Option<String> {
    if !has_known_marker(text) {
        return None;
    }

    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut changed = false;

    for m in re_url().find_iter(text) {
        // Sentence punctuation right after a link is not part of it.
        let candidate = m
            .as_str()
            .trim_end_matches(|c| matches!(c, '.' | ',' | ';' | '!' | '?' | ')' | ']' | '>'));
        if let Some(clean) = unwrap_fully(candidate) {
            out.push_str(&text[last..m.start()]);
            out.push_str(&clean);
            last = m.start() + candidate.len();
            changed = true;
        }
    }

    if !changed {
        return None;
    }
    out.push_str(&text[last..]);
    Some(out)
}

/// Whether `text` contains at least one link `unwrap_all` can clean.
pub fn contains_wrapped(text: &str) -> bool {
    unwrap_all(text).is_some()
}

#[cfg(test)]
mod tests;
