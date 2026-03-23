//! Mutation Engine for Evasion
//!
//! Provides payload obfuscation and mutation capabilities for bypassing
//! WAF and security filters.

use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use rand::seq::SliceRandom;

/// Types of payload mutations available
#[derive(Debug, Clone)]
pub enum MutationType {
    /// Replace characters with Unicode homoglyphs
    UnicodeHomoglyph,
    /// Base64 encode the payload
    Base64Wrap,
    /// Hex encode the payload
    HexWrap,
    /// Add random junk padding
    JunkPadding(u8), // 0-10 intensity
    /// Apply multiple mutations in sequence
    MultiLayer(Vec<MutationType>),
    /// URL encode special characters
    UrlEncode,
    /// Double URL encode
    DoubleUrlEncode,
    /// Unicode escape sequences
    UnicodeEscape,
    /// HTML entity encoding
    HtmlEntity,
    /// Case variation
    CaseVariation,
}

/// Dynamic mutator for payload obfuscation.
pub struct PayloadMutator;

impl PayloadMutator {
    /// Mutate a base string using the specified mutation type.
    pub fn mutate(base: &str, mtype: &MutationType) -> String {
        match mtype {
            MutationType::UnicodeHomoglyph => Self::unicode_homoglyph(base),
            MutationType::Base64Wrap => Self::base64_encode(base),
            MutationType::HexWrap => Self::hex_encode(base),
            MutationType::JunkPadding(intensity) => Self::add_junk(base, *intensity),
            MutationType::MultiLayer(types) => {
                let mut current = base.to_string();
                for t in types {
                    current = Self::mutate(&current, t);
                }
                current
            }
            MutationType::UrlEncode => Self::url_encode(base),
            MutationType::DoubleUrlEncode => Self::url_encode(&Self::url_encode(base)),
            MutationType::UnicodeEscape => Self::unicode_escape(base),
            MutationType::HtmlEntity => Self::html_entity_encode(base),
            MutationType::CaseVariation => Self::case_variation(base),
        }
    }

    /// Base64 encode using the modern API
    fn base64_encode(input: &str) -> String {
        general_purpose::STANDARD.encode(input)
    }

    /// Hex encode a string
    fn hex_encode(input: &str) -> String {
        input
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    /// URL encode special characters
    fn url_encode(input: &str) -> String {
        urlencoding::encode(input).into_owned()
    }

    /// Unicode escape sequences
    fn unicode_escape(input: &str) -> String {
        input
            .chars()
            .map(|c| format!("\\u{:04x}", c as u32))
            .collect()
    }

    /// HTML entity encoding
    fn html_entity_encode(input: &str) -> String {
        input
            .chars()
            .map(|c| match c {
                '<' => "&lt;".to_string(),
                '>' => "&gt;".to_string(),
                '"' => "&quot;".to_string(),
                '\'' => "&#39;".to_string(),
                '&' => "&amp;".to_string(),
                _ => c.to_string(),
            })
            .collect()
    }

    /// Case variation for case-insensitive bypasses
    fn case_variation(input: &str) -> String {
        let mut rng = rand::thread_rng();
        input
            .chars()
            .map(|c| {
                if c.is_ascii_alphabetic() && rng.gen_bool(0.5) {
                    if c.is_ascii_lowercase() {
                        c.to_ascii_uppercase()
                    } else {
                        c.to_ascii_lowercase()
                    }
                } else {
                    c
                }
            })
            .collect()
    }

    /// Replace common symbols with look-alike Unicode characters.
    fn unicode_homoglyph(input: &str) -> String {
        input
            .chars()
            .map(|c| match c {
                '/' => '\u{2215}', // DIVISION SLASH
                '.' => '\u{2024}', // ONE DOT LEADER
                'A' => '\u{0391}', // GREEK CAPITAL ALPHA
                'B' => '\u{0392}', // GREEK CAPITAL BETA
                'E' => '\u{0395}', // GREEK CAPITAL EPSILON
                'O' => '\u{039F}', // GREEK CAPITAL OMICRON
                'P' => '\u{03A1}', // GREEK CAPITAL RHO
                'H' => '\u{0397}', // GREEK CAPITAL ETA
                'C' => '\u{0421}', // CYRILLIC CAPITAL ES
                'a' => '\u{0430}', // CYRILLIC SMALL A
                'c' => '\u{0441}', // CYRILLIC SMALL ES
                'e' => '\u{0435}', // CYRILLIC SMALL IE
                'o' => '\u{043E}', // CYRILLIC SMALL O
                'p' => '\u{0440}', // CYRILLIC SMALL ER
                'x' => '\u{0445}', // CYRILLIC SMALL HA
                'y' => '\u{0443}', // CYRILLIC SMALL U
                _ => c,
            })
            .collect()
    }

    /// Add non-functional junk characters to bypass signature matching.
    fn add_junk(input: &str, intensity: u8) -> String {
        let mut rng = rand::thread_rng();
        let mut output = String::new();
        let junk_chars = [' ', '\t', '\n', '\r', '\u{200B}']; // Zero-width space included

        for c in input.chars() {
            output.push(c);
            if rng.gen_bool(0.1 * intensity as f64) {
                output.push(*junk_chars.choose(&mut rng).unwrap());
            }
        }
        output
    }

    /// Create an adaptive mutation chain based on WAF detection.
    pub fn get_stealth_chain() -> MutationType {
        MutationType::MultiLayer(vec![
            MutationType::UnicodeHomoglyph,
            MutationType::JunkPadding(2),
        ])
    }

    /// Create a heavy obfuscation chain for strict filters
    pub fn get_heavy_chain() -> MutationType {
        MutationType::MultiLayer(vec![
            MutationType::UnicodeHomoglyph,
            MutationType::CaseVariation,
            MutationType::JunkPadding(3),
        ])
    }

    /// Create encoding-only chain (no structural changes)
    pub fn get_encoding_chain() -> MutationType {
        MutationType::MultiLayer(vec![MutationType::Base64Wrap])
    }

    /// Detect if a response indicates WAF blocking
    pub fn is_waf_blocked(status: reqwest::StatusCode, body: &str) -> bool {
        let waf_indicators = [
            "blocked",
            "forbidden",
            "waf",
            "firewall",
            "security",
            "attack detected",
            "malicious",
            "rejected",
            "access denied",
            "cloudflare",
            "akamai",
            "incapsula",
            "sucuri",
        ];

        let lower = body.to_lowercase();
        let status_blocked = status == reqwest::StatusCode::FORBIDDEN
            || status == reqwest::StatusCode::NOT_ACCEPTABLE
            || status == reqwest::StatusCode::BAD_REQUEST;

        status_blocked || waf_indicators.iter().any(|w| lower.contains(w))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        let result = PayloadMutator::mutate("hello", &MutationType::Base64Wrap);
        assert_eq!(result, "aGVsbG8=");
    }

    #[test]
    fn test_hex_encode() {
        let result = PayloadMutator::mutate("AB", &MutationType::HexWrap);
        assert_eq!(result, "4142");
    }

    #[test]
    fn test_unicode_homoglyph() {
        let result = PayloadMutator::mutate("AB", &MutationType::UnicodeHomoglyph);
        // A -> Greek Alpha, B -> Greek Beta
        assert_ne!(result, "AB");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_multi_layer() {
        let chain = MutationType::MultiLayer(vec![
            MutationType::Base64Wrap,
            MutationType::HexWrap,
        ]);
        let result = PayloadMutator::mutate("A", &chain);
        // First base64: "A" -> "QQ==", then hex: "51513d3d"
        assert_eq!(result, "51513d3d");
    }

    #[test]
    fn test_url_encode() {
        let result = PayloadMutator::mutate("<script>", &MutationType::UrlEncode);
        assert!(result.contains("%3C"));
        assert!(result.contains("%3E"));
    }

    #[test]
    fn test_html_entity() {
        let result = PayloadMutator::mutate("<script>", &MutationType::HtmlEntity);
        assert_eq!(result, "&lt;script&gt;");
    }

    #[test]
    fn test_case_variation() {
        let result = PayloadMutator::mutate("AAAA", &MutationType::CaseVariation);
        // Should have some variation (statistical test)
        assert_ne!(result, "aaaa"); // Shouldn't be all lowercase
    }

    #[test]
    fn test_stealth_chain() {
        let chain = PayloadMutator::get_stealth_chain();
        let result = PayloadMutator::mutate("test", &chain);
        // Should contain some mutation
        assert!(!result.is_empty());
    }
}