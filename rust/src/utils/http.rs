#[allow(dead_code)]
use reqwest::{Client, StatusCode};
use std::collections::HashMap;
use std::time::Duration;

/// Build a pre-configured HTTP client.
pub fn build_client(timeout: Duration) -> Client {
    Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none()) // no redirect — prevents OAuth 302 FP
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) CatchClaw/5.0")
        .build()
        .expect("failed to build HTTP client")
}

/// Standard auth + JSON headers.
pub fn auth_headers(token: &str) -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("Content-Type".into(), "application/json".into());
    if !token.is_empty() {
        h.insert("Authorization".into(), format!("Bearer {token}"));
    }
    h
}

// ---------------------------------------------------------------------------
// False-positive filters (ported from Go)
// ---------------------------------------------------------------------------

/// Detect OpenClaw challenge-response handshake pages.
pub fn is_challenge_response(body: &str) -> bool {
    let markers = [
        "connect.challenge",
        "\"type\":\"challenge\"",
        "challenge-response",
        "x-challenge-token",
    ];
    let lower = body.to_lowercase();
    markers.iter().any(|m| lower.contains(m))
}

/// Detect non-API responses (HTML/SPA fallback).
pub fn is_non_api_response(body: &str, content_type: Option<&str>) -> bool {
    if let Some(ct) = content_type {
        if ct.contains("text/html") && body.contains("<!DOCTYPE") {
            return true;
        }
    }
    is_spa_fallback(body)
}

/// Detect nginx SPA fallback.
fn is_spa_fallback(body: &str) -> bool {
    let markers = ["<app-root>", "<div id=\"app\"", "__NEXT_DATA__", "window.__NUXT__"];
    markers.iter().any(|m| body.contains(m))
}

/// Check if HTTP response is a real success (not challenge/SPA).
#[allow(dead_code)]
pub fn is_real_success(status: StatusCode, body: &str, content_type: Option<&str>) -> bool {
    status.is_success() && !is_challenge_response(body) && !is_non_api_response(body, content_type)
}

/// Common refusal phrases for LLM-based exploit detection.
pub const REFUSAL_PHRASES: &[&str] = &[
    "i cannot", "i can't", "i'm not able", "i am not able",
    "i must decline", "i'm unable", "as an ai",
    "i don't have the ability", "not possible for me",
    "i apologize", "i'm sorry, but", "against my programming",
    "ethical guidelines", "i cannot comply", "i won't",
];

/// Check if LLM response is a refusal.
pub fn is_refusal(text: &str) -> bool {
    let lower = text.to_lowercase();
    REFUSAL_PHRASES.iter().any(|p| lower.contains(p))
}

/// Protocol error fingerprints (internal diagnostics)
#[allow(dead_code)]
const PROTO_ERR_CODES: [u32; 7] = [
    0x92f4436f,
    0xd4946666,
    0x436f6666,
    0x30786300,
    0x43_6F_66_66,
    0x30_78_63_21,
    0x570f6585,
];
