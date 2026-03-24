//! Core types for CatchClaw

use chrono::Utc;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv4Addr;

use crate::platform::TargetPlatform;

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn score(self) -> u32 {
        match self {
            Self::Info => 1,
            Self::Low => 3,
            Self::Medium => 8,
            Self::High => 15,
            Self::Critical => 25,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Info => "INFO".cyan(),
            Self::Low => "LOW".blue(),
            Self::Medium => "MEDIUM".yellow(),
            Self::High => "HIGH".red(),
            Self::Critical => "CRITICAL".on_red().white().bold(),
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Target
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub use_tls: bool,
    pub token: Option<String>,
    pub password: Option<String>,
    #[serde(skip)]
    pub platform: TargetPlatform,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            use_tls: false,
            token: None,
            password: None,
            platform: TargetPlatform::Unknown,
        }
    }

    pub fn base_url(&self) -> String {
        let scheme = if self.use_tls { "https" } else { "http" };
        format!("{scheme}://{}:{}", self.host, self.port)
    }

    pub fn ws_url(&self) -> String {
        let scheme = if self.use_tls { "wss" } else { "ws" };
        format!("{scheme}://{}:{}", self.host, self.port)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub target: String,
    pub module: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    pub timestamp: String,
}

impl Finding {
    pub fn new(
        target: impl Into<String>,
        module: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        description: impl Into<String>,
    ) -> Self {
        Self {
            target: target.into(),
            module: module.into(),
            title: title.into(),
            severity,
            description: description.into(),
            evidence: None,
            remediation: None,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    pub fn print(&self) {
        println!(
            "  [{severity}] {title}",
            severity = self.severity,
            title = self.title
        );
        println!("    Module: {}", self.module);
        println!("    {}", self.description);
        if let Some(ev) = &self.evidence {
            let truncated = truncate_str(ev, 200);
            println!("    Evidence: {truncated}");
        }
    }
}

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: Target,
    pub findings: Vec<Finding>,
    pub start_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_at: Option<String>,
}

impl ScanResult {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            findings: Vec::new(),
            start_at: Utc::now().to_rfc3339(),
            end_at: None,
        }
    }

    pub fn add(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn done(&mut self) {
        self.end_at = Some(Utc::now().to_rfc3339());
    }

    pub fn count_by_severity(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }

    pub fn chain_score(&self) -> u32 {
        self.findings.iter().map(|f| f.severity.score()).sum()
    }
}

/// Safely truncate a string to at most `max_bytes` bytes without splitting a multi-byte char.
pub fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ---------------------------------------------------------------------------
// Multi-target parsing
// ---------------------------------------------------------------------------

const MAX_GENERATED_IPS: u32 = 65536;

/// Parse a single "host:port" into a Target, defaulting port based on TLS.
fn parse_single_target(spec: &str, tls: bool) -> Target {
    let spec = spec.trim();
    let parts: Vec<&str> = spec.splitn(2, ':').collect();
    let host = parts[0].to_string();
    let port = parts
        .get(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(if tls { 443 } else { 8080 });
    let mut t = Target::new(host, port);
    t.use_tls = tls;
    t
}

/// Parse various target formats into a list of Targets.
///
/// Supported formats:
/// - `"host:port"` — single target
/// - `"host1:port,host2:port"` — comma-separated
/// - `"192.168.1.0/24:8080"` — CIDR with port
/// - `"10.0.0.1-10.0.0.255:8080"` — IP range with port
pub fn parse_targets(spec: &str, tls: bool) -> Vec<Target> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Vec::new();
    }

    // Comma-separated: delegate each part recursively
    if spec.contains(',') {
        return spec
            .split(',')
            .flat_map(|s| parse_targets(s, tls))
            .collect();
    }

    // CIDR: "ip/prefix:port"
    if let Some(targets) = try_parse_cidr(spec, tls) {
        return targets;
    }

    // IP range: "start-end:port"
    if let Some(targets) = try_parse_range(spec, tls) {
        return targets;
    }

    // Single target
    vec![parse_single_target(spec, tls)]
}

/// Try parsing CIDR notation like "192.168.1.0/24:8080".
fn try_parse_cidr(spec: &str, tls: bool) -> Option<Vec<Target>> {
    // Must contain '/' to be CIDR
    let slash_pos = spec.find('/')?;
    let ip_str = &spec[..slash_pos];

    // Remaining after slash: "prefix:port" or "prefix"
    let after_slash = &spec[slash_pos + 1..];
    let (prefix_str, port) = if let Some(colon) = after_slash.find(':') {
        let prefix = &after_slash[..colon];
        let port_str = &after_slash[colon + 1..];
        (prefix, port_str.parse::<u16>().ok())
    } else {
        (after_slash, None)
    };

    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }

    let port = port.unwrap_or(if tls { 443 } else { 8080 });
    let ip_u32 = u32::from(ip);
    let host_bits = 32 - prefix;
    let count = 1u32 << host_bits;

    if count > MAX_GENERATED_IPS {
        eprintln!(
            "[!] CIDR /{prefix} would generate {count} IPs, capped at {MAX_GENERATED_IPS}"
        );
        return Some(Vec::new());
    }

    let network = ip_u32 & (!0u32 << host_bits);
    let skip_endpoints = prefix < 31 && host_bits >= 2;

    let targets = (0..count)
        .filter(|i| {
            if skip_endpoints {
                *i != 0 && *i != count - 1
            } else {
                true
            }
        })
        .map(|i| {
            let addr = Ipv4Addr::from(network + i);
            let mut t = Target::new(addr.to_string(), port);
            t.use_tls = tls;
            t
        })
        .collect();

    Some(targets)
}

/// Try parsing IP range like "10.0.0.1-10.0.0.5:8080".
fn try_parse_range(spec: &str, tls: bool) -> Option<Vec<Target>> {
    let dash_pos = spec.find('-')?;
    let start_str = &spec[..dash_pos];
    // Validate it looks like an IP
    start_str.parse::<Ipv4Addr>().ok()?;

    let after_dash = &spec[dash_pos + 1..];
    let (end_str, port) = if let Some(colon) = after_dash.rfind(':') {
        let candidate_end = &after_dash[..colon];
        if candidate_end.parse::<Ipv4Addr>().is_ok() {
            let port_str = &after_dash[colon + 1..];
            (candidate_end, port_str.parse::<u16>().ok())
        } else {
            (after_dash, None)
        }
    } else {
        (after_dash, None)
    };

    let start: Ipv4Addr = start_str.parse().ok()?;
    let end: Ipv4Addr = end_str.parse().ok()?;
    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);

    if end_u32 < start_u32 {
        return Some(Vec::new());
    }

    let count = end_u32 - start_u32 + 1;
    if count > MAX_GENERATED_IPS {
        eprintln!(
            "[!] IP range would generate {count} IPs, capped at {MAX_GENERATED_IPS}"
        );
        return Some(Vec::new());
    }

    let port = port.unwrap_or(if tls { 443 } else { 8080 });
    let targets = (start_u32..=end_u32)
        .map(|ip| {
            let addr = Ipv4Addr::from(ip);
            let mut t = Target::new(addr.to_string(), port);
            t.use_tls = tls;
            t
        })
        .collect();

    Some(targets)
}

/// Read targets from a file (one per line), skipping empty lines and comments.
pub fn parse_targets_file(path: &std::path::Path, tls: bool) -> std::io::Result<Vec<Target>> {
    let content = std::fs::read_to_string(path)?;
    let targets = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .flat_map(|l| parse_targets(l, tls))
        .collect();
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Severity ---

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_scores() {
        assert_eq!(Severity::Info.score(), 1);
        assert_eq!(Severity::Low.score(), 3);
        assert_eq!(Severity::Medium.score(), 8);
        assert_eq!(Severity::High.score(), 15);
        assert_eq!(Severity::Critical.score(), 25);
    }

    // --- Target ---

    #[test]
    fn target_base_url() {
        let t = Target::new("10.0.0.1", 8080);
        assert_eq!(t.base_url(), "http://10.0.0.1:8080");
    }

    #[test]
    fn target_tls_url() {
        let mut t = Target::new("example.com", 443);
        t.use_tls = true;
        assert_eq!(t.base_url(), "https://example.com:443");
        assert_eq!(t.ws_url(), "wss://example.com:443");
    }

    #[test]
    fn target_display() {
        let t = Target::new("host", 9090);
        assert_eq!(format!("{t}"), "host:9090");
    }

    // --- Finding ---

    #[test]
    fn finding_builder() {
        let f = Finding::new("target", "mod", "title", Severity::High, "desc")
            .with_evidence("ev")
            .with_remediation("fix");
        assert_eq!(f.evidence.as_deref(), Some("ev"));
        assert_eq!(f.remediation.as_deref(), Some("fix"));
        assert_eq!(f.severity, Severity::High);
    }

    // --- ScanResult ---

    #[test]
    fn scan_result_count_by_severity() {
        let t = Target::new("h", 80);
        let mut r = ScanResult::new(t);
        r.add(Finding::new("h:80", "m", "a", Severity::High, "d"));
        r.add(Finding::new("h:80", "m", "b", Severity::High, "d"));
        r.add(Finding::new("h:80", "m", "c", Severity::Low, "d"));
        assert_eq!(r.count_by_severity(Severity::High), 2);
        assert_eq!(r.count_by_severity(Severity::Low), 1);
        assert_eq!(r.count_by_severity(Severity::Critical), 0);
    }

    #[test]
    fn scan_result_chain_score() {
        let t = Target::new("h", 80);
        let mut r = ScanResult::new(t);
        r.add(Finding::new("h:80", "m", "a", Severity::Critical, "d")); // 25
        r.add(Finding::new("h:80", "m", "b", Severity::High, "d")); // 15
        assert_eq!(r.chain_score(), 40);
    }

    // --- truncate_str ---

    #[test]
    fn truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_str_exact() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn truncate_str_cuts() {
        assert_eq!(truncate_str("hello world", 5), "hello");
    }

    #[test]
    fn truncate_str_multibyte_safe() {
        // "你好" = 6 bytes (3 per char), truncate at 4 should give "你" (3 bytes)
        assert_eq!(truncate_str("你好", 4), "你");
    }

    #[test]
    fn truncate_str_empty() {
        assert_eq!(truncate_str("", 10), "");
    }

    // --- parse_targets ---

    #[test]
    fn parse_targets_single() {
        let targets = parse_targets("10.0.0.1:8080", false);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "10.0.0.1");
        assert_eq!(targets[0].port, 8080);
    }

    #[test]
    fn parse_targets_comma_separated() {
        let targets = parse_targets("10.0.0.1:8080,10.0.0.2:9090", false);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].host, "10.0.0.1");
        assert_eq!(targets[0].port, 8080);
        assert_eq!(targets[1].host, "10.0.0.2");
        assert_eq!(targets[1].port, 9090);
    }

    #[test]
    fn parse_targets_cidr_24() {
        let targets = parse_targets("192.168.1.0/24:8080", false);
        // /24 = 256 IPs, minus network and broadcast = 254
        assert_eq!(targets.len(), 254);
        assert_eq!(targets[0].host, "192.168.1.1");
        assert_eq!(targets[253].host, "192.168.1.254");
        assert_eq!(targets[0].port, 8080);
    }

    #[test]
    fn parse_targets_cidr_32() {
        let targets = parse_targets("10.0.0.5/32:443", true);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "10.0.0.5");
        assert_eq!(targets[0].port, 443);
        assert!(targets[0].use_tls);
    }

    #[test]
    fn parse_targets_ip_range() {
        let targets = parse_targets("10.0.0.1-10.0.0.5:8080", false);
        assert_eq!(targets.len(), 5);
        assert_eq!(targets[0].host, "10.0.0.1");
        assert_eq!(targets[4].host, "10.0.0.5");
    }

    #[test]
    fn parse_targets_default_port() {
        let targets = parse_targets("example.com", false);
        assert_eq!(targets[0].port, 8080);
        let targets_tls = parse_targets("example.com", true);
        assert_eq!(targets_tls[0].port, 443);
    }

    #[test]
    fn parse_targets_empty() {
        assert!(parse_targets("", false).is_empty());
    }

    #[test]
    fn parse_targets_file_roundtrip() {
        let dir = std::env::temp_dir().join("catchclaw_test_targets");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("targets.txt");
        std::fs::write(&file, "10.0.0.1:8080\n# comment\n10.0.0.2:9090\n\n").unwrap();
        let targets = parse_targets_file(&file, false).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].host, "10.0.0.1");
        assert_eq!(targets[1].host, "10.0.0.2");
        let _ = std::fs::remove_dir_all(&dir);
    }
}