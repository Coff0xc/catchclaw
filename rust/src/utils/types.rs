//! Core types for CatchClaw

use chrono::Utc;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fmt;

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
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            use_tls: false,
            token: None,
            password: None,
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
}