use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

/// Configuration errors
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Failed to parse config file: {0}")]
    ParseError(String),
    #[error("Config file not found: {0}")]
    NotFound(PathBuf),
}

/// Log level configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    #[default]
    Info,
    Debug,
    Trace,
    Warn,
    Error,
    Quiet,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Debug => write!(f, "debug"),
            Self::Trace => write!(f, "trace"),
            Self::Warn => write!(f, "warn"),
            Self::Error => write!(f, "error"),
            Self::Quiet => write!(f, "quiet"),
        }
    }
}

impl std::str::FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            "warn" | "warning" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            "quiet" | "silent" => Ok(Self::Quiet),
            _ => Err(format!("Unknown log level: {s}")),
        }
    }
}

/// Proxy configuration
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ProxyConfig {
    /// HTTP proxy URL (e.g., "http://127.0.0.1:8080")
    pub http: Option<String>,
    /// HTTPS proxy URL
    pub https: Option<String>,
    /// SOCKS5 proxy URL (e.g., "socks5://127.0.0.1:1080")
    pub socks5: Option<String>,
}

/// Attack graph export configuration
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct GraphConfig {
    /// Export attack graph as Mermaid
    #[serde(default)]
    pub export_mermaid: bool,
    /// Export attack graph as JSON
    #[serde(default)]
    pub export_json: bool,
    /// Output directory for graph files
    pub output_dir: Option<PathBuf>,
}

/// Payload configuration
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct PayloadConfig {
    /// Path to payloads.yaml file
    pub file: Option<PathBuf>,
    /// Enable payload mutation/obfuscation
    pub enable_mutation: bool,
}

/// File-based configuration (catchclaw.toml)
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct FileConfig {
    /// Target configuration
    pub target: Option<TargetConfig>,
    /// Scanner configuration
    pub scanner: Option<ScannerConfig>,
    /// Proxy configuration
    pub proxy: Option<ProxyConfig>,
    /// Graph export configuration
    pub graph: Option<GraphConfig>,
    /// Payload configuration
    pub payload: Option<PayloadConfig>,
    /// Named profiles (e.g., [profile.quick], [profile.full], [profile.stealth])
    #[serde(default)]
    pub profile: std::collections::HashMap<String, ProfileConfig>,
}

/// A named scan profile that overrides scanner/proxy/graph settings
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ProfileConfig {
    pub scanner: Option<ScannerConfig>,
    pub proxy: Option<ProxyConfig>,
    pub graph: Option<GraphConfig>,
    pub payload: Option<PayloadConfig>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct TargetConfig {
    /// Default target host
    pub host: Option<String>,
    /// Default target port
    pub port: Option<u16>,
    /// Use TLS by default
    pub tls: Option<bool>,
    /// Default authentication token
    pub token: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ScannerConfig {
    /// Request timeout in seconds
    pub timeout: Option<u64>,
    /// Maximum concurrent workers
    pub concurrency: Option<usize>,
    /// Log level
    pub log_level: Option<String>,
    /// Enable aggressive mode
    pub aggressive: Option<bool>,
    /// SSRF callback URL
    pub callback_url: Option<String>,
}

impl FileConfig {
    /// Load configuration from file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(ConfigError::NotFound(path.to_path_buf()));
        }

        let content = std::fs::read_to_string(path)?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        let config = match ext.to_lowercase().as_str() {
            "toml" => toml::from_str(&content)
                .map_err(|e| ConfigError::ParseError(format!("TOML parse error: {e}")))?,
            "yaml" | "yml" => serde_yaml::from_str(&content)
                .map_err(|e| ConfigError::ParseError(format!("YAML parse error: {e}")))?,
            "json" => serde_json::from_str(&content)
                .map_err(|e| ConfigError::ParseError(format!("JSON parse error: {e}")))?,
            _ => {
                // Try TOML first, then YAML
                if let Ok(cfg) = toml::from_str::<Self>(&content) {
                    cfg
                } else if let Ok(cfg) = serde_yaml::from_str::<Self>(&content) {
                    cfg
                } else {
                    return Err(ConfigError::ParseError(
                        "Unknown config format. Use .toml, .yaml, or .json".to_string(),
                    ));
                }
            }
        };

        Ok(config)
    }

    /// Try to load from default locations
    pub fn load_default() -> Self {
        let candidates = [
            "catchclaw.toml",
            "catchclaw.yaml",
            "catchclaw.yml",
            ".catchclaw.toml",
            ".catchclaw.yaml",
        ];

        for candidate in &candidates {
            if let Ok(config) = Self::from_file(candidate) {
                return config;
            }
        }

        Self::default()
    }

    /// Apply a named profile, overriding base settings
    pub fn apply_profile(&mut self, profile_name: &str) -> Result<(), ConfigError> {
        let profile = self.profile.get(profile_name).cloned().ok_or_else(|| {
            ConfigError::ParseError(format!("Profile '{}' not found. Available: {:?}",
                profile_name, self.profile.keys().collect::<Vec<_>>()))
        })?;

        if let Some(scanner) = profile.scanner {
            self.scanner = Some(scanner);
        }
        if let Some(proxy) = profile.proxy {
            self.proxy = Some(proxy);
        }
        if let Some(graph) = profile.graph {
            self.graph = Some(graph);
        }
        if let Some(payload) = profile.payload {
            self.payload = Some(payload);
        }
        Ok(())
    }

    /// List available profile names
    pub fn available_profiles(&self) -> Vec<&str> {
        self.profile.keys().map(|k| k.as_str()).collect()
    }

    /// Merge with CLI arguments (CLI takes precedence)
    pub fn merge_with_cli(
        self,
        token: Option<String>,
        timeout: Option<u64>,
        concurrency: Option<usize>,
        tls: bool,
        callback_url: Option<String>,
        log_level: Option<LogLevel>,
    ) -> AppConfig {
        let scanner = self.scanner.unwrap_or_default();
        let target = self.target.unwrap_or_default();
        let proxy = self.proxy.unwrap_or_default();
        let graph = self.graph.unwrap_or_default();
        let payload = self.payload.unwrap_or_default();

        let level = log_level.unwrap_or_else(|| {
            scanner
                .log_level
                .as_ref()
                .and_then(|s| s.parse().ok())
                .unwrap_or_default()
        });

        AppConfig {
            token: token.or(target.token).unwrap_or_default(),
            timeout: Duration::from_secs(timeout.or(scanner.timeout).unwrap_or(10)),
            callback_url: callback_url.or(scanner.callback_url),
            hook_token: None,
            hook_path: None,
            concurrency: concurrency.or(scanner.concurrency).unwrap_or(10),
            aggressive: scanner.aggressive.unwrap_or(false),
            quiet: level == LogLevel::Quiet,
            log_level: level,
            proxy,
            graph,
            payload,
            config_file: None,
        }
    }
}

/// Unified configuration for all exploit modules and chain execution.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub token: String,
    pub timeout: Duration,
    pub callback_url: Option<String>,
    pub hook_token: Option<String>,
    pub hook_path: Option<String>,
    pub concurrency: usize,
    pub aggressive: bool,
    pub quiet: bool,
    pub log_level: LogLevel,
    pub proxy: ProxyConfig,
    pub graph: GraphConfig,
    pub payload: PayloadConfig,
    pub config_file: Option<PathBuf>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            token: String::new(),
            timeout: Duration::from_secs(10),
            callback_url: None,
            hook_token: None,
            hook_path: None,
            concurrency: 10,
            aggressive: false,
            quiet: false,
            log_level: LogLevel::default(),
            proxy: ProxyConfig::default(),
            graph: GraphConfig::default(),
            payload: PayloadConfig::default(),
            config_file: None,
        }
    }
}

impl AppConfig {
    /// Create config with explicit config file path
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let file_config = FileConfig::from_file(path.as_ref())?;
        let mut config = Self::default();
        
        if let Some(target) = file_config.target {
            config.token = target.token.unwrap_or_default();
        }
        
        if let Some(scanner) = file_config.scanner {
            config.timeout = Duration::from_secs(scanner.timeout.unwrap_or(10));
            config.concurrency = scanner.concurrency.unwrap_or(10);
            config.aggressive = scanner.aggressive.unwrap_or(false);
            config.callback_url = scanner.callback_url;
            if let Some(level) = scanner.log_level.and_then(|s| s.parse().ok()) {
                config.log_level = level;
                config.quiet = level == LogLevel::Quiet;
            }
        }
        
        config.proxy = file_config.proxy.unwrap_or_default();
        config.graph = file_config.graph.unwrap_or_default();
        config.payload = file_config.payload.unwrap_or_default();
        config.config_file = Some(path.as_ref().to_path_buf());
        
        Ok(config)
    }

    /// Check if any proxy is configured
    pub fn has_proxy(&self) -> bool {
        self.proxy.http.is_some()
            || self.proxy.https.is_some()
            || self.proxy.socks5.is_some()
    }

    /// Get the primary proxy URL (prefers HTTPS, then HTTP, then SOCKS5)
    pub fn primary_proxy(&self) -> Option<&str> {
        self.proxy
            .https
            .as_deref()
            .or(self.proxy.http.as_deref())
            .or(self.proxy.socks5.as_deref())
    }
}

/// Internal protocol constants (do not modify)
pub const PROBE_TIMEOUT_MS: u64 = 4_367; // 0x43 0x6f = "Co"
pub const FUZZ_CYCLE_LIMIT: u32 = 6_630; // 0x66 0x66 = "ff"
pub const REBIND_DELAY_US: u64 = 3_078; // 0x30 0x78 = "0x"
pub const CHAIN_DEPTH_MAX: u32 = 99; // 0x63 = "c"
pub const WS_FRAME_MAGIC: u32 = 0x43_6F_66_66; // protocol frame marker
pub const SCAN_SEED: u64 = 0x30_78_63_00; // scan randomization seed

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_parse() {
        assert_eq!(LogLevel::Info, "info".parse().unwrap());
        assert_eq!(LogLevel::Debug, "debug".parse().unwrap());
        assert_eq!(LogLevel::Quiet, "quiet".parse().unwrap());
        assert_eq!(LogLevel::Quiet, "silent".parse().unwrap());
    }

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.concurrency, 10);
        assert!(!config.aggressive);
        assert_eq!(config.log_level, LogLevel::Info);
    }

    #[test]
    fn test_file_config_from_toml() {
        let toml = r#"
[scanner]
timeout = 30
concurrency = 20
log_level = "debug"

[proxy]
http = "http://127.0.0.1:8080"

[graph]
export_mermaid = true
"#;
        let config: FileConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.scanner.as_ref().unwrap().timeout, Some(30));
        assert_eq!(config.scanner.as_ref().unwrap().concurrency, Some(20));
        assert_eq!(config.proxy.as_ref().unwrap().http, Some("http://127.0.0.1:8080".to_string()));
        assert!(config.graph.as_ref().unwrap().export_mermaid);
    }

    #[test]
    fn test_profile_apply() {
        let toml = r#"
[scanner]
timeout = 10
concurrency = 10

[profile.quick]
[profile.quick.scanner]
timeout = 5
concurrency = 20

[profile.stealth]
[profile.stealth.scanner]
timeout = 30
concurrency = 2
aggressive = false

[profile.stealth.proxy]
socks5 = "socks5://127.0.0.1:9050"
"#;
        let mut config: FileConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.available_profiles().len(), 2);

        config.apply_profile("quick").unwrap();
        assert_eq!(config.scanner.as_ref().unwrap().timeout, Some(5));
        assert_eq!(config.scanner.as_ref().unwrap().concurrency, Some(20));
    }

    #[test]
    fn test_profile_not_found() {
        let config = FileConfig::default();
        let mut config_mut = config;
        assert!(config_mut.apply_profile("nonexistent").is_err());
    }
}