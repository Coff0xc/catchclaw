//! Payload Registry - Centralized payload management from YAML
//!
//! This module provides a unified interface for loading and accessing
//! attack payloads from the centralized payloads.yaml file.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;
use thiserror::Error;

/// Payload registry errors
#[derive(Debug, Error)]
pub enum PayloadError {
    #[error("Failed to read payload file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Failed to parse payload file: {0}")]
    ParseError(String),
    #[error("Payload category not found: {0}")]
    CategoryNotFound(String),
    #[error("Payload key not found: {0}.{1}")]
    PayloadNotFound(String, String),
}

/// Single payload entry
#[derive(Debug, Clone, Deserialize)]
pub struct PayloadEntry {
    /// Optional name/key for the payload
    #[serde(flatten)]
    pub data: HashMap<String, String>,
}

/// All payload categories from payloads.yaml
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PayloadRegistry {
    // Fuzzer payloads
    pub xss: Option<Vec<PayloadEntry>>,
    pub sqli: Option<Vec<PayloadEntry>>,
    pub ssrf: Option<Vec<PayloadEntry>>,
    pub cmdi: Option<Vec<PayloadEntry>>,
    pub prompt_inject: Option<Vec<PayloadEntry>>,

    // Exploit module payloads
    pub ssrf_exploit: Option<Vec<PayloadEntry>>,
    pub ssrf_ipv6: Option<Vec<PayloadEntry>>,
    pub ssrf_proxy: Option<Vec<PayloadEntry>>,
    pub ssrf_rebind: Option<Vec<PayloadEntry>>,
    pub prompt_exploit: Option<Vec<PayloadEntry>>,
    pub c2_exfil: Option<Vec<PayloadEntry>>,
    pub cmdi_exploit: Option<Vec<PayloadEntry>>,
    pub rce_exploit: Option<Vec<PayloadEntry>>,
    pub marker_spoof: Option<Vec<PayloadEntry>>,
    pub skill_bypass: Option<Vec<PayloadEntry>>,
    pub canary: Option<Vec<PayloadEntry>>,

    // Wordlists
    pub default_tokens: Option<Vec<PayloadEntry>>,
    pub sensitive_indicators: Option<Vec<PayloadEntry>>,
    pub skill_poison: Option<Vec<PayloadEntry>>,
    pub sqli_detect: Option<Vec<PayloadEntry>>,

    // Probe bodies
    pub probe: Option<Vec<PayloadEntry>>,

    // SSRF variants
    pub browser_ssrf: Option<Vec<PayloadEntry>>,
    pub cron_ssrf: Option<Vec<PayloadEntry>>,
    pub gateway_ssrf: Option<Vec<PayloadEntry>>,
    pub media_ssrf: Option<Vec<PayloadEntry>>,
    pub ssrf_rebind_extra: Option<Vec<PayloadEntry>>,
    pub media_ssrf_bypass: Option<Vec<PayloadEntry>>,

    // Injection payloads
    pub agent_inject: Option<Vec<PayloadEntry>>,
    pub obfuscation: Option<Vec<PayloadEntry>>,
    pub hook_inject: Option<Vec<PayloadEntry>>,
}

impl PayloadRegistry {
    /// Load payload registry from file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, PayloadError> {
        let content = std::fs::read_to_string(path)?;
        let registry: Self = serde_yaml::from_str(&content)
            .map_err(|e| PayloadError::ParseError(format!("YAML parse error: {e}")))?;
        Ok(registry)
    }

    /// Load from default location
    pub fn load_default() -> &'static Self {
        static REGISTRY: OnceLock<PayloadRegistry> = OnceLock::new();
        
        REGISTRY.get_or_init(|| {
            let candidates = [
                "payloads.yaml",
                "../payloads.yaml",
                "../../payloads.yaml",
                "/etc/catchclaw/payloads.yaml",
            ];

            for candidate in &candidates {
                if let Ok(registry) = Self::from_file(candidate) {
                    tracing::info!("Loaded payloads from {}", candidate);
                    return registry;
                }
            }

            tracing::warn!("No payloads.yaml found, using empty registry");
            Self::default()
        })
    }

    /// Get all payloads from a category as string slice
    pub fn get_category(&self, category: &str) -> Result<Vec<&str>, PayloadError> {
        let entries = match category {
            "xss" => self.xss.as_ref(),
            "sqli" => self.sqli.as_ref(),
            "ssrf" => self.ssrf.as_ref(),
            "cmdi" => self.cmdi.as_ref(),
            "prompt_inject" => self.prompt_inject.as_ref(),
            "ssrf_exploit" => self.ssrf_exploit.as_ref(),
            "ssrf_ipv6" => self.ssrf_ipv6.as_ref(),
            "ssrf_proxy" => self.ssrf_proxy.as_ref(),
            "ssrf_rebind" => self.ssrf_rebind.as_ref(),
            "prompt_exploit" => self.prompt_exploit.as_ref(),
            "c2_exfil" => self.c2_exfil.as_ref(),
            "cmdi_exploit" => self.cmdi_exploit.as_ref(),
            "rce_exploit" => self.rce_exploit.as_ref(),
            "marker_spoof" => self.marker_spoof.as_ref(),
            "skill_bypass" => self.skill_bypass.as_ref(),
            "canary" => self.canary.as_ref(),
            "default_tokens" => self.default_tokens.as_ref(),
            "sensitive_indicators" => self.sensitive_indicators.as_ref(),
            "skill_poison" => self.skill_poison.as_ref(),
            "sqli_detect" => self.sqli_detect.as_ref(),
            "probe" => self.probe.as_ref(),
            "browser_ssrf" => self.browser_ssrf.as_ref(),
            "cron_ssrf" => self.cron_ssrf.as_ref(),
            "gateway_ssrf" => self.gateway_ssrf.as_ref(),
            "media_ssrf" => self.media_ssrf.as_ref(),
            "ssrf_rebind_extra" => self.ssrf_rebind_extra.as_ref(),
            "media_ssrf_bypass" => self.media_ssrf_bypass.as_ref(),
            "agent_inject" => self.agent_inject.as_ref(),
            "obfuscation" => self.obfuscation.as_ref(),
            "hook_inject" => self.hook_inject.as_ref(),
            _ => return Err(PayloadError::CategoryNotFound(category.to_string())),
        };

        Ok(entries
            .map(|e| e.iter().flat_map(|p| p.data.values().map(String::as_str)).collect())
            .unwrap_or_default())
    }

    /// Get a specific payload by category and key
    pub fn get(&self, category: &str, key: &str) -> Result<&str, PayloadError> {
        let entries = match category {
            "xss" => self.xss.as_ref(),
            "sqli" => self.sqli.as_ref(),
            "ssrf" => self.ssrf.as_ref(),
            "cmdi" => self.cmdi.as_ref(),
            "prompt_inject" => self.prompt_inject.as_ref(),
            "ssrf_exploit" => self.ssrf_exploit.as_ref(),
            "ssrf_ipv6" => self.ssrf_ipv6.as_ref(),
            "ssrf_proxy" => self.ssrf_proxy.as_ref(),
            "ssrf_rebind" => self.ssrf_rebind.as_ref(),
            "prompt_exploit" => self.prompt_exploit.as_ref(),
            "c2_exfil" => self.c2_exfil.as_ref(),
            "cmdi_exploit" => self.cmdi_exploit.as_ref(),
            "rce_exploit" => self.rce_exploit.as_ref(),
            "marker_spoof" => self.marker_spoof.as_ref(),
            "skill_bypass" => self.skill_bypass.as_ref(),
            "canary" => self.canary.as_ref(),
            "default_tokens" => self.default_tokens.as_ref(),
            "sensitive_indicators" => self.sensitive_indicators.as_ref(),
            "skill_poison" => self.skill_poison.as_ref(),
            "sqli_detect" => self.sqli_detect.as_ref(),
            "probe" => self.probe.as_ref(),
            "browser_ssrf" => self.browser_ssrf.as_ref(),
            "cron_ssrf" => self.cron_ssrf.as_ref(),
            "gateway_ssrf" => self.gateway_ssrf.as_ref(),
            "media_ssrf" => self.media_ssrf.as_ref(),
            "ssrf_rebind_extra" => self.ssrf_rebind_extra.as_ref(),
            "media_ssrf_bypass" => self.media_ssrf_bypass.as_ref(),
            "agent_inject" => self.agent_inject.as_ref(),
            "obfuscation" => self.obfuscation.as_ref(),
            "hook_inject" => self.hook_inject.as_ref(),
            _ => return Err(PayloadError::CategoryNotFound(category.to_string())),
        };

        entries
            .and_then(|e| {
                e.iter().find_map(|p| p.data.get(key).map(String::as_str))
            })
            .ok_or_else(|| PayloadError::PayloadNotFound(category.to_string(), key.to_string()))
    }

    /// Get canary value by name
    pub fn canary(&self, name: &str) -> Option<&str> {
        self.canary
            .as_ref()?
            .iter()
            .find_map(|p| p.data.get(name).map(String::as_str))
    }

    /// Get all SSRF payloads (combined from multiple categories)
    pub fn all_ssrf(&self) -> Vec<&str> {
        let mut payloads = Vec::new();
        
        if let Some(p) = &self.ssrf {
            payloads.extend(p.iter().flat_map(|e| e.data.values().map(String::as_str)));
        }
        if let Some(p) = &self.ssrf_exploit {
            payloads.extend(p.iter().flat_map(|e| e.data.values().map(String::as_str)));
        }
        if let Some(p) = &self.ssrf_ipv6 {
            payloads.extend(p.iter().flat_map(|e| e.data.values().map(String::as_str)));
        }
        
        payloads
    }

    /// Get all prompt injection payloads
    pub fn all_prompt_inject(&self) -> Vec<&str> {
        let mut payloads = Vec::new();
        
        if let Some(p) = &self.prompt_inject {
            payloads.extend(p.iter().flat_map(|e| e.data.values().map(String::as_str)));
        }
        if let Some(p) = &self.prompt_exploit {
            payloads.extend(p.iter().flat_map(|e| e.data.values().map(String::as_str)));
        }
        
        payloads
    }

    /// Get default tokens for brute force
    pub fn default_tokens(&self) -> Vec<&str> {
        self.default_tokens
            .as_ref()
            .map(|p| p.iter().flat_map(|e| e.data.values().map(String::as_str)).collect())
            .unwrap_or_default()
    }
}

/// Global payload registry accessor
pub fn payloads() -> &'static PayloadRegistry {
    PayloadRegistry::load_default()
}

/// Convenience macro to get a payload
#[macro_export]
macro_rules! payload {
    ($category:expr, $key:expr) => {
        $crate::payload::payloads().get($category, $key)
    };
}

/// Convenience macro to get all payloads in a category
#[macro_export]
macro_rules! payloads {
    ($category:expr) => {
        $crate::payload::payloads().get_category($category)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_default() {
        let registry = PayloadRegistry::default();
        assert!(registry.xss.is_none());
    }

    #[test]
    fn test_get_category_empty() {
        let registry = PayloadRegistry::default();
        let result = registry.get_category("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_canary_helper() {
        let registry = PayloadRegistry::default();
        assert!(registry.canary("test").is_none());
    }
}
