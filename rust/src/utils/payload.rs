//! External payload file loader
//!
//! Loads custom payloads from YAML files. Format:
//! ```yaml
//! xss:
//!   - "<script>alert(1)</script>"
//!   - "<img src=x onerror=alert(1)>"
//! sqli:
//!   - "' OR 1=1 --"
//! custom_category:
//!   - "payload1"
//! ```

use std::collections::HashMap;
use std::path::Path;

/// Registry of categorized payloads loaded from external files
#[derive(Debug, Clone, Default)]
pub struct PayloadRegistry {
    payloads: HashMap<String, Vec<String>>,
}

impl PayloadRegistry {
    /// Load payloads from a YAML file
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read payload file {}: {}", path.display(), e))?;

        let parsed: HashMap<String, Vec<String>> = serde_yaml::from_str(&content)
            .map_err(|e| format!("Failed to parse payload file: {e}"))?;

        Ok(Self { payloads: parsed })
    }

    /// Load from YAML string (for testing or embedded payloads)
    pub fn from_str(yaml: &str) -> Result<Self, String> {
        let parsed: HashMap<String, Vec<String>> = serde_yaml::from_str(yaml)
            .map_err(|e| format!("Failed to parse payload YAML: {e}"))?;
        Ok(Self { payloads: parsed })
    }

    /// Get payloads for a category
    pub fn get(&self, category: &str) -> &[String] {
        self.payloads.get(category).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// List all available categories
    pub fn categories(&self) -> Vec<&str> {
        self.payloads.keys().map(|k| k.as_str()).collect()
    }

    /// Total number of payloads across all categories
    pub fn total_count(&self) -> usize {
        self.payloads.values().map(|v| v.len()).sum()
    }

    /// Merge another registry into this one (other takes precedence for duplicate categories)
    pub fn merge(&mut self, other: PayloadRegistry) {
        for (cat, payloads) in other.payloads {
            self.payloads.entry(cat).or_default().extend(payloads);
        }
    }

    /// Check if a category exists
    pub fn has_category(&self, category: &str) -> bool {
        self.payloads.contains_key(category)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str() {
        let yaml = r#"
xss:
  - "<script>alert(1)</script>"
  - "<img src=x onerror=alert(1)>"
sqli:
  - "' OR 1=1 --"
"#;
        let reg = PayloadRegistry::from_str(yaml).unwrap();
        assert_eq!(reg.get("xss").len(), 2);
        assert_eq!(reg.get("sqli").len(), 1);
        assert_eq!(reg.total_count(), 3);
        assert!(reg.has_category("xss"));
        assert!(!reg.has_category("rce"));
    }

    #[test]
    fn test_empty_category() {
        let reg = PayloadRegistry::default();
        assert!(reg.get("nonexistent").is_empty());
        assert_eq!(reg.total_count(), 0);
    }

    #[test]
    fn test_merge() {
        let yaml1 = "xss:\n  - \"<script>1</script>\"";
        let yaml2 = "xss:\n  - \"<script>2</script>\"\nsqli:\n  - \"' OR 1=1\"";
        let mut reg1 = PayloadRegistry::from_str(yaml1).unwrap();
        let reg2 = PayloadRegistry::from_str(yaml2).unwrap();
        reg1.merge(reg2);
        assert_eq!(reg1.get("xss").len(), 2);
        assert_eq!(reg1.get("sqli").len(), 1);
    }

    #[test]
    fn test_categories() {
        let yaml = "a:\n  - \"1\"\nb:\n  - \"2\"\nc:\n  - \"3\"";
        let reg = PayloadRegistry::from_str(yaml).unwrap();
        assert_eq!(reg.categories().len(), 3);
    }

    #[test]
    fn test_from_file_not_found() {
        let result = PayloadRegistry::from_file(Path::new("/nonexistent/payloads.yaml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_yaml() {
        let result = PayloadRegistry::from_str("{{invalid yaml");
        assert!(result.is_err());
    }
}
