// Comprehensive output format for 0-day exploit cataloging
#[allow(dead_code)]
use crate::utils::ScanResult;
use std::path::Path;

/// Write scan result to JSON file.
pub fn write_json(result: &ScanResult, path: &Path) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(result)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(path, json)
}
