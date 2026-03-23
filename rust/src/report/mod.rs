//! Report generation and export module

use crate::chain::AttackGraph;
use crate::config::GraphConfig;
use crate::utils::{Finding, ScanResult};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Report errors
#[derive(Debug, Error)]
pub enum ReportError {
    #[error("Failed to write report: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Failed to serialize report: {0}")]
    SerializeError(String),
}

/// Extended scan result with attack graph
#[derive(Debug, serde::Serialize)]
pub struct ExtendedScanResult {
    #[serde(flatten)]
    pub base: ScanResult,
    pub attack_graph: Option<AttackGraphExport>,
    pub summary: ScanSummary,
}

#[derive(Debug, serde::Serialize)]
pub struct AttackGraphExport {
    pub mermaid: String,
    pub edges: Vec<GraphEdge>,
    pub nodes: Vec<GraphNode>,
}

#[derive(Debug, serde::Serialize)]
pub struct GraphEdge {
    pub from: u32,
    pub to: u32,
    pub to_name: String,
    pub findings: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct GraphNode {
    pub id: u32,
    pub status: String,
    pub findings: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct ScanSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub risk_score: u32,
}

impl ScanSummary {
    pub fn from_result(result: &ScanResult) -> Self {
        use crate::utils::Severity;
        
        Self {
            total_findings: result.findings.len(),
            critical: result.count_by_severity(Severity::Critical),
            high: result.count_by_severity(Severity::High),
            medium: result.count_by_severity(Severity::Medium),
            low: result.count_by_severity(Severity::Low),
            info: result.count_by_severity(Severity::Info),
            risk_score: result.chain_score().min(100),
        }
    }
}

/// Write JSON report to file
pub fn write_json(result: &ScanResult, path: &Path) -> Result<(), ReportError> {
    let summary = ScanSummary::from_result(result);
    
    let output = serde_json::to_string_pretty(&serde_json::json!({
        "target": result.target,
        "findings": result.findings,
        "summary": summary,
        "start_at": result.start_at,
        "end_at": result.end_at,
    })).map_err(|e| ReportError::SerializeError(e.to_string()))?;

    std::fs::write(path, output)?;
    Ok(())
}

/// Write extended JSON report with attack graph
pub fn write_extended_json(
    result: &ScanResult,
    graph: &AttackGraph,
    nodes: &std::collections::HashMap<u32, (String, String)>,
    path: &Path,
) -> Result<(), ReportError> {
    let summary = ScanSummary::from_result(result);
    
    let graph_export = export_graph_data(graph, nodes);
    
    let output = serde_json::to_string_pretty(&serde_json::json!({
        "target": result.target,
        "findings": result.findings,
        "attack_graph": graph_export,
        "summary": summary,
        "start_at": result.start_at,
        "end_at": result.end_at,
    })).map_err(|e| ReportError::SerializeError(e.to_string()))?;

    std::fs::write(path, output)?;
    Ok(())
}

/// Export attack graph data
fn export_graph_data(
    graph: &AttackGraph,
    nodes: &std::collections::HashMap<u32, (String, String)>,
) -> AttackGraphExport {
    let mermaid = graph.to_mermaid(nodes);
    
    let edges: Vec<GraphEdge> = graph
        .edges
        .iter()
        .map(|e| GraphEdge {
            from: e.from_id,
            to: e.to_id,
            to_name: e.to_name.clone(),
            findings: e.findings,
        })
        .collect();

    let nodes_out: Vec<GraphNode> = graph
        .node_status
        .iter()
        .map(|(id, status)| GraphNode {
            id: *id,
            status: status.clone(),
            findings: graph.node_findings.get(id).copied().unwrap_or(0),
        })
        .collect();

    AttackGraphExport {
        mermaid,
        edges,
        nodes: nodes_out,
    }
}

/// Export attack graph based on configuration
pub async fn export_graph(result: &ScanResult, config: &GraphConfig) -> Result<(), ReportError> {
    if !config.export_mermaid && !config.export_json {
        return Ok(());
    }

    let output_dir = config.output_dir.as_ref()
        .map(|p| p.as_path())
        .unwrap_or_else(|| Path::new("."));

    // Ensure output directory exists
    if !output_dir.exists() {
        std::fs::create_dir_all(output_dir)?;
    }

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let target_id = format!("{}_{}", 
        result.target.host.replace(['.', ':'], "_"),
        result.target.port
    );

    if config.export_mermaid {
        // Note: Actual graph export requires the AttackGraph from scan execution
        // This is a placeholder that creates a summary diagram
        let mermaid_path = output_dir.join(format!("attack_graph_{}_{}.mmd", target_id, timestamp));
        let summary = ScanSummary::from_result(result);
        
        let content = format!(
            r#"graph TD
    subgraph Summary
        A[Total Findings: {}]
        B[Critical: {}]
        C[High: {}]
        D[Medium: {}]
        E[Low: {}]
        F[Info: {}]
    end
    
    G[Target: {}:{}]
    G --> A
    
    classDef critical fill:#ff6b6b,stroke:#c92a2a,color:#fff
    classDef high fill:#ffa94d,stroke:#e8590c,color:#fff
    classDef medium fill:#ffd43b,stroke:#f08c00,color:#000
    classDef low fill:#69db7c,stroke:#2b8a3e,color:#fff
    classDef info fill:#74c0fc,stroke:#1c7ed6,color:#fff
    
    class B critical
    class C high
    class D medium
    class E low
    class F info
"#,
            summary.total_findings,
            summary.critical,
            summary.high,
            summary.medium,
            summary.low,
            summary.info,
            result.target.host,
            result.target.port
        );
        
        std::fs::write(&mermaid_path, content)?;
        println!("{} Attack graph exported to {}", "[+]".green(), mermaid_path.display());
    }

    if config.export_json {
        let json_path = output_dir.join(format!("findings_{}_{}.json", target_id, timestamp));
        write_json(result, &json_path)?;
        println!("{} Findings exported to {}", "[+]".green(), json_path.display());
    }

    Ok(())
}

/// Print findings summary to stdout
pub fn print_summary(result: &ScanResult) {
    let summary = ScanSummary::from_result(result);
    
    println!("\n{}", "═".repeat(60));
    println!(
        "{} Scan complete: {} findings, risk score: {}/100",
        "[✓]".green(),
        summary.total_findings,
        summary.risk_score
    );
    println!(
        "  Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}",
        summary.critical, summary.high, summary.medium, summary.low, summary.info
    );
    println!("{}", "═".repeat(60));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{Severity, Target};

    fn make_test_result() -> ScanResult {
        let mut result = ScanResult::new(Target::new("127.0.0.1", 8080));
        result.add(Finding::new("t", "m", "test1", Severity::Critical, "d"));
        result.add(Finding::new("t", "m", "test2", Severity::High, "d"));
        result.add(Finding::new("t", "m", "test3", Severity::Medium, "d"));
        result.done();
        result
    }

    #[test]
    fn test_summary() {
        let result = make_test_result();
        let summary = ScanSummary::from_result(&result);
        
        assert_eq!(summary.total_findings, 3);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 1);
        assert_eq!(summary.risk_score, 48); // 25 + 15 + 8
    }

    #[test]
    fn test_write_json() {
        let result = make_test_result();
        let path = std::env::temp_dir().join("catchclaw_test_report.json");
        
        assert!(write_json(&result, &path).is_ok());
        
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"findings\""));
        assert!(content.contains("\"summary\""));
        
        let _ = std::fs::remove_file(&path);
    }
}