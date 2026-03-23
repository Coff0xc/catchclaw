//! Report generation and export module

use crate::chain::AttackGraph;
use crate::config::GraphConfig;
use crate::utils::{Finding, ScanResult};
use colored::Colorize;
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

/// Write JSON report for multiple scan results
pub fn write_json_multi(results: &[ScanResult], path: &Path) -> Result<(), ReportError> {
    let entries: Vec<_> = results
        .iter()
        .map(|r| {
            let summary = ScanSummary::from_result(r);
            serde_json::json!({
                "target": r.target,
                "findings": r.findings,
                "summary": summary,
                "start_at": r.start_at,
                "end_at": r.end_at,
            })
        })
        .collect();

    let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
    let output = serde_json::to_string_pretty(&serde_json::json!({
        "targets_scanned": results.len(),
        "total_findings": total_findings,
        "results": entries,
    }))
    .map_err(|e| ReportError::SerializeError(e.to_string()))?;

    std::fs::write(path, output)?;
    Ok(())
}

/// Write Markdown report to file
pub fn write_markdown(result: &ScanResult, path: &Path) -> Result<(), ReportError> {
    let summary = ScanSummary::from_result(result);
    let mut md = String::with_capacity(4096);

    md.push_str(&format!("# CatchClaw Security Report\n\n"));
    md.push_str(&format!("**Target:** {}:{}\n\n", result.target.host, result.target.port));
    if !result.start_at.is_empty() {
        md.push_str(&format!("**Scan started:** {}\n\n", result.start_at));
    }

    // Summary table
    md.push_str("## Summary\n\n");
    md.push_str(&format!("| Metric | Value |\n|--------|-------|\n"));
    md.push_str(&format!("| Total findings | {} |\n", summary.total_findings));
    md.push_str(&format!("| Risk score | {}/100 |\n", summary.risk_score));
    md.push_str(&format!("| Critical | {} |\n", summary.critical));
    md.push_str(&format!("| High | {} |\n", summary.high));
    md.push_str(&format!("| Medium | {} |\n", summary.medium));
    md.push_str(&format!("| Low | {} |\n", summary.low));
    md.push_str(&format!("| Info | {} |\n\n", summary.info));

    // Findings
    if !result.findings.is_empty() {
        md.push_str("## Findings\n\n");
        for (i, f) in result.findings.iter().enumerate() {
            md.push_str(&format!("### {}. [{}] {}\n\n", i + 1, severity_label(&f.severity), f.title));
            md.push_str(&format!("- **Module:** {}\n", f.module));
            md.push_str(&format!("- **Severity:** {}\n", severity_label(&f.severity)));
            md.push_str(&format!("- **Description:** {}\n", f.description));
            if let Some(ref ev) = f.evidence {
                md.push_str(&format!("- **Evidence:** `{}`\n", truncate(ev, 200)));
            }
            if let Some(ref rem) = f.remediation {
                md.push_str(&format!("- **Remediation:** {}\n", rem));
            }
            md.push('\n');
        }
    }

    md.push_str("---\n*Generated by CatchClaw v5.2.0*\n");
    std::fs::write(path, md)?;
    Ok(())
}

/// Write HTML report to file
pub fn write_html(result: &ScanResult, path: &Path) -> Result<(), ReportError> {
    let summary = ScanSummary::from_result(result);
    let mut html = String::with_capacity(8192);

    html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CatchClaw Security Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 960px; margin: 0 auto; padding: 2rem; background: #0d1117; color: #c9d1d9; }
  h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }
  h2 { color: #c9d1d9; margin-top: 2rem; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  th, td { border: 1px solid #30363d; padding: 0.5rem 1rem; text-align: left; }
  th { background: #161b22; color: #58a6ff; }
  .critical { color: #f85149; font-weight: bold; }
  .high { color: #db6d28; font-weight: bold; }
  .medium { color: #d29922; }
  .low { color: #3fb950; }
  .info { color: #58a6ff; }
  .finding { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; margin: 1rem 0; }
  .finding h3 { margin-top: 0; }
  code { background: #1f2428; padding: 0.2rem 0.4rem; border-radius: 3px; font-size: 0.9em; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin: 1rem 0; }
  .summary-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; text-align: center; }
  .summary-card .value { font-size: 2rem; font-weight: bold; }
  footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #30363d; color: #8b949e; font-size: 0.85rem; }
</style>
</head>
<body>
"#);

    html.push_str(&format!("<h1>CatchClaw Security Report</h1>\n"));
    html.push_str(&format!("<p><strong>Target:</strong> {}:{}</p>\n",
        html_escape(&result.target.host), result.target.port));

    // Summary cards
    html.push_str("<h2>Summary</h2>\n<div class=\"summary-grid\">\n");
    html.push_str(&format!("<div class=\"summary-card\"><div class=\"value\">{}</div><div>Findings</div></div>\n", summary.total_findings));
    html.push_str(&format!("<div class=\"summary-card\"><div class=\"value\">{}/100</div><div>Risk Score</div></div>\n", summary.risk_score));
    html.push_str(&format!("<div class=\"summary-card critical\"><div class=\"value\">{}</div><div>Critical</div></div>\n", summary.critical));
    html.push_str(&format!("<div class=\"summary-card high\"><div class=\"value\">{}</div><div>High</div></div>\n", summary.high));
    html.push_str(&format!("<div class=\"summary-card medium\"><div class=\"value\">{}</div><div>Medium</div></div>\n", summary.medium));
    html.push_str(&format!("<div class=\"summary-card low\"><div class=\"value\">{}</div><div>Low</div></div>\n", summary.low));
    html.push_str("</div>\n");

    // Findings table
    if !result.findings.is_empty() {
        html.push_str("<h2>Findings</h2>\n");
        html.push_str("<table><thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Module</th><th>Description</th></tr></thead><tbody>\n");
        for (i, f) in result.findings.iter().enumerate() {
            let sev_class = severity_class(&f.severity);
            html.push_str(&format!(
                "<tr><td>{}</td><td class=\"{sev_class}\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                i + 1,
                severity_label(&f.severity),
                html_escape(&f.title),
                html_escape(&f.module),
                html_escape(&f.description),
            ));
        }
        html.push_str("</tbody></table>\n");

        // Detailed findings
        html.push_str("<h2>Details</h2>\n");
        for (i, f) in result.findings.iter().enumerate() {
            let sev_class = severity_class(&f.severity);
            html.push_str(&format!("<div class=\"finding\">\n<h3>{}. <span class=\"{sev_class}\">[{}]</span> {}</h3>\n",
                i + 1, severity_label(&f.severity), html_escape(&f.title)));
            html.push_str(&format!("<p><strong>Module:</strong> {}</p>\n", html_escape(&f.module)));
            html.push_str(&format!("<p><strong>Description:</strong> {}</p>\n", html_escape(&f.description)));
            if let Some(ref ev) = f.evidence {
                html.push_str(&format!("<p><strong>Evidence:</strong> <code>{}</code></p>\n", html_escape(&truncate(ev, 200))));
            }
            if let Some(ref rem) = f.remediation {
                html.push_str(&format!("<p><strong>Remediation:</strong> {}</p>\n", html_escape(rem)));
            }
            html.push_str("</div>\n");
        }
    }

    html.push_str("<footer>Generated by CatchClaw v5.2.0</footer>\n</body>\n</html>\n");
    std::fs::write(path, html)?;
    Ok(())
}

fn severity_label(s: &crate::utils::Severity) -> &'static str {
    use crate::utils::Severity;
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn severity_class(s: &crate::utils::Severity) -> &'static str {
    use crate::utils::Severity;
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("{}...", &s[..max]) }
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

    #[test]
    fn test_summary_all_severities() {
        let mut result = ScanResult::new(Target::new("10.0.0.1", 443));
        result.add(Finding::new("t", "m", "a", Severity::Critical, "d"));
        result.add(Finding::new("t", "m", "b", Severity::High, "d"));
        result.add(Finding::new("t", "m", "c", Severity::Medium, "d"));
        result.add(Finding::new("t", "m", "d", Severity::Low, "d"));
        result.add(Finding::new("t", "m", "e", Severity::Info, "d"));
        result.done();
        let s = ScanSummary::from_result(&result);
        assert_eq!(s.total_findings, 5);
        assert_eq!(s.critical, 1);
        assert_eq!(s.high, 1);
        assert_eq!(s.medium, 1);
        assert_eq!(s.low, 1);
        assert_eq!(s.info, 1);
    }

    #[test]
    fn test_summary_empty() {
        let mut result = ScanResult::new(Target::new("10.0.0.1", 443));
        result.done();
        let s = ScanSummary::from_result(&result);
        assert_eq!(s.total_findings, 0);
        assert_eq!(s.risk_score, 0);
    }

    #[test]
    fn test_risk_score_capped() {
        let mut result = ScanResult::new(Target::new("10.0.0.1", 443));
        for i in 0..20 {
            result.add(Finding::new("t", "m", &format!("crit{i}"), Severity::Critical, "d"));
        }
        result.done();
        let s = ScanSummary::from_result(&result);
        assert!(s.risk_score <= 100);
    }

    #[test]
    fn test_write_json_invalid_path() {
        let result = make_test_result();
        let path = std::path::Path::new("/nonexistent/dir/report.json");
        assert!(write_json(&result, path).is_err());
    }

    #[test]
    fn test_write_markdown() {
        let result = make_test_result();
        let path = std::env::temp_dir().join("catchclaw_test_report.md");
        assert!(write_markdown(&result, &path).is_ok());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("# CatchClaw Security Report"));
        assert!(content.contains("CRITICAL"));
        assert!(content.contains("127.0.0.1:8080"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_write_html() {
        let result = make_test_result();
        let path = std::env::temp_dir().join("catchclaw_test_report.html");
        assert!(write_html(&result, &path).is_ok());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("<!DOCTYPE html>"));
        assert!(content.contains("CatchClaw Security Report"));
        assert!(content.contains("class=\"critical\""));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>alert('xss')</script>"), "&lt;script&gt;alert('xss')&lt;/script&gt;");
    }
}