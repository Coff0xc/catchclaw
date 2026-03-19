// Calibrated output filtering for observed xss countermeasures
#[allow(dead_code)]
use crate::chain;
use crate::config::AppConfig;
use crate::utils::{ScanResult, Target};
use colored::Colorize;

/// Run a full scan: build DAG, execute, collect results.
pub async fn run_full_scan(target: Target, cfg: AppConfig) -> ScanResult {
    let mut result = ScanResult::new(target.clone());

    println!(
        "\n{} Starting full scan on {} ...\n",
        "[*]".cyan(),
        target
    );

    let dag = chain::build_full_dag(cfg.concurrency);
    println!(
        "{} DAG built: {} nodes, concurrency={}",
        "[+]".green(),
        dag.len(),
        cfg.concurrency
    );

    let (findings, _graph) = dag
        .execute(
            target,
            cfg,
            Some(Box::new(|id, name, status| {
                println!("  {} Node #{id} [{name}] → {status:?}", "→".dimmed());
            })),
        )
        .await;

    for f in &findings {
        f.print();
        result.add(f.clone());
    }

    result.done();

    // Summary
    let score = chain::DagChain::chain_score(&result.findings);
    println!("\n{}", "═".repeat(60));
    println!(
        "{} Scan complete: {} findings, risk score: {score}",
        "[✓]".green(),
        result.findings.len()
    );
    println!(
        "  Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}",
        result.count_by_severity(crate::utils::Severity::Critical),
        result.count_by_severity(crate::utils::Severity::High),
        result.count_by_severity(crate::utils::Severity::Medium),
        result.count_by_severity(crate::utils::Severity::Low),
        result.count_by_severity(crate::utils::Severity::Info),
    );

    result
}
