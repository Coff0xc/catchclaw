//! Full scan orchestration module

use crate::chain;
use crate::config::AppConfig;
use crate::utils::{PayloadRegistry, ScanResult, Target};
use colored::Colorize;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Run a full scan: build DAG, execute, collect results.
pub async fn run_full_scan(target: Target, cfg: AppConfig) -> ScanResult {
    let mut result = ScanResult::new(target.clone());

    println!(
        "\n{} Starting full scan on {} ...\n",
        "[*]".cyan(),
        target
    );

    // Log configuration
    tracing::info!(
        "Scan config: timeout={:?}, concurrency={}, aggressive={}",
        cfg.timeout, cfg.concurrency, cfg.aggressive
    );

    if cfg.has_proxy() {
        tracing::info!("Using proxy: {}", cfg.primary_proxy().unwrap_or("unknown"));
    }

    // Load external payloads
    let _payload_registry = if let Some(ref path) = cfg.payload.file {
        PayloadRegistry::from_file(path).ok()
    } else {
        PayloadRegistry::from_directory(Path::new("payloads")).ok()
    };
    if let Some(ref reg) = _payload_registry {
        tracing::info!("Loaded {} external payloads across {} categories",
            reg.total_count(), reg.categories().len());
    }

    let dag = chain::build_full_dag(cfg.concurrency);
    println!(
        "{} DAG built: {} nodes, concurrency={}",
        "[+]".green(),
        dag.len(),
        cfg.concurrency
    );

    let (findings, graph) = dag
        .execute(
            target,
            cfg,
            Some(Box::new(|id, name, status| {
                tracing::debug!("Node #{id} [{name}] → {status:?}");
            })),
        )
        .await;

    for f in &findings {
        f.print();
        result.add(f.clone());
    }

    result.done();

    // Store the attack graph for later export
    // Note: In a full implementation, we'd store this in ScanResult
    let _ = graph; // Suppress unused warning for now

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

/// Run scans on multiple targets concurrently with bounded parallelism.
pub async fn run_multi_scan(targets: Vec<Target>, cfg: AppConfig) -> Vec<ScanResult> {
    let total = targets.len();
    let max_parallel = cfg.concurrency.min(total);
    let semaphore = Arc::new(Semaphore::new(max_parallel));

    println!(
        "\n{} Scanning {} targets (max {} parallel) ...\n",
        "[*]".cyan(),
        total,
        max_parallel,
    );

    let mut handles = Vec::with_capacity(total);

    for (i, target) in targets.into_iter().enumerate() {
        let cfg = cfg.clone();
        let sem = semaphore.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed");
            println!(
                "{} Scanning target {}/{}: {}",
                "[*]".cyan(),
                i + 1,
                total,
                target,
            );
            run_full_scan(target, cfg).await
        }));
    }

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        match handle.await {
            Ok(result) => results.push(result),
            Err(e) => eprintln!("{} Target scan task failed: {e}", "[!]".red()),
        }
    }

    // Summary
    let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
    println!(
        "\n{} Multi-scan complete: {} targets, {} total findings",
        "[✓]".green(),
        results.len(),
        total_findings,
    );

    results
}