mod chain;
mod config;
mod exploit;
mod payload;
mod report;
mod scan;
mod utils;

use clap::{Parser, Subcommand};
use colored::Colorize;
use config::{AppConfig, FileConfig, LogLevel};
use std::path::PathBuf;
use std::time::Duration;
use utils::{Target, parse_targets, parse_targets_file};

#[derive(Parser)]
#[command(
    name = "catchclaw",
    version = "5.2.0",
    about = "OpenClaw 安全评估工具 v5.2.0 (Rust)",
    long_about = "CatchClaw v5.2.0 — OpenClaw/Open-WebUI AI编程平台安全评估工具\n\n\
        功能特性:\n  \
        DAG 攻击链 | 59个 Exploit 模块 | Payload Registry | 配置文件支持 | 代理支持\n\n\
        快速开始:\n  \
        catchclaw scan -t 目标IP:端口\n  \
        catchclaw scan -t 目标IP:端口 -o report.json\n  \
        catchclaw scan -t 目标IP:端口 --config catchclaw.toml\n  \
        catchclaw exploit -t 目标IP:端口 --token xxx"
)]
struct Cli {
    /// Configuration file path (TOML/YAML/JSON)
    #[arg(short, long, global = true, env = "CATCHCLAW_CONFIG")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run full security scan
    Scan {
        /// Target host:port (single target)
        #[arg(short, long)]
        target: Option<String>,

        /// Multiple targets: comma-separated, CIDR, or IP range
        #[arg(long)]
        targets: Option<String>,

        /// File with targets (one per line)
        #[arg(short = 'f', long)]
        targets_file: Option<PathBuf>,

        /// Authentication token
        #[arg(long, env = "CATCHCLAW_TOKEN", default_value = "")]
        token: String,

        /// Request timeout in seconds
        #[arg(long)]
        timeout: Option<u64>,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output format: json, html, markdown
        #[arg(long, default_value = "json")]
        format: String,

        /// Max concurrent exploit workers
        #[arg(long)]
        concurrency: Option<usize>,

        /// Use TLS (HTTPS/WSS)
        #[arg(long)]
        tls: bool,

        /// SSRF callback URL
        #[arg(long)]
        callback: Option<String>,

        /// Log level: trace, debug, info, warn, error, quiet
        #[arg(long)]
        log_level: Option<String>,

        /// Export attack graph as Mermaid
        #[arg(long)]
        export_graph: bool,

        /// Graph output directory
        #[arg(long)]
        graph_dir: Option<PathBuf>,

        /// Scan profile from config (e.g., quick, stealth, full)
        #[arg(long)]
        profile: Option<String>,

        /// Filter results by severity: critical,high,medium,low,info
        #[arg(long)]
        severity_filter: Option<String>,

        /// Dry-run: show which exploits would execute without scanning
        #[arg(long)]
        dry_run: bool,
    },

    /// Run specific exploit chain
    Exploit {
        /// Target host:port
        #[arg(short, long)]
        target: String,

        /// Authentication token
        #[arg(long, env = "CATCHCLAW_TOKEN", default_value = "")]
        token: String,

        /// Request timeout in seconds
        #[arg(long)]
        timeout: Option<u64>,

        /// Specific chain node ID to run
        #[arg(long)]
        chain_id: Option<u32>,

        /// Use TLS (HTTPS/WSS)
        #[arg(long)]
        tls: bool,

        /// Max concurrent workers
        #[arg(long)]
        concurrency: Option<usize>,

        /// Log level: trace, debug, info, warn, error, quiet
        #[arg(long)]
        log_level: Option<String>,
    },

    /// List registered exploit modules
    List,

    /// Show current configuration
    Config,
}

fn setup_logging(level: LogLevel) {
    let filter = match level {
        LogLevel::Trace => "catchclaw=trace",
        LogLevel::Debug => "catchclaw=debug",
        LogLevel::Info => "catchclaw=info",
        LogLevel::Warn => "catchclaw=warn",
        LogLevel::Error => "catchclaw=error",
        LogLevel::Quiet => "off",
    };

    if level != LogLevel::Quiet {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(filter.parse().unwrap()),
            )
            .with_target(false)
            .init();
    }
}

fn banner() {
    let art = r#"
     ╔═╗╔═╗╔╦╗╔═╗╦ ╦╔═╗╦  ╔═╗╦ ╦
     ║  ╠═╣ ║ ║  ╠═╣║  ║  ╠═╣║║║
     ╚═╝╩ ╩ ╩ ╚═╝╩ ╩╚═╝╩═╝╩ ╩╚╩╝
    "#;
    println!("{}", art.red().bold());
    println!(
        "    {} v5.2.0 — OpenClaw Security Assessment Tool (Rust)\n",
        "CatchClaw".red().bold()
    );
}

fn load_config(cli_config_path: Option<PathBuf>) -> FileConfig {
    if let Some(path) = cli_config_path {
        match FileConfig::from_file(&path) {
            Ok(cfg) => {
                println!("{} Loaded config from {}", "[+]".green(), path.display());
                return cfg;
            }
            Err(e) => {
                eprintln!("{} Failed to load config: {e}", "[!]".red());
            }
        }
    }
    FileConfig::load_default()
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    banner();

    // Load configuration file
    let file_config = load_config(cli.config);

    match cli.command {
        Commands::Scan {
            target,
            targets,
            targets_file,
            token,
            timeout,
            output,
            format,
            concurrency,
            tls,
            callback,
            log_level,
            export_graph,
            graph_dir,
            profile,
            severity_filter,
            dry_run,
        } => {
            let level = log_level
                .and_then(|s| s.parse().ok())
                .unwrap_or_default();
            setup_logging(level);

            // Collect targets from all sources
            let mut all_targets: Vec<Target> = Vec::new();

            if let Some(ref t) = target {
                all_targets.extend(parse_targets(t, tls));
            }
            if let Some(ref ts) = targets {
                all_targets.extend(parse_targets(ts, tls));
            }
            if let Some(ref file) = targets_file {
                match parse_targets_file(file, tls) {
                    Ok(ts) => all_targets.extend(ts),
                    Err(e) => {
                        eprintln!("{} Failed to read targets file: {e}", "[!]".red());
                        std::process::exit(1);
                    }
                }
            }

            if all_targets.is_empty() {
                eprintln!("{} No targets specified. Use -t, --targets, or -f", "[!]".red());
                std::process::exit(1);
            }

            // Apply token to all targets
            let tok = if token.is_empty() { None } else { Some(token.clone()) };
            for t in &mut all_targets {
                t.token = tok.clone();
            }

            // Load and apply profile
            let mut file_cfg = file_config;
            if let Some(ref pname) = profile {
                if let Err(e) = file_cfg.apply_profile(pname) {
                    eprintln!("{} {e}", "[!]".red());
                    std::process::exit(1);
                }
                println!("{} Using profile: {}", "[+]".green(), pname);
            }

            // Merge file config with CLI args
            let mut cfg = file_cfg.merge_with_cli(
                if token.is_empty() { None } else { Some(token) },
                timeout,
                concurrency,
                tls,
                callback,
                Some(level),
            );

            // Override graph settings from CLI
            if export_graph {
                cfg.graph.export_mermaid = true;
            }
            if let Some(dir) = graph_dir {
                cfg.graph.output_dir = Some(dir);
            }

            // Print scan configuration summary
            print_scan_config(&cfg, &all_targets);

            // Dry-run mode
            if dry_run {
                print_dry_run();
                return;
            }

            if all_targets.len() == 1 {
                let t = all_targets.into_iter().next().unwrap();
                let mut result = scan::run_full_scan(t, cfg.clone()).await;

                // Apply severity filter
                if let Some(ref filter) = severity_filter {
                    filter_findings(&mut result, filter);
                }

                // Export attack graph if configured
                if cfg.graph.export_mermaid || cfg.graph.export_json {
                    if let Err(e) = report::export_graph(&result, &cfg.graph).await {
                        eprintln!("{} Failed to export graph: {e}", "[!]".red());
                    }
                }

                if let Some(path) = output {
                    let write_result = match format.as_str() {
                        "html" => report::write_html(&result, &path),
                        "markdown" | "md" => report::write_markdown(&result, &path),
                        _ => report::write_json(&result, &path),
                    };
                    match write_result {
                        Ok(()) => println!("\n{} Report saved to {} ({})", "[+]".green(), path.display(), format),
                        Err(e) => eprintln!("{} Failed to write report: {e}", "[!]".red()),
                    }
                }
            } else {
                let results = scan::run_multi_scan(all_targets, cfg).await;

                if let Some(path) = output {
                    match report::write_json_multi(&results, &path) {
                        Ok(()) => println!("\n{} Report saved to {}", "[+]".green(), path.display()),
                        Err(e) => eprintln!("{} Failed to write report: {e}", "[!]".red()),
                    }
                }
            }
        }

        Commands::Exploit {
            target,
            token,
            timeout,
            chain_id,
            tls,
            concurrency,
            log_level,
        } => {
            let level = log_level
                .and_then(|s| s.parse().ok())
                .unwrap_or_default();
            setup_logging(level);

            let t = parse_targets(&target, tls).into_iter().next()
                .unwrap_or_else(|| { eprintln!("Invalid target"); std::process::exit(1); });
            let cfg = file_config.merge_with_cli(
                if token.is_empty() { None } else { Some(token) },
                timeout,
                concurrency,
                tls,
                None,
                Some(level),
            );

            let dag = chain::build_full_dag(cfg.concurrency);

            let findings = if let Some(id) = chain_id {
                println!("{} Running single chain node #{id}", "[*]".cyan());
                dag.execute_single(id, t, cfg).await
            } else {
                println!("{} Running full exploit chain", "[*]".cyan());
                let (f, _) = dag.execute(t, cfg, None).await;
                f
            };

            for f in &findings {
                f.print();
            }
            println!(
                "\n{} Exploit complete: {} findings",
                "[✓]".green(),
                findings.len()
            );
        }

        Commands::List => {
            let exploits = exploit::registered_exploits();
            println!("{} Registered exploit modules ({} total)\n", "[*]".cyan(), exploits.len());
            println!(
                "  {:<4} {:<22} {:<26} {:<14} {}",
                "#", "ID", "Name", "Category", "Phase"
            );
            println!("  {}", "─".repeat(80));
            for (i, e) in exploits.iter().enumerate() {
                println!(
                    "  {:<4} {:<22} {:<26} {:<14} {:?}",
                    i + 1, e.id, e.name, format!("{:?}", e.category), e.phase
                );
            }
            println!("\n  {} {} exploit modules registered", "[✓]".green(), exploits.len());
        }

        Commands::Config => {
            println!("{} Current configuration:\n", "[*]".cyan());
            println!("  Default settings:");
            let default = AppConfig::default();
            println!("    Timeout: {:?}", default.timeout);
            println!("    Concurrency: {}", default.concurrency);
            println!("    Log level: {}", default.log_level);
            println!("\n  File config loaded: {}", file_config.scanner.is_some() || file_config.target.is_some());
            
            if let Some(ref scanner) = file_config.scanner {
                println!("\n  [scanner]");
                if let Some(t) = scanner.timeout {
                    println!("    timeout = {t}");
                }
                if let Some(c) = scanner.concurrency {
                    println!("    concurrency = {c}");
                }
                if let Some(ref l) = scanner.log_level {
                    println!("    log_level = {l}");
                }
            }
            
            if let Some(ref proxy) = file_config.proxy {
                println!("\n  [proxy]");
                if let Some(ref p) = proxy.http {
                    println!("    http = {p}");
                }
                if let Some(ref p) = proxy.https {
                    println!("    https = {p}");
                }
                if let Some(ref p) = proxy.socks5 {
                    println!("    socks5 = {p}");
                }
            }
            
            if let Some(ref payload) = file_config.payload {
                println!("\n  [payload]");
                if let Some(ref f) = payload.file {
                    println!("    file = {}", f.display());
                }
                println!("    enable_mutation = {}", payload.enable_mutation);
            }
        }
    }
}

/// Print scan configuration summary before starting
fn print_scan_config(cfg: &AppConfig, targets: &[Target]) {
    println!("{}", "┌─────────────────────────────────────────────┐".cyan());
    println!("{} {:<43} {}", "│".cyan(), format!("Targets: {}", targets.len()), "│".cyan());
    println!("{} {:<43} {}", "│".cyan(), format!("Timeout: {:?}", cfg.timeout), "│".cyan());
    println!("{} {:<43} {}", "│".cyan(), format!("Concurrency: {}", cfg.concurrency), "│".cyan());
    println!("{} {:<43} {}", "│".cyan(), format!("Aggressive: {}", cfg.aggressive), "│".cyan());
    if cfg.has_proxy() {
        println!("{} {:<43} {}", "│".cyan(),
            format!("Proxy: {}", cfg.primary_proxy().unwrap_or("configured")), "│".cyan());
    }
    println!("{}", "└─────────────────────────────────────────────┘".cyan());
}

/// Print dry-run output showing which exploits would execute
fn print_dry_run() {
    let dag = chain::build_full_dag(10);
    let levels = dag.topological_levels();
    let nodes = dag.nodes_ref();

    println!("\n{} Dry-run: {} nodes would execute across {} levels\n",
        "[*]".cyan(), nodes.len(), levels.len());

    let phase_names = ["Recon", "Initial Access", "Credential Access", "Execution", "Persistence", "Exfiltration"];
    for (i, level) in levels.iter().enumerate() {
        let phase = phase_names.get(i).unwrap_or(&"Advanced");
        println!("  {} Level {}: {} ({}  nodes)", "▸".cyan(), i, phase, level.len());
        for &idx in level {
            if let Some(node) = nodes.get(idx) {
                println!("    {} #{:<3} {}", "·".white(), node.id, node.name);
            }
        }
    }
    println!("\n{} No scan performed (--dry-run)", "[*]".yellow());
}

/// Filter findings by severity level
fn filter_findings(result: &mut utils::ScanResult, filter: &str) {
    use utils::Severity;
    let allowed: Vec<Severity> = filter.split(',')
        .filter_map(|s| match s.trim().to_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" => Some(Severity::Info),
            _ => None,
        })
        .collect();

    if !allowed.is_empty() {
        result.findings.retain(|f| allowed.contains(&f.severity));
    }
}