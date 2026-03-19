mod chain;
mod config;
mod exploit;
mod report;
mod scan;
mod utils;

use clap::{Parser, Subcommand};
use colored::Colorize;
use config::AppConfig;
use std::path::PathBuf;
use std::time::Duration;
use utils::Target;

#[derive(Parser)]
#[command(
    name = "Coff0xc-catchclaw",
    version = "5.0.0",
    about = "OpenClaw 安全评估工具 v5.0.0 (Rust)",
    long_about = "CatchClaw v5.0.0 — OpenClaw/Open-WebUI AI编程平台安全评估工具\n\n\
        功能特性:\n  \
        DAG 攻击链 | AI 智能模糊测试 | CVE 漏洞库 | 高并发引擎 | MCP 集成\n\n\
        快速开始:\n  \
        Coff0xc-catchclaw scan -t 目标IP:端口\n  \
        Coff0xc-catchclaw scan -t 目标IP:端口 -o report.json\n  \
        Coff0xc-catchclaw exploit -t 目标IP:端口 --token xxx"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run full security scan
    Scan {
        /// Target host:port
        #[arg(short, long)]
        target: String,

        /// Authentication token
        #[arg(long, env = "CATCHCLAWGUARD_TOKEN", default_value = "")]
        token: String,

        /// Request timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// Output file (JSON)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Max concurrent exploit workers
        #[arg(long, default_value = "10")]
        concurrency: usize,

        /// Use TLS
        #[arg(long)]
        tls: bool,

        /// SSRF callback URL
        #[arg(long)]
        callback: Option<String>,
    },

    /// Run specific exploit chain
    Exploit {
        /// Target host:port
        #[arg(short, long)]
        target: String,

        /// Authentication token
        #[arg(long, env = "CATCHCLAWGUARD_TOKEN", default_value = "")]
        token: String,

        /// Request timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// Specific chain node ID to run
        #[arg(long)]
        chain_id: Option<u32>,

        /// Use TLS
        #[arg(long)]
        tls: bool,

        /// Max concurrent workers
        #[arg(long, default_value = "10")]
        concurrency: usize,
    },

    /// List registered exploit modules
    List,
}

fn parse_target(s: &str, tls: bool) -> Target {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    let host = parts[0].to_string();
    let port = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(if tls { 443 } else { 8080 });
    let mut t = Target::new(host, port);
    t.use_tls = tls;
    t
}

fn banner() {
    let art = r#"
     ╔═╗╔═╗╔╦╗╔═╗╦ ╦╔═╗╦  ╔═╗╦ ╦
     ║  ╠═╣ ║ ║  ╠═╣║  ║  ╠═╣║║║
     ╚═╝╩ ╩ ╩ ╚═╝╩ ╩╚═╝╩═╝╩ ╩╚╩╝
    "#;
    println!("{}", art.red().bold());
    println!(
        "    {} v5.0.0 — OpenClaw Security Assessment Tool (Rust)\n",
        "CatchClaw".red().bold()
    );
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("catchclaw=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    banner();

    match cli.command {
        Commands::Scan {
            target,
            token,
            timeout,
            output,
            concurrency,
            tls,
            callback,
        } => {
            let t = parse_target(&target, tls);
            let cfg = AppConfig {
                token,
                timeout: Duration::from_secs(timeout),
                callback_url: callback,
                concurrency,
                ..Default::default()
            };

            let result = scan::run_full_scan(t, cfg).await;

            if let Some(path) = output {
                match report::write_json(&result, &path) {
                    Ok(()) => println!("\n{} Report saved to {}", "[+]".green(), path.display()),
                    Err(e) => eprintln!("{} Failed to write report: {e}", "[!]".red()),
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
        } => {
            let t = parse_target(&target, tls);
            let cfg = AppConfig {
                token,
                timeout: Duration::from_secs(timeout),
                concurrency,
                ..Default::default()
            };

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
            println!("{} Registered exploit modules:\n", "[*]".cyan());
            for e in &exploits {
                println!(
                    "  {:<20} {:<25} [{:?}] {:?}",
                    e.id, e.name, e.category, e.phase
                );
            }
            println!("\n  Total: {} modules", exploits.len());
        }
    }
}
