// Core orchestration framework for offensive x-ray classification
#[allow(dead_code)]
use crate::chain::dag::{has_any_finding, ChainNode, DagChain};
use crate::exploit;

/// Build the full attack DAG - 59 nodes, 5 layers, ATT&CK phases.
pub fn build_full_dag(concurrency: usize) -> DagChain {
    let mut dag = DagChain::new(concurrency);

    // === Recon ===
    dag.add_node(ChainNode { id: 0, name: "CORS Bypass".into(), category: "config".into(), phase: "Recon".into(),
        depends_on: vec![], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::cors_bypass::check(t, c))) });
    dag.add_node(ChainNode { id: 13, name: "WS Hijack".into(), category: "transport".into(), phase: "Recon".into(),
        depends_on: vec![], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::ws_hijack::check(t, c))) });
    dag.add_node(ChainNode { id: 35, name: "Auth Mode Abuse".into(), category: "auth".into(), phase: "Recon".into(),
        depends_on: vec![], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::auth_mode_abuse::check(t, c))) });
    dag.add_node(ChainNode { id: 15, name: "Log Disclosure".into(), category: "disclosure".into(), phase: "Recon".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::log_disclosure::check(t, c))) });
    dag.add_node(ChainNode { id: 36, name: "Hidden Content".into(), category: "disclosure".into(), phase: "Recon".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::hidden_content::check(t, c))) });
    dag.add_node(ChainNode { id: 37, name: "Origin Wildcard".into(), category: "config".into(), phase: "Recon".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::origin_wildcard::check(t, c))) });
    // === InitAccess ===
    dag.add_node(ChainNode { id: 1, name: "SSRF".into(), category: "ssrf".into(), phase: "InitAccess".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::ssrf::check(t, c))) });
    dag.add_node(ChainNode { id: 2, name: "Eval Injection".into(), category: "injection".into(), phase: "InitAccess".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::eval_inject::check(t, c))) });
    // === CredAccess ===
    dag.add_node(ChainNode { id: 3, name: "API Key Steal".into(), category: "credential".into(), phase: "CredAccess".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::apikey_steal::check(t, c))) });
    // === InitAccess ===
    dag.add_node(ChainNode { id: 4, name: "Pairing Brute".into(), category: "auth".into(), phase: "InitAccess".into(),
        depends_on: vec![0, 35], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::pairing_brute::check(t, c))) });
    dag.add_node(ChainNode { id: 6, name: "Prompt Injection".into(), category: "injection".into(), phase: "InitAccess".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::prompt_inject::check(t, c))) });
    dag.add_node(ChainNode { id: 19, name: "OAuth Abuse".into(), category: "auth".into(), phase: "InitAccess".into(),
        depends_on: vec![0, 35], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::oauth_abuse::check(t, c))) });
    dag.add_node(ChainNode { id: 20, name: "Responses API".into(), category: "api".into(), phase: "InitAccess".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::responses_exploit::check(t, c))) });
    dag.add_node(ChainNode { id: 21, name: "WS Fuzz".into(), category: "fuzz".into(), phase: "InitAccess".into(),
        depends_on: vec![13], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::ws_fuzz::check(t, c))) });
    dag.add_node(ChainNode { id: 31, name: "MCP Plugin Inject".into(), category: "injection".into(), phase: "InitAccess".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::mcp_inject::check(t, c))) });
    dag.add_node(ChainNode { id: 32, name: "ACP Bypass".into(), category: "auth".into(), phase: "InitAccess".into(),
        depends_on: vec![0, 35], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::acp_bypass::check(t, c))) });
    dag.add_node(ChainNode { id: 33, name: "Unicode Bypass".into(), category: "injection".into(), phase: "InitAccess".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::unicode_bypass::check(t, c))) });
    dag.add_node(ChainNode { id: 34, name: "Channel Inject".into(), category: "injection".into(), phase: "InitAccess".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::channel_inject::check(t, c))) });
    dag.add_node(ChainNode { id: 38, name: "CSRF No Origin".into(), category: "config".into(), phase: "InitAccess".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::csrf_no_origin::check(t, c))) });
    dag.add_node(ChainNode { id: 39, name: "Silent Pair".into(), category: "auth".into(), phase: "InitAccess".into(),
        depends_on: vec![0, 35], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::silent_pair_abuse::check(t, c))) });
    dag.add_node(ChainNode { id: 40, name: "SSRF Proxy Bypass".into(), category: "ssrf".into(), phase: "InitAccess".into(),
        depends_on: vec![1], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::ssrf_proxy_bypass::check(t, c))) });
    dag.add_node(ChainNode { id: 41, name: "SSRF Rebind".into(), category: "ssrf".into(), phase: "InitAccess".into(),
        depends_on: vec![1], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::ssrf_rebind::check(t, c))) });
    dag.add_node(ChainNode { id: 42, name: "Ratelimit Bypass".into(), category: "auth".into(), phase: "InitAccess".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::ratelimit_scope_bypass::check(t, c))) });
    // === CredAccess ===
    dag.add_node(ChainNode { id: 43, name: "OAuth Token Theft".into(), category: "credential".into(), phase: "CredAccess".into(),
        depends_on: vec![19], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::oauth_token_theft::check(t, c))) });
    // === InitAccess ===
    dag.add_node(ChainNode { id: 44, name: "Link Template Inject".into(), category: "injection".into(), phase: "InitAccess".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::link_template_inject::check(t, c))) });
    // === Execution ===
    dag.add_node(ChainNode { id: 7, name: "RCE Check".into(), category: "rce".into(), phase: "Execution".into(),
        depends_on: vec![2], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::rce::check(t, c))) });
    dag.add_node(ChainNode { id: 8, name: "Hook Injection".into(), category: "injection".into(), phase: "Execution".into(),
        depends_on: vec![0, 6], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::hook_inject::check(t, c))) });
    // === CredAccess ===
    dag.add_node(ChainNode { id: 9, name: "Secret Extract".into(), category: "credential".into(), phase: "CredAccess".into(),
        depends_on: vec![0, 3], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::secret_extract::check(t, c))) });
    // === Persistence ===
    dag.add_node(ChainNode { id: 10, name: "Config Tamper".into(), category: "config".into(), phase: "Persistence".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::config_tamper::check(t, c))) });
    // === Execution ===
    dag.add_node(ChainNode { id: 11, name: "Tools Invoke".into(), category: "rce".into(), phase: "Execution".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::tools_invoke::check(t, c))) });
    // === CredAccess ===
    dag.add_node(ChainNode { id: 12, name: "Session Hijack".into(), category: "session".into(), phase: "CredAccess".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::session_hijack::check(t, c))) });
    // === Execution ===
    dag.add_node(ChainNode { id: 16, name: "Patch Escape".into(), category: "traversal".into(), phase: "Execution".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::patch_escape::check(t, c))) });
    dag.add_node(ChainNode { id: 5, name: "Agent Inject".into(), category: "injection".into(), phase: "Execution".into(),
        depends_on: vec![6], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::agent_inject::check(t, c))) });
    dag.add_node(ChainNode { id: 14, name: "Agent File Inject".into(), category: "injection".into(), phase: "Execution".into(),
        depends_on: vec![5], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::agent_file_inject::check(t, c))) });
    dag.add_node(ChainNode { id: 45, name: "Marker Spoof".into(), category: "injection".into(), phase: "Execution".into(),
        depends_on: vec![6], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::marker_spoof::check(t, c))) });
    dag.add_node(ChainNode { id: 46, name: "Obfuscation Bypass".into(), category: "injection".into(), phase: "Execution".into(),
        depends_on: vec![7], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::obfuscation_bypass::check(t, c))) });
    dag.add_node(ChainNode { id: 47, name: "Skill Scanner Bypass".into(), category: "injection".into(), phase: "Execution".into(),
        depends_on: vec![7], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::skill_scanner_bypass::check(t, c))) });
    dag.add_node(ChainNode { id: 48, name: "Exec Race TOCTOU".into(), category: "rce".into(), phase: "Execution".into(),
        depends_on: vec![11], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::exec_race_toctou::check(t, c))) });
    dag.add_node(ChainNode { id: 49, name: "Keychain Cmd Inject".into(), category: "rce".into(), phase: "Execution".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::keychain_cmd_inject::check(t, c))) });
    dag.add_node(ChainNode { id: 50, name: "QMD Cmd Inject".into(), category: "rce".into(), phase: "Execution".into(),
        depends_on: vec![10], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::qmd_cmd_inject::check(t, c))) });
    dag.add_node(ChainNode { id: 51, name: "Browser Request".into(), category: "ssrf".into(), phase: "Execution".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::browser_request::check(t, c))) });
    dag.add_node(ChainNode { id: 52, name: "Browser Upload Traversal".into(), category: "rce".into(), phase: "Execution".into(),
        depends_on: vec![51], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::browser_upload_traversal::check(t, c))) });
    dag.add_node(ChainNode { id: 53, name: "Bypass Soul".into(), category: "injection".into(), phase: "Execution".into(),
        depends_on: vec![6], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::bypass_soul::check(t, c))) });
    dag.add_node(ChainNode { id: 54, name: "Approval Hijack".into(), category: "auth".into(), phase: "Execution".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::approval_hijack::check(t, c))) });
    // === Persistence ===
    dag.add_node(ChainNode { id: 55, name: "Cron Bypass".into(), category: "rce".into(), phase: "Persistence".into(),
        depends_on: vec![7], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::cron_bypass::check(t, c))) });
    // === CredAccess ===
    dag.add_node(ChainNode { id: 56, name: "Auth Disable Leak".into(), category: "auth".into(), phase: "CredAccess".into(),
        depends_on: vec![35], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::auth_disable_leak::check(t, c))) });
    // === Persistence ===
    dag.add_node(ChainNode { id: 57, name: "Skill Poison".into(), category: "injection".into(), phase: "Persistence".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::skill_poison::check(t, c))) });
    dag.add_node(ChainNode { id: 58, name: "Webhook Verify".into(), category: "config".into(), phase: "Persistence".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::webhook_verify::check(t, c))) });
    dag.add_node(ChainNode { id: 59, name: "Session File Write".into(), category: "rce".into(), phase: "Persistence".into(),
        depends_on: vec![12], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::session_file_write::check(t, c))) });
    dag.add_node(ChainNode { id: 60, name: "Flood Guard Reset".into(), category: "auth".into(), phase: "Persistence".into(),
        depends_on: vec![42], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::flood_guard_reset::check(t, c))) });
    // === LateralMove ===
    dag.add_node(ChainNode { id: 61, name: "Rogue Node".into(), category: "injection".into(), phase: "LateralMove".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::rogue_node::check(t, c))) });
    // === Execution ===
    dag.add_node(ChainNode { id: 62, name: "Secret Exec Abuse".into(), category: "rce".into(), phase: "Execution".into(),
        depends_on: vec![9], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::secret_exec_abuse::check(t, c))) });
    // === CredAccess ===
    dag.add_node(ChainNode { id: 63, name: "Secrets Resolve".into(), category: "credential".into(), phase: "CredAccess".into(),
        depends_on: vec![9], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::secrets_resolve::check(t, c))) });
    dag.add_node(ChainNode { id: 64, name: "Exec Socket Leak".into(), category: "dataleak".into(), phase: "CredAccess".into(),
        depends_on: vec![11], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::exec_socket_leak::check(t, c))) });
    // === Exfiltration ===
    dag.add_node(ChainNode { id: 65, name: "C2 Exfil".into(), category: "exfil".into(), phase: "Exfiltration".into(),
        depends_on: vec![7], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::c2_exfil::check(t, c))) });
    dag.add_node(ChainNode { id: 66, name: "Memory Data Leak".into(), category: "dataleak".into(), phase: "Exfiltration".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::memory_data_leak::check(t, c))) });
    dag.add_node(ChainNode { id: 67, name: "Talk Secrets".into(), category: "dataleak".into(), phase: "Exfiltration".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::talk_secrets::check(t, c))) });
    dag.add_node(ChainNode { id: 68, name: "Redact Bypass".into(), category: "dataleak".into(), phase: "Exfiltration".into(),
        depends_on: vec![67], fallback_for: None, condition: Some(Box::new(|r| has_any_finding(r))),
        execute: Box::new(|t, c| Box::pin(exploit::redact_bypass::check(t, c))) });
    dag.add_node(ChainNode { id: 69, name: "Transcript Theft".into(), category: "dataleak".into(), phase: "Exfiltration".into(),
        depends_on: vec![0], fallback_for: None, condition: None,
        execute: Box::new(|t, c| Box::pin(exploit::transcript_theft::check(t, c))) });

    dag
}
