//! Declarative chain definition system
//!
//! This module provides a declarative way to define attack chains
//! using static configuration instead of repetitive code.

use crate::chain::dag::{ChainNode, DagChain};
use crate::exploit;

/// Attack chain node definition for declarative configuration
#[derive(Debug, Clone)]
pub struct ChainDef {
    pub id: u32,
    pub name: &'static str,
    pub category: &'static str,
    pub phase: &'static str,
    pub depends_on: &'static [u32],
    pub fallback_for: Option<u32>,
    pub check_fn: &'static str, // Function identifier
}

/// Macro to define a chain node concisely
#[macro_export]
macro_rules! chain_node {
    // Basic node with no dependencies
    ($id:expr, $name:expr, $cat:expr, $phase:expr, $check:expr) => {
        $crate::chain::ChainDef {
            id: $id,
            name: $name,
            category: $cat,
            phase: $phase,
            depends_on: &[],
            fallback_for: None,
            check_fn: $check,
        }
    };
    // Node with dependencies
    ($id:expr, $name:expr, $cat:expr, $phase:expr, $deps:expr, $check:expr) => {
        $crate::chain::ChainDef {
            id: $id,
            name: $name,
            category: $cat,
            phase: $phase,
            depends_on: $deps,
            fallback_for: None,
            check_fn: $check,
        }
    };
    // Node with dependencies and fallback
    ($id:expr, $name:expr, $cat:expr, $phase:expr, $deps:expr, $fallback:expr, $check:expr) => {
        $crate::chain::ChainDef {
            id: $id,
            name: $name,
            category: $cat,
            phase: $phase,
            depends_on: $deps,
            fallback_for: Some($fallback),
            check_fn: $check,
        }
    };
}

/// All chain definitions as a static array
pub static CHAIN_DEFINITIONS: &[ChainDef] = &[
    // === Recon Phase (Level 0) ===
    chain_node!(0, "CORS Bypass", "config", "Recon", "cors_bypass::check"),
    chain_node!(13, "WS Hijack", "transport", "Recon", "ws_hijack::check"),
    chain_node!(35, "Auth Mode Abuse", "auth", "Recon", "auth_mode_abuse::check"),
    chain_node!(15, "Log Disclosure", "disclosure", "Recon", &[0], "log_disclosure::check"),
    chain_node!(36, "Hidden Content", "disclosure", "Recon", &[0], "hidden_content::check"),
    chain_node!(37, "Origin Wildcard", "config", "Recon", &[0], "origin_wildcard::check"),

    // === Initial Access Phase (Level 1) ===
    chain_node!(1, "SSRF", "ssrf", "InitAccess", &[0], "ssrf::check"),
    chain_node!(2, "Eval Injection", "injection", "InitAccess", &[0], "eval_inject::check"),
    chain_node!(4, "Pairing Brute", "auth", "InitAccess", &[0, 35], "pairing_brute::check"),
    chain_node!(6, "Prompt Injection", "injection", "InitAccess", &[0], "prompt_inject::check"),
    chain_node!(19, "OAuth Abuse", "auth", "InitAccess", &[0, 35], "oauth_abuse::check"),
    chain_node!(20, "Responses API", "api", "InitAccess", &[0], "responses_exploit::check"),
    chain_node!(31, "MCP Plugin Inject", "injection", "InitAccess", &[0], "mcp_inject::check"),
    chain_node!(32, "ACP Bypass", "auth", "InitAccess", &[0, 35], "acp_bypass::check"),
    chain_node!(33, "Unicode Bypass", "injection", "InitAccess", &[0], "unicode_bypass::check"),
    chain_node!(34, "Channel Inject", "injection", "InitAccess", &[0], "channel_inject::check"),
    chain_node!(38, "CSRF No Origin", "config", "InitAccess", &[0], "csrf_no_origin::check"),
    chain_node!(39, "Silent Pair", "auth", "InitAccess", &[0, 35], "silent_pair_abuse::check"),
    chain_node!(42, "Ratelimit Bypass", "auth", "InitAccess", &[0], "ratelimit_scope_bypass::check"),

    // === Credential Access Phase ===
    chain_node!(3, "API Key Steal", "credential", "CredAccess", &[0], "apikey_steal::check"),
    chain_node!(43, "OAuth Token Theft", "credential", "CredAccess", &[19], "oauth_token_theft::check"),

    // === Execution Phase ===
    chain_node!(7, "RCE Check", "rce", "Execution", &[2], "rce::check"),
    chain_node!(8, "Hook Injection", "injection", "Execution", &[0, 6], "hook_inject::check"),
    chain_node!(11, "Tools Invoke", "rce", "Execution", &[0], "tools_invoke::check"),
    chain_node!(16, "Patch Escape", "traversal", "Execution", &[0], "patch_escape::check"),
    chain_node!(5, "Agent Inject", "injection", "Execution", &[6], "agent_inject::check"),
    chain_node!(14, "Agent File Inject", "injection", "Execution", &[5], "agent_file_inject::check"),
    chain_node!(45, "Marker Spoof", "injection", "Execution", &[6], "marker_spoof::check"),
    chain_node!(49, "Keychain Cmd Inject", "rce", "Execution", &[0], "keychain_cmd_inject::check"),
    chain_node!(51, "Browser Request", "ssrf", "Execution", &[0], "browser_request::check"),
    chain_node!(53, "Bypass Soul", "injection", "Execution", &[6], "bypass_soul::check"),
    chain_node!(54, "Approval Hijack", "auth", "Execution", &[0], "approval_hijack::check"),

    // === Persistence Phase ===
    chain_node!(10, "Config Tamper", "config", "Persistence", &[0], "config_tamper::check"),
    chain_node!(57, "Skill Poison", "injection", "Persistence", &[0], "skill_poison::check"),
    chain_node!(58, "Webhook Verify", "config", "Persistence", &[0], "webhook_verify::check"),
    chain_node!(60, "Flood Guard Reset", "auth", "Persistence", &[42], "flood_guard_reset::check"),

    // === Lateral Movement Phase ===
    chain_node!(61, "Rogue Node", "injection", "LateralMove", &[0], "rogue_node::check"),

    // === Exfiltration Phase ===
    chain_node!(65, "C2 Exfil", "exfil", "Exfiltration", &[7], "c2_exfil::check"),
    chain_node!(66, "Memory Data Leak", "dataleak", "Exfiltration", &[0], "memory_data_leak::check"),
    chain_node!(67, "Talk Secrets", "dataleak", "Exfiltration", &[0], "talk_secrets::check"),
    chain_node!(69, "Transcript Theft", "dataleak", "Exfiltration", &[0], "transcript_theft::check"),

    // === Session/Credential Access ===
    chain_node!(12, "Session Hijack", "session", "CredAccess", &[0], "session_hijack::check"),
    chain_node!(9, "Secret Extract", "credential", "CredAccess", &[0, 3], "secret_extract::check"),
    chain_node!(63, "Secrets Resolve", "credential", "CredAccess", &[9], "secrets_resolve::check"),
    chain_node!(64, "Exec Socket Leak", "dataleak", "CredAccess", &[11], "exec_socket_leak::check"),
    chain_node!(56, "Auth Disable Leak", "auth", "CredAccess", &[35], "auth_disable_leak::check"),

    // === CVE-Targeted Modules (2026 Threat Intelligence) ===
    // Recon
    chain_node!(70, "Gateway Hijack", "transport", "Recon", "gateway_hijack::check"),          // CVE-2026-25253
    chain_node!(71, "Localhost Trust", "auth", "Recon", "localhost_trust::check"),              // ClawJacked
    chain_node!(72, "mDNS Config Leak", "dataleak", "Recon", "mdns_leak::check"),              // Config leak

    // Initial Access
    chain_node!(73, "WS Auth Brute", "auth", "InitAccess", &[13], "ws_auth_brute::check"),    // CVE-2026-32025
    chain_node!(74, "Guest Mode Abuse", "config", "InitAccess", &[71], "guest_mode_abuse::check"),
    chain_node!(75, "Skill Supply Chain", "dataleak", "InitAccess", &[0], "skill_supply_chain::check"), // ClawHavoc

    // Execution
    chain_node!(76, "SafeBins Bypass", "rce", "Execution", &[7], "safebins_bypass::check"),    // CVE-2026-28363

    // === P0: Additional CVE coverage ===
    chain_node!(77, "Voice Ext RCE", "rce", "Execution", &[0], "voice_ext_rce::check"),        // CVE-2026-28446
    chain_node!(78, "Env Injection", "injection", "Execution", &[7], "env_inject::check"),      // CVE-2026-32056
    chain_node!(79, "IPv6 SSRF Bypass", "ssrf", "InitAccess", &[1], "ipv6_ssrf_bypass::check"),
    chain_node!(80, "Msg Platform Spoof", "auth", "InitAccess", &[0], "msg_platform_spoof::check"),

    // === P2: Multi-platform probes ===
    chain_node!(81, "LibreChat Probe", "recon", "Recon", "librechat_probe::check"),
    chain_node!(82, "LobeChat Probe", "recon", "Recon", "lobechat_probe::check"),
    chain_node!(83, "Dify Probe", "recon", "Recon", "dify_probe::check"),
    chain_node!(84, "FastGPT Probe", "recon", "Recon", "fastgpt_probe::check"),
    chain_node!(85, "NextChat Probe", "recon", "Recon", "nextchat_probe::check"),
    chain_node!(86, "AnythingLLM Probe", "recon", "Recon", "anythingllm_probe::check"),
    chain_node!(87, "Flowise Probe", "recon", "Recon", "flowise_probe::check"),
    chain_node!(88, "RAGFlow Probe", "recon", "Recon", "ragflow_probe::check"),
];

/// Build the full attack DAG from definitions
pub fn build_full_dag(concurrency: usize) -> DagChain {
    let mut dag = DagChain::new(concurrency);

    for def in CHAIN_DEFINITIONS {
        dag.add_node(ChainNode {
            id: def.id,
            name: def.name.to_string(),
            category: def.category.to_string(),
            phase: def.phase.to_string(),
            depends_on: def.depends_on.to_vec(),
            fallback_for: def.fallback_for,
            execute: build_execute_fn(def.check_fn),
            condition: None,
        });
    }

    dag
}

/// Build execute function from function identifier
fn build_execute_fn(fn_name: &str) -> crate::chain::dag::ExecFn {
    use crate::exploit::registry::ExploitResult;
    use crate::config::AppConfig;
    use crate::utils::Target;

    // Map function names to actual implementations
    match fn_name {
        // Recon
        "cors_bypass::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::cors_bypass::check(t, c).await.into_standard() })
        }),
        "ws_hijack::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::ws_hijack::check(t, c).await.into_standard() })
        }),
        "auth_mode_abuse::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::auth_mode_abuse::check(t, c).await.into_standard() })
        }),
        "log_disclosure::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::log_disclosure::check(t, c).await.into_standard() })
        }),
        "hidden_content::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::hidden_content::check(t, c).await.into_standard() })
        }),
        "origin_wildcard::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::origin_wildcard::check(t, c).await.into_standard() })
        }),

        // Initial Access
        "ssrf::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::ssrf::check(t, c).await.into_standard() })
        }),
        "eval_inject::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::eval_inject::check(t, c).await.into_standard() })
        }),
        "pairing_brute::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::pairing_brute::check(t, c).await.into_standard() })
        }),
        "prompt_inject::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::prompt_inject::check(t, c).await.into_standard() })
        }),
        "oauth_abuse::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::oauth_abuse::check(t, c).await.into_standard() })
        }),
        "responses_exploit::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::responses_exploit::check(t, c).await.into_standard() })
        }),
        "mcp_inject::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::mcp_inject::check(t, c).await.into_standard() })
        }),
        "acp_bypass::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::acp_bypass::check(t, c).await.into_standard() })
        }),
        "unicode_bypass::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::unicode_bypass::check(t, c).await.into_standard() })
        }),
        "channel_inject::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::channel_inject::check(t, c).await.into_standard() })
        }),
        "csrf_no_origin::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::csrf_no_origin::check(t, c).await.into_standard() })
        }),
        "silent_pair_abuse::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::silent_pair_abuse::check(t, c).await.into_standard() })
        }),
        "ratelimit_scope_bypass::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::ratelimit_scope_bypass::check(t, c).await.into_standard() })
        }),

        // Credential Access
        "apikey_steal::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::apikey_steal::check(t, c).await.into_standard() })
        }),
        "oauth_token_theft::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::oauth_token_theft::check(t, c).await.into_standard() })
        }),
        "secret_extract::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::secret_extract::check(t, c).await.into_standard() })
        }),
        "secrets_resolve::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::secrets_resolve::check(t, c).await.into_standard() })
        }),
        "session_hijack::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::session_hijack::check(t, c).await.into_standard() })
        }),
        "auth_disable_leak::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::auth_disable_leak::check(t, c).await.into_standard() })
        }),

        // Execution
        "rce::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::rce::check(t, c).await.into_standard() })
        }),
        "hook_inject::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::hook_inject::check(t, c).await.into_standard() })
        }),
        "tools_invoke::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::tools_invoke::check(t, c).await.into_standard() })
        }),
        "patch_escape::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::patch_escape::check(t, c).await.into_standard() })
        }),
        "agent_inject::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::agent_inject::check(t, c).await.into_standard() })
        }),
        "agent_file_inject::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::agent_file_inject::check(t, c).await.into_standard() })
        }),
        "marker_spoof::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::marker_spoof::check(t, c).await.into_standard() })
        }),
        "keychain_cmd_inject::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::keychain_cmd_inject::check(t, c).await.into_standard() })
        }),
        "browser_request::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::browser_request::check(t, c).await.into_standard() })
        }),
        "bypass_soul::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::bypass_soul::check(t, c).await.into_standard() })
        }),
        "approval_hijack::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::approval_hijack::check(t, c).await.into_standard() })
        }),

        // Persistence
        "config_tamper::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::config_tamper::check(t, c).await.into_standard() })
        }),
        "skill_poison::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::skill_poison::check(t, c).await.into_standard() })
        }),
        "webhook_verify::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::webhook_verify::check(t, c).await.into_standard() })
        }),
        "flood_guard_reset::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::flood_guard_reset::check(t, c).await.into_standard() })
        }),

        // Lateral Movement
        "rogue_node::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::rogue_node::check(t, c).await.into_standard() })
        }),

        // Exfiltration
        "c2_exfil::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::c2_exfil::check(t, c).await.into_standard() })
        }),
        "memory_data_leak::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::memory_data_leak::check(t, c).await.into_standard() })
        }),
        "talk_secrets::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::talk_secrets::check(t, c).await.into_standard() })
        }),
        "transcript_theft::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::transcript_theft::check(t, c).await.into_standard() })
        }),

        // Additional modules
        "exec_socket_leak::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::exec_socket_leak::check(t, c).await.into_standard() })
        }),

        // CVE-targeted modules (2026 threat intelligence)
        "gateway_hijack::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::gateway_hijack::check(t, c).await.into_standard() })
        }),
        "localhost_trust::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::localhost_trust::check(t, c).await.into_standard() })
        }),
        "mdns_leak::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::mdns_leak::check(t, c).await.into_standard() })
        }),
        "ws_auth_brute::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::ws_auth_brute::check(t, c).await.into_standard() })
        }),
        "guest_mode_abuse::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::guest_mode_abuse::check(t, c).await.into_standard() })
        }),
        "skill_supply_chain::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::skill_supply_chain::check(t, c).await.into_standard() })
        }),
        "safebins_bypass::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::safebins_bypass::check(t, c).await.into_standard() })
        }),

        // P0: Additional CVE modules
        "voice_ext_rce::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::voice_ext_rce::check(t, c).await.into_standard() })
        }),
        "env_inject::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::env_inject::check(t, c).await.into_standard() })
        }),
        "ipv6_ssrf_bypass::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::ipv6_ssrf_bypass::check(t, c).await.into_standard() })
        }),
        "msg_platform_spoof::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::msg_platform_spoof::check(t, c).await.into_standard() })
        }),

        // P2: Multi-platform probes
        "librechat_probe::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::librechat_probe::check(t, c).await.into_standard() })
        }),
        "lobechat_probe::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::lobechat_probe::check(t, c).await.into_standard() })
        }),
        "dify_probe::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::dify_probe::check(t, c).await.into_standard() })
        }),
        "fastgpt_probe::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::fastgpt_probe::check(t, c).await.into_standard() })
        }),
        "nextchat_probe::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::nextchat_probe::check(t, c).await.into_standard() })
        }),
        "anythingllm_probe::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::anythingllm_probe::check(t, c).await.into_standard() })
        }),
        "flowise_probe::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::flowise_probe::check(t, c).await.into_standard() })
        }),
        "ragflow_probe::check" => Box::new(|t: Target, c: AppConfig| {
            Box::pin(async move { exploit::ragflow_probe::check(t, c).await.into_standard() })
        }),

        _ => {
            // Default: return empty findings
            Box::new(|_t: Target, _c: AppConfig| {
                Box::pin(async move { (vec![], crate::exploit::base::ExploitOutcome::Clean(String::new())) })
            })
        }
    }
}

/// Get chain definition by ID
pub fn get_chain_by_id(id: u32) -> Option<&'static ChainDef> {
    CHAIN_DEFINITIONS.iter().find(|d| d.id == id)
}

/// Get all chains for a specific phase
pub fn get_chains_by_phase(phase: &str) -> Vec<&'static ChainDef> {
    CHAIN_DEFINITIONS
        .iter()
        .filter(|d| d.phase == phase)
        .collect()
}

/// Get chain statistics
pub fn chain_stats() -> (usize, std::collections::HashMap<&'static str, usize>) {
    let total = CHAIN_DEFINITIONS.len();
    let mut by_phase = std::collections::HashMap::new();

    for def in CHAIN_DEFINITIONS {
        *by_phase.entry(def.phase).or_insert(0) += 1;
    }

    (total, by_phase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_definitions_not_empty() {
        assert!(!CHAIN_DEFINITIONS.is_empty());
    }

    #[test]
    fn test_chain_stats() {
        let (total, by_phase) = chain_stats();
        assert!(total > 0);
        assert!(by_phase.contains_key(&"Recon"));
    }

    #[test]
    fn test_get_chain_by_id() {
        let chain = get_chain_by_id(0);
        assert!(chain.is_some());
        assert_eq!(chain.unwrap().name, "CORS Bypass");
    }

    #[test]
    fn test_get_chains_by_phase() {
        let recon = get_chains_by_phase("Recon");
        assert!(!recon.is_empty());
    }
}