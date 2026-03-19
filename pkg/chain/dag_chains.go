package chain

import (
	"github.com/coff0xc/lobster-guard/pkg/exploit"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍BuildFullDAG creates the complete 66-node DAG with deep dependencies, conditions,
// ATT&CK phases, and fallback paths. Max depth: 7 layers.
func BuildFullDAG(concurrency int, aggressive bool) *DAGChain {
	dag := NewDAGChain(concurrency, aggressive)

	// ====================================================================
	//  Layer 0: Reconnaissance (zero-auth, no dependencies)
	// ====================================================================

	dag.AddNode(&ChainNode{
		ID:       0,
		Name:     "Platform Fingerprint",
		Category: "recon",
		Phase:    PhaseRecon,
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.PlatformFingerprint(t, exploit.PlatformFingerprintConfig{Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       13,
		Name:     "CORS Bypass",
		Category: "config",
		Phase:    PhaseRecon,
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.CORSBypassCheck(t, exploit.CORSBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       17,
		Name:     "WS Hijack",
		Category: "transport",
		Phase:    PhaseRecon,
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.WSHijackCheck(t, exploit.WSHijackConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       35,
		Name:     "Auth Mode Abuse",
		Category: "auth",
		Phase:    PhaseRecon,
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.AuthModeAbuseCheck(t, exploit.AuthModeConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// ====================================================================
	//  Layer 1: Initial Access & Early Credential Harvesting
	// ====================================================================

	dag.AddNode(&ChainNode{
		ID:       1,
		Name:     "SSRF",
		Category: "ssrf",
		Phase:    PhaseInitAccess,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SSRFCheck(t, exploit.SSRFConfig{Token: c.Token, Timeout: c.Timeout, CallbackURL: c.CallbackURL})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       2,
		Name:     "Eval Injection",
		Category: "injection",
		Phase:    PhaseInitAccess,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.EvalInjectCheck(t, exploit.EvalInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       3,
		Name:     "API Key Steal",
		Category: "credential",
		Phase:    PhaseCredAccess,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.APIKeyStealCheck(t, exploit.APIKeyStealConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       4,
		Name:     "Pairing Brute",
		Category: "auth",
		Phase:    PhaseInitAccess,
		DependsOn: []int{0, 35},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			cfg := exploit.DefaultPairingBruteConfig()
			cfg.Token = c.Token
			cfg.Timeout = c.Timeout
			return exploit.PairingBruteCheck(t, cfg)
		},
	})

	dag.AddNode(&ChainNode{
		ID:       6,
		Name:     "Prompt Injection",
		Category: "injection",
		Phase:    PhaseInitAccess,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.PromptInjectCheck(t, exploit.PromptInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       15,
		Name:     "Log Disclosure",
		Category: "disclosure",
		Phase:    PhaseRecon,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.LogDisclosureCheck(t, exploit.LogDisclosureConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       19,
		Name:     "OAuth Abuse",
		Category: "auth",
		Phase:    PhaseInitAccess,
		DependsOn: []int{0, 35},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.OAuthAbuseCheck(t, exploit.OAuthAbuseConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       20,
		Name:     "Responses API Exploit",
		Category: "api",
		Phase:    PhaseInitAccess,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ResponsesExploitCheck(t, exploit.ResponsesExploitConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       21,
		Name:     "WS Fuzz",
		Category: "fuzz",
		Phase:    PhaseInitAccess,
		DependsOn: []int{17},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.WSFuzzCheck(t, exploit.WSFuzzConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       31,
		Name:     "MCP Plugin Inject",
		Category: "injection",
		Phase:    PhaseInitAccess,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.McpInjectCheck(t, exploit.McpInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       32,
		Name:     "ACP Permission Bypass",
		Category: "auth",
		Phase:    PhaseInitAccess,
		DependsOn: []int{0, 35},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.AcpBypassCheck(t, exploit.AcpBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       33,
		Name:     "Unicode Filter Bypass",
		Category: "injection",
		Phase:    PhaseInitAccess,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.UnicodeBypassCheck(t, exploit.UnicodeBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       36,
		Name:     "Skill Scanner Bypass",
		Category: "evasion",
		Phase:    PhaseInitAccess,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SkillScannerBypassCheck(t, exploit.SkillScanBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       38,
		Name:     "Rate Limit Scope Bypass",
		Category: "auth",
		Phase:    PhaseInitAccess,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.RateLimitBypassCheck(t, exploit.RateLimitBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       42,
		Name:     "CSRF No-Origin Bypass",
		Category: "config",
		Phase:    PhaseInitAccess,
		DependsOn: []int{13},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.CSRFNoOriginCheck(t, exploit.CSRFBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       43,
		Name:     "Origin Wildcard Check",
		Category: "config",
		Phase:    PhaseInitAccess,
		DependsOn: []int{13},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.OriginWildcardCheck(t, exploit.OriginWildcardConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       50,
		Name:     "Link Template Injection",
		Category: "injection",
		Phase:    PhaseInitAccess,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.LinkTemplateInjectCheck(t, exploit.LinkTemplateInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       51,
		Name:     "QMD Command Injection",
		Category: "rce",
		Phase:    PhaseExecution,
		DependsOn: []int{0},
		Severity: "CRITICAL",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.QMDCmdInjectCheck(t, exploit.QMDCmdInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       65,
		Name:     "Webhook Signature Verification",
		Category: "auth",
		Phase:    PhaseInitAccess,
		DependsOn: []int{0},
		Severity: "HIGH",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.WebhookVerifyCheck(t, exploit.WebhookVerifyConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       66,
		Name:     "MCP Server List Enumeration",
		Category: "recon",
		Phase:    PhaseRecon,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.McpServerListCheck(t, exploit.McpInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       7,
		Name:     "RCE Check",
		Category: "rce",
		Phase:    PhaseExecution,
		DependsOn: []int{2},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Severity: "CRITICAL",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.RCECheck(t, exploit.RCEConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       8,
		Name:     "Hook Injection",
		Category: "injection",
		Phase:    PhaseExecution,
		DependsOn: []int{0, 6},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.HookInjectCheck(t, exploit.HookInjectConfig{Token: c.Token, HookToken: c.HookToken, HookPath: c.HookPath, Timeout: c.Timeout})
		},
	})

	// ====================================================================
	//  Layer 2: Execution & Deeper Credential Access
	// ====================================================================

	dag.AddNode(&ChainNode{
		ID:       9,
		Name:     "Secret Extract",
		Category: "credential",
		Phase:    PhaseCredAccess,
		DependsOn: []int{0, 3},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SecretExtractCheck(t, exploit.SecretExtractConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       10,
		Name:     "Config Tamper",
		Category: "config",
		Phase:    PhasePersistence,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ConfigTamperCheck(t, exploit.ConfigTamperConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       11,
		Name:     "Tools Invoke",
		Category: "rce",
		Phase:    PhaseExecution,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ToolsInvokeCheck(t, exploit.ToolsInvokeConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       12,
		Name:     "Session Hijack",
		Category: "session",
		Phase:    PhaseCredAccess,
		DependsOn: []int{0, 19},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SessionHijackCheck(t, exploit.SessionHijackConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       14,
		Name:     "Channel Inject",
		Category: "injection",
		Phase:    PhaseExecution,
		DependsOn: []int{17},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ChannelInjectCheck(t, exploit.ChannelInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       16,
		Name:     "Patch Escape",
		Category: "traversal",
		Phase:    PhaseExecution,
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.PatchEscapeCheck(t, exploit.PatchEscapeConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       18,
		Name:     "Agent Inject",
		Category: "injection",
		Phase:    PhaseExecution,
		DependsOn: []int{6},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.AgentInjectCheck(t, exploit.AgentInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       39,
		Name:     "Flood Guard Reset",
		Category: "auth",
		Phase:    PhaseInitAccess,
		DependsOn: []int{38},
		FallbackFor: 38,
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.FloodGuardResetCheck(t, exploit.FloodGuardConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       40,
		Name:     "Silent Local Pairing",
		Category: "auth",
		Phase:    PhaseInitAccess,
		DependsOn: []int{4},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SilentPairCheck(t, exploit.SilentPairConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       41,
		Name:     "Auth Disable Leak",
		Category: "auth",
		Phase:    PhaseCredAccess,
		DependsOn: []int{35},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.AuthDisableLeakCheck(t, exploit.AuthDisableConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       55,
		Name:     "OAuth Token Theft",
		Category: "credential",
		Phase:    PhaseCredAccess,
		DependsOn: []int{19},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Severity: "HIGH",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.OAuthTokenTheftCheck(t, exploit.OAuthTokenTheftConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       56,
		Name:     "ClawJacked Token Theft",
		Category: "credential",
		Phase:    PhaseCredAccess,
		DependsOn: []int{17},
		Severity: "CRITICAL",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ClawJackedCheck(t, exploit.WSHijackConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       57,
		Name:     "Gateway URL SSRF",
		Category: "ssrf",
		Phase:    PhaseInitAccess,
		DependsOn: []int{1},
		FallbackFor: 1,
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.GatewayURLSSRFCheck(t, exploit.GatewayURLSSRFConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       58,
		Name:     "Browser Upload Traversal",
		Category: "traversal",
		Phase:    PhaseExecution,
		DependsOn: []int{0},
		Severity: "CRITICAL",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.BrowserUploadTraversalCheck(t, exploit.BrowserUploadTraversalConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       59,
		Name:     "Keychain Cmd Inject",
		Category: "rce",
		Phase:    PhaseExecution,
		DependsOn: []int{0},
		Severity: "CRITICAL",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.KeychainCmdInjectCheck(t, exploit.KeychainCmdInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       63,
		Name:     "Bypass Soul Parameter Injection",
		Category: "auth",
		Phase:    PhaseInitAccess,
		DependsOn: []int{0, 6},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Severity: "CRITICAL",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.BypassSoulCheck(t, exploit.BypassSoulConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// ====================================================================
	//  Layer 3: Lateral Movement & Collection
	// ====================================================================

	dag.AddNode(&ChainNode{
		ID:       5,
		Name:     "Cron Bypass",
		Category: "persistence",
		Phase:    PhasePersistence,
		DependsOn: []int{0, 10},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.CronBypassCheck(t, exploit.CronBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       22,
		Name:     "Agent File Inject",
		Category: "persistence",
		Phase:    PhasePersistence,
		DependsOn: []int{18},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.AgentFileInjectCheck(t, exploit.AgentFileInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       23,
		Name:     "Session File Write",
		Category: "traversal",
		Phase:    PhasePersistence,
		DependsOn: []int{12, 56},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SessionFileWriteCheck(t, exploit.SessionFileWriteConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       24,
		Name:     "Approval Hijack",
		Category: "auth",
		Phase:    PhaseExecution,
		DependsOn: []int{7},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ApprovalHijackCheck(t, exploit.ApprovalHijackConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       25,
		Name:     "Talk Secrets",
		Category: "credential",
		Phase:    PhaseCredAccess,
		DependsOn: []int{9},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.TalkSecretsCheck(t, exploit.TalkSecretsConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       26,
		Name:     "Browser Request SSRF",
		Category: "ssrf",
		Phase:    PhaseLateral,
		DependsOn: []int{1},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.BrowserRequestCheck(t, exploit.BrowserRequestConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       27,
		Name:     "Secrets Resolve",
		Category: "credential",
		Phase:    PhaseCredAccess,
		DependsOn: []int{9},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SecretsResolveCheck(t, exploit.SecretsResolveConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       28,
		Name:     "Transcript Theft",
		Category: "disclosure",
		Phase:    PhaseCollection,
		DependsOn: []int{12},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.TranscriptTheftCheck(t, exploit.TranscriptTheftConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       29,
		Name:     "Rogue Node",
		Category: "persistence",
		Phase:    PhasePersistence,
		DependsOn: []int{4, 41},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.RogueNodeCheck(t, exploit.RogueNodeConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       44,
		Name:     "SSRF DNS Rebinding",
		Category: "ssrf",
		Phase:    PhaseLateral,
		DependsOn: []int{1},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SSRFRebindCheck(t, exploit.SSRFRebindConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       45,
		Name:     "SSRF Proxy Bypass",
		Category: "ssrf",
		Phase:    PhaseLateral,
		DependsOn: []int{1},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SSRFProxyBypassCheck(t, exploit.SSRFProxyConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       49,
		Name:     "Redaction Pattern Bypass",
		Category: "disclosure",
		Phase:    PhaseCollection,
		DependsOn: []int{15},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.RedactBypassCheck(t, exploit.RedactBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       52,
		Name:     "Exec Race TOCTOU",
		Category: "rce",
		Phase:    PhaseExecution,
		DependsOn: []int{7},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Severity: "CRITICAL",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ExecRaceTOCTOUCheck(t, exploit.ExecRaceTOCTOUConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// ====================================================================
	//  Layer 4: Deep Exploitation & Privilege Escalation
	// ====================================================================

	dag.AddNode(&ChainNode{
		ID:       53,
		Name:     "Hidden Content Discovery",
		Category: "disclosure",
		Phase:    PhaseCollection,
		DependsOn: []int{0, 15},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.HiddenContentCheck(t, exploit.HiddenContentConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       54,
		Name:     "Memory Data Leak",
		Category: "disclosure",
		Phase:    PhaseCollection,
		DependsOn: []int{12, 55},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.MemoryDataLeakCheck(t, exploit.MemoryDataLeakConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       60,
		Name:     "Cron Webhook SSRF",
		Category: "ssrf",
		Phase:    PhaseLateral,
		DependsOn: []int{5},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.CronWebhookSSRFCheck(t, exploit.CronWebhookSSRFConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       34,
		Name:     "Secret Exec Abuse",
		Category: "credential",
		Phase:    PhaseExecution,
		DependsOn: []int{9, 27},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SecretExecAbuseCheck(t, exploit.SecretExecConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       46,
		Name:     "Obfuscation Unicode Bypass",
		Category: "evasion",
		Phase:    PhaseExecution,
		DependsOn: []int{7, 33},
		Condition: func(f []utils.Finding) bool { return HasCriticalOrHigh(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ObfuscationBypassCheck(t, exploit.ObfuscationBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       47,
		Name:     "Exec Socket Leak",
		Category: "disclosure",
		Phase:    PhaseCollection,
		DependsOn: []int{7},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ExecSocketLeakCheck(t, exploit.ExecSocketConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// ====================================================================
	//  Layer 5: Full Kill Chain
	// ====================================================================

	dag.AddNode(&ChainNode{
		ID:       48,
		Name:     "Marker Spoof + Skill Evasion",
		Category: "evasion",
		Phase:    PhaseExecution,
		DependsOn: []int{33, 36},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.MarkerSpoofCheck(t, exploit.MarkerSpoofConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// ====================================================================
	//  Layer 6: Exfiltration & Impact
	// ====================================================================

	dag.AddNode(&ChainNode{
		ID:       61,
		Name:     "Skill Poison",
		Category: "injection",
		Phase:    PhasePersistence,
		DependsOn: []int{22, 36},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Severity: "CRITICAL",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SkillPoisonCheck(t, exploit.SkillPoisonConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// ====================================================================
	//  Layer 7
	// ====================================================================

	dag.AddNode(&ChainNode{
		ID:       62,
		Name:     "Media SSRF",
		Category: "ssrf",
		Phase:    PhaseLateral,
		DependsOn: []int{1, 26},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.MediaSSRFCheck(t, exploit.MediaSSRFConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       30,
		Name:     "Full RCE Chain",
		Category: "rce",
		Phase:    PhaseExecution,
		DependsOn: []int{7, 24},
		Condition: func(f []utils.Finding) bool { return HasCriticalOrHigh(f) },
		Severity: "CRITICAL",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.FullRCECheck(t, exploit.FullRCEConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       64,
		Name:     "C2 Exfiltration via Command Filter",
		Category: "rce",
		Phase:    PhaseExfil,
		DependsOn: []int{30, 61},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Severity: "CRITICAL",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.C2ExfilCheck(t, exploit.C2ExfilConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	return dag
}

// RunDAGChain executes the full DAG attack chain (v2 replacement for RunFullChain)
func RunDAGChain(target utils.Target, cfg ChainConfig, concurrency int, aggressive bool) []utils.Finding {
	dag := BuildFullDAG(concurrency, aggressive)
	return dag.Execute(target, cfg)
}
