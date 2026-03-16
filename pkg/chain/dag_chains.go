package chain

import (
	"github.com/coff0xc/lobster-guard/pkg/exploit"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// BuildFullDAG creates the complete 49-chain DAG with dependencies and conditions
func BuildFullDAG(concurrency int, aggressive bool) *DAGChain {
	dag := NewDAGChain(concurrency, aggressive)

	// === Level 0: Zero-auth reconnaissance ===
	dag.AddNode(&ChainNode{
		ID:       0,
		Name:     "Platform Fingerprint",
		Category: "recon",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.PlatformFingerprint(t, exploit.PlatformFingerprintConfig{Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       13,
		Name:     "CORS Bypass",
		Category: "config",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.CORSBypassCheck(t, exploit.CORSBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:       17,
		Name:     "WS Hijack",
		Category: "transport",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.WSHijackCheck(t, exploit.WSHijackConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// === Level 0b: Auth mode analysis (new) ===
	dag.AddNode(&ChainNode{
		ID:       35,
		Name:     "Auth Mode Abuse",
		Category: "auth",
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.AuthModeAbuseCheck(t, exploit.AuthModeConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// === Level 1: Requires basic access or auth ===
	dag.AddNode(&ChainNode{
		ID:        1,
		Name:      "SSRF",
		Category:  "ssrf",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SSRFCheck(t, exploit.SSRFConfig{Token: c.Token, Timeout: c.Timeout, CallbackURL: c.CallbackURL})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        2,
		Name:      "Eval Injection",
		Category:  "injection",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.EvalInjectCheck(t, exploit.EvalInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        3,
		Name:      "API Key Steal",
		Category:  "credential",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.APIKeyStealCheck(t, exploit.APIKeyStealConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        4,
		Name:      "Pairing Brute",
		Category:  "auth",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			cfg := exploit.DefaultPairingBruteConfig()
			cfg.Token = c.Token
			cfg.Timeout = c.Timeout
			return exploit.PairingBruteCheck(t, cfg)
		},
	})

	dag.AddNode(&ChainNode{
		ID:        6,
		Name:      "Prompt Injection",
		Category:  "injection",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.PromptInjectCheck(t, exploit.PromptInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        15,
		Name:      "Log Disclosure",
		Category:  "disclosure",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.LogDisclosureCheck(t, exploit.LogDisclosureConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        19,
		Name:      "OAuth Abuse",
		Category:  "auth",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.OAuthAbuseCheck(t, exploit.OAuthAbuseConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        20,
		Name:      "Responses API Exploit",
		Category:  "api",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ResponsesExploitCheck(t, exploit.ResponsesExploitConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        21,
		Name:      "WS Fuzz",
		Category:  "fuzz",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.WSFuzzCheck(t, exploit.WSFuzzConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// === Level 1b: New v2 attacks (parallel) ===
	dag.AddNode(&ChainNode{
		ID:        31,
		Name:      "MCP Plugin Inject",
		Category:  "injection",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.McpInjectCheck(t, exploit.McpInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        32,
		Name:      "ACP Permission Bypass",
		Category:  "auth",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.AcpBypassCheck(t, exploit.AcpBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        33,
		Name:      "Unicode Filter Bypass",
		Category:  "injection",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.UnicodeBypassCheck(t, exploit.UnicodeBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        36,
		Name:      "Skill Scanner Bypass",
		Category:  "evasion",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SkillScannerBypassCheck(t, exploit.SkillScanBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// === Level 2: Requires authenticated access ===
	dag.AddNode(&ChainNode{
		ID:        5,
		Name:      "Cron Bypass",
		Category:  "persistence",
		DependsOn: []int{0},
		Condition: func(f []utils.Finding) bool { return HasAnyFinding(f) },
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.CronBypassCheck(t, exploit.CronBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        7,
		Name:      "RCE Check",
		Category:  "rce",
		DependsOn: []int{2},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.RCECheck(t, exploit.RCEConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        8,
		Name:      "Hook Injection",
		Category:  "injection",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.HookInjectCheck(t, exploit.HookInjectConfig{
				Token: c.Token, HookToken: c.HookToken, HookPath: c.HookPath, Timeout: c.Timeout,
			})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        9,
		Name:      "Secret Extract",
		Category:  "credential",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SecretExtractCheck(t, exploit.SecretExtractConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        10,
		Name:      "Config Tamper",
		Category:  "config",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ConfigTamperCheck(t, exploit.ConfigTamperConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        11,
		Name:      "Tools Invoke",
		Category:  "rce",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ToolsInvokeCheck(t, exploit.ToolsInvokeConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        12,
		Name:      "Session Hijack",
		Category:  "session",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SessionHijackCheck(t, exploit.SessionHijackConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        14,
		Name:      "Channel Inject",
		Category:  "injection",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ChannelInjectCheck(t, exploit.ChannelInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        16,
		Name:      "Patch Escape",
		Category:  "traversal",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.PatchEscapeCheck(t, exploit.PatchEscapeConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        18,
		Name:      "Agent Inject",
		Category:  "injection",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.AgentInjectCheck(t, exploit.AgentInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        22,
		Name:      "Agent File Inject",
		Category:  "persistence",
		DependsOn: []int{18},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.AgentFileInjectCheck(t, exploit.AgentFileInjectConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        23,
		Name:      "Session File Write",
		Category:  "traversal",
		DependsOn: []int{12},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SessionFileWriteCheck(t, exploit.SessionFileWriteConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        24,
		Name:      "Approval Hijack",
		Category:  "auth",
		DependsOn: []int{7},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ApprovalHijackCheck(t, exploit.ApprovalHijackConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        25,
		Name:      "Talk Secrets",
		Category:  "credential",
		DependsOn: []int{9},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.TalkSecretsCheck(t, exploit.TalkSecretsConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        26,
		Name:      "Browser Request SSRF",
		Category:  "ssrf",
		DependsOn: []int{1},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.BrowserRequestCheck(t, exploit.BrowserRequestConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        27,
		Name:      "Secrets Resolve",
		Category:  "credential",
		DependsOn: []int{9},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SecretsResolveCheck(t, exploit.SecretsResolveConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        28,
		Name:      "Transcript Theft",
		Category:  "disclosure",
		DependsOn: []int{12},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.TranscriptTheftCheck(t, exploit.TranscriptTheftConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        29,
		Name:      "Rogue Node",
		Category:  "persistence",
		DependsOn: []int{4},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.RogueNodeCheck(t, exploit.RogueNodeConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// === Level 2b: New v2 with dependencies ===
	dag.AddNode(&ChainNode{
		ID:        34,
		Name:      "Secret Exec Abuse",
		Category:  "credential",
		DependsOn: []int{9, 27},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SecretExecAbuseCheck(t, exploit.SecretExecConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// === Level 3: Full RCE chain (requires prior findings) ===
	dag.AddNode(&ChainNode{
		ID:        30,
		Name:      "Full RCE Chain",
		Category:  "rce",
		DependsOn: []int{7, 24},
		Condition: func(f []utils.Finding) bool {
			return HasFindingWithSeverity(f, utils.SevHigh)
		},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.FullRCECheck(t, exploit.FullRCEConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// === Level 1c: V3 Auth/Session layer attacks ===
	dag.AddNode(&ChainNode{
		ID:        38,
		Name:      "Rate Limit Scope Bypass",
		Category:  "auth",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.RateLimitBypassCheck(t, exploit.RateLimitBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        39,
		Name:      "Flood Guard Reset",
		Category:  "auth",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.FloodGuardResetCheck(t, exploit.FloodGuardConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        40,
		Name:      "Silent Local Pairing",
		Category:  "auth",
		DependsOn: []int{4},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SilentPairCheck(t, exploit.SilentPairConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        41,
		Name:      "Auth Disable Leak",
		Category:  "auth",
		DependsOn: []int{35},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.AuthDisableLeakCheck(t, exploit.AuthDisableConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// === Level 1d: V3 CSRF/Origin attacks ===
	dag.AddNode(&ChainNode{
		ID:        42,
		Name:      "CSRF No-Origin Bypass",
		Category:  "config",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.CSRFNoOriginCheck(t, exploit.CSRFBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        43,
		Name:      "Origin Wildcard Check",
		Category:  "config",
		DependsOn: []int{0},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.OriginWildcardCheck(t, exploit.OriginWildcardConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// === Level 2c: V3 SSRF deep bypass (depends on initial SSRF) ===
	dag.AddNode(&ChainNode{
		ID:        44,
		Name:      "SSRF DNS Rebinding",
		Category:  "ssrf",
		DependsOn: []int{1},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SSRFRebindCheck(t, exploit.SSRFRebindConfig{Token: c.Token, Timeout: c.Timeout, CallbackURL: c.CallbackURL})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        45,
		Name:      "SSRF Proxy Bypass",
		Category:  "ssrf",
		DependsOn: []int{1},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.SSRFProxyBypassCheck(t, exploit.SSRFProxyConfig{Token: c.Token, Timeout: c.Timeout, CallbackURL: c.CallbackURL})
		},
	})

	// === Level 3b: V3 Exec pipeline (depends on RCE check) ===
	dag.AddNode(&ChainNode{
		ID:        46,
		Name:      "Obfuscation Unicode Bypass",
		Category:  "evasion",
		DependsOn: []int{7},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ObfuscationBypassCheck(t, exploit.ObfuscationBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	dag.AddNode(&ChainNode{
		ID:        47,
		Name:      "Exec Socket Leak",
		Category:  "disclosure",
		DependsOn: []int{7},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.ExecSocketLeakCheck(t, exploit.ExecSocketConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// === Level 2d: V3 Content/Skill evasion (depends on unicode bypass) ===
	dag.AddNode(&ChainNode{
		ID:        48,
		Name:      "Marker Spoof + Skill Evasion",
		Category:  "evasion",
		DependsOn: []int{33},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.MarkerSpoofCheck(t, exploit.MarkerSpoofConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	// === Level 2e: V3 Log redaction bypass (depends on log disclosure) ===
	dag.AddNode(&ChainNode{
		ID:        49,
		Name:      "Redaction Pattern Bypass",
		Category:  "disclosure",
		DependsOn: []int{15},
		Execute: func(t utils.Target, c ChainConfig) []utils.Finding {
			return exploit.RedactBypassCheck(t, exploit.RedactBypassConfig{Token: c.Token, Timeout: c.Timeout})
		},
	})

	return dag
}

// RunDAGChain executes the full DAG attack chain (v2 replacement for RunFullChain)
func RunDAGChain(target utils.Target, cfg ChainConfig, concurrency int, aggressive bool) []utils.Finding {
	dag := BuildFullDAG(concurrency, aggressive)
	return dag.Execute(target, cfg)
}
