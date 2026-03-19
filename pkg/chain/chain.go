package chain

import (
	"fmt"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/exploit"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍ChainConfig holds configuration for attack chain orchestration
type ChainConfig struct {
	Token       string
	HookToken   string
	HookPath    string
	CallbackURL string
	Timeout     time.Duration
}

// RunFullChain executes all OpenClaw-specific attack chains in order
func RunFullChain(target utils.Target, cfg ChainConfig) []utils.Finding {
	var all []utils.Finding

	fmt.Printf("\n[*] ═══ OpenClaw Attack Chain Orchestration ═══\n")
	fmt.Printf("[*] Target: %s\n", target.String())

	// Chain 0: Platform fingerprint (zero-auth)
	all = append(all, exploit.PlatformFingerprint(target, exploit.PlatformFingerprintConfig{
		Timeout: cfg.Timeout,
	})...)

	// Chain 1: SSRF with full cloud metadata coverage
	all = append(all, exploit.SSRFCheck(target, exploit.SSRFConfig{
		Token:       cfg.Token,
		Timeout:     cfg.Timeout,
		CallbackURL: cfg.CallbackURL,
	})...)

	// Chain 2: eval()/exec() code injection (Issue #45502)
	all = append(all, exploit.EvalInjectCheck(target, exploit.EvalInjectConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 3: API key theft (Issue #11829)
	all = append(all, exploit.APIKeyStealCheck(target, exploit.APIKeyStealConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 4: DM pairing code brute force (Issue #16458)
	pairingCfg := exploit.DefaultPairingBruteConfig()
	pairingCfg.Token = cfg.Token
	pairingCfg.Timeout = cfg.Timeout
	all = append(all, exploit.PairingBruteCheck(target, pairingCfg)...)

	// Chain 5: Cron deny list bypass + persistence (Issue #46635)
	all = append(all, exploit.CronBypassCheck(target, exploit.CronBypassConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 6: Prompt injection
	all = append(all, exploit.PromptInjectCheck(target, exploit.PromptInjectConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 7: RCE reachability
	all = append(all, exploit.RCECheck(target, exploit.RCEConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 8: Hook injection
	all = append(all, exploit.HookInjectCheck(target, exploit.HookInjectConfig{
		Token:     cfg.Token,
		HookToken: cfg.HookToken,
		HookPath:  cfg.HookPath,
		Timeout:   cfg.Timeout,
	})...)

	// Chain 9: Secret extraction — secrets.list + secrets.get plaintext theft
	all = append(all, exploit.SecretExtractCheck(target, exploit.SecretExtractConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 10: Config tampering — config.set write access probe
	all = append(all, exploit.ConfigTamperCheck(target, exploit.ConfigTamperConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 11: Direct tool invocation — tools.invoke bypasses chat-layer security
	all = append(all, exploit.ToolsInvokeCheck(target, exploit.ToolsInvokeConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 12: Session hijack — sessions.preview IDOR + cross-session injection
	all = append(all, exploit.SessionHijackCheck(target, exploit.SessionHijackConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 13: CORS misconfiguration — active origin reflection probe
	all = append(all, exploit.CORSBypassCheck(target, exploit.CORSBypassConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 14: Channel injection — Mattermost/Slack/Discord unsigned command injection
	all = append(all, exploit.ChannelInjectCheck(target, exploit.ChannelInjectConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 15: Log disclosure — logs.query credential/sensitive data leak
	all = append(all, exploit.LogDisclosureCheck(target, exploit.LogDisclosureConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 16: apply_patch path traversal — write outside workspace
	all = append(all, exploit.PatchEscapeCheck(target, exploit.PatchEscapeConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 17: WebSocket hijack — cross-origin WS upgrade + token replay
	all = append(all, exploit.WSHijackCheck(target, exploit.WSHijackConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 18: Agent injection — agents.create/update backdoor + system prompt leak
	all = append(all, exploit.AgentInjectCheck(target, exploit.AgentInjectConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 19: OAuth abuse — Slack OAuth redirect hijack + state fixation
	all = append(all, exploit.OAuthAbuseCheck(target, exploit.OAuthAbuseConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 20: Responses API exploit — /v1/responses auth bypass + tool injection
	all = append(all, exploit.ResponsesExploitCheck(target, exploit.ResponsesExploitConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 21: WebSocket protocol fuzzing — malformed JSON-RPC + method injection
	all = append(all, exploit.WSFuzzCheck(target, exploit.WSFuzzConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 22: Agent file injection — persistent prompt backdoor via agents.files.set
	all = append(all, exploit.AgentFileInjectCheck(target, exploit.AgentFileInjectConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 23: Session file overwrite — arbitrary file write via sessions.patch + sessions.compact
	all = append(all, exploit.SessionFileWriteCheck(target, exploit.SessionFileWriteConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 24: Exec approval hijack — prefix ID matching + policy tamper
	all = append(all, exploit.ApprovalHijackCheck(target, exploit.ApprovalHijackConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 25: Talk config secrets — API key exfiltration via talk.config(includeSecrets)
	all = append(all, exploit.TalkSecretsCheck(target, exploit.TalkSecretsConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 26: Browser request SSRF — internal dispatch via browser.request + browser.navigate
	all = append(all, exploit.BrowserRequestCheck(target, exploit.BrowserRequestConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 27: secrets.resolve plaintext extraction — internal secret injection API
	all = append(all, exploit.SecretsResolveCheck(target, exploit.SecretsResolveConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 28: Session transcript theft — unredacted conversation history + tool outputs
	all = append(all, exploit.TranscriptTheftCheck(target, exploit.TranscriptTheftConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 29: Rogue node registration — self-approved pairing to intercept commands
	all = append(all, exploit.RogueNodeCheck(target, exploit.RogueNodeConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 30: Full RCE chain — nodes.list → exec.approval.request → self-approve → node.invoke system.run
	all = append(all, exploit.FullRCECheck(target, exploit.FullRCEConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 56: ClawJacked token theft (CVE-2026-25253)
	all = append(all, exploit.ClawJackedCheck(target, exploit.WSHijackConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 57: GatewayUrl override SSRF (CVE-2026-26322)
	all = append(all, exploit.GatewayURLSSRFCheck(target, exploit.GatewayURLSSRFConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 58: Browser upload path traversal (CVE-2026-26329)
	all = append(all, exploit.BrowserUploadTraversalCheck(target, exploit.BrowserUploadTraversalConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 59: macOS keychain command injection (CVE-2026-27487)
	all = append(all, exploit.KeychainCmdInjectCheck(target, exploit.KeychainCmdInjectConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	// Chain 60: Cron webhook SSRF (CVE-2026-27488)
	all = append(all, exploit.CronWebhookSSRFCheck(target, exploit.CronWebhookSSRFConfig{
		Token:   cfg.Token,
		Timeout: cfg.Timeout,
	})...)

	fmt.Printf("\n[*] ═══ Attack chain complete: %d findings ═══\n", len(all))
	return all
}
