package interactive

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/audit"
	"github.com/coff0xc/lobster-guard/pkg/auth"
	"github.com/coff0xc/lobster-guard/pkg/chain"
	"github.com/coff0xc/lobster-guard/pkg/exploit"
	"github.com/coff0xc/lobster-guard/pkg/recon"
	"github.com/coff0xc/lobster-guard/pkg/report"
	"github.com/coff0xc/lobster-guard/pkg/scanner"
	"github.com/coff0xc/lobster-guard/pkg/utils"
	"github.com/fatih/color"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍ShellState holds the interactive shell session state
type ShellState struct {
	Target      string
	Token       string
	UseTLS      bool
	Timeout     time.Duration
	LastResults []*utils.ScanResult
}

var chainNames = [31]string{
	"Platform fingerprint (zero-auth)",
	"SSRF + cloud metadata",
	"eval()/exec() injection",
	"API key theft",
	"Pairing code brute force",
	"Cron deny list bypass",
	"Prompt injection",
	"RCE reachability",
	"Hook injection",
	"Secret extraction",
	"Config tampering",
	"Direct tool invocation",
	"Session hijack",
	"CORS bypass",
	"Channel injection",
	"Log disclosure",
	"apply_patch escape",
	"WebSocket hijack",
	"Agent injection",
	"OAuth abuse",
	"Responses API exploit",
	"WebSocket protocol fuzz",
	"Agent file injection (persistent prompt backdoor)",
	"Session file overwrite",
	"Exec approval hijack",
	"Talk config secrets",
	"Browser request SSRF",
	"secrets.resolve plaintext extraction",
	"Session transcript theft",
	"Rogue node registration",
	"Full RCE chain (self-approve + node.invoke)",
}

// RunShell starts the interactive REPL loop
func RunShell() {
	state := &ShellState{
		Timeout: 10 * time.Second,
	}

	prompt := color.New(color.FgCyan, color.Bold).Sprint("lobster🦞> ")
	scanner_ := bufio.NewScanner(os.Stdin)

	fmt.Println("LobsterGuard interactive shell. Type 'help' for commands.")

	for {
		fmt.Print(prompt)
		if !scanner_.Scan() {
			break
		}
		line := strings.TrimSpace(scanner_.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		cmd := strings.ToLower(fields[0])

		switch cmd {
		case "exit", "quit":
			fmt.Println("Bye.")
			return

		case "help":
			printHelp()

		case "status":
			printStatus(state)

		case "target":
			if len(fields) < 2 {
				fmt.Println("[!] Usage: target <host:port>")
				continue
			}
			state.Target = fields[1]
			fmt.Printf("[*] Target set: %s\n", state.Target)

		case "token":
			if len(fields) < 2 {
				fmt.Println("[!] Usage: token <value>")
				continue
			}
			state.Token = fields[1]
			fmt.Printf("[*] Token set: %s\n", maskToken(state.Token))

		case "tls":
			if len(fields) < 2 {
				fmt.Println("[!] Usage: tls on|off")
				continue
			}
			switch strings.ToLower(fields[1]) {
			case "on":
				state.UseTLS = true
				fmt.Println("[*] TLS enabled")
			case "off":
				state.UseTLS = false
				fmt.Println("[*] TLS disabled")
			default:
				fmt.Println("[!] Usage: tls on|off")
			}

		case "verify":
			if len(fields) < 2 {
				fmt.Println("[!] Usage: verify on|off")
				continue
			}
			switch strings.ToLower(fields[1]) {
			case "on":
				utils.SkipTLSVerify = false
				fmt.Println("[*] TLS certificate verification enabled (strict)")
			case "off":
				utils.SkipTLSVerify = true
				fmt.Println("[*] TLS certificate verification disabled (insecure)")
			default:
				fmt.Println("[!] Usage: verify on|off")
			}

		case "timeout":
			if len(fields) < 2 {
				fmt.Println("[!] Usage: timeout <seconds>")
				continue
			}
			secs, err := strconv.Atoi(fields[1])
			if err != nil || secs <= 0 {
				fmt.Println("[!] Invalid timeout value")
				continue
			}
			state.Timeout = time.Duration(secs) * time.Second
			fmt.Printf("[*] Timeout set: %ds\n", secs)

		case "chains":
			for i, name := range chainNames {
				fmt.Printf("Chain %2d: %s\n", i, name)
			}

		case "results":
			if len(state.LastResults) == 0 {
				fmt.Println("[*] No results yet. Run a scan first.")
				continue
			}
			report.PrintSummary(state.LastResults)

		case "export":
			if len(fields) < 2 {
				fmt.Println("[!] Usage: export <path>")
				continue
			}
			if len(state.LastResults) == 0 {
				fmt.Println("[*] No results to export.")
				continue
			}
			if err := report.WriteReport(state.LastResults, fields[1]); err != nil {
				fmt.Printf("[!] Export failed: %v\n", err)
			}

		case "scan", "fingerprint", "auth", "recon", "audit", "exploit":
			t, ok := requireTarget(state)
			if !ok {
				continue
			}
			runModule(cmd, t, state)

		case "chain":
			if len(fields) < 2 {
				fmt.Println("[!] Usage: chain <N>")
				continue
			}
			n, err := strconv.Atoi(fields[1])
			if err != nil || n < 0 || n > 30 {
				fmt.Println("[!] Chain number must be 0-30")
				continue
			}
			t, ok := requireTarget(state)
			if !ok {
				continue
			}
			runChain(n, t, state)

		default:
			fmt.Printf("[!] Unknown command: %s (type 'help')\n", cmd)
		}
	}
}

func printHelp() {
	fmt.Println(`Commands:
  target <host:port>   Set target
  token <value>        Set gateway token
  tls on|off           Toggle TLS (HTTPS/WSS)
  verify on|off        Toggle TLS cert verification (default: off)
  timeout <seconds>    Set timeout
  scan                 Full scan pipeline
  fingerprint          Detect OpenClaw
  auth                 Auth checks + brute
  recon                Endpoint + WS enum
  audit                Config audit
  exploit              Full 31-chain attack
  chain <N>            Run specific chain (0-30)
  chains               List all chains
  status               Show current config
  results              Show last results
  export <path>        Export results (JSON or HTML by extension)
  help                 Show this help
  exit                 Quit`)
}

func printStatus(state *ShellState) {
	target := state.Target
	if target == "" {
		target = "(not set)"
	}
	token := "(not set)"
	if state.Token != "" {
		token = maskToken(state.Token)
	}
	tls := "off"
	if state.UseTLS {
		tls = "on"
	}
	verify := "off (insecure)"
	if !utils.SkipTLSVerify {
		verify = "on (strict)"
	}
	fmt.Printf("  Target:  %s\n  Token:   %s\n  TLS:     %s\n  Verify:  %s\n  Timeout: %s\n  Results: %d\n",
		target, token, tls, verify, state.Timeout, len(state.LastResults))
}

func maskToken(t string) string {
	if len(t) <= 6 {
		return "***"
	}
	return t[:3] + "..." + t[len(t)-3:]
}

func requireTarget(state *ShellState) (utils.Target, bool) {
	if state.Target == "" {
		fmt.Println("[!] No target set. Use: target <host:port>")
		return utils.Target{}, false
	}
	t, err := utils.ParseTarget(state.Target)
	if err != nil {
		fmt.Printf("[!] Invalid target: %v\n", err)
		return utils.Target{}, false
	}
	t.UseTLS = state.UseTLS
	return t, true
}

func runModule(cmd string, target utils.Target, state *ShellState) {
	result := utils.NewScanResult(target)
	timeout := state.Timeout

	switch cmd {
	case "fingerprint":
		_, findings := scanner.Fingerprint(target, timeout)
		for _, f := range findings {
			result.Add(f)
		}
	case "auth":
		for _, f := range auth.NoAuthCheck(target, timeout) {
			result.Add(f)
		}
	case "recon":
		_, f1 := recon.VersionDetect(target, timeout)
		for _, f := range f1 {
			result.Add(f)
		}
		_, f2 := recon.EnumEndpoints(target, state.Token, timeout)
		for _, f := range f2 {
			result.Add(f)
		}
		_, f3 := recon.EnumWSMethods(target, state.Token, timeout)
		for _, f := range f3 {
			result.Add(f)
		}
	case "audit":
		for _, f := range audit.RunAudit(target, audit.AuditConfig{Token: state.Token, Timeout: timeout}) {
			result.Add(f)
		}
	case "exploit", "scan":
		cfg := chain.ChainConfig{
			Token:   state.Token,
			Timeout: timeout,
		}
		if cmd == "scan" {
			// Full pipeline: fingerprint first
			fpResult, fpFindings := scanner.Fingerprint(target, timeout)
			for _, f := range fpFindings {
				result.Add(f)
			}
			if !fpResult.IsOpenClaw {
				fmt.Printf("[*] %s is not OpenClaw\n", target.String())
				result.Done()
				state.LastResults = []*utils.ScanResult{result}
				report.PrintSummary(state.LastResults)
				return
			}
			for _, f := range auth.NoAuthCheck(target, timeout) {
				result.Add(f)
			}
		}
		for _, f := range chain.RunFullChain(target, cfg) {
			result.Add(f)
		}
	}

	result.Done()
	state.LastResults = []*utils.ScanResult{result}
	report.PrintSummary(state.LastResults)
}

func runChain(n int, target utils.Target, state *ShellState) {
	result := utils.NewScanResult(target)
	timeout := state.Timeout
	token := state.Token

	fmt.Printf("[*] Running chain %d: %s\n", n, chainNames[n])

	var findings []utils.Finding
	switch n {
	case 0:
		findings = exploit.PlatformFingerprint(target, exploit.PlatformFingerprintConfig{Timeout: timeout})
	case 1:
		findings = exploit.SSRFCheck(target, exploit.SSRFConfig{Token: token, Timeout: timeout})
	case 2:
		findings = exploit.EvalInjectCheck(target, exploit.EvalInjectConfig{Token: token, Timeout: timeout})
	case 3:
		findings = exploit.APIKeyStealCheck(target, exploit.APIKeyStealConfig{Token: token, Timeout: timeout})
	case 4:
		cfg := exploit.DefaultPairingBruteConfig()
		cfg.Token = token
		cfg.Timeout = timeout
		findings = exploit.PairingBruteCheck(target, cfg)
	case 5:
		findings = exploit.CronBypassCheck(target, exploit.CronBypassConfig{Token: token, Timeout: timeout})
	case 6:
		findings = exploit.PromptInjectCheck(target, exploit.PromptInjectConfig{Token: token, Timeout: timeout})
	case 7:
		findings = exploit.RCECheck(target, exploit.RCEConfig{Token: token, Timeout: timeout})
	case 8:
		findings = exploit.HookInjectCheck(target, exploit.HookInjectConfig{Token: token, Timeout: timeout})
	case 9:
		findings = exploit.SecretExtractCheck(target, exploit.SecretExtractConfig{Token: token, Timeout: timeout})
	case 10:
		findings = exploit.ConfigTamperCheck(target, exploit.ConfigTamperConfig{Token: token, Timeout: timeout})
	case 11:
		findings = exploit.ToolsInvokeCheck(target, exploit.ToolsInvokeConfig{Token: token, Timeout: timeout})
	case 12:
		findings = exploit.SessionHijackCheck(target, exploit.SessionHijackConfig{Token: token, Timeout: timeout})
	case 13:
		findings = exploit.CORSBypassCheck(target, exploit.CORSBypassConfig{Token: token, Timeout: timeout})
	case 14:
		findings = exploit.ChannelInjectCheck(target, exploit.ChannelInjectConfig{Token: token, Timeout: timeout})
	case 15:
		findings = exploit.LogDisclosureCheck(target, exploit.LogDisclosureConfig{Token: token, Timeout: timeout})
	case 16:
		findings = exploit.PatchEscapeCheck(target, exploit.PatchEscapeConfig{Token: token, Timeout: timeout})
	case 17:
		findings = exploit.WSHijackCheck(target, exploit.WSHijackConfig{Token: token, Timeout: timeout})
	case 18:
		findings = exploit.AgentInjectCheck(target, exploit.AgentInjectConfig{Token: token, Timeout: timeout})
	case 19:
		findings = exploit.OAuthAbuseCheck(target, exploit.OAuthAbuseConfig{Token: token, Timeout: timeout})
	case 20:
		findings = exploit.ResponsesExploitCheck(target, exploit.ResponsesExploitConfig{Token: token, Timeout: timeout})
	case 21:
		findings = exploit.WSFuzzCheck(target, exploit.WSFuzzConfig{Token: token, Timeout: timeout})
	case 22:
		findings = exploit.AgentFileInjectCheck(target, exploit.AgentFileInjectConfig{Token: token, Timeout: timeout})
	case 23:
		findings = exploit.SessionFileWriteCheck(target, exploit.SessionFileWriteConfig{Token: token, Timeout: timeout})
	case 24:
		findings = exploit.ApprovalHijackCheck(target, exploit.ApprovalHijackConfig{Token: token, Timeout: timeout})
	case 25:
		findings = exploit.TalkSecretsCheck(target, exploit.TalkSecretsConfig{Token: token, Timeout: timeout})
	case 26:
		findings = exploit.BrowserRequestCheck(target, exploit.BrowserRequestConfig{Token: token, Timeout: timeout})
	case 27:
		findings = exploit.SecretsResolveCheck(target, exploit.SecretsResolveConfig{Token: token, Timeout: timeout})
	case 28:
		findings = exploit.TranscriptTheftCheck(target, exploit.TranscriptTheftConfig{Token: token, Timeout: timeout})
	case 29:
		findings = exploit.RogueNodeCheck(target, exploit.RogueNodeConfig{Token: token, Timeout: timeout})
	case 30:
		findings = exploit.FullRCECheck(target, exploit.FullRCEConfig{Token: token, Timeout: timeout})
	}

	for _, f := range findings {
		result.Add(f)
	}
	result.Done()
	state.LastResults = []*utils.ScanResult{result}
	report.PrintSummary(state.LastResults)
}
