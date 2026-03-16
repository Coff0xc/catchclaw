package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/ai"
	"github.com/coff0xc/lobster-guard/pkg/audit"
	"github.com/coff0xc/lobster-guard/pkg/auth"
	"github.com/coff0xc/lobster-guard/pkg/chain"
	"github.com/coff0xc/lobster-guard/pkg/discovery"
	"github.com/coff0xc/lobster-guard/pkg/interactive"
	"github.com/coff0xc/lobster-guard/pkg/mcp"
	"github.com/coff0xc/lobster-guard/pkg/recon"
	"github.com/coff0xc/lobster-guard/pkg/report"
	"github.com/coff0xc/lobster-guard/pkg/scanner"
	"github.com/coff0xc/lobster-guard/pkg/utils"
	"github.com/spf13/cobra"
)

var (
	flagTarget    string
	flagTargets   string
	flagTimeout   int
	flagOutput    string
	flagWordlist  string
	flagDelay     int
	flagMaxRetry  int
	flagNoBrute   bool
	flagTLS       bool
	flagToken     string
	flagCallback  string
	flagHookToken string
	flagHookPath  string
	flagNoExploit    bool
	flagConcurrency  int
	flagTLSVerify    bool
	flagShodanKey string
	flagFofaEmail string
	flagFofaKey   string
	flagDiscQuery string
	flagDiscMax   int
	flagDiscOut    string
	flagAggressive bool
	flagDAG        bool
	flagChainID    int
	flagAIAnalyze  bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "lobster-guard",
		Short: "OpenClaw Security Assessment Tool",
		Long:  "LobsterGuard — automated security scanner for public OpenClaw instances",
	}

	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Full scan: fingerprint + auth + brute + recon + audit + exploit",
		RunE:  runScan,
	}
	addCommonFlags(scanCmd)
	addBruteFlags(scanCmd)
	scanCmd.Flags().StringVar(&flagToken, "token", "", "Known Gateway token for authenticated checks")
	scanCmd.Flags().StringVar(&flagCallback, "callback", "", "OOB callback URL for SSRF detection")
	scanCmd.Flags().BoolVar(&flagNoExploit, "no-exploit", false, "Skip exploit/vuln verification phase")
	scanCmd.Flags().BoolVar(&flagAggressive, "aggressive", false, "Aggressive mode: DAG chains, max concurrency, no delays")
	scanCmd.Flags().BoolVar(&flagAIAnalyze, "ai-analyze", false, "Use AI to analyze results")

	fpCmd := &cobra.Command{Use: "fingerprint", Short: "Detect OpenClaw instances", RunE: runFingerprint}
	addCommonFlags(fpCmd)

	authCmd := &cobra.Command{Use: "auth", Short: "Auth test: no-auth + brute force", RunE: runAuth}
	addCommonFlags(authCmd)
	addBruteFlags(authCmd)
	authCmd.Flags().StringVar(&flagToken, "token", "", "Known Gateway token")

	auditCmd := &cobra.Command{Use: "audit", Short: "Config audit (needs token)", RunE: runAudit}
	addCommonFlags(auditCmd)
	auditCmd.Flags().StringVar(&flagToken, "token", "", "Gateway token (required)")

	reconCmd := &cobra.Command{Use: "recon", Short: "Endpoint + WS method enum + version detect", RunE: runRecon}
	addCommonFlags(reconCmd)
	reconCmd.Flags().StringVar(&flagToken, "token", "", "Gateway token for authenticated enum")

	exploitCmd := &cobra.Command{Use: "exploit", Short: "49-chain OpenClaw attack suite (DAG-based v3)", RunE: runExploit}
	addCommonFlags(exploitCmd)
	exploitCmd.Flags().StringVar(&flagToken, "token", "", "Gateway token (required for most tests)")
	exploitCmd.Flags().StringVar(&flagCallback, "callback", "", "OOB callback URL for SSRF detection")
	exploitCmd.Flags().StringVar(&flagHookToken, "hook-token", "", "Hook-specific token")
	exploitCmd.Flags().StringVar(&flagHookPath, "hook-path", "/hooks", "Hook base path")
	exploitCmd.Flags().BoolVar(&flagAggressive, "aggressive", false, "Aggressive mode: max concurrency, no delays")
	exploitCmd.Flags().BoolVar(&flagDAG, "dag", true, "Use DAG-based chain execution (v2)")
	exploitCmd.Flags().IntVar(&flagChainID, "chain-id", -1, "Run single chain by ID (-1 = all)")
	exploitCmd.Flags().BoolVar(&flagAIAnalyze, "ai-analyze", false, "Use AI to analyze results (requires ANTHROPIC_API_KEY or OPENAI_API_KEY)")

	rootCmd.AddCommand(scanCmd, fpCmd, authCmd, auditCmd, reconCmd, exploitCmd)

	// MCP Server command
	mcpCmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start MCP Server (stdio JSON-RPC) for AI agent integration",
		Run: func(cmd *cobra.Command, args []string) {
			srv := mcp.NewServer()
			if err := srv.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "[MCP] Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	rootCmd.AddCommand(mcpCmd)

	discoverCmd := &cobra.Command{Use: "discover", Short: "Asset discovery via Shodan/FOFA", RunE: runDiscover}
	discoverCmd.Flags().StringVar(&flagShodanKey, "shodan-key", "", "Shodan API key")
	discoverCmd.Flags().StringVar(&flagFofaEmail, "fofa-email", "", "FOFA email")
	discoverCmd.Flags().StringVar(&flagFofaKey, "fofa-key", "", "FOFA API key")
	discoverCmd.Flags().StringVar(&flagDiscQuery, "query", "", "Custom search query")
	discoverCmd.Flags().IntVar(&flagDiscMax, "max-results", 100, "Max results per source")
	discoverCmd.Flags().IntVar(&flagTimeout, "timeout", 30, "API timeout in seconds")
	discoverCmd.Flags().StringVarP(&flagDiscOut, "output", "o", "", "Output targets file path")

	rootCmd.AddCommand(discoverCmd)

	shellCmd := &cobra.Command{
		Use:   "shell",
		Short: "Interactive shell (msfconsole-style)",
		Run: func(cmd *cobra.Command, args []string) {
			utils.Banner()
			interactive.RunShell()
		},
	}
	rootCmd.AddCommand(shellCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func addCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&flagTarget, "target", "t", "", "Target host:port (e.g. 1.2.3.4:18789)")
	cmd.Flags().StringVarP(&flagTargets, "targets", "T", "", "File with targets, one per line")
	cmd.Flags().IntVar(&flagTimeout, "timeout", 10, "HTTP timeout in seconds")
	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Output JSON report path")
	cmd.Flags().BoolVar(&flagTLS, "tls", false, "Use HTTPS/WSS")
	cmd.Flags().IntVarP(&flagConcurrency, "concurrency", "c", 1, "Number of concurrent target scans")
	cmd.Flags().BoolVar(&flagTLSVerify, "tls-verify", false, "Enable strict TLS certificate verification (default: skip)")
}

func addBruteFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&flagWordlist, "wordlist", "w", "", "Custom wordlist for brute force")
	cmd.Flags().IntVar(&flagDelay, "delay", 500, "Delay between brute attempts (ms)")
	cmd.Flags().IntVar(&flagMaxRetry, "max-attempts", 0, "Max brute force attempts (0=unlimited)")
	cmd.Flags().BoolVar(&flagNoBrute, "no-brute", false, "Skip brute force")
}

func resolveTargets() ([]utils.Target, error) {
	// Apply TLS verification setting
	if flagTLSVerify {
		utils.SkipTLSVerify = false
	}
	// Resolve token from env if not provided via flag
	if flagToken == "" {
		if envToken := os.Getenv("LOBSTERGUARD_TOKEN"); envToken != "" {
			flagToken = envToken
		}
	}
	var targets []utils.Target
	if flagTarget != "" {
		t, err := utils.ParseTarget(flagTarget)
		if err != nil {
			return nil, fmt.Errorf("invalid target: %w", err)
		}
		t.UseTLS = flagTLS
		targets = append(targets, t)
	}
	if flagTargets != "" {
		f, err := os.Open(flagTargets)
		if err != nil {
			return nil, fmt.Errorf("open targets file: %w", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			t, err := utils.ParseTarget(line)
			if err != nil {
				fmt.Printf("[!] Skipping invalid target: %s\n", line)
				continue
			}
			t.UseTLS = flagTLS
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets specified. Use -t or -T")
	}
	return targets, nil
}

func outputResults(results []*utils.ScanResult) error {
	report.PrintSummary(results)
	if flagOutput != "" {
		return report.WriteReport(results, flagOutput)
	}
	return nil
}

func makeBruteConfig() auth.BruteConfig {
	cfg := auth.DefaultBruteConfig()
	cfg.Delay = time.Duration(flagDelay) * time.Millisecond
	cfg.MaxAttempts = flagMaxRetry
	if flagWordlist != "" {
		cfg.Wordlist = flagWordlist
	}
	return cfg
}

func runConcurrent(targets []utils.Target, worker func(utils.Target) *utils.ScanResult) []*utils.ScanResult {
	if flagConcurrency <= 1 {
		var results []*utils.ScanResult
		for _, t := range targets {
			results = append(results, worker(t))
		}
		return results
	}

	var (
		results []*utils.ScanResult
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, flagConcurrency)
	)

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(target utils.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			r := worker(target)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	return results
}

// --- scan: full pipeline ---
func runScan(cmd *cobra.Command, args []string) error {
	utils.Banner()
	targets, err := resolveTargets()
	if err != nil {
		return err
	}
	timeout := time.Duration(flagTimeout) * time.Second

	results := runConcurrent(targets, func(target utils.Target) *utils.ScanResult {
		result := utils.NewScanResult(target)

		// 1. Fingerprint
		fpResult, fpFindings := scanner.Fingerprint(target, timeout)
		for _, f := range fpFindings {
			result.Add(f)
		}
		if !fpResult.IsOpenClaw {
			fmt.Printf("\n[*] %s is not OpenClaw, skipping\n", target.String())
			result.Done()
			return result
		}

		// 2. No-auth check
		for _, f := range auth.NoAuthCheck(target, timeout) {
			result.Add(f)
		}

		// 3. Brute force
		activeToken := flagToken
		if !flagNoBrute && fpResult.AuthMode != "none" {
			cfg := makeBruteConfig()
			cfg.Timeout = timeout
			bruteResult, bruteFindings := auth.TokenBrute(target, cfg)
			for _, f := range bruteFindings {
				result.Add(f)
			}
			if bruteResult != nil && bruteResult.Found && bruteResult.Token != "" {
				activeToken = bruteResult.Token
			}
		}

		// 4. Recon
		for _, f := range reconAll(target, activeToken, timeout) {
			result.Add(f)
		}

		// 5. Config audit
		if activeToken != "" {
			for _, f := range audit.RunAudit(target, audit.AuditConfig{Token: activeToken, Timeout: timeout}) {
				result.Add(f)
			}
		}

		// 6. Exploit verification — full OpenClaw attack chain
		if !flagNoExploit && (activeToken != "" || fpResult.AuthMode == "none") {
			chainCfg := chain.ChainConfig{
				Token:       activeToken,
				HookToken:   flagHookToken,
				HookPath:    flagHookPath,
				CallbackURL: flagCallback,
				Timeout:     timeout,
			}
			var exploitFindings []utils.Finding
			if flagAggressive {
				exploitFindings = chain.RunDAGChain(target, chainCfg, 20, true)
			} else {
				exploitFindings = chain.RunFullChain(target, chainCfg)
			}
			for _, f := range exploitFindings {
				result.Add(f)
			}

			// AI analysis
			if flagAIAnalyze && len(exploitFindings) > 0 {
				analyzer := ai.NewAnalyzer()
				analysis, _ := analyzer.AnalyzeFindings(exploitFindings, "triage")
				if analysis != nil {
					fmt.Printf("\n[AI] Risk: %d/100 | %s\n", analysis.RiskScore, analysis.Summary)
				}
			}
		}

		result.Done()
		return result
	})
	return outputResults(results)
}

// --- fingerprint only ---
func runFingerprint(cmd *cobra.Command, args []string) error {
	utils.Banner()
	targets, err := resolveTargets()
	if err != nil {
		return err
	}
	timeout := time.Duration(flagTimeout) * time.Second
	var results []*utils.ScanResult
	for _, target := range targets {
		result := utils.NewScanResult(target)
		_, findings := scanner.Fingerprint(target, timeout)
		for _, f := range findings {
			result.Add(f)
		}
		result.Done()
		results = append(results, result)
	}
	return outputResults(results)
}

// --- auth only ---
func runAuth(cmd *cobra.Command, args []string) error {
	utils.Banner()
	targets, err := resolveTargets()
	if err != nil {
		return err
	}
	timeout := time.Duration(flagTimeout) * time.Second
	var results []*utils.ScanResult
	for _, target := range targets {
		result := utils.NewScanResult(target)
		for _, f := range auth.NoAuthCheck(target, timeout) {
			result.Add(f)
		}
		if !flagNoBrute {
			cfg := makeBruteConfig()
			cfg.Timeout = timeout
			_, findings := auth.TokenBrute(target, cfg)
			for _, f := range findings {
				result.Add(f)
			}
		}
		result.Done()
		results = append(results, result)
	}
	return outputResults(results)
}

// --- audit only ---
func runAudit(cmd *cobra.Command, args []string) error {
	utils.Banner()
	targets, err := resolveTargets()
	if err != nil {
		return err
	}
	timeout := time.Duration(flagTimeout) * time.Second
	var results []*utils.ScanResult
	for _, target := range targets {
		result := utils.NewScanResult(target)
		for _, f := range audit.RunAudit(target, audit.AuditConfig{Token: flagToken, Timeout: timeout}) {
			result.Add(f)
		}
		result.Done()
		results = append(results, result)
	}
	return outputResults(results)
}

// --- recon only ---
func runRecon(cmd *cobra.Command, args []string) error {
	utils.Banner()
	targets, err := resolveTargets()
	if err != nil {
		return err
	}
	timeout := time.Duration(flagTimeout) * time.Second
	var results []*utils.ScanResult
	for _, target := range targets {
		result := utils.NewScanResult(target)
		for _, f := range reconAll(target, flagToken, timeout) {
			result.Add(f)
		}
		result.Done()
		results = append(results, result)
	}
	return outputResults(results)
}

func reconAll(target utils.Target, token string, timeout time.Duration) []utils.Finding {
	var all []utils.Finding
	_, f1 := recon.VersionDetect(target, timeout)
	all = append(all, f1...)
	_, f2 := recon.EnumEndpoints(target, token, timeout)
	all = append(all, f2...)
	_, f3 := recon.EnumWSMethods(target, token, timeout)
	all = append(all, f3...)
	return all
}

// --- exploit only (full OpenClaw attack chain — v2 DAG-based) ---
func runExploit(cmd *cobra.Command, args []string) error {
	utils.Banner()
	targets, err := resolveTargets()
	if err != nil {
		return err
	}
	timeout := time.Duration(flagTimeout) * time.Second

	results := runConcurrent(targets, func(target utils.Target) *utils.ScanResult {
		result := utils.NewScanResult(target)
		chainCfg := chain.ChainConfig{
			Token:       flagToken,
			HookToken:   flagHookToken,
			HookPath:    flagHookPath,
			CallbackURL: flagCallback,
			Timeout:     timeout,
		}

		var findings []utils.Finding
		if flagDAG {
			// v2: DAG-based execution
			concurrency := flagConcurrency
			if concurrency < 1 {
				concurrency = 5
			}
			if flagChainID >= 0 {
				// Single chain execution
				dag := chain.BuildFullDAG(concurrency, flagAggressive)
				findings = dag.ExecuteSingle(target, chainCfg, flagChainID)
			} else {
				findings = chain.RunDAGChain(target, chainCfg, concurrency, flagAggressive)
			}
		} else {
			// v1: linear execution (legacy)
			findings = chain.RunFullChain(target, chainCfg)
		}

		for _, f := range findings {
			result.Add(f)
		}
		result.Done()

		// AI analysis if requested
		if flagAIAnalyze && len(findings) > 0 {
			analyzer := ai.NewAnalyzer()
			if analyzer.Available() {
				fmt.Printf("\n[AI] Analyzing %d findings...\n", len(findings))
			}
			analysis, err := analyzer.AnalyzeFindings(findings, "attack-path")
			if err == nil && analysis != nil {
				fmt.Printf("\n[AI] Risk Score: %d/100\n", analysis.RiskScore)
				fmt.Printf("[AI] Summary: %s\n", analysis.Summary)
				for i, path := range analysis.CriticalPaths {
					fmt.Printf("[AI] Critical Path %d: %s\n", i+1, path)
				}
				for i, rec := range analysis.Recommendations {
					fmt.Printf("[AI] Recommendation %d: %s\n", i+1, rec)
				}
			}
		}

		return result
	})
	return outputResults(results)
}

// --- discover: Shodan/FOFA asset discovery ---
func runDiscover(cmd *cobra.Command, args []string) error {
	utils.Banner()
	if flagShodanKey == "" && (flagFofaEmail == "" || flagFofaKey == "") {
		return fmt.Errorf("at least one source required: --shodan-key or --fofa-email + --fofa-key")
	}
	cfg := discovery.DiscoveryConfig{
		ShodanKey:  flagShodanKey,
		FofaEmail:  flagFofaEmail,
		FofaKey:    flagFofaKey,
		Query:      flagDiscQuery,
		MaxResults: flagDiscMax,
		Timeout:    time.Duration(flagTimeout) * time.Second,
	}
	targets, err := discovery.Discover(cfg)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println("[*] No targets discovered")
		return nil
	}
	for _, t := range targets {
		fmt.Printf("  %s\n", t.String())
	}
	if flagDiscOut != "" {
		if err := discovery.WriteTargets(targets, flagDiscOut); err != nil {
			return err
		}
		fmt.Printf("\n[*] Targets saved to %s — use with: lobster-guard scan -T %s\n", flagDiscOut, flagDiscOut)
	}
	return nil
}
