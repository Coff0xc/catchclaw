package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coff0xc/lobster-guard/internal/assets"
	"github.com/coff0xc/lobster-guard/pkg/ai"
	"github.com/coff0xc/lobster-guard/pkg/audit"
	"github.com/coff0xc/lobster-guard/pkg/auth"
	"github.com/coff0xc/lobster-guard/pkg/chain"
	"github.com/coff0xc/lobster-guard/pkg/concurrent"
	"github.com/coff0xc/lobster-guard/pkg/cve"
	"github.com/coff0xc/lobster-guard/pkg/discovery"
	"github.com/coff0xc/lobster-guard/pkg/fuzzer"
	"github.com/coff0xc/lobster-guard/pkg/interactive"
	"github.com/coff0xc/lobster-guard/pkg/mcp"
	"github.com/coff0xc/lobster-guard/pkg/recon"
	"github.com/coff0xc/lobster-guard/pkg/report"
	"github.com/coff0xc/lobster-guard/pkg/scanner"
	"github.com/coff0xc/lobster-guard/pkg/tui"
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
	flagAggressive      bool
	flagUltraAggressive bool
	flagDAG             bool
	flagChainID         int
	flagAIAnalyze       bool
	flagWorkers         int
	flagRateLimit       float64
	flagFuzzCategories  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "lobster-guard",
		Short: "OpenClaw 安全评估工具 v4.0.0",
		Long: `LobsterGuard v4.0.0 — OpenClaw/Open-WebUI AI编程平台安全评估工具

功能特性:
  55条 DAG 攻击链 | AI 智能模糊测试 | CVE 漏洞库 | 高并发引擎 | MCP 集成

快速开始:
  lobster-guard scan -t 目标IP:端口                    # 全量扫描
  lobster-guard scan -t 目标IP:端口 -o report.html     # 扫描并生成 HTML 报告
  lobster-guard exploit -t 目标IP:端口 --token xxx     # 仅运行漏洞利用链
  lobster-guard tui                                     # 启动交互式 TUI 面板
  lobster-guard shell                                   # 启动命令行交互 Shell

报告输出 (-o):
  -o result.json    自动输出 JSON 格式
  -o result.html    自动输出 HTML 格式 (根据扩展名自动识别)`,
	}

	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "全量扫描: 指纹识别 + 认证检测 + 爆破 + 信息收集 + 配置审计 + 漏洞利用",
		Example: `  lobster-guard scan -t 10.0.0.5:18789
  lobster-guard scan -t 10.0.0.5:18789 --token abc123
  lobster-guard scan -t 10.0.0.5:18789 -o report.html
  lobster-guard scan -T targets.txt -c 5 --aggressive`,
		RunE:  runScan,
	}
	addCommonFlags(scanCmd)
	addBruteFlags(scanCmd)
	scanCmd.Flags().StringVar(&flagToken, "token", "", "Gateway 认证令牌 (用于已认证的检测项)")
	scanCmd.Flags().StringVar(&flagCallback, "callback", "", "OOB 回调地址 (用于 SSRF 检测)")
	scanCmd.Flags().BoolVar(&flagNoExploit, "no-exploit", false, "跳过漏洞利用验证阶段")
	scanCmd.Flags().BoolVar(&flagAggressive, "aggressive", false, "激进模式: DAG链并发, 最大并发, 无延迟")
	scanCmd.Flags().BoolVar(&flagAIAnalyze, "ai-analyze", false, "使用 AI 分析扫描结果")

	fpCmd := &cobra.Command{Use: "fingerprint", Short: "平台指纹识别: 检测 OpenClaw 实例", RunE: runFingerprint}
	addCommonFlags(fpCmd)

	authCmd := &cobra.Command{Use: "auth", Short: "认证检测: 未授权访问 + 令牌爆破", RunE: runAuth}
	addCommonFlags(authCmd)
	addBruteFlags(authCmd)
	authCmd.Flags().StringVar(&flagToken, "token", "", "已知的 Gateway 认证令牌")

	auditCmd := &cobra.Command{Use: "audit", Short: "配置审计: 安全配置检查 (需要令牌)", RunE: runAudit}
	addCommonFlags(auditCmd)
	auditCmd.Flags().StringVar(&flagToken, "token", "", "Gateway 认证令牌 (必须)")

	reconCmd := &cobra.Command{Use: "recon", Short: "信息收集: 端点枚举 + WS方法枚举 + 版本探测", RunE: runRecon}
	addCommonFlags(reconCmd)
	reconCmd.Flags().StringVar(&flagToken, "token", "", "Gateway 认证令牌 (用于已认证的枚举)")

	exploitCmd := &cobra.Command{
		Use:   "exploit",
		Short: "漏洞利用: 55条 DAG 攻击链 (v4)",
		Example: `  lobster-guard exploit -t 10.0.0.5:18789 --token abc123
  lobster-guard exploit -t 10.0.0.5:18789 --chain-id 7     # 运行单条攻击链
  lobster-guard exploit -t 10.0.0.5:18789 --aggressive      # 激进模式
  lobster-guard exploit -t 10.0.0.5:18789 --ultra-aggressive # 极限模式(200并发)`,
		RunE: runExploit,
	}
	addCommonFlags(exploitCmd)
	exploitCmd.Flags().StringVar(&flagToken, "token", "", "Gateway 认证令牌 (多数检测项需要)")
	exploitCmd.Flags().StringVar(&flagCallback, "callback", "", "OOB 回调地址 (用于 SSRF 检测)")
	exploitCmd.Flags().StringVar(&flagHookToken, "hook-token", "", "Hook 专用令牌")
	exploitCmd.Flags().StringVar(&flagHookPath, "hook-path", "/hooks", "Hook 基础路径")
	exploitCmd.Flags().BoolVar(&flagAggressive, "aggressive", false, "激进模式: 最大并发, 无延迟")
	exploitCmd.Flags().BoolVar(&flagUltraAggressive, "ultra-aggressive", false, "极限模式: 200并发, 无速率限制, 全链执行")
	exploitCmd.Flags().IntVar(&flagWorkers, "workers", 0, "并发引擎 Worker 数量 (0=自动)")
	exploitCmd.Flags().Float64Var(&flagRateLimit, "rate-limit", 0, "每秒最大请求数 (0=不限制)")
	exploitCmd.Flags().BoolVar(&flagDAG, "dag", true, "使用 DAG 依赖图执行攻击链")
	exploitCmd.Flags().IntVar(&flagChainID, "chain-id", -1, "运行单条攻击链 (-1=全部)")
	exploitCmd.Flags().BoolVar(&flagAIAnalyze, "ai-analyze", false, "使用 AI 分析结果 (需要 ANTHROPIC_API_KEY 或 OPENAI_API_KEY)")

	rootCmd.AddCommand(scanCmd, fpCmd, authCmd, auditCmd, reconCmd, exploitCmd)

	// v4: Fuzz command
	fuzzCmd := &cobra.Command{Use: "fuzz", Short: "AI 模糊测试 (XSS/SQL注入/SSRF/命令注入/提示词注入)", RunE: runFuzz}
	addCommonFlags(fuzzCmd)
	fuzzCmd.Flags().StringVar(&flagToken, "token", "", "Gateway 认证令牌")
	fuzzCmd.Flags().StringVar(&flagFuzzCategories, "categories", "", "测试类别 (逗号分隔): xss,sqli,ssrf,cmdi,prompt_inject")
	rootCmd.AddCommand(fuzzCmd)

	// v4: CVE lookup command
	cveCmd := &cobra.Command{Use: "cve", Short: "CVE 漏洞库查询 (OpenClaw/Open-WebUI 相关漏洞)", RunE: runCVE}
	rootCmd.AddCommand(cveCmd)

	// MCP Server command
	mcpCmd := &cobra.Command{
		Use:   "mcp",
		Short: "启动 MCP Server (stdio JSON-RPC, 用于 AI Agent 集成)",
		Run: func(cmd *cobra.Command, args []string) {
			srv := mcp.NewServer()
			if err := srv.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "[MCP] Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	rootCmd.AddCommand(mcpCmd)

	discoverCmd := &cobra.Command{Use: "discover", Short: "资产发现: 通过 Shodan/FOFA 搜索目标", RunE: runDiscover}
	discoverCmd.Flags().StringVar(&flagShodanKey, "shodan-key", "", "Shodan API 密钥")
	discoverCmd.Flags().StringVar(&flagFofaEmail, "fofa-email", "", "FOFA 邮箱")
	discoverCmd.Flags().StringVar(&flagFofaKey, "fofa-key", "", "FOFA API 密钥")
	discoverCmd.Flags().StringVar(&flagDiscQuery, "query", "", "自定义搜索语句")
	discoverCmd.Flags().IntVar(&flagDiscMax, "max-results", 100, "每个来源最大结果数")
	discoverCmd.Flags().IntVar(&flagTimeout, "timeout", 30, "API 超时时间 (秒)")
	discoverCmd.Flags().StringVarP(&flagDiscOut, "output", "o", "", "输出目标文件路径")

	rootCmd.AddCommand(discoverCmd)

	shellCmd := &cobra.Command{
		Use:   "shell",
		Short: "交互式命令行 Shell (类 msfconsole 风格)",
		Run: func(cmd *cobra.Command, args []string) {
			utils.Banner()
			interactive.RunShell()
		},
	}
	rootCmd.AddCommand(shellCmd)

	tuiCmd := &cobra.Command{
		Use:   "tui",
		Short: "交互式 TUI 仪表盘 (实时进度/漏洞表格/日志滚动)",
		Example: `  lobster-guard tui
  lobster-guard tui -t 10.0.0.5:18789 --token abc123 --tls`,
		RunE:  runTUI,
	}
	addCommonFlags(tuiCmd)
	tuiCmd.Flags().StringVar(&flagToken, "token", "", "Gateway 认证令牌")
	rootCmd.AddCommand(tuiCmd)

	extractCmd := &cobra.Command{
		Use:   "extract [目录]",
		Short: "导出内置 Nuclei 模板和规则文件到指定目录",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runExtract,
	}
	rootCmd.AddCommand(extractCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func addCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&flagTarget, "target", "t", "", "目标地址 host:port (例: 1.2.3.4:18789)")
	cmd.Flags().StringVarP(&flagTargets, "targets", "T", "", "目标列表文件，每行一个地址")
	cmd.Flags().IntVar(&flagTimeout, "timeout", 10, "HTTP 超时时间 (秒)")
	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "输出报告路径 (按扩展名自动选择格式: .html→HTML报告, .json→JSON报告)")
	cmd.Flags().BoolVar(&flagTLS, "tls", false, "使用 HTTPS/WSS 加密连接")
	cmd.Flags().IntVarP(&flagConcurrency, "concurrency", "c", 1, "并发扫描目标数")
	cmd.Flags().BoolVar(&flagTLSVerify, "tls-verify", false, "启用严格 TLS 证书验证 (默认跳过)")
}

func addBruteFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&flagWordlist, "wordlist", "w", "", "自定义爆破字典文件路径")
	cmd.Flags().IntVar(&flagDelay, "delay", 500, "爆破请求间隔 (毫秒)")
	cmd.Flags().IntVar(&flagMaxRetry, "max-attempts", 0, "最大爆破次数 (0=不限)")
	cmd.Flags().BoolVar(&flagNoBrute, "no-brute", false, "跳过爆破测试")
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
		if flagTLS {
			t.UseTLS = true
		}
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
			if flagTLS {
				t.UseTLS = true
			}
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
		// Always run exploit chains: zero-auth chains (ClawJacked, CORS, WS hijack,
		// gatewayUrl SSRF, browser upload traversal) work without a token.
		// Token-dependent chains will self-skip when token is empty.
		if !flagNoExploit {
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
			concurrency := flagConcurrency
			if concurrency < 1 {
				concurrency = 5
			}
			if flagUltraAggressive {
				concurrency = 200
			} else if flagAggressive && concurrency < 20 {
				concurrency = 20
			}

			if flagChainID >= 0 {
				dag := chain.BuildFullDAG(concurrency, flagAggressive || flagUltraAggressive)
				findings = dag.ExecuteSingle(target, chainCfg, flagChainID)
			} else if flagUltraAggressive || flagWorkers > 0 {
				// v4: Use concurrent engine for ultra-aggressive or explicit workers
				workers := flagWorkers
				if workers <= 0 {
					workers = concurrency
				}
				engine := concurrent.NewEngine(workers, flagRateLimit)
				engine.Timeout = timeout
				dag := chain.BuildFullDAG(workers, true)
				var tasks []concurrent.ScanTask
				for _, node := range dag.Nodes {
					n := node
					tasks = append(tasks, concurrent.ScanTask{
						ID:       n.ID,
						Name:     n.Name,
						Target:   target,
						Token:    flagToken,
						ChainID:  n.ID,
						Priority: 1,
						Execute: func(t utils.Target, token string) []utils.Finding {
							return n.Execute(t, chainCfg)
						},
					})
				}
				findings = engine.Run(tasks)
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

// --- fuzz: AI-powered fuzzing (v4) ---
func runFuzz(cmd *cobra.Command, args []string) error {
	utils.Banner()
	targets, err := resolveTargets()
	if err != nil {
		return err
	}
	timeout := time.Duration(flagTimeout) * time.Second

	for _, target := range targets {
		analyzer := ai.NewAnalyzer()
		f := fuzzer.NewAIFuzzer(target, flagToken, analyzer)
		f.Timeout = timeout

		var categories []string
		if flagFuzzCategories != "" {
			for _, c := range strings.Split(flagFuzzCategories, ",") {
				c = strings.TrimSpace(c)
				if c != "" {
					categories = append(categories, c)
				}
			}
		}

		results := f.Fuzz(nil, categories)
		findings := fuzzer.Findings(results)

		fmt.Printf("\n[*] Fuzz complete: %d tests, %d vulns found\n", len(results), len(findings))
		for _, finding := range findings {
			fmt.Printf("  [+] %s: %s\n", finding.Severity, finding.Title)
		}
	}
	return nil
}

// --- cve: CVE database lookup (v4) ---
func runCVE(cmd *cobra.Command, args []string) error {
	utils.Banner()
	db := cve.NewDatabase()

	keyword := ""
	if len(args) > 0 {
		keyword = strings.Join(args, " ")
	}

	var results []cve.CVEEntry
	if keyword != "" {
		results = db.Search(keyword)
	} else {
		results = db.All()
	}

	fmt.Printf("\n[*] CVE Database: %d entries\n\n", db.Count())
	for _, e := range results {
		exploit := ""
		if e.ExploitAvailable {
			exploit = " [EXPLOIT]"
		}
		chains := ""
		if len(e.ChainIDs) > 0 {
			chainStrs := make([]string, len(e.ChainIDs))
			for i, id := range e.ChainIDs {
				chainStrs[i] = fmt.Sprintf("#%d", id)
			}
			chains = fmt.Sprintf(" → chains: %s", strings.Join(chainStrs, ","))
		}
		fmt.Printf("  %-18s [%s] CVSS %.1f%s%s\n    %s\n\n",
			e.ID, e.Severity, e.CVSS, exploit, chains,
			utils.Truncate(e.Description, 120))
	}

	summary := db.Summary()
	fmt.Printf("[*] Summary: %v total, %v exploitable\n", summary["total"], summary["exploitable"])
	return nil
}

// --- tui: interactive TUI dashboard ---
func runTUI(cmd *cobra.Command, args []string) error {
	var target utils.Target
	if flagTarget != "" {
		t, err := utils.ParseTarget(flagTarget)
		if err != nil {
			return fmt.Errorf("invalid target: %w", err)
		}
		if flagTLS {
			t.UseTLS = true
		}
		target = t
	}
	if flagToken == "" {
		if envToken := os.Getenv("LOBSTERGUARD_TOKEN"); envToken != "" {
			flagToken = envToken
		}
	}
	timeout := time.Duration(flagTimeout) * time.Second
	return tui.Run(target, flagToken, flagTLS, timeout)
}

func runExtract(cmd *cobra.Command, args []string) error {
	outDir := "."
	if len(args) > 0 {
		outDir = args[0]
	}

	allFiles := assets.List()
	extracted := 0
	for _, fpath := range allFiles {
		data, err := assets.ReadFile(fpath)
		if err != nil {
			return fmt.Errorf("read embedded %s: %w", fpath, err)
		}
		target := filepath.Join(outDir, fpath)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(target), err)
		}
		if err := os.WriteFile(target, data, 0644); err != nil {
			return fmt.Errorf("write %s: %w", target, err)
		}
		extracted++
	}

	// Count by category
	nucleiCount, rulesCount := 0, 0
	for _, f := range allFiles {
		if strings.HasPrefix(f, "nuclei-templates/") {
			nucleiCount++
		} else if strings.HasPrefix(f, "rules/") {
			rulesCount++
		}
	}
	fmt.Printf("[+] Nuclei 模板已导出: %d 个文件 → %s/nuclei-templates/\n", nucleiCount, outDir)
	fmt.Printf("[+] 规则文件已导出: %d 个文件 → %s/rules/\n", rulesCount, outDir)
	fmt.Printf("[*] 共导出 %d 个文件\n", extracted)
	return nil
}
