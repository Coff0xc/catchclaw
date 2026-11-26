package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Coff0xc/catchclaw/go/internal/config"
	"github.com/Coff0xc/catchclaw/go/internal/core"
	"github.com/Coff0xc/catchclaw/go/internal/exploit"
	"github.com/Coff0xc/catchclaw/go/internal/mcpserver"
	"github.com/Coff0xc/catchclaw/go/internal/nuclei"
	"github.com/Coff0xc/catchclaw/go/internal/osint"
	"github.com/Coff0xc/catchclaw/go/internal/report"
	"github.com/Coff0xc/catchclaw/go/internal/scan"
)

const Version = "6.0.0"

func Banner() {
	art := `
     ╔═╗╔═╗╔╦╗╔═╗╦ ╦╔═╗╦  ╔═╗╦ ╦
     ║  ╠═╣ ║ ║  ╠═╣║  ║  ╠═╣║║║
     ╚═╝╩ ╩ ╩ ╚═╝╩ ╩╚═╝╩═╝╩ ╩╚╩╝
`
	fmt.Print("\033[31;1m" + art + "\033[0m")
	fmt.Printf("    \033[31;1mCatchClaw\033[0m v%s — Authorized AI/LLM platform security assessment (Go)\n", Version)
	fmt.Printf("    Written authorization required worldwide. Unauthorized use is illegal. See LEGAL.md\n\n")
}

func Run() {
	if len(os.Args) < 2 {
		Banner()
		printUsage()
		os.Exit(1)
	}

	if os.Args[1] == "mcp" {
		protoOut := os.Stdout
		os.Stdout = os.Stderr
		runMCPWithOutput(os.Args[2:], protoOut)
		return
	}

	Banner()

	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "exploit":
		runExploit(os.Args[2:])
	case "chain":
		runChain(os.Args[2:])
	case "list":
		exploit.PrintModules()
	case "config":
		runConfig(os.Args[2:])
	case "discover":
		runDiscover(os.Args[2:])
	case "nuclei":
		runNuclei(os.Args[2:])
	case "osint":
		runOsint(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("CatchClaw v%s (Go)\n", Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`Usage: catchclaw <COMMAND> [FLAGS]

Authorized testing only. Prior written authorization required for every target.
Unauthorized access is illegal in every applicable jurisdiction. You assume all legal risk.
See LEGAL.md and LICENSE. This is not legal advice.

Commands:
  scan       Full security scan (DAG orchestrated)
  exploit    Run specific exploit chains
  chain      Run multi-stage attack chains only (state-passing)
  discover   Port scan and platform fingerprinting
  nuclei     Run Nuclei templates
  osint      Search Shodan / FOFA / Hunter for exposed AI platforms
  list       List all registered exploit modules
  config     Show current configuration
  version    Show version

Scan Flags:
  -t, --target <HOST:PORT>     Target address
      --targets <SPEC>         Multi-target: comma,CIDR,IP range
  -f, --targets-file <FILE>    Target file (one per line)
      --token <TOKEN>          Auth token
      --timeout <SECS>         Request timeout (default 10)
  -o, --output <FILE>          Report output path
      --format <FMT>           Output: json | html | markdown (default json)
      --concurrency <N>        Max concurrency (default 10)
      --tls                    Use HTTPS/WSS
      --callback <URL>         SSRF callback URL
      --profile <NAME>         Scan profile from config
      --severity-filter <SEV>  Filter: critical,high,medium,low,info
      --dry-run                Preview execution plan
      --config <FILE>          Config file path
      --platform <PLATFORM>    Target platform

Exploit Flags:
  -t, --target <HOST:PORT>     Target address
      --token <TOKEN>          Auth token
      --chain-id <ID>          Run single chain node
      --concurrency <N>        Max concurrency (default 10)
      --tls                    Use HTTPS/WSS

Discover Flags:
  -t, --target <HOST>          Target host
      --ports <PORTS>          Comma-separated ports (default: common)
      --timeout <SECS>         Timeout (default 5)

Nuclei Flags:
  -t, --target <URL>           Target URL
      --templates <DIR>        Templates directory (default: ./nuclei-templates)
      --list                   List loaded templates

OSINT Flags:
      --engine <NAME>          shodan | fofa | hunter
      --query <DORK>           Raw engine query
      --platform <NAME>        Use built-in dork for an AI platform
      --size <N>               Max results (default/max 100)
      --json                   JSON output
      --list-dorks             List built-in platform dorks
  Env keys: SHODAN_API_KEY, FOFA_EMAIL + FOFA_KEY, HUNTER_API_KEY
`)
}

type scanFlags struct {
	target         string
	targets        string
	targetsFile    string
	token          string
	timeout        int
	output         string
	format         string
	concurrency    int
	tls            bool
	callback       string
	profile        string
	severityFilter string
	dryRun         bool
	configFile     string
	platform       string
}

func parseScanFlags(args []string) *scanFlags {
	f := &scanFlags{}
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	fs.StringVar(&f.target, "t", "", "Target host:port")
	fs.StringVar(&f.target, "target", "", "Target host:port")
	fs.StringVar(&f.targets, "targets", "", "Multi-target spec")
	fs.StringVar(&f.targetsFile, "f", "", "Target file")
	fs.StringVar(&f.targetsFile, "targets-file", "", "Target file")
	fs.StringVar(&f.token, "token", "", "Auth token")
	fs.IntVar(&f.timeout, "timeout", 0, "Timeout seconds")
	fs.StringVar(&f.output, "o", "", "Output file")
	fs.StringVar(&f.output, "output", "", "Output file")
	fs.StringVar(&f.format, "format", "json", "Output format")
	fs.IntVar(&f.concurrency, "concurrency", 0, "Concurrency")
	fs.BoolVar(&f.tls, "tls", false, "Use TLS")
	fs.StringVar(&f.callback, "callback", "", "SSRF callback URL")
	fs.StringVar(&f.profile, "profile", "", "Scan profile")
	fs.StringVar(&f.severityFilter, "severity-filter", "", "Severity filter")
	fs.BoolVar(&f.dryRun, "dry-run", false, "Dry run")
	fs.StringVar(&f.configFile, "config", "", "Config file")
	fs.StringVar(&f.platform, "platform", "", "Target platform")
	fs.Parse(args)
	return f
}

func runScan(args []string) {
	f := parseScanFlags(args)

	fileCfg := config.LoadDefault()
	if f.configFile != "" {
		if cfg, err := config.LoadFile(f.configFile); err == nil {
			fileCfg = cfg
			fmt.Printf("\033[32m[+]\033[0m Loaded config from %s\n", f.configFile)
		}
	}

	if f.profile != "" {
		if err := fileCfg.ApplyProfile(f.profile); err != nil {
			fmt.Printf("\033[31m[!]\033[0m %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\033[32m[+]\033[0m Using profile: %s\n", f.profile)
	}

	level := config.LogInfo
	cfg := fileCfg.Merge(f.token, 0, 0, f.tls, f.callback, level)
	if f.timeout > 0 {
		cfg.Timeout = 0
		cfg.Timeout = time.Duration(f.timeout) * time.Second
	}
	if f.concurrency > 0 {
		cfg.Concurrency = f.concurrency
	}

	var allTargets []core.Target
	if f.target != "" {
		allTargets = append(allTargets, core.ParseTargets(f.target, f.tls)...)
	}
	if f.targets != "" {
		allTargets = append(allTargets, core.ParseTargets(f.targets, f.tls)...)
	}
	if f.targetsFile != "" {
		if targets, err := core.ParseTargetsFile(f.targetsFile, f.tls); err == nil {
			allTargets = append(allTargets, targets...)
		}
	}

	if len(allTargets) == 0 {
		fmt.Println("\033[31m[!]\033[0m No targets specified. Use -t, --targets, or -f")
		os.Exit(1)
	}

	if f.token != "" {
		for i := range allTargets {
			allTargets[i].Token = f.token
		}
	}

	if f.platform != "" {
		p := parsePlatform(f.platform)
		for i := range allTargets {
			allTargets[i].Platform = p
		}
	}

	printScanConfig(cfg, allTargets)

	if f.dryRun {
		printDryRun()
		return
	}

	if len(allTargets) == 1 {
		t := allTargets[0]
		result := scan.RunFullScan(t, cfg)

		if f.severityFilter != "" {
			filterFindings(result, f.severityFilter)
		}

		if f.output != "" {
			writeReport(result, f.output, f.format)
		}
	} else {
		results := scan.RunMultiScan(allTargets, cfg)
		if f.output != "" {
			if err := report.WriteJSONMulti(results, f.output); err != nil {
				fmt.Printf("\033[31m[!]\033[0m Failed to write report: %v\n", err)
			} else {
				fmt.Printf("\n\033[32m[+]\033[0m Report saved to %s\n", f.output)
			}
		}
	}
}

func parsePlatform(s string) core.Platform {
	switch strings.ToLower(s) {
	case "openclaw", "open-webui", "openwebui":
		return core.PlatformOpenClaw
	case "dify":
		return core.PlatformDify
	case "fastgpt":
		return core.PlatformFastGPT
	case "lobechat":
		return core.PlatformLobeChat
	case "nextchat", "chatgpt-next-web":
		return core.PlatformNextChat
	case "anythingllm":
		return core.PlatformAnythingLLM
	case "flowise":
		return core.PlatformFlowise
	case "ragflow":
		return core.PlatformRagFlow
	case "librechat":
		return core.PlatformLibreChat
	case "langflow":
		return core.PlatformLangflow
	case "litellm":
		return core.PlatformLiteLLM
	case "ollama":
		return core.PlatformOllama
	case "vllm":
		return core.PlatformVLLM
	case "ray":
		return core.PlatformRay
	case "mlflow":
		return core.PlatformMLflow
	case "gradio":
		return core.PlatformGradio
	case "comfyui", "comfy":
		return core.PlatformComfyUI
	case "dbgpt", "db-gpt":
		return core.PlatformDBGPT
	case "chromadb", "chroma":
		return core.PlatformChromaDB
	case "qdrant":
		return core.PlatformQdrant
	case "weaviate":
		return core.PlatformWeaviate
	case "milvus":
		return core.PlatformMilvus
	case "localai", "local-ai":
		return core.PlatformLocalAI
	case "xinference":
		return core.PlatformXinference
	case "jupyter", "notebook":
		return core.PlatformJupyter
	default:
		return core.PlatformUnknown
	}
}

func printScanConfig(cfg *config.Config, targets []core.Target) {
	fmt.Printf("\033[36m%s\033[0m\n", "┌─────────────────────────────────────────────┐")
	fmt.Printf("\033[36m│\033[0m %-43s \033[36m│\033[0m\n", fmt.Sprintf("Targets: %d", len(targets)))
	fmt.Printf("\033[36m│\033[0m %-43s \033[36m│\033[0m\n", fmt.Sprintf("Timeout: %v", cfg.Timeout))
	fmt.Printf("\033[36m│\033[0m %-43s \033[36m│\033[0m\n", fmt.Sprintf("Concurrency: %d", cfg.Concurrency))
	fmt.Printf("\033[36m│\033[0m %-43s \033[36m│\033[0m\n", fmt.Sprintf("Aggressive: %v", cfg.Aggressive))
	if cfg.HasProxy() {
		fmt.Printf("\033[36m│\033[0m %-43s \033[36m│\033[0m\n", fmt.Sprintf("Proxy: %s", cfg.PrimaryProxy()))
	}
	fmt.Printf("\033[36m%s\033[0m\n", "└─────────────────────────────────────────────┘")
}

func printDryRun() {
	fmt.Printf("\n\033[36m[*]\033[0m Dry-run: DAG execution plan\n\n")
	scanner := scan.NewScanner(config.Default())
	dag := scanner.BuildDAGForDryRun()
	levels := dag.TopologicalLevels()
	nodes := dag.Nodes()

	phaseNames := []string{"Recon", "Initial Access", "Credential Access", "Execution", "Persistence", "Exfiltration"}
	for i, level := range levels {
		phase := "Advanced"
		if i < len(phaseNames) {
			phase = phaseNames[i]
		}
		fmt.Printf("  \033[36m▸\033[0m Level %d: %s (%d nodes)\n", i, phase, len(level))
		for _, idx := range level {
			if idx < len(nodes) {
				fmt.Printf("    \033[37m·\033[0m #%-3d %s\n", nodes[idx].ID, nodes[idx].Name)
			}
		}
	}
	fmt.Printf("\n\033[33m[*]\033[0m No scan performed (--dry-run)\n")
}

func filterFindings(result *core.ScanResult, filter string) {
	allowed := make(map[core.Severity]bool)
	for _, s := range strings.Split(filter, ",") {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "critical":
			allowed[core.Critical] = true
		case "high":
			allowed[core.High] = true
		case "medium":
			allowed[core.Medium] = true
		case "low":
			allowed[core.Low] = true
		case "info":
			allowed[core.Info] = true
		}
	}
	var filtered []core.Finding
	for _, f := range result.Findings {
		if allowed[f.Severity] {
			filtered = append(filtered, f)
		}
	}
	result.Findings = filtered
}

func writeReport(result *core.ScanResult, path, format string) {
	var err error
	switch format {
	case "html":
		err = report.WriteHTML(result, path)
	case "markdown", "md":
		err = report.WriteMarkdown(result, path)
	default:
		err = report.WriteJSON(result, path)
	}
	if err != nil {
		fmt.Printf("\033[31m[!]\033[0m Failed to write report: %v\n", err)
	} else {
		fmt.Printf("\n\033[32m[+]\033[0m Report saved to %s (%s)\n", path, format)
	}
}

type exploitFlags struct {
	target      string
	token       string
	chainID     int
	timeout     int
	tls         bool
	concurrency int
}

func runExploit(args []string) {
	f := &exploitFlags{}
	fs := flag.NewFlagSet("exploit", flag.ExitOnError)
	fs.StringVar(&f.target, "t", "", "Target host:port")
	fs.StringVar(&f.target, "target", "", "Target host:port")
	fs.StringVar(&f.token, "token", "", "Auth token")
	fs.IntVar(&f.chainID, "chain-id", 0, "Chain node ID")
	fs.IntVar(&f.timeout, "timeout", 0, "Timeout seconds")
	fs.BoolVar(&f.tls, "tls", false, "Use TLS")
	fs.IntVar(&f.concurrency, "concurrency", 10, "Concurrency")
	fs.Parse(args)

	if f.target == "" {
		fmt.Println("\033[31m[!]\033[0m Target required: -t HOST:PORT")
		os.Exit(1)
	}

	fileCfg := config.LoadDefault()
	cfg := fileCfg.Merge(f.token, 0, f.concurrency, f.tls, "", config.LogInfo)

	targets := core.ParseTargets(f.target, f.tls)
	if len(targets) == 0 {
		fmt.Println("\033[31m[!]\033[0m Invalid target")
		os.Exit(1)
	}
	t := targets[0]

	scanner := scan.NewScanner(cfg)
	dag := scanner.BuildDAGForDryRun()

	var findings []core.Finding
	if f.chainID > 0 {
		fmt.Printf("\033[36m[*]\033[0m Running single chain node #%d\n", f.chainID)
		findings = dag.ExecuteSingle(f.chainID, t, cfg)
	} else {
		fmt.Printf("\033[36m[*]\033[0m Running full exploit chain\n")
		findings, _ = dag.Execute(t, cfg, nil)
	}

	for _, f := range findings {
		f.Print()
	}
	fmt.Printf("\n\033[32m[✓]\033[0m Exploit complete: %d findings\n", len(findings))
}

func runChain(args []string) {
	f := &exploitFlags{}
	fs := flag.NewFlagSet("chain", flag.ExitOnError)
	fs.StringVar(&f.target, "t", "", "Target host:port")
	fs.StringVar(&f.target, "target", "", "Target host:port")
	fs.StringVar(&f.token, "token", "", "Auth token")
	fs.IntVar(&f.timeout, "timeout", 0, "Timeout seconds")
	fs.BoolVar(&f.tls, "tls", false, "Use TLS")
	var chainFilter string
	var output, format string
	fs.StringVar(&chainFilter, "id", "", "Run single chain by ID")
	fs.StringVar(&output, "o", "", "Output file")
	fs.StringVar(&output, "output", "", "Output file")
	fs.StringVar(&format, "format", "html", "Output format: html|markdown|json")
	fs.Parse(args)

	if f.target == "" {
		fmt.Println("\033[31m[!]\033[0m Target required: -t HOST:PORT")
		os.Exit(1)
	}

	fileCfg := config.LoadDefault()
	cfg := fileCfg.Merge(f.token, 0, 10, f.tls, "", config.LogInfo)
	targets := core.ParseTargets(f.target, f.tls)
	if len(targets) == 0 {
		fmt.Println("\033[31m[!]\033[0m Invalid target")
		os.Exit(1)
	}
	t := targets[0]

	exploit.ResetTraces()

	var chainMods []exploit.Module
	for _, m := range exploit.GlobalRegistry().All() {
		id := m.Meta().ID
		if !strings.HasPrefix(id, "chain_") {
			continue
		}
		if chainFilter != "" && id != chainFilter {
			continue
		}
		chainMods = append(chainMods, m)
	}

	fmt.Printf("\033[36m[*]\033[0m Running %d attack chains against %s\n\n", len(chainMods), t)

	result := core.NewScanResult(t)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	var mu sync.Mutex

	for _, m := range chainMods {
		wg.Add(1)
		go func(mod exploit.Module) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			findings, _ := mod.Run(t, cfg)
			mu.Lock()
			for _, f := range findings {
				result.Add(f)
			}
			mu.Unlock()
		}(m)
	}
	wg.Wait()
	result.Done()

	complete := 0
	for _, tr := range exploit.Traces() {
		if tr.Complete {
			complete++
		}
	}
	fmt.Printf("\n\033[32m[✓]\033[0m Chains complete: %d findings, %d/%d full compromises\n",
		len(result.Findings), complete, len(chainMods))

	if output != "" {
		writeReport(result, output, format)
	}
}

type discoverFlags struct {
	target  string
	ports   string
	timeout int
}

func runDiscover(args []string) {
	f := &discoverFlags{}
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	fs.StringVar(&f.target, "t", "", "Target host")
	fs.StringVar(&f.target, "target", "", "Target host")
	fs.StringVar(&f.ports, "ports", "", "Comma-separated ports")
	fs.IntVar(&f.timeout, "timeout", 5, "Timeout seconds")
	fs.Parse(args)

	if f.target == "" {
		fmt.Println("\033[31m[!]\033[0m Target required: -t HOST")
		os.Exit(1)
	}

	var ports []int
	if f.ports != "" {
		for _, p := range strings.Split(f.ports, ",") {
			var port int
			fmt.Sscanf(strings.TrimSpace(p), "%d", &port)
			if port > 0 {
				ports = append(ports, port)
			}
		}
	}

	timeout := time.Duration(f.timeout) * time.Second
	results := scan.DiscoverServices(f.target, ports, timeout, 50)

	if len(results) == 0 {
		fmt.Println("\033[33m[!]\033[0m No open ports or services found")
		return
	}

	fmt.Printf("\n\033[32m[+]\033[0m Found %d open services:\n\n", len(results))
	for _, r := range results {
		platformStr := string(r.Platform)
		if r.Platform == core.PlatformUnknown {
			platformStr = "unknown"
		}
		fmt.Printf("  %s:%d [%s]\n", r.Host, r.Port, platformStr)
	}
}

func runConfig(args []string) {
	fileCfg := config.LoadDefault()
	cfg := config.Default()

	fmt.Printf("\033[36m[*]\033[0m Current configuration:\n\n")
	fmt.Println("  Default settings:")
	fmt.Printf("    Timeout: %v\n", cfg.Timeout)
	fmt.Printf("    Concurrency: %d\n", cfg.Concurrency)
	fmt.Printf("    Log level: %s\n", cfg.LogLevel)

	if fileCfg.Scanner != nil {
		fmt.Println("\n  [scanner]")
		if fileCfg.Scanner.Timeout > 0 {
			fmt.Printf("    timeout = %d\n", fileCfg.Scanner.Timeout)
		}
		if fileCfg.Scanner.Concurrency > 0 {
			fmt.Printf("    concurrency = %d\n", fileCfg.Scanner.Concurrency)
		}
	}

	if fileCfg.Proxy != nil {
		fmt.Println("\n  [proxy]")
		if fileCfg.Proxy.HTTP != "" {
			fmt.Printf("    http = %s\n", fileCfg.Proxy.HTTP)
		}
		if fileCfg.Proxy.HTTPS != "" {
			fmt.Printf("    https = %s\n", fileCfg.Proxy.HTTPS)
		}
		if fileCfg.Proxy.SOCKS5 != "" {
			fmt.Printf("    socks5 = %s\n", fileCfg.Proxy.SOCKS5)
		}
	}

	if len(fileCfg.Profiles) > 0 {
		fmt.Println("\n  Available profiles:")
		for name := range fileCfg.Profiles {
			fmt.Printf("    %s\n", name)
		}
	}
}

type nucleiFlags struct {
	target    string
	templates string
	list      bool
}

func runNuclei(args []string) {
	f := &nucleiFlags{}
	fs := flag.NewFlagSet("nuclei", flag.ExitOnError)
	fs.StringVar(&f.target, "t", "", "Target URL")
	fs.StringVar(&f.target, "target", "", "Target URL")
	fs.StringVar(&f.templates, "templates", "../nuclei-templates", "Templates directory")
	fs.BoolVar(&f.list, "list", false, "List templates")
	fs.Parse(args)

	runner := nuclei.NewRunner(f.templates)
	if err := runner.LoadTemplates(); err != nil {
		fmt.Printf("\033[31m[!]\033[0m Failed to load templates: %v\n", err)
		os.Exit(1)
	}

	if f.list {
		runner.ListTemplates()
		return
	}

	if f.target == "" {
		fmt.Println("\033[31m[!]\033[0m Target required: -t URL")
		os.Exit(1)
	}

	fmt.Printf("\033[36m[*]\033[0m Running %d Nuclei templates against %s\n\n", len(runner.Templates), f.target)

	findings := runner.RunAll(f.target)
	if len(findings) == 0 {
		fmt.Println("\033[32m[✓]\033[0m No issues found")
		return
	}

	fmt.Printf("\033[31m[!]\033[0m Found %d issues:\n\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  [%s] %s\n", f.Severity, f.Name)
		fmt.Printf("    Template: %s\n", f.TemplateID)
		fmt.Printf("    URL: %s\n", f.URL)
		if f.Evidence != "" {
			fmt.Printf("    Evidence: %s\n", f.Evidence)
		}
		fmt.Println()
	}
}

func runOsint(args []string) {
	fs := flag.NewFlagSet("osint", flag.ExitOnError)
	engine := fs.String("engine", "", "shodan | fofa | hunter")
	query := fs.String("query", "", "Raw engine query")
	platform := fs.String("platform", "", "Built-in dork for AI platform")
	size := fs.Int("size", 100, "Max results")
	jsonOut := fs.Bool("json", false, "JSON output")
	listDorks := fs.Bool("list-dorks", false, "List built-in platform dorks")
	fs.Parse(args)

	if *listDorks {
		fmt.Printf("\033[36m[*]\033[0m Built-in dorks (%d platforms):\n\n", len(osint.Dorks))
		for _, p := range osint.Platforms() {
			fmt.Printf("  %s\n", p)
			for _, e := range osint.Engines {
				if q, ok := osint.DorkFor(p, e); ok {
					fmt.Printf("    %-8s %s\n", e+":", q)
				}
			}
		}
		return
	}

	if *engine == "" {
		fmt.Println("\033[31m[!]\033[0m --engine required (shodan|fofa|hunter)")
		os.Exit(1)
	}

	q := *query
	if q == "" && *platform != "" {
		dork, ok := osint.DorkFor(*platform, *engine)
		if !ok {
			fmt.Printf("\033[31m[!]\033[0m No dork for platform %q on %s (see --list-dorks)\n", *platform, *engine)
			os.Exit(1)
		}
		q = dork
		fmt.Printf("\033[36m[*]\033[0m Using dork: %s\n", q)
	}
	if q == "" {
		fmt.Println("\033[31m[!]\033[0m --query or --platform required")
		os.Exit(1)
	}

	fmt.Printf("\033[36m[*]\033[0m Querying %s ...\n\n", *engine)
	hosts, err := osint.Query(*engine, q, *size)
	if err != nil {
		fmt.Printf("\033[31m[!]\033[0m %v\n", err)
		os.Exit(1)
	}
	if len(hosts) == 0 {
		fmt.Println("\033[32m[✓]\033[0m No results")
		return
	}

	fmt.Printf("\033[31m[!]\033[0m %d hosts:\n\n", len(hosts))
	if *jsonOut {
		data, _ := json.MarshalIndent(hosts, "", "  ")
		fmt.Println(string(data))
		return
	}
	fmt.Print(osint.Format(hosts))
}

func runMCPWithOutput(args []string, protoOut *os.File) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	allow := fs.String("allow", "", "Comma-separated extra allowed targets (CIDR/host)")
	allowFile := fs.String("allow-file", "", "File with one allowed target per line")
	nucleiDir := fs.String("nuclei-templates", "../nuclei-templates", "Nuclei templates directory")
	fs.Parse(args)

	var allowed []string
	if *allow != "" {
		for _, t := range strings.Split(*allow, ",") {
			allowed = append(allowed, strings.TrimSpace(t))
		}
	}
	if *allowFile != "" {
		data, err := os.ReadFile(*allowFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\033[31m[!]\033[0m cannot read allow-file: %v\n", err)
			os.Exit(1)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				allowed = append(allowed, line)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "[catchclaw-mcp] v%s starting on stdio (allowlist: private ranges + %d extra)\n", Version, len(allowed))

	srv := mcpserver.New(mcpserver.Options{
		AllowedTargets: allowed,
		NucleiDir:      *nucleiDir,
		AuditLog:       os.Stderr,
	})
	if err := srv.Serve(os.Stdin, protoOut); err != nil && err.Error() != "EOF" {
		fmt.Fprintf(os.Stderr, "[catchclaw-mcp] exited: %v\n", err)
	}
}
