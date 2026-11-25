package scan

import (
	"fmt"
	"strings"
	"sync"

	"github.com/Coff0xc/catchclaw/go/internal/config"
	"github.com/Coff0xc/catchclaw/go/internal/core"
	"github.com/Coff0xc/catchclaw/go/internal/exploit"
	"github.com/Coff0xc/catchclaw/go/internal/payload"
)

type Scanner struct {
	cfg      *config.Config
	payloads *payload.Registry
	registry *exploit.Registry
}

func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{
		cfg:      cfg,
		payloads: payload.Default(),
		registry: exploit.GlobalRegistry(),
	}
}

func (s *Scanner) Registry() *exploit.Registry {
	return s.registry
}

func (s *Scanner) BuildDAGForDryRun() *core.DAG {
	return s.buildDAG()
}

func (s *Scanner) Scan(target core.Target) *core.ScanResult {
	result := core.NewScanResult(target)

	fmt.Printf("\n\033[36m[*]\033[0m Starting full scan on %s ...\n", target)
	fmt.Printf("\033[32m[+]\033[0m Modules loaded: %d\n", s.registry.Len())

	dag := s.buildDAG()
	fmt.Printf("\033[32m[+]\033[0m DAG built: %d nodes\n", dag.Len())

	findings, _ := dag.Execute(target, s.cfg, nil)
	for _, f := range findings {
		result.Add(f)
	}
	result.Done()

	s.printSummary(result)
	return result
}

var chainDefs = []struct {
	id        int
	moduleID  string
	dependsOn []int
}{
	{0, "cors_bypass", nil},
	{1, "ws_hijack", nil},
	{2, "auth_mode_abuse", nil},
	{3, "log_disclosure", []int{0}},
	{4, "hidden_content", []int{0}},
	{5, "origin_wildcard", []int{0}},
	{6, "ssrf", []int{0}},
	{7, "eval_inject", []int{0}},
	{8, "prompt_inject", []int{0}},
	{9, "mcp_inject", []int{0}},
	{10, "pairing_brute", []int{0, 2}},
	{11, "oauth_abuse", []int{0, 2}},
	{12, "responses_exploit", []int{0}},
	{13, "ws_fuzz", []int{1}},
	{14, "acp_bypass", []int{0, 2}},
	{15, "csrf_no_origin", []int{0}},
	{16, "silent_pair_abuse", []int{0, 2}},
	{17, "ratelimit_scope_bypass", []int{0}},
	{18, "apikey_steal", []int{0}},
	{19, "oauth_token_theft", []int{11}},
	{20, "secret_extract", []int{0}},
	{21, "secrets_resolve", []int{20}},
	{22, "talk_secrets", []int{0}},
	{23, "session_hijack", []int{0}},
	{24, "transcript_theft", []int{0}},
	{25, "memory_data_leak", []int{0}},
	{26, "c2_exfil", []int{7}},
	{27, "rce", []int{7}},
	{28, "agent_inject", []int{8}},
	{29, "agent_file_inject", []int{28}},
	{30, "channel_inject", []int{0}},
	{31, "skill_poison", []int{0}},
	{32, "config_tamper", []int{0}},
	{33, "rogue_node", []int{0}},
	{34, "patch_escape", []int{0}},
	{35, "session_file_write", []int{0}},
	{36, "cron_bypass", []int{0}},
	{37, "keychain_cmd_inject", []int{0}},
	{38, "qmd_cmd_inject", []int{0}},
	{39, "exec_race_toctou", []int{27}},
	{40, "browser_upload_traversal", []int{0}},
	{41, "voice_ext_rce", []int{0}},
	{42, "env_inject", []int{27}},
	{43, "ipv6_ssrf_bypass", []int{6}},
	{44, "msg_platform_spoof", []int{0}},
	{45, "gateway_hijack", nil},
	{46, "safebins_bypass", []int{27}},
	{47, "guest_mode_abuse", []int{0}},
	{48, "mdns_leak", nil},
	{49, "skill_supply_chain", []int{0}},
	{50, "webhook_verify", []int{0}},
	{51, "skill_scanner_bypass", []int{0}},
	{52, "flood_guard_reset", []int{17}},
	{53, "bypass_soul", []int{8}},
	{54, "marker_spoof", []int{8}},
	{55, "redact_bypass", []int{0}},
	{56, "obfuscation_bypass", []int{0}},
	{57, "unicode_bypass", []int{0}},
	{58, "ssrf_rebind", []int{6}},
	{59, "ssrf_proxy_bypass", []int{6}},
	{60, "browser_request", []int{0}},
	{61, "secret_exec_abuse", []int{0}},
	{62, "link_template_inject", []int{0}},
	{63, "tools_invoke", []int{0}},
	{64, "hook_inject", []int{0, 8}},
	{65, "approval_hijack", []int{0}},
	{66, "ws_auth_brute", []int{1}},
	{67, "localhost_trust", nil},
	{68, "exec_socket_leak", []int{63}},
	{69, "dify_probe", nil},
	{70, "fastgpt_probe", nil},
	{71, "lobechat_probe", nil},
	{72, "librechat_probe", nil},
	{73, "nextchat_probe", nil},
	{74, "anythingllm_probe", nil},
	{75, "flowise_probe", nil},
	{76, "ragflow_probe", nil},
	{77, "langflow_probe", nil},
	{78, "litellm_probe", nil},
	{79, "ollama_probe", nil},
	{80, "vllm_probe", nil},
	{81, "dify_tap_probe", nil},
}

func (s *Scanner) buildDAG() *core.DAG {
	dag := core.NewDAG(s.cfg.Concurrency)

	moduleMap := make(map[string]exploit.Module)
	for _, m := range s.registry.All() {
		meta := m.Meta()
		moduleMap[meta.ID] = m
	}

	for _, def := range chainDefs {
		mod, ok := moduleMap[def.moduleID]
		if !ok {
			continue
		}
		meta := mod.Meta()
		m := mod
		dag.AddNode(core.Node{
			ID:        def.id,
			Name:      meta.Name,
			Category:  string(meta.Category),
			Phase:     string(meta.Phase),
			DependsOn: def.dependsOn,
			Run: func(target core.Target, cfg interface{}) ([]core.Finding, core.Outcome) {
				c, ok := cfg.(*config.Config)
				if !ok {
					return nil, core.OutcomeError
				}
				return m.Run(target, c)
			},
		})
	}

	return dag
}

func (s *Scanner) ScanMulti(targets []core.Target) []*core.ScanResult {
	total := len(targets)
	maxParallel := s.cfg.Concurrency
	if maxParallel > total {
		maxParallel = total
	}

	fmt.Printf("\n\033[36m[*]\033[0m Scanning %d targets (max %d parallel) ...\n", total, maxParallel)

	var results []*core.ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxParallel)

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, t core.Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fmt.Printf("\033[36m[*]\033[0m Scanning target %d/%d: %s\n", idx+1, total, t)
			r := s.Scan(t)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(i, target)
	}
	wg.Wait()

	totalFindings := 0
	for _, r := range results {
		totalFindings += len(r.Findings)
	}
	fmt.Printf("\n\033[32m[✓]\033[0m Multi-scan complete: %d targets, %d total findings\n", len(results), totalFindings)
	return results
}

func (s *Scanner) printSummary(result *core.ScanResult) {
	score := result.ChainScore()
	if score > 100 {
		score = 100
	}
	fmt.Printf("\n%s\n", strings.Repeat("═", 60))
	fmt.Printf("\033[32m[✓]\033[0m Scan complete: %d findings, risk score: %d\n", len(result.Findings), score)
	fmt.Printf("  Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d\n",
		result.CountBySeverity(core.Critical),
		result.CountBySeverity(core.High),
		result.CountBySeverity(core.Medium),
		result.CountBySeverity(core.Low),
		result.CountBySeverity(core.Info))
	fmt.Printf("%s\n", strings.Repeat("═", 60))
}

func RunFullScan(target core.Target, cfg *config.Config) *core.ScanResult {
	scanner := NewScanner(cfg)
	return scanner.Scan(target)
}

func RunMultiScan(targets []core.Target, cfg *config.Config) []*core.ScanResult {
	scanner := NewScanner(cfg)
	return scanner.ScanMulti(targets)
}
