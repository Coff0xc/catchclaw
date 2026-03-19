// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍Package scan 提供统一的扫描编排逻辑，作为 CLI / TUI / WebUI 的唯一调用入口。
package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/audit"
	"github.com/coff0xc/lobster-guard/pkg/auth"
	"github.com/coff0xc/lobster-guard/pkg/chain"
	"github.com/coff0xc/lobster-guard/pkg/concurrent"
	"github.com/coff0xc/lobster-guard/pkg/recon"
	"github.com/coff0xc/lobster-guard/pkg/scanner"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ---------------------------------------------------------------------------
// ScanConfig — 覆盖所有 CLI 选项的统一配置
// ---------------------------------------------------------------------------

// ScanConfig 包含完整扫描流程所需的全部参数。
type ScanConfig struct {
	Token       string
	HookToken   string
	HookPath    string
	CallbackURL string
	Timeout     time.Duration

	// 爆破相关
	NoBrute     bool
	BruteConfig auth.BruteConfig

	// 漏洞利用选项
	NoExploit       bool
	Aggressive      bool
	UltraAggressive bool
	DAG             bool
	ChainID         int     // -1 = 全部
	Workers         int
	RateLimit       float64
}

// DefaultScanConfig 返回合理的默认配置。
func DefaultScanConfig() ScanConfig {
	return ScanConfig{
		Timeout:     30 * time.Second,
		HookPath:    "/hooks",
		DAG:         true,
		ChainID:     -1,
		BruteConfig: auth.DefaultBruteConfig(),
	}
}

// chainConfig 从 ScanConfig 构建 chain.ChainConfig。
func (c *ScanConfig) chainConfig() chain.ChainConfig {
	return chain.ChainConfig{
		Token:       c.Token,
		HookToken:   c.HookToken,
		HookPath:    c.HookPath,
		CallbackURL: c.CallbackURL,
		Timeout:     c.Timeout,
	}
}

// concurrency 根据配置计算实际并发数。
func (c *ScanConfig) concurrency() int {
	n := c.Workers
	if n < 1 {
		n = 5
	}
	if c.UltraAggressive {
		return 200
	}
	if c.Aggressive && n < 20 {
		return 20
	}
	return n
}

// ---------------------------------------------------------------------------
// 通道辅助函数
// ---------------------------------------------------------------------------

// SendLog 向日志通道发送消息（非阻塞，通道为 nil 时安全忽略）。
func SendLog(ch chan string, msg string) {
	if ch != nil {
		select {
		case ch <- msg:
		default:
		}
	}
}

// sendProgress 向进度通道发送更新（非阻塞）。
func sendProgress(ch chan concurrent.Progress, p concurrent.Progress) {
	if ch != nil {
		select {
		case ch <- p:
		default:
		}
	}
}

// ---------------------------------------------------------------------------
// RunFullScan — 完整扫描流水线
// ---------------------------------------------------------------------------

// RunFullScan 执行完整扫描流水线：指纹 → 认证 → 信息收集 → 配置审计 → 漏洞利用。
func RunFullScan(ctx context.Context, target utils.Target, cfg ScanConfig,
	progressCh chan concurrent.Progress, logCh chan string) []utils.Finding {

	var all []utils.Finding

	// ── 阶段 1: 指纹识别 ──
	SendLog(logCh, "[*] 阶段 1: 指纹识别...")
	fpResult, fpFindings := scanner.Fingerprint(target, cfg.Timeout)
	all = append(all, fpFindings...)
	if !fpResult.IsOpenClaw {
		SendLog(logCh, fmt.Sprintf("[*] %s 不是 OpenClaw 平台，终止扫描", target.String()))
		return all
	}
	SendLog(logCh, fmt.Sprintf("[+] 检测到 OpenClaw: %s", fpResult.Version))

	// ── 阶段 2: 认证检测 + 可选爆破 ──
	if ctx.Err() != nil {
		return all
	}
	SendLog(logCh, "[*] 阶段 2: 认证检测...")
	all = append(all, auth.NoAuthCheck(target, cfg.Timeout)...)

	activeToken := cfg.Token
	if !cfg.NoBrute {
		bruteCfg := cfg.BruteConfig
		bruteCfg.Timeout = cfg.Timeout
		bruteResult, bruteFindings := auth.TokenBrute(target, bruteCfg)
		all = append(all, bruteFindings...)
		if bruteResult != nil && bruteResult.Found && bruteResult.Token != "" {
			activeToken = bruteResult.Token
			SendLog(logCh, fmt.Sprintf("[+] 爆破成功，获取令牌: %s", activeToken))
		}
	}

	// 后续阶段使用可能更新的令牌
	phaseCfg := cfg
	phaseCfg.Token = activeToken

	// ── 阶段 3: 信息收集 ──
	if ctx.Err() != nil {
		return all
	}
	SendLog(logCh, "[*] 阶段 3: 信息收集...")
	all = append(all, RunReconCheck(target, phaseCfg, logCh)...)

	// ── 阶段 4: 配置审计 ──
	if ctx.Err() != nil {
		return all
	}
	if activeToken != "" {
		SendLog(logCh, "[*] 阶段 4: 配置审计...")
		all = append(all, RunAuditCheck(target, phaseCfg, logCh)...)
	} else {
		SendLog(logCh, "[*] 阶段 4: 跳过配置审计 (无令牌)")
	}

	// ── 阶段 5: 漏洞利用 ──
	if ctx.Err() != nil {
		return all
	}
	if !cfg.NoExploit {
		SendLog(logCh, "[*] 阶段 5: 漏洞利用...")
		all = append(all, RunExploitScan(ctx, target, phaseCfg, progressCh, logCh)...)
	} else {
		SendLog(logCh, "[*] 阶段 5: 跳过漏洞利用 (--no-exploit)")
	}

	return all
}

// ---------------------------------------------------------------------------
// RunExploitScan — 漏洞利用编排（支持全部模式）
// ---------------------------------------------------------------------------

// RunExploitScan 执行漏洞利用扫描，支持以下模式：
//   - DAG=false                     → chain.RunFullChain (v1 线性执行)
//   - ChainID >= 0                  → dag.ExecuteSingle (单条攻击链)
//   - UltraAggressive / Workers > 0 → concurrent.NewEngine (高并发引擎)
//   - 默认 DAG                      → chain.RunDAGChain (DAG 拓扑排序并行)
func RunExploitScan(ctx context.Context, target utils.Target, cfg ScanConfig,
	progressCh chan concurrent.Progress, logCh chan string) []utils.Finding {

	chainCfg := cfg.chainConfig()

	// ── 模式 1: 线性执行 (legacy) ──
	if !cfg.DAG {
		SendLog(logCh, "[*] 线性模式: 顺序执行全部攻击链")
		return chain.RunFullChain(target, chainCfg)
	}

	conc := cfg.concurrency()
	aggressive := cfg.Aggressive || cfg.UltraAggressive

	// ── 模式 2: 单条攻击链 ──
	if cfg.ChainID >= 0 {
		SendLog(logCh, fmt.Sprintf("[*] 单链模式: 执行攻击链 #%d", cfg.ChainID))
		dag := chain.BuildFullDAG(conc, aggressive)
		return dag.ExecuteSingle(target, chainCfg, cfg.ChainID)
	}

	// ── 模式 3: 高并发引擎 (ultra-aggressive 或显式 workers) ──
	if cfg.UltraAggressive || cfg.Workers > 0 {
		workers := cfg.Workers
		if workers <= 0 {
			workers = conc
		}
		engine := concurrent.NewEngine(workers, cfg.RateLimit)
		engine.Timeout = cfg.Timeout
		engine.ProgressChan = progressCh

		dag := chain.BuildFullDAG(workers, true)
		SendLog(logCh, fmt.Sprintf("[*] 高并发引擎: %d 条攻击链, workers=%d, rate=%.0f/s",
			len(dag.Nodes), workers, cfg.RateLimit))

		var tasks []concurrent.ScanTask
		for _, node := range dag.Nodes {
			n := node // 闭包捕获
			tasks = append(tasks, concurrent.ScanTask{
				ID:       n.ID,
				Name:     n.Name,
				Target:   target,
				Token:    cfg.Token,
				ChainID:  n.ID,
				Priority: 1,
				Execute: func(t utils.Target, token string) []utils.Finding {
					return n.Execute(t, chainCfg)
				},
			})
		}
		return engine.Run(tasks)
	}

	// ── 模式 4: 默认 DAG 拓扑排序并行 ──
	SendLog(logCh, fmt.Sprintf("[*] DAG 模式: 并发=%d, aggressive=%v", conc, aggressive))

	// 带进度回调的 DAG 执行
	dag := chain.BuildFullDAG(conc, aggressive)
	onProgress := func(p chain.NodeProgress) {
		sendProgress(progressCh, concurrent.Progress{
			TaskID:  p.NodeID,
			Name:    p.Name,
			Status:  p.Status,
			Elapsed: p.Elapsed,
		})
	}
	onFinding := func(f utils.Finding) {
		SendLog(logCh, fmt.Sprintf("[+] 发现: [%s] %s — %s", f.Severity, f.Title, f.Description))
	}
	return dag.ExecuteWithProgress(ctx, target, chainCfg, onProgress, onFinding)
}

// ---------------------------------------------------------------------------
// 单阶段扫描函数
// ---------------------------------------------------------------------------

// RunFingerprint 仅执行指纹识别。
func RunFingerprint(target utils.Target, cfg ScanConfig, logCh chan string) []utils.Finding {
	SendLog(logCh, "[*] 指纹识别...")
	_, findings := scanner.Fingerprint(target, cfg.Timeout)
	return findings
}

// RunAuthCheck 执行认证检测，包含可选的令牌爆破。
func RunAuthCheck(target utils.Target, cfg ScanConfig, logCh chan string) []utils.Finding {
	SendLog(logCh, "[*] 认证检测...")
	findings := auth.NoAuthCheck(target, cfg.Timeout)

	// 可选爆破
	if !cfg.NoBrute {
		bruteCfg := cfg.BruteConfig
		bruteCfg.Timeout = cfg.Timeout
		_, bruteFindings := auth.TokenBrute(target, bruteCfg)
		findings = append(findings, bruteFindings...)
	}

	return findings
}

// RunReconCheck 执行信息收集（版本探测 + 端点枚举 + WS 方法枚举）。
func RunReconCheck(target utils.Target, cfg ScanConfig, logCh chan string) []utils.Finding {
	SendLog(logCh, "[*] 信息收集...")
	var all []utils.Finding
	_, f1 := recon.VersionDetect(target, cfg.Timeout)
	all = append(all, f1...)
	_, f2 := recon.EnumEndpoints(target, cfg.Token, cfg.Timeout)
	all = append(all, f2...)
	_, f3 := recon.EnumWSMethods(target, cfg.Token, cfg.Timeout)
	all = append(all, f3...)
	return all
}

// RunAuditCheck 执行配置安全审计。
func RunAuditCheck(target utils.Target, cfg ScanConfig, logCh chan string) []utils.Finding {
	SendLog(logCh, "[*] 配置审计...")
	return audit.RunAudit(target, audit.AuditConfig{Token: cfg.Token, Timeout: cfg.Timeout})
}
