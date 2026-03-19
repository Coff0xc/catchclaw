package concurrent

import (
	"container/heap"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍QuietMode suppresses direct stdout prints from the engine (for TUI mode).
var QuietMode bool

// ScanEngine 提供可配置并发度的高性能扫描引擎
// 支持优先级调度、速率限制、失败重试和实时进度报告
type ScanEngine struct {
	MaxWorkers   int           // 最大并发 worker 数 (默认 50)
	RateLimit    float64       // 每秒最大请求数 (0 = 不限制)
	Timeout      time.Duration // 单任务超时
	RetryCount   int           // 失败重试次数
	ProgressChan chan Progress  // 进度报告通道 (可选)
}

// ScanTask 表示一个扫描任务
type ScanTask struct {
	ID       int                                                          // 任务唯一 ID
	Name     string                                                      // 任务名称
	Target   utils.Target                                                // 扫描目标
	Token    string                                                      // 认证令牌
	ChainID  int                                                         // 攻击链 ID
	Priority int                                                         // 优先级: 0=high, 1=medium, 2=low
	Execute  func(target utils.Target, token string) []utils.Finding     // 执行函数
}

// Progress 报告任务执行进度
type Progress struct {
	TaskID  int           `json:"task_id"`
	Name    string        `json:"name"`
	Status  string        `json:"status"` // "pending", "running", "done", "error", "retry"
	Finding *utils.Finding `json:"finding,omitempty"`
	Error   error         `json:"error,omitempty"`
	Elapsed time.Duration `json:"elapsed"`
}

// EngineStats 引擎运行统计
type EngineStats struct {
	TotalTasks  int           `json:"total_tasks"`
	Completed   int           `json:"completed"`
	Failed      int           `json:"failed"`
	Retried     int           `json:"retried"`
	TotalTime   time.Duration `json:"total_time"`
	FindingCount int          `json:"finding_count"`
}

// --- 优先级队列实现 ---

type taskQueue []*ScanTask

func (q taskQueue) Len() int            { return len(q) }
func (q taskQueue) Less(i, j int) bool  { return q[i].Priority < q[j].Priority }
func (q taskQueue) Swap(i, j int)       { q[i], q[j] = q[j], q[i] }
func (q *taskQueue) Push(x interface{}) { *q = append(*q, x.(*ScanTask)) }
func (q *taskQueue) Pop() interface{} {
	old := *q
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	*q = old[:n-1]
	return item
}

// --- 令牌桶速率限制器 ---

type rateLimiter struct {
	tokens   float64
	maxRate  float64
	lastTime time.Time
	mu       sync.Mutex
}

func newRateLimiter(rate float64) *rateLimiter {
	return &rateLimiter{
		tokens:   rate,
		maxRate:  rate,
		lastTime: time.Now(),
	}
}

// acquire 等待直到获取一个令牌
func (r *rateLimiter) acquire(ctx context.Context) error {
	if r.maxRate <= 0 {
		return nil // 不限速
	}
	for {
		r.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(r.lastTime).Seconds()
		r.tokens += elapsed * r.maxRate
		if r.tokens > r.maxRate {
			r.tokens = r.maxRate
		}
		r.lastTime = now

		if r.tokens >= 1.0 {
			r.tokens -= 1.0
			r.mu.Unlock()
			return nil
		}
		r.mu.Unlock()

		// 等待补充
		wait := time.Duration(float64(time.Second) / r.maxRate)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// NewEngine 创建高并发扫描引擎
func NewEngine(workers int, ratePerSec float64) *ScanEngine {
	if workers <= 0 {
		workers = 50
	}
	return &ScanEngine{
		MaxWorkers: workers,
		RateLimit:  ratePerSec,
		Timeout:    30 * time.Second,
		RetryCount: 2,
	}
}

// Run 执行所有扫描任务，返回所有发现
func (e *ScanEngine) Run(tasks []ScanTask) []utils.Finding {
	return e.RunWithCallback(tasks, nil)
}

// RunWithCallback 执行扫描任务并通过回调报告进度
func (e *ScanEngine) RunWithCallback(tasks []ScanTask, cb func(Progress)) []utils.Finding {
	if len(tasks) == 0 {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	limiter := newRateLimiter(e.RateLimit)
	startTime := time.Now()

	if !QuietMode {
		fmt.Printf("\n[*] ═══ Concurrent Engine: %d tasks, %d workers, rate=%.0f/s ═══\n",
			len(tasks), e.MaxWorkers, e.RateLimit)
	}

	// 构建优先级队列
	pq := make(taskQueue, 0, len(tasks))
	for i := range tasks {
		pq = append(pq, &tasks[i])
	}
	heap.Init(&pq)

	var (
		allFindings []utils.Finding
		mu          sync.Mutex
		wg          sync.WaitGroup
		sem         = make(chan struct{}, e.MaxWorkers)
		completed   int32
		failed      int32
		retried     int32
	)

	// 从优先级队列中取任务执行
	for pq.Len() > 0 {
		task := heap.Pop(&pq).(*ScanTask)

		wg.Add(1)
		sem <- struct{}{}

		go func(t *ScanTask) {
			defer wg.Done()
			defer func() { <-sem }()

			// 速率限制
			if err := limiter.acquire(ctx); err != nil {
				e.report(cb, Progress{TaskID: t.ID, Name: t.Name, Status: "error", Error: err})
				atomic.AddInt32(&failed, 1)
				return
			}

			e.report(cb, Progress{TaskID: t.ID, Name: t.Name, Status: "running"})

			findings := e.executeWithRetry(ctx, t, &retried)

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()

			elapsed := time.Since(startTime)
			if len(findings) > 0 {
				atomic.AddInt32(&completed, 1)
				for i := range findings {
					e.report(cb, Progress{
						TaskID: t.ID, Name: t.Name, Status: "done",
						Finding: &findings[i], Elapsed: elapsed,
					})
				}
			} else {
				atomic.AddInt32(&completed, 1)
				e.report(cb, Progress{TaskID: t.ID, Name: t.Name, Status: "done", Elapsed: elapsed})
			}

			if !QuietMode {
				fmt.Printf("  [%d/%d] %s: %d findings\n",
					atomic.LoadInt32(&completed), len(tasks), t.Name, len(findings))
			}
		}(task)
	}

	wg.Wait()

	totalTime := time.Since(startTime)
	if !QuietMode {
		fmt.Printf("\n[*] ═══ Engine complete: %d findings, %d tasks in %s (retried: %d, failed: %d) ═══\n",
			len(allFindings), len(tasks), totalTime.Round(time.Millisecond),
			atomic.LoadInt32(&retried), atomic.LoadInt32(&failed))
	}

	return allFindings
}

// RunWithContext 支持外部取消的扫描执行
func (e *ScanEngine) RunWithContext(ctx context.Context, tasks []ScanTask, cb func(Progress)) []utils.Finding {
	if len(tasks) == 0 {
		return nil
	}

	limiter := newRateLimiter(e.RateLimit)

	// 构建优先级队列
	pq := make(taskQueue, 0, len(tasks))
	for i := range tasks {
		pq = append(pq, &tasks[i])
	}
	heap.Init(&pq)

	var (
		allFindings []utils.Finding
		mu          sync.Mutex
		wg          sync.WaitGroup
		sem         = make(chan struct{}, e.MaxWorkers)
		retried     int32
	)

	for pq.Len() > 0 {
		select {
		case <-ctx.Done():
			wg.Wait()
			return allFindings
		default:
		}

		task := heap.Pop(&pq).(*ScanTask)
		wg.Add(1)
		sem <- struct{}{}

		go func(t *ScanTask) {
			defer wg.Done()
			defer func() { <-sem }()

			if err := limiter.acquire(ctx); err != nil {
				return
			}

			e.report(cb, Progress{TaskID: t.ID, Name: t.Name, Status: "running"})
			findings := e.executeWithRetry(ctx, t, &retried)

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()

			e.report(cb, Progress{TaskID: t.ID, Name: t.Name, Status: "done", Elapsed: 0})
		}(task)
	}

	wg.Wait()
	return allFindings
}

// Stats 返回引擎统计信息 (在 Run 完成后调用)
func (e *ScanEngine) Stats(findings []utils.Finding, elapsed time.Duration) EngineStats {
	return EngineStats{
		TotalTime:    elapsed,
		FindingCount: len(findings),
	}
}

// executeWithRetry 带重试执行单个任务
func (e *ScanEngine) executeWithRetry(ctx context.Context, t *ScanTask, retried *int32) []utils.Finding {
	for attempt := 0; attempt <= e.RetryCount; attempt++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if attempt > 0 {
			atomic.AddInt32(retried, 1)
			if !QuietMode {
				fmt.Printf("  [!] Retry %d/%d: %s\n", attempt, e.RetryCount, t.Name)
			}
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}

		// 通过 channel + goroutine 实现任务超时
		type result struct {
			findings []utils.Finding
			err      error
		}
		ch := make(chan result, 1)

		go func() {
			defer func() {
				if r := recover(); r != nil {
					ch <- result{err: fmt.Errorf("panic: %v", r)}
				}
			}()
			findings := t.Execute(t.Target, t.Token)
			ch <- result{findings: findings}
		}()

		timeout := e.Timeout
		if timeout == 0 {
			timeout = 30 * time.Second
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(timeout):
			if !QuietMode {
				fmt.Printf("  [!] Timeout: %s (attempt %d)\n", t.Name, attempt+1)
			}
			continue
		case r := <-ch:
			if r.err != nil {
				if !QuietMode {
					fmt.Printf("  [!] Error: %s: %v\n", t.Name, r.err)
				}
				continue
			}
			return r.findings
		}
	}

	return nil
}

// report 发送进度通知
func (e *ScanEngine) report(cb func(Progress), p Progress) {
	if cb != nil {
		cb(p)
	}
	if e.ProgressChan != nil {
		select {
		case e.ProgressChan <- p:
		default:
		}
	}
}
