package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍CVEEntry 表示一个 CVE 漏洞条目
type CVEEntry struct {
	ID               string   `json:"id"`
	Description      string   `json:"description"`
	Severity         string   `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	CVSS             float64  `json:"cvss"`
	References       []string `json:"references"`
	Affected         string   `json:"affected"`
	Published        string   `json:"published"`
	ExploitAvailable bool     `json:"exploit_available"`
	ChainIDs         []int    `json:"chain_ids,omitempty"` // 映射到的 LobsterGuard 攻击链
}

// Database 管理 OpenClaw/open-webui 相关 CVE 数据
type Database struct {
	entries    []CVEEntry
	httpClient *http.Client
}

// NewDatabase 返回包含内置 CVE 数据的数据库
func NewDatabase() *Database {
	db := &Database{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	db.loadBuiltin()
	return db
}

// loadBuiltin 加载内置 CVE 数据库
func (db *Database) loadBuiltin() {
	db.entries = []CVEEntry{
		{
			ID:               "CVE-2024-6707",
			Description:      "SSRF vulnerability in open-webui allows unauthenticated attackers to access internal services and cloud metadata endpoints via crafted URL parameters",
			Severity:         "CRITICAL",
			CVSS:             9.8,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-6707", "https://github.com/open-webui/open-webui/issues/2699"},
			Affected:         "open-webui <= 0.3.8",
			Published:        "2024-07-15",
			ExploitAvailable: true,
			ChainIDs:         []int{1, 26, 44, 45},
		},
		{
			ID:               "CVE-2024-7038",
			Description:      "Stored XSS in open-webui chat interface allows persistent script injection through crafted messages, enabling session hijacking and data theft",
			Severity:         "HIGH",
			CVSS:             7.5,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-7038"},
			Affected:         "open-webui <= 0.3.10",
			Published:        "2024-08-01",
			ExploitAvailable: true,
			ChainIDs:         []int{6, 14, 18},
		},
		{
			ID:               "CVE-2024-7050",
			Description:      "Path traversal in open-webui file upload API allows reading arbitrary files from the server filesystem via ../../ sequences",
			Severity:         "HIGH",
			CVSS:             8.1,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-7050"},
			Affected:         "open-webui <= 0.3.12",
			Published:        "2024-08-10",
			ExploitAvailable: true,
			ChainIDs:         []int{16, 23},
		},
		{
			ID:               "CVE-2024-8360",
			Description:      "Arbitrary file read vulnerability in open-webui document processing allows exfiltration of sensitive server files including configuration and secrets",
			Severity:         "CRITICAL",
			CVSS:             9.1,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-8360"},
			Affected:         "open-webui <= 0.3.15",
			Published:        "2024-09-02",
			ExploitAvailable: true,
			ChainIDs:         []int{9, 25, 27, 34},
		},
		{
			ID:               "CVE-2024-8489",
			Description:      "SQL injection in open-webui user management API allows authentication bypass and database manipulation via crafted query parameters",
			Severity:         "CRITICAL",
			CVSS:             9.4,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-8489"},
			Affected:         "open-webui <= 0.3.16",
			Published:        "2024-09-15",
			ExploitAvailable: true,
			ChainIDs:         []int{12, 28},
		},
		// LobsterGuard 新发现的漏洞 (尚未分配 CVE)
		{
			ID:               "CVE-2025-XXXX-01",
			Description:      "Template injection via MCP plugin command fields allows arbitrary code execution through server-side template rendering in OpenClaw Gateway",
			Severity:         "CRITICAL",
			CVSS:             9.8,
			References:       []string{"https://github.com/coff0xc/lobster-guard/blob/master/.audit/v2-comprehensive.md"},
			Affected:         "OpenClaw Gateway (all versions)",
			Published:        "2025-01-01",
			ExploitAvailable: true,
			ChainIDs:         []int{31, 2},
		},
		{
			ID:               "CVE-2025-XXXX-02",
			Description:      "OAuth state fixation and redirect hijack allows complete account takeover via Slack/GitHub OAuth integration in OpenClaw Gateway",
			Severity:         "HIGH",
			CVSS:             8.5,
			References:       []string{"https://github.com/coff0xc/lobster-guard/blob/master/.audit/v2-comprehensive.md"},
			Affected:         "OpenClaw Gateway (all versions)",
			Published:        "2025-01-01",
			ExploitAvailable: true,
			ChainIDs:         []int{19},
		},
		{
			ID:               "CVE-2025-XXXX-03",
			Description:      "ACP tool permission bypass via name aliasing allows execution of restricted tools without proper authorization checks",
			Severity:         "HIGH",
			CVSS:             8.2,
			References:       []string{"https://github.com/coff0xc/lobster-guard/blob/master/.audit/v2-comprehensive.md"},
			Affected:         "OpenClaw Gateway (all versions)",
			Published:        "2025-01-01",
			ExploitAvailable: true,
			ChainIDs:         []int{32},
		},
		{
			ID:               "CVE-2025-XXXX-04",
			Description:      "Unicode bidi/combining character filter bypass allows WAF evasion and injection attacks via homoglyph substitution",
			Severity:         "MEDIUM",
			CVSS:             6.8,
			References:       []string{"https://github.com/coff0xc/lobster-guard/blob/master/.audit/v2-comprehensive.md"},
			Affected:         "OpenClaw Gateway (all versions)",
			Published:        "2025-01-01",
			ExploitAvailable: true,
			ChainIDs:         []int{33, 46, 48},
		},
		{
			ID:               "CVE-2025-XXXX-05",
			Description:      "Rate limit scope bypass via header manipulation allows unlimited requests by switching between per-IP and per-token scopes",
			Severity:         "MEDIUM",
			CVSS:             5.3,
			References:       []string{"https://github.com/coff0xc/lobster-guard/blob/master/.audit/v3-comprehensive.md"},
			Affected:         "OpenClaw Gateway (all versions)",
			Published:        "2025-03-01",
			ExploitAvailable: true,
			ChainIDs:         []int{38, 39},
		},
		{
			ID:               "CVE-2025-XXXX-06",
			Description:      "CSRF protection bypass via missing Origin header validation allows cross-site state-changing requests against authenticated sessions",
			Severity:         "HIGH",
			CVSS:             7.6,
			References:       []string{"https://github.com/coff0xc/lobster-guard/blob/master/.audit/v3-comprehensive.md"},
			Affected:         "OpenClaw Gateway (all versions)",
			Published:        "2025-03-01",
			ExploitAvailable: true,
			ChainIDs:         []int{42, 43},
		},
		{
			ID:               "CVE-2025-XXXX-07",
			Description:      "SSRF DNS rebinding attack bypasses IP-based allowlist by resolving to internal addresses after initial DNS check",
			Severity:         "CRITICAL",
			CVSS:             9.0,
			References:       []string{"https://github.com/coff0xc/lobster-guard/blob/master/.audit/v3-comprehensive.md"},
			Affected:         "OpenClaw Gateway (all versions)",
			Published:        "2025-03-01",
			ExploitAvailable: true,
			ChainIDs:         []int{44, 45},
		},
		{
			ID:               "CVE-2025-XXXX-08",
			Description:      "Exec socket file descriptor leak allows unauthorized command execution via leaked WebSocket handles from previous exec sessions",
			Severity:         "HIGH",
			CVSS:             8.0,
			References:       []string{"https://github.com/coff0xc/lobster-guard/blob/master/.audit/v3-comprehensive.md"},
			Affected:         "OpenClaw Gateway (all versions)",
			Published:        "2025-03-01",
			ExploitAvailable: true,
			ChainIDs:         []int{47},
		},
		// ═══ CVE-2026: NVD-verified OpenClaw vulnerabilities ═══
		{
			ID:               "CVE-2026-25253",
			Description:      "OpenClaw before 2026.1.29 obtains a gatewayUrl from a query string and automatically makes a WebSocket connection without prompting, sending a token value. 1-click RCE via token exfiltration (ClawJacked)",
			Severity:         "HIGH",
			CVSS:             8.8,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-25253", "https://github.com/openclaw/openclaw/security/advisories/GHSA-g8p2-7wf7-98mq"},
			Affected:         "OpenClaw < 2026.1.29",
			Published:        "2026-02-01",
			ExploitAvailable: true,
			ChainIDs:         []int{17, 56},
		},
		{
			ID:               "CVE-2026-26322",
			Description:      "OpenClaw before 2026.2.14: Gateway tool accepted tool-supplied gatewayUrl without restrictions, causing the host to attempt outbound WebSocket connections to user-specified targets (SSRF via WS)",
			Severity:         "MEDIUM",
			CVSS:             5.0,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-26322"},
			Affected:         "OpenClaw < 2026.2.14",
			Published:        "2026-02-19",
			ExploitAvailable: true,
			ChainIDs:         []int{57},
		},
		{
			ID:               "CVE-2026-26324",
			Description:      "OpenClaw before 2026.2.14: SSRF protection bypassed using full-form IPv4-mapped IPv6 literals such as 0:0:0:0:0:ffff:7f00:1 (127.0.0.1), allowing requests to loopback/private/metadata endpoints",
			Severity:         "HIGH",
			CVSS:             7.5,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-26324", "https://github.com/openclaw/openclaw/security/advisories/GHSA-jrvc-8ff5-2f9f"},
			Affected:         "OpenClaw < 2026.2.14",
			Published:        "2026-02-19",
			ExploitAvailable: true,
			ChainIDs:         []int{45},
		},
		{
			ID:               "CVE-2026-26329",
			Description:      "OpenClaw before 2026.2.14: authenticated attackers can read arbitrary files from Gateway host by supplying absolute paths or path traversal sequences to the browser tool upload action",
			Severity:         "MEDIUM",
			CVSS:             6.5,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-26329"},
			Affected:         "OpenClaw < 2026.2.14",
			Published:        "2026-02-19",
			ExploitAvailable: true,
			ChainIDs:         []int{58},
		},
		{
			ID:               "CVE-2026-27487",
			Description:      "OpenClaw before 2026.2.14 on macOS: keychain credential refresh path constructs shell command via security add-generic-password -w with user-controlled OAuth tokens, enabling OS command injection",
			Severity:         "HIGH",
			CVSS:             8.0,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-27487"},
			Affected:         "OpenClaw < 2026.2.14 (macOS)",
			Published:        "2026-03-05",
			ExploitAvailable: true,
			ChainIDs:         []int{59},
		},
		{
			ID:               "CVE-2026-27488",
			Description:      "OpenClaw before 2026.2.19: Cron webhook delivery uses fetch() directly, so webhook targets can reach private/metadata/internal endpoints without SSRF policy checks",
			Severity:         "HIGH",
			CVSS:             7.3,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-27488", "https://github.com/openclaw/openclaw/commit/99db4d13e5c139883ef0def9ff963e9273179655"},
			Affected:         "OpenClaw < 2026.2.19",
			Published:        "2026-03-05",
			ExploitAvailable: true,
			ChainIDs:         []int{60},
		},
		{
			ID:               "CVE-2026-28467",
			Description:      "OpenClaw before 2026.2.2: SSRF in attachment and media URL hydration allows remote attackers to fetch arbitrary HTTP(S) URLs via model-controlled sendAttachment or auto-reply mechanisms",
			Severity:         "HIGH",
			CVSS:             8.6,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-28467"},
			Affected:         "OpenClaw < 2026.2.2",
			Published:        "2026-03-10",
			ExploitAvailable: true,
			ChainIDs:         []int{55},
		},
	}
}

// Count 返回数据库中的条目数量
func (db *Database) Count() int {
	return len(db.entries)
}

// All 返回所有 CVE 条目
func (db *Database) All() []CVEEntry {
	result := make([]CVEEntry, len(db.entries))
	copy(result, db.entries)
	return result
}

// GetByID 按 CVE ID 精确查找
func (db *Database) GetByID(id string) *CVEEntry {
	for i := range db.entries {
		if strings.EqualFold(db.entries[i].ID, id) {
			return &db.entries[i]
		}
	}
	return nil
}

// Search 按关键词搜索 CVE (匹配 ID、描述、影响版本)
func (db *Database) Search(keyword string) []CVEEntry {
	if keyword == "" {
		return db.All()
	}

	kw := strings.ToLower(keyword)
	var results []CVEEntry

	for _, entry := range db.entries {
		if strings.Contains(strings.ToLower(entry.ID), kw) ||
			strings.Contains(strings.ToLower(entry.Description), kw) ||
			strings.Contains(strings.ToLower(entry.Affected), kw) ||
			strings.Contains(strings.ToLower(entry.Severity), kw) {
			results = append(results, entry)
		}
	}

	return results
}

// SearchBySeverity 按严重级别筛选
func (db *Database) SearchBySeverity(severity string) []CVEEntry {
	sev := strings.ToUpper(severity)
	var results []CVEEntry
	for _, entry := range db.entries {
		if entry.Severity == sev {
			results = append(results, entry)
		}
	}
	return results
}

// SearchByCVSS 查找 CVSS >= threshold 的条目
func (db *Database) SearchByCVSS(threshold float64) []CVEEntry {
	var results []CVEEntry
	for _, entry := range db.entries {
		if entry.CVSS >= threshold {
			results = append(results, entry)
		}
	}
	// 按 CVSS 降序排序
	sort.Slice(results, func(i, j int) bool {
		return results[i].CVSS > results[j].CVSS
	})
	return results
}

// FetchOnline 从 NVD API 获取最新 CVE 数据
func (db *Database) FetchOnline(product string) ([]CVEEntry, error) {
	if product == "" {
		product = "open-webui"
	}

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=20", product)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("构建 NVD 请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "LobsterGuard/4.0")

	resp, err := db.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD API 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD API 返回 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB 限制
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	// 解析 NVD 2.0 响应
	var nvdResp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Description struct {
					Data []struct {
						Value string `json:"value"`
					} `json:"descriptions"`
				} `json:"descriptions"`
				Metrics struct {
					CvssV31 []struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
				Published string `json:"published"`
				Refs      struct {
					Data []struct {
						URL string `json:"url"`
					} `json:"references"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("解析 NVD 响应失败: %w", err)
	}

	var results []CVEEntry
	for _, v := range nvdResp.Vulnerabilities {
		entry := CVEEntry{
			ID:        v.CVE.ID,
			Published: v.CVE.Published,
			Affected:  product,
		}

		// 提取描述
		if descs := v.CVE.Description.Data; len(descs) > 0 {
			entry.Description = descs[0].Value
		}

		// 提取 CVSS
		if metrics := v.CVE.Metrics.CvssV31; len(metrics) > 0 {
			entry.CVSS = metrics[0].CvssData.BaseScore
			entry.Severity = metrics[0].CvssData.BaseSeverity
		}

		// 提取引用
		for _, ref := range v.CVE.Refs.Data {
			entry.References = append(entry.References, ref.URL)
		}

		// 映射攻击链
		entry.ChainIDs = db.MapToChains(entry)

		results = append(results, entry)
	}

	// 合并到数据库
	for _, r := range results {
		if db.GetByID(r.ID) == nil {
			db.entries = append(db.entries, r)
		}
	}

	return results, nil
}

// MapToChains 根据 CVE 描述和类型映射到 LobsterGuard 攻击链
func (db *Database) MapToChains(cve CVEEntry) []int {
	// 已有映射直接返回
	if len(cve.ChainIDs) > 0 {
		return cve.ChainIDs
	}

	desc := strings.ToLower(cve.Description)
	var chains []int

	// 基于关键词的映射规则
	mappings := []struct {
		keywords []string
		chainIDs []int
	}{
		{[]string{"ssrf", "server-side request"}, []int{1, 26, 44, 45}},
		{[]string{"xss", "cross-site scripting", "script injection"}, []int{6, 14, 18}},
		{[]string{"path traversal", "directory traversal", "file read"}, []int{16, 23}},
		{[]string{"sql injection", "sqli"}, []int{12, 28}},
		{[]string{"rce", "remote code execution", "command injection"}, []int{2, 7, 30}},
		{[]string{"authentication bypass", "auth bypass"}, []int{35, 41}},
		{[]string{"csrf", "cross-site request forgery"}, []int{42, 43}},
		{[]string{"credential", "secret", "api key", "token"}, []int{3, 9, 25, 27}},
		{[]string{"websocket", "ws hijack"}, []int{17, 21}},
		{[]string{"oauth", "redirect"}, []int{19}},
		{[]string{"rate limit", "brute force"}, []int{4, 38, 39}},
		{[]string{"prompt injection", "llm"}, []int{6, 31}},
	}

	for _, m := range mappings {
		for _, kw := range m.keywords {
			if strings.Contains(desc, kw) {
				chains = append(chains, m.chainIDs...)
				break
			}
		}
	}

	// 去重
	seen := make(map[int]bool)
	var unique []int
	for _, id := range chains {
		if !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}
	sort.Ints(unique)
	return unique
}

// Summary 返回数据库统计摘要
func (db *Database) Summary() map[string]interface{} {
	sevCount := map[string]int{}
	exploitable := 0
	for _, e := range db.entries {
		sevCount[e.Severity]++
		if e.ExploitAvailable {
			exploitable++
		}
	}
	return map[string]interface{}{
		"total":       len(db.entries),
		"by_severity": sevCount,
		"exploitable": exploitable,
	}
}
