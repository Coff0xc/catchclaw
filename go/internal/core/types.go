package core

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	return []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}[s]
}

func (s Severity) Score() int {
	return []int{1, 3, 8, 15, 25}[s]
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", strings.ToLower(s.String()))), nil
}

type Target struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	UseTLS   bool     `json:"use_tls"`
	Token    string   `json:"token,omitempty"`
	Platform Platform `json:"platform,omitempty"`
}

type Platform string

const (
	PlatformUnknown     Platform = ""
	PlatformOpenClaw    Platform = "openclaw"
	PlatformDify        Platform = "dify"
	PlatformFastGPT     Platform = "fastgpt"
	PlatformLobeChat    Platform = "lobechat"
	PlatformNextChat    Platform = "nextchat"
	PlatformAnythingLLM Platform = "anythingllm"
	PlatformFlowise     Platform = "flowise"
	PlatformRagFlow     Platform = "ragflow"
	PlatformLibreChat   Platform = "librechat"
	PlatformLangflow    Platform = "langflow"
	PlatformLiteLLM     Platform = "litellm"
	PlatformOllama      Platform = "ollama"
	PlatformVLLM        Platform = "vllm"
	PlatformCrewAI      Platform = "crewai"
	PlatformLangChain   Platform = "langchain"
	PlatformRay         Platform = "ray"
	PlatformMLflow      Platform = "mlflow"
	PlatformGradio      Platform = "gradio"
	PlatformComfyUI     Platform = "comfyui"
	PlatformDBGPT       Platform = "dbgpt"
	PlatformChromaDB    Platform = "chromadb"
	PlatformQdrant      Platform = "qdrant"
	PlatformWeaviate    Platform = "weaviate"
	PlatformMilvus      Platform = "milvus"
	PlatformLocalAI     Platform = "localai"
	PlatformXinference  Platform = "xinference"
	PlatformJupyter     Platform = "jupyter"
)

func (t *Target) BaseURL() string {
	scheme := "http"
	if t.UseTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, t.Host, t.Port)
}

func (t *Target) WSURL() string {
	scheme := "ws"
	if t.UseTLS {
		scheme = "wss"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, t.Host, t.Port)
}

func (t Target) String() string {
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

type Finding struct {
	Target      string   `json:"target"`
	Module      string   `json:"module"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Timestamp   string   `json:"timestamp"`
}

func NewFinding(target, module, title string, sev Severity, desc string) Finding {
	return Finding{
		Target:      target,
		Module:      module,
		Title:       title,
		Severity:    sev,
		Description: desc,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}
}

func (f Finding) WithEvidence(e string) Finding {
	f.Evidence = e
	return f
}

func (f Finding) WithRemediation(r string) Finding {
	f.Remediation = r
	return f
}

func (f Finding) Print() {
	sevStr := f.Severity.String()
	fmt.Printf("  [%s] %s\n", colorSeverity(sevStr), f.Title)
	fmt.Printf("    Module: %s\n", f.Module)
	fmt.Printf("    %s\n", f.Description)
	if f.Evidence != "" {
		fmt.Printf("    Evidence: %s\n", TruncateStr(f.Evidence, 200))
	}
}

func colorSeverity(s string) string {
	switch s {
	case "CRITICAL":
		return "\033[41;37;1m" + s + "\033[0m"
	case "HIGH":
		return "\033[31m" + s + "\033[0m"
	case "MEDIUM":
		return "\033[33m" + s + "\033[0m"
	case "LOW":
		return "\033[34m" + s + "\033[0m"
	default:
		return "\033[36m" + s + "\033[0m"
	}
}

type ScanResult struct {
	Target   Target    `json:"target"`
	Findings []Finding `json:"findings"`
	StartAt  string    `json:"start_at"`
	EndAt    string    `json:"end_at,omitempty"`
}

func NewScanResult(t Target) *ScanResult {
	return &ScanResult{
		Target:   t,
		Findings: []Finding{},
		StartAt:  time.Now().UTC().Format(time.RFC3339),
	}
}

func (r *ScanResult) Add(f Finding) {
	r.Findings = append(r.Findings, f)
}

func (r *ScanResult) Done() {
	r.EndAt = time.Now().UTC().Format(time.RFC3339)
}

func (r *ScanResult) CountBySeverity(s Severity) int {
	c := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			c++
		}
	}
	return c
}

func (r *ScanResult) ChainScore() int {
	score := 0
	for _, f := range r.Findings {
		score += f.Severity.Score()
	}
	if score > 100 {
		return 100
	}
	return score
}

func TruncateStr(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	end := maxBytes
	for end > 0 && !isCharBoundary(s, end) {
		end--
	}
	return s[:end]
}

func isCharBoundary(s string, i int) bool {
	return s[i]&0xC0 != 0x80
}

const MaxGeneratedIPs = 65536

func ParseTargets(spec string, tls bool) []Target {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	if strings.Contains(spec, ",") {
		var targets []Target
		for _, part := range strings.Split(spec, ",") {
			targets = append(targets, ParseTargets(strings.TrimSpace(part), tls)...)
		}
		return targets
	}
	if targets := tryParseCIDR(spec, tls); targets != nil {
		return targets
	}
	if targets := tryParseRange(spec, tls); targets != nil {
		return targets
	}
	return []Target{parseSingleTarget(spec, tls)}
}

func parseSingleTarget(spec string, tls bool) Target {
	host := spec
	port := 8080
	if tls {
		port = 443
	}
	if idx := strings.LastIndex(spec, ":"); idx > 0 && !strings.Contains(spec[idx+1:], ":") {
		host = spec[:idx]
		if p, err := parsePort(spec[idx+1:]); err == nil {
			port = p
		}
	}
	return Target{Host: host, Port: port, UseTLS: tls}
}

func parsePort(s string) (int, error) {
	var p int
	_, err := fmt.Sscanf(s, "%d", &p)
	return p, err
}

func tryParseCIDR(spec string, tls bool) []Target {
	slashIdx := strings.Index(spec, "/")
	if slashIdx < 0 {
		return nil
	}
	ipStr := spec[:slashIdx]
	afterSlash := spec[slashIdx+1:]

	prefix := afterSlash
	port := 0
	if colonIdx := strings.Index(afterSlash, ":"); colonIdx >= 0 {
		prefix = afterSlash[:colonIdx]
		fmt.Sscanf(afterSlash[colonIdx+1:], "%d", &port)
	}

	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return nil
	}
	var prefixLen int
	fmt.Sscanf(prefix, "%d", &prefixLen)
	if prefixLen > 32 {
		return nil
	}

	if port == 0 {
		if tls {
			port = 443
		} else {
			port = 8080
		}
	}

	hostBits := 32 - prefixLen
	count := 1 << hostBits
	if count > MaxGeneratedIPs {
		return nil
	}

	ipU32 := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	network := ipU32 &^ (uint32(1)<<hostBits - 1)
	skipEndpoints := prefixLen < 31 && hostBits >= 2

	var targets []Target
	for i := 0; i < count; i++ {
		if skipEndpoints && (i == 0 || i == count-1) {
			continue
		}
		addr := network + uint32(i)
		targets = append(targets, Target{
			Host:   fmt.Sprintf("%d.%d.%d.%d", byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)),
			Port:   port,
			UseTLS: tls,
		})
	}
	return targets
}

func tryParseRange(spec string, tls bool) []Target {
	dashIdx := strings.Index(spec, "-")
	if dashIdx < 0 {
		return nil
	}
	startStr := spec[:dashIdx]
	startIP := net.ParseIP(startStr).To4()
	if startIP == nil {
		return nil
	}

	afterDash := spec[dashIdx+1:]
	endStr := afterDash
	port := 0
	if colonIdx := strings.LastIndex(afterDash, ":"); colonIdx >= 0 {
		candidate := afterDash[:colonIdx]
		if net.ParseIP(candidate).To4() != nil {
			endStr = candidate
			fmt.Sscanf(afterDash[colonIdx+1:], "%d", &port)
		}
	}

	endIP := net.ParseIP(endStr).To4()
	if endIP == nil {
		return nil
	}

	startU32 := uint32(startIP[0])<<24 | uint32(startIP[1])<<16 | uint32(startIP[2])<<8 | uint32(startIP[3])
	endU32 := uint32(endIP[0])<<24 | uint32(endIP[1])<<16 | uint32(endIP[2])<<8 | uint32(endIP[3])

	if endU32 < startU32 {
		return nil
	}
	count := endU32 - startU32 + 1
	if count > MaxGeneratedIPs {
		return nil
	}

	if port == 0 {
		if tls {
			port = 443
		} else {
			port = 8080
		}
	}

	var targets []Target
	for i := startU32; i <= endU32; i++ {
		targets = append(targets, Target{
			Host:   fmt.Sprintf("%d.%d.%d.%d", byte(i>>24), byte(i>>16), byte(i>>8), byte(i)),
			Port:   port,
			UseTLS: tls,
		})
	}
	return targets
}

func ParseTargetsFile(path string, tls bool) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var targets []Target
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, ParseTargets(line, tls)...)
	}
	return targets, nil
}
