package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// Analyzer uses LLM APIs to analyze scan findings and recommend attack paths
type Analyzer struct {
	Provider string // "openai" or "anthropic"
	Model    string
	APIKey   string
	BaseURL  string
	Timeout  time.Duration
}

// AnalysisResult contains LLM-assisted analysis output
type AnalysisResult struct {
	Summary         string   `json:"summary"`
	CriticalPaths   []string `json:"critical_paths"`
	AttackChains    []string `json:"attack_chains"`
	Recommendations []string `json:"recommendations"`
	RiskScore       int      `json:"risk_score"` // 0-100
	FalsePositives  []string `json:"false_positives,omitempty"`
	RawResponse     string   `json:"raw_response,omitempty"`
}

// NewAnalyzer creates an AI analyzer from environment variables
func NewAnalyzer() *Analyzer {
	a := &Analyzer{Timeout: 60 * time.Second}

	// Auto-detect provider from available API keys
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		a.Provider = "anthropic"
		a.APIKey = key
		a.Model = envOr("LOBSTER_AI_MODEL", "claude-sonnet-4-20250514")
		a.BaseURL = envOr("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
	} else if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		a.Provider = "openai"
		a.APIKey = key
		a.Model = envOr("LOBSTER_AI_MODEL", "gpt-4o")
		a.BaseURL = envOr("OPENAI_BASE_URL", "https://api.openai.com")
	}

	return a
}

// Available returns true if an API key is configured
func (a *Analyzer) Available() bool {
	return a.APIKey != ""
}

// AnalyzeFindings sends scan findings to LLM for intelligent analysis
func (a *Analyzer) AnalyzeFindings(findings []utils.Finding, mode string) (*AnalysisResult, error) {
	if !a.Available() {
		return a.localAnalysis(findings, mode), nil
	}

	prompt := buildAnalysisPrompt(findings, mode)

	var response string
	var err error
	switch a.Provider {
	case "anthropic":
		response, err = a.callAnthropic(prompt)
	case "openai":
		response, err = a.callOpenAI(prompt)
	default:
		return a.localAnalysis(findings, mode), nil
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[AI] API call failed, using local analysis: %v\n", err)
		return a.localAnalysis(findings, mode), nil
	}

	result := parseAIResponse(response)
	result.RawResponse = response
	return result, nil
}

// localAnalysis provides rule-based analysis without LLM
func (a *Analyzer) localAnalysis(findings []utils.Finding, mode string) *AnalysisResult {
	result := &AnalysisResult{}

	critCount := 0
	highCount := 0
	categories := make(map[string]int)

	for _, f := range findings {
		categories[f.Module]++
		switch f.Severity {
		case utils.SevCritical:
			critCount++
		case utils.SevHigh:
			highCount++
		}
	}

	// Risk score
	result.RiskScore = min(100, critCount*25+highCount*15+len(findings)*2)

	// Summary
	result.Summary = fmt.Sprintf("Scan found %d findings (%d critical, %d high). Risk score: %d/100.",
		len(findings), critCount, highCount, result.RiskScore)

	// Attack chains from findings
	if critCount > 0 {
		result.CriticalPaths = append(result.CriticalPaths,
			fmt.Sprintf("%d critical vulnerabilities require immediate remediation", critCount))
	}

	// Module-based recommendations
	for mod, count := range categories {
		if count >= 2 {
			result.AttackChains = append(result.AttackChains,
				fmt.Sprintf("Module '%s' has %d findings — systematic weakness", mod, count))
		}
	}

	// Sort attack chains for consistent output
	sort.Strings(result.AttackChains)

	// Generic recommendations
	if categories["auth_mode_abuse"] > 0 || categories["fingerprint"] > 0 {
		result.Recommendations = append(result.Recommendations, "Enforce auth.mode=token with strong token")
	}
	if categories["mcp_inject"] > 0 {
		result.Recommendations = append(result.Recommendations, "Audit all MCP plugin command fields; whitelist allowed executables")
	}
	if categories["acp_bypass"] > 0 {
		result.Recommendations = append(result.Recommendations, "Unify ACP tool name resolution to single source")
	}
	if categories["unicode_bypass"] > 0 {
		result.Recommendations = append(result.Recommendations, "Extend Unicode folding to cover all bidi/combining/variation chars")
	}
	if categories["secret_exec_abuse"] > 0 {
		result.Recommendations = append(result.Recommendations, "Remove allowInsecurePath option from secret exec provider")
	}

	if len(result.Recommendations) == 0 {
		result.Recommendations = append(result.Recommendations, "No critical issues found — maintain security monitoring")
	}

	return result
}

func buildAnalysisPrompt(findings []utils.Finding, mode string) string {
	var sb strings.Builder
	sb.WriteString("You are a security analyst reviewing OpenClaw Gateway scan results.\n\n")

	switch mode {
	case "triage":
		sb.WriteString("Task: Triage findings by severity and urgency. Identify false positives.\n")
	case "attack-path":
		sb.WriteString("Task: Identify viable attack chains by linking findings into exploitation paths.\n")
	case "remediation":
		sb.WriteString("Task: Provide prioritized remediation recommendations for each finding.\n")
	default:
		sb.WriteString("Task: Provide comprehensive security analysis including triage, attack paths, and remediations.\n")
	}

	sb.WriteString("\nFindings:\n")
	for i, f := range findings {
		sb.WriteString(fmt.Sprintf("%d. [%s] %s (module: %s)\n   %s\n",
			i+1, f.Severity, f.Title, f.Module, f.Description))
		if f.Evidence != "" {
			sb.WriteString(fmt.Sprintf("   Evidence: %s\n", utils.Truncate(f.Evidence, 200)))
		}
	}

	sb.WriteString("\nProvide your analysis as JSON with keys: summary, critical_paths, attack_chains, recommendations, risk_score (0-100), false_positives\n")
	return sb.String()
}

func (a *Analyzer) callAnthropic(prompt string) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"model":      a.Model,
		"max_tokens": 4096,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
	})

	req, _ := http.NewRequest("POST", a.BaseURL+"/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: a.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("anthropic API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	json.Unmarshal(respBody, &result)
	if len(result.Content) > 0 {
		return result.Content[0].Text, nil
	}
	return "", fmt.Errorf("empty response")
}

func (a *Analyzer) callOpenAI(prompt string) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"model":      a.Model,
		"max_tokens": 4096,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
	})

	req, _ := http.NewRequest("POST", a.BaseURL+"/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.APIKey)

	client := &http.Client{Timeout: a.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("openai API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.Unmarshal(respBody, &result)
	if len(result.Choices) > 0 {
		return result.Choices[0].Message.Content, nil
	}
	return "", fmt.Errorf("empty response")
}

func parseAIResponse(response string) *AnalysisResult {
	result := &AnalysisResult{}

	// Try JSON parse first
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start >= 0 && end > start {
		json.Unmarshal([]byte(response[start:end+1]), result)
	}

	// Fallback: use raw text as summary
	if result.Summary == "" {
		result.Summary = utils.Truncate(response, 500)
	}

	return result
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
