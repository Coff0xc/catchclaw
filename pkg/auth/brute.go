package auth

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// DefaultTokens are commonly seen weak/default tokens for OpenClaw
var DefaultTokens = []string{
	"change-me-to-a-long-random-token",
	"openclaw",
	"OpenClaw",
	"test",
	"test123",
	"admin",
	"admin123",
	"password",
	"token",
	"secret",
	"123456",
	"default",
	"gateway",
	"lobster",
	"demo",
	"dev",
	"development",
	"staging",
	"production",
	"abc123",
	"letmein",
	"changeme",
	"1234567890",
	"qwerty",
	"master",
	"root",
}

// BruteConfig configures the brute force behavior
type BruteConfig struct {
	Wordlist     string        // path to wordlist file
	Tokens       []string      // inline token list
	Delay        time.Duration // delay between attempts
	MaxAttempts  int           // max attempts before stopping (0 = unlimited)
	RespectLimit bool          // back off on rate limit responses
	Timeout      time.Duration // HTTP timeout
}

// DefaultBruteConfig returns sensible defaults
func DefaultBruteConfig() BruteConfig {
	return BruteConfig{
		Tokens:       DefaultTokens,
		Delay:        500 * time.Millisecond,
		MaxAttempts:  0,
		RespectLimit: true,
		Timeout:      10 * time.Second,
	}
}

// BruteResult holds the result of a brute force attempt
type BruteResult struct {
	Found    bool
	Token    string
	Method   string // "token" or "password"
	Attempts int
}

// TokenBrute performs token/password brute force against the Gateway
func TokenBrute(target utils.Target, cfg BruteConfig) (*BruteResult, []utils.Finding) {
	var findings []utils.Finding
	tStr := target.String()
	base := target.BaseURL()
	client := utils.HTTPClient(cfg.Timeout)

	fmt.Printf("\n[*] Starting token brute force on %s ...\n", tStr)

	// Build candidate list
	candidates := buildCandidateList(cfg)
	if len(candidates) == 0 {
		fmt.Printf("  [-] No candidates to test\n")
		return nil, findings
	}
	fmt.Printf("  [*] Loaded %d candidates\n", len(candidates))

	// First, confirm auth is required
	status, _, _, err := utils.DoRequest(client, "POST", base+"/v1/chat/completions",
		map[string]string{"Content-Type": "application/json"},
		strings.NewReader(`{"model":"probe","messages":[{"role":"user","content":"ping"}]}`))
	if err != nil {
		fmt.Printf("  [-] Target unreachable: %v\n", err)
		return nil, findings
	}
	if status == 200 || status == 400 {
		fmt.Printf("  [!] Target has no auth — brute force unnecessary\n")
		return &BruteResult{Found: true, Token: "", Method: "none", Attempts: 0}, findings
	}
	if status != 401 && status != 403 {
		fmt.Printf("  [-] Unexpected status %d, aborting brute force\n", status)
		return nil, findings
	}

	// Brute force loop
	result := &BruteResult{}
	rateLimitHits := 0

	for i, candidate := range candidates {
		if cfg.MaxAttempts > 0 && i >= cfg.MaxAttempts {
			fmt.Printf("  [*] Max attempts (%d) reached, stopping\n", cfg.MaxAttempts)
			break
		}

		result.Attempts = i + 1

		// Try as Bearer token
		found, method, respStatus := tryCredential(client, base, candidate)
		if found {
			result.Found = true
			result.Token = candidate
			result.Method = method
			f := utils.NewFinding(tStr, "auth",
				fmt.Sprintf("Weak %s credential found", method),
				utils.SevCritical,
				fmt.Sprintf("Gateway %s '%s' found via brute force (%d attempts)", method, maskToken(candidate), i+1))
			f.Evidence = fmt.Sprintf("Credential: %s (method: %s)", maskToken(candidate), method)
			f.Remediation = "Use a strong random token: openssl rand -hex 32"
			findings = append(findings, f)
			fmt.Printf("  [!!!] FOUND! %s = '%s' (attempt %d)\n", method, maskToken(candidate), i+1)
			return result, findings
		}

		// Check for rate limiting (from the same response)
		if respStatus == 429 {
			rateLimitHits++
			if cfg.RespectLimit {
				waitTime := 65 * time.Second // default lockout window + buffer
				fmt.Printf("  [*] Rate limited (hit %d), waiting %v ...\n", rateLimitHits, waitTime)
				time.Sleep(waitTime)
			}
		}

		// Progress
		if (i+1)%10 == 0 {
			fmt.Printf("  [*] Tested %d/%d candidates ...\n", i+1, len(candidates))
		}

		if cfg.Delay > 0 {
			time.Sleep(cfg.Delay)
		}
	}

	fmt.Printf("  [-] No valid credentials found (%d attempts)\n", result.Attempts)
	if result.Attempts > 0 {
		f := utils.NewFinding(tStr, "auth", "Token brute force completed — no weak creds found",
			utils.SevInfo,
			fmt.Sprintf("Tested %d candidates, none valid", result.Attempts))
		findings = append(findings, f)
	}

	return result, findings
}

func tryCredential(client *http.Client, base, cred string) (bool, string, int) {
	// Try as Bearer token first
	status, _, _, err := utils.DoRequest(client, "POST", base+"/v1/chat/completions",
		map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + cred,
		},
		strings.NewReader(`{"model":"probe","messages":[]}`))
	if err != nil {
		return false, "", 0
	}
	if status == 200 || status == 400 {
		return true, "token", status
	}
	return false, "", status
}

func buildCandidateList(cfg BruteConfig) []string {
	seen := make(map[string]bool)
	var candidates []string

	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			candidates = append(candidates, s)
		}
	}

	// Add inline tokens first
	for _, t := range cfg.Tokens {
		add(t)
	}

	// Load wordlist file
	if cfg.Wordlist != "" {
		f, err := os.Open(cfg.Wordlist)
		if err != nil {
			fmt.Printf("  [!] Cannot open wordlist %s: %v\n", cfg.Wordlist, err)
		} else {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				add(scanner.Text())
			}
		}
	}

	return candidates
}

func maskToken(token string) string {
	if len(token) <= 4 {
		return "****"
	}
	return token[:2] + strings.Repeat("*", len(token)-4) + token[len(token)-2:]
}
