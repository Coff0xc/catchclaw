package discovery

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍DiscoveryConfig holds API keys and search parameters
type DiscoveryConfig struct {
	ShodanKey  string
	FofaEmail  string
	FofaKey    string
	Query      string
	MaxResults int
	Timeout    time.Duration
}

// DiscoveryResult holds a discovered target
type DiscoveryResult struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Hostname string `json:"hostname,omitempty"`
	Version  string `json:"version,omitempty"`
	Source   string `json:"source"`
}

// ShodanSearch queries Shodan for OpenClaw instances
func ShodanSearch(cfg DiscoveryConfig) ([]DiscoveryResult, error) {
	if cfg.ShodanKey == "" {
		return nil, fmt.Errorf("shodan API key required")
	}
	query := cfg.Query
	if query == "" {
		query = "port:18789"
	}
	maxResults := cfg.MaxResults
	if maxResults <= 0 {
		maxResults = 100
	}

	fmt.Printf("[*] Shodan search: %s\n", query)

	apiURL := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&minify=true",
		url.QueryEscape(cfg.ShodanKey), url.QueryEscape(query))

	client := &http.Client{Timeout: cfg.Timeout}
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("shodan request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("shodan API %d: %s", resp.StatusCode, truncBody(body))
	}

	var sr struct {
		Total   int `json:"total"`
		Matches []struct {
			IPStr     string   `json:"ip_str"`
			Port      int      `json:"port"`
			Hostnames []string `json:"hostnames"`
			Version   string   `json:"version"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("parse shodan: %w", err)
	}

	fmt.Printf("[+] Shodan: %d total results\n", sr.Total)

	var results []DiscoveryResult
	for i, m := range sr.Matches {
		if i >= maxResults {
			break
		}
		hostname := ""
		if len(m.Hostnames) > 0 {
			hostname = m.Hostnames[0]
		}
		results = append(results, DiscoveryResult{
			IP: m.IPStr, Port: m.Port, Hostname: hostname,
			Version: m.Version, Source: "shodan",
		})
	}
	fmt.Printf("[+] Shodan: %d targets collected\n", len(results))
	return results, nil
}

// FofaSearch queries FOFA for OpenClaw instances
func FofaSearch(cfg DiscoveryConfig) ([]DiscoveryResult, error) {
	if cfg.FofaEmail == "" || cfg.FofaKey == "" {
		return nil, fmt.Errorf("fofa email and key required")
	}
	query := cfg.Query
	if query == "" {
		query = `port="18789"`
	}
	maxResults := cfg.MaxResults
	if maxResults <= 0 {
		maxResults = 100
	}

	fmt.Printf("[*] FOFA search: %s\n", query)

	qb64 := base64.StdEncoding.EncodeToString([]byte(query))
	apiURL := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=%d&fields=ip,port,host",
		url.QueryEscape(cfg.FofaEmail), url.QueryEscape(cfg.FofaKey), qb64, maxResults)

	client := &http.Client{Timeout: cfg.Timeout}
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("fofa request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fofa API %d: %s", resp.StatusCode, truncBody(body))
	}

	var fr struct {
		Error   bool       `json:"error"`
		ErrMsg  string     `json:"errmsg"`
		Size    int        `json:"size"`
		Results [][]string `json:"results"`
	}
	if err := json.Unmarshal(body, &fr); err != nil {
		return nil, fmt.Errorf("parse fofa: %w", err)
	}
	if fr.Error {
		return nil, fmt.Errorf("fofa: %s", fr.ErrMsg)
	}

	fmt.Printf("[+] FOFA: %d results\n", fr.Size)

	var results []DiscoveryResult
	for _, r := range fr.Results {
		if len(r) < 3 {
			continue
		}
		port := 18789
		fmt.Sscanf(r[1], "%d", &port)
		results = append(results, DiscoveryResult{
			IP: r[0], Port: port, Hostname: r[2], Source: "fofa",
		})
	}
	fmt.Printf("[+] FOFA: %d targets collected\n", len(results))
	return results, nil
}

// Discover runs all configured sources and deduplicates
func Discover(cfg DiscoveryConfig) ([]utils.Target, error) {
	seen := make(map[string]bool)
	var targets []utils.Target

	add := func(results []DiscoveryResult) {
		for _, r := range results {
			key := fmt.Sprintf("%s:%d", r.IP, r.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			targets = append(targets, utils.Target{Host: r.IP, Port: r.Port})
		}
	}

	if cfg.ShodanKey != "" {
		if results, err := ShodanSearch(cfg); err != nil {
			fmt.Printf("[!] Shodan error: %v\n", err)
		} else {
			add(results)
		}
	}
	if cfg.FofaEmail != "" && cfg.FofaKey != "" {
		if results, err := FofaSearch(cfg); err != nil {
			fmt.Printf("[!] FOFA error: %v\n", err)
		} else {
			add(results)
		}
	}

	fmt.Printf("[*] Total unique targets: %d\n", len(targets))
	return targets, nil
}

// WriteTargets writes discovered targets to a file
func WriteTargets(targets []utils.Target, path string) error {
	var lines []string
	for _, t := range targets {
		lines = append(lines, t.String())
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func truncBody(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}
