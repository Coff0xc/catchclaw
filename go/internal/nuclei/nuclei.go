package nuclei

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Template struct {
	ID       string                 `yaml:"id"`
	Info     TemplateInfo           `yaml:"info"`
	HTTP     []HTTPRequest          `yaml:"http"`
	Requests []HTTPRequest          `yaml:"requests"`
}

type TemplateInfo struct {
	Name        string      `yaml:"name"`
	Severity    string      `yaml:"severity"`
	Description string      `yaml:"description"`
	Tags        interface{} `yaml:"tags"`
	Reference   interface{} `yaml:"reference"`
}

type HTTPRequest struct {
	Method  string   `yaml:"method"`
	Path    []string `yaml:"path"`
	Body    string   `yaml:"body"`
	Headers map[string]string `yaml:"headers"`
	Matchers []Matcher `yaml:"matchers"`
}

type Matcher struct {
	Type      string   `yaml:"type"`
	Words     []string `yaml:"words"`
	Status    []int    `yaml:"status"`
	Condition string   `yaml:"condition"`
}

type Runner struct {
	TemplatesDir string
	Templates    []*Template
}

func NewRunner(templatesDir string) *Runner {
	return &Runner{
		TemplatesDir: templatesDir,
	}
}

func (r *Runner) LoadTemplates() error {
	patterns := []string{"*.yaml", "*.yml"}
	var files []string
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(r.TemplatesDir, pattern))
		files = append(files, matches...)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var tpl Template
		if err := yaml.Unmarshal(data, &tpl); err != nil {
			continue
		}

		if tpl.ID == "" {
			continue
		}

		r.Templates = append(r.Templates, &tpl)
	}

	return nil
}

func (r *Runner) ListTemplates() {
	fmt.Printf("\033[36m[*]\033[0m Loaded %d Nuclei templates\n\n", len(r.Templates))
	fmt.Printf("  %-4s %-30s %-12s %s\n", "#", "ID", "Severity", "Name")
	fmt.Printf("  %s\n", "────────────────────────────────────────────────────────────────")
	for i, tpl := range r.Templates {
		sev := tpl.Info.Severity
		if sev == "" {
			sev = "info"
		}
		fmt.Printf("  %-4d %-30s %-12s %s\n", i+1, tpl.ID, sev, tpl.Info.Name)
	}
}

func (r *Runner) RunTemplate(tpl *Template, targetURL string) (*Finding, error) {
	requests := tpl.HTTP
	if len(requests) == 0 {
		requests = tpl.Requests
	}

	for _, req := range requests {
		method := req.Method
		if method == "" {
			method = "GET"
		}

		for _, path := range req.Path {
			url := strings.ReplaceAll(path, "{{BaseURL}}", targetURL)
			if !strings.HasPrefix(url, "http") {
				url = targetURL + path
			}

			var cmd *exec.Cmd
			if method == "POST" && req.Body != "" {
				body := strings.ReplaceAll(req.Body, "{{BaseURL}}", targetURL)
				cmd = exec.Command("curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", body, url)
			} else {
				cmd = exec.Command("curl", "-s", "-X", method, url)
			}

			output, err := cmd.CombinedOutput()
			if err != nil {
				continue
			}

			body := string(output)
			for _, matcher := range req.Matchers {
				if matchMatcher(matcher, body, 200) {
					return &Finding{
						TemplateID: tpl.ID,
						Name:       tpl.Info.Name,
						Severity:   tpl.Info.Severity,
						URL:        url,
						Evidence:   truncateStr(body, 200),
					}, nil
				}
			}
		}
	}

	return nil, nil
}

func matchMatcher(m Matcher, body string, status int) bool {
	condition := m.Condition
	if condition == "" {
		condition = "or"
	}

	matched := false
	if len(m.Words) > 0 {
		for _, word := range m.Words {
			if strings.Contains(body, word) {
				matched = true
				if condition == "or" {
					return true
				}
			} else if condition == "and" {
				return false
			}
		}
	}

	if len(m.Status) > 0 {
		for _, s := range m.Status {
			if status == s {
				matched = true
				if condition == "or" {
					return true
				}
			} else if condition == "and" {
				return false
			}
		}
	}

	return matched
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

type Finding struct {
	TemplateID string
	Name       string
	Severity   string
	URL        string
	Evidence   string
}

func (r *Runner) RunAll(targetURL string) []*Finding {
	var findings []*Finding
	for _, tpl := range r.Templates {
		if f, err := r.RunTemplate(tpl, targetURL); err == nil && f != nil {
			findings = append(findings, f)
		}
	}
	return findings
}
