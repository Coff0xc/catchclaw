package report

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LobsterGuard Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}
.container{max-width:1100px;margin:0 auto;padding:20px}
.header{background:linear-gradient(135deg,#b91c1c,#991b1b);padding:30px;border-radius:12px;margin-bottom:24px;text-align:center}
.header h1{color:#fff;font-size:28px;margin-bottom:8px}
.header .subtitle{color:#fca5a5;font-size:14px}
.stats{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
.stat{flex:1;min-width:120px;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}
.stat .num{font-size:32px;font-weight:700}
.stat .label{font-size:12px;color:#8b949e;text-transform:uppercase}
.stat.critical .num{color:#f85149}
.stat.high .num{color:#f0883e}
.stat.medium .num{color:#d29922}
.stat.low .num{color:#58a6ff}
.stat.info .num{color:#8b949e}
.target{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:16px;overflow:hidden}
.target-header{padding:16px 20px;border-bottom:1px solid #30363d;display:flex;justify-content:space-between;align-items:center}
.target-header h2{font-size:18px;color:#58a6ff}
.target-header .duration{color:#8b949e;font-size:13px}
.finding{padding:14px 20px;border-bottom:1px solid #21262d}
.finding:last-child{border-bottom:none}
.finding .sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;margin-right:8px;text-transform:uppercase}
.sev-CRITICAL{background:#f85149;color:#fff}
.sev-HIGH{background:#f0883e;color:#fff}
.sev-MEDIUM{background:#d29922;color:#fff}
.sev-LOW{background:#58a6ff;color:#fff}
.sev-INFO{background:#30363d;color:#8b949e}
.finding .title{font-weight:600;color:#c9d1d9}
.finding .desc{color:#8b949e;font-size:13px;margin-top:4px}
.finding .evidence{background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:8px 12px;margin-top:8px;font-family:monospace;font-size:12px;color:#7ee787;white-space:pre-wrap;word-break:break-all}
.finding .remedy{color:#58a6ff;font-size:12px;margin-top:6px}
.footer{text-align:center;color:#484f58;font-size:12px;margin-top:24px;padding:16px}
.no-findings{padding:20px;text-align:center;color:#3fb950}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>&#x1f99e; LobsterGuard Security Report</h1>
<div class="subtitle">Generated: {{.GeneratedAt}} | Targets: {{.TargetCount}} | Findings: {{.TotalFindings}}</div>
</div>

<div class="stats">
<div class="stat critical"><div class="num">{{.Critical}}</div><div class="label">Critical</div></div>
<div class="stat high"><div class="num">{{.High}}</div><div class="label">High</div></div>
<div class="stat medium"><div class="num">{{.Medium}}</div><div class="label">Medium</div></div>
<div class="stat low"><div class="num">{{.Low}}</div><div class="label">Low</div></div>
<div class="stat info"><div class="num">{{.Info}}</div><div class="label">Info</div></div>
</div>

{{range .Results}}
<div class="target">
<div class="target-header">
<h2>{{.TargetStr}}</h2>
<div class="duration">{{.Duration}}</div>
</div>
{{if .Findings}}
{{range .Findings}}
<div class="finding">
<span class="sev sev-{{.SevStr}}">{{.SevStr}}</span>
<span class="title">{{.Title}}</span>
<div class="desc">{{.Description}}</div>
{{if .Evidence}}<div class="evidence">{{.Evidence}}</div>{{end}}
{{if .Remediation}}<div class="remedy">&#x1f527; {{.Remediation}}</div>{{end}}
</div>
{{end}}
{{else}}
<div class="no-findings">&#x2705; No findings</div>
{{end}}
</div>
{{end}}

<div class="footer">LobsterGuard v0.1.0 — OpenClaw Security Assessment Tool</div>
</div>
</body>
</html>`

type htmlReportData struct {
	GeneratedAt   string
	TargetCount   int
	TotalFindings int
	Critical      int
	High          int
	Medium        int
	Low           int
	Info          int
	Results       []htmlTargetData
}

type htmlTargetData struct {
	TargetStr string
	Duration  string
	Findings  []htmlFindingData
}

type htmlFindingData struct {
	SevStr      string
	Title       string
	Description string
	Evidence    string
	Remediation string
}

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍WriteHTML generates an HTML report
func WriteHTML(results []*utils.ScanResult, path string) error {
	data := htmlReportData{
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		TargetCount: len(results),
	}

	for _, r := range results {
		r.Done()
		td := htmlTargetData{
			TargetStr: r.Target.String(),
			Duration:  r.EndAt.Sub(r.StartAt).Round(time.Millisecond).String(),
		}
		for _, f := range r.Findings {
			data.TotalFindings++
			switch f.Severity {
			case utils.SevCritical:
				data.Critical++
			case utils.SevHigh:
				data.High++
			case utils.SevMedium:
				data.Medium++
			case utils.SevLow:
				data.Low++
			case utils.SevInfo:
				data.Info++
			}
			td.Findings = append(td.Findings, htmlFindingData{
				SevStr:      f.Severity.String(),
				Title:       f.Title,
				Description: f.Description,
				Evidence:    f.Evidence,
				Remediation: f.Remediation,
			})
		}
		data.Results = append(data.Results, td)
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	fmt.Printf("\n[*] HTML report saved to %s\n", path)
	return nil
}

// WriteReport dispatches to the correct format writer
func WriteReport(results []*utils.ScanResult, path string) error {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm"):
		return WriteHTML(results, path)
	default:
		return WriteJSON(results, path)
	}
}
