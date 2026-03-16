package utils

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

// Severity levels
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "INFO"
	case SevLow:
		return "LOW"
	case SevMedium:
		return "MEDIUM"
	case SevHigh:
		return "HIGH"
	case SevCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) Color() *color.Color {
	switch s {
	case SevCritical:
		return color.New(color.FgRed, color.Bold)
	case SevHigh:
		return color.New(color.FgRed)
	case SevMedium:
		return color.New(color.FgYellow)
	case SevLow:
		return color.New(color.FgCyan)
	default:
		return color.New(color.FgWhite)
	}
}

// Finding represents a security finding
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
		Target:    target,
		Module:    module,
		Title:     title,
		Severity:  sev,
		Description: desc,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

func (f Finding) Print() {
	sev := f.Severity.Color()
	fmt.Printf("  ")
	sev.Printf("[%s]", f.Severity)
	fmt.Printf(" %s\n", f.Title)
	if f.Description != "" {
		fmt.Printf("         %s\n", f.Description)
	}
	if f.Evidence != "" {
		evidenceLines := strings.Split(f.Evidence, "\n")
		for _, line := range evidenceLines {
			fmt.Printf("         > %s\n", line)
		}
	}
}

// ScanResult holds all findings for a target
type ScanResult struct {
	Target   Target    `json:"target"`
	Findings []Finding `json:"findings"`
	StartAt  time.Time `json:"start_at"`
	EndAt    time.Time `json:"end_at"`
}

func NewScanResult(t Target) *ScanResult {
	return &ScanResult{
		Target:   t,
		Findings: []Finding{},
		StartAt:  time.Now(),
	}
}

func (r *ScanResult) Add(f Finding) {
	r.Findings = append(r.Findings, f)
}

func (r *ScanResult) Done() {
	r.EndAt = time.Now()
}

func (r *ScanResult) CountBySeverity(sev Severity) int {
	count := 0
	for _, f := range r.Findings {
		if f.Severity == sev {
			count++
		}
	}
	return count
}

// Banner prints the tool banner
func Banner() {
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan)
	red.Println(`
    __    ____  ____  _____ ______ ______ ____     ________ __ ___    ____  ____
   / /   / __ \/ __ )/ ___//_  __// ____// __ \   / ____/ // //   |  / __ \/ __ \
  / /   / / / / __  |\__ \  / /  / __/  / /_/ /  / / __/ // // /| | / /_/ / / / /
 / /___/ /_/ / /_/ /___/ / / /  / /___ / _, _/  / /_/ /__  _/ ___ |/ _, _/ /_/ /
/_____/\____/_____//____/ /_/  /_____//_/ |_|   \____/  /_//_/  |_/_/ |_/_____/  `)
	cyan.Println("                    OpenClaw Security Assessment Tool v3.0.0")
	fmt.Println(strings.Repeat("─", 76))
}
