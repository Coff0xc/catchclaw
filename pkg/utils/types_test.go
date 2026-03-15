package utils

import (
	"testing"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SevInfo, "INFO"},
		{SevLow, "LOW"},
		{SevMedium, "MEDIUM"},
		{SevHigh, "HIGH"},
		{SevCritical, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestNewFinding(t *testing.T) {
	f := NewFinding("target:80", "auth", "Weak token", SevCritical, "Found default token")
	if f.Target != "target:80" {
		t.Errorf("Target = %q, want %q", f.Target, "target:80")
	}
	if f.Module != "auth" {
		t.Errorf("Module = %q, want %q", f.Module, "auth")
	}
	if f.Title != "Weak token" {
		t.Errorf("Title = %q, want %q", f.Title, "Weak token")
	}
	if f.Severity != SevCritical {
		t.Errorf("Severity = %v, want %v", f.Severity, SevCritical)
	}
	if f.Description != "Found default token" {
		t.Errorf("Description = %q", f.Description)
	}
	if f.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
}

func TestScanResult(t *testing.T) {
	target := Target{Host: "test", Port: 18789}
	sr := NewScanResult(target)

	if sr.Target.Host != "test" {
		t.Errorf("Target.Host = %q, want %q", sr.Target.Host, "test")
	}
	if len(sr.Findings) != 0 {
		t.Errorf("Findings should be empty, got %d", len(sr.Findings))
	}

	sr.Add(NewFinding("test:18789", "auth", "f1", SevHigh, "d1"))
	sr.Add(NewFinding("test:18789", "auth", "f2", SevHigh, "d2"))
	sr.Add(NewFinding("test:18789", "exploit", "f3", SevCritical, "d3"))
	sr.Add(NewFinding("test:18789", "recon", "f4", SevInfo, "d4"))

	if len(sr.Findings) != 4 {
		t.Fatalf("Findings count = %d, want 4", len(sr.Findings))
	}
	if sr.CountBySeverity(SevHigh) != 2 {
		t.Errorf("CountBySeverity(High) = %d, want 2", sr.CountBySeverity(SevHigh))
	}
	if sr.CountBySeverity(SevCritical) != 1 {
		t.Errorf("CountBySeverity(Critical) = %d, want 1", sr.CountBySeverity(SevCritical))
	}
	if sr.CountBySeverity(SevLow) != 0 {
		t.Errorf("CountBySeverity(Low) = %d, want 0", sr.CountBySeverity(SevLow))
	}

	sr.Done()
	if sr.EndAt.IsZero() {
		t.Error("EndAt should be set after Done()")
	}
}
