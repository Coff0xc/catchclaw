package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

func makeScanResult() *utils.ScanResult {
	target := utils.Target{Host: "test", Port: 18789}
	sr := utils.NewScanResult(target)
	f1 := utils.NewFinding("test:18789", "auth", "Weak token", utils.SevCritical, "Default token found")
	f1.Evidence = "token: ch****me"
	f1.Remediation = "Use strong random token"
	sr.Add(f1)
	f2 := utils.NewFinding("test:18789", "recon", "Endpoints exposed", utils.SevMedium, "5 endpoints found")
	sr.Add(f2)
	sr.Done()
	return sr
}

func TestWriteJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	results := []*utils.ScanResult{makeScanResult()}

	if err := WriteJSON(results, path); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	var parsed []map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(parsed))
	}
}

func TestWriteHTML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	results := []*utils.ScanResult{makeScanResult()}

	if err := WriteHTML(results, path); err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	html := string(data)
	for _, want := range []string{"LobsterGuard", "Security Report", "Weak token", "CRITICAL", "MEDIUM"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing expected string %q", want)
		}
	}
}

func TestWriteReportDispatchJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	results := []*utils.ScanResult{makeScanResult()}

	if err := WriteReport(results, path); err != nil {
		t.Fatalf("WriteReport(.json) error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍Should be valid JSON
	var parsed interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("Expected JSON output, got unmarshal error: %v", err)
	}
}

func TestWriteReportDispatchHTML(t *testing.T) {
	dir := t.TempDir()
	results := []*utils.ScanResult{makeScanResult()}

	for _, ext := range []string{".html", ".htm"} {
		path := filepath.Join(dir, "out"+ext)
		if err := WriteReport(results, path); err != nil {
			t.Fatalf("WriteReport(%s) error: %v", ext, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "<!DOCTYPE html>") {
			t.Errorf("WriteReport(%s) should produce HTML", ext)
		}
	}
}
