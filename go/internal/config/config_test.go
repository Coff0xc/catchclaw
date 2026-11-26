package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadYAMLAndMerge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catchclaw.yaml")
	body := []byte(`
scanner:
  timeout: 7
  concurrency: 4
  log_level: quiet
  aggressive: true
  tls_skip_verify: false
  callback_url: "http://oast.example/x"
proxy:
  http: "http://127.0.0.1:8080"
payload:
  enable_mutation: true
profile:
  stealth:
    scanner:
      concurrency: 2
      timeout: 30
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	fc, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := fc.Merge("", 0, 0, false, "", LogInfo)
	if cfg.Timeout != 7*time.Second || cfg.Concurrency != 4 {
		t.Fatalf("timeout/conc = %v %d", cfg.Timeout, cfg.Concurrency)
	}
	if cfg.TLSSkipVerify {
		t.Fatal("tls_skip_verify: false was ignored")
	}
	if !cfg.Aggressive || cfg.CallbackURL != "http://oast.example/x" {
		t.Fatalf("scanner fields %#v", cfg)
	}
	if cfg.Proxy.HTTP != "http://127.0.0.1:8080" {
		t.Fatalf("proxy = %#v", cfg.Proxy)
	}
	if !cfg.Quiet {
		t.Fatal("quiet from log_level")
	}

	if err := fc.ApplyProfile("stealth"); err != nil {
		t.Fatal(err)
	}
	cfg = fc.Merge("", 0, 0, false, "", LogInfo)
	if cfg.Concurrency != 2 || cfg.Timeout != 30*time.Second {
		t.Fatalf("profile overlay conc/timeout = %d %v", cfg.Concurrency, cfg.Timeout)
	}
}

func TestApplyProfileMissing(t *testing.T) {
	fc := &FileConfig{Profiles: map[string]*ProfileConfig{}}
	if err := fc.ApplyProfile("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDefaultSkipVerify(t *testing.T) {
	if !Default().TLSSkipVerify {
		t.Fatal("default must skip verify for lab scans")
	}
}

func TestCLITimeoutOverridesFile(t *testing.T) {
	fc := &FileConfig{Scanner: &ScannerConfig{Timeout: 7, Concurrency: 4}}
	cfg := fc.Merge("", 0, 0, false, "", LogInfo)
	if cfg.Timeout != 7*time.Second {
		t.Fatal(cfg.Timeout)
	}
	cfg.Timeout = 3 * time.Second
	if cfg.Timeout != 3*time.Second {
		t.Fatal("cli override lost")
	}
}

func TestParseLogLevel(t *testing.T) {
	if ParseLogLevel("DEBUG") != LogDebug || ParseLogLevel("silent") != LogQuiet {
		t.Fatal("log level parse")
	}
}
