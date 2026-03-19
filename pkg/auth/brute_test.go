package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMaskToken(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"ab", "****"},
		{"abcd", "****"},
		{"abcde", "ab*de"},
		{"abcdefgh", "ab****gh"},
		{"a", "****"},
		{"", "****"},
	}
	for _, tt := range tests {
		if got := maskToken(tt.input); got != tt.want {
			t.Errorf("maskToken(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDefaultBruteConfig(t *testing.T) {
	cfg := DefaultBruteConfig()
	if len(cfg.Tokens) == 0 {
		t.Error("DefaultBruteConfig().Tokens should not be empty")
	}
	if cfg.Delay != 500*time.Millisecond {
		t.Errorf("Delay = %v, want 500ms", cfg.Delay)
	}
	if !cfg.RespectLimit {
		t.Error("RespectLimit should be true")
	}
	if cfg.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", cfg.Timeout)
	}
}

func TestBuildCandidateListDedup(t *testing.T) {
	cfg := BruteConfig{Tokens: []string{"a", "b", "a", "c", "b"}}
	got := buildCandidateList(cfg)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (deduped)", len(got))
	}
	if got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("got %v, want [a b c]", got)
	}
}

func TestBuildCandidateListEmpty(t *testing.T) {
	cfg := BruteConfig{}
	got := buildCandidateList(cfg)
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

func TestBuildCandidateListWordlist(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "tokens.txt")
	if err := os.WriteFile(wl, []byte("tok1\ntok2\ntok1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := BruteConfig{
		Tokens:   []string{"inline1", "tok2"},
		Wordlist: wl,
	}
	got := buildCandidateList(cfg)
	// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍inline1, tok2 (from inline), tok1 (from file, tok2 deduped)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3, got %v", len(got), got)
	}
}

func TestBuildCandidateListBadWordlist(t *testing.T) {
	cfg := BruteConfig{
		Tokens:   []string{"a"},
		Wordlist: "/nonexistent/path/file.txt",
	}
	got := buildCandidateList(cfg)
	if len(got) != 1 {
		t.Errorf("len = %d, want 1 (only inline token)", len(got))
	}
}
