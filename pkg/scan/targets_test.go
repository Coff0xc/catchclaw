package scan

import (
	"testing"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

func TestParseTargets_SingleHostPort(t *testing.T) {
	targets := ParseTargets("10.0.0.1:3002", false)
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].Host != "10.0.0.1" || targets[0].Port != 3002 {
		t.Errorf("unexpected target: %+v", targets[0])
	}
}

func TestParseTargets_CommaSeparated(t *testing.T) {
	targets := ParseTargets("10.0.0.1:3002,10.0.0.2:8080", false)
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
}

func TestParseTargets_NewlineSeparated(t *testing.T) {
	targets := ParseTargets("10.0.0.1:3002\n10.0.0.2:8080\n10.0.0.3:9090", false)
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}
}

func TestParseTargets_SemicolonSeparated(t *testing.T) {
	targets := ParseTargets("10.0.0.1:3002;10.0.0.2:8080", false)
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
}

func TestParseTargets_CIDR30(t *testing.T) {
	// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍/30 = 4 addresses, skip .0 network and .255 broadcast (but range is .0-.3)
	// For 10.0.0.0/30: 10.0.0.0 (skip, last octet 0), 10.0.0.1, 10.0.0.2, 10.0.0.3
	// So 3 usable IPs × len(DefaultPorts) targets
	targets := ParseTargets("10.0.0.0/30", false)
	// .0 is skipped (network), .1 .2 .3 are kept (none is 255)
	expected := 3 * len(DefaultPorts)
	if len(targets) != expected {
		t.Fatalf("expected %d targets for /30 CIDR, got %d", expected, len(targets))
	}
}

func TestParseTargets_IPRangeShort(t *testing.T) {
	// "10.0.0.1-3" → 10.0.0.1, 10.0.0.2, 10.0.0.3
	targets := ParseTargets("10.0.0.1-3", false)
	expected := 3 * len(DefaultPorts)
	if len(targets) != expected {
		t.Fatalf("expected %d targets for IP range, got %d", expected, len(targets))
	}
}

func TestParseTargets_BareIP(t *testing.T) {
	targets := ParseTargets("10.0.0.1", false)
	if len(targets) != len(DefaultPorts) {
		t.Fatalf("expected %d targets (default ports), got %d", len(DefaultPorts), len(targets))
	}
	for i, p := range DefaultPorts {
		if targets[i].Port != p {
			t.Errorf("target[%d] port = %d, want %d", i, targets[i].Port, p)
		}
	}
}

func TestParseTargets_HTTPSPrefix(t *testing.T) {
	targets := ParseTargets("https://10.0.0.1:8443", false)
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if !targets[0].UseTLS {
		t.Error("expected UseTLS=true for https:// prefix")
	}
}

func TestParseTargets_HTTPPrefix(t *testing.T) {
	targets := ParseTargets("http://10.0.0.1:3002", true) // useTLS=true but http:// should keep it
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	// http:// prefix does NOT flip useTLS to false — it just strips the prefix,
	// the useTLS param is passed through unless overridden by https/wss
	// Looking at parseSingleEntry: only https/wss set useTLS=true; http/ws just strip prefix
	// So the caller's useTLS=true is preserved for http://
	if !targets[0].UseTLS {
		t.Error("expected UseTLS=true (caller's value preserved for http:// prefix)")
	}
}

func TestParseTargets_EmptyAndCommentLines(t *testing.T) {
	// Note: splitMulti splits on spaces too, so use comma/newline-separated
	// entries with comments that have no spaces (or are standalone tokens).
	input := "#skip\n10.0.0.1:3002\n\n#ignore\n10.0.0.2:8080\n"
	targets := ParseTargets(input, false)
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets (skip empty/comment), got %d", len(targets))
	}
}

func TestParseTargets_Deduplication(t *testing.T) {
	targets := ParseTargets("10.0.0.1:3002,10.0.0.1:3002,10.0.0.1:3002", false)
	if len(targets) != 1 {
		t.Fatalf("expected 1 target after dedup, got %d", len(targets))
	}
}

func TestParseTargets_EmptyInput(t *testing.T) {
	targets := ParseTargets("", false)
	if len(targets) != 0 {
		t.Fatalf("expected 0 targets for empty input, got %d", len(targets))
	}
}

func TestParseTargets_BareIPTLSOnPort8443(t *testing.T) {
	// expandDefaultPorts forces UseTLS=true for port 8443
	targets := ParseTargets("10.0.0.1", false)
	for _, tgt := range targets {
		if tgt.Port == 8443 && !tgt.UseTLS {
			t.Error("expected UseTLS=true for port 8443")
		}
		if tgt.Port != 8443 && tgt.UseTLS {
			t.Errorf("expected UseTLS=false for port %d", tgt.Port)
		}
	}
}

func TestTargetCount(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"10.0.0.1:3002", 1},
		{"10.0.0.1:3002,10.0.0.2:8080", 2},
		{"10.0.0.1", len(DefaultPorts)},
		{"", 0},
	}
	for _, tt := range tests {
		got := TargetCount(tt.input)
		if got != tt.want {
			t.Errorf("TargetCount(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestFormatTargetSummary(t *testing.T) {
	tests := []struct {
		name    string
		targets []utils.Target
		want    string
	}{
		{
			name:    "zero targets",
			targets: nil,
			want:    "无目标",
		},
		{
			name:    "one target",
			targets: []utils.Target{{Host: "10.0.0.1", Port: 3002}},
			want:    "10.0.0.1:3002",
		},
		{
			name: "multiple targets",
			targets: []utils.Target{
				{Host: "10.0.0.1", Port: 3002},
				{Host: "10.0.0.2", Port: 8080},
				{Host: "10.0.0.3", Port: 9090},
			},
			want: "3 个目标 (10.0.0.1:3002 ... 10.0.0.3:9090)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatTargetSummary(tt.targets)
			if got != tt.want {
				t.Errorf("FormatTargetSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}
