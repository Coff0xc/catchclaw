package cli

import (
	"github.com/Coff0xc/catchclaw/go/internal/core"
	"testing"
)

func TestParsePlatform(t *testing.T) {
	cases := map[string]core.Platform{
		"dify":           core.PlatformDify,
		"Open-WebUI":     core.PlatformOpenClaw,
		"ollama":         core.PlatformOllama,
		"jupyter":        core.PlatformJupyter,
		"not-a-platform": core.PlatformUnknown,
		"chroma":         core.PlatformChromaDB,
	}
	for in, want := range cases {
		if got := parsePlatform(in); got != want {
			t.Errorf("parsePlatform(%q) = %q, want %q", in, got, want)
		}
	}
}
