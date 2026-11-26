package utils

import (
	"net/http"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Coff0xc/catchclaw/go/internal/config"
	"github.com/Coff0xc/catchclaw/go/internal/core"
)

func TestChallengeAndSPAFilters(t *testing.T) {
	if !IsChallengeResponse(`{"type":"challenge"}`) {
		t.Fatal("challenge json")
	}
	if IsChallengeResponse(`{"ok":true}`) {
		t.Fatal("clean json flagged")
	}
	if !IsNonAPIResponse("<!DOCTYPE html><html><div id=\"app\">x</div>", "text/html") {
		t.Fatal("html spa")
	}
	if IsNonAPIResponse(`{"data":1}`, "application/json") {
		t.Fatal("json flagged as spa")
	}
}

func TestIsRealSuccess(t *testing.T) {
	if !IsRealSuccess(200, `{"ok":true}`, "application/json") {
		t.Fatal("json 200")
	}
	if IsRealSuccess(200, "<!DOCTYPE html><html>", "text/html") {
		t.Fatal("html 200")
	}
	if IsRealSuccess(404, `{"ok":true}`, "application/json") {
		t.Fatal("404")
	}
}

func TestBuildClientTLSAndRedirect(t *testing.T) {
	skip := BuildClient(time.Second, nil, true)
	tr, ok := skip.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport type")
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("skip verify")
	}
	verify := BuildClient(time.Second, &config.ProxyConfig{HTTP: "http://127.0.0.1:9"}, false)
	tr2 := verify.Transport.(*http.Transport)
	if tr2.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("verify still skipped")
	}
	if tr2.Proxy == nil {
		t.Fatal("http proxy not installed")
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.invalid/", nil)
	if err := skip.CheckRedirect(req, []*http.Request{req}); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy = %v", err)
	}
}

func TestTruncateValidUTF8(t *testing.T) {
	got := core.TruncateStr("ééé", 3)
	if !utf8.ValidString(got) {
		t.Fatalf("invalid utf8 %q", got)
	}
}
