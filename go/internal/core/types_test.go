package core

import (
	"testing"
)

func TestParseTargetsSingleAndComma(t *testing.T) {
	got := ParseTargets("10.0.0.5:9000", false)
	if len(got) != 1 || got[0].Host != "10.0.0.5" || got[0].Port != 9000 || got[0].UseTLS {
		t.Fatalf("single = %#v", got)
	}
	got = ParseTargets("a.example:1,b.example:2", true)
	if len(got) != 2 || !got[0].UseTLS || got[1].Port != 2 {
		t.Fatalf("comma = %#v", got)
	}
}

func TestParseTargetsDefaultPort(t *testing.T) {
	http := ParseTargets("127.0.0.1", false)
	if http[0].Port != 8080 {
		t.Fatalf("http default port = %d", http[0].Port)
	}
	https := ParseTargets("127.0.0.1", true)
	if https[0].Port != 443 {
		t.Fatalf("tls default port = %d", https[0].Port)
	}
}

func TestTargetURLs(t *testing.T) {
	t0 := Target{Host: "127.0.0.1", Port: 8080}
	if t0.BaseURL() != "http://127.0.0.1:8080" || t0.WSURL() != "ws://127.0.0.1:8080" {
		t.Fatalf("plain urls %s %s", t0.BaseURL(), t0.WSURL())
	}
	t1 := Target{Host: "127.0.0.1", Port: 443, UseTLS: true}
	if t1.BaseURL() != "https://127.0.0.1:443" || t1.WSURL() != "wss://127.0.0.1:443" {
		t.Fatalf("tls urls %s %s", t1.BaseURL(), t1.WSURL())
	}
}

func TestSeverityScoreAndChainCap(t *testing.T) {
	if Critical.Score() != 25 || Info.Score() != 1 {
		t.Fatalf("scores %d %d", Critical.Score(), Info.Score())
	}
	r := NewScanResult(Target{Host: "h", Port: 1})
	for i := 0; i < 10; i++ {
		r.Add(NewFinding("h:1", "m", "t", Critical, "d"))
	}
	if r.ChainScore() != 100 {
		t.Fatalf("cap = %d", r.ChainScore())
	}
}

func TestTruncateUTF8(t *testing.T) {
	if TruncateStr("abc", 10) != "abc" {
		t.Fatal("short string changed")
	}
	got := TruncateStr("ééé", 3)
	if len(got) > 3 {
		t.Fatalf("too long %q", got)
	}
}
