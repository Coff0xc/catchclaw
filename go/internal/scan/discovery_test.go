package scan

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/Coff0xc/catchclaw/go/internal/core"
)

func TestDetectPlatformDify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"name":"Dify","version":"1"}`))
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	got, _ := DetectPlatform(host, port, false, 2*time.Second)
	if got != core.PlatformDify {
		t.Fatalf("platform = %q, want dify", got)
	}
}

func TestPortScanLocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	open := PortScan("127.0.0.1", []int{port, 1}, 500*time.Millisecond, 4)
	found := false
	for _, p := range open {
		if p == port {
			found = true
		}
	}
	if !found {
		t.Fatalf("open = %v, want %d", open, port)
	}
}
