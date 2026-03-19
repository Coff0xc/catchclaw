package utils

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍Target represents a scan target
type Target struct {
	Host     string
	Port     int
	UseTLS   bool
	Token    string // optional pre-known token
	Password string // optional pre-known password
}

func (t Target) BaseURL() string {
	scheme := "http"
	if t.UseTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, t.Host, t.Port)
}

func (t Target) WsURL() string {
	scheme := "ws"
	if t.UseTLS {
		scheme = "wss"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, t.Host, t.Port)
}

func (t Target) String() string {
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

// ParseTarget parses "host:port" string into Target
// Supports URL format: https://host:port, http://host:port
// Auto-detects TLS from scheme (https/wss) or port 443
func ParseTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	useTLS := false
	// strip scheme if present, remember TLS
	for _, prefix := range []string{"https://", "wss://"} {
		if strings.HasPrefix(raw, prefix) {
			raw = strings.TrimPrefix(raw, prefix)
			useTLS = true
			break
		}
	}
	for _, prefix := range []string{"http://", "ws://"} {
		if strings.HasPrefix(raw, prefix) {
			raw = strings.TrimPrefix(raw, prefix)
			break
		}
	}
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		// try default port
		host = raw
		return Target{Host: host, Port: 18789, UseTLS: useTLS}, nil
	}
	port := 18789
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		port = 18789
	}
	// Auto-detect TLS from port
	if port == 443 {
		useTLS = true
	}
	return Target{Host: host, Port: port, UseTLS: useTLS}, nil
}

// SkipTLSVerify controls whether TLS certificate verification is skipped.
// Default true — pentest tools typically target self-signed or internal certs.
// Set to false via --tls-verify flag for strict certificate validation.
var SkipTLSVerify = true

// HTTPClient returns a configured http client.
// Does NOT follow redirects — returns the original status code so callers
// can distinguish 301/302 (auth redirect) from real 200 (no auth).
func HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: SkipTLSVerify},
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Stop following redirects — return the redirect response directly.
			// This prevents OAuth/Cognito 302→200 false positives.
			return http.ErrUseLastResponse
		},
	}
}

// DoRequest performs an HTTP request and returns status, body, headers
func DoRequest(client *http.Client, method, url string, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "LobsterGuard/1.0")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return resp.StatusCode, nil, resp.Header, err
	}
	return resp.StatusCode, respBody, resp.Header, nil
}

// Truncate trims a string to maxLen, appending "..." if truncated.
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
