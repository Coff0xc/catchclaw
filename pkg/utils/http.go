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

// Target represents a scan target
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
func ParseTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	// strip scheme if present
	for _, prefix := range []string{"https://", "http://", "wss://", "ws://"} {
		if strings.HasPrefix(raw, prefix) {
			raw = strings.TrimPrefix(raw, prefix)
			break
		}
	}
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		// try default port
		host = raw
		return Target{Host: host, Port: 18789}, nil
	}
	port := 18789
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		port = 18789
	}
	return Target{Host: host, Port: port}, nil
}

// SkipTLSVerify controls whether TLS certificate verification is skipped.
// Default true — pentest tools typically target self-signed or internal certs.
// Set to false via --tls-verify flag for strict certificate validation.
var SkipTLSVerify = true

// HTTPClient returns a configured http client
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
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
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
