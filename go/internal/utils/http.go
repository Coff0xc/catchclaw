package utils

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Coff0xc/catchclaw/go/internal/config"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Apple) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
}

func BuildClient(timeout time.Duration, proxyCfg *config.ProxyConfig, skipTLSVerify bool) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: skipTLSVerify},
		DialContext: (&netDialer{
			timeout: timeout,
		}).DialContext,
	}

	if proxyCfg != nil {
		switch {
		case proxyCfg.SOCKS5 != "":
			transport.Proxy = func(req *http.Request) (*url.URL, error) {
				return url.Parse(proxyCfg.SOCKS5)
			}
		case proxyCfg.HTTPS != "":
			transport.Proxy = func(req *http.Request) (*url.URL, error) {
				return url.Parse(proxyCfg.HTTPS)
			}
		case proxyCfg.HTTP != "":
			transport.Proxy = func(req *http.Request) (*url.URL, error) {
				return url.Parse(proxyCfg.HTTP)
			}
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type netDialer struct {
	timeout time.Duration
}

func (d *netDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: d.timeout}).DialContext(ctx, network, addr)
}

func AuthHeaders(token string) map[string]string {
	h := map[string]string{"Content-Type": "application/json"}
	if token != "" {
		h["Authorization"] = "Bearer " + token
	}
	return h
}

func RandomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func IsChallengeResponse(body string) bool {
	markers := []string{"connect.challenge", "\"type\":\"challenge\"", "challenge-response", "x-challenge-token"}
	lower := strings.ToLower(body)
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

func IsNonAPIResponse(body string, contentType string) bool {
	if strings.Contains(contentType, "text/html") && strings.Contains(body, "<!DOCTYPE") {
		return true
	}
	return isSPAFallback(body)
}

func isSPAFallback(body string) bool {
	markers := []string{"<app-root>", "<div id=\"app\"", "__NEXT_DATA__", "window.__NUXT__"}
	for _, m := range markers {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

func IsRealSuccess(status int, body, contentType string) bool {
	return status >= 200 && status < 300 && !IsChallengeResponse(body) && !IsNonAPIResponse(body, contentType)
}

var refusalPhrases = []string{
	"i cannot", "i can't", "i'm not able", "i am not able", "i must decline",
	"i'm unable", "as an ai", "i don't have the ability", "not possible for me",
	"i apologize", "i'm sorry, but", "against my programming", "ethical guidelines",
	"i cannot comply", "i won't",
}

func IsRefusal(text string) bool {
	lower := strings.ToLower(text)
	for _, p := range refusalPhrases {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func IsWAFBlocked(status int, body string) bool {
	if status == 403 || status == 406 || status == 400 {
		return true
	}
	indicators := []string{"blocked", "forbidden", "waf", "firewall", "security", "attack detected", "malicious", "rejected", "access denied", "cloudflare", "akamai", "incapsula", "sucuri"}
	lower := strings.ToLower(body)
	for _, w := range indicators {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func StatusText(code int) string {
	return fmt.Sprintf("%d", code)
}
