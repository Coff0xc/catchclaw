package utils

import (
	"testing"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort int
	}{
		{"1.2.3.4:18789", "1.2.3.4", 18789},
		{"example.com", "example.com", 18789},
		{"http://1.2.3.4:8080", "1.2.3.4", 8080},
		{"https://host:443", "host", 443},
		{"  spaced:1234  ", "spaced", 1234},
		{"ws://10.0.0.1:9999", "10.0.0.1", 9999},
		{"wss://secure:18789", "secure", 18789},
		{"bare-host", "bare-host", 18789},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseTarget(tt.input)
			if err != nil {
				t.Fatalf("ParseTarget(%q) error: %v", tt.input, err)
			}
			if got.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", got.Host, tt.wantHost)
			}
			if got.Port != tt.wantPort {
				t.Errorf("Port = %d, want %d", got.Port, tt.wantPort)
			}
		})
	}
}

func TestTargetBaseURL(t *testing.T) {
	tests := []struct {
		target Target
		want   string
	}{
		{Target{Host: "h", Port: 80, UseTLS: false}, "http://h:80"},
		{Target{Host: "h", Port: 443, UseTLS: true}, "https://h:443"},
	}
	for _, tt := range tests {
		if got := tt.target.BaseURL(); got != tt.want {
			t.Errorf("BaseURL() = %q, want %q", got, tt.want)
		}
	}
}

func TestTargetWsURL(t *testing.T) {
	tests := []struct {
		target Target
		want   string
	}{
		{Target{Host: "h", Port: 80}, "ws://h:80"},
		{Target{Host: "h", Port: 443, UseTLS: true}, "wss://h:443"},
	}
	for _, tt := range tests {
		if got := tt.target.WsURL(); got != tt.want {
			t.Errorf("WsURL() = %q, want %q", got, tt.want)
		}
	}
}

func TestTargetString(t *testing.T) {
	target := Target{Host: "myhost", Port: 8080}
	if got := target.String(); got != "myhost:8080" {
		t.Errorf("String() = %q, want %q", got, "myhost:8080")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
		{"abc", 3, "abc"},
		{"abcd", 3, "abc..."},
	}
	for _, tt := range tests {
		if got := Truncate(tt.input, tt.maxLen); got != tt.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}
