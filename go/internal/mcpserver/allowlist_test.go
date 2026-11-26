package mcpserver

import (
	"io"
	"testing"
)

func TestValidateTargetPrivateDefault(t *testing.T) {
	s := New(Options{AuditLog: io.Discard})
	if _, err := s.validateTarget("127.0.0.1:8080"); err != nil {
		t.Fatalf("loopback: %v", err)
	}
	if _, err := s.validateTarget("10.9.8.7:1"); err != nil {
		t.Fatalf("rfc1918: %v", err)
	}
	if _, err := s.validateTarget("192.168.1.1:65535"); err != nil {
		t.Fatalf("192.168: %v", err)
	}
}

func TestValidateTargetPublicDenied(t *testing.T) {
	s := New(Options{AuditLog: io.Discard})
	if _, err := s.validateTarget("8.8.8.8:53"); err == nil {
		t.Fatal("public IP must be denied")
	}
}

func TestValidateTargetExtraAllow(t *testing.T) {
	s := New(Options{AllowedTargets: []string{"203.0.113.9/32"}, AuditLog: io.Discard})
	if _, err := s.validateTarget("203.0.113.9:443"); err != nil {
		t.Fatalf("explicit allow: %v", err)
	}
	if _, err := s.validateTarget("203.0.113.10:443"); err == nil {
		t.Fatal("neighbor IP must stay denied")
	}
}

func TestValidateTargetRejectsJunk(t *testing.T) {
	s := New(Options{AuditLog: io.Discard})
	cases := []string{"", "no-port", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:80/x", "host name:80"}
	for _, c := range cases {
		if _, err := s.validateTarget(c); err == nil {
			t.Fatalf("accepted %q", c)
		}
	}
}

func TestClampTimeout(t *testing.T) {
	s := New(Options{AuditLog: io.Discard})
	if s.clampTimeout(0) != 10 || s.clampTimeout(-1) != 10 {
		t.Fatal("default")
	}
	if s.clampTimeout(9999) != maxTimeoutSec {
		t.Fatal("cap")
	}
	if s.clampTimeout(15) != 15 {
		t.Fatal("passthrough")
	}
}
