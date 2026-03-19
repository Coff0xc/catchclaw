package scan

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍OpenClaw 常见默认端口
var DefaultPorts = []int{3002, 18789, 8080, 8443, 3000, 3001, 8000, 8888, 9090}

// ParseTargets parses a multi-target input string into a list of targets.
// Supports: single host:port, comma/newline separated, CIDR (192.168.1.0/24),
// IP range (10.0.0.1-10.0.0.50), bare IP (expands to default ports).
func ParseTargets(input string, useTLS bool) []utils.Target {
	var targets []utils.Target
	seen := make(map[string]bool)

	// Split by comma, newline, semicolon, space
	lines := splitMulti(input, ",\n; ")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parsed := parseSingleEntry(line, useTLS)
		for _, t := range parsed {
			key := t.String()
			if !seen[key] {
				seen[key] = true
				targets = append(targets, t)
			}
		}
	}
	return targets
}

func splitMulti(s string, seps string) []string {
	// Replace all separators with \n then split
	for _, c := range seps {
		s = strings.ReplaceAll(s, string(c), "\n")
	}
	return strings.Split(s, "\n")
}

func parseSingleEntry(entry string, useTLS bool) []utils.Target {
	entry = strings.TrimSpace(entry)

	// Strip scheme
	for _, prefix := range []string{"https://", "wss://", "http://", "ws://"} {
		if strings.HasPrefix(entry, prefix) {
			if prefix == "https://" || prefix == "wss://" {
				useTLS = true
			}
			entry = strings.TrimPrefix(entry, prefix)
			break
		}
	}

	// CIDR: 192.168.1.0/24
	if strings.Contains(entry, "/") && !strings.Contains(entry, ":") {
		return expandCIDR(entry, useTLS)
	}

	// IP range: 10.0.0.1-10.0.0.50 or 10.0.0.1-50
	if strings.Contains(entry, "-") && !strings.Contains(entry, ":") {
		return expandRange(entry, useTLS)
	}

	// Has port: host:port
	if strings.Contains(entry, ":") {
		t, err := utils.ParseTarget(entry)
		if err == nil {
			t.UseTLS = useTLS
			return []utils.Target{t}
		}
		return nil
	}

	// Bare IP/hostname — expand to default ports
	return expandDefaultPorts(entry, useTLS)
}

func expandCIDR(cidr string, useTLS bool) []utils.Target {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	var targets []utils.Target
	for ip := cloneIP(ipNet.IP.Mask(ipNet.Mask)); ipNet.Contains(ip); incIP(ip) {
		// Skip network and broadcast for /24+
		if ip[len(ip)-1] == 0 || ip[len(ip)-1] == 255 {
			continue
		}
		targets = append(targets, expandDefaultPorts(ip.String(), useTLS)...)
	}
	return targets
}

func expandRange(rangeStr string, useTLS bool) []utils.Target {
	parts := strings.SplitN(rangeStr, "-", 2)
	if len(parts) != 2 {
		return nil
	}
	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	if startIP == nil {
		return nil
	}
	startIP = startIP.To4()
	if startIP == nil {
		return nil
	}

	endPart := strings.TrimSpace(parts[1])
	var endIP net.IP

	// Check if end is just a number (last octet)
	if n, err := strconv.Atoi(endPart); err == nil && n >= 0 && n <= 255 {
		endIP = cloneIP(startIP)
		endIP[3] = byte(n)
	} else {
		endIP = net.ParseIP(endPart)
		if endIP == nil {
			return nil
		}
		endIP = endIP.To4()
	}

	if endIP == nil {
		return nil
	}

	var targets []utils.Target
	for ip := cloneIP(startIP); !ipGreater(ip, endIP); incIP(ip) {
		targets = append(targets, expandDefaultPorts(ip.String(), useTLS)...)
	}
	return targets
}

func expandDefaultPorts(host string, useTLS bool) []utils.Target {
	var targets []utils.Target
	for _, port := range DefaultPorts {
		targets = append(targets, utils.Target{
			Host:   host,
			Port:   port,
			UseTLS: useTLS || port == 8443,
		})
	}
	return targets
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ipGreater(a, b net.IP) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] > b[i] {
			return true
		}
		if a[i] < b[i] {
			return false
		}
	}
	return false
}

// TargetCount returns the estimated number of targets for display.
func TargetCount(input string) int {
	targets := ParseTargets(input, false)
	return len(targets)
}

// FormatTargetSummary returns a human-readable summary of parsed targets.
func FormatTargetSummary(targets []utils.Target) string {
	if len(targets) == 0 {
		return "无目标"
	}
	if len(targets) == 1 {
		return targets[0].String()
	}
	return fmt.Sprintf("%d 个目标 (%s ... %s)", len(targets), targets[0].String(), targets[len(targets)-1].String())
}
