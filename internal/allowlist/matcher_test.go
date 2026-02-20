package allowlist

import (
	"net"
	"testing"
)

func buildMatcher(t *testing.T, raw string) *Matcher {
	t.Helper()
	entries, err := Parse(raw, "")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	m, err := NewMatcher(entries)
	if err != nil {
		t.Fatalf("matcher error: %v", err)
	}
	return m
}

func TestMatcherDomainExact(t *testing.T) {
	m := buildMatcher(t, "example.com,target.com")

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"EXAMPLE.COM", true},
		{"example.com.", true},
		{"target.com", true},
		{"other.com", false},
		{"sub.example.com", false},
	}

	for _, tt := range tests {
		got := m.IsDomainAllowed(tt.domain)
		if got != tt.want {
			t.Errorf("IsDomainAllowed(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestMatcherDomainWildcard(t *testing.T) {
	m := buildMatcher(t, "*.example.com")

	tests := []struct {
		domain string
		want   bool
	}{
		{"sub.example.com", true},
		{"deep.sub.example.com", true},
		{"example.com", false}, // wildcard doesn't match base
		{"notexample.com", false},
	}

	for _, tt := range tests {
		got := m.IsDomainAllowed(tt.domain)
		if got != tt.want {
			t.Errorf("IsDomainAllowed(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestMatcherDomainBothExactAndWildcard(t *testing.T) {
	m := buildMatcher(t, "example.com,*.example.com")

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"other.com", false},
	}

	for _, tt := range tests {
		got := m.IsDomainAllowed(tt.domain)
		if got != tt.want {
			t.Errorf("IsDomainAllowed(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestMatcherIPAllowed(t *testing.T) {
	m := buildMatcher(t, "1.2.3.4,10.0.0.0/8")

	tests := []struct {
		ip   string
		want bool
	}{
		{"1.2.3.4", true},
		{"1.2.3.5", false},
		{"10.1.2.3", true},
		{"10.255.255.255", true},
		{"11.0.0.1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := m.IsIPAllowed(ip)
		if got != tt.want {
			t.Errorf("IsIPAllowed(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestMatcherGetStaticIPs(t *testing.T) {
	m := buildMatcher(t, "1.2.3.4,example.com,10.0.0.0/8,5.6.7.8")
	ips := m.GetStaticIPs()
	if len(ips) != 2 {
		t.Fatalf("expected 2 static IPs, got %d", len(ips))
	}
}

func TestMatcherGetCIDRs(t *testing.T) {
	m := buildMatcher(t, "1.2.3.4,10.0.0.0/8,172.16.0.0/12")
	cidrs := m.GetCIDRs()
	if len(cidrs) != 2 {
		t.Fatalf("expected 2 CIDRs, got %d", len(cidrs))
	}
}

func TestMatcherSummary(t *testing.T) {
	m := buildMatcher(t, "example.com,*.target.com,1.2.3.4,10.0.0.0/8")
	s := m.Summary()
	if s != "2 domains, 1 CIDRs, 1 IPs" {
		t.Errorf("unexpected summary: %q", s)
	}
}

func TestMatcherEmptyEntries(t *testing.T) {
	m, err := NewMatcher(nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.IsDomainAllowed("example.com") {
		t.Error("empty matcher should not allow any domain")
	}
	if m.Summary() != "0 entries" {
		t.Errorf("unexpected summary: %q", m.Summary())
	}
}
