package dns

import (
	"net"
	"testing"
)

func TestTracker_RecordAndLookup(t *testing.T) {
	tr := NewTracker()

	ip1 := net.ParseIP("93.184.216.34")
	ip2 := net.ParseIP("93.184.216.35")

	tr.RecordResolution("example.com", "A", []net.IP{ip1, ip2}, nil, "ALLOWED")

	// GetIPsForDomain
	ips := tr.GetIPsForDomain("example.com")
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(ips))
	}

	// GetDomainsForIP
	domains := tr.GetDomainsForIP(ip1)
	if len(domains) != 1 || domains[0] != "example.com" {
		t.Errorf("GetDomainsForIP = %v, want [example.com]", domains)
	}

	// Unknown domain
	ips = tr.GetIPsForDomain("unknown.com")
	if len(ips) != 0 {
		t.Errorf("expected empty IPs for unknown domain, got %v", ips)
	}
}

func TestTracker_MultipleDomainsToSameIP(t *testing.T) {
	tr := NewTracker()

	ip := net.ParseIP("1.2.3.4")
	tr.RecordResolution("foo.com", "A", []net.IP{ip}, nil, "ALLOWED")
	tr.RecordResolution("bar.com", "A", []net.IP{ip}, nil, "ALLOWED")

	domains := tr.GetDomainsForIP(ip)
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains for IP, got %d", len(domains))
	}
}

func TestTracker_GetStats(t *testing.T) {
	tr := NewTracker()

	tr.RecordResolution("example.com", "A", []net.IP{net.ParseIP("1.1.1.1")}, nil, "ALLOWED")
	tr.RecordResolution("blocked.com", "A", nil, nil, "BLOCKED")
	tr.RecordResolution("example.com", "AAAA", nil, nil, "ALLOWED")

	total, blocked, unique := tr.GetStats()
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if blocked != 1 {
		t.Errorf("blocked = %d, want 1", blocked)
	}
	if unique != 2 {
		t.Errorf("unique = %d, want 2", unique)
	}
}

func TestTracker_BlockedResolution(t *testing.T) {
	tr := NewTracker()

	tr.RecordResolution("blocked.com", "A", nil, nil, "BLOCKED")

	ips := tr.GetIPsForDomain("blocked.com")
	if len(ips) != 0 {
		t.Errorf("blocked domain should have no IPs, got %v", ips)
	}

	resolutions := tr.GetAllResolutions()
	if len(resolutions) != 1 {
		t.Fatalf("expected 1 resolution, got %d", len(resolutions))
	}
	if resolutions[0].Action != "BLOCKED" {
		t.Errorf("action = %q, want BLOCKED", resolutions[0].Action)
	}
}

func TestIsKnownDoHDoT(t *testing.T) {
	tests := []struct {
		ip       string
		wantOk   bool
		wantName string
	}{
		{"1.1.1.1", true, "Cloudflare"},
		{"8.8.8.8", true, "Google"},
		{"9.9.9.9", true, "Quad9"},
		{"10.0.0.1", false, ""},
	}

	for _, tt := range tests {
		provider, ok := IsKnownDoHDoT(tt.ip)
		if ok != tt.wantOk {
			t.Errorf("IsKnownDoHDoT(%q) ok = %v, want %v", tt.ip, ok, tt.wantOk)
		}
		if provider != tt.wantName {
			t.Errorf("IsKnownDoHDoT(%q) provider = %q, want %q", tt.ip, provider, tt.wantName)
		}
	}
}
