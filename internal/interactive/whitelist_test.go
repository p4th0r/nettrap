package interactive

import (
	"net"
	"testing"

	nfdns "github.com/p4th0r/nettrap/internal/dns"
)

func TestWhitelist_ApproveIP(t *testing.T) {
	tracker := nfdns.NewTracker()
	wl := NewWhitelist(tracker)

	ip := net.ParseIP("1.2.3.4")
	if wl.IsAllowed(ip) {
		t.Error("IP should not be allowed before approval")
	}

	wl.ApproveIP(ip)
	if !wl.IsAllowed(ip) {
		t.Error("IP should be allowed after approval")
	}
}

func TestWhitelist_ApproveDomain(t *testing.T) {
	tracker := nfdns.NewTracker()
	ip1 := net.ParseIP("1.2.3.4")
	ip2 := net.ParseIP("5.6.7.8")
	tracker.RecordResolution("example.com", "A", []net.IP{ip1, ip2}, nil, "ALLOWED")

	wl := NewWhitelist(tracker)

	wl.ApproveDomain("example.com")

	// All IPs from the domain should be whitelisted
	if !wl.IsAllowed(ip1) {
		t.Error("IP1 should be allowed after domain approval")
	}
	if !wl.IsAllowed(ip2) {
		t.Error("IP2 should be allowed after domain approval")
	}

	// Domain should be marked as approved
	if !wl.IsDomainApproved("example.com") {
		t.Error("domain should be approved")
	}
}

func TestWhitelist_DomainBasedLookup(t *testing.T) {
	tracker := nfdns.NewTracker()
	ip := net.ParseIP("1.2.3.4")
	tracker.RecordResolution("example.com", "A", []net.IP{ip}, nil, "ALLOWED")

	wl := NewWhitelist(tracker)
	wl.ApproveDomain("example.com")

	// New IP resolved for the same domain via DNS tracker
	ip2 := net.ParseIP("9.8.7.6")
	tracker.RecordResolution("example.com", "A", []net.IP{ip2}, nil, "ALLOWED")

	// Should be allowed via domain-based lookup from tracker
	if !wl.IsAllowed(ip2) {
		t.Error("new IP for approved domain should be allowed via domain lookup")
	}
}

func TestWhitelist_ApproveIPsForDomain(t *testing.T) {
	tracker := nfdns.NewTracker()
	wl := NewWhitelist(tracker)

	// Approve a domain first
	wl.ApproveDomain("example.com")

	// New IPs arrive for the domain
	newIPs := []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}
	wl.ApproveIPsForDomain("example.com", newIPs)

	if !wl.IsAllowed(newIPs[0]) {
		t.Error("new IP should be whitelisted after ApproveIPsForDomain")
	}
}

func TestWhitelist_ApproveIPsForDomain_UnapprovedDomain(t *testing.T) {
	tracker := nfdns.NewTracker()
	wl := NewWhitelist(tracker)

	// Don't approve the domain
	newIPs := []net.IP{net.ParseIP("10.0.0.1")}
	wl.ApproveIPsForDomain("unapproved.com", newIPs)

	if wl.IsAllowed(newIPs[0]) {
		t.Error("IP should not be whitelisted for unapproved domain")
	}
}

func TestWhitelist_UnknownIP(t *testing.T) {
	tracker := nfdns.NewTracker()
	wl := NewWhitelist(tracker)

	ip := net.ParseIP("192.168.1.1")
	if wl.IsAllowed(ip) {
		t.Error("unknown IP should not be allowed")
	}
}
