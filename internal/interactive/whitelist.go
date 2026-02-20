// Package interactive provides NFQUEUE-based interactive mode for nettrap.
package interactive

import (
	"net"
	"sync"

	nfdns "github.com/p4th0r/nettrap/internal/dns"
)

// Whitelist tracks approved destinations during an interactive session.
// Thread-safe for concurrent access from NFQUEUE handler and DNS callbacks.
type Whitelist struct {
	mu         sync.RWMutex
	ips        map[string]struct{} // approved individual IPs (as strings)
	domains    map[string]struct{} // approved domains (when user chooses "always")
	dnsTracker *nfdns.Tracker      // for resolving domain → IP mappings
}

// NewWhitelist creates a new session whitelist.
func NewWhitelist(dnsTracker *nfdns.Tracker) *Whitelist {
	return &Whitelist{
		ips:        make(map[string]struct{}),
		domains:    make(map[string]struct{}),
		dnsTracker: dnsTracker,
	}
}

// IsAllowed checks if a destination IP is already whitelisted.
// Checks both direct IP approval and domain-based approval
// (if the IP was resolved from an approved domain).
func (w *Whitelist) IsAllowed(ip net.IP) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Check direct IP approval
	if _, ok := w.ips[ip.String()]; ok {
		return true
	}

	// Check domain-based approval via DNS tracker
	domains := w.dnsTracker.GetDomainsForIP(ip)
	for _, domain := range domains {
		if _, ok := w.domains[domain]; ok {
			return true
		}
	}

	return false
}

// IsDomainApproved checks if a domain was approved via the "always" response.
func (w *Whitelist) IsDomainApproved(domain string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.domains[domain]
	return ok
}

// ApproveIP adds a single IP to the whitelist.
// Called when user responds 'y' (yes, this IP only).
func (w *Whitelist) ApproveIP(ip net.IP) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ips[ip.String()] = struct{}{}
}

// ApproveDomain adds a domain and ALL its currently-known IPs to the whitelist.
// Also stores the domain so that any future IPs resolving to this domain
// are automatically whitelisted.
// Called when user responds 'a' (always, this domain).
func (w *Whitelist) ApproveDomain(domain string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.domains[domain] = struct{}{}

	// Also whitelist all currently-known IPs for this domain
	ips := w.dnsTracker.GetIPsForDomain(domain)
	for _, ip := range ips {
		w.ips[ip.String()] = struct{}{}
	}
}

// ApproveIPsForDomain is called when new DNS resolutions happen for an
// already-approved domain. Keeps the whitelist in sync with new IPs.
func (w *Whitelist) ApproveIPsForDomain(domain string, ips []net.IP) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, ok := w.domains[domain]; !ok {
		return // domain not approved, nothing to do
	}

	for _, ip := range ips {
		w.ips[ip.String()] = struct{}{}
	}
}
