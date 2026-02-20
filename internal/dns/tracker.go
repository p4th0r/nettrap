// Package dns provides the DNS proxy and domain tracking for nettrap.
package dns

import (
	"net"
	"sync"
	"time"
)

// Resolution records a single DNS query and its result.
type Resolution struct {
	Timestamp time.Time
	Domain    string   // normalized (lowercase, no trailing dot)
	QueryType string   // "A", "AAAA", "CNAME", "MX", etc.
	IPs       []net.IP // resolved IPs (terminal A/AAAA records)
	CNAMEs    []string // intermediate CNAME targets (for logging only)
	Action    string   // "ALLOWED" or "BLOCKED"
}

// Tracker maintains an in-memory record of all DNS resolutions during a session.
// It is safe for concurrent use.
type Tracker struct {
	mu          sync.RWMutex
	resolutions []Resolution
	domainToIPs map[string]map[string]struct{} // domain → set of IP strings
	ipToDomains map[string]map[string]struct{} // IP string → set of domains
}

// NewTracker creates a new Tracker.
func NewTracker() *Tracker {
	return &Tracker{
		resolutions: make([]Resolution, 0),
		domainToIPs: make(map[string]map[string]struct{}),
		ipToDomains: make(map[string]map[string]struct{}),
	}
}

// RecordResolution appends a resolution to the log and updates lookup maps.
func (t *Tracker) RecordResolution(domain, queryType string, ips []net.IP, cnames []string, action string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	res := Resolution{
		Timestamp: time.Now(),
		Domain:    domain,
		QueryType: queryType,
		IPs:       ips,
		CNAMEs:    cnames,
		Action:    action,
	}
	t.resolutions = append(t.resolutions, res)

	// Update maps only for successful resolutions with IPs
	if len(ips) > 0 {
		if t.domainToIPs[domain] == nil {
			t.domainToIPs[domain] = make(map[string]struct{})
		}
		for _, ip := range ips {
			ipStr := ip.String()
			t.domainToIPs[domain][ipStr] = struct{}{}

			if t.ipToDomains[ipStr] == nil {
				t.ipToDomains[ipStr] = make(map[string]struct{})
			}
			t.ipToDomains[ipStr][domain] = struct{}{}
		}
	}
}

// GetIPsForDomain returns all IPs ever resolved for a domain.
func (t *Tracker) GetIPsForDomain(domain string) []net.IP {
	t.mu.RLock()
	defer t.mu.RUnlock()

	ipSet, ok := t.domainToIPs[domain]
	if !ok {
		return nil
	}

	ips := make([]net.IP, 0, len(ipSet))
	for ipStr := range ipSet {
		ips = append(ips, net.ParseIP(ipStr))
	}
	return ips
}

// GetDomainsForIP returns all domains that resolved to this IP.
func (t *Tracker) GetDomainsForIP(ip net.IP) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	domainSet, ok := t.ipToDomains[ip.String()]
	if !ok {
		return nil
	}

	domains := make([]string, 0, len(domainSet))
	for d := range domainSet {
		domains = append(domains, d)
	}
	return domains
}

// GetAllResolutions returns a copy of the full resolution log.
func (t *Tracker) GetAllResolutions() []Resolution {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]Resolution, len(t.resolutions))
	copy(result, t.resolutions)
	return result
}

// GetStats returns summary statistics for the session.
func (t *Tracker) GetStats() (totalQueries, blockedQueries, uniqueDomains int) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	totalQueries = len(t.resolutions)
	domains := make(map[string]struct{})
	for _, r := range t.resolutions {
		if r.Action == "BLOCKED" {
			blockedQueries++
		}
		domains[r.Domain] = struct{}{}
	}
	uniqueDomains = len(domains)
	return
}

// KnownDoHDoTServers contains IPs of well-known DNS-over-HTTPS and DNS-over-TLS providers.
var KnownDoHDoTServers = map[string]string{
	"1.1.1.1":         "Cloudflare",
	"1.0.0.1":         "Cloudflare",
	"8.8.8.8":         "Google",
	"8.8.4.4":         "Google",
	"9.9.9.9":         "Quad9",
	"149.112.112.112": "Quad9",
	"208.67.222.222":  "OpenDNS",
	"208.67.220.220":  "OpenDNS",
}

// IsKnownDoHDoT checks if an IP belongs to a known DoH/DoT provider.
func IsKnownDoHDoT(ip string) (provider string, ok bool) {
	provider, ok = KnownDoHDoTServers[ip]
	return
}
