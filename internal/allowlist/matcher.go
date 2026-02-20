package allowlist

import (
	"fmt"
	"net"
	"strings"

	nfdns "github.com/p4th0r/nettrap/internal/dns"
)

// Matcher checks domains and IPs against the parsed allow-list.
// It implements dns.AllowChecker for use with the DNS proxy.
type Matcher struct {
	domains *nfdns.DomainAllowList // domain matching (exact + wildcard)
	ips     map[string]struct{}    // set of allowed IP strings
	cidrs   []*net.IPNet           // list of allowed CIDRs
	entries []Entry                // all parsed entries
}

// NewMatcher creates a Matcher from parsed allow-list entries.
func NewMatcher(entries []Entry) (*Matcher, error) {
	m := &Matcher{
		ips:     make(map[string]struct{}),
		entries: entries,
	}

	var exactDomains []string
	var wildcards []string

	for _, e := range entries {
		switch e.Type {
		case EntryExactDomain:
			exactDomains = append(exactDomains, e.Domain)
		case EntryWildcard:
			wildcards = append(wildcards, "*."+e.Domain)
		case EntryIPv4, EntryIPv6:
			m.ips[e.IP.String()] = struct{}{}
		case EntryCIDR:
			m.cidrs = append(m.cidrs, e.Network)
		}
	}

	m.domains = nfdns.NewDomainAllowList(exactDomains, wildcards)

	return m, nil
}

// IsDomainAllowed checks if a domain matches the allow-list.
// Implements dns.AllowChecker interface.
func (m *Matcher) IsDomainAllowed(domain string) bool {
	return m.domains.IsDomainAllowed(domain)
}

// IsIPAllowed checks if an IP matches static IPs or CIDRs in the allow-list.
// Note: IPs dynamically added from DNS resolution are handled by nftables sets,
// not by this matcher. This only checks the statically configured entries.
func (m *Matcher) IsIPAllowed(ip net.IP) bool {
	if _, ok := m.ips[ip.String()]; ok {
		return true
	}
	for _, cidr := range m.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// GetStaticIPs returns all explicit IPs from the allow-list (EntryIPv4 + EntryIPv6).
// Used to pre-populate nftables sets.
func (m *Matcher) GetStaticIPs() []net.IP {
	var ips []net.IP
	for _, e := range m.entries {
		if e.Type == EntryIPv4 || e.Type == EntryIPv6 {
			ips = append(ips, e.IP)
		}
	}
	return ips
}

// GetCIDRs returns all CIDR entries. Used to pre-populate nftables sets.
func (m *Matcher) GetCIDRs() []*net.IPNet {
	cidrs := make([]*net.IPNet, len(m.cidrs))
	copy(cidrs, m.cidrs)
	return cidrs
}

// GetEntries returns all parsed entries. Used for dry-run display and logging.
func (m *Matcher) GetEntries() []Entry {
	return m.entries
}

// Summary returns a human-readable summary: "5 domains, 2 CIDRs, 1 IPs"
func (m *Matcher) Summary() string {
	var domainCount, wildcardCount, ipCount, cidrCount int
	for _, e := range m.entries {
		switch e.Type {
		case EntryExactDomain:
			domainCount++
		case EntryWildcard:
			wildcardCount++
		case EntryIPv4, EntryIPv6:
			ipCount++
		case EntryCIDR:
			cidrCount++
		}
	}

	parts := []string{}
	total := domainCount + wildcardCount
	if total > 0 {
		parts = append(parts, fmt.Sprintf("%d domains", total))
	}
	if cidrCount > 0 {
		parts = append(parts, fmt.Sprintf("%d CIDRs", cidrCount))
	}
	if ipCount > 0 {
		parts = append(parts, fmt.Sprintf("%d IPs", ipCount))
	}

	if len(parts) == 0 {
		return "0 entries"
	}
	return strings.Join(parts, ", ")
}
