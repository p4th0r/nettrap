package dns

import (
	"strings"
)

// AllowChecker determines if a domain is permitted by the allow-list.
// In analyse and interactive modes, this is nil (all domains allowed).
type AllowChecker interface {
	IsDomainAllowed(domain string) bool
}

// DomainAllowList implements AllowChecker with exact and wildcard domain matching.
type DomainAllowList struct {
	exactDomains map[string]struct{} // exact domain matches (lowercase)
	wildcards    []string            // wildcard suffixes (e.g., ".target.com" for *.target.com)
}

// NewDomainAllowList creates a new DomainAllowList from exact domains and wildcard patterns.
// Exact domains should be plain domain names (e.g., "target.com").
// Wildcards should be in the form "*.target.com" — the leading "*." is stripped
// and stored as a suffix ".target.com".
func NewDomainAllowList(exact []string, wildcards []string) *DomainAllowList {
	dal := &DomainAllowList{
		exactDomains: make(map[string]struct{}, len(exact)),
		wildcards:    make([]string, 0, len(wildcards)),
	}

	for _, d := range exact {
		dal.exactDomains[normalizeDomain(d)] = struct{}{}
	}

	for _, w := range wildcards {
		// Convert "*.target.com" to suffix ".target.com"
		w = normalizeDomain(w)
		if strings.HasPrefix(w, "*.") {
			dal.wildcards = append(dal.wildcards, w[1:]) // store ".target.com"
		}
	}

	return dal
}

// IsDomainAllowed returns true if the domain matches the allow-list.
func (dal *DomainAllowList) IsDomainAllowed(domain string) bool {
	domain = normalizeDomain(domain)

	// Exact match
	if _, ok := dal.exactDomains[domain]; ok {
		return true
	}

	// Wildcard match: *.target.com matches foo.target.com but NOT target.com
	for _, suffix := range dal.wildcards {
		if strings.HasSuffix(domain, suffix) && domain != suffix[1:] {
			return true
		}
	}

	return false
}

// normalizeDomain lowercases and strips trailing dot from a domain name.
func normalizeDomain(domain string) string {
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	return domain
}
