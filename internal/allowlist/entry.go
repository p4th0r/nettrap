// Package allowlist provides parsing and matching of allow-list entries
// (domains, wildcards, IPs, CIDRs) for nettrap's allow mode.
package allowlist

import (
	"fmt"
	"net"
)

// EntryType indicates the kind of allow-list entry.
type EntryType int

const (
	EntryExactDomain EntryType = iota // "example.com"
	EntryWildcard                     // "*.example.com"
	EntryIPv4                         // "93.184.216.34"
	EntryIPv6                         // "2606:2800:220:1::248"
	EntryCIDR                         // "10.10.10.0/24"
)

// Entry represents a single parsed allow-list entry.
type Entry struct {
	Type     EntryType  // classified type
	Raw      string     // original string as provided by user
	Domain   string     // normalized domain (for EntryExactDomain and EntryWildcard)
	IP       net.IP     // parsed IP (for EntryIPv4 and EntryIPv6)
	Network  *net.IPNet // parsed CIDR (for EntryCIDR)
	Wildcard string     // suffix for matching, e.g. ".example.com" (for EntryWildcard)
}

// String returns a human-readable representation of the entry.
func (e Entry) String() string {
	switch e.Type {
	case EntryExactDomain:
		return fmt.Sprintf("domain   %s", e.Domain)
	case EntryWildcard:
		return fmt.Sprintf("wildcard *.%s", e.Domain)
	case EntryIPv4:
		return fmt.Sprintf("ip       %s", e.IP)
	case EntryIPv6:
		return fmt.Sprintf("ip       %s", e.IP)
	case EntryCIDR:
		return fmt.Sprintf("cidr     %s", e.Network)
	default:
		return e.Raw
	}
}
