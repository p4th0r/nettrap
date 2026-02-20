// Package logging provides output formatting and event aggregation for nettrap.
package logging

import (
	"net"
	"time"
)

// EventType identifies the type of network event.
type EventType int

const (
	// EventDNSAllowed is a DNS query that was resolved (allowed).
	EventDNSAllowed EventType = iota
	// EventDNSBlocked is a DNS query that was refused (blocked).
	EventDNSBlocked
	// EventConnAllowed is a connection that was accepted by the firewall.
	EventConnAllowed
	// EventConnDropped is a connection that was dropped by the firewall.
	EventConnDropped
	// EventConnLogged is a connection observed in analyse mode (neither explicitly allowed nor dropped).
	EventConnLogged
	// EventDoHWarning is a connection to a known DoH/DoT server.
	EventDoHWarning
)

// Event represents a network event during a nettrap session.
type Event struct {
	Timestamp time.Time
	Type      EventType
	Protocol  string // "tcp", "udp", "icmp"
	SrcIP     net.IP
	SrcPort   uint16
	DstIP     net.IP
	DstPort   uint16
	Domain    string // enriched from DNS tracker (may be empty)
	DomainSrc string // "dns_proxy", "reverse_dns", ""
	Action    string // "ALLOWED", "BLOCKED", "DROPPED", "LOGGED"
	Extra     string // additional context (e.g., "host-port forwarded", DoH provider)

	// DNS-specific fields
	QueryType   string   // "A", "AAAA", etc.
	ResponseIPs []net.IP // resolved IPs
	CNAMEs      []string // CNAME chain

	// Interactive mode fields
	InteractiveDecision string // "approved_ip", "approved_domain", "denied", "denied_timeout"
}

// IsDNSEvent returns true if the event is a DNS event.
func (e *Event) IsDNSEvent() bool {
	return e.Type == EventDNSAllowed || e.Type == EventDNSBlocked
}

// IsConnEvent returns true if the event is a connection event.
func (e *Event) IsConnEvent() bool {
	return e.Type == EventConnAllowed || e.Type == EventConnDropped || e.Type == EventConnLogged
}
