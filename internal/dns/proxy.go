package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/p4th0r/nettrap/internal/logging"
)

// Proxy is a DNS proxy server that listens on a veth interface and forwards
// queries to an upstream resolver. It supports allow-list filtering and
// tracks all domain→IP resolutions for the session.
type Proxy struct {
	listenAddr   string
	upstream     string
	tracker      *Tracker
	allowChecker AllowChecker
	logger       *logging.StderrLogger
	udpServer    *dns.Server
	tcpServer    *dns.Server
	ctx          context.Context
	cancel       context.CancelFunc

	// OnAllowedResolve is called when an allowed domain is resolved to IPs.
	// Phase 3 wires this up for dynamic nftables set updates.
	OnAllowedResolve func(domain string, ips []net.IP)

	// OnResolve is called for every successful DNS resolution, regardless of mode.
	// Used by interactive mode to auto-whitelist IPs for approved domains.
	OnResolve func(domain string, ips []net.IP)

	// EventCh receives DNS events for the central event logger.
	// If nil, events are logged directly to stderr via the logger.
	EventCh chan<- logging.Event
}

// ProxyConfig holds the configuration for creating a new DNS Proxy.
type ProxyConfig struct {
	ListenAddr   string       // e.g., "10.200.42.1:53"
	Upstream     string       // upstream DNS server IP (e.g., "1.1.1.1")
	Tracker      *Tracker     // domain→IP mapping tracker
	AllowChecker AllowChecker // nil = allow all (analyse/interactive mode)
	Logger       *logging.StderrLogger
}

// NewProxy creates a new DNS proxy. Call Start() to begin serving.
func NewProxy(cfg ProxyConfig) *Proxy {
	ctx, cancel := context.WithCancel(context.Background())

	// Ensure upstream has port
	upstream := cfg.Upstream
	if !strings.Contains(upstream, ":") {
		upstream = upstream + ":53"
	}

	return &Proxy{
		listenAddr:   cfg.ListenAddr,
		upstream:     upstream,
		tracker:      cfg.Tracker,
		allowChecker: cfg.AllowChecker,
		logger:       cfg.Logger,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Start begins serving DNS on both UDP and TCP. Non-blocking.
func (p *Proxy) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", p.handleQuery)

	p.udpServer = &dns.Server{
		Addr:    p.listenAddr,
		Net:     "udp",
		Handler: mux,
	}

	p.tcpServer = &dns.Server{
		Addr:    p.listenAddr,
		Net:     "tcp",
		Handler: mux,
	}

	// Start UDP
	udpReady := make(chan error, 1)
	go func() {
		udpReady <- p.udpServer.ListenAndServe()
	}()

	// Start TCP
	tcpReady := make(chan error, 1)
	go func() {
		tcpReady <- p.tcpServer.ListenAndServe()
	}()

	// Give servers a moment to bind or fail
	select {
	case err := <-udpReady:
		if err != nil {
			return fmt.Errorf("starting UDP DNS server on %s: %w", p.listenAddr, err)
		}
	case <-time.After(500 * time.Millisecond):
		// Server started successfully (still running)
	}

	select {
	case err := <-tcpReady:
		if err != nil {
			p.udpServer.Shutdown()
			return fmt.Errorf("starting TCP DNS server on %s: %w", p.listenAddr, err)
		}
	case <-time.After(500 * time.Millisecond):
		// Server started successfully (still running)
	}

	p.logger.Debug("DNS proxy listening on %s (UDP+TCP), upstream %s", p.listenAddr, p.upstream)
	return nil
}

// Stop gracefully shuts down the DNS proxy.
func (p *Proxy) Stop() error {
	p.cancel()

	var errs []string
	if p.udpServer != nil {
		if err := p.udpServer.Shutdown(); err != nil {
			errs = append(errs, fmt.Sprintf("UDP shutdown: %v", err))
		}
	}
	if p.tcpServer != nil {
		if err := p.tcpServer.Shutdown(); err != nil {
			errs = append(errs, fmt.Sprintf("TCP shutdown: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("stopping DNS proxy: %s", strings.Join(errs, "; "))
	}
	return nil
}

// handleQuery processes a single DNS query.
func (p *Proxy) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		return
	}

	q := req.Question[0]
	domain := normalizeDomain(q.Name)
	queryType := dns.TypeToString[q.Qtype]

	// Check allow-list if configured
	if p.allowChecker != nil && !p.allowChecker.IsDomainAllowed(domain) {
		// Return REFUSED
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeRefused)
		w.WriteMsg(resp)

		p.tracker.RecordResolution(domain, queryType, nil, nil, "BLOCKED")
		p.emitDNSEvent(domain, queryType, "BLOCKED", nil, nil)
		return
	}

	// Forward to upstream
	resp, cnames, ips, err := p.forwardQuery(req)
	if err != nil {
		p.logger.Debug("DNS upstream error for %s: %v", domain, err)

		// Return SERVFAIL
		fail := new(dns.Msg)
		fail.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(fail)

		p.tracker.RecordResolution(domain, queryType, nil, nil, "ALLOWED")
		return
	}

	// Record resolution
	p.tracker.RecordResolution(domain, queryType, ips, cnames, "ALLOWED")

	// Notify firewall of newly resolved IPs (Phase 3 callback)
	if p.OnAllowedResolve != nil && len(ips) > 0 {
		p.OnAllowedResolve(domain, ips)
	}

	// Notify interactive mode of all resolutions (for auto-whitelisting)
	if p.OnResolve != nil && len(ips) > 0 {
		p.OnResolve(domain, ips)
	}

	p.emitDNSEvent(domain, queryType, "ALLOWED", ips, cnames)

	// Send upstream response back unmodified
	w.WriteMsg(resp)
}

// forwardQuery sends the query to the upstream resolver and extracts IPs and CNAMEs.
func (p *Proxy) forwardQuery(req *dns.Msg) (resp *dns.Msg, cnames []string, ips []net.IP, err error) {
	client := &dns.Client{
		Timeout: 5 * time.Second,
		Net:     "udp",
	}

	resp, _, err = client.Exchange(req, p.upstream)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("upstream query: %w", err)
	}

	// If truncated, retry over TCP
	if resp.Truncated {
		client.Net = "tcp"
		resp, _, err = client.Exchange(req, p.upstream)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("upstream TCP retry: %w", err)
		}
	}

	// Extract IPs and CNAMEs from answer section
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A)
		case *dns.AAAA:
			ips = append(ips, v.AAAA)
		case *dns.CNAME:
			cnames = append(cnames, normalizeDomain(v.Target))
		}
	}

	return resp, cnames, ips, nil
}

// emitDNSEvent sends a DNS event to the event channel, or falls back to direct
// stderr logging if no event channel is configured.
func (p *Proxy) emitDNSEvent(domain, queryType, action string, ips []net.IP, cnames []string) {
	if p.EventCh != nil {
		evType := logging.EventDNSAllowed
		if action == "BLOCKED" {
			evType = logging.EventDNSBlocked
		}
		ev := logging.Event{
			Timestamp:   time.Now(),
			Type:        evType,
			Domain:      domain,
			QueryType:   queryType,
			Action:      action,
			ResponseIPs: ips,
			CNAMEs:      cnames,
		}
		select {
		case p.EventCh <- ev:
		case <-p.ctx.Done():
		}
		return
	}
	// Fallback: direct stderr logging
	p.logger.DNSEvent(domain, queryType, action, ips, cnames)
}
