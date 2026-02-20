package interactive

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	nfdns "github.com/p4th0r/nettrap/internal/dns"
	"github.com/p4th0r/nettrap/internal/logging"
)

// Response represents the user's decision for a prompted connection.
type Response int

const (
	// ResponseYes approves this IP only.
	ResponseYes Response = iota
	// ResponseAlways approves the entire domain.
	ResponseAlways
	// ResponseNo denies the connection.
	ResponseNo
	// ResponseDetail requests more details before deciding.
	ResponseDetail
)

// Prompter handles user-facing prompts on stderr and reads responses from stdin.
type Prompter struct {
	timeout    time.Duration
	dnsTracker *nfdns.Tracker
	logger     *logging.StderrLogger
	mu         sync.Mutex // serialize prompts (one at a time)
	ctx        context.Context
	reader     *bufio.Reader
	rdnCache   map[string]string // reverse DNS cache
	rdnMu      sync.Mutex
}

// NewPrompter creates a new Prompter.
func NewPrompter(ctx context.Context, timeout time.Duration, dnsTracker *nfdns.Tracker, logger *logging.StderrLogger) *Prompter {
	return &Prompter{
		timeout:    timeout,
		dnsTracker: dnsTracker,
		logger:     logger,
		ctx:        ctx,
		reader:     bufio.NewReader(os.Stdin),
		rdnCache:   make(map[string]string),
	}
}

// Prompt displays a connection prompt and waits for user input.
// Returns the user's decision. Blocks until input, timeout, or context cancellation.
func (p *Prompter) Prompt(dstIP net.IP, dstPort uint16, protocol string, domain string) Response {
	p.mu.Lock()
	defer p.mu.Unlock()

	hasDomain := domain != ""

	p.printPromptBox(dstIP, dstPort, protocol, domain)
	p.printPromptLine(hasDomain, false)

	return p.readResponse(dstIP, dstPort, protocol, domain, hasDomain, false)
}

func (p *Prompter) printPromptBox(dstIP net.IP, dstPort uint16, protocol string, domain string) {
	w := os.Stderr
	fmt.Fprintf(w, "[nettrap] ┌─ NEW CONNECTION ────────────────────────────\n")
	fmt.Fprintf(w, "[nettrap] │ Destination: %s:%d/%s\n", dstIP, dstPort, protocol)
	if domain != "" {
		fmt.Fprintf(w, "[nettrap] │ Domain:      %s (via DNS proxy)\n", domain)
	} else {
		fmt.Fprintf(w, "[nettrap] │ Domain:      (unknown — no DNS query observed)\n")
	}
	fmt.Fprintf(w, "[nettrap] └─────────────────────────────────────────────\n")
}

func (p *Prompter) printDetailsBox(dstIP net.IP, dstPort uint16, protocol string, domain string) {
	w := os.Stderr
	fmt.Fprintf(w, "[nettrap] ┌─ DETAILS ──────────────────────────────────\n")
	fmt.Fprintf(w, "[nettrap] │ IP:          %s\n", dstIP)
	fmt.Fprintf(w, "[nettrap] │ Port:        %d/%s\n", dstPort, protocol)

	if domain != "" {
		fmt.Fprintf(w, "[nettrap] │ Domain:      %s (via DNS proxy)\n", domain)
	} else {
		fmt.Fprintf(w, "[nettrap] │ Domain:      (unknown — no DNS query observed)\n")
	}

	// Reverse DNS lookup (cached)
	rdns := p.lookupReverseDNS(dstIP)
	fmt.Fprintf(w, "[nettrap] │ Reverse DNS: %s\n", rdns)

	if domain == "" {
		fmt.Fprintf(w, "[nettrap] │ Note:        No matching DNS query — tool used hardcoded IP\n")
	} else {
		// Show all IPs for the domain
		allIPs := p.dnsTracker.GetIPsForDomain(domain)
		if len(allIPs) > 1 {
			ipStrs := make([]string, len(allIPs))
			for i, ip := range allIPs {
				ipStrs[i] = ip.String()
			}
			fmt.Fprintf(w, "[nettrap] │ All IPs:     %s\n", strings.Join(ipStrs, ", "))
		}
	}

	fmt.Fprintf(w, "[nettrap] └─────────────────────────────────────────────\n")
}

func (p *Prompter) printPromptLine(hasDomain bool, afterDetails bool) {
	w := os.Stderr
	if hasDomain {
		fmt.Fprintf(w, "[nettrap] Allow? [y]es / [n]o / [a]lways (domain) / [d]etails: ")
	} else {
		if afterDetails {
			// After details, don't show [d] again
			fmt.Fprintf(w, "[nettrap] Allow? [y]es / [n]o: ")
		} else {
			fmt.Fprintf(w, "[nettrap] Allow? [y]es / [n]o / [d]etails: ")
		}
	}
}

func (p *Prompter) readResponse(dstIP net.IP, dstPort uint16, protocol string, domain string, hasDomain bool, afterDetails bool) Response {
	for {
		input, err := p.readLineWithTimeout()
		if err != nil {
			if err == errTimeout {
				fmt.Fprintf(os.Stderr, "\n[nettrap] ⏱ Timeout (%s) — connection denied\n", p.timeout)
				return ResponseNo
			}
			// Context cancelled or other error
			return ResponseNo
		}

		input = strings.TrimSpace(strings.ToLower(input))

		if input == "" {
			// Empty = deny (safe default)
			return ResponseNo
		}

		switch input[0] {
		case 'y':
			return ResponseYes
		case 'n':
			return ResponseNo
		case 'a':
			if hasDomain {
				return ResponseAlways
			}
			// No domain — 'a' not valid
			fmt.Fprintf(os.Stderr, "[nettrap] No domain known — cannot use 'always'. Try y/n: ")
			continue
		case 'd':
			if afterDetails {
				fmt.Fprintf(os.Stderr, "[nettrap] Invalid choice, try again: ")
				continue
			}
			p.printDetailsBox(dstIP, dstPort, protocol, domain)
			p.printPromptLine(hasDomain, true)
			// After details, recurse with afterDetails=true so 'd' is no longer valid
			return p.readResponse(dstIP, dstPort, protocol, domain, hasDomain, true)
		default:
			fmt.Fprintf(os.Stderr, "[nettrap] Invalid choice, try again: ")
			continue
		}
	}
}

var errTimeout = fmt.Errorf("prompt timeout")

// readLineWithTimeout reads a line from stdin with timeout and context awareness.
func (p *Prompter) readLineWithTimeout() (string, error) {
	type result struct {
		line string
		err  error
	}

	ch := make(chan result, 1)
	go func() {
		line, err := p.reader.ReadString('\n')
		ch <- result{line: strings.TrimRight(line, "\r\n"), err: err}
	}()

	timer := time.NewTimer(p.timeout)
	defer timer.Stop()

	select {
	case r := <-ch:
		if r.err != nil {
			if r.err == io.EOF {
				return "", errTimeout
			}
			return "", r.err
		}
		return r.line, nil
	case <-timer.C:
		return "", errTimeout
	case <-p.ctx.Done():
		return "", p.ctx.Err()
	}
}

// lookupReverseDNS performs a cached reverse DNS lookup.
func (p *Prompter) lookupReverseDNS(ip net.IP) string {
	ipStr := ip.String()

	p.rdnMu.Lock()
	if cached, ok := p.rdnCache[ipStr]; ok {
		p.rdnMu.Unlock()
		return cached
	}
	p.rdnMu.Unlock()

	names, err := net.LookupAddr(ipStr)
	var result string
	if err != nil || len(names) == 0 {
		result = ipStr // fallback to IP itself
	} else {
		result = strings.TrimSuffix(names[0], ".")
	}

	p.rdnMu.Lock()
	p.rdnCache[ipStr] = result
	p.rdnMu.Unlock()

	return result
}
