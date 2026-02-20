package firewall

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	nfdns "github.com/p4th0r/nettrap/internal/dns"
	"github.com/p4th0r/nettrap/internal/logging"
)

// ConnTracker monitors new connections from the namespace using the conntrack
// utility and emits enriched events to the EventLogger.
type ConnTracker struct {
	namespaceIP string // "10.200.X.2"
	hostVethIP  string // "10.200.X.1"
	hostPorts   map[int]bool
	mode        string
	dnsTracker  *nfdns.Tracker
	eventCh     chan<- logging.Event
	logger      *logging.StderrLogger
	cmd         *exec.Cmd
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// ConnTrackerConfig holds configuration for creating a ConnTracker.
type ConnTrackerConfig struct {
	NamespaceIP string // "10.200.X.2"
	HostVethIP  string // "10.200.X.1"
	HostPorts   []int
	Mode        string
	DNSTracker  *nfdns.Tracker
	EventCh     chan<- logging.Event
	Logger      *logging.StderrLogger
}

// NewConnTracker creates a new ConnTracker.
func NewConnTracker(cfg ConnTrackerConfig) *ConnTracker {
	ctx, cancel := context.WithCancel(context.Background())

	hp := make(map[int]bool)
	for _, p := range cfg.HostPorts {
		hp[p] = true
	}

	return &ConnTracker{
		namespaceIP: cfg.NamespaceIP,
		hostVethIP:  cfg.HostVethIP,
		hostPorts:   hp,
		mode:        cfg.Mode,
		dnsTracker:  cfg.DNSTracker,
		eventCh:     cfg.EventCh,
		logger:      cfg.Logger,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start begins listening for connection events. Returns an error if the
// conntrack tool is not available.
func (ct *ConnTracker) Start() error {
	// Check if conntrack is available
	conntrackPath, err := exec.LookPath("conntrack")
	if err != nil {
		ct.logger.Debug("conntrack tool not found: %v — connection tracking disabled", err)
		return fmt.Errorf("conntrack tool not found: %w (install with: apt install conntrack)", err)
	}

	ct.cmd = exec.CommandContext(ct.ctx, conntrackPath, "-E", "-e", "NEW", "-s", ct.namespaceIP)
	stdout, err := ct.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe: %w", err)
	}

	// Capture stderr for debugging
	ct.cmd.Stderr = nil

	if err := ct.cmd.Start(); err != nil {
		return fmt.Errorf("starting conntrack: %w", err)
	}

	ct.logger.Debug("Connection tracker started (conntrack -E -e NEW -s %s)", ct.namespaceIP)

	ct.wg.Add(1)
	go func() {
		defer ct.wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if ct.ctx.Err() != nil {
				return
			}
			line := scanner.Text()
			ev := ct.parseLine(line)
			if ev != nil {
				select {
				case ct.eventCh <- *ev:
				case <-ct.ctx.Done():
					return
				}
			}
		}
	}()

	return nil
}

// Stop stops the connection tracker and waits for the goroutine to finish.
func (ct *ConnTracker) Stop() {
	ct.cancel()
	if ct.cmd != nil && ct.cmd.Process != nil {
		ct.cmd.Process.Kill()
	}
	ct.wg.Wait()
}

// parseLine parses a conntrack event line and returns an enriched Event,
// or nil if the line should be skipped.
func (ct *ConnTracker) parseLine(line string) *logging.Event {
	if !strings.Contains(line, "[NEW]") {
		return nil
	}

	proto, dstIP, dstPort := ct.extractFields(line)
	if proto == "" || dstIP == nil {
		return nil
	}

	// Skip DNS proxy traffic (internal)
	if dstIP.String() == ct.hostVethIP && dstPort == 53 {
		return nil
	}

	ev := &logging.Event{
		Timestamp: time.Now(),
		Protocol:  proto,
		DstIP:     dstIP,
		DstPort:   dstPort,
	}

	// Determine event type based on mode
	switch ct.mode {
	case "allow":
		ev.Type = logging.EventConnAllowed
		ev.Action = "ALLOWED"
	case "analyse":
		ev.Type = logging.EventConnLogged
		ev.Action = "LOGGED"
	default:
		ev.Type = logging.EventConnLogged
		ev.Action = "LOGGED"
	}

	// Enrich with domain from DNS tracker
	if ct.dnsTracker != nil {
		domains := ct.dnsTracker.GetDomainsForIP(dstIP)
		if len(domains) > 0 {
			ev.Domain = domains[0]
			ev.DomainSrc = "dns_proxy"
		}
	}

	// Check for host-port forwarded traffic
	if dstIP.String() == ct.hostVethIP && ct.hostPorts[int(dstPort)] {
		ev.Extra = "host-port forwarded"
	}

	// Check for DoH/DoT servers
	if ev.Domain == "" {
		if provider, ok := nfdns.IsKnownDoHDoT(dstIP.String()); ok {
			if dstPort == 443 || dstPort == 853 {
				// Emit DoH warning as a separate event
				dohEv := &logging.Event{
					Timestamp: time.Now(),
					Type:      logging.EventDoHWarning,
					Protocol:  proto,
					DstIP:     dstIP,
					DstPort:   dstPort,
					Extra:     provider,
					Action:    "WARNING",
				}
				select {
				case ct.eventCh <- *dohEv:
				default:
				}
			}
		}
	}

	return ev
}

// extractFields extracts protocol, destination IP and port from a conntrack line.
// It takes the first occurrence of each field (original tuple).
func (ct *ConnTracker) extractFields(line string) (proto string, dstIP net.IP, dstPort uint16) {
	fields := strings.Fields(line)

	var foundSrc bool
	var dstIPStr string

	for _, f := range fields {
		switch {
		case proto == "" && (f == "tcp" || f == "udp" || f == "icmp"):
			proto = f
		case !foundSrc && strings.HasPrefix(f, "src="):
			foundSrc = true
		case foundSrc && dstIPStr == "" && strings.HasPrefix(f, "dst="):
			dstIPStr = f[4:]
		case foundSrc && dstPort == 0 && strings.HasPrefix(f, "dport="):
			v, _ := strconv.ParseUint(f[6:], 10, 16)
			dstPort = uint16(v)
		}
	}

	if dstIPStr != "" {
		dstIP = net.ParseIP(dstIPStr)
	}

	return
}
