package interactive

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/p4th0r/nettrap/internal/dns"
	"github.com/p4th0r/nettrap/internal/firewall"
	"github.com/p4th0r/nettrap/internal/logging"
)

// NFQueueHandler intercepts packets via NFQUEUE and prompts the user
// for each new destination.
type NFQueueHandler struct {
	queueNum   uint16
	whitelist  *Whitelist
	firewall   *firewall.Firewall
	dnsTracker *dns.Tracker
	prompter   *Prompter
	eventCh    chan<- logging.Event
	logger     *logging.StderrLogger
	ctx        context.Context
	cancel     context.CancelFunc
	nf         *nfqueue.Nfqueue
	mu         sync.Mutex
}

// NFQueueConfig holds configuration for creating a new NFQueueHandler.
type NFQueueConfig struct {
	QueueNum   uint16
	Whitelist  *Whitelist
	Firewall   *firewall.Firewall
	DNSTracker *dns.Tracker
	Prompter   *Prompter
	EventCh    chan<- logging.Event
	Logger     *logging.StderrLogger
}

// NewNFQueueHandler creates a new NFQUEUE handler.
func NewNFQueueHandler(cfg NFQueueConfig) *NFQueueHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &NFQueueHandler{
		queueNum:   cfg.QueueNum,
		whitelist:  cfg.Whitelist,
		firewall:   cfg.Firewall,
		dnsTracker: cfg.DNSTracker,
		prompter:   cfg.Prompter,
		eventCh:    cfg.EventCh,
		logger:     cfg.Logger,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start opens the NFQUEUE and begins processing packets.
func (h *NFQueueHandler) Start() error {
	cfg := nfqueue.Config{
		NfQueue:      h.queueNum,
		MaxPacketLen: 128, // only need IP + TCP/UDP headers
		MaxQueueLen:  256,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagFailOpen, // fail-open if handler crashes
		WriteTimeout: 1 * time.Second,
	}

	nf, err := nfqueue.Open(&cfg)
	if err != nil {
		return fmt.Errorf("opening nfqueue %d: %w", h.queueNum, err)
	}
	h.nf = nf

	err = nf.RegisterWithErrorFunc(h.ctx,
		func(a nfqueue.Attribute) int {
			h.handlePacket(a)
			return 0
		},
		func(e error) int {
			if h.ctx.Err() != nil {
				return 1 // shutting down
			}
			h.logger.Debug("NFQUEUE error: %v", e)
			return 0
		},
	)
	if err != nil {
		nf.Close()
		return fmt.Errorf("registering nfqueue handler: %w", err)
	}

	h.logger.Debug("NFQUEUE handler started on queue %d", h.queueNum)
	return nil
}

// Stop cancels the handler and closes the NFQUEUE connection.
func (h *NFQueueHandler) Stop() error {
	h.cancel()
	if h.nf != nil {
		return h.nf.Close()
	}
	return nil
}

// handlePacket processes a single queued packet.
func (h *NFQueueHandler) handlePacket(attr nfqueue.Attribute) {
	if attr.PacketID == nil {
		return
	}
	packetID := *attr.PacketID

	if attr.Payload == nil || len(*attr.Payload) == 0 {
		// No payload — accept by default
		h.nf.SetVerdict(packetID, nfqueue.NfAccept)
		return
	}

	dstIP, dstPort, protocol := parsePacketHeaders(*attr.Payload)
	if dstIP == nil {
		// Can't parse — accept to avoid blocking unknown traffic
		h.nf.SetVerdict(packetID, nfqueue.NfAccept)
		return
	}

	// Fast path: already whitelisted
	if h.whitelist.IsAllowed(dstIP) {
		h.nf.SetVerdict(packetID, nfqueue.NfAccept)
		return
	}

	// Look up domain from DNS tracker
	domains := h.dnsTracker.GetDomainsForIP(dstIP)
	domain := ""
	if len(domains) > 0 {
		domain = domains[0]
	}

	// Prompt user (blocks until response or timeout)
	response := h.prompter.Prompt(dstIP, dstPort, protocol, domain)

	switch response {
	case ResponseYes:
		h.whitelist.ApproveIP(dstIP)
		h.firewall.AddAllowedIPs([]net.IP{dstIP})
		h.nf.SetVerdict(packetID, nfqueue.NfAccept)
		fmt.Fprintf(os.Stderr, "[nettrap] ✓ Approved: %s (this IP only)\n", dstIP)
		h.emitEvent(logging.EventConnAllowed, dstIP, dstPort, protocol, domain, "approved_ip")

	case ResponseAlways:
		if domain != "" {
			h.whitelist.ApproveDomain(domain)
			allIPs := h.dnsTracker.GetIPsForDomain(domain)
			if len(allIPs) > 0 {
				h.firewall.AddAllowedIPs(allIPs)
			}
			fmt.Fprintf(os.Stderr, "[nettrap] ✓ Whitelisted: %s (%s + all future IPs)\n", domain, dstIP)
			h.emitEvent(logging.EventConnAllowed, dstIP, dstPort, protocol, domain, "approved_domain")
		} else {
			// Fallback: no domain, treat as single IP
			h.whitelist.ApproveIP(dstIP)
			h.firewall.AddAllowedIPs([]net.IP{dstIP})
			fmt.Fprintf(os.Stderr, "[nettrap] ✓ Approved: %s (this IP only — no domain known)\n", dstIP)
			h.emitEvent(logging.EventConnAllowed, dstIP, dstPort, protocol, domain, "approved_ip")
		}
		h.nf.SetVerdict(packetID, nfqueue.NfAccept)

	case ResponseNo:
		h.nf.SetVerdict(packetID, nfqueue.NfDrop)
		fmt.Fprintf(os.Stderr, "[nettrap] ✗ Denied: %s:%d\n", dstIP, dstPort)
		h.emitEvent(logging.EventConnDropped, dstIP, dstPort, protocol, domain, "denied")

	default:
		// Timeout or error — deny
		h.nf.SetVerdict(packetID, nfqueue.NfDrop)
		h.emitEvent(logging.EventConnDropped, dstIP, dstPort, protocol, domain, "denied_timeout")
	}
}

// emitEvent sends an event to the event logger channel.
func (h *NFQueueHandler) emitEvent(evType logging.EventType, dstIP net.IP, dstPort uint16, protocol, domain, decision string) {
	ev := logging.Event{
		Timestamp:           time.Now(),
		Type:                evType,
		Protocol:            protocol,
		DstIP:               dstIP,
		DstPort:             dstPort,
		Domain:              domain,
		DomainSrc:           "dns_proxy",
		Action:              eventAction(evType),
		InteractiveDecision: decision,
	}
	if domain == "" {
		ev.DomainSrc = ""
	}

	select {
	case h.eventCh <- ev:
	case <-h.ctx.Done():
	}
}

func eventAction(evType logging.EventType) string {
	switch evType {
	case logging.EventConnAllowed:
		return "ALLOWED"
	case logging.EventConnDropped:
		return "DROPPED"
	default:
		return "UNKNOWN"
	}
}

// parsePacketHeaders extracts dst IP, dst port, and protocol from raw IP packet bytes.
func parsePacketHeaders(data []byte) (dstIP net.IP, dstPort uint16, protocol string) {
	if len(data) < 20 {
		return nil, 0, ""
	}

	version := data[0] >> 4

	if version == 4 {
		// IPv4
		ihl := int(data[0]&0x0f) * 4
		if ihl < 20 || len(data) < ihl {
			return nil, 0, ""
		}

		proto := data[9]
		dstIP = net.IP(make([]byte, 4))
		copy(dstIP, data[16:20])

		switch proto {
		case 6: // TCP
			protocol = "tcp"
			if len(data) >= ihl+4 {
				dstPort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
			}
		case 17: // UDP
			protocol = "udp"
			if len(data) >= ihl+4 {
				dstPort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
			}
		case 1: // ICMP
			protocol = "icmp"
			dstPort = 0
		default:
			protocol = fmt.Sprintf("proto-%d", proto)
		}
		return
	}

	if version == 6 && len(data) >= 40 {
		// IPv6
		proto := data[6] // Next Header
		dstIP = net.IP(make([]byte, 16))
		copy(dstIP, data[24:40])

		switch proto {
		case 6: // TCP
			protocol = "tcp"
			if len(data) >= 44 {
				dstPort = binary.BigEndian.Uint16(data[42:44])
			}
		case 17: // UDP
			protocol = "udp"
			if len(data) >= 44 {
				dstPort = binary.BigEndian.Uint16(data[42:44])
			}
		case 58: // ICMPv6
			protocol = "icmpv6"
			dstPort = 0
		default:
			protocol = fmt.Sprintf("proto-%d", proto)
		}
		return
	}

	return nil, 0, ""
}

// QueueNumFromSessionID derives an NFQUEUE number from the session ID.
// Uses the first 2 bytes of the hex session ID as a uint16.
func QueueNumFromSessionID(sessionID string) uint16 {
	if len(sessionID) < 4 {
		return 100 // fallback
	}
	var num uint16
	for i := 0; i < 4 && i < len(sessionID); i++ {
		c := sessionID[i]
		var val byte
		switch {
		case c >= '0' && c <= '9':
			val = c - '0'
		case c >= 'a' && c <= 'f':
			val = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			val = c - 'A' + 10
		}
		num = (num << 4) | uint16(val)
	}
	return num
}
