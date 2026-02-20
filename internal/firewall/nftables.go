// Package firewall provides nftables-based firewall management for nettrap sessions.
package firewall

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/p4th0r/nettrap/internal/allowlist"
	"github.com/p4th0r/nettrap/internal/logging"
	"golang.org/x/sys/unix"
)

// Firewall manages the nftables rules for a nettrap session.
type Firewall struct {
	sessionID string
	subnet    string // e.g., "10.200.42"
	hostVeth  string // e.g., "veth-host-a3f8"
	mode      string // "allow", "analyse", "interactive"
	ipv6      bool
	hostPorts []int
	queueNum  uint16
	logger    *logging.StderrLogger

	mu        sync.Mutex
	conn      *nftables.Conn
	table     *nftables.Table
	allowedV4 *nftables.Set
	allowedV6 *nftables.Set
}

// Config holds the configuration for creating a new Firewall.
type Config struct {
	SessionID string
	Subnet    string
	HostVeth  string
	Mode      string
	IPv6      bool
	HostPorts []int
	QueueNum  uint16 // NFQUEUE number for interactive mode
	Logger    *logging.StderrLogger
}

// New creates a new Firewall instance. Call Setup() to install the rules.
func New(cfg Config) *Firewall {
	return &Firewall{
		sessionID: cfg.SessionID,
		subnet:    cfg.Subnet,
		hostVeth:  cfg.HostVeth,
		mode:      cfg.Mode,
		ipv6:      cfg.IPv6,
		hostPorts: cfg.HostPorts,
		queueNum:  cfg.QueueNum,
		logger:    cfg.Logger,
	}
}

// Setup creates the complete nftables ruleset for this session.
// For allow mode, pass the matcher to pre-populate allow sets.
// For other modes, matcher can be nil.
func (fw *Firewall) Setup(matcher *allowlist.Matcher) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}
	fw.conn = conn

	tableName := fmt.Sprintf("nettrap_%s", fw.sessionID)
	fw.table = &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}
	conn.AddTable(fw.table)

	hostIP := net.ParseIP(fmt.Sprintf("%s.1", fw.subnet)).To4()

	// Create allowed_v4 set for allow and interactive modes
	if fw.mode == "allow" || fw.mode == "interactive" {
		fw.allowedV4 = &nftables.Set{
			Name:     "allowed_v4",
			Table:    fw.table,
			KeyType:  nftables.TypeIPAddr,
			Interval: true,
		}

		var elements []nftables.SetElement
		if fw.mode == "allow" {
			elements = buildSetElements(matcher, false)
		}
		if err := conn.AddSet(fw.allowedV4, elements); err != nil {
			return fmt.Errorf("adding allowed_v4 set: %w", err)
		}

		// Create allowed_v6 set when IPv6 is enabled
		if fw.ipv6 {
			fw.allowedV6 = &nftables.Set{
				Name:     "allowed_v6",
				Table:    fw.table,
				KeyType:  nftables.TypeIP6Addr,
				Interval: true,
			}
			var v6elements []nftables.SetElement
			if fw.mode == "allow" {
				v6elements = buildSetElements(matcher, true)
			}
			if err := conn.AddSet(fw.allowedV6, v6elements); err != nil {
				return fmt.Errorf("adding allowed_v6 set: %w", err)
			}
		}
	}

	// Build forward chain
	if err := fw.buildForwardChain(conn, hostIP); err != nil {
		return fmt.Errorf("building forward chain: %w", err)
	}

	// Build NAT prerouting chain (for host-port DNAT)
	if len(fw.hostPorts) > 0 {
		fw.buildNATPrerouting(conn, hostIP)
	}

	// Build NAT postrouting chain (masquerade)
	fw.buildNATPostrouting(conn, hostIP)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flushing nftables rules: %w", err)
	}

	// Add iptables FORWARD rules for compatibility with systems that have
	// iptables FORWARD policy DROP (e.g., Docker). Both iptables and nftables
	// are evaluated by the kernel, so we need iptables to allow the traffic too.
	if err := setupIPTablesForward(fw.hostVeth); err != nil {
		fw.logger.Debug("Warning: could not add iptables FORWARD rules: %v", err)
		// Non-fatal: system may not have iptables or may not need it
	}

	if fw.ipv6 {
		if err := setupIP6TablesForward(fw.hostVeth); err != nil {
			fw.logger.Debug("Warning: could not add ip6tables FORWARD rules: %v", err)
		}
	}

	fw.logger.Debug("nftables table %s created", tableName)
	return nil
}

// buildForwardChain creates the forward filter chain with mode-specific rules.
func (fw *Firewall) buildForwardChain(conn *nftables.Conn, hostIP net.IP) error {
	policy := nftables.ChainPolicyDrop
	if fw.mode == "analyse" {
		policy = nftables.ChainPolicyAccept
	}

	forwardChain := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    fw.table,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
		Policy:   &policy,
	})

	// Rule: ct state established,related accept
	// ct state is a host-endian bitmask — use NativeEndian, not BigEndian
	conn.AddRule(&nftables.Rule{
		Table: fw.table,
		Chain: forwardChain,
		Exprs: []expr.Any{
			&expr.Ct{
				Register:       1,
				SourceRegister: false,
				Key:            expr.CtKeySTATE,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Rule: allow DNS to proxy (UDP)
	conn.AddRule(&nftables.Rule{
		Table: fw.table,
		Chain: forwardChain,
		Exprs: dnsAllowExprs(hostIP, unix.IPPROTO_UDP),
	})

	// Rule: allow DNS to proxy (TCP)
	conn.AddRule(&nftables.Rule{
		Table: fw.table,
		Chain: forwardChain,
		Exprs: dnsAllowExprs(hostIP, unix.IPPROTO_TCP),
	})

	// Allow/Interactive mode: lookup against allowed_v4 set
	if fw.mode == "allow" || fw.mode == "interactive" {
		conn.AddRule(&nftables.Rule{
			Table: fw.table,
			Chain: forwardChain,
			Exprs: []expr.Any{
				// Match IPv4 only (required in inet family for payload context)
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{unix.NFPROTO_IPV4},
				},
				// Load IPv4 dest address
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       16,
					Len:          4,
				},
				&expr.Lookup{
					SourceRegister: 1,
					SetName:        fw.allowedV4.Name,
					SetID:          fw.allowedV4.ID,
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})

		// IPv6 lookup against allowed_v6 set
		if fw.ipv6 && fw.allowedV6 != nil {
			conn.AddRule(&nftables.Rule{
				Table: fw.table,
				Chain: forwardChain,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte{unix.NFPROTO_IPV6},
					},
					// Load IPv6 dest address (offset 24, len 16 in IPv6 header)
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       24,
						Len:          16,
					},
					&expr.Lookup{
						SourceRegister: 1,
						SetName:        fw.allowedV6.Name,
						SetID:          fw.allowedV6.ID,
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			})
		}
	}

	// Host-port: allow traffic to host veth IP on each forwarded port
	for _, port := range fw.hostPorts {
		conn.AddRule(&nftables.Rule{
			Table: fw.table,
			Chain: forwardChain,
			Exprs: []expr.Any{
				// Match: ip daddr == hostIP
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       16,
					Len:          4,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     hostIP,
				},
				// Match: tcp dport == port
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{unix.IPPROTO_TCP},
				},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2,
					Len:          2,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.BigEndian.PutUint16(uint16(port)),
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}

	// Interactive mode: send new connections to NFQUEUE for userspace decision
	if fw.mode == "interactive" {
		conn.AddRule(&nftables.Rule{
			Table: fw.table,
			Chain: forwardChain,
			Exprs: []expr.Any{
				// Match ct state new
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            expr.CtKeySTATE,
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW),
					Xor:            binaryutil.NativeEndian.PutUint32(0),
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     binaryutil.NativeEndian.PutUint32(0),
				},
				&expr.Queue{
					Num:  fw.queueNum,
					Flag: expr.QueueFlagBypass, // fail-open if handler not running
				},
			},
		})
	}

	return nil
}

// dnsAllowExprs returns expressions to match DNS traffic to the proxy.
func dnsAllowExprs(hostIP net.IP, proto byte) []expr.Any {
	return []expr.Any{
		// Match: nfproto == ipv4
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.NFPROTO_IPV4},
		},
		// Match: ip daddr == hostIP
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     hostIP,
		},
		// Match: l4proto == proto
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{proto},
		},
		// Match: dport == 53
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(53),
		},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// buildNATPrerouting creates prerouting DNAT rules for host-port forwarding.
// Traffic arriving on veth-host destined to hostIP:<port> is DNATted to 127.0.0.1:<port>.
func (fw *Firewall) buildNATPrerouting(conn *nftables.Conn, hostIP net.IP) {
	preroutingChain := conn.AddChain(&nftables.Chain{
		Name:     "nat_prerouting",
		Table:    fw.table,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
	})

	loopback := net.ParseIP("127.0.0.1").To4()

	for _, port := range fw.hostPorts {
		conn.AddRule(&nftables.Rule{
			Table: fw.table,
			Chain: preroutingChain,
			Exprs: []expr.Any{
				// Match: iifname == veth-host-<sid>
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     ifname(fw.hostVeth),
				},
				// Match: ip daddr == hostIP
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       16,
					Len:          4,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     hostIP,
				},
				// Match: tcp dport == port
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{unix.IPPROTO_TCP},
				},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2,
					Len:          2,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.BigEndian.PutUint16(uint16(port)),
				},
				// DNAT to 127.0.0.1:<port>
				&expr.Immediate{Register: 1, Data: loopback},
				&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
				&expr.NAT{
					Type:        expr.NATTypeDestNAT,
					Family:      unix.NFPROTO_IPV4,
					RegAddrMin:  1,
					RegAddrMax:  1,
					RegProtoMin: 2,
					RegProtoMax: 2,
					Specified:   true,
				},
			},
		})
		// Same for UDP
		conn.AddRule(&nftables.Rule{
			Table: fw.table,
			Chain: preroutingChain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     ifname(fw.hostVeth),
				},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       16,
					Len:          4,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     hostIP,
				},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{unix.IPPROTO_UDP},
				},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2,
					Len:          2,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.BigEndian.PutUint16(uint16(port)),
				},
				&expr.Immediate{Register: 1, Data: loopback},
				&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
				&expr.NAT{
					Type:        expr.NATTypeDestNAT,
					Family:      unix.NFPROTO_IPV4,
					RegAddrMin:  1,
					RegAddrMax:  1,
					RegProtoMin: 2,
					RegProtoMax: 2,
					Specified:   true,
				},
			},
		})
	}
}

// buildNATPostrouting creates postrouting masquerade rules.
func (fw *Firewall) buildNATPostrouting(conn *nftables.Conn, hostIP net.IP) {
	postroutingChain := conn.AddChain(&nftables.Chain{
		Name:     "nat_postrouting",
		Table:    fw.table,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Type:     nftables.ChainTypeNAT,
	})

	subnetIP, subnetMask := parseSubnet(fw.subnet)

	// Masquerade traffic from the namespace subnet going outbound
	// (not back to the veth itself)
	conn.AddRule(&nftables.Rule{
		Table: fw.table,
		Chain: postroutingChain,
		Exprs: []expr.Any{
			// Match: nfproto == ipv4
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.NFPROTO_IPV4},
			},
			// Match: ip saddr in subnet
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12, // source IP offset
				Len:          4,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           subnetMask,
				Xor:            []byte{0, 0, 0, 0},
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     subnetIP,
			},
			// Match: oifname != veth-host-<sid>
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     ifname(fw.hostVeth),
			},
			&expr.Masq{},
		},
	})

	// Host-port: masquerade traffic going to loopback (for DNAT'd host-port traffic)
	if len(fw.hostPorts) > 0 {
		conn.AddRule(&nftables.Rule{
			Table: fw.table,
			Chain: postroutingChain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{unix.NFPROTO_IPV4},
				},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       16,
					Len:          4,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     net.ParseIP("127.0.0.1").To4(),
				},
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     ifname("lo"),
				},
				&expr.Masq{},
			},
		})
	}
}

// GetQueueNum returns the NFQUEUE number for interactive mode.
func (fw *Firewall) GetQueueNum() uint16 {
	return fw.queueNum
}

// Teardown removes the nftables table atomically, deleting all chains, sets, and rules.
// Also removes iptables compatibility rules.
// This is idempotent — safe to call even if the table doesn't exist.
func (fw *Firewall) Teardown() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	// Remove iptables FORWARD compatibility rules
	teardownIPTablesForward(fw.hostVeth)
	if fw.ipv6 {
		teardownIP6TablesForward(fw.hostVeth)
	}

	if fw.conn == nil {
		return nil
	}

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection for teardown: %w", err)
	}

	conn.DelTable(fw.table)
	if err := conn.Flush(); err != nil {
		// Ignore errors — table may already be gone
		return nil
	}

	fw.logger.Debug("nftables table nettrap_%s deleted", fw.sessionID)
	return nil
}

// buildSetElements converts matcher's static IPs and CIDRs into nftables set elements.
// If ipv6 is true, returns only IPv6 elements; otherwise returns only IPv4 elements.
func buildSetElements(matcher *allowlist.Matcher, ipv6 bool) []nftables.SetElement {
	if matcher == nil {
		return nil
	}

	var elements []nftables.SetElement

	// Add individual IPs
	for _, ip := range matcher.GetStaticIPs() {
		if ipv6 {
			if ip.To4() != nil {
				continue // Skip IPv4
			}
			ip16 := ip.To16()
			elements = append(elements,
				nftables.SetElement{Key: ip16},
				nftables.SetElement{Key: nextIP(ip16), IntervalEnd: true},
			)
		} else {
			ip4 := ip.To4()
			if ip4 == nil {
				continue // Skip IPv6
			}
			elements = append(elements,
				nftables.SetElement{Key: ip4},
				nftables.SetElement{Key: nextIP(ip4), IntervalEnd: true},
			)
		}
	}

	// Add CIDRs as intervals
	for _, cidr := range matcher.GetCIDRs() {
		if ipv6 {
			if cidr.IP.To4() != nil {
				continue // Skip IPv4 CIDRs
			}
			start := cidr.IP.To16()
			end := lastIP(cidr)
			elements = append(elements,
				nftables.SetElement{Key: start},
				nftables.SetElement{Key: nextIP(end.To16()), IntervalEnd: true},
			)
		} else {
			if cidr.IP.To4() == nil {
				continue // Skip IPv6 CIDRs
			}
			start := cidr.IP.To4()
			end := lastIP(cidr)
			elements = append(elements,
				nftables.SetElement{Key: start},
				nftables.SetElement{Key: nextIP(end), IntervalEnd: true},
			)
		}
	}

	return elements
}

// nextIP returns the IP address immediately following the given one.
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

// lastIP returns the last IP address in a CIDR range.
func lastIP(cidr *net.IPNet) net.IP {
	ip := cidr.IP.To4()
	mask := cidr.Mask
	last := make(net.IP, len(ip))
	for i := range ip {
		last[i] = ip[i] | ^mask[i]
	}
	return last
}

// ifname pads an interface name to 16 bytes (IFNAMSIZ) for nftables comparison.
func ifname(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}

// parseSubnet returns the network IP and mask for a /24 subnet prefix like "10.200.42".
func parseSubnet(prefix string) (net.IP, net.IPMask) {
	_, network, _ := net.ParseCIDR(fmt.Sprintf("%s.0/24", prefix))
	return network.IP.To4(), net.IPMask(network.Mask)
}
