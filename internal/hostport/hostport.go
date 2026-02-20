package hostport

import (
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// EnableRouteLocalnet enables route_localnet on the host-side veth interface.
// Required for DNAT to 127.0.0.1 to work — without it, the kernel drops
// packets with a loopback destination arriving on a non-loopback interface.
func EnableRouteLocalnet(hostVeth string) error {
	path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/route_localnet", hostVeth)
	if err := os.WriteFile(path, []byte("1"), 0644); err != nil {
		return fmt.Errorf("enabling route_localnet on %s: %w", hostVeth, err)
	}
	return nil
}

// DisableRouteLocalnet reverts the route_localnet sysctl.
func DisableRouteLocalnet(hostVeth string) error {
	path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/route_localnet", hostVeth)
	if err := os.WriteFile(path, []byte("0"), 0644); err != nil {
		// Interface may already be gone during cleanup
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("disabling route_localnet on %s: %w", hostVeth, err)
	}
	return nil
}

// SetupNamespaceDNAT creates nftables DNAT rules inside the namespace so that
// connections to 127.0.0.1:<port> are redirected to the host veth IP.
func SetupNamespaceDNAT(nsName, sessionID, subnet string, ports []int) error {
	if len(ports) == 0 {
		return nil
	}

	hostVethIP := net.ParseIP(fmt.Sprintf("%s.1", subnet)).To4()

	// Lock the OS thread so setns affects only this goroutine
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save current namespace
	origNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("getting current namespace: %w", err)
	}
	defer origNS.Close()

	// Enter the target namespace
	targetNS, err := netns.GetFromName(nsName)
	if err != nil {
		return fmt.Errorf("getting namespace %s: %w", nsName, err)
	}
	defer targetNS.Close()

	if err := netns.Set(targetNS); err != nil {
		return fmt.Errorf("entering namespace %s: %w", nsName, err)
	}

	// Ensure we return to original namespace
	defer netns.Set(origNS)

	// Create nftables rules inside the namespace
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection in namespace: %w", err)
	}

	tableName := fmt.Sprintf("nettrap_ns_%s", sessionID)
	table := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}
	conn.AddTable(table)

	// Output NAT chain — catches outgoing connections from the namespace
	outputChain := conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
	})

	loopback := net.ParseIP("127.0.0.1").To4()

	for _, port := range ports {
		// TCP DNAT: 127.0.0.1:<port> → <hostVethIP>:<port>
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: outputChain,
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
					Data:     loopback,
				},
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
				&expr.Immediate{Register: 1, Data: hostVethIP},
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

		// UDP DNAT
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: outputChain,
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
					Data:     loopback,
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
				&expr.Immediate{Register: 1, Data: hostVethIP},
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

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flushing namespace nftables rules: %w", err)
	}

	return nil
}
