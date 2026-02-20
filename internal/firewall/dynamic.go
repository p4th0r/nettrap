package firewall

import (
	"fmt"
	"net"

	"github.com/google/nftables"
)

// AddAllowedIPs adds IPs to the nftables allowed_v4 (and allowed_v6) sets in real-time.
// Called by the DNS proxy's OnAllowedResolve callback (allow mode) or by the
// NFQUEUE handler when the user approves a destination (interactive mode).
// Thread-safe: can be called from DNS proxy goroutines or the NFQUEUE handler.
func (fw *Firewall) AddAllowedIPs(ips []net.IP) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if fw.conn == nil {
		return nil
	}

	var v4elements []nftables.SetElement
	var v6elements []nftables.SetElement

	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			if fw.allowedV4 != nil {
				v4elements = append(v4elements,
					nftables.SetElement{Key: ip4},
					nftables.SetElement{Key: nextIP(ip4), IntervalEnd: true},
				)
			}
		} else if ip16 := ip.To16(); ip16 != nil && fw.allowedV6 != nil {
			v6elements = append(v6elements,
				nftables.SetElement{Key: ip16},
				nftables.SetElement{Key: nextIP(ip16), IntervalEnd: true},
			)
		}
	}

	if len(v4elements) == 0 && len(v6elements) == 0 {
		return nil
	}

	// Create a fresh connection for the update to avoid interference with
	// any pending operations on the main connection.
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection for set update: %w", err)
	}

	if len(v4elements) > 0 && fw.allowedV4 != nil {
		if err := conn.SetAddElements(fw.allowedV4, v4elements); err != nil {
			return fmt.Errorf("adding elements to allowed_v4: %w", err)
		}
	}

	if len(v6elements) > 0 && fw.allowedV6 != nil {
		if err := conn.SetAddElements(fw.allowedV6, v6elements); err != nil {
			return fmt.Errorf("adding elements to allowed_v6: %w", err)
		}
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flushing set update: %w", err)
	}

	return nil
}
