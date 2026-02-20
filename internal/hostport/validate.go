// Package hostport provides host loopback port forwarding into the namespace.
package hostport

import (
	"fmt"
	"strconv"
	"strings"
)

// Parse parses a comma-separated list of port numbers.
// Returns an error if any entry is not a valid port (1-65535).
func Parse(hostPortStr string) ([]int, error) {
	if hostPortStr == "" {
		return nil, nil
	}

	parts := strings.Split(hostPortStr, ",")
	ports := make([]int, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", p, err)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range (1-65535)", port)
		}

		ports = append(ports, port)
	}

	return ports, nil
}
