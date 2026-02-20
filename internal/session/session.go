// Package session provides session ID generation and subnet allocation.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// GenerateSessionID returns a unique 4-character random hex string (e.g., "a3f8").
// It checks for collisions with existing namespaces, veths, and nftables tables.
func GenerateSessionID() (string, error) {
	for attempt := 0; attempt < 100; attempt++ {
		bytes := make([]byte, 2)
		if _, err := rand.Read(bytes); err != nil {
			return "", fmt.Errorf("generating session ID: %w", err)
		}
		id := hex.EncodeToString(bytes)

		if !isSessionIDInUse(id) {
			return id, nil
		}
	}
	return "", fmt.Errorf("could not generate a unique session ID after 100 attempts (too many concurrent sessions?)")
}

// isSessionIDInUse checks if any resources already exist for the given session ID.
func isSessionIDInUse(id string) bool {
	// Check for existing namespace
	nsPath := filepath.Join("/var/run/netns", NamespaceName(id))
	if _, err := os.Stat(nsPath); err == nil {
		return true
	}

	// Check for existing veth
	ifaces, _ := net.Interfaces()
	hostVeth := HostVethName(id)
	for _, iface := range ifaces {
		if iface.Name == hostVeth {
			return true
		}
	}

	// Check for existing nftables table by listing and matching
	// This is a best-effort check — nftables.New() may fail without privileges
	return isNFTablesTableInUse(NFTablesTableName(id))
}

// isNFTablesTableInUse checks if an nftables table with the given name exists.
func isNFTablesTableInUse(tableName string) bool {
	// Read /proc/net/nf_tables if available (works without full privileges)
	data, err := os.ReadFile("/proc/net/nf_tables")
	if err != nil {
		return false // Can't check, assume not in use
	}
	return strings.Contains(string(data), tableName)
}

// AllocateSubnet derives a subnet from the session ID and finds an available one.
// Returns the subnet prefix (e.g., "10.200.42") without the trailing ".0/24".
func AllocateSubnet(sessionID string) (string, error) {
	if len(sessionID) < 2 {
		return "", fmt.Errorf("session ID too short: %s", sessionID)
	}

	// Decode first byte of session ID to get starting X value
	bytes, err := hex.DecodeString(sessionID[:2])
	if err != nil {
		return "", fmt.Errorf("decoding session ID: %w", err)
	}

	// X must be in range 1-254 (avoid 0 and 255)
	startX := int(bytes[0])
	if startX == 0 {
		startX = 1
	} else if startX == 255 {
		startX = 254
	}

	// Try to find an available subnet
	for i := 0; i < 254; i++ {
		x := ((startX - 1 + i) % 254) + 1 // Cycle through 1-254
		subnet := fmt.Sprintf("10.200.%d", x)

		if !isSubnetInUse(subnet) {
			return subnet, nil
		}
	}

	return "", fmt.Errorf("no available subnet found in 10.200.0.0/16 range")
}

// isSubnetInUse checks if a subnet is already in use by checking for routes.
func isSubnetInUse(subnet string) bool {
	// Check if any interface has an IP in this subnet
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	subnetPrefix := subnet + "."
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP.String()
				// Check if IP starts with our subnet prefix (e.g., "10.200.42.")
				if len(ip) >= len(subnetPrefix) && ip[:len(subnetPrefix)] == subnetPrefix {
					return true
				}
			}
		}
	}

	return false
}

// ResourceName generates a consistent resource name with the session ID.
func ResourceName(sessionID, resource string) string {
	return fmt.Sprintf("%s-%s", resource, sessionID)
}

// NamespaceName returns the network namespace name for a session.
func NamespaceName(sessionID string) string {
	return fmt.Sprintf("nettrap-%s", sessionID)
}

// HostVethName returns the host-side veth interface name.
func HostVethName(sessionID string) string {
	return fmt.Sprintf("veth-host-%s", sessionID)
}

// JailVethName returns the namespace-side veth interface name.
func JailVethName(sessionID string) string {
	return fmt.Sprintf("veth-jail-%s", sessionID)
}

// NFTablesTableName returns the nftables table name for a session.
func NFTablesTableName(sessionID string) string {
	return fmt.Sprintf("nettrap_%s", sessionID)
}
