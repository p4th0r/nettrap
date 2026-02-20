// Package namespace provides veth pair setup and configuration.
package namespace

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// VethConfig holds the configuration for a veth pair.
type VethConfig struct {
	SessionID     string
	Subnet        string // e.g., "10.200.42"
	NamespaceName string
	DisableIPv6   bool
}

// SetupVethPair creates and configures a veth pair between the host and namespace.
func SetupVethPair(cfg VethConfig) error {
	hostVethName := fmt.Sprintf("veth-host-%s", cfg.SessionID)
	jailVethName := fmt.Sprintf("veth-jail-%s", cfg.SessionID)
	hostIP := fmt.Sprintf("%s.1/24", cfg.Subnet)
	jailIP := fmt.Sprintf("%s.2/24", cfg.Subnet)
	gatewayIP := fmt.Sprintf("%s.1", cfg.Subnet)

	// Create veth pair
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: hostVethName},
		PeerName:  jailVethName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("creating veth pair: %w", err)
	}

	// Get namespace handle
	nsHandle, err := GetHandle(cfg.NamespaceName)
	if err != nil {
		netlink.LinkDel(veth) // Cleanup on error
		return fmt.Errorf("getting namespace handle: %w", err)
	}
	defer nsHandle.Close()

	// Get the jail-side veth link
	jailVeth, err := netlink.LinkByName(jailVethName)
	if err != nil {
		netlink.LinkDel(veth)
		return fmt.Errorf("finding jail veth: %w", err)
	}

	// Move jail veth into the namespace
	if err := netlink.LinkSetNsFd(jailVeth, int(nsHandle)); err != nil {
		netlink.LinkDel(veth)
		return fmt.Errorf("moving veth to namespace: %w", err)
	}

	// Configure host-side veth
	hostVeth, err := netlink.LinkByName(hostVethName)
	if err != nil {
		return fmt.Errorf("finding host veth: %w", err)
	}

	hostAddr, err := netlink.ParseAddr(hostIP)
	if err != nil {
		netlink.LinkDel(hostVeth)
		return fmt.Errorf("parsing host IP: %w", err)
	}

	if err := netlink.AddrAdd(hostVeth, hostAddr); err != nil {
		netlink.LinkDel(hostVeth)
		return fmt.Errorf("setting host veth IP: %w", err)
	}

	if err := netlink.LinkSetUp(hostVeth); err != nil {
		netlink.LinkDel(hostVeth)
		return fmt.Errorf("bringing up host veth: %w", err)
	}

	// Configure inside the namespace
	if err := configureInsideNamespace(nsHandle, jailVethName, jailIP, gatewayIP, cfg.DisableIPv6); err != nil {
		netlink.LinkDel(hostVeth)
		return fmt.Errorf("configuring namespace internals: %w", err)
	}

	return nil
}

// configureInsideNamespace configures the network inside the namespace.
func configureInsideNamespace(nsHandle netns.NsHandle, jailVethName, jailIP, gatewayIP string, disableIPv6 bool) error {
	// Lock OS thread for namespace switching
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save current namespace
	origNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("getting current namespace: %w", err)
	}
	defer origNS.Close()
	defer netns.Set(origNS) // Ensure we return to original namespace

	// Switch to target namespace
	if err := netns.Set(nsHandle); err != nil {
		return fmt.Errorf("switching to namespace: %w", err)
	}

	// Get jail veth inside namespace
	jailVeth, err := netlink.LinkByName(jailVethName)
	if err != nil {
		return fmt.Errorf("finding jail veth in namespace: %w", err)
	}

	// Set IP address
	jailAddr, err := netlink.ParseAddr(jailIP)
	if err != nil {
		return fmt.Errorf("parsing jail IP: %w", err)
	}

	if err := netlink.AddrAdd(jailVeth, jailAddr); err != nil {
		return fmt.Errorf("setting jail veth IP: %w", err)
	}

	// Bring up jail veth
	if err := netlink.LinkSetUp(jailVeth); err != nil {
		return fmt.Errorf("bringing up jail veth: %w", err)
	}

	// Bring up loopback
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("finding loopback: %w", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return fmt.Errorf("bringing up loopback: %w", err)
	}

	// Add default route via host veth IP
	gateway := net.ParseIP(gatewayIP)
	route := &netlink.Route{
		Dst: nil, // Default route
		Gw:  gateway,
	}
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("adding default route: %w", err)
	}

	// Disable IPv6 if requested
	if disableIPv6 {
		if err := disableIPv6InNamespace(); err != nil {
			return fmt.Errorf("disabling IPv6: %w", err)
		}
	}

	// resolv.conf is handled separately via WriteResolvConfFile + bind mount
	// during command execution (ExecuteInNamespace), because we only have a
	// network namespace here — no mount namespace to isolate /etc/resolv.conf.

	return nil
}

// disableIPv6InNamespace disables IPv6 via sysctl.
func disableIPv6InNamespace() error {
	sysctls := []string{
		"/proc/sys/net/ipv6/conf/all/disable_ipv6",
		"/proc/sys/net/ipv6/conf/default/disable_ipv6",
	}

	for _, path := range sysctls {
		if err := os.WriteFile(path, []byte("1"), 0644); err != nil {
			// IPv6 might not be available, that's okay
			if !os.IsNotExist(err) {
				return fmt.Errorf("writing %s: %w", path, err)
			}
		}
	}

	return nil
}

// WriteResolvConfFile writes a resolv.conf to a temp file for later bind-mounting
// into the namespace's mount namespace during command execution.
// Returns the path to the temp file. Caller is responsible for cleanup.
func WriteResolvConfFile(sessionID, nameserver string) (string, error) {
	content := fmt.Sprintf("# Generated by nettrap\nnameserver %s\n", nameserver)
	tmpPath := fmt.Sprintf("/tmp/nettrap-resolv-%s", sessionID)
	if err := os.WriteFile(tmpPath, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("writing resolv.conf: %w", err)
	}
	return tmpPath, nil
}

// CleanupResolvConf removes the temporary resolv.conf file.
func CleanupResolvConf(sessionID string) {
	os.Remove(fmt.Sprintf("/tmp/nettrap-resolv-%s", sessionID))
}

// GetHostNameserver reads the first nameserver from the host's /etc/resolv.conf.
// This must be called BEFORE namespace creation to capture the host's DNS config.
func GetHostNameserver() string {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}

	return ""
}

// TeardownVethPair removes the veth pair. Deleting one end removes both.
// This is idempotent - no error if the interface doesn't exist.
func TeardownVethPair(sessionID string) error {
	hostVethName := fmt.Sprintf("veth-host-%s", sessionID)

	link, err := netlink.LinkByName(hostVethName)
	if err != nil {
		// Interface not found - already cleaned up
		if strings.Contains(err.Error(), "not found") {
			return nil
		}
		return fmt.Errorf("finding veth for cleanup: %w", err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("deleting veth: %w", err)
	}

	return nil
}

// EnableIPForwarding enables IP forwarding for the veth interface.
func EnableIPForwarding(sessionID string) error {
	hostVethName := fmt.Sprintf("veth-host-%s", sessionID)

	// Enable global IP forwarding (check first, don't disable on cleanup)
	globalPath := "/proc/sys/net/ipv4/ip_forward"
	current, err := os.ReadFile(globalPath)
	if err != nil {
		return fmt.Errorf("reading ip_forward: %w", err)
	}

	if strings.TrimSpace(string(current)) != "1" {
		if err := os.WriteFile(globalPath, []byte("1"), 0644); err != nil {
			return fmt.Errorf("enabling ip_forward: %w", err)
		}
	}

	// Enable forwarding for the specific interface
	ifacePath := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", hostVethName)
	if err := os.WriteFile(ifacePath, []byte("1"), 0644); err != nil {
		return fmt.Errorf("enabling forwarding on %s: %w", hostVethName, err)
	}

	return nil
}
