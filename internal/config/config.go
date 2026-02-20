// Package config provides the unified configuration struct for nettrap.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

// Config holds all parsed CLI state for a nettrap session.
type Config struct {
	// Mode flags (exactly one mode is active, except Allow which coexists with AllowFile)
	AllowList   string // raw --allow value (comma-separated)
	AllowFile   string // raw --allow-file path
	Analyse     bool
	Interactive bool

	// Options
	LogPath     string
	NoLog       bool
	PcapPath    string
	HostPorts   string // raw --host-port value (parsed later)
	Quiet       bool
	Verbose     bool
	DNSUpstream string
	Timeout     int
	DryRun      bool
	IPv6        bool

	// Privilege options
	RunAsRoot bool // run wrapped command as root (skip privilege drop)

	// Derived values (set after parsing)
	Command    []string // the command + args after --
	SessionID  string   // generated 4-char hex
	Subnet     string   // allocated subnet prefix (e.g., "10.200.42")
	CallerUID  int      // UID of the user who invoked sudo (-1 if unavailable)
	CallerGID  int      // GID of the user who invoked sudo (-1 if unavailable)
	CallerUser string   // username of the sudo caller (from SUDO_USER)
}

// DetectCallerIdentity reads SUDO_UID, SUDO_GID, and SUDO_USER environment
// variables to identify the real user behind a sudo invocation.
// Returns -1, -1, "" if the variables are absent or if SUDO_UID is 0
// (which means nettrap was run as root directly, not via sudo from a real user).
func DetectCallerIdentity() (uid, gid int, user string) {
	sudoUID := os.Getenv("SUDO_UID")
	sudoGID := os.Getenv("SUDO_GID")
	sudoUser := os.Getenv("SUDO_USER")

	if sudoUID == "" || sudoGID == "" {
		return -1, -1, ""
	}

	uid, err := strconv.Atoi(sudoUID)
	if err != nil || uid == 0 {
		return -1, -1, ""
	}

	gid, err = strconv.Atoi(sudoGID)
	if err != nil {
		return -1, -1, ""
	}

	return uid, gid, sudoUser
}

// Mode returns a string describing the active mode.
func (c *Config) Mode() string {
	if c.Analyse {
		return "analyse"
	}
	if c.Interactive {
		return "interactive"
	}
	if c.AllowList != "" || c.AllowFile != "" {
		return "allow"
	}
	return "none"
}

// IsAllowMode returns true if running in allow mode.
func (c *Config) IsAllowMode() bool {
	return c.AllowList != "" || c.AllowFile != ""
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	// Check mode selection
	hasAllow := c.AllowList != "" || c.AllowFile != ""
	modeCount := 0
	if hasAllow {
		modeCount++
	}
	if c.Analyse {
		modeCount++
	}
	if c.Interactive {
		modeCount++
	}

	if modeCount == 0 {
		return fmt.Errorf("no mode specified: use --allow, --allow-file, --analyse, or --interactive")
	}
	if modeCount > 1 {
		return fmt.Errorf("modes are mutually exclusive: choose one of --allow/--allow-file, --analyse, or --interactive")
	}

	// Check command
	if len(c.Command) == 0 {
		return fmt.Errorf("no command specified: provide a command after --")
	}

	// Check timeout
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive (got %d)", c.Timeout)
	}

	// Check DNS upstream if set
	if c.DNSUpstream != "" {
		if ip := net.ParseIP(c.DNSUpstream); ip == nil {
			return fmt.Errorf("invalid DNS upstream IP: %s", c.DNSUpstream)
		}
	}

	return nil
}

// HostVethIP returns the IP address for the host-side veth interface.
func (c *Config) HostVethIP() string {
	return fmt.Sprintf("%s.1", c.Subnet)
}

// JailVethIP returns the IP address for the namespace-side veth interface.
func (c *Config) JailVethIP() string {
	return fmt.Sprintf("%s.2", c.Subnet)
}

// SubnetCIDR returns the full subnet in CIDR notation.
func (c *Config) SubnetCIDR() string {
	return fmt.Sprintf("%s.0/24", c.Subnet)
}

// NamespaceName returns the network namespace name.
func (c *Config) NamespaceName() string {
	return fmt.Sprintf("nettrap-%s", c.SessionID)
}

// HostVethName returns the host-side veth interface name.
func (c *Config) HostVethName() string {
	return fmt.Sprintf("veth-host-%s", c.SessionID)
}

// JailVethName returns the namespace-side veth interface name.
func (c *Config) JailVethName() string {
	return fmt.Sprintf("veth-jail-%s", c.SessionID)
}
