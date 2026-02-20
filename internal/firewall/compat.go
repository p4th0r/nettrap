package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

// setupIPTablesForward adds iptables FORWARD rules to allow traffic through the veth.
// This is needed because the system's iptables FORWARD chain may have a default
// DROP policy (common with Docker). nftables and iptables coexist — both are
// evaluated — so we must ensure iptables allows the forwarded traffic.
// The actual filtering is done by our nftables rules.
func setupIPTablesForward(hostVeth string) error {
	commands := [][]string{
		{"iptables", "-I", "FORWARD", "-i", hostVeth, "-j", "ACCEPT"},
		{"iptables", "-I", "FORWARD", "-o", hostVeth, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("running %s: %w (output: %s)", strings.Join(cmdArgs, " "), err, string(output))
		}
	}

	return nil
}

// setupIP6TablesForward adds ip6tables FORWARD rules for IPv6 traffic.
func setupIP6TablesForward(hostVeth string) error {
	commands := [][]string{
		{"ip6tables", "-I", "FORWARD", "-i", hostVeth, "-j", "ACCEPT"},
		{"ip6tables", "-I", "FORWARD", "-o", hostVeth, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("running %s: %w (output: %s)", strings.Join(cmdArgs, " "), err, string(output))
		}
	}

	return nil
}

// teardownIPTablesForward removes the iptables FORWARD rules added by setupIPTablesForward.
// Idempotent — safe to call even if rules don't exist.
func teardownIPTablesForward(hostVeth string) {
	commands := [][]string{
		{"iptables", "-D", "FORWARD", "-i", hostVeth, "-j", "ACCEPT"},
		{"iptables", "-D", "FORWARD", "-o", hostVeth, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.CombinedOutput() // Ignore errors — rules may not exist
	}
}

// teardownIP6TablesForward removes ip6tables FORWARD rules.
func teardownIP6TablesForward(hostVeth string) {
	commands := [][]string{
		{"ip6tables", "-D", "FORWARD", "-i", hostVeth, "-j", "ACCEPT"},
		{"ip6tables", "-D", "FORWARD", "-o", hostVeth, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.CombinedOutput() // Ignore errors — rules may not exist
	}
}
