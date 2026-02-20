// Package cli provides the command-line interface for nettrap.
package cli

import (
	"github.com/p4th0r/nettrap/internal/config"
	"github.com/spf13/cobra"
)

// AddFlags adds all flags to the root command.
func AddFlags(cmd *cobra.Command, cfg *config.Config) {
	// Mode flags
	cmd.Flags().StringVar(&cfg.AllowList, "allow", "", "Comma-separated allow-list of domains, IPs, and CIDRs")
	cmd.Flags().StringVar(&cfg.AllowFile, "allow-file", "", "Path to allow-list file (one entry per line)")
	cmd.Flags().BoolVar(&cfg.Analyse, "analyse", false, "Permit all traffic, log everything")
	cmd.Flags().BoolVar(&cfg.Interactive, "interactive", false, "Prompt for each new destination")

	// Common options
	cmd.Flags().StringVar(&cfg.LogPath, "log", "", "Path for JSON log output (default: ./nettrap-<sid>-<timestamp>.json)")
	cmd.Flags().BoolVar(&cfg.NoLog, "no-log", false, "Disable JSON log file")
	cmd.Flags().StringVar(&cfg.PcapPath, "pcap", "", "Capture traffic to a pcapng file")
	cmd.Flags().StringVar(&cfg.HostPorts, "host-port", "", "Expose host loopback ports into namespace (comma-separated)")
	cmd.Flags().BoolVarP(&cfg.Quiet, "quiet", "q", false, "Suppress real-time connection logging")
	cmd.Flags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Show debug output")
	cmd.Flags().StringVar(&cfg.DNSUpstream, "dns-upstream", "", "Upstream DNS server for the proxy")
	cmd.Flags().IntVar(&cfg.Timeout, "timeout", 30, "Interactive mode: seconds before auto-denying unresponded prompts")
	cmd.Flags().BoolVar(&cfg.DryRun, "dry-run", false, "Show what would be configured without executing")
	cmd.Flags().BoolVar(&cfg.IPv6, "ipv6", false, "Enable IPv6 in namespace (disabled by default)")
	cmd.Flags().BoolVar(&cfg.RunAsRoot, "run-as-root", false, "Run the wrapped command as root instead of dropping to the calling user")
}

// ParsePositionalArgs extracts the command and its arguments from positional args.
func ParsePositionalArgs(args []string, cfg *config.Config) {
	cfg.Command = args
}
