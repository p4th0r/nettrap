// Package logging provides output formatting for nettrap.
package logging

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// StderrLogger provides formatted output to stderr.
type StderrLogger struct {
	out     io.Writer
	quiet   bool
	verbose bool
}

// NewStderrLogger creates a new StderrLogger.
func NewStderrLogger(quiet, verbose bool) *StderrLogger {
	return &StderrLogger{
		out:     os.Stderr,
		quiet:   quiet,
		verbose: verbose,
	}
}

// Info logs an informational message.
func (l *StderrLogger) Info(format string, args ...interface{}) {
	if l.quiet {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.out, "[nettrap] %s\n", msg)
}

// Debug logs a debug message (only if verbose is enabled).
func (l *StderrLogger) Debug(format string, args ...interface{}) {
	if l.quiet || !l.verbose {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.out, "[nettrap] DEBUG: %s\n", msg)
}

// Error logs an error message.
func (l *StderrLogger) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.out, "[nettrap] Error: %s\n", msg)
}

// Separator prints a visual separator line.
func (l *StderrLogger) Separator() {
	if l.quiet {
		return
	}
	fmt.Fprintln(l.out, "[nettrap] ───────────────────────────────────────────────")
}

// SessionStart logs the session start information.
func (l *StderrLogger) SessionStart(sessionID, namespace, subnet, mode, allowSummary, hostPorts string) {
	if l.quiet {
		return
	}
	l.Info("Session %s started", sessionID)
	l.Info("Namespace: %s | Subnet: %s.0/24", namespace, subnet)
	if allowSummary != "" {
		l.Info("Mode: %s | %s", mode, allowSummary)
	} else {
		l.Info("Mode: %s", mode)
	}
	if hostPorts != "" {
		l.Info("Host ports: %s", hostPorts)
	}
}

// RunningAs logs information about the privilege context the wrapped command
// will run under.
//
//   - runAsRoot=true:  --run-as-root flag was passed.
//   - noSudo=true:     SUDO_UID not available (nettrap run as root directly).
//   - otherwise:       privilege drop to user/uid/gid.
func (l *StderrLogger) RunningAs(user string, uid, gid int, runAsRoot, noSudo bool) {
	if l.quiet {
		return
	}
	switch {
	case runAsRoot:
		l.Info("Running as: root (--run-as-root)")
	case noSudo:
		fmt.Fprintf(l.out, "[nettrap] \u26a0 Running as: root (not invoked via sudo \u2014 cannot drop privileges)\n")
		l.Info("Hint: use 'sudo nettrap' instead of running as root directly")
	default:
		if user != "" {
			l.Info("Running as: %s (uid=%d, gid=%d)", user, uid, gid)
		} else {
			l.Info("Running as: uid=%d, gid=%d", uid, gid)
		}
	}
}

// SessionEnd logs the session end information.
func (l *StderrLogger) SessionEnd(sessionID string, exitCode int, duration time.Duration) {
	if l.quiet {
		return
	}
	l.Separator()
	l.Info("Session %s finished (exit code %d, duration %.1fs)", sessionID, exitCode, duration.Seconds())
}

// Executing logs the command being executed.
func (l *StderrLogger) Executing(command []string) {
	if l.quiet {
		return
	}
	cmdStr := formatCommand(command)
	l.Info("Executing: %s", cmdStr)
	l.Separator()
}

// DryRunConfig holds configuration for dry-run display.
type DryRunConfig struct {
	SessionID       string
	Namespace       string
	Subnet          string
	Mode            string
	Command         []string
	AllowEntryLines []string
	HostPorts       string
	DNSUpstream     string
	IPv6            bool
	LogPath         string
	PcapPath        string
	Timeout         int
	QueueNum        uint16

	// Privilege info
	RunAsUser string // empty when noSudo
	RunAsUID  int    // -1 when noSudo
	RunAsGID  int    // -1 when noSudo
	RunAsRoot bool   // --run-as-root flag
}

// DryRun logs dry run information.
func (l *StderrLogger) DryRun(cfg DryRunConfig) {
	l.Info("DRY RUN — no resources will be created")
	l.Separator()
	l.Info("Session ID:  %s", cfg.SessionID)
	l.Info("Namespace:   %s", cfg.Namespace)
	l.Info("Subnet:      %s.0/24", cfg.Subnet)

	hostVeth := fmt.Sprintf("veth-host-%s", cfg.SessionID)
	jailVeth := fmt.Sprintf("veth-jail-%s", cfg.SessionID)
	l.Info("Veth pair:   %s (%s.1) ↔ %s (%s.2)", hostVeth, cfg.Subnet, jailVeth, cfg.Subnet)

	l.Info("Mode:        %s", cfg.Mode)

	// Privilege info
	switch {
	case cfg.RunAsRoot:
		l.Info("Running as:  root (--run-as-root)")
	case cfg.RunAsUID > 0:
		if cfg.RunAsUser != "" {
			l.Info("Running as:  %s (uid=%d, gid=%d)", cfg.RunAsUser, cfg.RunAsUID, cfg.RunAsGID)
		} else {
			l.Info("Running as:  uid=%d, gid=%d", cfg.RunAsUID, cfg.RunAsGID)
		}
	default:
		l.Info("Running as:  root (SUDO_UID not set — cannot drop privileges)")
	}

	if len(cfg.AllowEntryLines) > 0 {
		l.Info("Allow-list entries:")
		for _, line := range cfg.AllowEntryLines {
			l.Info("  %s", line)
		}
	}
	if cfg.HostPorts != "" {
		l.Info("Host ports:  %s", cfg.HostPorts)
	}

	if cfg.DNSUpstream != "" {
		l.Info("DNS upstream: %s", cfg.DNSUpstream)
	} else {
		l.Info("DNS upstream: system default")
	}

	if cfg.IPv6 {
		l.Info("IPv6:        enabled")
	} else {
		l.Info("IPv6:        disabled")
	}

	if cfg.Mode == "interactive" {
		l.Info("NFQUEUE:     %d", cfg.QueueNum)
		l.Info("Timeout:     %ds (auto-deny)", cfg.Timeout)
		l.Info("Stdin:       reserved for prompts (wrapped command gets /dev/null)")
	}

	if cfg.LogPath != "" {
		l.Info("Log file:    %s", cfg.LogPath)
	} else {
		l.Info("Log file:    ./nettrap-%s-<timestamp>.json", cfg.SessionID)
	}

	if cfg.PcapPath != "" {
		l.Info("PCAP file:   %s", cfg.PcapPath)
	}

	l.Separator()
	l.Info("nftables table: nettrap_%s", cfg.SessionID)
	l.Info("  chain forward (filter, %s)", chainPolicyStr(cfg.Mode))
	l.Info("    ct state established,related accept")
	l.Info("    ip daddr %s.1 udp/tcp dport 53 accept  # DNS proxy", cfg.Subnet)
	if cfg.Mode == "allow" || cfg.Mode == "interactive" {
		l.Info("    ip daddr @allowed_v4 accept")
	}
	for _, hp := range strings.Split(cfg.HostPorts, ",") {
		hp = strings.TrimSpace(hp)
		if hp != "" {
			l.Info("    ip daddr %s.1 tcp dport %s accept  # host-port", cfg.Subnet, hp)
		}
	}
	if cfg.Mode == "interactive" {
		l.Info("    ct state new queue num %d bypass  # NFQUEUE", cfg.QueueNum)
	}
	l.Info("  chain nat_postrouting (masquerade)")
	if cfg.HostPorts != "" {
		l.Info("  chain nat_prerouting (DNAT for host-port → 127.0.0.1)")
	}

	l.Separator()
	l.Info("Command: %s", formatCommand(cfg.Command))
}

func chainPolicyStr(mode string) string {
	if mode == "analyse" {
		return "policy accept"
	}
	return "policy drop"
}

// formatCommand formats a command slice for display.
func formatCommand(command []string) string {
	if len(command) == 0 {
		return "(none)"
	}

	result := ""
	for i, arg := range command {
		if i > 0 {
			result += " "
		}
		// Quote arguments with spaces
		if containsSpace(arg) {
			result += fmt.Sprintf("%q", arg)
		} else {
			result += arg
		}
	}
	return result
}

func containsSpace(s string) bool {
	for _, c := range s {
		if c == ' ' || c == '\t' {
			return true
		}
	}
	return false
}

// DNSEvent logs a DNS resolution event in real-time.
func (l *StderrLogger) DNSEvent(domain, queryType, action string, ips []net.IP, cnames []string) {
	if l.quiet {
		return
	}

	ts := time.Now().Format("15:04:05")

	if action == "BLOCKED" {
		fmt.Fprintf(l.out, "[nettrap] %s DNS  BLOCKED  %s\n", ts, domain)
		return
	}

	// Format resolved IPs
	if len(ips) > 0 {
		ipStrs := make([]string, len(ips))
		for i, ip := range ips {
			ipStrs[i] = ip.String()
		}
		if queryType != "" && queryType != "A" {
			fmt.Fprintf(l.out, "[nettrap] %s DNS  ALLOWED  %s (%s) → %s\n",
				ts, domain, queryType, strings.Join(ipStrs, ", "))
		} else {
			fmt.Fprintf(l.out, "[nettrap] %s DNS  ALLOWED  %s → %s\n",
				ts, domain, strings.Join(ipStrs, ", "))
		}
	} else {
		fmt.Fprintf(l.out, "[nettrap] %s DNS  ALLOWED  %s (%s)\n", ts, domain, queryType)
	}

	// Show CNAME chain in verbose mode
	if l.verbose && len(cnames) > 0 {
		fmt.Fprintf(l.out, "[nettrap]   CNAME chain: %s\n", strings.Join(cnames, " → "))
	}
}

// DNSSummary logs DNS statistics at session end.
func (l *StderrLogger) DNSSummary(totalQueries, blockedQueries, uniqueDomains int) {
	if l.quiet {
		return
	}
	allowed := totalQueries - blockedQueries
	l.Info("DNS: %d queries (%d allowed, %d blocked), %d unique domains",
		totalQueries, allowed, blockedQueries, uniqueDomains)
}

// ConnEvent logs a connection event in real-time.
func (l *StderrLogger) ConnEvent(protocol, action string, dstIP net.IP, dstPort uint16, domain, extra string, seenCount int) {
	if l.quiet {
		return
	}

	ts := time.Now().Format("15:04:05")
	proto := strings.ToUpper(protocol)

	// Build domain/context suffix
	ctx := ""
	if extra != "" {
		ctx = fmt.Sprintf(" (%s)", extra)
	} else if domain != "" {
		ctx = fmt.Sprintf(" (%s)", domain)
	} else {
		ctx = " (unknown)"
	}

	// Verbose: show seen count
	countSuffix := ""
	if l.verbose && seenCount > 1 {
		countSuffix = fmt.Sprintf(" [seen %dx]", seenCount)
	} else if l.verbose && seenCount <= 1 {
		countSuffix = " [first seen]"
	}

	if action == "LOGGED" {
		// Analyse mode: no action label
		fmt.Fprintf(l.out, "[nettrap] %s %s  %s:%d%s%s\n",
			ts, proto, dstIP, dstPort, ctx, countSuffix)
	} else {
		fmt.Fprintf(l.out, "[nettrap] %s %s  %-7s  %s:%d%s%s\n",
			ts, proto, action, dstIP, dstPort, ctx, countSuffix)
	}
}

// DoHWarning logs a warning about a possible DoH/DoT connection.
func (l *StderrLogger) DoHWarning(dstIP net.IP, dstPort uint16, provider string) {
	if l.quiet {
		return
	}
	ts := time.Now().Format("15:04:05")
	fmt.Fprintf(l.out, "[nettrap] %s TCP  %s:%d — possible DoH (%s) — DNS queries may not be visible\n",
		ts, dstIP, dstPort, provider)
}

// PrintSessionSummary prints the full session-end summary to stderr.
func (l *StderrLogger) PrintSessionSummary(sessionID string, exitCode int, duration time.Duration, mode string, summary Summary, allowed []DestInfo, blockedDNS map[string]int, dropped []DestInfo) {
	if l.quiet {
		return
	}

	l.Separator()
	l.Info("Session %s finished (exit code %d, duration %.1fs)", sessionID, exitCode, duration.Seconds())

	// DNS summary
	if mode == "allow" {
		l.Info("DNS: %d queries (%d allowed, %d blocked)",
			summary.TotalDNSQueries, summary.AllowedDNSQueries, summary.BlockedDNSQueries)
	} else {
		l.Info("DNS: %d queries, %d unique domains",
			summary.TotalDNSQueries, summary.UniqueDNSDomains)
	}

	// Connection summary
	if mode == "allow" || mode == "interactive" {
		l.Info("Connections: %d total (%d allowed, %d dropped), %d unique destinations",
			summary.TotalConnections, summary.AllowedConnections, summary.DroppedConnections, summary.UniqueDestinations)
	} else {
		l.Info("Connections: %d total, %d unique destinations",
			summary.TotalConnections, summary.UniqueDestinations)
	}

	// Detailed destination list
	if mode == "allow" {
		if len(allowed) > 0 {
			l.Info("  Allowed destinations:")
			for _, d := range allowed {
				label := d.IP
				if d.Domain != "" {
					label = fmt.Sprintf("%s (%s)", d.Domain, d.IP)
				}
				l.Info("    %s — %d/%s ×%d", label, d.Port, d.Protocol, d.Count)
			}
		}
		if len(blockedDNS) > 0 {
			l.Info("  Blocked DNS queries:")
			for domain, count := range blockedDNS {
				l.Info("    %s ×%d", domain, count)
			}
		}
		if len(dropped) > 0 {
			l.Info("  Dropped connections:")
			for _, d := range dropped {
				label := fmt.Sprintf("%s:%d/%s", d.IP, d.Port, d.Protocol)
				note := ""
				if d.Domain == "" {
					note = " (no matching DNS — hardcoded IP?)"
				}
				l.Info("    %s ×%d%s", label, d.Count, note)
			}
		}
	} else if mode == "interactive" {
		if len(allowed) > 0 {
			l.Info("  Approved:")
			for _, d := range allowed {
				label := d.IP
				if d.Domain != "" {
					label = fmt.Sprintf("%s (%s)", d.Domain, d.IP)
				}
				decision := ""
				if d.Decision != "" {
					decision = fmt.Sprintf(" [%s]", d.Decision)
				}
				l.Info("    %s — %d/%s ×%d%s", label, d.Port, d.Protocol, d.Count, decision)
			}
		}
		if len(dropped) > 0 {
			l.Info("  Denied:")
			for _, d := range dropped {
				label := fmt.Sprintf("%s:%d/%s", d.IP, d.Port, d.Protocol)
				decision := ""
				if d.Decision != "" {
					decision = fmt.Sprintf(" [%s]", d.Decision)
				}
				l.Info("    %s ×%d%s", label, d.Count, decision)
			}
		}
	} else {
		// Analyse mode
		if len(allowed) > 0 {
			l.Info("  Destinations:")
			for _, d := range allowed {
				label := d.IP
				if d.Domain != "" {
					label = fmt.Sprintf("%s (%s)", d.Domain, d.IP)
				}
				l.Info("    %s — %d/%s ×%d", label, d.Port, d.Protocol, d.Count)
			}
		}
	}
}

// CleanupStart logs the start of cleanup.
func (l *StderrLogger) CleanupStart() {
	l.Info("Scanning for orphaned nettrap resources...")
}

// CleanupFound logs found orphaned resources.
func (l *StderrLogger) CleanupFound(resourceType, name string) {
	l.Info("Found orphaned %s: %s", resourceType, name)
}

// CleanupRemoved logs a removed resource.
func (l *StderrLogger) CleanupRemoved(resourceType, name string) {
	l.Info("Removed %s: %s", resourceType, name)
}

// CleanupNone logs when no orphaned resources were found.
func (l *StderrLogger) CleanupNone() {
	l.Info("No orphaned resources found")
}
