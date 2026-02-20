// Package cli provides the root command and main execution flow for nettrap.
package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/p4th0r/nettrap/internal/allowlist"
	"github.com/p4th0r/nettrap/internal/capture"
	"github.com/p4th0r/nettrap/internal/config"
	nfdns "github.com/p4th0r/nettrap/internal/dns"
	"github.com/p4th0r/nettrap/internal/firewall"
	"github.com/p4th0r/nettrap/internal/hostport"
	"github.com/p4th0r/nettrap/internal/interactive"
	"github.com/p4th0r/nettrap/internal/logging"
	"github.com/p4th0r/nettrap/internal/namespace"
	"github.com/p4th0r/nettrap/internal/session"
	"github.com/spf13/cobra"
)

// NewRootCmd creates the root command for nettrap.
func NewRootCmd(version ...string) *cobra.Command {
	ver := "dev"
	if len(version) > 0 && version[0] != "" {
		ver = version[0]
	}
	cfg := &config.Config{}

	cmd := &cobra.Command{
		Use:   "nettrap [MODE FLAGS] [OPTIONS] -- <command> [args...]",
		Short: "Network isolation tool for untrusted commands",
		Long: `nettrap wraps untrusted commands inside a kernel-enforced network namespace
with controlled, filtered egress.

Modes (exactly one required):
  --allow <list>      Comma-separated allow-list of domains, IPs, CIDRs
  --allow-file <path> Path to allow-list file
  --analyse           Permit all traffic, log everything
  --interactive       Prompt for each new destination

The -- separator is mandatory to distinguish nettrap flags from the wrapped command.

Example:
  nettrap --analyse -- curl https://example.com
  nettrap --allow "example.com,10.0.0.0/8" -- python3 tool.py`,
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: false,
		SilenceUsage:       true,
		SilenceErrors:      true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ParsePositionalArgs(args, cfg)
			return runNettrap(cfg)
		},
	}

	AddFlags(cmd, cfg)

	// Add subcommands
	cmd.AddCommand(NewCleanupCmd())
	cmd.AddCommand(NewVersionCmd(ver))
	cmd.AddCommand(NewCompletionCmd())

	return cmd
}

func runNettrap(cfg *config.Config) error {
	// Platform check
	if err := checkPlatform(); err != nil {
		return err
	}

	logger := logging.NewStderrLogger(cfg.Quiet, cfg.Verbose)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Parse allow-list if in allow mode
	var matcher *allowlist.Matcher
	if cfg.IsAllowMode() {
		entries, err := allowlist.Parse(cfg.AllowList, cfg.AllowFile)
		if err != nil {
			return fmt.Errorf("parsing allow-list: %w", err)
		}
		matcher, err = allowlist.NewMatcher(entries)
		if err != nil {
			return fmt.Errorf("creating allow-list matcher: %w", err)
		}
	}

	// Parse host-port if specified
	var hostPorts []int
	if cfg.HostPorts != "" {
		var err error
		hostPorts, err = hostport.Parse(cfg.HostPorts)
		if err != nil {
			return fmt.Errorf("parsing host-port: %w", err)
		}
	}

	// Generate session ID (needed for dry run display)
	sessionID, err := session.GenerateSessionID()
	if err != nil {
		return fmt.Errorf("generating session ID: %w", err)
	}
	cfg.SessionID = sessionID

	// Allocate subnet (needed for dry run display)
	subnet, err := session.AllocateSubnet(sessionID)
	if err != nil {
		return fmt.Errorf("allocating subnet: %w", err)
	}
	cfg.Subnet = subnet

	// Detect the identity of the real user behind sudo.  Done early so dry-run
	// can also display the privilege context.
	cfg.CallerUID, cfg.CallerGID, cfg.CallerUser = config.DetectCallerIdentity()

	// Handle dry run (before privilege checks so it works without sudo)
	if cfg.DryRun {
		var entryLines []string
		if matcher != nil {
			for _, e := range matcher.GetEntries() {
				entryLines = append(entryLines, e.String())
			}
		}

		var queueNum uint16
		if cfg.Interactive {
			queueNum = interactive.QueueNumFromSessionID(cfg.SessionID)
		}

		logger.DryRun(logging.DryRunConfig{
			SessionID:       cfg.SessionID,
			Namespace:       cfg.NamespaceName(),
			Subnet:          cfg.Subnet,
			Mode:            cfg.Mode(),
			Command:         cfg.Command,
			AllowEntryLines: entryLines,
			HostPorts:       cfg.HostPorts,
			DNSUpstream:     cfg.DNSUpstream,
			IPv6:            cfg.IPv6,
			LogPath:         cfg.LogPath,
			PcapPath:        cfg.PcapPath,
			Timeout:         cfg.Timeout,
			QueueNum:        queueNum,
			RunAsUser:       cfg.CallerUser,
			RunAsUID:        cfg.CallerUID,
			RunAsGID:        cfg.CallerGID,
			RunAsRoot:       cfg.RunAsRoot,
		})
		return nil
	}

	// Check privileges (only needed for actual execution)
	if err := checkPrivileges(); err != nil {
		return err
	}

	// Log the privilege context the wrapped command will run under.
	noSudo := cfg.CallerUID <= 0
	logger.RunningAs(cfg.CallerUser, cfg.CallerUID, cfg.CallerGID, cfg.RunAsRoot, noSudo)

	// Read host's upstream DNS BEFORE creating the namespace
	dnsUpstream := cfg.DNSUpstream
	if dnsUpstream == "" {
		dnsUpstream = namespace.GetHostNameserver()
		if dnsUpstream == "" {
			dnsUpstream = "1.1.1.1" // last resort fallback
		}
	}
	logger.Debug("Upstream DNS: %s", dnsUpstream)

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Track resources for cleanup
	var (
		namespaceCreated   bool
		vethCreated        bool
		firewallCreated    bool
		dnsProxyStarted    bool
		routeLocalnetSet   bool
		connTrackerStarted bool
		pcapStarted        bool
		eventLoggerStarted bool
		nfqueueStarted     bool
		dnsProxy           *nfdns.Proxy
		dnsTracker         *nfdns.Tracker
		fw                 *firewall.Firewall
		connTracker        *firewall.ConnTracker
		pcapCapture        *capture.Capture
		eventLogger        *logging.EventLogger
		nfqueueHandler     *interactive.NFQueueHandler
		sessionWhitelist   *interactive.Whitelist
	)

	// Cleanup function
	cleanup := func() {
		logger.Debug("Running cleanup...")

		if nfqueueStarted && nfqueueHandler != nil {
			logger.Debug("Stopping NFQUEUE handler...")
			if err := nfqueueHandler.Stop(); err != nil {
				logger.Debug("NFQUEUE stop error: %v", err)
			}
		}

		if pcapStarted && pcapCapture != nil {
			logger.Debug("Stopping PCAP capture...")
			if err := pcapCapture.Stop(); err != nil {
				logger.Debug("PCAP stop error: %v", err)
			}
		}

		if connTrackerStarted && connTracker != nil {
			logger.Debug("Stopping connection tracker...")
			connTracker.Stop()
		}

		if dnsProxyStarted && dnsProxy != nil {
			logger.Debug("Stopping DNS proxy...")
			if err := dnsProxy.Stop(); err != nil {
				logger.Debug("DNS proxy stop error: %v", err)
			}
		}

		if eventLoggerStarted && eventLogger != nil {
			logger.Debug("Stopping event logger...")
			eventLogger.Stop()
		}

		if firewallCreated && fw != nil {
			logger.Debug("Tearing down nftables rules...")
			if err := fw.Teardown(); err != nil {
				logger.Debug("Firewall teardown error: %v", err)
			}
		}

		if routeLocalnetSet {
			if err := hostport.DisableRouteLocalnet(cfg.HostVethName()); err != nil {
				logger.Debug("Route localnet cleanup error: %v", err)
			}
		}

		if vethCreated {
			if err := namespace.TeardownVethPair(cfg.SessionID); err != nil {
				logger.Debug("Veth cleanup error: %v", err)
			}
		}

		if namespaceCreated {
			if err := namespace.Delete(cfg.NamespaceName()); err != nil {
				logger.Debug("Namespace cleanup error: %v", err)
			}
		}

		// Clean up temp resolv.conf
		namespace.CleanupResolvConf(cfg.SessionID)
	}

	// Ensure cleanup runs on exit
	defer cleanup()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Handle signals in a goroutine
	go func() {
		sig := <-sigChan
		logger.Debug("Received signal: %v", sig)
		cancel() // Cancel the context
	}()

	// Create network namespace
	logger.Debug("Creating namespace: %s", cfg.NamespaceName())
	if err := namespace.Create(cfg.NamespaceName()); err != nil {
		return fmt.Errorf("creating namespace: %w", err)
	}
	namespaceCreated = true

	// Set up veth pair
	logger.Debug("Setting up veth pair...")
	vethCfg := namespace.VethConfig{
		SessionID:     cfg.SessionID,
		Subnet:        cfg.Subnet,
		NamespaceName: cfg.NamespaceName(),
		DisableIPv6:   !cfg.IPv6,
	}
	if err := namespace.SetupVethPair(vethCfg); err != nil {
		return fmt.Errorf("setting up veth: %w", err)
	}
	vethCreated = true

	// Enable IP forwarding
	logger.Debug("Enabling IP forwarding...")
	if err := namespace.EnableIPForwarding(cfg.SessionID); err != nil {
		return fmt.Errorf("enabling IP forwarding: %w", err)
	}

	// Set up nftables firewall
	logger.Debug("Setting up nftables rules...")
	var queueNum uint16
	if cfg.Interactive {
		queueNum = interactive.QueueNumFromSessionID(cfg.SessionID)
	}

	fw = firewall.New(firewall.Config{
		SessionID: cfg.SessionID,
		Subnet:    cfg.Subnet,
		HostVeth:  cfg.HostVethName(),
		Mode:      cfg.Mode(),
		IPv6:      cfg.IPv6,
		HostPorts: hostPorts,
		QueueNum:  queueNum,
		Logger:    logger,
	})
	if err := fw.Setup(matcher); err != nil {
		return fmt.Errorf("setting up firewall: %w", err)
	}
	firewallCreated = true

	// Set up host-port forwarding if requested
	if len(hostPorts) > 0 {
		logger.Debug("Setting up host-port forwarding for ports: %v", hostPorts)

		if err := hostport.EnableRouteLocalnet(cfg.HostVethName()); err != nil {
			return fmt.Errorf("enabling route_localnet: %w", err)
		}
		routeLocalnetSet = true

		if err := hostport.SetupNamespaceDNAT(cfg.NamespaceName(), cfg.SessionID, cfg.Subnet, hostPorts); err != nil {
			return fmt.Errorf("setting up namespace DNAT: %w", err)
		}
	}

	// Write resolv.conf temp file pointing to DNS proxy address
	resolvPath, err := namespace.WriteResolvConfFile(cfg.SessionID, cfg.HostVethIP())
	if err != nil {
		return fmt.Errorf("writing resolv.conf: %w", err)
	}

	// Create event logger
	eventLogger = logging.NewEventLogger(logger, cfg.Mode())
	eventLogger.Start()
	eventLoggerStarted = true

	// Create DNS tracker and proxy
	dnsTracker = nfdns.NewTracker()

	var allowChecker nfdns.AllowChecker
	if matcher != nil {
		allowChecker = matcher
	}

	dnsProxy = nfdns.NewProxy(nfdns.ProxyConfig{
		ListenAddr:   cfg.HostVethIP() + ":53",
		Upstream:     dnsUpstream,
		Tracker:      dnsTracker,
		Logger:       logger,
		AllowChecker: allowChecker,
	})

	// Wire DNS events to event logger
	dnsProxy.EventCh = eventLogger.EventCh()

	// Wire DNS → firewall callback for dynamic set updates in allow mode
	if cfg.IsAllowMode() {
		dnsProxy.OnAllowedResolve = func(domain string, ips []net.IP) {
			if err := fw.AddAllowedIPs(ips); err != nil {
				logger.Debug("Failed to add resolved IPs to firewall: %v", err)
			}
		}
	}

	// Start DNS proxy
	logger.Debug("Starting DNS proxy on %s:53...", cfg.HostVethIP())
	if err := dnsProxy.Start(); err != nil {
		return fmt.Errorf("starting DNS proxy: %w", err)
	}
	dnsProxyStarted = true

	// Create and start connection tracker
	connTracker = firewall.NewConnTracker(firewall.ConnTrackerConfig{
		NamespaceIP: cfg.JailVethIP(),
		HostVethIP:  cfg.HostVethIP(),
		HostPorts:   hostPorts,
		Mode:        cfg.Mode(),
		DNSTracker:  dnsTracker,
		EventCh:     eventLogger.EventCh(),
		Logger:      logger,
	})
	if err := connTracker.Start(); err != nil {
		// Non-fatal: connection tracking is optional
		logger.Debug("Connection tracking unavailable: %v", err)
	} else {
		connTrackerStarted = true
	}

	// Start PCAP capture if requested
	if cfg.PcapPath != "" {
		comment := capture.BuildSectionComment("", cfg.SessionID, cfg.Mode(), cfg.Command, nil)
		if matcher != nil {
			var entries []string
			for _, e := range matcher.GetEntries() {
				entries = append(entries, e.String())
			}
			comment = capture.BuildSectionComment("", cfg.SessionID, cfg.Mode(), cfg.Command, entries)
		}

		pcapCapture = capture.New(capture.CaptureConfig{
			Interface: cfg.HostVethName(),
			FilePath:  cfg.PcapPath,
			Logger:    logger,
			Comment:   comment,
		})
		if err := pcapCapture.Start(); err != nil {
			return fmt.Errorf("starting PCAP capture: %w", err)
		}
		pcapStarted = true
	}

	// Set up interactive mode (NFQUEUE handler, whitelist, prompter)
	if cfg.Interactive {
		sessionWhitelist = interactive.NewWhitelist(dnsTracker)

		// Wire auto-whitelisting: when DNS resolves IPs for an already-approved domain
		dnsProxy.OnResolve = func(domain string, ips []net.IP) {
			if sessionWhitelist.IsDomainApproved(domain) {
				sessionWhitelist.ApproveIPsForDomain(domain, ips)
				if err := fw.AddAllowedIPs(ips); err != nil {
					logger.Debug("Failed to add auto-whitelisted IPs: %v", err)
				}
			}
		}

		prompter := interactive.NewPrompter(ctx, time.Duration(cfg.Timeout)*time.Second, dnsTracker, logger)

		nfqueueHandler = interactive.NewNFQueueHandler(interactive.NFQueueConfig{
			QueueNum:   queueNum,
			Whitelist:  sessionWhitelist,
			Firewall:   fw,
			DNSTracker: dnsTracker,
			Prompter:   prompter,
			EventCh:    eventLogger.EventCh(),
			Logger:     logger,
		})
		if err := nfqueueHandler.Start(); err != nil {
			return fmt.Errorf("starting NFQUEUE handler: %w", err)
		}
		nfqueueStarted = true
	}

	// Record session start time
	startTime := time.Now()

	// Log session start
	allowSummary := ""
	if matcher != nil {
		allowSummary = matcher.Summary()
	}
	logger.SessionStart(cfg.SessionID, cfg.NamespaceName(), cfg.Subnet, cfg.Mode(), allowSummary, cfg.HostPorts)
	if cfg.Interactive {
		logger.Info("Note: stdin is reserved for nettrap prompts — wrapped command receives no stdin")
	}
	logger.Executing(cfg.Command)

	// Build exec configuration — drop privileges to calling user unless --run-as-root.
	execCfg := namespace.ExecConfig{
		NSName:         cfg.NamespaceName(),
		Command:        cfg.Command,
		ResolvConfPath: resolvPath,
		NullStdin:      cfg.Interactive,
	}
	if !cfg.RunAsRoot && cfg.CallerUID > 0 {
		execCfg.DropUID = cfg.CallerUID
		execCfg.DropGID = cfg.CallerGID
		execCfg.DropUser = cfg.CallerUser
		execCfg.Env = namespace.BuildUserEnv(cfg.CallerUID, cfg.CallerGID, cfg.CallerUser)
	}

	// Execute command in namespace with custom resolv.conf
	exitCode, err := namespace.ExecuteInNamespaceWithConfig(ctx, execCfg)
	if err != nil {
		// Check if it was cancelled (signal received)
		if ctx.Err() != nil {
			logger.Debug("Command cancelled by signal")
			// Give the process a moment to clean up
			time.Sleep(100 * time.Millisecond)
		} else {
			logger.Error("Command execution failed: %v", err)
		}
	}

	// Record session end time
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Allow a brief window for final conntrack events to arrive
	time.Sleep(200 * time.Millisecond)

	// Stop PCAP capture
	if pcapStarted && pcapCapture != nil {
		logger.Debug("Stopping PCAP capture...")
		if err := pcapCapture.Stop(); err != nil {
			logger.Debug("PCAP stop error: %v", err)
		}
		pcapStarted = false
	}

	// Stop NFQUEUE handler
	if nfqueueStarted && nfqueueHandler != nil {
		logger.Debug("Stopping NFQUEUE handler...")
		if err := nfqueueHandler.Stop(); err != nil {
			logger.Debug("NFQUEUE stop error: %v", err)
		}
		nfqueueStarted = false
	}

	// Stop connection tracker
	if connTrackerStarted && connTracker != nil {
		logger.Debug("Stopping connection tracker...")
		connTracker.Stop()
		connTrackerStarted = false
	}

	// Stop DNS proxy
	if dnsProxyStarted && dnsProxy != nil {
		logger.Debug("Stopping DNS proxy...")
		if err := dnsProxy.Stop(); err != nil {
			logger.Debug("DNS proxy stop error: %v", err)
		}
		dnsProxyStarted = false
	}

	// Stop event logger (drain remaining events)
	if eventLoggerStarted && eventLogger != nil {
		eventLogger.Stop()
		eventLoggerStarted = false
	}

	// Print session summary
	summary := eventLogger.GetSummary()
	allowed, blockedDNS, dropped := eventLogger.GetDetailedSummary()
	logger.PrintSessionSummary(cfg.SessionID, exitCode, duration, cfg.Mode(), summary, allowed, blockedDNS, dropped)

	// Write JSON log file
	if !cfg.NoLog {
		logPath := cfg.LogPath
		if logPath == "" {
			logPath = logging.DefaultLogPath(cfg.SessionID)
		}

		// Determine what the wrapped command ran as for the JSON log.
		runAsUser := "root"
		runAsUID := 0
		if !cfg.RunAsRoot && cfg.CallerUID > 0 {
			runAsUID = cfg.CallerUID
			runAsUser = cfg.CallerUser
			if runAsUser == "" {
				runAsUser = fmt.Sprintf("uid=%d", cfg.CallerUID)
			}
		}

		sessionInfo := logging.SessionInfo{
			ID:           cfg.SessionID,
			StartTime:    startTime,
			EndTime:      endTime,
			DurationSecs: duration.Seconds(),
			Mode:         cfg.Mode(),
			Command:      cfg.Command,
			ExitCode:     exitCode,
			Namespace:    cfg.NamespaceName(),
			Subnet:       cfg.Subnet + ".0/24",
			HostPorts:    hostPorts,
			RunAsUser:    runAsUser,
			RunAsUID:     runAsUID,
			RunAsRoot:    cfg.RunAsRoot,
		}
		if matcher != nil {
			for _, e := range matcher.GetEntries() {
				sessionInfo.AllowList = append(sessionInfo.AllowList, e.Raw)
			}
		}

		events := eventLogger.GetEvents()
		jsonLog := logging.BuildJSONLog(sessionInfo, events, summary)

		if err := logging.WriteJSONLog(logPath, jsonLog); err != nil {
			logger.Error("Failed to write JSON log: %v", err)
		} else {
			logger.Debug("JSON log written to %s", logPath)
		}

		// Chown log file to calling user so they can read it without sudo.
		if cfg.CallerUID > 0 {
			if err := os.Chown(logPath, cfg.CallerUID, cfg.CallerGID); err != nil {
				logger.Debug("Chown log file: %v", err)
			}
		}
	}

	// Chown PCAP file to calling user if one was written.
	if cfg.PcapPath != "" && cfg.CallerUID > 0 {
		if err := os.Chown(cfg.PcapPath, cfg.CallerUID, cfg.CallerGID); err != nil {
			logger.Debug("Chown pcap file: %v", err)
		}
	}

	// Teardown firewall
	if firewallCreated && fw != nil {
		logger.Debug("Tearing down nftables rules...")
		if err := fw.Teardown(); err != nil {
			logger.Debug("Firewall teardown error: %v", err)
		}
		firewallCreated = false
	}

	// Disable route_localnet
	if routeLocalnetSet {
		if err := hostport.DisableRouteLocalnet(cfg.HostVethName()); err != nil {
			logger.Debug("Route localnet cleanup error: %v", err)
		}
		routeLocalnetSet = false
	}

	// Teardown veth
	if vethCreated {
		if err := namespace.TeardownVethPair(cfg.SessionID); err != nil {
			logger.Debug("Veth cleanup error: %v", err)
		}
		vethCreated = false
	}

	// Delete namespace
	if namespaceCreated {
		if err := namespace.Delete(cfg.NamespaceName()); err != nil {
			logger.Debug("Namespace cleanup error: %v", err)
		}
		namespaceCreated = false
	}

	// Clean up temp resolv.conf
	namespace.CleanupResolvConf(cfg.SessionID)

	// Exit with the wrapped command's exit code
	os.Exit(exitCode)
	return nil
}

// checkPrivileges verifies we have sufficient privileges to run.
func checkPrivileges() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("nettrap requires root privileges — run with sudo")
	}
	return nil
}

// checkPlatform ensures we're running on Linux.
func checkPlatform() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("nettrap requires Linux (network namespaces are a Linux kernel feature)")
	}
	return nil
}
