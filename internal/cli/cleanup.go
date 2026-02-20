// Package cli provides the cleanup subcommand for nettrap.
package cli

import (
	"fmt"

	"github.com/p4th0r/nettrap/internal/logging"
	"github.com/p4th0r/nettrap/internal/session"
	"github.com/spf13/cobra"
)

// NewCleanupCmd creates the cleanup subcommand.
func NewCleanupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cleanup",
		Short: "Remove orphaned nettrap resources",
		Long: `Finds and removes orphaned nettrap resources from crashed sessions.

This includes:
  - Network namespaces matching "nettrap-*"
  - Veth pairs matching "veth-host-*" / "veth-jail-*"
  - nftables tables matching "nettrap_*" (Phase 3)

Run this if nettrap was killed with SIGKILL or crashed, leaving resources behind.`,
		RunE: runCleanup,
	}
}

func runCleanup(cmd *cobra.Command, args []string) error {
	logger := logging.NewStderrLogger(false, false)
	logger.CleanupStart()

	// Find orphaned resources
	resources, err := session.FindOrphanedResources()
	if err != nil {
		return fmt.Errorf("finding orphaned resources: %w", err)
	}

	if len(resources) == 0 {
		logger.CleanupNone()
		return nil
	}

	// Log what we found
	for _, res := range resources {
		logger.CleanupFound(string(res.Type), res.Name)
	}

	// Clean them up
	if err := session.CleanupOrphanedResources(resources); err != nil {
		return fmt.Errorf("cleaning up resources: %w", err)
	}

	// Confirm removal
	for _, res := range resources {
		logger.CleanupRemoved(string(res.Type), res.Name)
	}

	return nil
}
