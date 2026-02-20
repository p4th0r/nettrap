// Package cli provides the completion subcommand for nettrap.
package cli

import (
	"os"

	"github.com/spf13/cobra"
)

// NewCompletionCmd creates the completion subcommand with shell-specific subcommands.
func NewCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for nettrap.

To load completions:

Bash:
  $ source <(nettrap completion bash)
  # To load completions for each session, execute once:
  $ nettrap completion bash > /etc/bash_completion.d/nettrap

Zsh:
  $ source <(nettrap completion zsh)
  # To load completions for each session, execute once:
  $ nettrap completion zsh > "${fpath[1]}/_nettrap"

Fish:
  $ nettrap completion fish | source
  # To load completions for each session, execute once:
  $ nettrap completion fish > ~/.config/fish/completions/nettrap.fish`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			}
			return nil
		},
	}

	return cmd
}
