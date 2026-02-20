// nettrap is a Linux network isolation tool that wraps untrusted commands
// inside a kernel-enforced network namespace with controlled, filtered egress.
package main

import (
	"fmt"
	"os"

	"github.com/p4th0r/nettrap/internal/cli"
)

// version is set via ldflags at build time
var version = "dev"

func main() {
	rootCmd := cli.NewRootCmd(version)
	rootCmd.Version = version

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "[nettrap] Error: %v\n", err)
		os.Exit(1)
	}
}
