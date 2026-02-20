// Package capture provides packet capture functionality for nettrap sessions.
package capture

import (
	"fmt"
	"strings"
)

// BuildSectionComment returns a comment string for the pcapng section header.
func BuildSectionComment(version, sessionID, mode string, command []string, allowList []string) string {
	var sb strings.Builder

	if version != "" {
		fmt.Fprintf(&sb, "nettrap %s | session %s\n", version, sessionID)
	} else {
		fmt.Fprintf(&sb, "nettrap | session %s\n", sessionID)
	}
	fmt.Fprintf(&sb, "mode: %s\n", mode)
	fmt.Fprintf(&sb, "command: %s\n", strings.Join(command, " "))
	if len(allowList) > 0 {
		fmt.Fprintf(&sb, "allow-list: %s\n", strings.Join(allowList, ", "))
	}

	return sb.String()
}
