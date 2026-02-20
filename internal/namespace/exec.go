// Package namespace provides command execution inside network namespaces.
package namespace

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/vishvananda/netns"
)

// ExecConfig holds options for executing a command in a namespace.
type ExecConfig struct {
	NSName         string   // network namespace name
	Command        []string // command and arguments
	ResolvConfPath string   // if set, bind-mount this file over /etc/resolv.conf
	NullStdin      bool     // if true, connect child stdin to /dev/null

	// Privilege dropping — set DropUID > 0 to drop privileges before exec.
	DropUID  int    // target UID (0 or -1 = no drop)
	DropGID  int    // target GID
	DropUser string // username for --init-groups supplementary group lookup

	// Env overrides the child process environment when non-nil.
	// Used to remove SUDO_* variables and set correct HOME/USER/LOGNAME.
	Env []string
}

// ExecuteInNamespace runs a command inside the specified network namespace.
// Returns the exit code of the command.
func ExecuteInNamespace(ctx context.Context, nsName string, command []string) (int, error) {
	return ExecuteInNamespaceWithConfig(ctx, ExecConfig{
		NSName:  nsName,
		Command: command,
	})
}

// ExecuteInNamespaceWithConfig runs a command inside a network namespace
// with additional configuration options like custom resolv.conf and privilege dropping.
func ExecuteInNamespaceWithConfig(ctx context.Context, cfg ExecConfig) (int, error) {
	if len(cfg.Command) == 0 {
		return 1, fmt.Errorf("no command specified")
	}

	nsPath := GetPath(cfg.NSName)

	nsenterPath, err := exec.LookPath("nsenter")
	if err != nil {
		return 1, fmt.Errorf("nsenter not found: %w", err)
	}

	dropping := cfg.DropUID > 0

	// Build the privilege-drop argument prefix (inserted after the nsenter "--").
	// dropArgs are the setpriv invocation, or nil on fallback.
	var dropArgs []string
	// nsenterFlags carries --setuid/--setgid for the nsenter fallback.
	var nsenterDropFlags []string
	if dropping {
		setprivPath, spErr := exec.LookPath("setpriv")
		if spErr == nil {
			// Preferred: use setpriv so supplementary groups are initialised.
			dropArgs = []string{
				setprivPath,
				fmt.Sprintf("--reuid=%d", cfg.DropUID),
				fmt.Sprintf("--regid=%d", cfg.DropGID),
			}
			if cfg.DropUser != "" {
				dropArgs = append(dropArgs, "--init-groups")
			}
			dropArgs = append(dropArgs, "--")
		} else {
			// Fallback: nsenter's own --setuid/--setgid (no supplementary groups).
			nsenterDropFlags = []string{
				fmt.Sprintf("--setuid=%d", cfg.DropUID),
				fmt.Sprintf("--setgid=%d", cfg.DropGID),
			}
		}
	}

	var cmd *exec.Cmd

	if cfg.ResolvConfPath != "" {
		// When we have a custom resolv.conf, we need a mount namespace to
		// bind-mount it without affecting the host.  The shell script runs as
		// root (to perform the bind-mount), then exec's either setpriv (for
		// privilege drop) or the wrapped command directly.
		//
		// Full invocation:
		//   nsenter [--setuid=N --setgid=N] --net=<path> --
		//     unshare --mount --propagation private --
		//       sh -c 'mount --bind <resolvconf> /etc/resolv.conf; exec "$@"' _
		//         [setpriv --reuid=N --regid=N [--init-groups] --]
		//         <cmd> <args>
		//
		// Note: when using setpriv, nsenterDropFlags is empty (no --setuid on nsenter
		// itself), because the privilege drop happens inside the sh -c script via setpriv.
		// When using the nsenter fallback, nsenterDropFlags carries --setuid/--setgid
		// and dropArgs is nil.
		unshare, err := exec.LookPath("unshare")
		if err != nil {
			return 1, fmt.Errorf("unshare not found: %w", err)
		}
		sh, err := exec.LookPath("sh")
		if err != nil {
			return 1, fmt.Errorf("sh not found: %w", err)
		}

		args := []string{nsenterPath}
		args = append(args, nsenterDropFlags...)
		args = append(args,
			"--net="+nsPath,
			"--",
			unshare,
			"--mount",
			"--propagation", "private",
			"--",
			sh, "-c",
			fmt.Sprintf("mount --bind %s /etc/resolv.conf; exec \"$@\"", cfg.ResolvConfPath),
			"_", // $0 placeholder for sh -c
		)
		args = append(args, dropArgs...)
		args = append(args, cfg.Command...)
		cmd = exec.CommandContext(ctx, args[0], args[1:]...)
	} else {
		// Simple nsenter without a mount namespace.
		args := []string{nsenterPath}
		args = append(args, nsenterDropFlags...)
		args = append(args, "--net="+nsPath, "--")
		args = append(args, dropArgs...)
		args = append(args, cfg.Command...)
		cmd = exec.CommandContext(ctx, args[0], args[1:]...)
	}

	if cfg.NullStdin {
		devNull, nerr := os.Open(os.DevNull)
		if nerr != nil {
			return 1, fmt.Errorf("opening /dev/null: %w", nerr)
		}
		defer devNull.Close()
		cmd.Stdin = devNull
	} else {
		cmd.Stdin = os.Stdin
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set the process group so we can signal all children.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Override the child environment when requested.
	if cfg.Env != nil {
		cmd.Env = cfg.Env
	}

	err = cmd.Run()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return status.ExitStatus(), nil
			}
			return 1, nil
		}
		return 1, fmt.Errorf("executing command: %w", err)
	}

	return 0, nil
}

// ExecuteInNamespaceWithHandle runs a command using an existing namespace handle.
func ExecuteInNamespaceWithHandle(ctx context.Context, nsHandle netns.NsHandle, command []string) (int, error) {
	if len(command) == 0 {
		return 1, fmt.Errorf("no command specified")
	}

	cmdPath, err := exec.LookPath(command[0])
	if err != nil {
		cmdPath = command[0]
	}

	nsenterPath, err := exec.LookPath("nsenter")
	if err != nil {
		return 1, fmt.Errorf("nsenter not found: %w", err)
	}

	nsenterArgs := []string{
		nsenterPath,
		fmt.Sprintf("--net=/proc/self/fd/%d", int(nsHandle)),
		"--",
	}
	nsenterArgs = append(nsenterArgs, cmdPath)
	nsenterArgs = append(nsenterArgs, command[1:]...)

	cmd := exec.CommandContext(ctx, nsenterArgs[0], nsenterArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	err = cmd.Run()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return status.ExitStatus(), nil
			}
			return 1, nil
		}
		return 1, fmt.Errorf("executing command: %w", err)
	}

	return 0, nil
}

// SignalProcessGroup sends a signal to the process group of a running command.
func SignalProcessGroup(pid int, sig syscall.Signal) error {
	return syscall.Kill(-pid, sig)
}

// BuildUserEnv constructs an environment for the privilege-dropped child process.
// It starts from the current process environment, removes all SUDO_* variables,
// and overrides HOME, USER, LOGNAME, and UID to match the target user.
func BuildUserEnv(uid, gid int, username string) []string {
	homeDir := "/tmp" // safe fallback
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		if u.HomeDir != "" {
			homeDir = u.HomeDir
		}
		if username == "" {
			username = u.Username
		}
	}

	overrides := map[string]string{
		"HOME":    homeDir,
		"USER":    username,
		"LOGNAME": username,
		"UID":     strconv.Itoa(uid),
	}

	base := os.Environ()
	filtered := make([]string, 0, len(base)+len(overrides))
	for _, e := range base {
		key := strings.SplitN(e, "=", 2)[0]
		if strings.HasPrefix(key, "SUDO_") {
			continue
		}
		if _, override := overrides[key]; override {
			continue
		}
		filtered = append(filtered, e)
	}
	for k, v := range overrides {
		filtered = append(filtered, k+"="+v)
	}
	return filtered
}
