// Package namespace provides network namespace creation and management.
package namespace

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const nsRunDir = "/var/run/netns"

// Create creates a named network namespace.
// Uses the bind-mount approach that makes the namespace visible to `ip netns list`.
func Create(name string) error {
	// Ensure the namespace directory exists
	if err := os.MkdirAll(nsRunDir, 0755); err != nil {
		return fmt.Errorf("creating namespace directory: %w", err)
	}

	nsPath := filepath.Join(nsRunDir, name)

	// Create the file that will be the mount point
	f, err := os.Create(nsPath)
	if err != nil {
		return fmt.Errorf("creating namespace file: %w", err)
	}
	f.Close()

	// Lock the OS thread because we're about to switch network namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save reference to current namespace so we can return to it
	origNS, err := netns.Get()
	if err != nil {
		os.Remove(nsPath)
		return fmt.Errorf("getting current namespace: %w", err)
	}
	defer origNS.Close()

	// Create a new network namespace
	newNS, err := netns.New()
	if err != nil {
		os.Remove(nsPath)
		return fmt.Errorf("creating new namespace: %w", err)
	}
	defer newNS.Close()

	// Bind mount the new namespace to the file
	// This makes it persistent and visible to iproute2 tools
	nsProcPath := fmt.Sprintf("/proc/self/fd/%d", int(newNS))
	if err := unix.Mount(nsProcPath, nsPath, "none", unix.MS_BIND, ""); err != nil {
		// Switch back before cleaning up
		netns.Set(origNS)
		os.Remove(nsPath)
		return fmt.Errorf("bind mounting namespace: %w", err)
	}

	// Switch back to original namespace
	if err := netns.Set(origNS); err != nil {
		return fmt.Errorf("returning to original namespace: %w", err)
	}

	return nil
}

// Delete removes a named network namespace.
// This is idempotent - no error if the namespace doesn't exist.
func Delete(name string) error {
	nsPath := filepath.Join(nsRunDir, name)

	// Check if it exists
	if _, err := os.Stat(nsPath); os.IsNotExist(err) {
		return nil // Already gone
	}

	// Unmount the namespace
	if err := unix.Unmount(nsPath, unix.MNT_DETACH); err != nil {
		// Ignore "not mounted" errors
		if err != unix.EINVAL && err != unix.ENOENT {
			return fmt.Errorf("unmounting namespace: %w", err)
		}
	}

	// Remove the file
	if err := os.Remove(nsPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("removing namespace file: %w", err)
	}

	return nil
}

// GetPath returns the filesystem path for a named namespace.
func GetPath(name string) string {
	return filepath.Join(nsRunDir, name)
}

// GetHandle returns a handle to a named network namespace.
func GetHandle(name string) (netns.NsHandle, error) {
	nsPath := GetPath(name)
	return netns.GetFromPath(nsPath)
}

// Exists checks if a named namespace exists.
func Exists(name string) bool {
	nsPath := GetPath(name)
	_, err := os.Stat(nsPath)
	return err == nil
}
