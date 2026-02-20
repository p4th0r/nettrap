// Package session provides session management including cleanup of orphaned resources.
package session

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
)

// ResourceType indicates the type of orphaned resource.
type ResourceType string

const (
	ResourceNamespace     ResourceType = "namespace"
	ResourceVeth          ResourceType = "veth"
	ResourceNFTablesTable ResourceType = "nftables"
	ResourceResolvConf    ResourceType = "resolv.conf"
)

// OrphanedResource represents a nettrap resource that needs cleanup.
type OrphanedResource struct {
	Type ResourceType
	Name string
}

// FindOrphanedResources scans for namespaces, veths, and nftables tables
// matching nettrap naming patterns.
func FindOrphanedResources() ([]OrphanedResource, error) {
	var resources []OrphanedResource

	// Find orphaned namespaces
	nsResources, err := findOrphanedNamespaces()
	if err != nil {
		return nil, fmt.Errorf("finding orphaned namespaces: %w", err)
	}
	resources = append(resources, nsResources...)

	// Find orphaned veth interfaces
	vethResources, err := findOrphanedVeths()
	if err != nil {
		return nil, fmt.Errorf("finding orphaned veths: %w", err)
	}
	resources = append(resources, vethResources...)

	// Find orphaned nftables tables
	nftResources, err := findOrphanedNFTables()
	if err != nil {
		return nil, fmt.Errorf("finding orphaned nftables tables: %w", err)
	}
	resources = append(resources, nftResources...)

	// Find orphaned resolv.conf temp files
	rcResources := findOrphanedResolvConf()
	resources = append(resources, rcResources...)

	return resources, nil
}

// findOrphanedNamespaces looks for network namespaces matching "nettrap-*".
func findOrphanedNamespaces() ([]OrphanedResource, error) {
	var resources []OrphanedResource

	nsDir := "/var/run/netns"
	entries, err := os.ReadDir(nsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return resources, nil
		}
		return nil, fmt.Errorf("reading namespace directory: %w", err)
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "nettrap-") {
			resources = append(resources, OrphanedResource{
				Type: ResourceNamespace,
				Name: entry.Name(),
			})
		}
	}

	return resources, nil
}

// findOrphanedVeths looks for veth interfaces matching "veth-host-*" or "veth-jail-*".
func findOrphanedVeths() ([]OrphanedResource, error) {
	var resources []OrphanedResource

	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("listing network interfaces: %w", err)
	}

	for _, link := range links {
		name := link.Attrs().Name
		if strings.HasPrefix(name, "veth-host-") || strings.HasPrefix(name, "veth-jail-") {
			resources = append(resources, OrphanedResource{
				Type: ResourceVeth,
				Name: name,
			})
		}
	}

	return resources, nil
}

// CleanupOrphanedResources removes the specified orphaned resources.
// Operations are idempotent - no error if resource is already gone.
func CleanupOrphanedResources(resources []OrphanedResource) error {
	var errs []string

	for _, res := range resources {
		var err error
		switch res.Type {
		case ResourceNamespace:
			err = cleanupNamespace(res.Name)
		case ResourceVeth:
			err = cleanupVeth(res.Name)
		case ResourceNFTablesTable:
			err = cleanupNFTable(res.Name)
		case ResourceResolvConf:
			err = cleanupResolvConf(res.Name)
		}

		if err != nil {
			errs = append(errs, fmt.Sprintf("%s %s: %v", res.Type, res.Name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors:\n  %s", strings.Join(errs, "\n  "))
	}

	return nil
}

// cleanupNamespace removes a network namespace.
func cleanupNamespace(name string) error {
	nsPath := filepath.Join("/var/run/netns", name)

	if err := os.Remove(nsPath); err != nil {
		if os.IsNotExist(err) {
			return nil // Already gone, that's fine
		}
		return fmt.Errorf("removing namespace file: %w", err)
	}

	return nil
}

// cleanupVeth removes a veth interface.
func cleanupVeth(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil // Already gone, that's fine
		}
		return fmt.Errorf("finding interface: %w", err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("deleting interface: %w", err)
	}

	return nil
}

// findOrphanedNFTables looks for nftables tables matching "nettrap_*".
func findOrphanedNFTables() ([]OrphanedResource, error) {
	var resources []OrphanedResource

	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("creating nftables connection: %w", err)
	}

	tables, err := conn.ListTables()
	if err != nil {
		return nil, fmt.Errorf("listing nftables tables: %w", err)
	}

	for _, t := range tables {
		if strings.HasPrefix(t.Name, "nettrap_") {
			resources = append(resources, OrphanedResource{
				Type: ResourceNFTablesTable,
				Name: t.Name,
			})
		}
	}

	return resources, nil
}

// findOrphanedResolvConf looks for temp resolv.conf files matching "nettrap-resolv-*".
func findOrphanedResolvConf() []OrphanedResource {
	var resources []OrphanedResource

	entries, err := os.ReadDir("/tmp")
	if err != nil {
		return resources
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "nettrap-resolv-") {
			resources = append(resources, OrphanedResource{
				Type: ResourceResolvConf,
				Name: entry.Name(),
			})
		}
	}

	return resources
}

// cleanupResolvConf removes a temporary resolv.conf file.
func cleanupResolvConf(name string) error {
	path := filepath.Join("/tmp", name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s: %w", path, err)
	}
	return nil
}

// cleanupNFTable deletes an nftables table by name. Idempotent.
func cleanupNFTable(name string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	conn.DelTable(&nftables.Table{
		Name:   name,
		Family: nftables.TableFamilyINet,
	})

	if err := conn.Flush(); err != nil {
		// Ignore errors if table is already gone
		return nil
	}

	return nil
}
