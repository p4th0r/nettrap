package allowlist

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// Parse processes both --allow (comma-separated string) and --allow-file (file path)
// and returns a unified list of entries. Either or both can be provided.
func Parse(allowStr string, allowFilePath string) ([]Entry, error) {
	var entries []Entry

	// Parse comma-separated --allow string
	if allowStr != "" {
		parts := strings.Split(allowStr, ",")
		for _, raw := range parts {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			entry, err := parseEntry(raw)
			if err != nil {
				return nil, fmt.Errorf("parsing allow entry %q: %w", raw, err)
			}
			entries = append(entries, entry)
		}
	}

	// Parse --allow-file
	if allowFilePath != "" {
		fileEntries, err := parseFile(allowFilePath)
		if err != nil {
			return nil, err
		}
		entries = append(entries, fileEntries...)
	}

	return entries, nil
}

// parseFile reads an allow-list file and parses each line.
func parseFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening allow-file %q: %w", path, err)
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, err := parseEntry(line)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: parsing %q: %w", path, lineNum, line, err)
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading allow-file %q: %w", path, err)
	}

	return entries, nil
}

// parseEntry classifies and parses a single allow-list entry string.
func parseEntry(raw string) (Entry, error) {
	raw = strings.TrimSpace(raw)

	// Wildcard: starts with "*."
	if strings.HasPrefix(raw, "*.") {
		domain := strings.ToLower(raw[2:])
		domain = strings.TrimSuffix(domain, ".")
		if domain == "" {
			return Entry{}, fmt.Errorf("empty wildcard domain")
		}
		return Entry{
			Type:     EntryWildcard,
			Raw:      raw,
			Domain:   domain,
			Wildcard: "." + domain,
		}, nil
	}

	// CIDR: contains "/"
	if strings.Contains(raw, "/") {
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return Entry{}, fmt.Errorf("invalid CIDR: %w", err)
		}
		return Entry{
			Type:    EntryCIDR,
			Raw:     raw,
			Network: network,
		}, nil
	}

	// IP address
	if ip := net.ParseIP(raw); ip != nil {
		entryType := EntryIPv4
		if ip.To4() == nil {
			entryType = EntryIPv6
		}
		return Entry{
			Type: entryType,
			Raw:  raw,
			IP:   ip,
		}, nil
	}

	// Domain: validate it looks reasonable (no spaces, no special chars except dots and hyphens)
	domain := strings.ToLower(raw)
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return Entry{}, fmt.Errorf("empty entry")
	}
	if err := validateDomain(domain); err != nil {
		return Entry{}, err
	}

	return Entry{
		Type:   EntryExactDomain,
		Raw:    raw,
		Domain: domain,
	}, nil
}

// validateDomain checks that a domain string is syntactically plausible.
func validateDomain(domain string) error {
	if len(domain) > 253 {
		return fmt.Errorf("domain too long: %s", domain)
	}
	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_') {
			return fmt.Errorf("invalid character %q in domain %q", c, domain)
		}
	}
	if strings.HasPrefix(domain, ".") || strings.HasPrefix(domain, "-") {
		return fmt.Errorf("domain cannot start with %q: %s", domain[0:1], domain)
	}
	return nil
}
