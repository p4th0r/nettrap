package allowlist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseEntry(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantType EntryType
		wantErr  bool
	}{
		{"exact domain", "example.com", EntryExactDomain, false},
		{"domain with trailing dot", "example.com.", EntryExactDomain, false},
		{"domain uppercase", "Example.COM", EntryExactDomain, false},
		{"wildcard", "*.example.com", EntryWildcard, false},
		{"wildcard uppercase", "*.Example.COM", EntryWildcard, false},
		{"ipv4", "93.184.216.34", EntryIPv4, false},
		{"ipv6", "2606:2800:220:1:248:1893:25c8:1946", EntryIPv6, false},
		{"cidr v4", "10.10.10.0/24", EntryCIDR, false},
		{"cidr v6", "2606:2800::/32", EntryCIDR, false},
		{"subdomain", "sub.domain.example.com", EntryExactDomain, false},
		{"domain with hyphen", "my-domain.example.com", EntryExactDomain, false},
		{"empty wildcard", "*.", EntryWildcard, true},
		{"invalid cidr", "10.10.10.0/99", EntryCIDR, true},
		{"invalid chars", "exam ple.com", EntryExactDomain, true},
		{"empty", "", EntryExactDomain, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := parseEntry(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for input %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
			if entry.Type != tt.wantType {
				t.Errorf("input %q: got type %d, want %d", tt.input, entry.Type, tt.wantType)
			}
			if entry.Raw != tt.input {
				t.Errorf("input %q: Raw = %q", tt.input, entry.Raw)
			}
		})
	}
}

func TestParseCommaSeparated(t *testing.T) {
	entries, err := Parse("example.com, *.target.com, 10.0.0.0/8, 1.2.3.4", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}
	if entries[0].Type != EntryExactDomain {
		t.Errorf("entry 0: expected domain, got %d", entries[0].Type)
	}
	if entries[1].Type != EntryWildcard {
		t.Errorf("entry 1: expected wildcard, got %d", entries[1].Type)
	}
	if entries[2].Type != EntryCIDR {
		t.Errorf("entry 2: expected CIDR, got %d", entries[2].Type)
	}
	if entries[3].Type != EntryIPv4 {
		t.Errorf("entry 3: expected IPv4, got %d", entries[3].Type)
	}
}

func TestParseFile(t *testing.T) {
	content := `# scope.txt
example.com
*.target.com

# APIs
api.shodan.io

# IPs
93.184.216.34
10.10.10.0/24
`
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	entries, err := Parse("", path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
}

func TestParseCombined(t *testing.T) {
	content := "example.com\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	entries, err := Parse("1.1.1.1", path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Type != EntryIPv4 {
		t.Errorf("entry 0: expected IPv4, got %d", entries[0].Type)
	}
	if entries[1].Type != EntryExactDomain {
		t.Errorf("entry 1: expected domain, got %d", entries[1].Type)
	}
}

func TestParseInvalidEntry(t *testing.T) {
	_, err := Parse("example.com, not valid!!!", "")
	if err == nil {
		t.Error("expected error for invalid entry")
	}
}

func TestParseNonExistentFile(t *testing.T) {
	_, err := Parse("", "/tmp/nonexistent_allow_file_12345.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestParseFileInvalidLine(t *testing.T) {
	content := "example.com\nnot valid!!!\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Parse("", path)
	if err == nil {
		t.Error("expected error for invalid line in file")
	}
}

func TestEntryNormalization(t *testing.T) {
	entry, err := parseEntry("Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Domain != "example.com" {
		t.Errorf("domain not normalized: got %q", entry.Domain)
	}

	entry, err = parseEntry("*.Target.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Domain != "target.com" {
		t.Errorf("wildcard domain not normalized: got %q", entry.Domain)
	}
	if entry.Wildcard != ".target.com" {
		t.Errorf("wildcard suffix wrong: got %q", entry.Wildcard)
	}
}
