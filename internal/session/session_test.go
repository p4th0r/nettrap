package session

import (
	"regexp"
	"testing"
)

func TestGenerateSessionID(t *testing.T) {
	// Generate multiple IDs and verify format
	seen := make(map[string]bool)
	hexPattern := regexp.MustCompile(`^[0-9a-f]{4}$`)

	for i := 0; i < 100; i++ {
		id, err := GenerateSessionID()
		if err != nil {
			t.Fatalf("GenerateSessionID() returned error: %v", err)
		}

		if !hexPattern.MatchString(id) {
			t.Errorf("GenerateSessionID() = %q, want 4-char hex string", id)
		}

		if seen[id] {
			t.Errorf("GenerateSessionID() returned duplicate ID: %s", id)
		}
		seen[id] = true
	}
}

func TestAllocateSubnet(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
		wantErr   bool
	}{
		{
			name:      "valid session ID",
			sessionID: "a3f8",
			wantErr:   false,
		},
		{
			name:      "another valid session ID",
			sessionID: "00ff",
			wantErr:   false,
		},
		{
			name:      "short session ID",
			sessionID: "a",
			wantErr:   true,
		},
		{
			name:      "invalid hex",
			sessionID: "zzzz",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subnet, err := AllocateSubnet(tt.sessionID)

			if tt.wantErr {
				if err == nil {
					t.Errorf("AllocateSubnet(%q) expected error, got subnet %s", tt.sessionID, subnet)
				}
				return
			}

			if err != nil {
				t.Errorf("AllocateSubnet(%q) returned error: %v", tt.sessionID, err)
				return
			}

			// Verify subnet format: 10.200.X where X is 1-254
			subnetPattern := regexp.MustCompile(`^10\.200\.(25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9])$`)
			if !subnetPattern.MatchString(subnet) {
				t.Errorf("AllocateSubnet(%q) = %q, want 10.200.X format with X in 1-254", tt.sessionID, subnet)
			}
		})
	}
}

func TestResourceName(t *testing.T) {
	tests := []struct {
		sessionID string
		resource  string
		want      string
	}{
		{"a3f8", "nettrap", "nettrap-a3f8"},
		{"1234", "veth-host", "veth-host-1234"},
	}

	for _, tt := range tests {
		got := ResourceName(tt.sessionID, tt.resource)
		if got != tt.want {
			t.Errorf("ResourceName(%q, %q) = %q, want %q", tt.sessionID, tt.resource, got, tt.want)
		}
	}
}

func TestNamespaceName(t *testing.T) {
	got := NamespaceName("a3f8")
	want := "nettrap-a3f8"
	if got != want {
		t.Errorf("NamespaceName(%q) = %q, want %q", "a3f8", got, want)
	}
}

func TestVethNames(t *testing.T) {
	sessionID := "a3f8"

	hostVeth := HostVethName(sessionID)
	if hostVeth != "veth-host-a3f8" {
		t.Errorf("HostVethName(%q) = %q, want %q", sessionID, hostVeth, "veth-host-a3f8")
	}

	jailVeth := JailVethName(sessionID)
	if jailVeth != "veth-jail-a3f8" {
		t.Errorf("JailVethName(%q) = %q, want %q", sessionID, jailVeth, "veth-jail-a3f8")
	}
}

func TestNFTablesTableName(t *testing.T) {
	got := NFTablesTableName("a3f8")
	want := "nettrap_a3f8"
	if got != want {
		t.Errorf("NFTablesTableName(%q) = %q, want %q", "a3f8", got, want)
	}
}
