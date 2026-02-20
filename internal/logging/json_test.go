package logging

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildJSONLog(t *testing.T) {
	session := SessionInfo{
		ID:        "a3f8",
		StartTime: time.Now(),
		EndTime:   time.Now().Add(10 * time.Second),
		Mode:      "analyse",
		Command:   []string{"curl", "https://example.com"},
		ExitCode:  0,
		Namespace: "nettrap-a3f8",
		Subnet:    "10.200.42.0/24",
	}

	events := []Event{
		{
			Timestamp:   time.Now(),
			Type:        EventDNSAllowed,
			Domain:      "example.com",
			QueryType:   "A",
			Action:      "ALLOWED",
			ResponseIPs: []net.IP{net.ParseIP("93.184.216.34")},
		},
		{
			Timestamp: time.Now(),
			Type:      EventConnLogged,
			Protocol:  "tcp",
			DstIP:     net.ParseIP("93.184.216.34"),
			DstPort:   443,
			Domain:    "example.com",
			Action:    "LOGGED",
		},
	}

	summary := Summary{
		TotalDNSQueries:   1,
		TotalConnections:  1,
		LoggedConnections: 1,
	}

	log := BuildJSONLog(session, events, summary)

	if len(log.DNSQueries) != 1 {
		t.Errorf("DNSQueries count = %d, want 1", len(log.DNSQueries))
	}
	if len(log.Connections) != 1 {
		t.Errorf("Connections count = %d, want 1", len(log.Connections))
	}
	if log.Session.ID != "a3f8" {
		t.Errorf("Session.ID = %q, want a3f8", log.Session.ID)
	}

	// Verify it marshals to valid JSON
	data, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("JSON output is empty")
	}
}

func TestBuildJSONLog_EmptyEvents(t *testing.T) {
	session := SessionInfo{ID: "test"}
	log := BuildJSONLog(session, nil, Summary{})

	if log.DNSQueries == nil {
		t.Error("DNSQueries should be non-nil empty slice")
	}
	if log.Connections == nil {
		t.Error("Connections should be non-nil empty slice")
	}
}

func TestWriteJSONLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	log := JSONLog{
		Session: SessionInfo{ID: "test"},
	}

	if err := WriteJSONLog(path, log); err != nil {
		t.Fatalf("WriteJSONLog error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written file: %v", err)
	}

	var parsed JSONLog
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshaling written JSON: %v", err)
	}
	if parsed.Session.ID != "test" {
		t.Errorf("Session.ID = %q, want test", parsed.Session.ID)
	}
}

func TestDefaultLogPath(t *testing.T) {
	path := DefaultLogPath("a3f8")
	if path == "" {
		t.Error("DefaultLogPath returned empty string")
	}
	if len(path) < 20 {
		t.Errorf("DefaultLogPath too short: %q", path)
	}
}
