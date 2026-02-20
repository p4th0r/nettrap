package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// JSONLog is the top-level structure for the JSON log file.
type JSONLog struct {
	Session     SessionInfo `json:"session"`
	DNSQueries  []DNSEntry  `json:"dns_queries"`
	Connections []ConnEntry `json:"connections"`
	Summary     SummaryInfo `json:"summary"`
}

// SessionInfo holds metadata about the nettrap session.
type SessionInfo struct {
	ID           string    `json:"id"`
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
	DurationSecs float64   `json:"duration_seconds"`
	Mode         string    `json:"mode"`
	Command      []string  `json:"command"`
	ExitCode     int       `json:"exit_code"`
	Namespace    string    `json:"namespace"`
	Subnet       string    `json:"subnet"`
	AllowList    []string  `json:"allow_list,omitempty"`
	HostPorts    []int     `json:"host_ports,omitempty"`
	RunAsUser    string    `json:"run_as_user"`
	RunAsUID     int       `json:"run_as_uid"`
	RunAsRoot    bool      `json:"run_as_root"`
}

// DNSEntry represents a single DNS query in the log.
type DNSEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Query       string    `json:"query"`
	Type        string    `json:"type"`
	Action      string    `json:"action"`
	ResponseIPs []string  `json:"response_ips"`
	CNAMEs      []string  `json:"cnames,omitempty"`
}

// ConnEntry represents a single connection event in the log.
type ConnEntry struct {
	Timestamp           time.Time `json:"timestamp"`
	DstIP               string    `json:"dst_ip"`
	DstPort             uint16    `json:"dst_port"`
	Protocol            string    `json:"protocol"`
	Action              string    `json:"action"`
	Domain              string    `json:"domain,omitempty"`
	DomainSrc           string    `json:"domain_source,omitempty"`
	Extra               string    `json:"extra,omitempty"`
	InteractiveDecision string    `json:"interactive_decision,omitempty"`
}

// SummaryInfo holds summary statistics for the log.
type SummaryInfo struct {
	TotalDNSQueries    int `json:"total_dns_queries"`
	BlockedDNSQueries  int `json:"blocked_dns_queries"`
	TotalConnections   int `json:"total_connections"`
	AllowedConnections int `json:"allowed_connections"`
	DroppedConnections int `json:"dropped_connections"`
	UniqueDestinations int `json:"unique_destinations"`
	DoHWarnings        int `json:"doh_warnings"`
}

// BuildJSONLog constructs a JSONLog from session info and events.
func BuildJSONLog(session SessionInfo, events []Event, summary Summary) JSONLog {
	var dnsQueries []DNSEntry
	var connections []ConnEntry

	for _, ev := range events {
		switch {
		case ev.IsDNSEvent():
			ipStrs := make([]string, 0, len(ev.ResponseIPs))
			for _, ip := range ev.ResponseIPs {
				ipStrs = append(ipStrs, ip.String())
			}
			dnsQueries = append(dnsQueries, DNSEntry{
				Timestamp:   ev.Timestamp,
				Query:       ev.Domain,
				Type:        ev.QueryType,
				Action:      ev.Action,
				ResponseIPs: ipStrs,
				CNAMEs:      ev.CNAMEs,
			})

		case ev.IsConnEvent():
			connections = append(connections, ConnEntry{
				Timestamp:           ev.Timestamp,
				DstIP:               ev.DstIP.String(),
				DstPort:             ev.DstPort,
				Protocol:            ev.Protocol,
				Action:              ev.Action,
				Domain:              ev.Domain,
				DomainSrc:           ev.DomainSrc,
				Extra:               ev.Extra,
				InteractiveDecision: ev.InteractiveDecision,
			})
		}
	}

	if dnsQueries == nil {
		dnsQueries = []DNSEntry{}
	}
	if connections == nil {
		connections = []ConnEntry{}
	}

	return JSONLog{
		Session:     session,
		DNSQueries:  dnsQueries,
		Connections: connections,
		Summary: SummaryInfo{
			TotalDNSQueries:    summary.TotalDNSQueries,
			BlockedDNSQueries:  summary.BlockedDNSQueries,
			TotalConnections:   summary.TotalConnections,
			AllowedConnections: summary.AllowedConnections,
			DroppedConnections: summary.DroppedConnections,
			UniqueDestinations: summary.UniqueDestinations,
			DoHWarnings:        summary.DoHWarnings,
		},
	}
}

// WriteJSONLog writes the JSON log to the specified path atomically.
func WriteJSONLog(path string, log JSONLog) error {
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON log: %w", err)
	}

	// Write atomically: write to .tmp, then rename
	dir := filepath.Dir(path)
	tmpPath := path + ".tmp"

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating log directory %s: %w", dir, err)
	}

	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("writing temporary log file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		// Fallback: if rename fails (e.g., cross-device), just write directly
		os.Remove(tmpPath)
		if err := os.WriteFile(path, data, 0644); err != nil {
			return fmt.Errorf("writing log file: %w", err)
		}
	}

	return nil
}

// DefaultLogPath returns the default log file path for a session.
func DefaultLogPath(sessionID string) string {
	ts := time.Now().Format("20060102-150405")
	return fmt.Sprintf("./nettrap-%s-%s.json", sessionID, ts)
}
