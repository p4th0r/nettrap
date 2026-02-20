package logging

import (
	"net"
	"testing"
	"time"
)

func TestEvent_IsDNSEvent(t *testing.T) {
	tests := []struct {
		typ  EventType
		want bool
	}{
		{EventDNSAllowed, true},
		{EventDNSBlocked, true},
		{EventConnAllowed, false},
		{EventConnDropped, false},
		{EventConnLogged, false},
		{EventDoHWarning, false},
	}

	for _, tt := range tests {
		ev := Event{Type: tt.typ}
		if got := ev.IsDNSEvent(); got != tt.want {
			t.Errorf("Event{Type: %d}.IsDNSEvent() = %v, want %v", tt.typ, got, tt.want)
		}
	}
}

func TestEvent_IsConnEvent(t *testing.T) {
	tests := []struct {
		typ  EventType
		want bool
	}{
		{EventDNSAllowed, false},
		{EventConnAllowed, true},
		{EventConnDropped, true},
		{EventConnLogged, true},
		{EventDoHWarning, false},
	}

	for _, tt := range tests {
		ev := Event{Type: tt.typ}
		if got := ev.IsConnEvent(); got != tt.want {
			t.Errorf("Event{Type: %d}.IsConnEvent() = %v, want %v", tt.typ, got, tt.want)
		}
	}
}

func TestEventLogger_GetSummary(t *testing.T) {
	logger := NewStderrLogger(true, false) // quiet mode to suppress output
	el := NewEventLogger(logger, "analyse")
	el.Start()

	// Send some events
	el.EventCh() <- Event{
		Timestamp: time.Now(),
		Type:      EventDNSAllowed,
		Domain:    "example.com",
		QueryType: "A",
		Action:    "ALLOWED",
	}
	el.EventCh() <- Event{
		Timestamp: time.Now(),
		Type:      EventDNSBlocked,
		Domain:    "blocked.com",
		QueryType: "A",
		Action:    "BLOCKED",
	}
	el.EventCh() <- Event{
		Timestamp: time.Now(),
		Type:      EventConnLogged,
		Protocol:  "tcp",
		DstIP:     net.ParseIP("1.2.3.4"),
		DstPort:   443,
		Action:    "LOGGED",
	}

	// Give time for events to process
	time.Sleep(50 * time.Millisecond)
	el.Stop()

	s := el.GetSummary()
	if s.TotalDNSQueries != 2 {
		t.Errorf("TotalDNSQueries = %d, want 2", s.TotalDNSQueries)
	}
	if s.BlockedDNSQueries != 1 {
		t.Errorf("BlockedDNSQueries = %d, want 1", s.BlockedDNSQueries)
	}
	if s.AllowedDNSQueries != 1 {
		t.Errorf("AllowedDNSQueries = %d, want 1", s.AllowedDNSQueries)
	}
	if s.TotalConnections != 1 {
		t.Errorf("TotalConnections = %d, want 1", s.TotalConnections)
	}
	if s.LoggedConnections != 1 {
		t.Errorf("LoggedConnections = %d, want 1", s.LoggedConnections)
	}
	if s.UniqueDNSDomains != 2 {
		t.Errorf("UniqueDNSDomains = %d, want 2", s.UniqueDNSDomains)
	}
}

func TestEventLogger_GetDetailedSummary(t *testing.T) {
	logger := NewStderrLogger(true, false)
	el := NewEventLogger(logger, "allow")
	el.Start()

	el.EventCh() <- Event{
		Timestamp: time.Now(),
		Type:      EventConnAllowed,
		Protocol:  "tcp",
		DstIP:     net.ParseIP("1.2.3.4"),
		DstPort:   443,
		Domain:    "example.com",
		Action:    "ALLOWED",
	}
	el.EventCh() <- Event{
		Timestamp: time.Now(),
		Type:      EventConnAllowed,
		Protocol:  "tcp",
		DstIP:     net.ParseIP("1.2.3.4"),
		DstPort:   443,
		Domain:    "example.com",
		Action:    "ALLOWED",
	}
	el.EventCh() <- Event{
		Timestamp: time.Now(),
		Type:      EventConnDropped,
		Protocol:  "tcp",
		DstIP:     net.ParseIP("5.6.7.8"),
		DstPort:   8443,
		Action:    "DROPPED",
	}
	el.EventCh() <- Event{
		Timestamp: time.Now(),
		Type:      EventDNSBlocked,
		Domain:    "blocked.com",
		QueryType: "A",
		Action:    "BLOCKED",
	}

	time.Sleep(50 * time.Millisecond)
	el.Stop()

	allowed, blockedDNS, dropped := el.GetDetailedSummary()
	if len(allowed) != 1 {
		t.Errorf("allowed destinations = %d, want 1", len(allowed))
	}
	if len(allowed) > 0 && allowed[0].Count != 2 {
		t.Errorf("allowed[0].Count = %d, want 2", allowed[0].Count)
	}
	if len(dropped) != 1 {
		t.Errorf("dropped destinations = %d, want 1", len(dropped))
	}
	if blockedDNS["blocked.com"] != 1 {
		t.Errorf("blockedDNS[blocked.com] = %d, want 1", blockedDNS["blocked.com"])
	}
}
