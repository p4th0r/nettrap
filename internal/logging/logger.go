package logging

import (
	"context"
	"fmt"
	"sync"
)

// EventLogger aggregates events from DNS proxy and connection tracker,
// handles real-time stderr output, and collects events for JSON log.
type EventLogger struct {
	events  []Event
	mu      sync.Mutex
	logger  *StderrLogger
	eventCh chan Event
	seen    map[string]int // dedup key -> count
	mode    string
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewEventLogger creates a new EventLogger.
func NewEventLogger(logger *StderrLogger, mode string) *EventLogger {
	ctx, cancel := context.WithCancel(context.Background())
	return &EventLogger{
		events:  make([]Event, 0, 256),
		logger:  logger,
		eventCh: make(chan Event, 1024),
		seen:    make(map[string]int),
		mode:    mode,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// EventCh returns the channel for sending events to the logger.
func (el *EventLogger) EventCh() chan<- Event {
	return el.eventCh
}

// Start begins processing events in a background goroutine.
func (el *EventLogger) Start() {
	el.wg.Add(1)
	go func() {
		defer el.wg.Done()
		for {
			select {
			case <-el.ctx.Done():
				el.drain()
				return
			case ev, ok := <-el.eventCh:
				if !ok {
					return
				}
				el.processEvent(ev)
			}
		}
	}()
}

// Stop stops the event logger and waits for all events to be processed.
func (el *EventLogger) Stop() {
	el.cancel()
	el.wg.Wait()
}

// drain processes any remaining events in the channel after context cancellation.
func (el *EventLogger) drain() {
	for {
		select {
		case ev, ok := <-el.eventCh:
			if !ok {
				return
			}
			el.processEvent(ev)
		default:
			return
		}
	}
}

func (el *EventLogger) processEvent(ev Event) {
	el.mu.Lock()
	el.events = append(el.events, ev)

	// Track seen count for connection event dedup
	var seenCount int
	if ev.IsConnEvent() || ev.Type == EventDoHWarning {
		key := fmt.Sprintf("%s:%s:%d", ev.Protocol, ev.DstIP, ev.DstPort)
		el.seen[key]++
		seenCount = el.seen[key]
	}
	el.mu.Unlock()

	el.printEvent(ev, seenCount)
}

func (el *EventLogger) printEvent(ev Event, seenCount int) {
	switch ev.Type {
	case EventDNSAllowed, EventDNSBlocked:
		el.logger.DNSEvent(ev.Domain, ev.QueryType, ev.Action, ev.ResponseIPs, ev.CNAMEs)

	case EventConnAllowed, EventConnDropped, EventConnLogged:
		if seenCount > 1 && !el.logger.verbose {
			return // suppress duplicates in non-verbose mode
		}
		el.logger.ConnEvent(ev.Protocol, ev.Action, ev.DstIP, ev.DstPort, ev.Domain, ev.Extra, seenCount)

	case EventDoHWarning:
		if seenCount > 1 {
			return // only warn once per destination
		}
		el.logger.DoHWarning(ev.DstIP, ev.DstPort, ev.Extra)
	}
}

// GetEvents returns a copy of all accumulated events.
func (el *EventLogger) GetEvents() []Event {
	el.mu.Lock()
	defer el.mu.Unlock()
	result := make([]Event, len(el.events))
	copy(result, el.events)
	return result
}

// Summary holds session statistics.
type Summary struct {
	TotalDNSQueries    int
	BlockedDNSQueries  int
	AllowedDNSQueries  int
	UniqueDNSDomains   int
	TotalConnections   int
	AllowedConnections int
	DroppedConnections int
	LoggedConnections  int
	UniqueDestinations int
	DoHWarnings        int
}

// GetSummary computes summary statistics from all events.
func (el *EventLogger) GetSummary() Summary {
	el.mu.Lock()
	defer el.mu.Unlock()

	var s Summary
	destinations := make(map[string]struct{})
	dnsDomains := make(map[string]struct{})

	for _, ev := range el.events {
		switch ev.Type {
		case EventDNSAllowed:
			s.TotalDNSQueries++
			s.AllowedDNSQueries++
			dnsDomains[ev.Domain] = struct{}{}
		case EventDNSBlocked:
			s.TotalDNSQueries++
			s.BlockedDNSQueries++
			dnsDomains[ev.Domain] = struct{}{}
		case EventConnAllowed:
			s.TotalConnections++
			s.AllowedConnections++
			destinations[fmt.Sprintf("%s:%d/%s", ev.DstIP, ev.DstPort, ev.Protocol)] = struct{}{}
		case EventConnDropped:
			s.TotalConnections++
			s.DroppedConnections++
			destinations[fmt.Sprintf("%s:%d/%s", ev.DstIP, ev.DstPort, ev.Protocol)] = struct{}{}
		case EventConnLogged:
			s.TotalConnections++
			s.LoggedConnections++
			destinations[fmt.Sprintf("%s:%d/%s", ev.DstIP, ev.DstPort, ev.Protocol)] = struct{}{}
		case EventDoHWarning:
			s.DoHWarnings++
		}
	}

	s.UniqueDestinations = len(destinations)
	s.UniqueDNSDomains = len(dnsDomains)
	return s
}

// DestInfo holds summarized destination information for the session-end report.
type DestInfo struct {
	Domain   string
	IP       string
	Port     uint16
	Protocol string
	Count    int
	Decision string // interactive mode: "approved_ip", "approved_domain", "denied", etc.
}

// GetDetailedSummary returns categorized destination lists for the session-end report.
func (el *EventLogger) GetDetailedSummary() (allowed []DestInfo, blockedDNS map[string]int, dropped []DestInfo) {
	el.mu.Lock()
	defer el.mu.Unlock()

	allowedMap := make(map[string]*DestInfo)
	droppedMap := make(map[string]*DestInfo)
	blockedDNS = make(map[string]int)

	for _, ev := range el.events {
		switch ev.Type {
		case EventDNSBlocked:
			blockedDNS[ev.Domain]++

		case EventConnAllowed, EventConnLogged:
			key := fmt.Sprintf("%s:%d/%s", ev.DstIP, ev.DstPort, ev.Protocol)
			if d, ok := allowedMap[key]; ok {
				d.Count++
			} else {
				allowedMap[key] = &DestInfo{
					Domain:   ev.Domain,
					IP:       ev.DstIP.String(),
					Port:     ev.DstPort,
					Protocol: ev.Protocol,
					Count:    1,
					Decision: ev.InteractiveDecision,
				}
			}

		case EventConnDropped:
			key := fmt.Sprintf("%s:%d/%s", ev.DstIP, ev.DstPort, ev.Protocol)
			if d, ok := droppedMap[key]; ok {
				d.Count++
			} else {
				droppedMap[key] = &DestInfo{
					Domain:   ev.Domain,
					IP:       ev.DstIP.String(),
					Port:     ev.DstPort,
					Protocol: ev.Protocol,
					Count:    1,
					Decision: ev.InteractiveDecision,
				}
			}
		}
	}

	for _, d := range allowedMap {
		allowed = append(allowed, *d)
	}
	for _, d := range droppedMap {
		dropped = append(dropped, *d)
	}
	return
}
