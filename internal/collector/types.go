// Package collector defines the Event type shared by all OS-level collectors
// (FileWatcher, ProcessWatcher, NetworkWatcher) and consumed by the SQLite buffer.
package collector

import "time"

// EventSource identifies which collector produced an event.
type EventSource string

const (
	SourceFile        EventSource = "file_access"
	SourceProcess     EventSource = "process"
	SourceNetwork     EventSource = "network"
	SourceAuth        EventSource = "auth"
	SourceSupplyChain EventSource = "supply_chain"
	SourceHealth      EventSource = "collector_health"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Event is a single OS-level observation emitted by a collector.
type Event struct {
	ID        int64       `json:"id"`
	Source    EventSource `json:"source"`
	Timestamp time.Time   `json:"timestamp"`

	// Process context
	PID        int    `json:"pid,omitempty"`
	PPID       int    `json:"ppid,omitempty"`
	Process    string `json:"process,omitempty"`    // e.g. "node", "python3"
	Executable string `json:"executable,omitempty"` // observed executable path when the OS exposes it
	CmdLine    string `json:"cmd_line,omitempty"`
	User       string `json:"user,omitempty"`

	// Event specifics
	Action   string `json:"action"`           // e.g. "read", "connect", "spawn", "write"
	Resource string `json:"resource"`         // file path, IP:port, process name
	Detail   string `json:"detail,omitempty"` // extra context

	Severity Severity `json:"severity"`
}
