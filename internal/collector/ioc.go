package collector

import (
	"fmt"
	"log/slog"
	"net"
	"time"
)

// IOCStore is a shared indicator-of-compromise lookup consulted by collectors
// (network today; extensible to file paths / process names). It is the seam the
// security wiki feeds: confirmed-bad indicators become detections without code
// changes. Kept OS-independent so both the darwin and linux network collectors
// share one implementation.
type IOCStore struct {
	ipRanges []ipRange
}

type ipRange struct {
	net      *net.IPNet
	label    string
	severity Severity
}

// IOCIPRange is the config-facing form of a bad-IP indicator.
type IOCIPRange struct {
	CIDR     string
	Label    string
	Severity Severity
}

// KnownC2IPRanges are well-known indicator ranges operators can opt into on
// hosts that have no business talking to them (e.g. prod validators). NOT
// enabled by default: vigilo's own Telegram alerter legitimately uses the
// Telegram ranges, so forcing them would self-alert. Seed these via config on
// hosts where such egress is anomalous.
//
// The Telegram ranges ship because the DPRK "Contagious Interview" infostealer
// family uses the Telegram Bot-API (149.154.x) for C2/exfil over :443, which
// port-based rules treat as safe.
var KnownC2IPRanges = []IOCIPRange{
	{CIDR: "149.154.160.0/20", Label: "Telegram (Bot-API C2/exfil channel — DPRK Contagious Interview)", Severity: SeverityCritical},
	{CIDR: "91.108.4.0/22", Label: "Telegram (Bot-API C2/exfil channel)", Severity: SeverityCritical},
	{CIDR: "91.108.8.0/22", Label: "Telegram (Bot-API C2/exfil channel)", Severity: SeverityCritical},
	{CIDR: "91.108.56.0/22", Label: "Telegram (Bot-API C2/exfil channel)", Severity: SeverityCritical},
}

// NewIOCStore compiles config entries into a lookup. Invalid CIDRs are skipped
// with a warning so one bad entry can't break the collector.
func NewIOCStore(ranges []IOCIPRange) *IOCStore {
	s := &IOCStore{}
	for _, r := range ranges {
		_, ipnet, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			slog.Warn("ioc: skipping invalid CIDR", "cidr", r.CIDR, "err", err)
			continue
		}
		sev := r.Severity
		if !validSeverityValue(sev) {
			sev = SeverityHigh
		}
		s.ipRanges = append(s.ipRanges, ipRange{net: ipnet, label: r.Label, severity: sev})
	}
	return s
}

// IOCMatch describes a matched indicator.
type IOCMatch struct {
	Label    string
	Severity Severity
}

// MatchIP reports whether ipStr falls in any indicator range. Nil-safe: a nil
// store matches nothing, so collectors can hold an optional store without
// guarding every call.
func (s *IOCStore) MatchIP(ipStr string) (IOCMatch, bool) {
	if s == nil || len(s.ipRanges) == 0 {
		return IOCMatch{}, false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return IOCMatch{}, false
	}
	for _, r := range s.ipRanges {
		if r.net.Contains(ip) {
			return IOCMatch{Label: r.label, Severity: r.severity}, true
		}
	}
	return IOCMatch{}, false
}

// Empty reports whether the store has no indicators (used to skip wiring).
func (s *IOCStore) Empty() bool { return s == nil || len(s.ipRanges) == 0 }

// NewIOCEvent builds the event for a matched indicator. Shared by the darwin
// and linux network watchers so the two platforms cannot drift.
func NewIOCEvent(remoteIP string, remotePort int, m IOCMatch) Event {
	return Event{
		Source:    SourceNetwork,
		Timestamp: time.Now(),
		Action:    "connect",
		Resource:  fmt.Sprintf("%s:%d", remoteIP, remotePort),
		Detail:    "outbound connection to known-bad indicator: " + m.Label,
		Severity:  m.Severity,
	}
}

func validSeverityValue(s Severity) bool {
	switch s {
	case SeverityInfo, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}
