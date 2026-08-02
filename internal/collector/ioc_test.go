package collector

import (
	"strings"
	"testing"
	"time"
)

func TestIOCStoreMatchesKnownC2(t *testing.T) {
	// A published Contagious Interview C2 address, reached over :443 — the case
	// port heuristics structurally miss.
	s := NewIOCStore(KnownC2IPRanges)
	m, ok := s.MatchIP("149.154.166.110")
	if !ok {
		t.Fatal("known-bad C2 IP not matched")
	}
	if m.Severity != SeverityCritical {
		t.Errorf("severity = %s, want critical", m.Severity)
	}
}

func TestIOCStoreCleanIP(t *testing.T) {
	s := NewIOCStore(KnownC2IPRanges)
	if _, ok := s.MatchIP("1.1.1.1"); ok {
		t.Error("clean IP matched an indicator")
	}
}

func TestIOCStoreCustomRange(t *testing.T) {
	s := NewIOCStore([]IOCIPRange{
		{CIDR: "203.0.113.0/24", Label: "test-bad", Severity: SeverityHigh},
	})
	m, ok := s.MatchIP("203.0.113.42")
	if !ok || m.Severity != SeverityHigh || m.Label != "test-bad" {
		t.Fatalf("custom range not matched correctly: %+v ok=%v", m, ok)
	}
}

func TestIOCStoreNilSafe(t *testing.T) {
	var s *IOCStore // nil — collectors hold an optional store
	if _, ok := s.MatchIP("149.154.166.110"); ok {
		t.Error("nil store should match nothing")
	}
	if !s.Empty() {
		t.Error("nil store should be Empty")
	}
}

func TestIOCStoreInvalidCIDRSkipped(t *testing.T) {
	s := NewIOCStore([]IOCIPRange{
		{CIDR: "not-a-cidr", Label: "bad", Severity: SeverityHigh},
		{CIDR: "198.51.100.0/24", Label: "good", Severity: SeverityCritical},
	})
	if s.Empty() {
		t.Fatal("valid entry should survive an invalid one")
	}
	if _, ok := s.MatchIP("198.51.100.7"); !ok {
		t.Error("valid range after invalid one not matched")
	}
}

func TestIOCStoreDefaultSeverity(t *testing.T) {
	s := NewIOCStore([]IOCIPRange{
		{CIDR: "192.0.2.0/24", Label: "no-sev"}, // severity omitted
	})
	m, ok := s.MatchIP("192.0.2.1")
	if !ok || m.Severity != SeverityHigh {
		t.Errorf("missing severity should default to high, got %s ok=%v", m.Severity, ok)
	}
}

// Contagious Interview C2 is a long-lived Telegram Bot-API connection. When
// vigilo is installed on an already-suspect host — and on every Restart=always
// restart — that connection already exists when the daemon starts, so the
// baseline scan must still report it. Baseline suppression is for the noisy
// port heuristics only.
func TestBaselineScanStillReportsKnownBadIndicator(t *testing.T) {
	out := make(chan Event, 4)
	nw := NewNetworkWatcher(time.Minute, out)
	nw.SetIOCStore(NewIOCStore(KnownC2IPRanges))

	c := connKey{
		localIP: "10.0.0.2", localPort: 51234,
		remoteIP: "149.154.166.110", remotePort: 443, // published C2 address, on a "safe" port
	}
	if !nw.checkIOC(c) {
		t.Fatal("known-bad indicator not matched")
	}
	select {
	case e := <-out:
		if e.Severity != SeverityCritical {
			t.Errorf("severity = %s, want critical", e.Severity)
		}
		if !strings.Contains(e.Resource, "149.154.166.110:443") {
			t.Errorf("resource = %q", e.Resource)
		}
	default:
		t.Fatal("resident C2 session was silently absorbed into the baseline")
	}
}

func TestCheckIOCIgnoresCleanRemote(t *testing.T) {
	out := make(chan Event, 4)
	nw := NewNetworkWatcher(time.Minute, out)
	nw.SetIOCStore(NewIOCStore(KnownC2IPRanges))
	c := connKey{remoteIP: "93.184.216.34", remotePort: 443}
	if nw.checkIOC(c) {
		t.Fatal("clean remote matched an indicator")
	}
	if len(out) != 0 {
		t.Fatal("clean remote produced an event")
	}
}

// Cycle-2: Stop() returns without waiting for the watcher goroutine, so a send
// already in flight must be cancellable — otherwise main's close(events) races
// it and panics the daemon under Restart=always.
func TestWatcherEmitUnblocksOnStop(t *testing.T) {
	out := make(chan Event) // unbuffered, no consumer
	nw := NewNetworkWatcher(time.Minute, out)
	nw.SetIOCStore(NewIOCStore(KnownC2IPRanges))
	c := connKey{remoteIP: "149.154.166.110", remotePort: 443}

	done := make(chan struct{})
	go func() {
		nw.checkIOC(c)
		close(done)
	}()
	nw.Stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher emit did not unblock after Stop — close(events) would race it")
	}
}
