//go:build darwin

package collector

import (
	"os"
	"testing"
	"time"
)

func TestParseProcessListPreservesStartAndExecutableIdentity(t *testing.T) {
	got := parseProcessList([]byte("  42  1 alice Tue Sep 23 20:45:12 2026 /Users/alice/Assessment Tools/worker\n"))
	process, ok := got[42]
	if !ok {
		t.Fatal("process row was not parsed")
	}
	if process.startTime != "Tue Sep 23 20:45:12 2026" {
		t.Fatalf("start time = %q", process.startTime)
	}
	if process.executable != "/Users/alice/Assessment Tools/worker" || process.name != "worker" {
		t.Fatalf("executable identity not preserved: %+v", process)
	}
}

func TestOwnPollingChild(t *testing.T) {
	self := os.Getpid()
	cases := []struct {
		name string
		proc procInfo
		want bool
	}{
		{"ps child of self", procInfo{ppid: self, name: "ps"}, true},
		{"exiting netstat child of self", procInfo{ppid: self, name: "(netstat)"}, true},
		{"netstat child of self", procInfo{ppid: self, name: "netstat"}, true},
		{"other child of self", procInfo{ppid: self, name: "sleep"}, false},
		{"ps child of another process", procInfo{ppid: self + 1, name: "ps"}, false},
	}
	for _, tc := range cases {
		if got := ownPollingChild(tc.proc); got != tc.want {
			t.Errorf("%s: ownPollingChild = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestProcessWatcherDoesNotReportItsOwnPollingChildren(t *testing.T) {
	events := make(chan Event, 64)
	watcher := NewProcessWatcher(time.Second, events, nil, true)
	watcher.scan(false)
	for i := 0; i < 3; i++ {
		watcher.scan(true)
	}
	close(events)
	for event := range events {
		if event.PPID == os.Getpid() && (event.Process == "ps" || event.Process == "netstat" || event.Process == "(netstat)") {
			t.Fatalf("watcher reported its own polling child: %+v", event)
		}
	}
}
