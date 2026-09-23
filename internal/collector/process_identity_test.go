package collector

import (
	"testing"
	"time"
)

func TestSuspiciousIdentity(t *testing.T) {
	tests := []struct {
		name, executable string
		want             bool
	}{
		{"systemupdate", "/tmp/systemupdate", true},
		{"iSync", "/Users/alex/Downloads/iSync", true},
		{"systemd", "/usr/lib/systemd/systemd", false},
		{"node", "/tmp/node", false},
		{"systemupdate", "/usr/bin/systemupdate", false},
		{"systemupdate", "systemupdate", false},
		{"iSync", "/Applications/iSync.app/Contents/MacOS/iSync", false},
	}
	for _, tt := range tests {
		if got := suspiciousIdentity(tt.name, tt.executable); got != tt.want {
			t.Errorf("suspiciousIdentity(%q, %q) = %v, want %v", tt.name, tt.executable, got, tt.want)
		}
	}
}

func TestChangedProcessesDetectsPIDReuseAndExecReplacement(t *testing.T) {
	old := map[int]procInfo{17: {pid: 17, name: "old", executable: "/usr/bin/old", startTime: "100"}}
	current := map[int]procInfo{
		17: {pid: 17, name: "new", executable: "/tmp/new", startTime: "101"},
		18: {pid: 18, name: "child", executable: "/bin/sh", ppid: 17, startTime: "102"},
	}
	changed := changedProcesses(old, current)
	if len(changed) != 2 || changed[0].pid != 17 || changed[1].pid != 18 {
		t.Fatalf("PID reuse/exec identities not detected deterministically: %+v", changed)
	}
}

func TestParentChildSignalUsesCurrentSnapshot(t *testing.T) {
	processes := map[int]procInfo{
		100: {pid: 100, name: "node", executable: "/usr/bin/node"},
		101: {pid: 101, ppid: 100, name: "bash", executable: "/bin/bash"},
	}
	severity, parent, ok := parentChildSignal(processes[101], processes)
	if !ok || severity != SeverityCritical || parent != "node" {
		t.Fatalf("parent created in the same scan was not considered: %q %q %v", severity, parent, ok)
	}
	out := make(chan Event, 1)
	watcher := NewProcessWatcher(time.Second, out, nil, false)
	if !watcher.checkProcess(processes[101], processes) {
		t.Fatal("process watcher did not classify child against current snapshot")
	}
	event := <-out
	if event.Action != "spawn" || event.Severity != SeverityCritical || event.PPID != 100 {
		t.Fatalf("current-snapshot parent context missing in event: %+v", event)
	}
}

func TestObservedProcessEventKeepsExecutableButNotCommandLine(t *testing.T) {
	out := make(chan Event, 1)
	watcher := NewProcessWatcher(1, out, nil, true)
	watcher.emitProcess(procInfo{pid: 42, name: "systemupdate", executable: "/tmp/systemupdate", user: "1000"}, SeverityInfo, "observed", "new process observed")
	event := <-out
	if event.Executable != "/tmp/systemupdate" || event.Resource != "/tmp/systemupdate" {
		t.Fatalf("executable context lost: %+v", event)
	}
	if event.CmdLine != "" {
		t.Fatalf("process event must not retain command-line arguments: %+v", event)
	}
}
