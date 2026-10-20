package collector

import (
	"strings"
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
	if !ok || severity != SeverityCritical || parent.name != "node" {
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

func TestSuspiciousChildDetail(t *testing.T) {
	long := "/" + strings.Repeat("a", 600)
	tests := []struct {
		name   string
		parent procInfo
		want   string
	}{
		{"names pid and executable", procInfo{pid: 100, name: "python", executable: "/work/proj/.venv/bin/python"},
			"suspicious child of python (parent pid 100, /work/proj/.venv/bin/python)"},
		{"unknown executable", procInfo{pid: 100, name: "python"},
			"suspicious child of python (parent pid 100, executable unavailable)"},
		{"control characters replaced", procInfo{pid: 7, name: "node", executable: "/tmp/x\nFAKE: all clear\x1b[31m/node"},
			"suspicious child of node (parent pid 7, /tmp/x?FAKE: all clear?[31m/node)"},
		{"format and separator characters replaced", procInfo{pid: 8, name: "node", executable: "/tmp/a b c‮d​e"},
			"suspicious child of node (parent pid 8, /tmp/a?b?c?d?e)"},
		{"path of exactly 256 runes not truncated", procInfo{pid: 9, name: "node", executable: long[:256]},
			"suspicious child of node (parent pid 9, " + long[:256] + ")"},
		{"truncation counts runes", procInfo{pid: 9, name: "node", executable: strings.Repeat("é", 300)},
			"suspicious child of node (parent pid 9, " + strings.Repeat("é", 256) + "...)"},
		{"long path truncated", procInfo{pid: 9, name: "python3", executable: long},
			"suspicious child of python3 (parent pid 9, " + long[:256] + "...)"},
	}
	for _, tt := range tests {
		if got := suspiciousChildDetail(tt.parent); got != tt.want {
			t.Errorf("%s:\n got %q\nwant %q", tt.name, got, tt.want)
		}
	}
}

func TestSuspiciousChildEventNamesTheParentProcess(t *testing.T) {
	processes := map[int]procInfo{
		100: {pid: 100, name: "python", executable: "/work/proj/.venv/bin/python"},
		101: {pid: 101, ppid: 100, name: "bash", executable: "/bin/bash"},
	}
	out := make(chan Event, 1)
	watcher := NewProcessWatcher(time.Second, out, nil, false)
	if !watcher.checkProcess(processes[101], processes) {
		t.Fatal("child of python was not classified")
	}
	event := <-out
	for _, want := range []string{"suspicious child of python", "pid 100", "/work/proj/.venv/bin/python"} {
		if !strings.Contains(event.Detail, want) {
			t.Fatalf("detail %q does not contain %q", event.Detail, want)
		}
	}
	if event.CmdLine != "" {
		t.Fatalf("process event must not retain command-line arguments: %+v", event)
	}
}
