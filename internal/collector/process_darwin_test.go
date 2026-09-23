//go:build darwin

package collector

import "testing"

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
