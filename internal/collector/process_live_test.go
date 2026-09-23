//go:build darwin || linux

package collector

import (
	"os/exec"
	"testing"
	"time"
)

func TestProcessWatcherObservesLiveProcessWithIdentity(t *testing.T) {
	events := make(chan Event, 8)
	watcher := NewProcessWatcher(50*time.Millisecond, events, nil, true)
	watcher.scan(false)

	child := exec.Command("/bin/sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatalf("start test process: %v", err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		watcher.scan(true)
		select {
		case event := <-events:
			if event.PID != child.Process.Pid {
				continue
			}
			if event.Source != SourceProcess || event.Action != "observed" {
				t.Fatalf("unexpected process event: %+v", event)
			}
			if event.Executable == "" || event.Resource != event.Executable || event.User == "" {
				t.Fatalf("process identity context missing: %+v", event)
			}
			return
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("process watcher did not report live PID %d with identity context", child.Process.Pid)
}
