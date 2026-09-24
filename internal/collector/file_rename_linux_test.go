//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAtomicSaveDoesNotEmitSeparateRenameAlert(t *testing.T) {
	root := t.TempDir()
	events := make(chan Event, 64)
	watcher, err := NewFileWatcher([]string{root}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()
	time.Sleep(100 * time.Millisecond)
	drainEvents(t, events)

	source := filepath.Join(root, "wallet.json.tmp")
	target := filepath.Join(root, "wallet.json")
	if err := os.WriteFile(source, []byte("new wallet contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(source, target); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(2 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Resource != target || event.Action != "create" {
				continue
			}
			if !strings.Contains(event.Detail, source) || !strings.Contains(event.Detail, "cannot confirm the destination") {
				t.Fatalf("create event did not explain the correlated rename and its uncertainty: %+v", event)
			}
			quiet := time.NewTimer(renameMatchWindow + 100*time.Millisecond)
			defer quiet.Stop()
			for {
				select {
				case later := <-events:
					if later.Resource == source && later.Action == "rename" {
						t.Fatalf("atomic save also emitted a separate rename alert: %+v", later)
					}
				case <-quiet.C:
					return
				}
			}
		case <-deadline:
			t.Fatal("timed out waiting for destination create event")
		}
	}
}
