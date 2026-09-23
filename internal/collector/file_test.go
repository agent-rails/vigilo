package collector

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSeverityForPath verifies the severity scoring table.
func TestSeverityForPath(t *testing.T) {
	cases := []struct {
		path    string
		wantMin Severity // severity must be >= this
	}{
		{"/app/keystore/UTC--key.json", SeverityCritical},
		{"/home/user/wallet.json", SeverityCritical},
		{"/app/.env", SeverityHigh},
		{"/home/user/.pem", SeverityCritical},
		{"/secrets/private_key", SeverityHigh},
		// macOS paths start with /private/var — must not downgrade id_rsa to high
		{"/private/var/folders/tmp/id_rsa", SeverityCritical},
		{"/home/user/.ethereum/keystore", SeverityHigh},
		{"/home/user/.ssh/id_rsa", SeverityCritical},
		{"/home/user/.ssh/id_ed25519", SeverityCritical},
		{"/app/mnemonic.txt", SeverityCritical},
		{"/home/user/seed_phrase.txt", SeverityHigh},
		{"/tmp/random.log", SeverityInfo},
		{"/var/log/nginx.log", SeverityInfo},
	}

	rank := map[Severity]int{
		SeverityInfo: 0, SeverityMedium: 1,
		SeverityHigh: 2, SeverityCritical: 3,
	}

	for _, tc := range cases {
		got := severityForPath(tc.path)
		if rank[got] < rank[tc.wantMin] {
			t.Errorf("severityForPath(%q) = %q, want >= %q", tc.path, got, tc.wantMin)
		}
	}
}

// TestFileWatcherDetectsWrite creates a temp dir, starts a watcher,
// writes to a sensitive-looking file, and confirms an event is emitted.
func TestFileWatcherDetectsWrite(t *testing.T) {
	dir := t.TempDir()

	events := make(chan Event, 16)
	watcher, err := NewFileWatcher([]string{dir}, nil, events)
	if err != nil {
		t.Fatalf("NewFileWatcher: %v", err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer watcher.Stop()

	// Give fsnotify time to register the watch
	time.Sleep(100 * time.Millisecond)

	targetFile := filepath.Join(dir, "wallet.json")
	if err := os.WriteFile(targetFile, []byte(`{"key":"secret"}`), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	select {
	case e := <-events:
		if e.Source != SourceFile {
			t.Errorf("source = %q, want %q", e.Source, SourceFile)
		}
		if e.Resource != targetFile {
			t.Errorf("resource = %q, want %q", e.Resource, targetFile)
		}
		if e.Severity != SeverityCritical {
			t.Errorf("severity = %q, want critical for wallet.json", e.Severity)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: no event received after writing wallet.json")
	}
}

// TestFileWatcherExcludePath confirms excluded paths don't emit events.
func TestFileWatcherExcludePath(t *testing.T) {
	dir := t.TempDir()
	excluded := filepath.Join(dir, "cache")
	if err := os.MkdirAll(excluded, 0755); err != nil {
		t.Fatal(err)
	}

	events := make(chan Event, 16)
	watcher, err := NewFileWatcher([]string{dir}, []string{excluded}, events)
	if err != nil {
		t.Fatalf("NewFileWatcher: %v", err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer watcher.Stop()

	time.Sleep(100 * time.Millisecond)

	// Write to excluded path — should NOT emit
	_ = os.WriteFile(filepath.Join(excluded, "wallet.json"), []byte("data"), 0600)

	// Write to watched path — SHOULD emit
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=x"), 0600)

	// Drain events — only the .env write should appear
	timeout := time.After(2 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Resource == filepath.Join(excluded, "wallet.json") {
				t.Errorf("event emitted for excluded path: %q", e.Resource)
			}
		case <-timeout:
			return
		}
	}
}

// TestFileWatcherWatchesASingleFilePath is a regression for a live-reproduced
// bug: watch_paths entries pointing directly at a single file (not a
// directory) -- e.g. config.example.yaml's own recommended /app/.env entry --
// fell through addRecursive's WalkDir callback with d.IsDir()==false and were
// never passed to watcher.Add(), silently leaving the file unwatched.
func TestFileWatcherWatchesASingleFilePath(t *testing.T) {
	dir := t.TempDir()
	targetFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(targetFile, []byte("SEED=1"), 0600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	events := make(chan Event, 16)
	// watch_paths points directly at the FILE, not its containing directory --
	// the exact shape that silently produced zero watches before the fix.
	watcher, err := NewFileWatcher([]string{targetFile}, nil, events)
	if err != nil {
		t.Fatalf("NewFileWatcher: %v", err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer watcher.Stop()

	time.Sleep(100 * time.Millisecond)

	if err := os.WriteFile(targetFile, []byte("SEED=2"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	select {
	case e := <-events:
		if e.Resource != targetFile {
			t.Errorf("resource = %q, want %q", e.Resource, targetFile)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: no event received for a watch_paths entry pointing directly at a file")
	}
}

// TestFileWatcherDetectsMoveOut confirms a key moved out of a watched directory
// surfaces as an event. fsnotify delivers Rename on the source path; the loop
// previously acted only on Write and Create, so a move produced nothing at all.
func TestFileWatcherDetectsMoveOut(t *testing.T) {
	dir := t.TempDir()
	dest := t.TempDir()

	events := make(chan Event, 16)
	watcher, err := NewFileWatcher([]string{dir}, nil, events)
	if err != nil {
		t.Fatalf("NewFileWatcher: %v", err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer watcher.Stop()

	time.Sleep(100 * time.Millisecond)

	targetFile := filepath.Join(dir, "wallet.json")
	if err := os.WriteFile(targetFile, []byte(`{"key":"secret"}`), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	drainEvents(t, events)

	if err := os.Rename(targetFile, filepath.Join(dest, "wallet.json")); err != nil {
		t.Fatalf("rename file: %v", err)
	}

	select {
	case e := <-events:
		if e.Action != "rename" {
			t.Errorf("action = %q, want %q", e.Action, "rename")
		}
		if e.Resource != targetFile {
			t.Errorf("resource = %q, want %q", e.Resource, targetFile)
		}
		if e.Severity != SeverityCritical {
			t.Errorf("severity = %q, want critical for wallet.json", e.Severity)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: no event received after moving wallet.json out of the watched directory")
	}
}

// TestFileWatcherDetectsRemove confirms deleting a watched key emits an event.
func TestFileWatcherDetectsRemove(t *testing.T) {
	dir := t.TempDir()

	events := make(chan Event, 16)
	watcher, err := NewFileWatcher([]string{dir}, nil, events)
	if err != nil {
		t.Fatalf("NewFileWatcher: %v", err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer watcher.Stop()

	time.Sleep(100 * time.Millisecond)

	targetFile := filepath.Join(dir, "wallet.json")
	if err := os.WriteFile(targetFile, []byte(`{"key":"secret"}`), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	drainEvents(t, events)

	if err := os.Remove(targetFile); err != nil {
		t.Fatalf("remove file: %v", err)
	}

	select {
	case e := <-events:
		if e.Action != "remove" {
			t.Errorf("action = %q, want %q", e.Action, "remove")
		}
		if e.Resource != targetFile {
			t.Errorf("resource = %q, want %q", e.Resource, targetFile)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: no event received after removing wallet.json")
	}
}

// drainEvents consumes the create/write events produced by test setup so the
// assertion that follows sees only the operation under test.
func drainEvents(t *testing.T, events <-chan Event) {
	t.Helper()
	for {
		select {
		case <-events:
		case <-time.After(300 * time.Millisecond):
			return
		}
	}
}
