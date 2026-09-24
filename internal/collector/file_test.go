package collector

import (
	"os"
	"path/filepath"
	"strings"
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

func TestFileWatcherReportsMissingConfiguredRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	events := make(chan Event, 2)
	watcher, err := NewFileWatcher([]string{missing}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Source != SourceHealth || event.Action != "watch_start_failed" || event.Resource != missing {
			t.Fatalf("unexpected coverage event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("missing configured root did not produce a coverage event")
	}
}

func TestFileWatcherReportsSymlinkRootAsUncovered(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "actual")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	events := make(chan Event, 8)
	watcher, err := NewFileWatcher([]string{alias}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Source != SourceHealth || event.Action != "watch_start_failed" || !strings.Contains(event.Detail, "symlink") {
			t.Fatalf("symlink root did not report missing coverage: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("symlink root was silently marked watched")
	}
}

func TestFileWatcherRootSlashContainsAbsolutePaths(t *testing.T) {
	watcher := &FileWatcher{roots: []string{string(filepath.Separator)}}
	if !watcher.isRelevant(filepath.Join(string(filepath.Separator), "tmp", "marker")) {
		t.Fatal("watch_paths root / must include absolute descendants")
	}
}

func TestFileWatcherRecoversMissingConfiguredDirectory(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "created-later")
	events := make(chan Event, 16)
	watcher, err := NewFileWatcher([]string{root}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Source == SourceFile && event.Resource == root {
				goto rootObserved
			}
		case <-deadline:
			t.Fatal("missing configured directory creation was not observed")
		}
	}

rootObserved:
	path := filepath.Join(root, "arbitrary-name.bin")
	if err := os.WriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline = time.After(2 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Source == SourceFile && event.Resource == path {
				return
			}
		case <-deadline:
			t.Fatal("watcher did not recover coverage under newly created root")
		}
	}
}

func TestFileWatcherDirectFileSurvivesAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "watched.config")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	events := make(chan Event, 16)
	watcher, err := NewFileWatcher([]string{target}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "replacement.tmp")
	if err := os.WriteFile(tmp, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, target); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Source == SourceFile && event.Resource == target {
				if err := os.WriteFile(target, []byte("after replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
				secondDeadline := time.After(2 * time.Second)
				for {
					select {
					case next := <-events:
						if next.Source == SourceFile && next.Resource == target {
							return
						}
					case <-secondDeadline:
						t.Fatal("write after atomic replacement was not observed")
					}
				}
			}
		case <-deadline:
			t.Fatal("atomic replacement was not observed through watched parent")
		}
	}
}

func TestFileWatcherRecoversWhenContainingDirectoryIsRecreated(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "watched-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "target.bin")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	events := make(chan Event, 32)
	watcher, err := NewFileWatcher([]string{target}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Source == SourceHealth && event.Action == "watch_root_unavailable" {
				goto parentWatchReinstalled
			}
		case <-deadline:
			t.Fatal("watcher did not report/recover the recreated parent directory")
		}
	}

parentWatchReinstalled:
	if err := os.WriteFile(target, []byte("created after recovery"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline = time.After(3 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Source == SourceFile && event.Resource == target && (event.Action == "write" || event.Action == "create") {
				return
			}
		case <-deadline:
			t.Fatal("watcher did not reinstall parent watch after containing directory recreation")
		}
	}
}

func TestFileWatcherUsesOnlyNearestExistingParent(t *testing.T) {
	base := t.TempDir()
	nearest := filepath.Join(base, "existing")
	if err := os.Mkdir(nearest, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(nearest, "missing", "root")
	watcher, err := NewFileWatcher([]string{root}, nil, make(chan Event, 8))
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	watcher.watchMu.Lock()
	defer watcher.watchMu.Unlock()
	if len(watcher.parentWatches) != 1 || !watcher.parentWatches[nearest] {
		t.Fatalf("parent watches = %v; want only nearest existing parent %q", watcher.parentWatches, nearest)
	}
}

func TestFileWatcherRecoversWhenHigherAncestorIsReplaced(t *testing.T) {
	base := t.TempDir()
	tree := filepath.Join(base, "tree")
	parent := filepath.Join(tree, "parent")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "watched.bin")
	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	events := make(chan Event, 32)
	watcher, err := NewFileWatcher([]string{path}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(tree, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(7 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Source == SourceHealth && event.Action == "watch_parent_changed" {
				goto replacementWatchRestored
			}
		case <-deadline:
			t.Fatal("watcher did not detect a replaced higher ancestor")
		}
	}

replacementWatchRestored:
	if err := os.WriteFile(path, []byte("after recovery"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline = time.After(2 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Source == SourceFile && event.Resource == path && event.Action == "write" {
				return
			}
		case <-deadline:
			t.Fatal("watcher did not observe writes after replacing a higher ancestor")
		}
	}
}

func TestFileWatcherRecoversNestedDirectoryWatchesAfterAncestorReplacement(t *testing.T) {
	base := t.TempDir()
	tree := filepath.Join(base, "tree")
	root := filepath.Join(tree, "watchroot")
	nested := filepath.Join(root, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(nested, "watched.bin")
	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	events := make(chan Event, 32)
	watcher, err := NewFileWatcher([]string{root}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(tree, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	writeTicker := time.NewTicker(200 * time.Millisecond)
	defer writeTicker.Stop()
	sawCoverageSignal := false
	for {
		select {
		case event := <-events:
			if event.Source == SourceHealth && strings.HasPrefix(event.Action, "watch_") {
				sawCoverageSignal = true
				t.Logf("coverage event during recovery: %+v", event)
			}
			if event.Source == SourceFile && event.Resource == path && event.Action == "write" {
				return
			}
		case <-writeTicker.C:
			if err := os.WriteFile(path, []byte("after recovery"), 0o600); err != nil {
				t.Fatal(err)
			}
		case <-deadline.C:
			t.Fatalf("nested file watch was not restored after replacing a higher ancestor (coverage signal=%v, watches=%v)", sawCoverageSignal, watcher.watcher.WatchList())
		}
	}
}

func TestExcludedFileDoesNotSkipSiblingDirectories(t *testing.T) {
	root := t.TempDir()
	excluded := filepath.Join(root, "ignore.txt")
	if err := os.WriteFile(excluded, []byte("ignore"), 0o600); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(root, "keep")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	events := make(chan Event, 16)
	watcher, err := NewFileWatcher([]string{root}, []string{excluded}, events)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	// Give kqueue/fsnotify time to activate the initial recursive watch before
	// creating the child file; this test is about exclusions, not startup timing.
	time.Sleep(100 * time.Millisecond)
	path := filepath.Join(child, "visible.bin")
	if err := os.WriteFile(path, []byte("visible"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Source == SourceFile && event.Resource == path {
				return
			}
		case <-deadline:
			t.Fatal("excluded file caused sibling directory coverage to be skipped")
		}
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

// TestFileWatcherWatchesDeepDirectoryCreatedAfterStart confirms a tree created
// in one mkdir -p is watched all the way down. Only the top level yields a
// Create event — the intermediate directories already exist by the time it
// arrives — so adding just that level left the leaves unwatched and files
// written there invisible.
func TestFileWatcherWatchesDeepDirectoryCreatedAfterStart(t *testing.T) {
	dir := t.TempDir()

	events := make(chan Event, 32)
	watcher, err := NewFileWatcher([]string{dir}, nil, events)
	if err != nil {
		t.Fatalf("NewFileWatcher: %v", err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer watcher.Stop()

	time.Sleep(100 * time.Millisecond)

	deep := filepath.Join(dir, "deep", "nested", "tree")
	if err := os.MkdirAll(deep, 0700); err != nil {
		t.Fatalf("mkdir -p: %v", err)
	}
	drainEvents(t, events)

	targetFile := filepath.Join(deep, "wallet.json")
	if err := os.WriteFile(targetFile, []byte(`{"key":"secret"}`), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	deadline := time.After(3 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Resource == targetFile {
				if e.Severity != SeverityCritical {
					t.Errorf("severity = %q, want critical for wallet.json", e.Severity)
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout: no event for a file written inside a deep directory created after startup")
		}
	}
}
