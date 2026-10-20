package collector

import (
	"fmt"
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
			t.Fatalf("watcher did not reinstall parent watch after containing directory recreation; watches=%v parents=%v tracked=%v", watcher.watcher.WatchList(), watcher.parentWatches, watcher.watchedDirs)
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

// TestFileWatcherWatchesDeepDirectoryCreatedAfterStart confirms a tree and a
// file created immediately beneath it are observed. A file found while the
// new subtree is being registered must be described as present, not assigned
// an operation that the watcher did not see.
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

	targetFile := filepath.Join(deep, "wallet.json")
	if err := os.WriteFile(targetFile, []byte(`{"key":"secret"}`), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	deadline := time.After(3 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Resource == targetFile {
				if e.Action != "reconciled_present" && e.Action != "create" && e.Action != "write" {
					t.Errorf("action = %q, want reconciled_present, create, or write", e.Action)
				}
				if e.Action == "reconciled_present" && !strings.Contains(e.Detail, "preceding file operations are unknown") {
					t.Errorf("reconciliation event overstates what happened: %q", e.Detail)
				}
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

func TestFileWatcherReconcilesFilesAlreadyPresentInNewSubtree(t *testing.T) {
	root := t.TempDir()
	subtree := filepath.Join(root, "created-after-start")
	target := filepath.Join(subtree, "deep", "wallet.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("wallet present"), 0o600); err != nil {
		t.Fatal(err)
	}

	events := make(chan Event, 16)
	watcher, err := NewFileWatcher([]string{root}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	if err := watcher.enqueueSubtreeScan(root, subtree); err != nil {
		t.Fatalf("enqueue subtree reconciliation: %v", err)
	}
	for len(watcher.scanQueue) > 0 {
		watcher.processSubtreeScanBatch()
	}

	for len(events) > 0 {
		event := <-events
		if event.Source == SourceFile && event.Resource == target {
			if event.Action != "reconciled_present" {
				t.Fatalf("action = %q, want reconciled_present", event.Action)
			}
			if !strings.Contains(event.Detail, "preceding file operations are unknown") {
				t.Fatalf("reconciliation detail overstates what happened: %q", event.Detail)
			}
			if event.Severity != SeverityCritical {
				t.Fatalf("severity = %q, want critical for wallet.json", event.Severity)
			}
			return
		}
	}
	t.Fatalf("reconciliation did not report existing file %s", target)
}

func TestFileWatcherProcessesLargeSubtreeIncrementally(t *testing.T) {
	root := t.TempDir()
	subtree := filepath.Join(root, "created-after-start")
	if err := os.Mkdir(subtree, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		path := filepath.Join(subtree, fmt.Sprintf("file-%03d", i))
		if err := os.WriteFile(path, []byte("present"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	events := make(chan Event, 512)
	watcher, err := NewFileWatcher([]string{root}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()
	if err := watcher.enqueueSubtreeScan(root, subtree); err != nil {
		t.Fatalf("enqueue subtree reconciliation: %v", err)
	}

	watcher.processSubtreeScanBatch()
	firstBatch := len(events)
	if firstBatch == 0 || firstBatch > subtreeScanBatchSize {
		t.Fatalf("first batch emitted %d events; want 1..%d", firstBatch, subtreeScanBatchSize)
	}
	if len(watcher.scanQueue) == 0 {
		t.Fatal("large subtree was fully processed in one event-loop batch")
	}

	for len(watcher.scanQueue) > 0 {
		watcher.processSubtreeScanBatch()
	}
	if got := len(events); got != 300 {
		t.Fatalf("reconciled %d files, want 300", got)
	}
}

func TestFileWatcherCorrelatesSameDirectoryRenameAndCreate(t *testing.T) {
	root := t.TempDir()
	events := make(chan Event, 8)
	watcher, err := NewFileWatcher([]string{root}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	now := time.Now()
	source := filepath.Join(root, "wallet.json.tmp")
	target := filepath.Join(root, "wallet.json")
	watcher.holdRename(source, now)
	detail := watcher.correlateSameDirectoryRename(target, now.Add(50*time.Millisecond))
	if !strings.Contains(detail, source) || !strings.Contains(detail, "cannot confirm the destination") {
		t.Fatalf("correlation detail does not preserve uncertainty and source path: %q", detail)
	}
	if len(watcher.pendingRename) != 0 {
		t.Fatalf("correlated rename remains pending: %+v", watcher.pendingRename)
	}
}

func TestFileWatcherUnmatchedRenameIsReportedAfterCorrelationWindow(t *testing.T) {
	root := t.TempDir()
	events := make(chan Event, 8)
	watcher, err := NewFileWatcher([]string{root}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	source := filepath.Join(root, "wallet.json")
	now := time.Now()
	watcher.holdRename(source, now)
	watcher.flushExpiredRenames(now.Add(renameMatchWindow))
	select {
	case event := <-events:
		if event.Action != "rename" || event.Resource != source {
			t.Fatalf("event = %+v, want rename on source path", event)
		}
		if !strings.Contains(event.Detail, "destination unknown") {
			t.Fatalf("rename event should disclose its ambiguity: %q", event.Detail)
		}
	case <-time.After(time.Second):
		t.Fatal("unmatched rename was not reported")
	}
}

func TestFileWatcherKeepsRootWatchedWhenItContainsSymlink(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	events := make(chan Event, 16)
	watcher, err := NewFileWatcher([]string{root}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	if !watcher.rootState[normalizeWatchPath(root)] {
		t.Fatal("root containing a symlink was marked unavailable; it would be retried and re-reported every reconcile tick")
	}

	skipped := 0
	deadline := time.After(500 * time.Millisecond)
	for collecting := true; collecting; {
		select {
		case event := <-events:
			if event.Source != SourceHealth {
				continue
			}
			if event.Action == "watch_start_failed" {
				t.Fatalf("symlink inside the root must not fail the whole root: %+v", event)
			}
			if event.Action == "watch_subtree_symlink_skipped" && strings.Contains(event.Detail, link) {
				skipped++
				if event.Severity != SeverityMedium {
					t.Fatalf("a skipped symlink is not a failure and must stay below the default alert threshold, got %s", event.Severity)
				}
			}
		case <-deadline:
			collecting = false
		}
	}
	if skipped != 1 {
		t.Fatalf("want exactly one skipped-symlink report for %s, got %d", link, skipped)
	}

	if err := os.WriteFile(filepath.Join(nested, "after.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Source != SourceFile || !strings.HasSuffix(event.Resource, "after.txt") {
			t.Fatalf("unexpected event after symlink report: %+v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("file in a nested directory of a root with a symlink was not watched")
	}
}

func TestFileWatcherSummarisesManySymlinksWithoutDroppingOtherRootFailure(t *testing.T) {
	rootA := t.TempDir()
	target := t.TempDir()
	for i := 0; i < 600; i++ {
		if err := os.Symlink(target, filepath.Join(rootA, fmt.Sprintf("link-%03d", i))); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	rootB := filepath.Join(t.TempDir(), "absent")
	events := make(chan Event, 512)
	watcher, err := NewFileWatcher([]string{rootA, rootB}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	summaries, rootBFailed := 0, false
	for collecting := true; collecting; {
		select {
		case event := <-events:
			if event.Source != SourceHealth {
				continue
			}
			if event.Action == "watch_subtree_symlink_skipped" {
				summaries++
				if !strings.Contains(event.Detail, "600") {
					t.Fatalf("summary should state the symlink count: %+v", event)
				}
			}
			if event.Action == "watch_start_failed" && event.Resource == normalizeWatchPath(rootB) {
				rootBFailed = true
			}
		default:
			collecting = false
		}
	}
	if summaries != 1 {
		t.Fatalf("want one symlink summary for the root, got %d", summaries)
	}
	if !rootBFailed {
		t.Fatal("startup failure of the second root was dropped after the first root reported its symlinks")
	}
}

func TestFileWatcherReportsRealWalkErrorInsteadOfSymlinkSummary(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not apply to root")
	}
	root := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	events := make(chan Event, 16)
	watcher, err := NewFileWatcher([]string{root}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	var reports []Event
	for collecting := true; collecting; {
		select {
		case event := <-events:
			if event.Source == SourceHealth {
				reports = append(reports, event)
			}
		default:
			collecting = false
		}
	}
	if len(reports) != 1 || reports[0].Action != "watch_start_failed" {
		t.Fatalf("a real walk error must be the only startup report for the root, got %+v", reports)
	}
	if !strings.Contains(reports[0].Detail, "permission denied") || strings.Contains(reports[0].Detail, "symlink") {
		t.Fatalf("the report must carry the walk error, not the symlink summary: %q", reports[0].Detail)
	}
}

func TestFileWatcherDoesNotFollowDirectorySymlinkCreatedAfterStart(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "outside.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	events := make(chan Event, 64)
	watcher, err := NewFileWatcher([]string{root}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	link := filepath.Join(root, "newlink")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	created := false
	deadline := time.After(time.Second)
	for collecting := true; collecting; {
		select {
		case event := <-events:
			if event.Resource == link && event.Action == "create" {
				created = true
			}
			if strings.HasPrefix(event.Resource, link+string(filepath.Separator)) {
				t.Fatalf("contents behind a symlink must not be scanned or reported: %+v", event)
			}
		case <-deadline:
			collecting = false
		}
	}
	if !created {
		t.Fatal("creating the symlink itself must still be reported")
	}
}

func collectEvents(events <-chan Event, d time.Duration) []Event {
	var got []Event
	deadline := time.After(d)
	for {
		select {
		case event := <-events:
			got = append(got, event)
		case <-deadline:
			return got
		}
	}
}

func TestFileWatcherDirectorySymlinkCreateDoesNotAbsorbRename(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(root, "id_rsa")
	if err := os.WriteFile(secret, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	events := make(chan Event, 64)
	watcher, err := NewFileWatcher([]string{root}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	if err := os.Rename(secret, filepath.Join(outside, "id_rsa")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	renamed := false
	for _, event := range collectEvents(events, time.Second) {
		if event.Action == "rename" && event.Resource == secret {
			renamed = true
		}
		if event.Action == "create" && strings.Contains(event.Detail, "same-directory rename") {
			t.Fatalf("a directory symlink must not absorb an unrelated rename: %+v", event)
		}
	}
	if !renamed {
		t.Fatal("the rename of a sensitive file must still be reported")
	}
}

func TestFileWatcherReportsRootRecreatedAsSymlink(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	events := make(chan Event, 64)
	watcher, err := NewFileWatcher([]string{root}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), root); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	for _, event := range collectEvents(events, time.Second) {
		if event.Source == SourceHealth && event.Action == "watch_root_unavailable" && event.Severity == SeverityHigh {
			return
		}
	}
	t.Fatal("a root recreated as a symlink must be reported as unavailable, not treated as healthy")
}

func TestFileWatcherReportsSymlinkInMovedInSubtreeAtMediumSeverity(t *testing.T) {
	root := t.TempDir()
	incoming := filepath.Join(t.TempDir(), "incoming")
	if err := os.Mkdir(incoming, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(incoming, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	events := make(chan Event, 64)
	watcher, err := NewFileWatcher([]string{root}, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	if err := os.Rename(incoming, filepath.Join(root, "incoming")); err != nil {
		t.Fatal(err)
	}

	for _, event := range collectEvents(events, time.Second) {
		if event.Action == "watch_subtree_symlink_skipped" {
			if event.Severity != SeverityMedium {
				t.Fatalf("a symlink in a moved-in subtree must be medium, got %s", event.Severity)
			}
			return
		}
	}
	t.Fatal("expected a watch_subtree_symlink_skipped event for the moved-in subtree")
}
