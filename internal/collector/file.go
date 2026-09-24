package collector

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// sensitivePatterns marks accesses to these as high/critical severity.
var sensitivePatterns = []struct {
	pattern  string
	severity Severity
}{
	{".env", SeverityHigh},
	{"keystore", SeverityCritical},
	{"wallet.json", SeverityCritical},
	{".pem", SeverityCritical},
	{".key", SeverityCritical},
	{"private_key", SeverityHigh},
	{"mnemonic", SeverityCritical},
	{"seed", SeverityHigh},
	{"secret", SeverityHigh},
	{"credentials", SeverityHigh},
	{".ethereum", SeverityHigh},
	{".bitcoin", SeverityHigh},
	{"id_rsa", SeverityCritical},
	{"id_ed25519", SeverityCritical},
}

func severityForPath(path string) Severity {
	lower := strings.ToLower(path)
	for _, p := range sensitivePatterns {
		if strings.Contains(lower, p.pattern) {
			return p.severity
		}
	}
	return SeverityInfo
}

// FileWatcher uses fsnotify to emit create/write events, classified by path.
type FileWatcher struct {
	paths         []string
	roots         []string
	exclude       []string
	suppress      *SuppressMatcher
	out           chan<- Event
	watcher       *fsnotify.Watcher
	stop          chan struct{}
	stopOnce      sync.Once
	wg            sync.WaitGroup
	rootState     map[string]bool
	parentWatches map[string]bool
	parentInfo    map[string]os.FileInfo
	watchMu       sync.Mutex
}

func NewFileWatcher(paths, exclude []string, out chan<- Event, suppress ...*SuppressMatcher) (*FileWatcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	var sm *SuppressMatcher
	if len(suppress) > 0 {
		sm = suppress[0]
	}
	roots := make([]string, 0, len(paths))
	for _, path := range paths {
		roots = append(roots, normalizeWatchPath(path))
	}
	return &FileWatcher{
		paths: paths, roots: roots, exclude: exclude, suppress: sm, out: out, watcher: w,
		stop: make(chan struct{}), rootState: make(map[string]bool),
		parentWatches: make(map[string]bool), parentInfo: make(map[string]os.FileInfo),
	}, nil
}

func normalizeWatchPath(path string) string {
	path = strings.TrimSpace(expandPath(path))
	if path == "" {
		return ""
	}
	path = filepath.Clean(path)
	if absolute, err := filepath.Abs(path); err == nil {
		return absolute
	}
	return path
}

func (fw *FileWatcher) Start() error {
	for _, root := range fw.roots {
		if err := fw.watchRoot(root); err != nil {
			slog.Warn("file watcher: cannot watch path", "path", root, "err", err)
			fw.emitCoverageGap(root, "watch_start_failed", err)
		}
	}

	fw.wg.Add(1)
	go func() {
		defer fw.wg.Done()
		fw.loop()
	}()
	return nil
}

func (fw *FileWatcher) watchRoot(root string) error {
	if err := fw.addNearestParentWatch(root); err != nil {
		fw.rootState[root] = false
		return err
	}
	info, err := os.Lstat(root)
	if err != nil {
		fw.rootState[root] = false
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		fw.rootState[root] = false
		return fmt.Errorf("symlink watch roots are not followed; configure the resolved target path")
	}
	if !info.IsDir() {
		fw.rootState[root] = true
		return nil
	}
	if err := fw.addRecursive(root); err != nil {
		fw.rootState[root] = false
		return err
	}
	fw.rootState[root] = true
	return nil
}

func (fw *FileWatcher) addNearestParentWatch(root string) error {
	parent := filepath.Dir(root)
	for {
		info, err := os.Stat(parent)
		if err == nil && info.IsDir() {
			fw.watchMu.Lock()
			alreadyWatched := fw.parentWatches[parent]
			previousInfo := fw.parentInfo[parent]
			fw.watchMu.Unlock()
			if alreadyWatched && previousInfo != nil && os.SameFile(previousInfo, info) {
				return nil
			}
			if alreadyWatched {
				fw.watchMu.Lock()
				delete(fw.parentWatches, parent)
				delete(fw.parentInfo, parent)
				fw.watchMu.Unlock()
				_ = fw.watcher.Remove(parent)
			}
			if err := fw.watcher.Add(parent); err != nil {
				return err
			}
			currentInfo, statErr := os.Stat(parent)
			if statErr != nil {
				_ = fw.watcher.Remove(parent)
				return statErr
			}
			fw.watchMu.Lock()
			fw.parentWatches[parent] = true
			fw.parentInfo[parent] = currentInfo
			fw.watchMu.Unlock()
			return nil
		}
		next := filepath.Dir(parent)
		if next == parent {
			if err != nil {
				return err
			}
			return fmt.Errorf("no existing parent directory for %s", root)
		}
		parent = next
	}
}

func (fw *FileWatcher) Stop() {
	fw.stopOnce.Do(func() {
		close(fw.stop)
		fw.watcher.Close()
	})
	fw.wg.Wait()
}

func (fw *FileWatcher) addRecursive(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlink watch roots are not followed; configure the resolved target path")
	}
	if !info.IsDir() {
		// CORRECTED (live-reproduced): a watch_paths entry pointing directly
		// at a single file (not a directory) -- e.g. config.example.yaml's
		// own recommended /app/.env entry -- fell through WalkDir's callback
		// with d.IsDir()==false and was never passed to watcher.Add(),
		// silently leaving it unwatched. Verified live: writes to a
		// file-only watch_paths entry produced no fsnotify event or alert
		// until this fix.
		return nil // the containing directory is watched to survive atomic replacement
	}
	var firstErr error
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return nil // continue siblings, but report incomplete coverage
		}
		if fw.isExcluded(path) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if firstErr == nil {
				firstErr = fmt.Errorf("symlink subtree is not followed: %s", path)
			}
			return nil
		}
		if d.IsDir() {
			if err := fw.watcher.Add(path); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return firstErr
}

func (fw *FileWatcher) isExcluded(path string) bool {
	for _, ex := range fw.exclude {
		root := normalizeWatchPath(ex)
		cleanPath := filepath.Clean(path)
		if pathWithinRoot(cleanPath, root) {
			return true
		}
	}
	return false
}

func (fw *FileWatcher) isRelevant(path string) bool {
	cleanPath := filepath.Clean(path)
	for _, root := range fw.roots {
		if pathWithinRoot(cleanPath, root) {
			return true
		}
	}
	return false
}

func (fw *FileWatcher) isRootAncestor(path string) bool {
	cleanPath := filepath.Clean(path)
	for _, root := range fw.roots {
		if root != cleanPath && pathWithinRoot(root, cleanPath) {
			return true
		}
	}
	return false
}

func pathWithinRoot(path, root string) bool {
	if path == root {
		return true
	}
	if root == string(filepath.Separator) {
		return filepath.IsAbs(path)
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}

func (fw *FileWatcher) loop() {
	reconcile := time.NewTicker(5 * time.Second)
	defer reconcile.Stop()
	for {
		select {
		case <-reconcile.C:
			fw.reconcileParentWatches()
			for _, root := range fw.roots {
				if !fw.rootState[root] {
					if err := fw.watchRoot(root); err != nil {
						slog.Warn("file watcher: configured root still unavailable", "path", root, "err", err)
					}
				}
			}
		case event, ok := <-fw.watcher.Events:
			if !ok {
				return
			}
			// fsnotify reports create/write/remove/rename here, not file reads.
			rootPath := filepath.Clean(event.Name)
			for _, root := range fw.roots {
				if rootPath == root {
					if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
						fw.rootState[root] = false
						fw.emitCoverageGap(root, "watch_root_removed", nil)
					} else if event.Has(fsnotify.Create) {
						if _, err := os.Stat(root); err == nil {
							fw.rootState[root] = true
						}
					}
				}
			}
			if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				fw.removeWatchesUnder(rootPath)
				for _, root := range fw.roots {
					if pathWithinRoot(root, rootPath) {
						fw.rootState[root] = false
						fw.emitCoverageGap(root, "watch_parent_removed", nil)
					}
				}
			}
			if fw.isRootAncestor(rootPath) {
				for _, root := range fw.roots {
					if strings.HasPrefix(root, rootPath+string(filepath.Separator)) {
						if err := fw.addNearestParentWatch(root); err != nil {
							fw.emitCoverageGap(root, "watch_parent_failed", err)
						}
						if err := fw.watchRoot(root); err == nil {
							break
						} else {
							fw.emitCoverageGap(root, "watch_root_unavailable", err)
						}
					}
				}
			}
			// Extend directory coverage before forwarding the create event. A
			// consumer may immediately create descendants after receiving it.
			if event.Has(fsnotify.Create) && fw.isRelevant(event.Name) && !fw.isExcluded(event.Name) {
				info, statErr := os.Stat(event.Name)
				if statErr != nil {
					if !os.IsNotExist(statErr) {
						for _, root := range fw.roots {
							if event.Name == root || strings.HasPrefix(event.Name, root+string(filepath.Separator)) {
								fw.rootState[root] = false
								fw.emitCoverageGap(root, "watch_subtree_stat_failed", statErr)
							}
						}
					}
				} else if info.IsDir() {
					if addErr := fw.addRecursive(event.Name); addErr != nil {
						slog.Warn("file watcher: cannot watch new directory", "path", event.Name, "err", addErr)
						for _, root := range fw.roots {
							if event.Name == root || strings.HasPrefix(event.Name, root+string(filepath.Separator)) {
								fw.rootState[root] = false
								fw.emitCoverageGap(root, "watch_subtree_failed", addErr)
							}
						}
					} else if event.Name == rootPath {
						for _, root := range fw.roots {
							if root == event.Name {
								fw.rootState[root] = true
							}
						}
					}
				}
			}
			// Rename fires on the source path, so a key moved out of a watched
			// directory surfaces as an event on the path it left.
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) ||
				event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				if !fw.isRelevant(event.Name) || fw.isExcluded(event.Name) {
					continue
				}
				sev := severityForPath(event.Name)
				action := "write"
				switch {
				case event.Has(fsnotify.Create):
					action = "create"
				case event.Has(fsnotify.Remove):
					action = "remove"
				case event.Has(fsnotify.Rename):
					action = "rename"
				}
				e := Event{
					Source:    SourceFile,
					Timestamp: time.Now(),
					Action:    action,
					Resource:  event.Name,
					Severity:  sev,
				}
				if !fw.suppress.IsSuppressed(e) {
					// Cancellable: main closes the event bus after Stop, and a
					// send already in flight would otherwise panic on it.
					select {
					case fw.out <- e:
					case <-fw.stop:
						return
					}
				}
			}
		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}
			slog.Error("file watcher error", "err", err)
			fw.emitCoverageGap("", "watch_provider_error", err)
			fw.watchMu.Lock()
			fw.parentWatches = make(map[string]bool)
			fw.parentInfo = make(map[string]os.FileInfo)
			fw.watchMu.Unlock()
			for _, root := range fw.roots {
				fw.rootState[root] = false
			}
		}
	}
}

// removeWatchesUnder removes every fsnotify watch attached below a replaced
// directory path. Recursive watches have their own kqueue descriptors, so
// removing only the parent leaves them observing the old subtree inode.
func (fw *FileWatcher) removeWatchesUnder(root string) {
	watches := fw.watcher.WatchList()
	sort.Slice(watches, func(i, j int) bool { return len(watches[i]) > len(watches[j]) })
	for _, path := range watches {
		if pathWithinRoot(path, root) {
			_ = fw.watcher.Remove(path)
		}
	}

	fw.watchMu.Lock()
	for path := range fw.parentWatches {
		if pathWithinRoot(path, root) {
			delete(fw.parentWatches, path)
			delete(fw.parentInfo, path)
		}
	}
	fw.watchMu.Unlock()
}

// reconcileParentWatches detects a parent directory replaced through an
// unwatched higher ancestor. kqueue follows the old directory inode after a
// rename, so a healthy-looking path can otherwise stay attached to stale
// coverage indefinitely. Stat identity checks let us watch only the nearest
// existing parent at startup without retaining a descriptor for every ancestor.
func (fw *FileWatcher) reconcileParentWatches() {
	fw.watchMu.Lock()
	parents := make(map[string]os.FileInfo, len(fw.parentInfo))
	for parent, info := range fw.parentInfo {
		parents[parent] = info
	}
	fw.watchMu.Unlock()

	for parent, oldInfo := range parents {
		currentInfo, err := os.Stat(parent)
		if err == nil && os.SameFile(oldInfo, currentInfo) {
			continue
		}

		fw.watchMu.Lock()
		storedInfo := fw.parentInfo[parent]
		if storedInfo == nil || !os.SameFile(oldInfo, storedInfo) {
			fw.watchMu.Unlock()
			continue
		}
		fw.watchMu.Unlock()
		fw.removeWatchesUnder(parent)

		for _, root := range fw.roots {
			if !pathWithinRoot(root, parent) {
				continue
			}
			fw.rootState[root] = false
			cause := err
			if cause == nil {
				cause = fmt.Errorf("parent directory was replaced")
			}
			if watchErr := fw.watchRoot(root); watchErr != nil {
				fw.emitCoverageGap(root, "watch_root_unavailable", watchErr)
			}
			fw.emitCoverageGap(root, "watch_parent_changed", cause)
		}
	}
}

func (fw *FileWatcher) emitCoverageGap(path, action string, cause error) {
	detail := "file watcher coverage is incomplete"
	if cause != nil {
		detail += ": " + cause.Error()
	}
	e := Event{Source: SourceHealth, Timestamp: time.Now(), Action: action, Resource: path, Detail: detail, Severity: SeverityHigh}
	// Health reporting must never stall the filesystem event loop. The warning
	// remains visible in the daemon log if the shared event bus is saturated.
	select {
	case fw.out <- e:
	case <-fw.stop:
	default:
		slog.Error("file watcher coverage event dropped", "action", action, "path", path, "err", cause)
	}
}
