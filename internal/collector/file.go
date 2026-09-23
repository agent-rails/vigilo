package collector

import (
	"log/slog"
	"os"
	"path/filepath"
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
	paths    []string
	exclude  []string
	suppress *SuppressMatcher
	out      chan<- Event
	watcher  *fsnotify.Watcher
	stop     chan struct{}
	stopOnce sync.Once
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
	return &FileWatcher{
		paths: paths, exclude: exclude, suppress: sm, out: out, watcher: w,
		stop: make(chan struct{}),
	}, nil
}

func (fw *FileWatcher) Start() error {
	for _, p := range fw.paths {
		expanded := expandPath(p)
		if err := fw.addRecursive(expanded); err != nil {
			slog.Warn("file watcher: cannot watch path", "path", expanded, "err", err)
		}
	}

	go fw.loop()
	return nil
}

func (fw *FileWatcher) Stop() {
	fw.stopOnce.Do(func() {
		close(fw.stop)
		fw.watcher.Close()
	})
}

func (fw *FileWatcher) addRecursive(root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		// CORRECTED (live-reproduced): a watch_paths entry pointing directly
		// at a single file (not a directory) -- e.g. config.example.yaml's
		// own recommended /app/.env entry -- fell through WalkDir's callback
		// with d.IsDir()==false and was never passed to watcher.Add(),
		// silently leaving it unwatched. Verified live: writes to a
		// file-only watch_paths entry produced no fsnotify event or alert
		// until this fix.
		return fw.watcher.Add(root)
	}
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable
		}
		if fw.isExcluded(path) {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return fw.watcher.Add(path)
		}
		return nil
	})
}

func (fw *FileWatcher) isExcluded(path string) bool {
	for _, ex := range fw.exclude {
		if strings.HasPrefix(path, expandPath(ex)) {
			return true
		}
	}
	return false
}

func (fw *FileWatcher) loop() {
	for {
		select {
		case event, ok := <-fw.watcher.Events:
			if !ok {
				return
			}
			// fsnotify reports create/write/remove/rename here, not file reads.
			// Rename fires on the source path, so a key moved out of a watched
			// directory surfaces as an event on the path it left.
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) ||
				event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
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
			// New subdirectory created — start watching it
			if event.Has(fsnotify.Create) {
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					_ = fw.watcher.Add(event.Name)
				}
			}

		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}
			slog.Error("file watcher error", "err", err)
		}
	}
}
