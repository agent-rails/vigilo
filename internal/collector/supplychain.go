package collector

import (
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// maxManifestBytes caps how much of a matched file is read. Manifests and
// lockfiles are orders of magnitude smaller; anything larger is either not a
// real manifest or an attempt to exhaust the daemon's heap — the scanned files
// are attacker-supplied by premise, so the read must be bounded.
const maxManifestBytes = 5 << 20 // 5 MiB

// findingTTL is how long a finding stays deduplicated. Without expiry, a
// remediated-then-re-planted payload would never alert again — the exact
// persistence behaviour to expect after an eviction.
const findingTTL = 24 * time.Hour

// Ecosystem is a pluggable supply-chain analyzer for one package/dependency
// ecosystem (Terraform, npm, pip, cargo, …). New ecosystems are added by
// implementing this interface — the SupplyChainGuard needs no changes.
type Ecosystem interface {
	// Name identifies the ecosystem, e.g. "terraform".
	Name() string
	// Matches reports whether this ecosystem handles a file with the given base name.
	Matches(filename string) bool
	// Inspect parses a matched file and returns any findings as Events
	// (Source SourceSupplyChain, severity/action/detail already set).
	Inspect(path string, content []byte) []Event
}

// ExtraPathProvider is an optional capability: an ecosystem that also needs to
// inspect fixed absolute paths outside the scanned roots (e.g. a global CLI
// config referenced by an env var).
type ExtraPathProvider interface {
	ExtraPaths() []string
}

// SupplyChainGuard walks configured roots on an interval and routes each matched
// dependency-manifest / lockfile / CLI-config file to the ecosystems that handle
// it. It owns the shared machinery — scheduling, walking, dedup, suppress, emit —
// so ecosystems only implement parsing + validation. Tier-0: pure rules, no LLM.
type SupplyChainGuard struct {
	roots      []string
	interval   time.Duration
	ecosystems []Ecosystem
	suppress   *SuppressMatcher
	out        chan<- Event
	seen       map[string]time.Time // dedup with expiry: see findingTTL
	stop       chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
}

// NewSupplyChainGuard validates the scan roots up front. A root that expands to
// nothing, or that does not exist, is dropped with an ERROR — a supply-chain
// guard silently scanning zero files is worse than one that is switched off,
// because the operator believes they have coverage. Callers should check
// Roots() and treat an empty result as "no coverage".
func NewSupplyChainGuard(roots []string, interval time.Duration, ecosystems []Ecosystem, out chan<- Event, suppress ...*SuppressMatcher) *SupplyChainGuard {
	var sm *SuppressMatcher
	if len(suppress) > 0 {
		sm = suppress[0]
	}
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	expanded := make([]string, 0, len(roots))
	for _, r := range roots {
		p := expandPath(r)
		if p == "" || p == "/" || p == "." {
			slog.Error("supply-chain guard: refusing unusable scan root — NO COVERAGE for this root",
				"configured", r, "expanded", p)
			continue
		}
		fi, err := os.Stat(p)
		if err != nil || !fi.IsDir() {
			slog.Error("supply-chain guard: scan root unreadable — NO COVERAGE for this root",
				"configured", r, "expanded", p, "err", err)
			continue
		}
		expanded = append(expanded, p)
	}
	if len(expanded) == 0 {
		slog.Error("supply-chain guard: no usable scan roots — the guard will detect nothing",
			"configured", roots)
	}
	return &SupplyChainGuard{
		roots:      expanded,
		interval:   interval,
		ecosystems: ecosystems,
		suppress:   sm,
		out:        out,
		seen:       make(map[string]time.Time),
		stop:       make(chan struct{}),
	}
}

// Roots returns the validated, expanded scan roots actually in use. Log this
// rather than the configured value — the two differ exactly when coverage is
// missing, which is when the operator most needs to know.
func (g *SupplyChainGuard) Roots() []string { return g.roots }

func (g *SupplyChainGuard) Start() {
	g.wg.Add(1)
	go g.loop()
}

// Stop is idempotent — a second call must not panic on a closed channel.
func (g *SupplyChainGuard) Stop() {
	g.stopOnce.Do(func() { close(g.stop) })
	g.wg.Wait()
}

// stopping reports whether Stop has been called, so long walks can bail out.
func (g *SupplyChainGuard) stopping() bool {
	select {
	case <-g.stop:
		return true
	default:
		return false
	}
}

func (g *SupplyChainGuard) loop() {
	defer g.wg.Done()
	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()
	g.scan()
	for {
		select {
		case <-g.stop:
			return
		case <-ticker.C:
			g.scan()
		}
	}
}

func (g *SupplyChainGuard) scan() {
	g.pruneSeen()
	visited, inspected := 0, 0
	for _, root := range g.roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if g.stopping() {
				return filepath.SkipAll
			}
			if err != nil {
				return nil // skip unreadable
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "vendor", ".terraform":
					return filepath.SkipDir
				case "node_modules":
					// Don't recurse (deep trees are enormous), but do inspect
					// installed direct dependencies: in a BeaverTail-style npm
					// compromise the malicious lifecycle script lives in a
					// dependency's manifest, not the victim's own.
					v, i := g.scanInstalledPackages(path)
					visited += v
					inspected += i
					return filepath.SkipDir
				}
				return nil
			}
			visited++
			if g.inspectFile(path, d.Name()) {
				inspected++
			}
			return nil
		})
	}
	// Ecosystem-declared absolute paths outside the roots.
	for _, e := range g.ecosystems {
		ep, ok := e.(ExtraPathProvider)
		if !ok {
			continue
		}
		for _, p := range ep.ExtraPaths() {
			content, err := readCapped(p)
			if err != nil {
				continue
			}
			visited++
			inspected++
			for _, ev := range e.Inspect(p, content) {
				g.emit(ev)
			}
		}
	}
	// Distinguish "the roots are broken, you have no coverage" from "the roots
	// are fine, this codebase just has no manifests". Conflating them ERRORs
	// forever on a Go-only checkout, which trains operators to ignore the very
	// signal that exists to surface missing coverage.
	switch {
	case visited == 0:
		slog.Error("supply-chain guard scan reached no files — roots unreadable, NO COVERAGE",
			"roots", g.roots)
	case inspected == 0:
		slog.Info("supply-chain guard scan found no manifests",
			"roots", g.roots, "files_visited", visited)
	default:
		slog.Debug("supply-chain guard scan complete",
			"roots", g.roots, "files_visited", visited, "inspected", inspected)
	}
}

// scanInstalledPackages inspects the manifests of installed direct dependencies
// (node_modules/<pkg>/ and node_modules/@scope/<pkg>/) without descending into
// their own nested node_modules. Bounded by design: one level of packages.
// Returns (visited, inspected).
func (g *SupplyChainGuard) scanInstalledPackages(nodeModules string) (int, int) {
	visited, inspected := 0, 0
	entries, err := os.ReadDir(nodeModules)
	if err != nil {
		return 0, 0
	}
	for _, entry := range entries {
		if g.stopping() {
			return visited, inspected
		}
		if !entry.IsDir() {
			continue
		}
		dirs := []string{filepath.Join(nodeModules, entry.Name())}
		if strings.HasPrefix(entry.Name(), "@") {
			// Scoped packages nest one level deeper: @scope/<pkg>.
			scoped, err := os.ReadDir(dirs[0])
			if err != nil {
				continue
			}
			dirs = dirs[:0]
			for _, s := range scoped {
				if s.IsDir() {
					dirs = append(dirs, filepath.Join(nodeModules, entry.Name(), s.Name()))
				}
			}
		}
		for _, dir := range dirs {
			manifest := filepath.Join(dir, "package.json")
			visited++
			if g.inspectFile(manifest, "package.json") {
				inspected++
			}
		}
	}
	return visited, inspected
}

// inspectFile routes one file to every ecosystem that claims it, reading the
// file at most once. Reports whether the file was actually read and inspected.
func (g *SupplyChainGuard) inspectFile(path, name string) bool {
	var matched []Ecosystem
	for _, e := range g.ecosystems {
		if e.Matches(name) {
			matched = append(matched, e)
		}
	}
	if len(matched) == 0 {
		return false
	}
	content, err := readCapped(path)
	if err != nil {
		return false
	}
	for _, e := range matched {
		for _, ev := range e.Inspect(path, content) {
			g.emit(ev)
		}
	}
	return true
}

// readCapped reads at most maxManifestBytes from path. An oversized manifest is
// skipped rather than truncated — a partial parse would produce findings that
// don't correspond to what the package manager will actually do.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Read one byte past the cap so an oversized file is detected from the read
	// itself. Relying on Stat alone silently truncated when Stat failed — the
	// exact outcome this function exists to avoid.
	b, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxManifestBytes {
		slog.Warn("supply-chain guard: skipping oversized manifest",
			"path", path, "cap", maxManifestBytes)
		return nil, fs.ErrInvalid
	}
	return b, nil
}

// pruneSeen drops dedup entries past findingTTL so a re-planted payload alerts
// again, and so the map cannot grow without bound over the daemon's lifetime.
func (g *SupplyChainGuard) pruneSeen() {
	cutoff := time.Now().Add(-findingTTL)
	for k, at := range g.seen {
		if at.Before(cutoff) {
			delete(g.seen, k)
		}
	}
}

// emit deduplicates and forwards a finding to the event bus.
func (g *SupplyChainGuard) emit(e Event) {
	key := string(e.Source) + "|" + e.Action + "|" + e.Resource + "|" + e.Detail
	if at, ok := g.seen[key]; ok && time.Since(at) < findingTTL {
		return
	}
	g.seen[key] = time.Now()
	if g.suppress.IsSuppressed(e) {
		return
	}
	slog.Info("supply-chain finding",
		"action", e.Action, "resource", e.Resource, "severity", e.Severity)
	// Cancellable: a shutdown must not block on an unconsumed event bus, and
	// must not race the channel close in main.
	select {
	case g.out <- e:
	case <-g.stop:
	}
}
