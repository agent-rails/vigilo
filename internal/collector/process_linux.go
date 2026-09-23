//go:build linux

package collector

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// suspiciousChildren maps parent process names to child processes that are
// suspicious when spawned from that parent.
var suspiciousChildren = map[string][]string{
	"node":    {"sh", "bash", "curl", "wget", "python", "python3", "nc", "ncat"},
	"python":  {"sh", "bash", "curl", "wget", "nc", "ncat"},
	"python3": {"sh", "bash", "curl", "wget", "nc", "ncat"},
	"java":    {"sh", "bash", "curl", "wget"},
	"nginx":   {"sh", "bash", "python", "python3"},
}

type procInfo struct {
	pid        int
	ppid       int
	startTime  string
	name       string
	executable string
	user       string
}

// ProcessWatcher polls /proc to detect suspicious process spawning.
type ProcessWatcher struct {
	interval   time.Duration
	suppress   *SuppressMatcher
	out        chan<- Event
	seen       map[int]procInfo
	observeNew bool
	stop       chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
	lastIssue  time.Time
}

func NewProcessWatcher(interval time.Duration, out chan<- Event, suppress *SuppressMatcher, observeNew bool) *ProcessWatcher {
	return &ProcessWatcher{
		interval:   interval,
		suppress:   suppress,
		out:        out,
		seen:       make(map[int]procInfo),
		observeNew: observeNew,
		stop:       make(chan struct{}),
	}
}

func (pw *ProcessWatcher) Start() {
	pw.wg.Add(1)
	go pw.loop()
}

func (pw *ProcessWatcher) Stop() {
	pw.stopOnce.Do(func() { close(pw.stop) })
	pw.wg.Wait()
}

func (pw *ProcessWatcher) loop() {
	defer pw.wg.Done()
	ticker := time.NewTicker(pw.interval)
	defer ticker.Stop()

	// Populate baseline — don't alert on existing processes
	pw.scan(false)

	for {
		select {
		case <-pw.stop:
			return
		case <-ticker.C:
			pw.scan(true)
		}
	}
}

func (pw *ProcessWatcher) scan(emit bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		slog.Error("process watcher: cannot read /proc", "err", err)
		pw.reportProviderIssue(err)
		return
	}

	current := make(map[int]procInfo)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a PID directory
		}
		info, err := readProcInfo(pid)
		if err != nil {
			continue
		}
		current[pid] = info
	}
	if emit {
		for _, info := range changedProcesses(pw.seen, current) {
			if !pw.checkProcess(info, current) && pw.observeNew {
				action, detail := "observed", "new process observed"
				if _, existed := pw.seen[info.pid]; existed {
					action, detail = "identity_changed", "process identity changed while PID remained present"
				}
				pw.emitProcess(info, SeverityInfo, action, detail)
			}
		}
	}

	pw.seen = current
}

func (pw *ProcessWatcher) reportProviderIssue(err error) {
	if time.Since(pw.lastIssue) < time.Minute {
		return
	}
	pw.lastIssue = time.Now()
	e := Event{Source: SourceHealth, Timestamp: time.Now(), Action: "process_provider_unavailable", Resource: "/proc", Detail: err.Error(), Severity: SeverityHigh}
	select {
	case pw.out <- e:
	case <-pw.stop:
	default:
		slog.Error("process watcher coverage event dropped", "err", err)
	}
}

func (pw *ProcessWatcher) checkProcess(p procInfo, processes map[int]procInfo) bool {
	if suspiciousIdentity(p.name, p.executable) {
		pw.emitProcess(p, SeverityHigh, "identity_mismatch", "OS-like process name running outside a standard system executable directory")
		return true
	}
	if severity, parent, matched := parentChildSignal(p, processes); matched {
		pw.emitProcess(p, severity, "spawn", fmt.Sprintf("suspicious child of %s", parent))
		return true
	}
	return false
}

func (pw *ProcessWatcher) emitProcess(p procInfo, sev Severity, action, detail string) {
	childName := filepath.Base(p.name)
	e := Event{
		Source:     SourceProcess,
		Timestamp:  time.Now(),
		PID:        p.pid,
		PPID:       p.ppid,
		Process:    childName,
		Executable: p.executable,
		User:       p.user,
		Action:     action,
		Resource:   p.executable,
		Detail:     detail,
		Severity:   sev,
	}
	if !pw.suppress.IsSuppressed(e) {
		select {
		case pw.out <- e:
		case <-pw.stop:
		}
	}
}

func readProcInfo(pid int) (procInfo, error) {
	base := fmt.Sprintf("/proc/%d", pid)

	statusBytes, err := os.ReadFile(filepath.Join(base, "status"))
	if err != nil {
		return procInfo{}, err
	}

	info := procInfo{pid: pid}
	if statBytes, err := os.ReadFile(filepath.Join(base, "stat")); err == nil {
		stat := string(statBytes)
		if end := strings.LastIndex(stat, ")"); end >= 0 && end+1 < len(stat) {
			fields := strings.Fields(stat[end+1:])
			if len(fields) > 19 {
				info.startTime = fields[19]
			}
		}
	}
	if exe, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		info.executable = exe
		info.name = filepath.Base(exe)
	}
	for _, line := range strings.Split(string(statusBytes), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		val := strings.TrimSpace(parts[1])
		switch parts[0] {
		case "Name":
			if info.name == "" {
				info.name = val
			}
		case "PPid":
			info.ppid, _ = strconv.Atoi(val)
		case "Uid":
			info.user = val
		}
	}

	return info, nil
}
