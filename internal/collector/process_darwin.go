//go:build darwin

package collector

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

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

// ProcessWatcher polls `ps` on macOS to detect suspicious process spawning.
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
	// Do not collect argv: it often contains secrets. lstart distinguishes PID
	// reuse; /bin/ps avoids a PATH-controlled executable substitution.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/ps", "-axo", "pid=,ppid=,user=,lstart=,comm=").Output()
	if err != nil {
		slog.Error("process watcher: ps inventory failed", "err", err)
		pw.reportProviderIssue(err)
		return
	}
	current := parseProcessList(out)
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
	e := Event{Source: SourceHealth, Timestamp: time.Now(), Action: "process_provider_unavailable", Resource: "/bin/ps", Detail: err.Error(), Severity: SeverityHigh}
	select {
	case pw.out <- e:
	case <-pw.stop:
	default:
		slog.Error("process watcher coverage event dropped", "err", err)
	}
}

func parseProcessList(output []byte) map[int]procInfo {
	current := make(map[int]procInfo)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1])
		executable := strings.Join(fields[8:], " ")
		info := procInfo{
			pid: pid, ppid: ppid, user: fields[2],
			startTime: strings.Join(fields[3:8], " "),
			name:      filepath.Base(executable), executable: executable,
		}
		current[pid] = info
	}
	return current
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
