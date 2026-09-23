//go:build linux

package collector

import (
	"bufio"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// AuditdWatcher tails /var/log/audit/audit.log and converts grouped SYSCALL,
// EXECVE, PATH, and CWD records into file and process Events. It requires read access to the audit log
// (typically: vigilo user in the adm group, or run as root).
//
// Auditd is Linux-only and is a richer alternative to /proc polling:
// it captures every file-open syscall, not just fsnotify write/create events.
//
// Enable auditd rules for vigilo with:
//
//	auditctl -w /app/keystore -p wa -k vigilo_keystore
//	auditctl -w /run/secrets  -p wa -k vigilo_secrets
//	auditctl -w /app/.env     -p wa  -k vigilo_env
//	auditctl -a always,exit -F arch=b64 -S execve,execveat -k vigilo_exec
type AuditdWatcher struct {
	logPath    string
	suppress   *SuppressMatcher
	out        chan<- Event
	stop       chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
	healthMu   sync.Mutex
	lastHealth map[string]time.Time
}

func NewAuditdWatcher(logPath string, out chan<- Event, suppress ...*SuppressMatcher) *AuditdWatcher {
	if logPath == "" {
		logPath = "/var/log/audit/audit.log"
	}
	var sm *SuppressMatcher
	if len(suppress) > 0 {
		sm = suppress[0]
	}
	return &AuditdWatcher{logPath: logPath, suppress: sm, out: out, stop: make(chan struct{}), lastHealth: make(map[string]time.Time)}
}

func (aw *AuditdWatcher) Start() error {
	f, err := os.Open(aw.logPath)
	if err != nil {
		return err
	}
	// Start from the end — historical records are outside the collection window.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return err
	}
	aw.wg.Add(1)
	go func() {
		defer aw.wg.Done()
		aw.tail(f)
	}()
	return nil
}

func (aw *AuditdWatcher) Stop() {
	aw.stopOnce.Do(func() { close(aw.stop) })
	aw.wg.Wait()
}

// auditRecord holds parsed fields from a single audit log line.
type auditRecord struct {
	serial    string
	recType   string
	timestamp time.Time
	fields    map[string]string
}

// auditGroup accumulates records sharing the same serial number.
type auditGroup struct {
	records  []auditRecord
	lastSeen time.Time
}

const (
	maxAuditLineBytes = 1 << 20
	maxAuditGroups    = 4096
	maxAuditRecords   = 256
	auditGroupQuiet   = 250 * time.Millisecond
	auditGroupTimeout = time.Second
)

var (
	// msg=audit(1234567890.123:456):
	reMsgSerial = regexp.MustCompile(`msg=audit\((\d+\.\d+):(\d+)\)`)
	// key=value or key="value"
	reField = regexp.MustCompile(`(\w+)=(?:"([^"]*)"|([\S]*))`)
)

func parseLine(line string) (auditRecord, bool) {
	// type=SYSCALL msg=audit(ts:serial): ...
	if !strings.HasPrefix(line, "type=") {
		return auditRecord{}, false
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return auditRecord{}, false
	}

	recType := strings.TrimPrefix(parts[0], "type=")
	sm := reMsgSerial.FindStringSubmatch(line)
	if sm == nil {
		return auditRecord{}, false
	}
	serial := sm[2]
	seconds, _ := strconv.ParseFloat(sm[1], 64)
	sec := int64(seconds)
	timestamp := time.Unix(sec, int64((seconds-float64(sec))*float64(time.Second)))

	fields := make(map[string]string)
	for _, m := range reField.FindAllStringSubmatch(line, -1) {
		key := m[1]
		val := m[2]
		if val == "" {
			val = m[3]
			switch key {
			case "name", "cwd", "exe", "comm":
				val = decodeAuditHex(val)
			}
		}
		fields[key] = val
	}

	return auditRecord{serial: serial, recType: recType, timestamp: timestamp, fields: fields}, true
}

// auditd hex-encodes values containing non-printable bytes. Decode only valid
// UTF-8 that actually contains a non-printable rune, so ordinary all-hex names
// such as "deadbeef" retain their literal meaning.
func decodeAuditHex(value string) string {
	if len(value) == 0 || len(value)%2 != 0 {
		return value
	}
	b, err := hex.DecodeString(value)
	if err != nil || !utf8.Valid(b) {
		return value
	}
	decoded := string(b)
	for _, r := range decoded {
		// audit_log_untrustedstring hex-encodes spaces, quotes, backslashes,
		// controls, and non-ASCII. A normal safe filename such as "deadbeef"
		// remains literal and must not be reinterpreted as hex.
		if unicode.IsControl(r) || r == ' ' || r == '"' || r == '\\' || r > unicode.MaxASCII {
			return decoded
		}
	}
	return value
}

func (aw *AuditdWatcher) tail(f *os.File) {
	defer func() { _ = f.Close() }()
	reader := bufio.NewReader(f)
	var partial string
	discardingLine := false
	groups := make(map[string]*auditGroup)
	flushTicker := time.NewTicker(500 * time.Millisecond)
	defer flushTicker.Stop()

	for {
		select {
		case <-aw.stop:
			return
		case <-flushTicker.C:
			// auditd deliberately omits EOE from its local disk log. Assemble
			// records by serial and flush complete groups after a quiet window;
			// incomplete groups are bounded by a longer timeout and discarded
			// with a visible coverage warning.
			now := time.Now()
			for serial, g := range groups {
				if now.Sub(g.lastSeen) >= auditGroupQuiet && auditGroupComplete(g) {
					aw.emitGroup(g)
					delete(groups, serial)
				} else if now.Sub(g.lastSeen) >= auditGroupTimeout {
					aw.emitHealth("audit_incomplete_group", "audit event did not reach EOE before timeout; partial evidence was discarded")
					delete(groups, serial)
				}
			}
		default:
			fragment, err := reader.ReadSlice('\n')
			if !discardingLine {
				if len(partial)+len(fragment) > maxAuditLineBytes {
					partial = ""
					discardingLine = true
				} else {
					partial += string(fragment)
				}
			}
			if err == nil {
				if discardingLine {
					aw.emitHealth("audit_line_too_large", "audit record exceeded 1 MiB and was discarded")
					partial = ""
					discardingLine = false
					continue
				}
				rec, ok := parseLine(strings.TrimSuffix(strings.TrimSuffix(partial, "\n"), "\r"))
				partial = ""
				if !ok {
					continue
				}
				groupKey := rec.timestamp.UTC().Format(time.RFC3339Nano) + ":" + rec.serial
				g, exists := groups[groupKey]
				if !exists {
					if len(groups) >= maxAuditGroups {
						aw.emitHealth("audit_group_limit", "too many incomplete audit events; new records are being dropped")
						continue
					}
					g = &auditGroup{}
					groups[groupKey] = g
				}
				if len(g.records) >= maxAuditRecords {
					delete(groups, groupKey)
					aw.emitHealth("audit_record_limit", "audit event exceeded 256 records and was discarded")
					continue
				}
				g.records = append(g.records, rec)
				g.lastSeen = time.Now()
				if rec.recType == "EOE" {
					aw.emitGroup(g)
					delete(groups, groupKey)
				}
			} else if errors.Is(err, bufio.ErrBufferFull) {
				continue
			} else if errors.Is(err, io.EOF) {
				// ReadSlice can be called again after EOF, so appended lines
				// remain visible; unlike Scanner, it does not terminate the tail.
				// Check the path as well as the open descriptor: auditd commonly
				// rotates by renaming the old inode and creating a new file.
				time.Sleep(100 * time.Millisecond)
				pathInfo, pathErr := os.Stat(aw.logPath)
				fileInfo, statErr := f.Stat()
				if pathErr != nil {
					aw.emitHealth("audit_path_unavailable", "cannot stat audit log path: "+pathErr.Error())
				}
				if statErr != nil {
					aw.emitHealth("audit_descriptor_unavailable", "cannot stat active audit log descriptor: "+statErr.Error())
				}
				if pathErr == nil && statErr == nil && !os.SameFile(pathInfo, fileInfo) {
					if nf, openErr := os.Open(aw.logPath); openErr == nil {
						if partial != "" || discardingLine {
							aw.emitHealth("audit_partial_record_discarded", "rotation interrupted an audit log record")
							partial = ""
							discardingLine = false
						}
						_ = f.Close()
						f = nf
						reader = bufio.NewReader(f)
						slog.Info("auditd log rotated; tailing replacement file", "path", aw.logPath)
					} else {
						aw.emitHealth("audit_reopen_failed", "cannot open replacement audit log: "+openErr.Error())
					}
				} else if statErr == nil {
					if offset, seekErr := f.Seek(0, io.SeekCurrent); seekErr == nil && offset > fileInfo.Size() {
						if _, seekErr = f.Seek(0, io.SeekStart); seekErr == nil {
							if partial != "" || discardingLine {
								aw.emitHealth("audit_partial_record_discarded", "truncation interrupted an audit log record")
								partial = ""
								discardingLine = false
							}
							reader = bufio.NewReader(f)
						}
					}
				}
			} else if err != nil {
				aw.emitHealth("audit_read_failed", "audit log read failed: "+err.Error())
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

func auditGroupComplete(g *auditGroup) bool {
	var syscall auditRecord
	hasExecve, hasPath := false, false
	pathCount := 0
	for _, rec := range g.records {
		switch rec.recType {
		case "SYSCALL":
			syscall = rec
		case "EXECVE":
			hasExecve = true
		case "PATH":
			if rec.fields["name"] != "" && rec.fields["name"] != "(null)" {
				pathCount++
			}
			if name := rec.fields["name"]; name != "" && name != "(null)" &&
				rec.fields["nametype"] != "CWD" && rec.fields["nametype"] != "PARENT" {
				hasPath = true
			}
		case "EOE":
			return true
		}
	}
	if syscall.recType == "" || syscall.fields["success"] != "yes" {
		return syscall.recType != "" // failed calls need no associated evidence
	}
	if expected, err := strconv.Atoi(syscall.fields["items"]); err == nil && expected > pathCount {
		return false // wait for every PATH record (rename and link calls can have several)
	}
	return hasExecve || hasPath
}

func (aw *AuditdWatcher) emitHealth(action, detail string) {
	aw.healthMu.Lock()
	if aw.lastHealth == nil {
		aw.lastHealth = make(map[string]time.Time)
	}
	if last := aw.lastHealth[action]; time.Since(last) < time.Minute {
		aw.healthMu.Unlock()
		return
	}
	aw.lastHealth[action] = time.Now()
	aw.healthMu.Unlock()
	e := Event{Source: SourceHealth, Timestamp: time.Now(), Action: action, Resource: aw.logPath, Detail: detail, Severity: SeverityHigh}
	select {
	case aw.out <- e:
	case <-aw.stop:
	default:
		slog.Error("auditd coverage event dropped", "action", action, "path", aw.logPath)
	}
}

func (aw *AuditdWatcher) emitGroup(g *auditGroup) {
	for _, e := range eventsForAuditGroup(g) {
		if !aw.suppress.IsSuppressed(e) {
			select {
			case aw.out <- e:
			case <-aw.stop:
				return
			}
		}
	}
}

func eventsForAuditGroup(g *auditGroup) []Event {
	// Collect SYSCALL and PATH records
	var syscall auditRecord
	var paths []string
	var key string
	var cwd string
	var hasExecveRecord bool

	for _, r := range g.records {
		switch r.recType {
		case "SYSCALL":
			syscall = r
			key = r.fields["key"]
		case "PATH":
			// CWD/PARENT records are context, not the object operated on.
			nametype := r.fields["nametype"]
			if name := r.fields["name"]; name != "" && name != "(null)" && nametype != "CWD" && nametype != "PARENT" {
				paths = append(paths, name)
			}
		case "CWD":
			cwd = r.fields["cwd"]
		case "EXECVE":
			hasExecveRecord = true
		}
	}

	if syscall.recType == "" || key == "" {
		return nil // no matching audit rule triggered — skip
	}

	// Only process events that matched a vigilo audit rule (key starts with "vigilo_")
	if !strings.HasPrefix(key, "vigilo_") {
		return nil
	}

	exe := syscall.fields["exe"]
	comm := syscall.fields["comm"]
	pidStr := syscall.fields["pid"]
	uid := syscall.fields["uid"]
	syscallNum := syscall.fields["syscall"]

	pid, _ := strconv.Atoi(pidStr)
	ppid, _ := strconv.Atoi(syscall.fields["ppid"])
	if syscall.fields["success"] != "yes" {
		return nil // failed syscalls do not establish a completed execution or file operation
	}
	action := syscallToAction(syscall.fields["arch"], syscallNum)
	access := "unknown"
	if action == "open" {
		action, access = classifyOpenAccess(syscall.fields["arch"], syscallNum, syscall.fields)
	}
	ts := syscall.timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	if hasExecveRecord {
		// SYSCALL.exe is the executing binary (for a script this can be its
		// interpreter). PATH identifies the requested script/file separately.
		// Do not retain EXECVE argv fields: they commonly contain credentials.
		resource := exe
		for _, path := range paths {
			if path != "" {
				resource = resolveAuditPath(path, cwd, auditPathUsesCWD(syscall.fields["arch"], syscallNum, syscall.fields))
				break
			}
		}
		name := comm
		if name == "" {
			name = exe
		}
		sev := SeverityInfo
		if suspiciousIdentity(name, exe) {
			sev = SeverityHigh
		}
		return []Event{{
			Source: SourceProcess, Timestamp: ts, PID: pid, PPID: ppid,
			Process: name, Executable: exe, User: uid,
			Action: "exec", Resource: resource, Detail: "auditd rule=" + key, Severity: sev,
		}}
	}

	events := make([]Event, 0, len(paths))
	for _, path := range paths {
		path = resolveAuditPath(path, cwd, auditPathUsesCWD(syscall.fields["arch"], syscallNum, syscall.fields))
		sev := severityForPath(path)
		if sev == SeverityInfo {
			sev = SeverityMedium // auditd rules matched = at least medium
		}

		e := Event{
			Source:     SourceFile,
			Timestamp:  ts,
			PID:        pid,
			PPID:       ppid,
			Process:    comm,
			Executable: exe,
			User:       uid,
			Action:     action,
			Resource:   path,
			Detail:     "auditd rule=" + key + " access=" + access,
			Severity:   sev,
		}
		events = append(events, e)
	}
	return events
}

func classifyOpenAccess(arch, num string, fields map[string]string) (string, string) {
	flagField := "a1"
	switch arch {
	case "c000003e": // x86_64: openat(dirfd, path, flags, mode)
		if num == "257" {
			flagField = "a2"
		}
	case "c00000b7": // aarch64 exposes openat, not open
		flagField = "a2"
	case "40000003": // i386
		if num == "295" {
			flagField = "a2"
		}
	}
	flags, err := strconv.ParseUint(strings.TrimPrefix(fields[flagField], "0x"), 16, 64)
	if err != nil {
		return "open", "unknown"
	}
	// O_ACCMODE: O_RDONLY=0, O_WRONLY=1, O_RDWR=2. Creation,
	// truncation, and append flags also establish write intent.
	const (
		oCreate = 0x40
		oTrunc  = 0x200
		oAppend = 0x400
	)
	if flags&(oCreate|oTrunc|oAppend) != 0 || flags&3 != 0 {
		if flags&3 == 2 {
			return "write", "read_write"
		}
		return "write", "write"
	}
	return "read", "read"
}

func resolveAuditPath(path, cwd string, usesCWD bool) string {
	if path == "" || filepath.IsAbs(path) || !usesCWD || cwd == "" || !filepath.IsAbs(cwd) {
		return path
	}
	return filepath.Clean(filepath.Join(cwd, path))
}

func auditPathUsesCWD(arch, num string, fields map[string]string) bool {
	switch arch {
	case "c000003e": // x86_64
		switch num {
		case "2", "87", "82", "59": // open, unlink, rename, execve
			return true
		case "257", "263", "322": // openat, unlinkat, execveat
			return auditDirFDIsCWD(fields["a0"])
		case "264": // renameat
			return auditDirFDIsCWD(fields["a0"]) && auditDirFDIsCWD(fields["a2"])
		}
	case "c00000b7": // aarch64
		switch num {
		case "221": // execve
			return true
		case "56", "35", "281": // openat, unlinkat, execveat
			return auditDirFDIsCWD(fields["a0"])
		case "38", "276": // renameat, renameat2
			return auditDirFDIsCWD(fields["a0"]) && auditDirFDIsCWD(fields["a2"])
		}
	case "40000003": // i386
		switch num {
		case "5", "10", "38", "11": // open, unlink, rename, execve
			return true
		case "295", "301", "358": // openat, unlinkat, execveat
			return auditDirFDIsCWD(fields["a0"])
		case "302": // renameat
			return auditDirFDIsCWD(fields["a0"]) && auditDirFDIsCWD(fields["a2"])
		}
	}
	return false
}

func auditDirFDIsCWD(value string) bool {
	value = strings.TrimPrefix(value, "0x")
	return value == "-100" || strings.EqualFold(value, "ffffffffffffff9c") || strings.EqualFold(value, "ffffff9c")
}

func syscallToAction(arch, num string) string {
	// The same syscall number has different meanings across Linux ABIs. Keep
	// the table deliberately narrow; execution is classified from EXECVE records.
	switch arch {
	case "c000003e": // x86_64
		switch num {
		case "2", "257":
			return "open"
		case "87", "263":
			return "delete"
		case "82", "264":
			return "rename"
		}
	case "c00000b7": // aarch64
		switch num {
		case "56":
			return "open"
		case "35":
			return "delete"
		case "38", "276":
			return "rename"
		}
	case "40000003": // i386
		switch num {
		case "5", "295":
			return "open"
		case "10", "301":
			return "delete"
		case "38", "302":
			return "rename"
		}
	}
	return "syscall_" + num
}
