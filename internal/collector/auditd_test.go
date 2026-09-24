//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func auditGroupFromLines(t *testing.T, lines ...string) *auditGroup {
	t.Helper()
	g := &auditGroup{}
	for _, line := range lines {
		record, ok := parseLine(line)
		if !ok {
			t.Fatalf("parseLine rejected fixture: %s", line)
		}
		g.records = append(g.records, record)
	}
	return g
}

func TestAuditdExecEventDetectsShortLivedMasqueradingProcess(t *testing.T) {
	g := auditGroupFromLines(t,
		`type=SYSCALL msg=audit(1700000000.123:42): arch=c00000b7 syscall=221 success=yes exit=0 ppid=30 pid=31 auid=1000 uid=1000 comm="systemupdate" exe="/tmp/systemupdate" key="vigilo_exec"`,
		`type=EXECVE msg=audit(1700000000.123:42): argc=1 a0="/tmp/systemupdate"`,
		`type=PATH msg=audit(1700000000.123:42): item=0 name="/tmp/systemupdate" inode=10 dev=00:00 mode=0100755 nametype=NORMAL`,
	)
	events := eventsForAuditGroup(g)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	e := events[0]
	if e.Source != SourceProcess || e.Action != "exec" || e.Severity != SeverityHigh {
		t.Fatalf("unexpected exec event classification: %+v", e)
	}
	if e.PID != 31 || e.PPID != 30 || e.User != "1000" || e.Executable != "/tmp/systemupdate" {
		t.Fatalf("exec identity context missing: %+v", e)
	}
	if e.CmdLine != "" {
		t.Fatalf("audit EXECVE arguments must not be retained: %+v", e)
	}
}

func TestAuditdFileEventIncludesActorWithoutArgv(t *testing.T) {
	g := auditGroupFromLines(t,
		`type=SYSCALL msg=audit(1700000000.123:43): arch=c000003e syscall=257 success=yes exit=3 ppid=50 pid=51 auid=1000 uid=1000 comm="node" exe="/usr/bin/node" key="vigilo_project"`,
		`type=PATH msg=audit(1700000000.123:43): item=0 name="/home/alex/project/.env" inode=11 dev=00:00 mode=0100644 nametype=NORMAL`,
	)
	events := eventsForAuditGroup(g)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	e := events[0]
	if e.Source != SourceFile || e.Resource != "/home/alex/project/.env" || e.PID != 51 || e.Executable != "/usr/bin/node" {
		t.Fatalf("file event attribution missing: %+v", e)
	}
	if e.CmdLine != "" {
		t.Fatalf("file event must not store command-line data: %+v", e)
	}
}

func TestAuditdDoesNotInferExecFromAmbiguousSyscallNumber(t *testing.T) {
	g := auditGroupFromLines(t,
		`type=SYSCALL msg=audit(1700000000.123:45): arch=c000003e syscall=221 success=yes exit=0 ppid=50 pid=51 auid=1000 uid=1000 comm="ordinary" exe="/usr/bin/ordinary" key="vigilo_exec"`,
	)
	if events := eventsForAuditGroup(g); len(events) != 0 {
		t.Fatalf("x86_64 syscall 221 was misclassified as execution: %+v", events)
	}
}

func TestAuditdDiskGroupCompletenessDoesNotRequireEOE(t *testing.T) {
	g := auditGroupFromLines(t,
		`type=SYSCALL msg=audit(1700000000.123:52): arch=c000003e syscall=82 items=2 success=yes exit=0 ppid=1 pid=2 uid=1000 comm="mv" exe="/usr/bin/mv" key="vigilo_project"`,
		`type=PATH msg=audit(1700000000.123:52): item=0 name="old" nametype=DELETE`,
	)
	if auditGroupComplete(g) {
		t.Fatal("rename group missing its second PATH item was treated as complete")
	}
	second, ok := parseLine(`type=PATH msg=audit(1700000000.123:52): item=1 name="new" nametype=CREATE`)
	if !ok {
		t.Fatal("second PATH fixture rejected")
	}
	g.records = append(g.records, second)
	if !auditGroupComplete(g) {
		t.Fatal("complete disk-log group incorrectly requires an EOE record")
	}
}

func TestAuditdDoesNotReportFailedExecutionAsRunningProcess(t *testing.T) {
	g := auditGroupFromLines(t,
		`type=SYSCALL msg=audit(1700000000.123:46): arch=c000003e syscall=59 success=no exit=-2 ppid=50 pid=51 auid=1000 uid=1000 comm="not-started" exe="/usr/bin/sh" key="vigilo_exec"`,
		`type=EXECVE msg=audit(1700000000.123:46): argc=1 a0="not-started"`,
	)
	if events := eventsForAuditGroup(g); len(events) != 0 {
		t.Fatalf("failed execution was reported as a running process: %+v", events)
	}
}

func TestAuditdPreservesKernelEventTimestamp(t *testing.T) {
	g := auditGroupFromLines(t,
		`type=SYSCALL msg=audit(1700000000.123:47): arch=c000003e syscall=257 success=yes exit=3 ppid=50 pid=51 auid=1000 uid=1000 comm="writer" exe="/usr/bin/writer" key="vigilo_project"`,
		`type=PATH msg=audit(1700000000.123:47): item=0 name="/tmp/any file" inode=11 dev=00:00 mode=0100644 nametype=NORMAL`,
	)
	events := eventsForAuditGroup(g)
	if len(events) != 1 || events[0].Timestamp.Unix() != 1700000000 || events[0].Timestamp.Nanosecond() < 122000000 || events[0].Timestamp.Nanosecond() > 124000000 {
		t.Fatalf("kernel event timestamp not preserved: %+v", events)
	}
}

func TestAuditdDecodesEncodedFieldsAndResolvesRelativePaths(t *testing.T) {
	if got := decodeAuditHex("2F746D702F610962"); got != "/tmp/a\tb" {
		t.Fatalf("decodeAuditHex() = %q", got)
	}
	if got := decodeAuditHex("2f746d702f612062"); got != "/tmp/a b" {
		t.Fatalf("space-containing audit hex did not decode: %q", got)
	}
	if got := decodeAuditHex("deadbeef"); got != "deadbeef" {
		t.Fatalf("ordinary hex-looking path changed: %q", got)
	}
	g := auditGroupFromLines(t,
		`type=SYSCALL msg=audit(1700000000.123:48): arch=c000003e syscall=257 a0=ffffffffffffff9c a2=0 success=yes exit=3 ppid=50 pid=51 auid=1000 uid=1000 comm="writer" exe="/usr/bin/writer" key="vigilo_project"`,
		`type=CWD msg=audit(1700000000.123:48): cwd="/home/alex/project"`,
		`type=PATH msg=audit(1700000000.123:48): item=0 name=".cache/payload.bin" inode=11 dev=00:00 mode=0100644 nametype=NORMAL`,
	)
	events := eventsForAuditGroup(g)
	if len(events) != 1 || events[0].Resource != "/home/alex/project/.cache/payload.bin" {
		t.Fatalf("relative audit path was not resolved against CWD: %+v", events)
	}
	if events[0].Action != "read" {
		t.Fatalf("read-only open misclassified as a mutation: %+v", events[0])
	}
}

func TestAuditdClassifiesOpenWriteFlags(t *testing.T) {
	g := auditGroupFromLines(t,
		`type=SYSCALL msg=audit(1700000000.123:50): arch=c000003e syscall=257 a0=ffffffffffffff9c a2=241 success=yes exit=3 ppid=50 pid=51 auid=1000 uid=1000 comm="writer" exe="/usr/bin/writer" key="vigilo_project"`,
		`type=CWD msg=audit(1700000000.123:50): cwd="/tmp"`,
		`type=PATH msg=audit(1700000000.123:50): item=0 name="payload.bin" inode=11 dev=00:00 mode=0100644 nametype=NORMAL`,
	)
	events := eventsForAuditGroup(g)
	if len(events) != 1 || events[0].Action != "write" || !strings.Contains(events[0].Detail, "access=write") {
		t.Fatalf("write-intent open was not classified: %+v", events)
	}
}

func TestAuditdDistinguishesCreatedPathFromWriteIntent(t *testing.T) {
	g := auditGroupFromLines(t,
		`type=SYSCALL msg=audit(1700000000.123:53): arch=c000003e syscall=257 a0=ffffffffffffff9c a2=241 success=yes exit=3 ppid=50 pid=51 auid=1000 uid=1000 comm="writer" exe="/usr/bin/writer" key="vigilo_project"`,
		`type=CWD msg=audit(1700000000.123:53): cwd="/tmp"`,
		`type=PATH msg=audit(1700000000.123:53): item=0 name="new-payload.bin" inode=12 dev=00:00 mode=0100644 nametype=CREATE`,
	)
	events := eventsForAuditGroup(g)
	if len(events) != 1 || events[0].Action != "create" || events[0].Resource != "/tmp/new-payload.bin" {
		t.Fatalf("audit CREATE path was not distinguished from a write: %+v", events)
	}
	if !strings.Contains(events[0].Detail, "access=write") {
		t.Fatalf("create event lost the observed write intent: %+v", events[0])
	}
}

func TestAuditdDoesNotInventCWDForNonCWDDirFD(t *testing.T) {
	g := auditGroupFromLines(t,
		`type=SYSCALL msg=audit(1700000000.123:51): arch=c000003e syscall=257 a0=3 a2=0 success=yes exit=3 ppid=50 pid=51 auid=1000 uid=1000 comm="writer" exe="/usr/bin/writer" key="vigilo_project"`,
		`type=CWD msg=audit(1700000000.123:51): cwd="/home/alex/project"`,
		`type=PATH msg=audit(1700000000.123:51): item=0 name="relative.bin" inode=11 dev=00:00 mode=0100644 nametype=NORMAL`,
	)
	events := eventsForAuditGroup(g)
	if len(events) != 1 || events[0].Resource != "relative.bin" {
		t.Fatalf("path relative to an unknown dirfd was falsely resolved: %+v", events)
	}
}

func TestAuditdExecPreservesBinaryAndScriptResourceSeparately(t *testing.T) {
	g := auditGroupFromLines(t,
		`type=SYSCALL msg=audit(1700000000.123:49): arch=c000003e syscall=59 success=yes exit=0 ppid=50 pid=51 auid=1000 uid=1000 comm="bash" exe="/usr/bin/bash" cwd="/home/alex" key="vigilo_exec"`,
		`type=EXECVE msg=audit(1700000000.123:49): argc=2 a0="/home/alex/job.sh" a1="secret"`,
		`type=CWD msg=audit(1700000000.123:49): cwd="/home/alex"`,
		`type=PATH msg=audit(1700000000.123:49): item=0 name="job.sh" inode=11 dev=00:00 mode=0100755 nametype=NORMAL`,
	)
	events := eventsForAuditGroup(g)
	if len(events) != 1 || events[0].Executable != "/usr/bin/bash" || events[0].Resource != "/home/alex/job.sh" {
		t.Fatalf("script target and executing binary were conflated: %+v", events)
	}
	if events[0].CmdLine != "" {
		t.Fatal("audit EXECVE arguments must not be retained")
	}
}

func TestAuditdFileEventAcceptsArbitraryPathAndSkipsContextPaths(t *testing.T) {
	g := auditGroupFromLines(t,
		`type=SYSCALL msg=audit(1700000000.123:44): arch=c000003e syscall=257 success=yes exit=3 ppid=50 pid=51 auid=1000 uid=1000 comm="package installer" exe="/usr/bin/node" key="vigilo_project"`,
		`type=PATH msg=audit(1700000000.123:44): item=0 name="/home/alex/project/.cache/arbitrary payload.bin" inode=11 dev=00:00 mode=0100644 nametype=NORMAL`,
		`type=PATH msg=audit(1700000000.123:44): item=1 name="/home/alex/project" inode=12 dev=00:00 mode=040755 nametype=CWD`,
	)
	events := eventsForAuditGroup(g)
	if len(events) != 1 {
		t.Fatalf("got %d events, want only operated-on path: %+v", len(events), events)
	}
	e := events[0]
	if e.Resource != "/home/alex/project/.cache/arbitrary payload.bin" || e.Process != "package installer" || e.PID != 51 || e.PPID != 50 || e.User != "1000" || e.Executable != "/usr/bin/node" {
		t.Fatalf("arbitrary path or actor context missing: %+v", e)
	}
	if e.CmdLine != "" {
		t.Fatalf("argv must not be retained: %+v", e)
	}
}

func TestAuditdWatcherReadsAppendsAfterEOFAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	events := make(chan Event, 8)
	watcher := NewAuditdWatcher(path, events)
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	appendText := func(text string) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteString(text)
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	writeRecord := func(serial, name string) {
		appendText("type=SYSCALL msg=audit(1700000000.123:" + serial + "): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=77 auid=1000 uid=1000 comm=\"" + name + "\" exe=\"/tmp/" + name + "\" key=\"vigilo_exec\"\n")
		appendText("type=EXECVE msg=audit(1700000000.123:" + serial + "): argc=1 a0=\"/tmp/" + name + "\"\n")
	}
	waitForProcessEvent := func(want string) {
		t.Helper()
		deadline := time.After(4 * time.Second)
		for {
			select {
			case e := <-events:
				if e.Source == SourceProcess && e.Process == want {
					return
				}
			case <-deadline:
				t.Fatalf("timed out waiting for audit exec event %q", want)
			}
		}
	}

	writeRecord("501", "append-after-eof")
	waitForProcessEvent("append-after-eof")
	partial := "type=SYSCALL msg=audit(1700000000.123:503): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=77 auid=1000 uid=1000 comm=\"split-across-eof\" exe=\"/tmp/split-across-eof\" key=\"vigilo_exec\"\n"
	cut := len(partial) / 2
	appendText(partial[:cut])
	time.Sleep(250 * time.Millisecond) // allow the reader to observe EOF with a partial record
	appendText(partial[cut:])
	appendText("type=EXECVE msg=audit(1700000000.123:503): argc=1 a0=\"/tmp/split-across-eof\"\n")
	waitForProcessEvent("split-across-eof")

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	writeRecord("502", "after-rotation")
	waitForProcessEvent("after-rotation")
}
