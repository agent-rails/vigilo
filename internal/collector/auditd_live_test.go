//go:build linux

package collector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAuditdLiveFileAndExecAttribution(t *testing.T) {
	if os.Getenv("VIGILO_AUDITD_E2E") != "1" {
		t.Skip("set VIGILO_AUDITD_E2E=1 on a disposable audit-capable Linux host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("live auditd test must run as root")
	}

	logPath := os.Getenv("VIGILO_AUDITD_LOG")
	if logPath == "" {
		logPath = "/var/log/audit/audit.log"
	}
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("audit log unavailable at %s: %v", logPath, err)
	}

	key := fmt.Sprintf("vigilo_live_%d", os.Getpid())
	if len(key) > 31 {
		t.Fatalf("audit key too long: %s", key)
	}
	root := t.TempDir()
	if err := addAuditRule("-w", root, "-p", "wa", "-k", key+"_file"); err != nil {
		t.Fatalf("install temporary file audit rule: %v", err)
	}
	t.Cleanup(func() {
		if output, err := runAuditctl("-W", root, "-p", "wa", "-k", key+"_file"); err != nil {
			t.Errorf("remove temporary file audit rule: %v: %s", err, output)
		}
	})
	if err := addAuditRule("-a", "always,exit", "-F", "arch=b64", "-S", "execve,execveat", "-k", key+"_exec"); err != nil {
		t.Fatalf("install temporary execution audit rule: %v", err)
	}
	t.Cleanup(func() {
		if output, err := runAuditctl("-d", "always,exit", "-F", "arch=b64", "-S", "execve,execveat", "-k", key+"_exec"); err != nil {
			t.Errorf("remove temporary execution audit rule: %v: %s", err, output)
		}
	})

	events := make(chan Event, 256)
	watcher := NewAuditdWatcher(logPath, events)
	if err := watcher.Start(); err != nil {
		t.Fatalf("start audit log watcher: %v", err)
	}
	t.Cleanup(watcher.Stop)

	filePath := filepath.Join(root, "arbitrary-assessment-payload.bin")
	renamedPath := filepath.Join(root, "renamed-arbitrary-payload.bin")
	if err := os.WriteFile(filePath, []byte("initial contents\n"), 0600); err != nil {
		t.Fatalf("create watched file: %v", err)
	}
	if err := os.WriteFile(filePath, []byte("overwritten contents\n"), 0600); err != nil {
		t.Fatalf("overwrite watched file: %v", err)
	}
	if err := os.Rename(filePath, renamedPath); err != nil {
		t.Fatalf("rename watched file: %v", err)
	}
	if err := os.Remove(renamedPath); err != nil {
		t.Fatalf("delete watched file: %v", err)
	}
	child := exec.Command("/bin/true")
	if err := child.Run(); err != nil {
		t.Fatalf("run short-lived test binary: %v", err)
	}
	childPID := child.ProcessState.Pid()

	deadline := time.After(10 * time.Second)
	required := map[string]map[string]bool{
		filePath:    {"create": false, "write": false, "rename": false},
		renamedPath: {"rename": false, "delete": false},
	}
	gotExec := false
	for !allAuditActionsSeen(required) || !gotExec {
		select {
		case event := <-events:
			if actions, relevant := required[event.Resource]; relevant && event.Source == SourceFile {
				if event.PID != os.Getpid() || event.Executable == "" || event.User == "" {
					t.Fatalf("live file event lacks correct actor identity: %+v", event)
				}
				if _, expected := actions[event.Action]; expected {
					actions[event.Action] = true
				}
			}
			if event.Source == SourceProcess && event.Action == "exec" && event.PID == childPID {
				if !strings.Contains(event.Executable, "true") || event.User == "" {
					t.Fatalf("live execution event lacks executable/user identity: %+v", event)
				}
				gotExec = true
			}
		case <-deadline:
			t.Fatalf("timed out waiting for audit events (actions=%v exec=%v); check audit rules and %s", required, gotExec, logPath)
		}
	}

	// Exercise a modest burst and compare the kernel's audit loss counter.
	// This proves delivery for this controlled load only; it does not establish
	// a sustained-throughput ceiling.
	lostBefore, err := auditLostCount()
	if err != nil {
		t.Fatalf("read audit loss counter before burst: %v", err)
	}
	const burstFiles = 128
	burstPaths := make(map[string]bool, burstFiles)
	for i := 0; i < burstFiles; i++ {
		path := filepath.Join(root, fmt.Sprintf("burst-%03d.bin", i))
		burstPaths[path] = false
		if err := os.WriteFile(path, []byte("burst"), 0600); err != nil {
			t.Fatalf("create burst file %d: %v", i, err)
		}
	}
	burstDeadline := time.After(10 * time.Second)
	for {
		complete := true
		for _, seen := range burstPaths {
			if !seen {
				complete = false
				break
			}
		}
		if complete {
			break
		}
		select {
		case event := <-events:
			if event.Source == SourceFile && event.Action == "create" {
				if _, expected := burstPaths[event.Resource]; expected {
					burstPaths[event.Resource] = true
				}
			}
		case <-burstDeadline:
			t.Fatalf("timed out waiting for burst file audit events (%d/%d)", countSeen(burstPaths), burstFiles)
		}
	}
	lostAfter, err := auditLostCount()
	if err != nil {
		t.Fatalf("read audit loss counter after burst: %v", err)
	}
	if lostAfter != lostBefore {
		t.Fatalf("kernel audit lost counter increased during %d-file burst: %d -> %d", burstFiles, lostBefore, lostAfter)
	}
}

func countSeen(paths map[string]bool) int {
	count := 0
	for _, seen := range paths {
		if seen {
			count++
		}
	}
	return count
}

func auditLostCount() (uint64, error) {
	output, err := runAuditctl("-s")
	if err != nil {
		return 0, fmt.Errorf("auditctl -s: %w: %s", err, output)
	}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "lost" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("parse lost counter %q: %w", fields[1], err)
			}
			return value, nil
		}
	}
	return 0, fmt.Errorf("auditctl -s output did not contain a lost counter: %s", output)
}

func allAuditActionsSeen(required map[string]map[string]bool) bool {
	for _, actions := range required {
		for _, seen := range actions {
			if !seen {
				return false
			}
		}
	}
	return true
}

func addAuditRule(args ...string) error {
	output, err := runAuditctl(args...)
	if err != nil {
		return fmt.Errorf("auditctl %s: %w: %s", strings.Join(args, " "), err, output)
	}
	return nil
}

func runAuditctl(args ...string) (string, error) {
	cmd := exec.Command("auditctl", args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
