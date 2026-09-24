//go:build linux

package collector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	if err := os.WriteFile(filePath, []byte("vigilo live audit test\n"), 0600); err != nil {
		t.Fatalf("write watched file: %v", err)
	}
	child := exec.Command("/bin/true")
	if err := child.Run(); err != nil {
		t.Fatalf("run short-lived test binary: %v", err)
	}
	childPID := child.ProcessState.Pid()

	deadline := time.After(10 * time.Second)
	gotFile, gotExec := false, false
	for !(gotFile && gotExec) {
		select {
		case event := <-events:
			if event.Resource == filePath && event.Source == SourceFile {
				if event.PID != os.Getpid() || event.Executable == "" || event.User == "" {
					t.Fatalf("live file event lacks correct actor identity: %+v", event)
				}
				gotFile = true
			}
			if event.Source == SourceProcess && event.Action == "exec" && event.PID == childPID {
				if !strings.Contains(event.Executable, "true") || event.User == "" {
					t.Fatalf("live execution event lacks executable/user identity: %+v", event)
				}
				gotExec = true
			}
		case <-deadline:
			t.Fatalf("timed out waiting for audit events (file=%v exec=%v); check audit rules and %s", gotFile, gotExec, logPath)
		}
	}
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
