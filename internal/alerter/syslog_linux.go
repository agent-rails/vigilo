//go:build linux

package alerter

import (
	"fmt"
	"log/syslog"

	"github.com/voltagebots/vigilo/internal/collector"
)

type syslogChannel struct {
	w *syslog.Writer
}

func newSyslogChannel() channel {
	w, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_WARNING, "vigilo")
	if err != nil {
		return nil
	}
	return &syslogChannel{w: w}
}

func (s *syslogChannel) name() string { return "syslog" }

func (s *syslogChannel) send(e collector.Event, _ string) error {
	sev := cefSeverity(e.Severity)
	cef := fmt.Sprintf(
		"CEF:0|VoltageBot|Vigilo|1.0|%s|%s %s|%d|src=%s filePath=%s dproc=%s sourceProcessId=%d sourceUserId=%s sourceExecutable=%s msg=%s",
		cefHeader(string(e.Source)),
		cefHeader(e.Action), cefHeader(e.Resource),
		sev,
		cefExtension(string(e.Source)), cefExtension(e.Resource), cefExtension(e.Process), e.PID,
		cefExtension(e.User), cefExtension(e.Executable), cefExtension(e.Detail),
	)

	switch e.Severity {
	case collector.SeverityCritical, collector.SeverityHigh:
		return s.w.Err(cef)
	case collector.SeverityMedium:
		return s.w.Warning(cef)
	default:
		return s.w.Info(cef)
	}
}

func cefSeverity(sev collector.Severity) int {
	switch sev {
	case collector.SeverityCritical:
		return 10
	case collector.SeverityHigh:
		return 7
	case collector.SeverityMedium:
		return 4
	default:
		return 1
	}
}
