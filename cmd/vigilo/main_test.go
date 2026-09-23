package main

import (
	"testing"

	"github.com/voltagebots/vigilo/internal/collector"
)

func TestSourceSeverityOverrides(t *testing.T) {
	got := sourceSeverityOverrides(map[string]string{
		"file_access":  "info",
		"not_a_source": "info",
		"process":      "urgent",
	})
	if got[collector.SourceFile] != collector.SeverityInfo {
		t.Fatalf("file_access threshold = %q, want info", got[collector.SourceFile])
	}
	if _, ok := got[collector.SourceProcess]; ok {
		t.Fatal("invalid severity must be ignored so the global threshold remains in force")
	}
	if _, ok := got[collector.EventSource("not_a_source")]; ok {
		t.Fatal("unknown source must be ignored")
	}
}
