package config

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAlerterSourceSeverityOverridesDecode(t *testing.T) {
	var cfg struct {
		Alerter AlerterConfig `yaml:"alerter"`
	}
	if err := yaml.Unmarshal([]byte("alerter:\n  min_severity: high\n  min_severity_by_source:\n    file_access: info\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Alerter.MinSeverityBySource["file_access"]; got != "info" {
		t.Fatalf("file_access threshold = %q, want info", got)
	}
}

func TestPersonalExampleConfigEnablesPersonalAlerts(t *testing.T) {
	data, err := os.ReadFile("../../config.personal.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Defaults
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode personal example config: %v", err)
	}
	if len(cfg.WatchPaths) < 2 {
		t.Fatalf("personal example must include common user paths, got %v", cfg.WatchPaths)
	}
	if !cfg.ProcessMonitor.ReportNewProcesses {
		t.Fatal("personal example must inventory newly observed processes")
	}
	if cfg.SignalCooldown != 0 {
		t.Fatalf("personal example signal cooldown = %s, want zero to report every observed change", cfg.SignalCooldown)
	}
	for _, source := range []string{"file_access", "process"} {
		if got := cfg.Alerter.MinSeverityBySource[source]; got != "info" {
			t.Errorf("personal example %s alert threshold = %q, want info", source, got)
		}
	}
}

func TestProcessInventoryIsIndependentFromAlertThreshold(t *testing.T) {
	cfg := Defaults
	if cfg.ProcessMonitor.Enabled != nil {
		t.Fatal("process monitoring should use the enabled compatibility default")
	}
	if cfg.ProcessMonitor.ReportNewProcesses {
		t.Fatal("new-process inventory should remain opt-in")
	}
	if err := yaml.Unmarshal([]byte("alerter:\n  min_severity_by_source:\n    process: info\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ProcessMonitor.ReportNewProcesses {
		t.Fatal("alert threshold unexpectedly enabled process inventory")
	}
	if err := yaml.Unmarshal([]byte("process_monitor:\n  enabled: false\n  report_new_processes: true\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ProcessMonitor.Enabled == nil || *cfg.ProcessMonitor.Enabled || !cfg.ProcessMonitor.ReportNewProcesses {
		t.Fatalf("process_monitor settings not decoded: %+v", cfg.ProcessMonitor)
	}
}
