package e2e_test

// The MCP transport is the analyst tier's query surface, not the daemon's main
// loop. These tests pin that relationship on mcp_transport: stdio — the shipped
// default in config.example.yaml, and the one deploy/install.sh copies into
// /etc/vigilo/config.yaml alongside a Restart=always unit.
//
// Nothing exercised it before: every other daemon in this suite runs on http,
// and config_test.go works around the stdio path rather than covering it. That
// gap is why the documented install shipped as a five-second restart loop whose
// pollers never reached a first tick.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// healthStatus mirrors the /healthz payload. mcp_transport_up is a pointer so
// an absent field is distinguishable from an explicit false.
type healthStatus struct {
	Status         string `json:"status"`
	MCPTransportUp *bool  `json:"mcp_transport_up"`
}

func getHealth(t *testing.T, d *instance) healthStatus {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + d.webAddr + "/healthz")
	if err != nil {
		return healthStatus{}
	}
	defer resp.Body.Close()
	var h healthStatus
	json.NewDecoder(resp.Body).Decode(&h) //nolint:errcheck
	return h
}

// Stdin at EOF is the normal condition under any service manager: systemd's
// StandardInput= defaults to null. The daemon must treat that as the analyst
// tier going away, not as a reason to stop watching keys — the alert path does
// not depend on a model being reachable, and must not depend on its transport
// either.
func TestStdioTransportEOFDoesNotStopDaemon(t *testing.T) {
	dir := t.TempDir()
	sink := newWebhookSink(t)
	d := startDaemon(t, daemonOpts{
		watchPaths: []string{dir}, mcpTransport: "stdio", webhookURL: sink.server.URL,
	})

	select {
	case <-d.exited:
		t.Fatalf("daemon exited after stdin EOF (%v) — collection and alerting must outlive the MCP transport\nstderr:\n%s",
			d.waitErr, d.stderr.String())
	case <-time.After(2 * time.Second):
	}

	// Still running is not enough; it has to still be detecting. A daemon that
	// stays up with dead collectors is the same silent non-coverage in a
	// different costume.
	if err := os.WriteFile(filepath.Join(dir, "wallet.json"), []byte(`{"key":"x"}`), 0600); err != nil {
		t.Fatalf("write wallet.json: %v", err)
	}
	ok := pollUntil(t, func() bool {
		for _, e := range getEvents(t, d, "&source=file_access", "") {
			if strings.Contains(e.Resource, "wallet.json") {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatalf("daemon survived stdin EOF but stopped detecting\nstderr:\n%s", d.stderr.String())
	}
	select {
	case payload := <-sink.received:
		if payload["source"] != "file_access" || payload["resource"] != filepath.Join(dir, "wallet.json") {
			t.Fatalf("unexpected alert after stdin EOF: %v", payload)
		}
	case <-time.After(8 * time.Second):
		t.Fatalf("daemon stored the event after stdin EOF but sent no webhook\nstderr:\n%s", d.stderr.String())
	}
}

// Losing the analyst tier while tier 1 keeps firing is a degradation an
// operator has to be able to see. A daemon that silently half-works is the
// failure this whole tool exists to avoid.
func TestStdioTransportLossIsReported(t *testing.T) {
	d := startDaemon(t, daemonOpts{watchPaths: []string{t.TempDir()}, mcpTransport: "stdio"})

	ok := pollUntil(t, func() bool {
		h := getHealth(t, d)
		return h.MCPTransportUp != nil && !*h.MCPTransportUp &&
			strings.Contains(d.stderr.String(), "MCP stdio transport closed")
	})
	if !ok {
		t.Errorf("healthz never reported mcp_transport_up=false after stdin EOF; "+
			"the analyst tier is unreachable and nothing surfaces it\nstderr:\n%s", d.stderr.String())
	}

	logs := d.stderr.String()
	if !strings.Contains(logs, "MCP stdio transport closed") {
		t.Errorf("no log line explaining the lost transport\nstderr:\n%s", logs)
	}
	if !strings.Contains(logs, "mcp_transport: http") {
		t.Errorf("the log names the problem but not the remedy\nstderr:\n%s", logs)
	}
}

// Guards the gauge against being vacuously false: on a transport that is
// actually serving it must read true.
func TestHTTPTransportReportsUp(t *testing.T) {
	d := startDaemon(t, daemonOpts{watchPaths: []string{t.TempDir()}, mcpToken: "e2e-s3cret"})

	if !pollUntil(t, func() bool {
		h := getHealth(t, d)
		return h.MCPTransportUp != nil && *h.MCPTransportUp
	}) {
		t.Fatal("healthz never reported mcp_transport_up=true for the HTTP transport")
	}
}

// The inverse of the EOF case, and the same defect: with stdin held open the
// stdio transport used to swallow the shutdown signal, so SIGTERM returned a
// bare "context canceled" that the daemon treated as a transport fault and
// exited(1) on — skipping the collector stop, the event-bus drain and
// store.Close(). Shutdown ordering there is a correctness property, not tidiness.
func TestStdioTransportShutsDownCleanlyOnSignal(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}, mcpTransport: "stdio", holdStdin: true})

	if err := os.WriteFile(filepath.Join(dir, "wallet.json"), []byte(`{"key":"x"}`), 0600); err != nil {
		t.Fatalf("write wallet.json: %v", err)
	}
	if !pollUntil(t, func() bool { return len(getEvents(t, d, "", "")) > 0 }) {
		t.Fatal("daemon did not record the event before shutdown")
	}

	if err := d.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}
	select {
	case <-d.exited:
	case <-time.After(20 * time.Second):
		t.Fatalf("daemon did not exit within 20s of SIGTERM\nstderr:\n%s", d.stderr.String())
	}

	if d.waitErr != nil {
		t.Errorf("SIGTERM exit = %v, want 0 — a shutdown signal is not a transport fault\nstderr:\n%s",
			d.waitErr, d.stderr.String())
	}
	if !strings.Contains(d.stderr.String(), "vigilo daemon stopped") {
		t.Errorf("daemon never reached its graceful shutdown path on SIGTERM; "+
			"the event-bus drain and store.Close() were skipped\nstderr:\n%s", d.stderr.String())
	}
}
