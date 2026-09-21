package e2e_test

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func postMCP(t *testing.T, addr string, headers map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/message", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// The MCP tools return the paths and process lineage of everything vigilo
// watches, so an unauthenticated listener answers "where are the keystores on
// this host". This asserts the running daemon enforces the token end to end,
// not just that the middleware exists.
func TestMCPHTTPRequiresToken(t *testing.T) {
	d := startDaemon(t, daemonOpts{watchPaths: []string{t.TempDir()}, mcpToken: "e2e-s3cret"})

	if code := postMCP(t, d.mcpAddr, nil); code != http.StatusUnauthorized {
		t.Errorf("no credentials = %d, want 401", code)
	}
	if code := postMCP(t, d.mcpAddr, map[string]string{"Authorization": "Bearer wrong"}); code != http.StatusUnauthorized {
		t.Errorf("wrong token = %d, want 401", code)
	}
	code := postMCP(t, d.mcpAddr, map[string]string{"Authorization": "Bearer e2e-s3cret"})
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		t.Errorf("correct token = %d, want the request to reach the server", code)
	}
}

func TestMCPHTTPRejectsBrowserOrigin(t *testing.T) {
	d := startDaemon(t, daemonOpts{watchPaths: []string{t.TempDir()}, mcpToken: "e2e-s3cret"})
	code := postMCP(t, d.mcpAddr, map[string]string{
		"Authorization": "Bearer e2e-s3cret",
		"Origin":        "https://evil.example",
	})
	if code != http.StatusForbidden {
		t.Errorf("browser origin = %d, want 403", code)
	}
}

// The daemon must refuse to serve the event buffer unauthenticated rather than
// inferring consent from an omitted secret.
func TestDaemonRefusesToStartUnauthenticated(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`watch_paths:
  - %s
poll_interval: 1s
buffer_retention_hours: 1
mcp_transport: http
mcp_addr: "127.0.0.1:%d"
`, dir, freePort(t))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	out, err := exec.Command(daemonBin, "-config", cfgPath, "-db", filepath.Join(dir, "events.db")).CombinedOutput() //nolint:gosec
	if err == nil {
		t.Fatal("daemon started on http transport with no token; it must refuse")
	}
	if !strings.Contains(string(out), "refusing to start") {
		t.Fatalf("expected a refusal on stderr, got: %s", out)
	}
}

// The explicit opt-out must still work, otherwise upgrading is a hard break.
func TestExplicitOptOutStartsUnauthenticated(t *testing.T) {
	d := startDaemon(t, daemonOpts{watchPaths: []string{t.TempDir()}})
	if code := postMCP(t, d.mcpAddr, nil); code == http.StatusUnauthorized {
		t.Fatalf("mcp_allow_unauthenticated should serve without a token, got %d", code)
	}
}
