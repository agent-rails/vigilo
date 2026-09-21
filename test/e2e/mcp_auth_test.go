package e2e_test

import (
	"net/http"
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
