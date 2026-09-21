package mcp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vigilomcp "github.com/voltagebots/vigilo/internal/mcp"
)

// startSSE serves the same handler chain ServeSSE listens with, so these tests
// exercise the real middleware rather than a stand-in. That the chain is also
// installed by the daemon is proved separately in test/e2e/mcp_auth_test.go
// against the real binary.
func startSSE(t *testing.T, token string) string {
	t.Helper()
	srv := vigilomcp.New(openTestStore(t))
	ts := httptest.NewServer(srv.SSEHandler("127.0.0.1:0", vigilomcp.AuthConfig{Token: token}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// post hits the message endpoint rather than /sse: /sse is a long-lived stream
// and would block a passing request until the client timeout.
func post(t *testing.T, base string, headers map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/message", strings.NewReader("{}"))
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

func TestMissingTokenIsRejected(t *testing.T) {
	base := startSSE(t, "s3cret")
	if code := post(t, base, nil); code != http.StatusUnauthorized {
		t.Fatalf("no credentials should be 401, got %d", code)
	}
}

func TestWrongTokenIsRejected(t *testing.T) {
	base := startSSE(t, "s3cret")
	if code := post(t, base, map[string]string{"Authorization": "Bearer wrong"}); code != http.StatusUnauthorized {
		t.Fatalf("wrong token should be 401, got %d", code)
	}
}

func TestMalformedAuthorizationHeaderIsRejected(t *testing.T) {
	base := startSSE(t, "s3cret")
	for _, header := range []string{"s3cret", "Basic s3cret", "bearer s3cret", ""} {
		if code := post(t, base, map[string]string{"Authorization": header}); code != http.StatusUnauthorized {
			t.Errorf("Authorization %q should be 401, got %d", header, code)
		}
	}
}

// The pinned SSE handler sets Access-Control-Allow-Origin: * unconditionally, so
// a cross-origin response that reached it would be readable by the calling page.
// Refusing anything that carries Origin closes that. It is not rebinding
// protection: a rebound request is same-origin and a same-origin GET sends no
// Origin at all. The token covers that case.
func TestBrowserOriginIsRejectedEvenWithValidToken(t *testing.T) {
	base := startSSE(t, "s3cret")
	code := post(t, base, map[string]string{
		"Authorization": "Bearer s3cret",
		"Origin":        "https://evil.example",
	})
	if code != http.StatusForbidden {
		t.Fatalf("a browser origin should be 403 even with a valid token, got %d", code)
	}
}

func TestValidTokenReachesTheServer(t *testing.T) {
	base := startSSE(t, "s3cret")
	code := post(t, base, map[string]string{"Authorization": "Bearer s3cret"})
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		t.Fatalf("a valid token must reach the MCP server, got %d", code)
	}
}

// An empty token disables authentication, matching the web dashboard. The daemon
// warns at startup in that case; this asserts the documented behaviour rather
// than endorsing it as a deployment choice.
func TestEmptyTokenDisablesAuthButOriginStillRejected(t *testing.T) {
	base := startSSE(t, "")
	if code := post(t, base, nil); code == http.StatusUnauthorized {
		t.Fatal("an empty token should disable authentication")
	}
	if code := post(t, base, map[string]string{"Origin": "https://evil.example"}); code != http.StatusForbidden {
		t.Fatalf("the origin check must apply even with auth disabled, got %d", code)
	}
}
