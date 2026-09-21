package mcp_test

import (
	"bufio"
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
	ts := httptest.NewServer(srv.SSEHandler(vigilomcp.AuthConfig{Token: token}))
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
	for _, header := range []string{"s3cret", "Basic s3cret", "Bearer", "Bearer wrong", ""} {
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
	// 400 "Missing sessionId" is mcp-go's own handleMessage answering, which is
	// what proves the request got past the middleware and into the MCP server.
	// Asserting merely "not 401 and not 403" would also pass against a bare
	// NotFoundHandler, i.e. if the MCP server were never mounted at all.
	if code := post(t, base, map[string]string{"Authorization": "Bearer s3cret"}); code != http.StatusBadRequest {
		t.Fatalf("a valid token must reach the MCP server (want 400), got %d", code)
	}
}

// RFC 7235 auth schemes are case-insensitive, so a client sending "bearer" is
// presenting a valid credential and must not be refused.
func TestSchemeIsCaseInsensitive(t *testing.T) {
	base := startSSE(t, "s3cret")
	for _, header := range []string{"Bearer s3cret", "bearer s3cret", "BEARER s3cret"} {
		if code := post(t, base, map[string]string{"Authorization": header}); code == http.StatusUnauthorized {
			t.Errorf("Authorization %q is a valid credential, got 401", header)
		}
	}
}

// Two Authorization headers are ambiguous. Header.Get would silently honour the
// first and ignore the rest, so a proxy-injected second header could ride along.
func TestDuplicateAuthorizationHeadersAreRejected(t *testing.T) {
	base := startSSE(t, "s3cret")
	req, err := http.NewRequest(http.MethodPost, base+"/message", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Add("Authorization", "Bearer s3cret")
	req.Header.Add("Authorization", "Bearer s3cret")
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("duplicate Authorization headers should be 401, got %d", resp.StatusCode)
	}
}

// The endpoint event must be relative so the client resolves it against the host
// it actually dialled. An absolute base derived from the listen address fails the
// SDK's origin equality check for every client reaching the daemon under a
// different hostname alias, which is the whole remote topology the README
// documents. This is the coverage whose absence let that regression through a
// green suite and two review passes.
func TestAdvertisedMessageEndpointIsRelative(t *testing.T) {
	base := startSSE(t, "s3cret")
	req, err := http.NewRequest(http.MethodGet, base+"/sse", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer s3cret")
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	for i := 0; i < 10; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read endpoint event: %v", err)
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		if strings.Contains(line, "http://") || strings.Contains(line, "https://") {
			t.Fatalf("advertised endpoint must be relative, got %q", strings.TrimSpace(line))
		}
		return
	}
	t.Fatal("no data: line in the SSE stream")
}

// An empty token disables authentication at the middleware. Reaching this state
// requires the operator to set mcp_allow_unauthenticated explicitly, because the
// daemon otherwise refuses to start; this asserts the opt-out behaves as
// documented rather than endorsing it as a deployment choice.
func TestEmptyTokenDisablesAuthButOriginStillRejected(t *testing.T) {
	base := startSSE(t, "")
	if code := post(t, base, nil); code == http.StatusUnauthorized {
		t.Fatal("an empty token should disable authentication")
	}
	if code := post(t, base, map[string]string{"Origin": "https://evil.example"}); code != http.StatusForbidden {
		t.Fatalf("the origin check must apply even with auth disabled, got %d", code)
	}
}
