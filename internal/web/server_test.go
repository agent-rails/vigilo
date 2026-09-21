package web_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/voltagebots/vigilo/internal/buffer"
	"github.com/voltagebots/vigilo/internal/web"
)

func openTestStore(t *testing.T) *buffer.Store {
	t.Helper()
	f, err := os.CreateTemp("", "vigilo-web-test-*.db")
	if err != nil {
		t.Fatalf("temp db: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	store, err := buffer.Open(f.Name(), 24)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return store
}

func get(t *testing.T, srv *web.Server, path string, headers map[string]string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec.Code
}

// VIGILO_WEB_TOKEN is read in New() as a fallback, so it has to be cleared or
// these tests inherit whatever the developer has exported.
func newServer(t *testing.T, token string) *web.Server {
	t.Helper()
	t.Setenv("VIGILO_WEB_TOKEN", "")
	return web.New(openTestStore(t), web.Config{Token: token})
}

func TestProtectedRoutesRejectMissingToken(t *testing.T) {
	srv := newServer(t, "s3cret")
	for _, path := range []string{"/", "/api/events", "/events/stream"} {
		if code := get(t, srv, path, nil); code != http.StatusUnauthorized {
			t.Errorf("%s without a token = %d, want 401", path, code)
		}
	}
}

func TestProtectedRoutesRejectWrongToken(t *testing.T) {
	srv := newServer(t, "s3cret")
	code := get(t, srv, "/api/events", map[string]string{"Authorization": "Bearer wrong"})
	if code != http.StatusUnauthorized {
		t.Errorf("wrong bearer token = %d, want 401", code)
	}
	if code := get(t, srv, "/api/events?token=wrong", nil); code != http.StatusUnauthorized {
		t.Errorf("wrong query token = %d, want 401", code)
	}
}

func TestBearerAndQueryTokenBothAuthorize(t *testing.T) {
	srv := newServer(t, "s3cret")
	if code := get(t, srv, "/api/events", map[string]string{"Authorization": "Bearer s3cret"}); code == http.StatusUnauthorized {
		t.Error("a correct bearer token must authorize")
	}
	if code := get(t, srv, "/api/events?token=s3cret", nil); code == http.StatusUnauthorized {
		t.Error("a correct query token must authorize")
	}
}

func TestEmptyTokenDisablesAuth(t *testing.T) {
	srv := newServer(t, "")
	if code := get(t, srv, "/api/events", nil); code == http.StatusUnauthorized {
		t.Error("an empty token should disable authentication")
	}
}

// /healthz and /metrics are registered without the auth middleware so that
// liveness probes and scrapers work without credentials. That is deliberate, but
// it means anything added to those handlers is public by construction.
func TestHealthAndMetricsAreUnauthenticatedByDesign(t *testing.T) {
	srv := newServer(t, "s3cret")
	for _, path := range []string{"/healthz", "/metrics"} {
		if code := get(t, srv, path, nil); code == http.StatusUnauthorized {
			t.Errorf("%s must stay reachable without a token, got %d", path, code)
		}
	}
}
