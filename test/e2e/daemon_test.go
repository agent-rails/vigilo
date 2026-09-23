// Package e2e runs black-box integration tests against a real vigilo daemon
// subprocess. Each test builds the binary once (via TestMain), starts a fresh
// daemon instance on ephemeral ports, triggers events via the filesystem, and
// asserts results through the web API.
//
// Run: go test ./test/e2e/ -v -timeout 60s
package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// daemonBin holds the path to the compiled vigilo binary, built once in TestMain.
var daemonBin string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "vigilo-e2e-bin-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create bin dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	daemonBin = filepath.Join(tmp, "vigilo")
	out, err := exec.Command("go", "build", "-o", daemonBin,
		"../../cmd/vigilo/").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s\n", err, out)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// --- daemon harness ---

type instance struct {
	webAddr string
	mcpAddr string

	cmd    *exec.Cmd
	stderr *safeBuffer

	// exited closes once the daemon process has been reaped. waitErr is only
	// valid after a receive on it. Tests that assert the daemon is still running
	// need this: a process that has exited but not been waited on is a zombie
	// that still answers signal 0.
	exited  chan struct{}
	waitErr error
}

type daemonOpts struct {
	watchPaths   []string
	excludePaths []string
	suppress     []suppressRule
	webToken     string
	mcpToken     string
	webhookURL   string // if set, configures immediate alerter webhook
	minSeverity  string // alerter min_severity (default: critical when empty)
	cooldown     string // signal_cooldown duration string (default: 1s)
	mcpTransport string // "http" (default) or "stdio"
	holdStdin    bool   // keep stdin open; otherwise it is /dev/null, as under systemd
}

// safeBuffer collects daemon stderr. os/exec writes it from a copier goroutine
// while the test reads it, so the mutex is required under -race.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type suppressRule struct {
	match  string
	source string
	reason string
}

// startDaemon launches a vigilo daemon with the given options, waits until
// its /healthz endpoint responds, and registers cleanup on t.
func startDaemon(t *testing.T, opts daemonOpts) *instance {
	t.Helper()

	// Keep daemon files (db, config) separate from watched paths to avoid
	// the file watcher generating events from its own SQLite writes.
	daemonDir := t.TempDir()
	dbPath := filepath.Join(daemonDir, "events.db")
	cfgPath := filepath.Join(daemonDir, "config.yaml")

	webPort := freePort(t)
	mcpPort := freePort(t)
	webAddr := fmt.Sprintf("127.0.0.1:%d", webPort)
	mcpAddr := fmt.Sprintf("127.0.0.1:%d", mcpPort)

	cfg := buildConfig(opts, mcpAddr, webAddr)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(daemonBin, "-config", cfgPath, "-db", dbPath) //nolint:gosec
	cmd.Stdout = io.Discard
	stderr := &safeBuffer{}
	cmd.Stderr = stderr
	// A nil Stdin is /dev/null — every read returns EOF immediately, which is
	// exactly what systemd's default StandardInput=null hands the process.
	if opts.holdStdin {
		if _, err := cmd.StdinPipe(); err != nil {
			t.Fatalf("stdin pipe: %v", err)
		}
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}

	d := &instance{
		webAddr: webAddr, mcpAddr: mcpAddr,
		cmd: cmd, stderr: stderr, exited: make(chan struct{}),
	}
	go func() {
		d.waitErr = cmd.Wait()
		close(d.exited)
	}()
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		<-d.exited
	})

	waitReady(t, webAddr, d)
	return d
}

func buildConfig(opts daemonOpts, mcpAddr, webAddr string) string {
	var sb strings.Builder

	sb.WriteString("watch_paths:\n")
	for _, p := range opts.watchPaths {
		fmt.Fprintf(&sb, "  - %s\n", p)
	}
	if len(opts.excludePaths) > 0 {
		sb.WriteString("exclude_paths:\n")
		for _, p := range opts.excludePaths {
			fmt.Fprintf(&sb, "  - %s\n", p)
		}
	}
	if len(opts.suppress) > 0 {
		sb.WriteString("suppress_rules:\n")
		for _, r := range opts.suppress {
			fmt.Fprintf(&sb, "  - match: %q\n    source: %q\n    reason: %q\n",
				r.match, r.source, r.reason)
		}
	}
	cooldown := opts.cooldown
	if cooldown == "" {
		cooldown = "1s"
	}
	minSev := opts.minSeverity
	if minSev == "" {
		minSev = "critical"
	}

	transport := opts.mcpTransport
	if transport == "" {
		transport = "http"
	}

	fmt.Fprintf(&sb, `
poll_interval: 1s
buffer_retention_hours: 1
mcp_transport: %s
web_addr: %s
signal_cooldown: %s
alerter:
  min_severity: %s
`, transport, webAddr, cooldown, minSev)

	if opts.webhookURL != "" {
		fmt.Fprintf(&sb, "  webhooks:\n    - name: test\n      url: %s\n", opts.webhookURL)
	}
	if opts.webToken != "" {
		fmt.Fprintf(&sb, "web_token: %q\n", opts.webToken)
	}
	if transport == "http" {
		fmt.Fprintf(&sb, "mcp_addr: %s\n", mcpAddr)
		if opts.mcpToken != "" {
			fmt.Fprintf(&sb, "mcp_token: %q\n", opts.mcpToken)
		} else {
			// The daemon refuses to serve http unauthenticated without this opt-out.
			sb.WriteString("mcp_allow_unauthenticated: true\n")
		}
	}
	return sb.String()
}

// waitReady blocks until the daemon answers /healthz. d may be nil; when it is
// not, a daemon that dies during startup fails the test straight away, with its
// stderr, rather than after the full deadline with no explanation.
func waitReady(t *testing.T, webAddr string, d *instance) {
	t.Helper()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if d != nil {
			select {
			case <-d.exited:
				t.Fatalf("daemon exited before becoming ready: %v\nstderr:\n%s", d.waitErr, d.stderr.String())
			default:
			}
		}
		resp, err := client.Get("http://" + webAddr + "/healthz")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("daemon did not become ready within 15s")
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// event mirrors collector.Event for JSON decoding.
type event struct {
	Source   string `json:"source"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Severity string `json:"severity"`
}

// getEvents fetches /api/events?since=<1h ago>&<extra> and decodes the result.
// Returns nil on transient errors (429, connection refused) so callers can retry.
func getEvents(t *testing.T, d *instance, extra string, token string) []event {
	t.Helper()
	// UTC so Format emits a "Z" suffix. A local offset like "+01:00" is
	// concatenated raw into the query below, where the "+" decodes to a space
	// and the server rejects the timestamp. That made the suite pass in CI (UTC)
	// and fail on any developer machine with a non-zero offset.
	since := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	url := "http://" + d.webAddr + "/api/events?since=" + since + extra

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil // transient — let caller retry
	}
	defer resp.Body.Close()
	if resp.StatusCode == 429 {
		return nil // rate limited — let caller retry after delay
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("events API status %d: %s", resp.StatusCode, body)
	}
	var events []event
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		t.Fatalf("decode events: %v", err)
	}
	return events
}

// pollUntil retries f until it returns true or the deadline passes.
// Interval is 500ms to stay well under the web server's 20-req burst limit.
func pollUntil(t *testing.T, fn func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// --- tests ---

func TestDaemonHealthCheck(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})

	resp, err := http.Get("http://" + d.webAddr + "/healthz")
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("health status: %d", resp.StatusCode)
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want ok", body.Status)
	}
}

func TestHealthReportsEventCount(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})

	// write a sensitive file so there is at least one event
	time.Sleep(150 * time.Millisecond) // let fsnotify register the watch
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=x"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	ok := pollUntil(t, func() bool {
		resp, err := http.Get("http://" + d.webAddr + "/healthz")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var body struct {
			EventsBuffered int `json:"events_buffered"`
		}
		json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck
		return body.EventsBuffered > 0
	})
	if !ok {
		t.Fatal("health never showed events_buffered > 0")
	}
}

func TestEmptyDatabaseReturnsEmptySlice(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})

	events := getEvents(t, d, "", "")
	if events == nil {
		t.Error("expected empty slice, got nil")
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events on fresh daemon, got %d", len(events))
	}
}

func TestDotEnvWriteProducesHighEvent(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})
	time.Sleep(150 * time.Millisecond)

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=abc"), 0600); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	ok := pollUntil(t, func() bool {
		for _, e := range getEvents(t, d, "&source=file_access", "") {
			if strings.Contains(e.Resource, ".env") {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatal("no .env file event within timeout")
	}

	// Confirm severity is at least high
	rank := map[string]int{"info": 0, "medium": 1, "high": 2, "critical": 3}
	for _, e := range getEvents(t, d, "&source=file_access", "") {
		if strings.Contains(e.Resource, ".env") {
			if rank[e.Severity] < rank["high"] {
				t.Errorf(".env severity = %q, want >= high", e.Severity)
			}
		}
	}
}

func TestWalletJSONIsCritical(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})
	time.Sleep(150 * time.Millisecond)

	if err := os.WriteFile(filepath.Join(dir, "wallet.json"),
		[]byte(`{"key":"secret"}`), 0600); err != nil {
		t.Fatalf("write wallet.json: %v", err)
	}

	ok := pollUntil(t, func() bool {
		for _, e := range getEvents(t, d, "&severity=critical&source=file_access", "") {
			if strings.Contains(e.Resource, "wallet.json") && e.Severity == "critical" {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatal("no critical wallet.json event within timeout")
	}
}

func TestSSHPrivateKeyIsCritical(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})
	time.Sleep(150 * time.Millisecond)

	if err := os.WriteFile(filepath.Join(dir, "id_rsa"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----"), 0600); err != nil {
		t.Fatalf("write id_rsa: %v", err)
	}

	ok := pollUntil(t, func() bool {
		for _, e := range getEvents(t, d, "&severity=critical&source=file_access", "") {
			if strings.Contains(e.Resource, "id_rsa") && e.Severity == "critical" {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatal("no critical id_rsa event within timeout")
	}
}

func TestExcludedPathProducesNoEvent(t *testing.T) {
	dir := t.TempDir()
	excluded := filepath.Join(dir, "cache")
	if err := os.MkdirAll(excluded, 0755); err != nil {
		t.Fatal(err)
	}

	d := startDaemon(t, daemonOpts{
		watchPaths:   []string{dir},
		excludePaths: []string{excluded},
	})
	time.Sleep(150 * time.Millisecond)

	// Write inside excluded subdir — should be suppressed
	_ = os.WriteFile(filepath.Join(excluded, "wallet.json"),
		[]byte(`{"key":"secret"}`), 0600)

	// Write to watched dir — to confirm watcher is live
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=x"), 0600)

	// Wait until the .env event appears (watcher confirmed live)
	ok := pollUntil(t, func() bool {
		for _, e := range getEvents(t, d, "", "") {
			if strings.Contains(e.Resource, ".env") {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatal("sentinel .env event never appeared — watcher not live")
	}

	// Now assert excluded file did NOT produce an event
	for _, e := range getEvents(t, d, "", "") {
		if strings.Contains(e.Resource, "cache") && strings.Contains(e.Resource, "wallet.json") {
			t.Errorf("event emitted for excluded path: %s", e.Resource)
		}
	}
}

func TestSuppressionRuleDropsEvent(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{
		watchPaths: []string{dir},
		suppress: []suppressRule{
			{match: "suppressed.env", source: "file_access", reason: "test suppression"},
		},
	})
	time.Sleep(150 * time.Millisecond)

	// Write the suppressed file and a sentinel file
	_ = os.WriteFile(filepath.Join(dir, "suppressed.env"), []byte("should-be-dropped"), 0600)
	_ = os.WriteFile(filepath.Join(dir, "sentinel.env"), []byte("should-appear"), 0600)

	// Wait for sentinel to appear
	ok := pollUntil(t, func() bool {
		for _, e := range getEvents(t, d, "", "") {
			if strings.Contains(e.Resource, "sentinel.env") {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatal("sentinel event never appeared — watcher not live")
	}

	// Suppressed file must not be in buffer
	for _, e := range getEvents(t, d, "", "") {
		if strings.Contains(e.Resource, "suppressed.env") {
			t.Errorf("suppressed event leaked into buffer: %s", e.Resource)
		}
	}
}

func TestSeverityQueryFilterExcludesLowEvents(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})
	time.Sleep(150 * time.Millisecond)

	// Write both a critical file and an ordinary one
	_ = os.WriteFile(filepath.Join(dir, "wallet.json"), []byte(`{}`), 0600)
	_ = os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello"), 0600)

	// Wait for at least one event
	pollUntil(t, func() bool {
		return len(getEvents(t, d, "", "")) > 0
	})

	// High+ filter must not return info/medium events
	rank := map[string]int{"info": 0, "medium": 1, "high": 2, "critical": 3}
	for _, e := range getEvents(t, d, "&severity=high", "") {
		if rank[e.Severity] < rank["high"] {
			t.Errorf("severity filter leak: got %q event for %s", e.Severity, e.Resource)
		}
	}
}

func TestSourceQueryFilterReturnsOnlyFileEvents(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})
	time.Sleep(150 * time.Millisecond)

	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=x"), 0600)

	pollUntil(t, func() bool {
		return len(getEvents(t, d, "&source=file_access", "")) > 0
	})

	for _, e := range getEvents(t, d, "&source=file_access", "") {
		if e.Source != "file_access" {
			t.Errorf("source filter leak: got source %q", e.Source)
		}
	}
}

func TestMultipleFilesAllProduceEvents(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})
	time.Sleep(150 * time.Millisecond)

	files := []string{"wallet.json", ".env", "id_rsa"}
	for _, f := range files {
		_ = os.WriteFile(filepath.Join(dir, f), []byte("data"), 0600)
	}

	ok := pollUntil(t, func() bool {
		events := getEvents(t, d, "&source=file_access", "")
		found := map[string]bool{}
		for _, e := range events {
			for _, f := range files {
				if strings.Contains(e.Resource, f) {
					found[f] = true
				}
			}
		}
		return len(found) == len(files)
	})
	if !ok {
		t.Fatalf("not all %d file events appeared within timeout", len(files))
	}
}

func TestWebAuthRequiredWhenTokenSet(t *testing.T) {
	dir := t.TempDir()
	const token = "test-secret-token-abc"
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}, webToken: token})

	// Request without token — must get 401
	resp, err := http.Get("http://" + d.webAddr + "/api/events")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("unauthenticated status = %d, want 401", resp.StatusCode)
	}
}

func TestWebAuthBearerTokenGrantsAccess(t *testing.T) {
	dir := t.TempDir()
	const token = "test-secret-token-xyz"
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}, webToken: token})

	events := getEvents(t, d, "", token)
	if events == nil {
		t.Error("authorized request returned nil instead of empty slice")
	}
}

func TestWebAuthQueryParamTokenGrantsAccess(t *testing.T) {
	dir := t.TempDir()
	const token = "test-secret-token-qp"
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}, webToken: token})

	since := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	url := "http://" + d.webAddr + "/api/events?since=" + since + "&token=" + token
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("query-param token status = %d, want 200", resp.StatusCode)
	}
}

func TestDashboardHTMLServed(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})

	resp, err := http.Get("http://" + d.webAddr + "/")
	if err != nil {
		t.Fatalf("dashboard request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("dashboard status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<html") {
		t.Error("dashboard response does not contain <html")
	}
}

func TestMetricsEndpointReachable(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})

	resp, err := http.Get("http://" + d.webAddr + "/metrics")
	if err != nil {
		t.Fatalf("metrics request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("metrics status = %d, want 200", resp.StatusCode)
	}
}

func TestInvalidSeverityFilterReturns400(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})

	resp, err := http.Get("http://" + d.webAddr + "/api/events?severity=bogus")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("invalid severity status = %d, want 400", resp.StatusCode)
	}
}

func TestInvalidSinceFilterReturns400(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})

	resp, err := http.Get("http://" + d.webAddr + "/api/events?since=not-a-timestamp")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("invalid since status = %d, want 400", resp.StatusCode)
	}
}
