// Package web serves a real-time event dashboard over HTTP.
// It is an optional component — enabled by setting web_addr in config.
package web

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"expvar"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/voltagebots/vigilo/internal/buffer"
	"github.com/voltagebots/vigilo/internal/collector"
)

// expvar counters — exposed at /metrics.
var (
	metricEventsTotal   = expvar.NewInt("vigilo_events_total")
	metricAlertsSent    = expvar.NewInt("vigilo_alerts_sent")
	metricAlertsDropped = expvar.NewInt("vigilo_alerts_dropped")
	metricWebRequests   = expvar.NewInt("vigilo_web_requests_total")

	// 1 while the MCP transport is serving, 0 once it has stopped. The daemon
	// keeps collecting and alerting either way, so without a gauge the loss of
	// the analyst tier is a single log line that scrolls away — silent
	// non-coverage, which is the characteristic failure of this class of tool.
	metricMCPTransportUp   = expvar.NewInt("vigilo_mcp_transport_up")
	metricCoverageDegraded = expvar.NewInt("vigilo_coverage_degraded")
)

// SetMCPTransportUp records whether the MCP query transport is serving.
// Process-wide rather than a method on Server, because the daemon must be able
// to report it whether or not the optional dashboard is enabled.
func SetMCPTransportUp(up bool) {
	var v int64
	if up {
		v = 1
	}
	metricMCPTransportUp.Set(v)
}

// Config holds web server configuration.
type Config struct {
	// AllowedOrigins is the list of origins permitted for CORS.
	// Empty = no CORS headers (same-origin only, recommended default).
	AllowedOrigins []string

	// Token is the shared secret required in Authorization: Bearer <token>
	// or ?token=<token> on all non-health routes. Empty = no auth.
	Token string
}

//go:embed dashboard.html
var dashboardHTML []byte

// ipLimiters holds per-IP token-bucket rate limiters.
type ipLimiters struct {
	mu sync.Mutex
	m  map[string]*rate.Limiter
}

func (l *ipLimiters) get(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lim, ok := l.m[ip]; ok {
		return lim
	}
	// 60 requests per minute with a burst of 20.
	lim := rate.NewLimiter(rate.Every(time.Minute/60), 20)
	l.m[ip] = lim
	return lim
}

// Server serves the Vigilo web dashboard.
type Server struct {
	store          *buffer.Store
	mux            *http.ServeMux
	cfg            Config
	broadcaster    *Broadcaster
	startTime      time.Time
	limiters       ipLimiters
	coverageMu     sync.RWMutex
	coverageStatus string
}

// New creates a Server. cfg.Token falls back to VIGILO_WEB_TOKEN env var.
func New(store *buffer.Store, cfg Config) *Server {
	if cfg.Token == "" {
		cfg.Token = os.Getenv("VIGILO_WEB_TOKEN")
	}
	s := &Server{
		store:          store,
		mux:            http.NewServeMux(),
		cfg:            cfg,
		broadcaster:    NewBroadcaster(),
		startTime:      time.Now(),
		limiters:       ipLimiters{m: make(map[string]*rate.Limiter)},
		coverageStatus: "unknown",
	}

	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/metrics", s.handleMetrics)
	s.mux.HandleFunc("/events/stream", s.authMiddleware(s.handleSSE))
	s.mux.HandleFunc("/api/events", s.authMiddleware(s.handleEvents))
	s.mux.HandleFunc("/", s.authMiddleware(s.handleDashboard))
	return s
}

// ReportCoverageIssue marks collection coverage degraded. It is conservative:
// the status is not reset automatically because a later successful event does
// not prove that missed events were recovered.
func (s *Server) ReportCoverageIssue() {
	s.coverageMu.Lock()
	s.coverageStatus = "degraded"
	s.coverageMu.Unlock()
	metricCoverageDegraded.Set(1)
}

// Broadcast publishes an event to all SSE subscribers and increments the counter.
func (s *Server) Broadcast(e collector.Event) {
	metricEventsTotal.Add(1)
	s.broadcaster.Publish(e)
}

// SetAlertCounters syncs alerter stats into expvar counters.
func (s *Server) SetAlertCounters(sent, dropped uint64) {
	metricAlertsSent.Set(int64(sent))
	metricAlertsDropped.Set(int64(dropped))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rw := &responseWriter{ResponseWriter: w, code: http.StatusOK}

	// Rate limiting before routing.
	ip := remoteIP(r)
	lim := s.limiters.get(ip)
	if !lim.Allow() {
		w.Header().Set("Retry-After", "1")
		jsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	s.mux.ServeHTTP(rw, r)
	metricWebRequests.Add(1)
	slog.Info("web request",
		"method", r.Method,
		"path", r.URL.Path,
		"status", rw.code,
		"latency_ms", time.Since(start).Milliseconds(),
		"remote_ip", ip,
	)
}

// Listen starts the HTTP server and blocks until ctx is cancelled.
func (s *Server) Listen(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:     s,
		ReadTimeout: 10 * time.Second,
		// WriteTimeout is intentionally 0 — SSE connections are long-lived.
		// Individual handlers are bounded by request context.
		IdleTimeout: 60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// --- middleware ---

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token == "" {
			next(w, r)
			return
		}
		// Both comparisons are constant time in the token's contents. Length is
		// still observable, since ConstantTimeCompare returns early when the two
		// operands differ in size.
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			if tokenMatches(strings.TrimPrefix(authHeader, "Bearer "), s.cfg.Token) {
				next(w, r)
				return
			}
		}
		// ?token= is kept for the dashboard, which is opened in a browser and
		// cannot set headers on a plain navigation. It is not offered on the MCP
		// transport, where every client can send an Authorization header.
		if tokenMatches(r.URL.Query().Get("token"), s.cfg.Token) {
			next(w, r)
			return
		}
		jsonError(w, "unauthorized", http.StatusUnauthorized)
	}
}

// --- handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	uptime := int64(time.Since(s.startTime).Seconds())
	count, _ := s.store.CountSince(time.Now().Add(-24 * time.Hour))
	s.coverageMu.RLock()
	coverage := s.coverageStatus
	s.coverageMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","coverage_status":%q,"uptime_seconds":%d,"events_buffered":%d,"mcp_transport_up":%t}`,
		coverage, uptime, count, metricMCPTransportUp.Value() == 1)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	expvar.Handler().ServeHTTP(w, r)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.setCORSHeaders(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(dashboardHTML)
}

var validSources = map[string]bool{
	"file_access": true, "process": true, "network": true, "collector_health": true,
}

var validSeverities = map[string]bool{
	"info": true, "medium": true, "high": true, "critical": true,
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	since := time.Now().Add(-time.Hour)
	if sinceStr := q.Get("since"); sinceStr != "" {
		t, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			jsonError(w, "invalid 'since' — expected RFC3339 timestamp", http.StatusBadRequest)
			return
		}
		since = t
	}

	limit := 500
	if limitStr := q.Get("limit"); limitStr != "" {
		var n int
		if _, err := fmt.Sscanf(limitStr, "%d", &n); err != nil || n < 1 || n > 1000 {
			jsonError(w, "invalid 'limit' — must be 1-1000", http.StatusBadRequest)
			return
		}
		limit = n
	}

	sevFilter := q.Get("severity")
	if sevFilter != "" && !validSeverities[sevFilter] {
		jsonError(w, "invalid 'severity' — must be info|medium|high|critical", http.StatusBadRequest)
		return
	}

	srcFilter := q.Get("source")
	if srcFilter != "" && !validSources[srcFilter] {
		jsonError(w, "invalid 'source' — must be file_access|process|network|collector_health", http.StatusBadRequest)
		return
	}

	opts := buffer.QueryOptions{
		Since:    since,
		Severity: sevFilter,
		Limit:    limit,
	}
	if srcFilter != "" {
		opts.Sources = []string{srcFilter}
	}

	events, err := s.store.List(opts)
	if err != nil {
		jsonError(w, "query failed", http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []collector.Event{}
	}

	s.setCORSHeaders(w, r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := s.broadcaster.Subscribe()
	if ch == nil {
		jsonError(w, "too many SSE clients", http.StatusServiceUnavailable)
		return
	}
	defer s.broadcaster.Unsubscribe(ch)

	s.setCORSHeaders(w, r)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

// --- helpers ---

func (s *Server) setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	if len(s.cfg.AllowedOrigins) == 0 {
		return // same-origin only
	}
	origin := r.Header.Get("Origin")
	for _, allowed := range s.cfg.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			return
		}
	}
}

func tokenMatches(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// responseWriter wraps http.ResponseWriter to capture the status code for logging.
type responseWriter struct {
	http.ResponseWriter
	code int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.code = code
	rw.ResponseWriter.WriteHeader(code)
}

// Flush delegates to the underlying writer so SSE handlers can stream events.
// Required because embedding an interface does not promote concrete-type methods.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
