// Package mcp exposes the vigilo event buffer over the Model Context Protocol.
// The daemon runs as an MCP server; the vigilo-agent (TypeScript) is the client.
// Any MCP-compatible client — including Claude Desktop — can connect directly
// to investigate events interactively.
package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/voltagebots/vigilo/internal/buffer"
	"github.com/voltagebots/vigilo/internal/collector"
)

// Server wraps the MCP server and exposes query tools over the event buffer.
type Server struct {
	store    *buffer.Store
	mcpSrv   *server.MCPServer
	handlers map[string]server.ToolHandlerFunc
}

func New(store *buffer.Store) *Server {
	s := &Server{
		store:    store,
		handlers: make(map[string]server.ToolHandlerFunc),
	}
	s.mcpSrv = server.NewMCPServer("vigilo", "0.1.0",
		server.WithToolCapabilities(true),
	)
	s.registerTools()
	return s
}

// CallTool invokes a registered tool by name. Used in tests and direct callers.
func (s *Server) CallTool(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	h, ok := s.handlers[req.Params.Name]
	if !ok {
		return nil, fmt.Errorf("tool %q not found", req.Params.Name)
	}
	return h(ctx, req)
}

// ServeStdio runs the MCP server over stdin/stdout (default transport).
func (s *Server) ServeStdio(ctx context.Context) error {
	return server.ServeStdio(s.mcpSrv)
}

// AuthConfig gates the HTTP transport. An empty Token disables authentication,
// which the daemon refuses to start with unless the operator sets
// mcp_allow_unauthenticated explicitly: consent to serve the event buffer
// unauthenticated should be stated, never inferred from an omitted secret.
type AuthConfig struct {
	Token string
}

// ServeSSE runs the MCP server over SSE (HTTP transport for remote agents).
//
// The listener is constructed here instead of calling SSEServer.Start: Start
// overwrites any configured *http.Server with one whose Handler is the bare SSE
// server, so wrapping via server.WithHTTPServer would be discarded and the event
// buffer would serve unauthenticated.
func (s *Server) ServeSSE(ctx context.Context, addr string, auth AuthConfig) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.SSEHandler(auth),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// SSEHandler returns the authenticated handler ServeSSE listens with. Keeping
// construction separate from binding lets tests exercise the real handler chain
// through httptest without reserving a port, and gives the listener a single
// place where authentication is applied.
//
// No WithBaseURL: the endpoint event then advertises a relative
// "/message?sessionId=...", which the client resolves against the host it
// actually dialled. Deriving an absolute base from the listen address conflates
// two different questions -- which socket to accept on, and what address a client
// should use to reach us -- and pins clients to that exact string, so a client
// dialling localhost, a tailnet name or a mapped container port fails the SDK's
// endpoint-origin equality check after connecting.
func (s *Server) SSEHandler(auth AuthConfig) http.Handler {
	return auth.wrap(server.NewSSEServer(s.mcpSrv))
}

func (a AuthConfig) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An Origin header means the caller is a browser making a cross-origin
		// request. The pinned SSE handler sets Access-Control-Allow-Origin: *
		// unconditionally, so any such response is readable by the calling page and
		// loopback binding does not prevent that. MCP clients are not browsers and
		// never send Origin, so refusing these costs nothing.
		//
		// This does not by itself stop DNS rebinding: a rebound request is
		// same-origin, and a same-origin GET carries no Origin header at all. The
		// token is what stops that.
		if r.Header.Get("Origin") != "" {
			http.Error(w, "browser origins are not permitted", http.StatusForbidden)
			return
		}
		if a.Token != "" {
			// More than one Authorization header is ambiguous; Header.Get would
			// silently take the first and ignore the rest.
			if headers := r.Header.Values("Authorization"); len(headers) != 1 || !bearerMatches(headers[0], a.Token) {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// bearerMatches compares in constant time. The token is only ever read from the
// Authorization header; there is deliberately no ?token= query path, because a
// token in a URL reaches browser history, proxy logs and Referer headers.
func bearerMatches(header, token string) bool {
	const prefix = "Bearer "
	// RFC 7235 makes the auth scheme case-insensitive, so "bearer" is a valid
	// credential and must not be rejected. Only the scheme is folded; the token
	// itself stays byte-exact.
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header[len(prefix):]), []byte(token)) == 1
}

func (s *Server) addTool(tool mcp.Tool, h server.ToolHandlerFunc) {
	s.mcpSrv.AddTool(tool, h)
	s.handlers[tool.Name] = h
}

func (s *Server) registerTools() {
	s.addTool(mcp.NewTool("get_file_access_events",
		mcp.WithDescription("Return file access events for sensitive paths (keystores, .env, private keys) in the given time window."),
		mcp.WithString("since", mcp.Required(), mcp.Description("ISO8601 timestamp — return events after this time")),
		mcp.WithNumber("limit", mcp.Description("Max events to return (default 100)")),
		mcp.WithString("severity", mcp.Description("Minimum severity: info|medium|high|critical")),
	), s.handleFileEvents)

	s.addTool(mcp.NewTool("get_process_events",
		mcp.WithDescription("Return suspicious process spawn events (e.g. shell spawned from node, curl from python)."),
		mcp.WithString("since", mcp.Required(), mcp.Description("ISO8601 timestamp")),
		mcp.WithNumber("limit", mcp.Description("Max events to return (default 100)")),
	), s.handleProcessEvents)

	s.addTool(mcp.NewTool("get_network_events",
		mcp.WithDescription("Return outbound network connection events to unexpected or suspicious destinations."),
		mcp.WithString("since", mcp.Required(), mcp.Description("ISO8601 timestamp")),
		mcp.WithNumber("limit", mcp.Description("Max events to return (default 100)")),
		mcp.WithString("severity", mcp.Description("Minimum severity: info|medium|high|critical")),
	), s.handleNetworkEvents)

	s.addTool(mcp.NewTool("get_all_events",
		mcp.WithDescription("Return all events across all sources in the given window. Use for correlation analysis."),
		mcp.WithString("since", mcp.Required(), mcp.Description("ISO8601 timestamp")),
		mcp.WithNumber("limit", mcp.Description("Max events to return (default 200)")),
		mcp.WithString("severity", mcp.Description("Minimum severity filter")),
	), s.handleAllEvents)

	s.addTool(mcp.NewTool("get_critical_events",
		mcp.WithDescription("Return only critical and high severity events. Use for rapid triage."),
		mcp.WithString("since", mcp.Required(), mcp.Description("ISO8601 timestamp")),
	), s.handleCriticalEvents)

	s.addTool(mcp.NewTool("get_events_ecs",
		mcp.WithDescription("Return events formatted as Elastic Common Schema (ECS) JSON. Use for SIEM ingestion, Elasticsearch, or structured log pipelines."),
		mcp.WithString("since", mcp.Required(), mcp.Description("ISO8601 timestamp")),
		mcp.WithNumber("limit", mcp.Description("Max events (default 500)")),
		mcp.WithString("severity", mcp.Description("Minimum severity filter")),
	), s.handleECSEvents)
}

// parseSinceResult parses the "since" argument. Returns (time, "") on success
// or (zero, errMsg) when the string is present but invalid RFC3339.
func parseSinceResult(args map[string]any) (time.Time, string) {
	sinceStr, _ := args["since"].(string)
	if sinceStr == "" {
		return time.Now().Add(-time.Hour), ""
	}
	t, err := time.Parse(time.RFC3339, sinceStr)
	if err != nil {
		return time.Time{}, "invalid 'since' — expected RFC3339 timestamp"
	}
	return t, ""
}

// parseSince is kept for callers that don't need error propagation.
func parseSince(args map[string]any) time.Time {
	t, _ := parseSinceResult(args)
	if t.IsZero() {
		return time.Now().Add(-time.Hour)
	}
	return t
}

func parseLimit(args map[string]any, def int) int {
	if v, ok := args["limit"].(float64); ok && v > 0 {
		n := int(v)
		if n > 1000 {
			n = 1000
		}
		return n
	}
	return def
}

func parseSeverity(args map[string]any) string {
	if v, ok := args["severity"].(string); ok {
		return v
	}
	return ""
}

func errorResult(msg string) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultText(fmt.Sprintf(`{"error":%q}`, msg)), nil
}

func (s *Server) queryAndRespond(opts buffer.QueryOptions) (*mcp.CallToolResult, error) {
	events, err := s.store.List(opts)
	if err != nil {
		return errorResult(fmt.Sprintf("query error: %v", err))
	}
	if events == nil {
		events = []collector.Event{}
	}
	b, err := json.Marshal(events)
	if err != nil {
		return errorResult("serialization error")
	}
	return mcp.NewToolResultText(string(b)), nil
}

func (s *Server) handleFileEvents(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	since, errMsg := parseSinceResult(req.Params.Arguments)
	if errMsg != "" {
		return errorResult(errMsg)
	}
	return s.queryAndRespond(buffer.QueryOptions{
		Since:    since,
		Sources:  []string{string(collector.SourceFile)},
		Severity: parseSeverity(req.Params.Arguments),
		Limit:    parseLimit(req.Params.Arguments, 100),
	})
}

func (s *Server) handleProcessEvents(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	since, errMsg := parseSinceResult(req.Params.Arguments)
	if errMsg != "" {
		return errorResult(errMsg)
	}
	return s.queryAndRespond(buffer.QueryOptions{
		Since:   since,
		Sources: []string{string(collector.SourceProcess)},
		Limit:   parseLimit(req.Params.Arguments, 100),
	})
}

func (s *Server) handleNetworkEvents(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	since, errMsg := parseSinceResult(req.Params.Arguments)
	if errMsg != "" {
		return errorResult(errMsg)
	}
	return s.queryAndRespond(buffer.QueryOptions{
		Since:    since,
		Sources:  []string{string(collector.SourceNetwork)},
		Severity: parseSeverity(req.Params.Arguments),
		Limit:    parseLimit(req.Params.Arguments, 100),
	})
}

func (s *Server) handleAllEvents(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	since, errMsg := parseSinceResult(req.Params.Arguments)
	if errMsg != "" {
		return errorResult(errMsg)
	}
	return s.queryAndRespond(buffer.QueryOptions{
		Since:    since,
		Severity: parseSeverity(req.Params.Arguments),
		Limit:    parseLimit(req.Params.Arguments, 200),
	})
}

func (s *Server) handleCriticalEvents(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	since, errMsg := parseSinceResult(req.Params.Arguments)
	if errMsg != "" {
		return errorResult(errMsg)
	}
	return s.queryAndRespond(buffer.QueryOptions{
		Since:    since,
		Severity: "high",
		Limit:    50,
	})
}

// ecsEvent is a minimal Elastic Common Schema representation of a vigilo event.
type ecsEvent struct {
	Timestamp string            `json:"@timestamp"`
	Event     ecsEventFields    `json:"event"`
	File      *ecsFile          `json:"file,omitempty"`
	Process   *ecsProcess       `json:"process,omitempty"`
	Network   *ecsNetwork       `json:"network,omitempty"`
	User      *ecsUser          `json:"user,omitempty"`
	Labels    map[string]string `json:"labels"`
}
type ecsEventFields struct {
	Kind     string   `json:"kind"`
	Category []string `json:"category"`
	Action   string   `json:"action"`
	Severity string   `json:"severity"`
}
type ecsFile struct {
	Path string `json:"path"`
}
type ecsProcess struct {
	Name string `json:"name,omitempty"`
	PID  int    `json:"pid,omitempty"`
	PPID int    `json:"parent,omitempty"`
	Args string `json:"command_line,omitempty"`
}
type ecsNetwork struct {
	DestinationIP string `json:"destination_ip"`
}
type ecsUser struct {
	ID string `json:"id,omitempty"`
}

func (s *Server) handleECSEvents(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	since, errMsg := parseSinceResult(req.Params.Arguments)
	if errMsg != "" {
		return errorResult(errMsg)
	}
	events, err := s.store.List(buffer.QueryOptions{
		Since:    since,
		Severity: parseSeverity(req.Params.Arguments),
		Limit:    parseLimit(req.Params.Arguments, 500),
	})
	if err != nil {
		return errorResult(fmt.Sprintf("query error: %v", err))
	}

	out := make([]ecsEvent, 0, len(events))
	for _, e := range events {
		ev := ecsEvent{
			Timestamp: e.Timestamp.UTC().Format(time.RFC3339Nano),
			Event: ecsEventFields{
				Kind:     "event",
				Action:   e.Action,
				Severity: string(e.Severity),
			},
			Labels: map[string]string{
				"vigilo_source":   string(e.Source),
				"vigilo_severity": string(e.Severity),
			},
		}
		switch e.Source {
		case collector.SourceFile:
			ev.Event.Category = []string{"file"}
			ev.File = &ecsFile{Path: e.Resource}
		case collector.SourceProcess:
			ev.Event.Category = []string{"process"}
			ev.Process = &ecsProcess{
				Name: e.Process, PID: e.PID, PPID: e.PPID, Args: e.CmdLine,
			}
		case collector.SourceNetwork:
			ev.Event.Category = []string{"network"}
			ev.Network = &ecsNetwork{DestinationIP: e.Resource}
		}
		if e.User != "" {
			ev.User = &ecsUser{ID: e.User}
		}
		if e.Process != "" && ev.Process == nil {
			ev.Process = &ecsProcess{Name: e.Process, PID: e.PID}
		}
		out = append(out, ev)
	}

	b, err := json.Marshal(out)
	if err != nil {
		return errorResult("serialization error")
	}
	return mcp.NewToolResultText(string(b)), nil
}
