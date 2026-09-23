// Package buffer persists collector events in a local SQLite database.
// Events are auto-purged after buffer_retention_hours (default 24h).
// The Store is the primary data source for the MCP server's query tools.
package buffer

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/voltagebots/vigilo/internal/collector"
	_ "modernc.org/sqlite"
)

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS events (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	source    TEXT    NOT NULL,
	timestamp TEXT    NOT NULL,
	pid       INTEGER,
	ppid      INTEGER,
	process   TEXT,
	executable TEXT,
	cmd_line  TEXT,
	user_id   TEXT,
	action    TEXT    NOT NULL,
	resource  TEXT    NOT NULL,
	detail    TEXT,
	severity  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source    ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);

CREATE TABLE IF NOT EXISTS signal_dedup (
	hash       TEXT PRIMARY KEY,
	first_seen TEXT NOT NULL,
	last_seen  TEXT NOT NULL,
	count      INTEGER NOT NULL DEFAULT 1
);
`

// Store persists events in SQLite and serves queries from the MCP server.
type Store struct {
	db             *sql.DB
	retentionHours int
}

func Open(path string, retentionHours int) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// SQLite is single-writer: one connection is both sufficient and correct.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := ensureColumn(db, "events", "executable"); err != nil {
		return nil, fmt.Errorf("migrate executable column: %w", err)
	}
	s := &Store{db: db, retentionHours: retentionHours}
	go s.pruneLoop()
	return s, nil
}

func ensureColumn(db *sql.DB, table, column string) error {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == column {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if found {
		if column == "executable" {
			_, err := db.Exec("UPDATE " + table + " SET " + column + " = '' WHERE " + column + " IS NULL")
			return err
		}
		return nil
	}
	_, err = db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " TEXT")
	if err == nil && column == "executable" {
		_, err = db.Exec("UPDATE " + table + " SET " + column + " = '' WHERE " + column + " IS NULL")
	}
	return err
}

// Close shuts down the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Insert(e collector.Event) error {
	_, err := s.db.Exec(`
		INSERT INTO events (source,timestamp,pid,ppid,process,executable,cmd_line,user_id,action,resource,detail,severity)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		string(e.Source), e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.PID, e.PPID, e.Process, e.Executable, e.CmdLine, e.User,
		e.Action, e.Resource, e.Detail, string(e.Severity),
	)
	return err
}

// QueryOptions controls filtering in List.
type QueryOptions struct {
	Since    time.Time
	Sources  []string
	Severity string // minimum severity: info|medium|high|critical
	Limit    int
}

var severityRank = map[string]int{
	"info": 0, "medium": 1, "high": 2, "critical": 3,
}

func (s *Store) List(opts QueryOptions) ([]collector.Event, error) {
	// Cap limit to prevent unbounded queries.
	if opts.Limit <= 0 || opts.Limit > 1000 {
		opts.Limit = 1000
	}

	query := `SELECT id,source,timestamp,pid,ppid,process,executable,cmd_line,user_id,action,resource,detail,severity
	          FROM events WHERE timestamp >= ?`
	args := []any{opts.Since.UTC().Format(time.RFC3339Nano)}

	if len(opts.Sources) > 0 {
		placeholders := ""
		for i, src := range opts.Sources {
			if i > 0 {
				placeholders += ","
			}
			placeholders += "?"
			args = append(args, src)
		}
		query += " AND source IN (" + placeholders + ")"
	}

	if opts.Severity != "" {
		rank := severityRank[opts.Severity]
		query += " AND ("
		first := true
		for sev, r := range severityRank {
			if r >= rank {
				if !first {
					query += " OR "
				}
				query += "severity=?"
				args = append(args, sev)
				first = false
			}
		}
		query += ")"
	}

	query += " ORDER BY timestamp DESC"
	query += fmt.Sprintf(" LIMIT %d", opts.Limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []collector.Event
	for rows.Next() {
		var e collector.Event
		var tsStr, source, severity string
		var pid, ppid sql.NullInt64
		var process, executable, cmdLine, userID, detail sql.NullString
		if err := rows.Scan(
			&e.ID, &source, &tsStr,
			&pid, &ppid, &process, &executable, &cmdLine, &userID,
			&e.Action, &e.Resource, &detail, &severity,
		); err != nil {
			return nil, err
		}
		if pid.Valid {
			e.PID = int(pid.Int64)
		}
		if ppid.Valid {
			e.PPID = int(ppid.Int64)
		}
		e.Process, e.Executable, e.CmdLine, e.User, e.Detail = process.String, executable.String, cmdLine.String, userID.String, detail.String
		e.Source = collector.EventSource(source)
		e.Severity = collector.Severity(severity)
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)
		events = append(events, e)
	}
	return events, rows.Err()
}

// CountSince returns the number of events recorded after the given time.
func (s *Store) CountSince(since time.Time) (int64, error) {
	var count int64
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM events WHERE timestamp >= ?`,
		since.UTC().Format(time.RFC3339Nano),
	).Scan(&count)
	return count, err
}

func (s *Store) ToJSON(events []collector.Event) (string, error) {
	b, err := json.Marshal(events)
	return string(b), err
}

// IsDuplicate returns true if this signal hash was seen within the cooldown window.
// If not a duplicate, it records the signal and returns false.
func (s *Store) IsDuplicate(hash string, cooldown time.Duration) (bool, error) {
	now := time.Now().UTC()
	cutoff := now.Add(-cooldown).Format(time.RFC3339)
	nowStr := now.Format(time.RFC3339)

	var lastSeen string
	err := s.db.QueryRow(
		`SELECT last_seen FROM signal_dedup WHERE hash = ?`, hash,
	).Scan(&lastSeen)

	if err == sql.ErrNoRows {
		// First time seeing this signal — record it
		_, err = s.db.Exec(
			`INSERT INTO signal_dedup (hash, first_seen, last_seen, count) VALUES (?, ?, ?, 1)`,
			hash, nowStr, nowStr,
		)
		return false, err
	}
	if err != nil {
		return false, err
	}

	if lastSeen >= cutoff {
		// Seen recently — update count and suppress
		_, _ = s.db.Exec(
			`UPDATE signal_dedup SET last_seen = ?, count = count + 1 WHERE hash = ?`,
			nowStr, hash,
		)
		return true, nil
	}

	// Cooldown expired — reset and allow
	_, err = s.db.Exec(
		`UPDATE signal_dedup SET last_seen = ?, count = 1 WHERE hash = ?`,
		nowStr, hash,
	)
	return false, err
}

func (s *Store) pruneSignalDedup(olderThan time.Duration) {
	cutoff := time.Now().Add(-olderThan).UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`DELETE FROM signal_dedup WHERE last_seen < ?`, cutoff); err != nil {
		slog.Warn("signal_dedup prune error", "err", err)
	}
}

func (s *Store) pruneLoop() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-time.Duration(s.retentionHours) * time.Hour)
		if _, err := s.db.Exec(
			"DELETE FROM events WHERE timestamp < ?",
			cutoff.UTC().Format(time.RFC3339Nano),
		); err != nil {
			slog.Warn("events prune error", "err", err)
		}
		// Prune dedup table entries older than 7 days
		s.pruneSignalDedup(7 * 24 * time.Hour)
	}
}
