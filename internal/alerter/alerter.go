// Package alerter provides immediate (daemon-side) push alerts for high/critical
// events — no LLM involved, fires within seconds of detection.
// The TS analyst agent handles pattern correlation on its own schedule.
package alerter

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/voltagebots/vigilo/internal/collector"
)

// SyslogConfig configures CEF syslog output (Linux only).
type SyslogConfig struct {
	Enabled bool `yaml:"enabled"`
}

// Config holds all alerter configuration loaded from the daemon config file.
type Config struct {
	// Minimum severity to trigger immediate alerts: "high" or "critical"
	MinSeverity string `yaml:"min_severity"`

	// Cooldown between repeat alerts for the same event fingerprint. Zero is
	// a real, meaningful value here (no cooldown -- fire on every match);
	// pass a negative Duration to request the package default (15m) instead.
	// A caller relying on the zero-value of an unset Config also gets the
	// default, since Go's zero Duration is 0 either way.
	Cooldown time.Duration

	Slack    *SlackConfig    `yaml:"slack"`
	Telegram *TelegramConfig `yaml:"telegram"`
	Email    *EmailConfig    `yaml:"email"`
	Webhooks []WebhookConfig `yaml:"webhooks"`
	Syslog   *SyslogConfig   `yaml:"syslog"`
}

// Stats holds counters for monitoring alerter health.
type Stats struct {
	AlertsSent    uint64
	AlertsDropped uint64
}

// Dispatcher fires all configured alert channels for a given event.
type Dispatcher struct {
	cfg      Config
	channels []channel
	client   *http.Client

	// daemon-side dedup: fingerprint → expiry
	dedupMu    sync.Mutex
	dedupCache map[string]time.Time

	// atomic counters — read with atomic.LoadUint64
	alertsSent    uint64
	alertsDropped uint64
}

type channel interface {
	name() string
	send(e collector.Event, msg string) error
}

var severityRank = map[collector.Severity]int{
	collector.SeverityInfo:     0,
	collector.SeverityMedium:   1,
	collector.SeverityHigh:     2,
	collector.SeverityCritical: 3,
}

func New(cfg Config) *Dispatcher {
	// CORRECTED (live-reproduced): treating Cooldown == 0 as "unset" made an
	// explicit signal_cooldown: 0s in config.yaml (a real, valid request for
	// "no cooldown, fire on every match") silently become 15 minutes instead
	// -- indistinguishable from a caller who never touched the field. Zero
	// is a meaningful value for this field; only a negative Duration
	// (impossible as a real cooldown) now requests the package default.
	if cfg.Cooldown < 0 {
		cfg.Cooldown = 15 * time.Minute
	}
	client := &http.Client{Timeout: 10 * time.Second}
	d := &Dispatcher{cfg: cfg, client: client, dedupCache: make(map[string]time.Time)}

	if cfg.Slack != nil && cfg.Slack.WebhookURL != "" {
		d.channels = append(d.channels, newSlackChannel(cfg.Slack, client))
	}
	if cfg.Telegram != nil && cfg.Telegram.BotToken != "" && cfg.Telegram.ChatID != "" {
		d.channels = append(d.channels, newTelegramChannel(cfg.Telegram, client))
	}
	if cfg.Email != nil && cfg.Email.SMTPHost != "" && len(cfg.Email.To) > 0 {
		d.channels = append(d.channels, newEmailChannel(cfg.Email))
	}
	for i := range cfg.Webhooks {
		d.channels = append(d.channels, newWebhookChannel(&cfg.Webhooks[i], client))
	}
	if cfg.Syslog != nil && cfg.Syslog.Enabled {
		if ch := newSyslogChannel(); ch != nil {
			d.channels = append(d.channels, ch)
		}
	}

	if len(d.channels) > 0 {
		names := make([]string, len(d.channels))
		for i, c := range d.channels {
			names[i] = c.name()
		}
		slog.Info("immediate alerter ready", "channels", strings.Join(names, ","))
	}

	// Background dedup cache pruner — every 5 minutes.
	go d.pruneDedupLoop()

	return d
}

// Stats returns a snapshot of alerter counters.
func (d *Dispatcher) Stats() Stats {
	return Stats{
		AlertsSent:    atomic.LoadUint64(&d.alertsSent),
		AlertsDropped: atomic.LoadUint64(&d.alertsDropped),
	}
}

// ShouldAlert returns true if the event severity meets the configured threshold.
func (d *Dispatcher) ShouldAlert(e collector.Event) bool {
	if len(d.channels) == 0 {
		return false
	}
	minSev := collector.Severity(d.cfg.MinSeverity)
	if minSev == "" {
		minSev = collector.SeverityHigh
	}
	return severityRank[e.Severity] >= severityRank[minSev]
}

// failureBackoff caps how long a delivery that reached nobody may suppress the
// same signal. It is deliberately short relative to any sane cooldown: an alert
// that was never delivered is not evidence that a human has been told, so it
// must not buy the silence a delivered one does. It is not zero either --
// dropping the entry outright would let a burst of identical events each open
// their own round of sends against an endpoint that is already failing.
const failureBackoff = 30 * time.Second

// Fire sends an immediate alert to all configured channels, with dedup suppression.
// On failure, a single retry is attempted after 500ms.
func (d *Dispatcher) Fire(e collector.Event) {
	fp := eventFingerprint(e)
	reserved := time.Now().Add(d.cfg.Cooldown)
	d.dedupMu.Lock()
	if expiry, seen := d.dedupCache[fp]; seen && time.Now().Before(expiry) {
		d.dedupMu.Unlock()
		slog.Debug("alert suppressed by daemon dedup",
			"resource", e.Resource, "action", e.Action, "source", e.Source)
		return
	}
	// Reserved before the first send, not recorded after the last one: main
	// dispatches Fire in a goroutine per event, so a burst of identical events
	// would otherwise all pass this check and all send. Total failure walks the
	// reservation back down to failureBackoff below.
	d.dedupCache[fp] = reserved
	d.dedupMu.Unlock()

	msg := formatAlert(e)
	allFailed := true
	for _, ch := range d.channels {
		err := ch.send(e, msg)
		if err != nil {
			slog.Warn("alert send failed, retrying", "channel", ch.name(), "err", err)
			time.Sleep(500 * time.Millisecond)
			err = ch.send(e, msg)
		}
		if err != nil {
			slog.Error("alert send failed after retry",
				"channel", ch.name(),
				"err", err,
				"event_id", e.ID,
				"source", e.Source,
				"severity", e.Severity,
			)
		} else {
			allFailed = false
		}
	}

	if len(d.channels) == 0 {
		return
	}
	if allFailed {
		d.releaseDedup(fp, reserved)
		atomic.AddUint64(&d.alertsDropped, 1)
		slog.Error("alert dropped — all channels failed",
			"event_id", e.ID,
			"source", e.Source,
			"severity", e.Severity,
			"retry_after", failureBackoff,
		)
	} else {
		atomic.AddUint64(&d.alertsSent, 1)
	}
}

// releaseDedup shortens a reservation whose alert reached no channel, so the
// next occurrence of that signal is retried within failureBackoff instead of
// the full cooldown. It never lengthens the window a successful send would
// have taken, and it leaves any reservation it does not own alone -- a later
// Fire that already took the fingerprint keeps its own expiry.
//
// This re-opens the fingerprint; it does not re-send the failed alert. Nothing
// is queued and nothing retries on a timer: the next send happens only when
// the host produces another event with the same fingerprint, so the send rate
// stays bounded by the event rate and, per fingerprint, by failureBackoff.
func (d *Dispatcher) releaseDedup(fp string, reserved time.Time) {
	backoff := d.cfg.Cooldown
	if backoff > failureBackoff {
		backoff = failureBackoff
	}

	d.dedupMu.Lock()
	defer d.dedupMu.Unlock()

	if cur, ok := d.dedupCache[fp]; !ok || !cur.Equal(reserved) {
		return
	}
	if backoff <= 0 {
		delete(d.dedupCache, fp)
		return
	}
	if expiry := time.Now().Add(backoff); expiry.Before(reserved) {
		d.dedupCache[fp] = expiry
	}
}

// pruneDedupLoop removes expired entries from dedupCache every 5 minutes.
func (d *Dispatcher) pruneDedupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		d.dedupMu.Lock()
		for k, expiry := range d.dedupCache {
			if now.After(expiry) {
				delete(d.dedupCache, k)
			}
		}
		d.dedupMu.Unlock()
	}
}

// Actions emitted by the file collector for a watched path that is no longer
// there. They are string literals in collector/file.go rather than constants;
// mirrored here so the classification below has one place to correct.
const (
	actionRemove = "remove"
	actionRename = "rename"
)

const (
	classMutate   = "mutate"
	classTerminal = "terminal"
)

// fingerprintClass groups actions that genuinely are one signal for dedup.
//
// CORRECTED (#31): the fingerprint excluded the action entirely, which was
// right while the only file actions were create and write -- a key written
// twice in an hour is one signal, and collapsing them is what keeps a busy
// path from flooding the push tier. It stopped being right when remove and
// rename arrived: those say the key left, not that it changed, and folding
// them into the same fingerprint as a write meant the shipped
// signal_cooldown: 1h suppressed the departure whenever the path had been
// written in the preceding hour. On a signing host that write is routine, so
// the move-out was the case that reliably went unsent.
//
// Classes rather than the raw action, in both directions on purpose: create
// and write stay collapsed, and remove and rename collapse into each other
// because both mean the same thing about the same path.
func fingerprintClass(action string) string {
	switch action {
	case actionRemove, actionRename:
		return classTerminal
	default:
		return classMutate
	}
}

// eventFingerprint produces a stable hash for daemon-side dedup: the source,
// the action class (see fingerprintClass) and the resource.
func eventFingerprint(e collector.Event) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s:%s:%s", e.Source, fingerprintClass(e.Action), e.Resource)
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

func formatAlert(e collector.Event) string {
	sev := strings.ToUpper(string(e.Severity))
	ts := e.Timestamp.UTC().Format(time.RFC3339)
	lines := []string{
		fmt.Sprintf("VIGILO ALERT -- %s", sev),
		fmt.Sprintf("Source:   %s", e.Source),
		fmt.Sprintf("Action:   %s", e.Action),
		fmt.Sprintf("Resource: %s", e.Resource),
		fmt.Sprintf("Time:     %s", ts),
	}
	if e.Process != "" {
		lines = append(lines, fmt.Sprintf("Process:  %s (pid %d)", e.Process, e.PID))
	}
	if e.Detail != "" {
		lines = append(lines, fmt.Sprintf("Detail:   %s", e.Detail))
	}
	return strings.Join(lines, "\n")
}
