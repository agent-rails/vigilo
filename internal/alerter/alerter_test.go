package alerter

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/voltagebots/vigilo/internal/collector"
)

type blockingAlertChannel struct {
	started chan struct{}
	release chan struct{}
}

func (c *blockingAlertChannel) name() string { return "blocking" }
func (c *blockingAlertChannel) send(collector.Event, string) error {
	select {
	case c.started <- struct{}{}:
	default:
	}
	<-c.release
	return nil
}

func TestDeliveryQueueBoundsSlowChannelBacklog(t *testing.T) {
	d := New(Config{MinSeverity: "high"})
	blocking := &blockingAlertChannel{started: make(chan struct{}, 1), release: make(chan struct{})}
	d.channels = []channel{blocking}
	queue := NewDeliveryQueue(d, 1, 1)
	if !queue.Submit(fileEvent("write", "/tmp/one"), nil) {
		t.Fatal("first event should be accepted")
	}
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start delivery")
	}
	if !queue.Submit(fileEvent("write", "/tmp/two"), nil) {
		t.Fatal("second event should occupy the one-slot queue")
	}
	if queue.Submit(fileEvent("write", "/tmp/three"), nil) {
		t.Fatal("event should be dropped once the bounded queue is full")
	}
	if got := d.Stats().AlertsDropped; got != 1 {
		t.Fatalf("dropped count = %d, want 1", got)
	}
	close(blocking.release)
	queue.Close()
}

func TestDeliveryQueueShutdownHasDeadline(t *testing.T) {
	d := New(Config{MinSeverity: "high"})
	blocking := &blockingAlertChannel{started: make(chan struct{}, 1), release: make(chan struct{})}
	d.channels = []channel{blocking}
	queue := NewDeliveryQueue(d, 1, 1)
	queue.Submit(fileEvent("write", "/tmp/one"), nil)
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start delivery")
	}
	if queue.closeWithin(10 * time.Millisecond) {
		t.Fatal("shutdown should report a worker that exceeded its deadline")
	}
	close(blocking.release)
	queue.workers.Wait()
}

// fakeChannel records every send() call for assertions -- avoids a real
// network call while still exercising Fire()'s real dedup/dispatch logic.
type fakeChannel struct {
	mu    sync.Mutex
	sends int
}

func (f *fakeChannel) name() string { return "fake" }
func (f *fakeChannel) send(_ collector.Event, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sends++
	return nil
}
func (f *fakeChannel) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sends
}

// failingChannel fails every send, including the in-Fire retry.
type failingChannel struct {
	mu       sync.Mutex
	attempts int
}

func (f *failingChannel) name() string { return "failing" }
func (f *failingChannel) send(_ collector.Event, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	return errors.New("channel down")
}
func (f *failingChannel) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts
}

func testEvent() collector.Event {
	return collector.Event{
		Source:   collector.SourceFile,
		Action:   "write",
		Resource: "/app/keystore/x",
		Severity: collector.SeverityCritical,
	}
}

func fileEvent(action, resource string) collector.Event {
	return collector.Event{
		Source:   collector.SourceFile,
		Action:   action,
		Resource: resource,
		Severity: collector.SeverityCritical,
	}
}

func TestProcessInventoryDoesNotSuppressLaterSecuritySignal(t *testing.T) {
	observed := collector.Event{Source: collector.SourceProcess, Action: "observed", Resource: "/tmp/worker"}
	suspicious := collector.Event{Source: collector.SourceProcess, Action: "spawn", Resource: "/tmp/worker"}
	if eventFingerprint(observed) == eventFingerprint(suspicious) {
		t.Fatal("low-severity inventory event shares dedup identity with later process security signal")
	}
}

func dedupExpiry(t *testing.T, d *Dispatcher, e collector.Event) time.Time {
	t.Helper()
	fp := eventFingerprint(e)
	d.dedupMu.Lock()
	defer d.dedupMu.Unlock()
	expiry, ok := d.dedupCache[fp]
	if !ok {
		t.Fatalf("no dedup entry for %s %s", e.Action, e.Resource)
	}
	return expiry
}

// TestZeroCooldownFiresOnEveryRepeat is a regression for a live-reproduced
// bug: New() treated Cooldown == 0 as "unset" and silently substituted 15
// minutes, so an explicit signal_cooldown: 0s in config.yaml (a real, valid
// request for "no cooldown") suppressed every repeat alert on the same
// resource for 15 minutes -- indistinguishable from never having set the
// field at all.
func TestZeroCooldownFiresOnEveryRepeat(t *testing.T) {
	d := New(Config{MinSeverity: "high", Cooldown: 0})
	fake := &fakeChannel{}
	d.channels = []channel{fake}

	d.Fire(testEvent())
	d.Fire(testEvent())
	d.Fire(testEvent())

	if got := fake.count(); got != 3 {
		t.Fatalf("with Cooldown=0, want 3 sends (no suppression), got %d", got)
	}
}

// TestNegativeCooldownUsesPackageDefault confirms the sentinel: a caller
// that wants the package default now passes a negative Duration instead of
// relying on the zero value, which is reserved for "explicitly no cooldown".
func TestNegativeCooldownUsesPackageDefault(t *testing.T) {
	d := New(Config{MinSeverity: "high", Cooldown: -1})
	fake := &fakeChannel{}
	d.channels = []channel{fake}

	d.Fire(testEvent())
	d.Fire(testEvent())

	if got := fake.count(); got != 1 {
		t.Fatalf("with Cooldown=-1 (package default 15m), want 1 send (second suppressed), got %d", got)
	}
	if d.cfg.Cooldown != 15*time.Minute {
		t.Fatalf("Cooldown = %v, want the resolved 15m default", d.cfg.Cooldown)
	}
}

func TestSourceSeverityOverrideCanAlertOnOrdinaryFileChanges(t *testing.T) {
	d := New(Config{
		MinSeverity: string(collector.SeverityHigh),
		MinSeverityBySource: map[collector.EventSource]collector.Severity{
			collector.SourceFile: collector.SeverityInfo,
		},
	})
	d.channels = []channel{&fakeChannel{}}

	if !d.ShouldAlert(collector.Event{Source: collector.SourceFile, Severity: collector.SeverityInfo}) {
		t.Fatal("info-level file event should pass the per-source override")
	}
	if d.ShouldAlert(collector.Event{Source: collector.SourceProcess, Severity: collector.SeverityInfo}) {
		t.Fatal("file override must not lower the process threshold")
	}
	if !d.ShouldAlert(collector.Event{Source: collector.SourceProcess, Severity: collector.SeverityHigh}) {
		t.Fatal("unspecified source should retain the global threshold")
	}
}

func TestFormatAlertIncludesFileChangeActorIdentity(t *testing.T) {
	message := formatAlert(collector.Event{
		Source: collector.SourceFile, Action: "write", Resource: "/home/alex/project/.env",
		Process: "node", PID: 51, PPID: 50, User: "1000", Executable: "/usr/bin/node",
		Severity: collector.SeverityMedium, Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	for _, expected := range []string{"node (pid 51, parent pid 50)", "executable=/usr/bin/node", "uid=1000"} {
		if !strings.Contains(message, expected) {
			t.Errorf("formatted alert missing %q:\n%s", expected, message)
		}
	}
}

// TestRenameAfterWriteAlertsWithinCooldown is the regression for #31: a
// routine write to a watched key burned the fingerprint, and the rename of
// that same path -- a key leaving the watched tree, the signal #27 added --
// was suppressed for the rest of the cooldown. With the shipped
// signal_cooldown: 1h and writes being routine on a signing host, the one
// event worth waking someone for was the one reliably swallowed.
func TestRenameAfterWriteAlertsWithinCooldown(t *testing.T) {
	d := New(Config{MinSeverity: "high", Cooldown: time.Hour})
	fake := &fakeChannel{}
	d.channels = []channel{fake}

	d.Fire(fileEvent("write", "/app/keystore/wallet.json"))
	d.Fire(fileEvent("rename", "/app/keystore/wallet.json"))

	if got := fake.count(); got != 2 {
		t.Fatalf("want 2 sends (write, then the rename of the same path), got %d", got)
	}
}

// TestRemoveAfterWriteAlertsWithinCooldown covers the other terminal action:
// a key deleted after a routine write is the same class of signal as a key
// moved out, and was suppressed the same way.
func TestRemoveAfterWriteAlertsWithinCooldown(t *testing.T) {
	d := New(Config{MinSeverity: "high", Cooldown: time.Hour})
	fake := &fakeChannel{}
	d.channels = []channel{fake}

	d.Fire(fileEvent("write", "/app/keystore/wallet.json"))
	d.Fire(fileEvent("remove", "/app/keystore/wallet.json"))

	if got := fake.count(); got != 2 {
		t.Fatalf("want 2 sends (write, then the remove of the same path), got %d", got)
	}
}

// TestCreateThenWriteRemainOneSignal pins the collapsing that is deliberate:
// create and write on one path are one signal, and splitting the fingerprint
// on the full action string would turn every file save into two alerts.
func TestCreateThenWriteRemainOneSignal(t *testing.T) {
	d := New(Config{MinSeverity: "high", Cooldown: time.Hour})
	fake := &fakeChannel{}
	d.channels = []channel{fake}

	d.Fire(fileEvent("create", "/app/keystore/wallet.json"))
	d.Fire(fileEvent("write", "/app/keystore/wallet.json"))

	if got := fake.count(); got != 1 {
		t.Fatalf("want 1 send (create and write are one signal), got %d", got)
	}
}

// TestRenameThenRemoveRemainOneSignal: both terminal actions say the key is
// no longer at this path. Separating them would buy nothing and cost a second
// page for one departure.
func TestRenameThenRemoveRemainOneSignal(t *testing.T) {
	d := New(Config{MinSeverity: "high", Cooldown: time.Hour})
	fake := &fakeChannel{}
	d.channels = []channel{fake}

	d.Fire(fileEvent("rename", "/app/keystore/wallet.json"))
	d.Fire(fileEvent("remove", "/app/keystore/wallet.json"))

	if got := fake.count(); got != 1 {
		t.Fatalf("want 1 send (rename and remove are one terminal signal), got %d", got)
	}
}

// TestRepeatRenameSuppressedWithinCooldown confirms the cooldown still holds
// inside a class -- the fix splits terminal from mutating, it does not remove
// flood control.
func TestRepeatRenameSuppressedWithinCooldown(t *testing.T) {
	d := New(Config{MinSeverity: "high", Cooldown: time.Hour})
	fake := &fakeChannel{}
	d.channels = []channel{fake}

	d.Fire(fileEvent("rename", "/app/keystore/wallet.json"))
	d.Fire(fileEvent("rename", "/app/keystore/wallet.json"))

	if got := fake.count(); got != 1 {
		t.Fatalf("want 1 send (repeat rename suppressed), got %d", got)
	}
}

// TestFailedDeliveryDoesNotHoldFullCooldown is the second half of #31: the
// dedup entry was written before the first send, so an alert that reached
// nobody still bought an hour of silence on that signal.
func TestFailedDeliveryDoesNotHoldFullCooldown(t *testing.T) {
	d := New(Config{MinSeverity: "high", Cooldown: time.Hour})
	down := &failingChannel{}
	d.channels = []channel{down}

	e := fileEvent("rename", "/app/keystore/wallet.json")
	d.Fire(e)

	if got := down.count(); got != 2 {
		t.Fatalf("want 2 attempts (send plus the in-Fire retry) before giving up, got %d", got)
	}

	held := time.Until(dedupExpiry(t, d, e))
	if held > failureBackoff {
		t.Fatalf("failed delivery held the fingerprint for %v, want at most the %v failure backoff", held, failureBackoff)
	}
	if held <= 0 {
		t.Fatalf("failed delivery left no backoff at all (%v) -- every repeat would re-send immediately", held)
	}
}

// TestSuccessfulDeliveryHoldsFullCooldown: the backoff applies only when the
// alert reached nobody. A delivered alert still suppresses for the configured
// cooldown.
func TestSuccessfulDeliveryHoldsFullCooldown(t *testing.T) {
	d := New(Config{MinSeverity: "high", Cooldown: time.Hour})
	d.channels = []channel{&fakeChannel{}}

	e := fileEvent("rename", "/app/keystore/wallet.json")
	d.Fire(e)

	if held := time.Until(dedupExpiry(t, d, e)); held < time.Hour-time.Minute {
		t.Fatalf("delivered alert held the fingerprint for %v, want the full 1h cooldown", held)
	}
}

// TestPartialFailureHoldsFullCooldown: one channel reaching a human is enough.
// Re-alerting because a second channel was down would page whoever the working
// channel already reached.
func TestPartialFailureHoldsFullCooldown(t *testing.T) {
	d := New(Config{MinSeverity: "high", Cooldown: time.Hour})
	d.channels = []channel{&failingChannel{}, &fakeChannel{}}

	e := fileEvent("rename", "/app/keystore/wallet.json")
	d.Fire(e)

	if held := time.Until(dedupExpiry(t, d, e)); held < time.Hour-time.Minute {
		t.Fatalf("partially delivered alert held the fingerprint for %v, want the full 1h cooldown", held)
	}
}

// TestFailedDeliveryWithZeroCooldownLeavesNoEntry: zero is a real value for
// this field ("fire on every match"), so a failed delivery must not introduce
// a suppression window the operator explicitly turned off.
func TestFailedDeliveryWithZeroCooldownLeavesNoEntry(t *testing.T) {
	d := New(Config{MinSeverity: "high", Cooldown: 0})
	d.channels = []channel{&failingChannel{}}

	e := fileEvent("rename", "/app/keystore/wallet.json")
	d.Fire(e)

	d.dedupMu.Lock()
	_, ok := d.dedupCache[eventFingerprint(e)]
	d.dedupMu.Unlock()
	if ok {
		t.Fatal("zero cooldown left a dedup entry after a failed delivery")
	}
}

// TestConcurrentFireSendsOnce pins the reason the fingerprint is reserved
// before the first send rather than recorded after it: main.go dispatches
// Fire in a goroutine per event, so recording on success would let a burst of
// identical events all pass the check and all send.
func TestConcurrentFireSendsOnce(t *testing.T) {
	d := New(Config{MinSeverity: "high", Cooldown: time.Hour})
	fake := &fakeChannel{}
	d.channels = []channel{fake}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Fire(fileEvent("rename", "/app/keystore/wallet.json"))
		}()
	}
	wg.Wait()

	if got := fake.count(); got != 1 {
		t.Fatalf("want 1 send for 16 concurrent identical events, got %d", got)
	}
}
