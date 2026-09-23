package alerter

import (
	"sync"
	"testing"
	"time"

	"github.com/voltagebots/vigilo/internal/collector"
)

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
