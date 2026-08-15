package sessions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	s, err := Open(filepath.Join(t.TempDir(), "s.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func flushStore(t *testing.T, s *Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := testStore(t)
	s.Touch("AA:BB:CC:00:00:01", "10.0.0.9", "dhcp", "PXE discover")
	s.SetMeta("aa:bb:cc:00:00:01", "uefi-x64", "", "")
	s.Touch("aa:bb:cc:00:00:01", "", "tftp", "served snponly.efi")
	s.SetMeta("aa:bb:cc:00:00:01", "", "u.iso", "linux-extract")
	if s.ActiveCount() != 1 {
		t.Fatalf("active = %d, want 1", s.ActiveCount())
	}
	s.Finish("aa:bb:cc:00:00:01", ResultCompleted, "payload delivered")
	if s.ActiveCount() != 0 {
		t.Fatalf("active after finish = %d", s.ActiveCount())
	}

	recent, err := s.Recent(10)
	if err != nil || len(recent) != 1 {
		t.Fatalf("recent: %v len=%d", err, len(recent))
	}
	sess := recent[0]
	if sess.MAC != "aa:bb:cc:00:00:01" || sess.Firmware != "uefi-x64" ||
		sess.Image != "u.iso" || sess.Result != ResultCompleted {
		t.Errorf("session row wrong: %+v", sess)
	}
	full, err := s.Get(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Events) != 3 { // dhcp, tftp, handoff
		t.Errorf("events = %d, want 3: %+v", len(full.Events), full.Events)
	}
}

func TestTouchByIPJoinsKnownSession(t *testing.T) {
	s := testStore(t)
	s.Touch("aa:bb:cc:00:00:02", "10.0.0.7", "dhcp", "discover")
	s.TouchByIP("10.0.0.7", "tftp", "served undionly.kpxe")
	if s.ActiveCount() != 1 {
		t.Fatalf("TouchByIP should join the existing session, active=%d", s.ActiveCount())
	}
	s.TouchByIP("10.0.0.99", "tftp", "served undionly.kpxe")
	if s.ActiveCount() != 2 {
		t.Fatalf("unknown IP should open an ip-keyed session, active=%d", s.ActiveCount())
	}
	if got := s.MACForIP("10.0.0.7"); got != "aa:bb:cc:00:00:02" {
		t.Errorf("MACForIP = %q", got)
	}
}

func TestOnFinishHook(t *testing.T) {
	s := testStore(t)
	var results []string
	s.OnFinish(func(r string) { results = append(results, r) })
	s.Touch("aa:bb:cc:00:00:03", "", "dhcp", "x")
	s.Finish("aa:bb:cc:00:00:03", ResultFailed, "boom")
	flushStore(t, s)
	if len(results) != 1 || results[0] != ResultFailed {
		t.Errorf("hook results = %v", results)
	}
	// Finishing an unknown MAC must be a no-op, not a phantom session.
	s.Finish("de:ad:be:ef:00:00", ResultCompleted, "")
	if len(results) != 1 {
		t.Errorf("finish of unknown mac fired hook: %v", results)
	}
}

func TestInactiveSessionIsClosedWhenNewBootReplacesIt(t *testing.T) {
	s := testStore(t)
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	var results []string
	s.OnFinish(func(result string) { results = append(results, result) })
	mac := "aa:bb:cc:00:00:04"
	s.Touch(mac, "10.0.0.4", "dhcp", "first boot")
	flushStore(t, s)

	now = now.Add(sessionGap + time.Second)
	s.Touch(mac, "10.0.0.4", "dhcp", "second boot")
	flushStore(t, s)

	recent, err := s.ForMAC(mac, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 2 {
		t.Fatalf("sessions = %d, want 2: %+v", len(recent), recent)
	}
	if recent[0].Result != "" || recent[1].Result != ResultStalled {
		t.Fatalf("replacement results = newest %q old %q", recent[0].Result, recent[1].Result)
	}
	if len(results) != 1 || results[0] != ResultStalled {
		t.Fatalf("finish hook = %v, want one stalled result", results)
	}
	old, err := s.Get(recent[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := old.Events[len(old.Events)-1]; got.Stage != "fail" || got.Detail != "superseded by a new boot after inactivity" {
		t.Fatalf("replacement terminal event = %+v", got)
	}
}

func TestQueueBackpressureNeverBlocksBootPathAndReservesFinish(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var releaseOnce sync.Once
	s, err := openWithQueue(filepath.Join(t.TempDir(), "s.db"), log, 4, func() {
		once.Do(func() { close(entered) })
		<-release
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		_ = s.Close()
	})

	var dropped atomic.Uint64
	var badLabel atomic.Bool
	s.OnDrop(func(operation string) {
		if operation != operationTouch && operation != operationMeta && operation != operationFinish {
			badLabel.Store(true)
		}
		dropped.Add(1)
	})

	mac := "aa:bb:cc:00:00:05"
	s.Touch(mac, "10.0.0.5", "dhcp", "start")
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer did not enter test gate")
	}

	start := time.Now()
	for i := 0; i < 10_000; i++ {
		s.Touch(mac, "10.0.0.5", "payload", "progress")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("saturated telemetry blocked callers for %s", elapsed)
	}
	if dropped.Load() == 0 || s.DroppedCount() == 0 {
		t.Fatal("expected explicit telemetry drops under backpressure")
	}
	if badLabel.Load() {
		t.Fatal("drop hook received an unbounded operation label")
	}

	// Normal progress events stop before the channel is full, so this
	// terminal result still fits in the reserved lifecycle capacity.
	s.Finish(mac, ResultCompleted, "handoff")
	if got := s.ActiveCount(); got != 0 {
		t.Fatalf("active after reserved finish = %d", got)
	}
	releaseOnce.Do(func() { close(release) })
	flushStore(t, s)
	recent, err := s.Recent(1)
	if err != nil || len(recent) != 1 {
		t.Fatalf("recent after drain: err=%v sessions=%d", err, len(recent))
	}
	if recent[0].Result != ResultCompleted {
		t.Fatalf("terminal result was lost under progress pressure: %q", recent[0].Result)
	}
}

func TestConcurrentTouchAndFinish(t *testing.T) {
	s := testStore(t)
	mac := "aa:bb:cc:00:00:06"
	s.Touch(mac, "10.0.0.6", "dhcp", "start")

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				s.Touch(mac, "10.0.0.6", "payload", "chunk")
			}
		}()
	}
	wg.Wait()
	s.Finish(mac, ResultCompleted, "done")
	flushStore(t, s)

	if s.DroppedCount() != 0 {
		t.Fatalf("unexpected drops in normal concurrency test: %d", s.DroppedCount())
	}
	recent, err := s.Recent(2)
	if err != nil || len(recent) != 1 {
		t.Fatalf("recent: err=%v sessions=%d", err, len(recent))
	}
	full, err := s.Get(recent[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(full.Events), 502; got != want {
		t.Fatalf("events = %d, want %d", got, want)
	}
	if full.Result != ResultCompleted {
		t.Fatalf("result = %q", full.Result)
	}
}

func TestStorageFailureIsAsynchronousAndCountedAsDrop(t *testing.T) {
	s := testStore(t)
	var dropped atomic.Uint64
	s.OnDrop(func(operation string) {
		if operation == operationTouch {
			dropped.Add(1)
		}
	})
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	s.Touch("aa:bb:cc:00:00:07", "10.0.0.7", "dhcp", "start")
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("SQLite failure blocked boot-path telemetry for %s", elapsed)
	}
	flushStore(t, s)
	if dropped.Load() != 1 || s.DroppedCount() != 1 {
		t.Fatalf("storage failure drops: hook=%d total=%d, want 1", dropped.Load(), s.DroppedCount())
	}
	if got := s.ActiveCount(); got != 0 {
		t.Fatalf("failed INSERT left %d phantom active session(s)", got)
	}
}

func TestTransientCreateFailureThenQueuedFinishRecoversSession(t *testing.T) {
	release := make(chan struct{})
	var blockOnce sync.Once
	path := filepath.Join(t.TempDir(), "sessions.db")
	s, err := openWithQueue(path, slog.New(slog.NewTextHandler(io.Discard, nil)), 16, func() {
		blockOnce.Do(func() { <-release })
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	var failOnce atomic.Bool
	failOnce.Store(true)
	s.writeFailure = func(op writeOperation) error {
		if op.newSession && failOnce.CompareAndSwap(true, false) {
			return errors.New("injected transient insert failure")
		}
		return nil
	}
	id := s.Touch("aa:bb:cc:00:00:10", "10.0.0.10", "dhcp", "start")
	s.FinishID(id, ResultHandoff, "done")
	close(release)
	flushStore(t, s)
	recent, err := s.Recent(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 1 || recent[0].ID != id || recent[0].Result != ResultHandoff {
		t.Fatalf("recovered sessions = %+v", recent)
	}
}

func TestPruneIdentitiesExpiresFinishedClients(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	mac := "aa:bb:cc:00:00:09"
	ip := "10.0.0.9"
	id := s.Touch(mac, ip, "dhcp", "start")
	s.FinishID(id, ResultHandoff, "done")
	flushStore(t, s)
	if got := s.MACForIP(ip); got == "" {
		t.Fatal("fresh finished-client identity was removed too early")
	}
	now = now.Add(identityTTL + time.Second)
	s.pruneIdentities()
	if got := s.MACForIP(ip); got != "" {
		t.Fatalf("expired identity remained: %q", got)
	}
}

func TestIPOnlyTrafficDoesNotRenewDHCPIdentity(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	ip := "10.0.0.19"
	mac := "aa:bb:cc:00:00:19"
	s.Touch(mac, ip, "dhcp", "observed")
	for i := 0; i < 4; i++ {
		now = now.Add(identityTTL / 3)
		s.TouchByIP(ip, "http", "menu retry")
	}
	if got := s.MACForIP(ip); got != "" {
		t.Fatalf("IP-only traffic renewed stale DHCP identity: %q", got)
	}
}

func TestInMemorySessionAndIdentityCardinalityIsBounded(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	s.mu.Lock()
	for i := 0; i < maxActiveSessions; i++ {
		key := fmt.Sprintf("synthetic-%d", i)
		s.active[key] = int64(i + 1)
		s.lastAt[key] = now
	}
	for i := 0; i < maxIPIdentities; i++ {
		s.ipToMAC[fmt.Sprintf("192.0.2.%d", i)] = ipIdentity{MAC: "aa:bb:cc:dd:ee:ff", LastSeen: now}
	}
	s.mu.Unlock()
	if id := s.Touch("aa:bb:cc:00:00:11", "198.51.100.11", "dhcp", "flood"); id != 0 {
		t.Fatalf("new session admitted above memory cap with id %d", id)
	}
	s.mu.Lock()
	identities := len(s.ipToMAC)
	active := len(s.active)
	s.mu.Unlock()
	if identities != maxIPIdentities || active != maxActiveSessions {
		t.Fatalf("bounded maps changed size: identities=%d active=%d", identities, active)
	}
}

func TestOpenClosesSessionsInterruptedByPreviousProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.db")
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	first, err := Open(path, log)
	if err != nil {
		t.Fatal(err)
	}
	first.Touch("aa:bb:cc:00:00:08", "10.0.0.8", "dhcp", "start")
	flushStore(t, first)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := Open(path, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	recent, err := second.Recent(1)
	if err != nil || len(recent) != 1 {
		t.Fatalf("recent after reopen: err=%v sessions=%d", err, len(recent))
	}
	if recent[0].Result != ResultStalled {
		t.Fatalf("interrupted result = %q, want stalled", recent[0].Result)
	}
	full, err := second.Get(recent[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	last := full.Events[len(full.Events)-1]
	if last.Stage != "fail" || last.Detail != "service stopped or restarted before completion" {
		t.Fatalf("recovery event = %+v", last)
	}
}

func TestSpike(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 10; i++ {
		mac := "aa:bb:cc:00:01:0" + string(rune('0'+i))
		s.Touch(mac, "", "dhcp", "x")
		if i < 4 {
			s.Finish(mac, ResultFailed, "x")
		} else {
			s.Finish(mac, ResultCompleted, "x")
		}
	}
	cfg := SpikeConfig{Window: 10 * time.Minute, ThresholdPc: 20, MinSessions: 10}
	failed, total, spiking := s.checkSpike(cfg)
	if !spiking || failed != 4 || total != 10 {
		t.Errorf("spike = %v (%d/%d), want spiking 4/10", spiking, failed, total)
	}
	cfg.ThresholdPc = 50
	if _, _, spiking := s.checkSpike(cfg); spiking {
		t.Error("40% failures must not trip a 50% threshold")
	}
	cfg.ThresholdPc = 20
	cfg.MinSessions = 20
	if _, _, spiking := s.checkSpike(cfg); spiking {
		t.Error("below min_sessions must never spike")
	}
}
