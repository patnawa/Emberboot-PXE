package sessions

import (
	"log/slog"
	"os"
	"path/filepath"
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
	if len(full.Events) != 3 { // dhcp, tftp, complete
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
	if len(results) != 1 || results[0] != ResultFailed {
		t.Errorf("hook results = %v", results)
	}
	// Finishing an unknown MAC must be a no-op, not a phantom session.
	s.Finish("de:ad:be:ef:00:00", ResultCompleted, "")
	if len(results) != 1 {
		t.Errorf("finish of unknown mac fired hook: %v", results)
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
