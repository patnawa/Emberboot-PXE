package alerts

import (
	"io"
	"log/slog"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestNotifierBoundsUntrustedDedupeKeys(t *testing.T) {
	n := New(slog.New(slog.NewTextHandler(io.Discard, nil)), func() (string, string) {
		return "test", ""
	})
	for i := 0; i < maxDedupeKeys*2; i++ {
		n.Fire(RoguePXEServer, "source-"+strconv.Itoa(i), "rogue", nil)
	}
	n.mu.Lock()
	got := len(n.lastFired)
	n.mu.Unlock()
	if got > maxDedupeKeys {
		t.Fatalf("dedupe map grew to %d, cap is %d", got, maxDedupeKeys)
	}
}

func TestAcceptedHookRunsAfterDedupe(t *testing.T) {
	n := New(slog.New(slog.NewTextHandler(io.Discard, nil)), func() (string, string) {
		return "test", ""
	})
	var accepted atomic.Int64
	n.OnAccepted(func(Kind) { accepted.Add(1) })
	n.Fire(ImageInvalid, "same.iso", "invalid", nil)
	n.Fire(ImageInvalid, "same.iso", "invalid again", nil)
	if got := accepted.Load(); got != 1 {
		t.Fatalf("accepted hook called %d times, want 1", got)
	}
}

func TestEmptyDedupeKeyAcceptsEveryOccurrence(t *testing.T) {
	n := New(slog.New(slog.NewTextHandler(io.Discard, nil)), func() (string, string) {
		return "test", ""
	})
	var accepted atomic.Int64
	n.OnAccepted(func(Kind) { accepted.Add(1) })
	n.Fire(ConfigRejected, "", "first rejection", nil)
	n.Fire(ConfigRejected, "", "second rejection", nil)
	if got := accepted.Load(); got != 2 {
		t.Fatalf("accepted hook called %d times, want 2", got)
	}
	if got := len(n.History()); got != 2 {
		t.Fatalf("history contains %d alerts, want 2", got)
	}
}
