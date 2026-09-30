package images

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func TestReplacePublishedISOWhileReadersKeepOldGeneration(t *testing.T) {
	mgr, _, gen := readyRuntimeManager(t, false)
	oldDigest, err := gen.h.validateContents(gen.info.Size(), nil)
	if err != nil {
		t.Fatal(err)
	}
	mgr.byName["runtime.iso"].SHA256 = oldDigest
	mgr.byName["runtime.iso"].fileInfo = gen.info
	if !mgr.PinVersion("runtime.iso", oldDigest, time.Now().Add(time.Hour)) {
		t.Fatal("could not pin original ISO")
	}
	raw, _, err := mgr.OpenRawVersion("runtime.iso", oldDigest)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	inside, _, _, _, err := mgr.OpenInsideVersion("runtime.iso", oldDigest, "boot/payload")
	if err != nil {
		t.Fatal(err)
	}
	defer inside.Close()
	oldBytes, err := io.ReadAll(raw)
	if err != nil {
		t.Fatal(err)
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Add(mgr.activeDir); err != nil {
		watcher.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	done := make(chan struct{})
	go func() { defer close(done); mgr.watchLoop(ctx, watcher, mgr.activeDir) }()
	t.Cleanup(func() { cancel(); <-done })
	candidate := writeRuntimeTestISO(t, mgr.activeDir, "replacement.tmp", map[string]string{"boot/payload": "replacement payload"})
	oldTime := time.Now().Add(-time.Minute)
	if err := os.Chtimes(candidate, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := replacePublishedISO(candidate, filepath.Join(mgr.activeDir, "runtime.iso")); err != nil {
		t.Fatalf("publish replacement with open readers: %v", err)
	}
	var current Image
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		var ok bool
		current, ok = mgr.Get("runtime.iso")
		if ok && current.State == StateReady && current.SHA256 != oldDigest {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("watcher did not publish replacement: %+v", current)
		case <-tick.C:
		}
	}
	got, err := io.ReadAll(inside)
	if err != nil || string(got) != "validated payload" {
		t.Fatalf("active reader changed: %q, %v", got, err)
	}
	retained, _, err := mgr.OpenRawVersion("runtime.iso", oldDigest)
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	got, err = io.ReadAll(retained)
	if err != nil || string(got) != string(oldBytes) {
		t.Fatalf("retained generation changed: %v", err)
	}
	latest, _, _, _, err := mgr.OpenInsideVersion("runtime.iso", current.SHA256, "boot/payload")
	if err != nil {
		t.Fatal(err)
	}
	defer latest.Close()
	got, err = io.ReadAll(latest)
	if err != nil || string(got) != "replacement payload" {
		t.Fatalf("new generation: %q, %v", got, err)
	}
}
