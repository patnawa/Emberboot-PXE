package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"emberboot/internal/config"
)

func TestLoadOrCreateSecretConcurrentCallersShareOneKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "boot-grant.key")
	const callers = 16
	keys := make(chan []byte, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, err := loadOrCreateSecret(path)
			if err != nil {
				errs <- err
				return
			}
			keys <- key
		}()
	}
	wg.Wait()
	close(keys)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var first []byte
	for key := range keys {
		if len(first) == 0 {
			first = key
		} else if !bytes.Equal(first, key) {
			t.Fatal("concurrent callers returned different grant keys")
		}
	}
	if len(first) != 32 {
		t.Fatalf("key length = %d, want 32", len(first))
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("key mode = %o, want 600", got)
		}
	}
}

func TestLoadOrCreateSecretRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, bytes.Repeat([]byte{'x'}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "boot-grant.key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := loadOrCreateSecret(link); err == nil {
		t.Fatal("symlink secret was accepted")
	}
}

func TestValidateRuntimePathTopology(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Site: "test"}
	cfg.ApplyDefaults()
	cfg.Images.Dir = filepath.Join(dir, "images")
	cfg.Images.AnswersDir = filepath.Join(dir, "answers")
	cfg.Sessions.DBPath = filepath.Join(dir, "state", "sessions.db")
	configPath := filepath.Join(dir, "emberboot.yaml")
	if err := config.ValidateRuntimePathTopology(configPath, cfg); err != nil {
		t.Fatalf("safe topology rejected: %v", err)
	}

	badReserved := *cfg
	badReserved.Sessions.DBPath = filepath.Join(dir, "state", ".running")
	if err := config.ValidateRuntimePathTopology(configPath, &badReserved); err == nil {
		t.Fatal("reserved crash-marker DB path accepted")
	}

	badSharedDir := *cfg
	badSharedDir.Images.AnswersDir = badSharedDir.Images.Dir
	if err := config.ValidateRuntimePathTopology(configPath, &badSharedDir); err == nil {
		t.Fatal("shared images/answers directory accepted")
	}

	badManagedConfig := *cfg
	badManagedConfig.Images.AnswersDir = filepath.Dir(configPath)
	if err := config.ValidateRuntimePathTopology(configPath, &badManagedConfig); err == nil {
		t.Fatal("config inside answer-management directory accepted")
	}
}
