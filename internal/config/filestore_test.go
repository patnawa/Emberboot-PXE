package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func testManager(t *testing.T, content string) (*Manager, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "emberboot.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(path, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return m, path
}

func TestPatchSetNestedAndReload(t *testing.T) {
	m, path := testManager(t, "site: alpha\nmenu:\n  title: Old\n")
	err := m.Patch([]PatchOp{
		{Path: []string{"menu", "title"}, Value: "New Title"},
		{Path: []string{"menu", "timeout_seconds"}, Value: 45},
		{Path: []string{"images", "attach", "u.iso", "disabled"}, Value: true},
	})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	c := m.Current()
	if c.Menu.Title != "New Title" || c.Menu.TimeoutSeconds != 45 {
		t.Errorf("patched config not live: %+v", c.Menu)
	}
	if !c.Images.Attach["u.iso"].Disabled {
		t.Error("nested attach setting not applied")
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "site: alpha") {
		t.Error("untouched keys must survive a patch")
	}
}

func TestPatchInvalidRejectedAtomically(t *testing.T) {
	m, path := testManager(t, "site: alpha\n")
	before, _ := os.ReadFile(path)
	err := m.Patch([]PatchOp{{Path: []string{"network", "tftp_port"}, Value: 99999}})
	if err == nil {
		t.Fatal("invalid port must be rejected")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("rejected patch must not modify the file")
	}
	if m.Current().Site != "alpha" {
		t.Error("running config must be unchanged after rejected patch")
	}
}

func TestPatchDeleteAndOverridesReplace(t *testing.T) {
	m, _ := testManager(t, "site: alpha\nmenu:\n  title: X\n")
	overrides := []any{
		map[string]any{"name": "lab", "subnet": "10.1.2.0/24", "menu": []any{"a.iso"}},
	}
	if err := m.Patch([]PatchOp{{Path: []string{"overrides"}, Value: overrides}}); err != nil {
		t.Fatalf("set overrides: %v", err)
	}
	if len(m.Current().Overrides) != 1 || m.Current().Overrides[0].Name != "lab" {
		t.Errorf("overrides not applied: %+v", m.Current().Overrides)
	}
	if err := m.Patch([]PatchOp{{Path: []string{"menu", "title"}, Delete: true}}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := m.Current().Menu.Title; got != "Emberboot Network Boot" {
		t.Errorf("deleted key should fall back to default, got %q", got)
	}
}

func TestSaveRawValidates(t *testing.T) {
	m, _ := testManager(t, "site: alpha\n")
	if err := m.SaveRaw([]byte("site: beta\nbogus: 1\n")); err == nil {
		t.Fatal("unknown field must be rejected")
	}
	if m.Current().Site != "alpha" {
		t.Error("rejected raw save must not apply")
	}
	if err := m.SaveRaw([]byte("site: beta\n")); err != nil {
		t.Fatalf("valid raw save: %v", err)
	}
	if m.Current().Site != "beta" {
		t.Error("valid raw save must apply immediately")
	}
}

func TestPatchRejectsUnsafeRuntimePathTopologyAtomically(t *testing.T) {
	m, path := testManager(t, "site: alpha\n")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = m.Patch([]PatchOp{{Path: []string{"images", "answers_dir"}, Value: filepath.Dir(path)}})
	if err == nil {
		t.Fatal("answers directory containing the config file was accepted")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(before) {
		t.Fatal("unsafe topology changed the config on disk")
	}
}

func TestReloadTightensExternalConfigPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	m, path := testManager(t, "site: alpha\n")
	if err := os.WriteFile(path, []byte("site: beta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("reloaded config mode = %o, want 600", got)
	}
}

func TestRedactedStripsSecrets(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := testManager(t, fmt.Sprintf("site: alpha\nauth:\n  admin_password_hash: %q\n  api_tokens: [tok1]\n", hash))
	doc, err := m.Redacted()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["auth"]; ok {
		t.Error("auth section must never reach the browser")
	}
	if doc["site"] != "alpha" {
		t.Errorf("site = %v", doc["site"])
	}
}

func TestUpdateAPITokensConcurrentAppendsAreNotLost(t *testing.T) {
	m, _ := testManager(t, "site: alpha\n")
	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			record := APITokenRecord(fmt.Sprintf("eb_concurrent_%02d_secret", i))
			errs <- m.UpdateAPITokens(func(current []string) ([]string, error) {
				return append(current, record), nil
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("UpdateAPITokens: %v", err)
		}
	}
	got := m.Current().Auth.APITokens
	if len(got) != workers {
		t.Fatalf("stored %d tokens, want %d", len(got), workers)
	}
	seen := make(map[string]bool, workers)
	for _, token := range got {
		seen[token] = true
	}
	for i := 0; i < workers; i++ {
		want := APITokenRecord(fmt.Sprintf("eb_concurrent_%02d_secret", i))
		if !seen[want] {
			t.Errorf("missing token verifier %d", i)
		}
	}
}

func TestSaveRawMigratesPlaintextAPITokensBeforePersisting(t *testing.T) {
	m, path := testManager(t, "site: alpha\n")
	token := "eb_raw_editor_plaintext_secret_value"
	if err := m.SaveRaw([]byte("site: beta\nauth:\n  api_tokens: [\"" + token + "\"]\n")); err != nil {
		t.Fatalf("SaveRaw: %v", err)
	}
	assertTokenMigrated(t, m, path, token)
}

func TestReloadMigratesExternallyEditedPlaintextAPITokens(t *testing.T) {
	m, path := testManager(t, "site: alpha\n")
	token := "eb_external_plaintext_secret_value"
	if err := os.WriteFile(path, []byte("site: beta\nauth:\n  api_tokens: [\""+token+"\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	assertTokenMigrated(t, m, path, token)
}

func assertTokenMigrated(t *testing.T, m *Manager, path, plaintext string) {
	t.Helper()
	want := APITokenRecord(plaintext)
	got := m.Current().Auth.APITokens
	if len(got) != 1 || got[0] != want {
		t.Fatalf("active token records = %q, want [%q]", got, want)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(onDisk), plaintext) {
		t.Fatal("plaintext API token persisted on disk")
	}
	if !strings.Contains(string(onDisk), want) {
		t.Fatal("one-way API token verifier was not persisted")
	}
}
