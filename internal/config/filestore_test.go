package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestRedactedStripsSecrets(t *testing.T) {
	m, _ := testManager(t, "site: alpha\nauth:\n  admin_password_hash: secret\n  api_tokens: [tok1]\n")
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
