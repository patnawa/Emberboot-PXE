package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimalYAML = `
site: test-site
`

func TestParseMinimalAppliesDefaults(t *testing.T) {
	c, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Network.DHCPMode != ModeProxy {
		t.Errorf("default dhcp_mode = %q, want %q", c.Network.DHCPMode, ModeProxy)
	}
	if c.Network.TFTPPort != 69 || c.Network.HTTPPort != 8090 {
		t.Errorf("default ports = %d/%d", c.Network.TFTPPort, c.Network.HTTPPort)
	}
	if c.Sessions.RetentionDays != 90 {
		t.Errorf("default retention = %d, want 90", c.Sessions.RetentionDays)
	}
	if !c.Security.AllowUnknown() {
		t.Error("unknown MACs should be allowed by default")
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte("site: x\nsubnett: oops\n"))
	if err == nil {
		t.Fatal("unknown field should be rejected")
	}
}

func TestParseReportsAllErrors(t *testing.T) {
	bad := `
site: ""
network:
  dhcp_mode: banana
  tftp_port: 99999
overrides:
  - name: broken
`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	for _, want := range []string{"site:", "dhcp_mode", "tftp_port", "broken"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should mention %q; got:\n%s", want, msg)
		}
	}
}

func TestOverrideValidation(t *testing.T) {
	good := `
site: s
overrides:
  - name: lab
    subnet: 10.1.2.0/24
    menu: [clonezilla.iso]
  - mac: "aa:bb:cc:*"
    deny: true
`
	if _, err := Parse([]byte(good)); err != nil {
		t.Fatalf("valid overrides rejected: %v", err)
	}
	bad := `
site: s
overrides:
  - mac: "zz:xx"
`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("bad MAC glob accepted")
	}
	conflict := `
site: s
overrides:
  - mac: "aa:*"
    deny: true
    menu: [x.iso]
`
	if _, err := Parse([]byte(conflict)); err == nil {
		t.Fatal("deny+menu should conflict")
	}
}

func TestManagerLastKnownGood(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "emberboot.yaml")
	if err := os.WriteFile(path, []byte("site: alpha\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	m, err := NewManager(path, log)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	var rejected error
	m.OnReject(func(err error) { rejected = err })

	// Break the file on disk: reload must fail but keep serving alpha.
	if err := os.WriteFile(path, []byte("site: beta\nbogus_field: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err == nil {
		t.Fatal("reload of broken config should error")
	}
	if got := m.Current().Site; got != "alpha" {
		t.Errorf("after rejected reload, site = %q, want alpha (last known good)", got)
	}
	if rejected == nil {
		t.Error("OnReject callback not fired")
	}
	if m.Status().Rejected == "" {
		t.Error("status should record the rejection")
	}

	// Fix the file: reload succeeds, rejection clears.
	if err := os.WriteFile(path, []byte("site: beta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err != nil {
		t.Fatalf("reload of fixed config: %v", err)
	}
	if got := m.Current().Site; got != "beta" {
		t.Errorf("site = %q, want beta", got)
	}
	if m.Status().Rejected != "" {
		t.Error("rejection should clear after successful reload")
	}
}
