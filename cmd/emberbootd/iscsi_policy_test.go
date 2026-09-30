package main

import (
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"

	"emberboot/internal/config"
	"emberboot/internal/images"
	"emberboot/internal/sessions"
)

func TestISCSIBootPolicyRechecksConfigurationAndIdentity(t *testing.T) {
	s, err := sessions.Open(filepath.Join(t.TempDir(), "sessions.db"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	unknown := false
	cfg := &config.Config{Security: config.Security{AllowUnknownMACs: &unknown}, Overrides: []config.Override{{MAC: "aa:bb:cc:dd:ee:01", Menu: []string{"private.iso"}}}}
	cfg.ApplyDefaults()
	ip := net.ParseIP("10.0.0.20")
	s.ObserveIdentity("aa:bb:cc:dd:ee:01", ip.String())
	available := true
	factory := iscsiTargetPolicy(func() *config.Config { return cfg }, s, func(suffix string) (images.Image, bool) {
		return images.Image{FileName: suffix + ".iso"}, available
	})
	allow := factory(ip)
	if !allow("private") || allow("other") {
		t.Fatal("MAC menu policy not applied")
	}
	cfg.Overrides[0].Deny = true
	if allow("private") {
		t.Fatal("hot deny did not revoke connection")
	}
	cfg.Overrides[0].Deny = false
	cfg.Overrides[0].Menu = []string{"other.iso"}
	if allow("private") {
		t.Fatal("menu change did not revoke target")
	}
	cfg.Overrides[0].Menu = []string{"private.iso"}
	available = false
	if allow("private") {
		t.Fatal("unavailable target remained authorized")
	}
	available = true
	s.ObserveIdentity("aa:bb:cc:dd:ee:02", ip.String())
	if allow("private") || factory(ip)("private") {
		t.Fatal("denied replacement client inherited authorization")
	}
	s.ObserveIdentity("aa:bb:cc:dd:ee:01", ip.String())
	if allow("private") || !factory(ip)("private") {
		t.Fatal("old binding was resurrected or fresh login was denied")
	}
	if factory(nil)("private") {
		t.Fatal("nil source IP authorized")
	}
}
