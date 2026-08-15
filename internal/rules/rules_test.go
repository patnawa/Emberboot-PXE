package rules

import (
	"net"
	"testing"

	"emberboot/internal/config"
)

func mustCfg(t *testing.T, overrides []config.Override, allowUnknown bool) *config.Config {
	t.Helper()
	c := &config.Config{Site: "t", Overrides: overrides}
	c.Security.AllowUnknownMACs = &allowUnknown
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		t.Fatalf("test config invalid: %v", err)
	}
	return c
}

func mac(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMACGlob(t *testing.T) {
	cases := []struct {
		pattern, mac string
		want         bool
	}{
		{"aa:bb:cc:*", "aa:bb:cc:11:22:33", true},
		{"aa:bb:cc:*", "aa:bb:cd:11:22:33", false},
		{"*", "de:ad:be:ef:00:01", true},
		{"aa:?b:*", "aa:1b:00:00:00:00", true},
		{"aa:?b:*", "aa:11:00:00:00:00", false},
		{"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", true},
		{"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:fe", false},
		{"*", "", false},
	}
	for _, c := range cases {
		if got := macGlobMatch(c.pattern, c.mac); got != c.want {
			t.Errorf("macGlobMatch(%q, %q) = %v, want %v", c.pattern, c.mac, got, c.want)
		}
	}
}

func TestUnknownIdentityCannotMatchCatchAllMACRule(t *testing.T) {
	cfg := mustCfg(t, []config.Override{{Name: "known-only", MAC: "*", Menu: []string{"secret.iso"}}}, false)
	if d := Evaluate(cfg, nil, net.ParseIP("10.0.0.50")); !d.Deny {
		t.Fatalf("unknown identity matched catch-all MAC rule: %+v", d)
	}
}

func TestFirstMatchWins(t *testing.T) {
	cfg := mustCfg(t, []config.Override{
		{Name: "lab", Subnet: "10.1.2.0/24", Menu: []string{"a.iso"}},
		{Name: "deny-lab-vip", MAC: "aa:*", Deny: true},
	}, false)
	d := Evaluate(cfg, mac(t, "aa:bb:cc:00:00:01"), net.ParseIP("10.1.2.9"))
	if d.Deny || d.RuleName != "lab" {
		t.Errorf("expected first rule (lab) to win, got %+v", d)
	}
	d = Evaluate(cfg, mac(t, "aa:bb:cc:00:00:01"), net.ParseIP("10.9.9.9"))
	if !d.Deny {
		t.Errorf("expected second rule deny outside lab subnet, got %+v", d)
	}
}

func TestLockdown(t *testing.T) {
	cfg := mustCfg(t, []config.Override{
		{Name: "known", MAC: "aa:bb:cc:*"},
	}, false)
	if d := Evaluate(cfg, mac(t, "aa:bb:cc:00:00:01"), nil); d.Deny {
		t.Error("known MAC should be allowed under lockdown")
	}
	if d := Evaluate(cfg, mac(t, "de:ad:be:ef:00:01"), nil); !d.Deny {
		t.Error("unknown MAC should be denied under lockdown")
	}
}

func TestSubnetRequiresIP(t *testing.T) {
	cfg := mustCfg(t, []config.Override{
		{Name: "net", Subnet: "10.0.0.0/8", Deny: true},
	}, true)
	if d := Evaluate(cfg, mac(t, "aa:bb:cc:00:00:01"), nil); d.Deny {
		t.Error("subnet rule must not match when client IP is unknown")
	}
}
