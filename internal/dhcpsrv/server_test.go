package dhcpsrv

import (
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"emberboot/internal/config"
	"emberboot/internal/metrics"
	"emberboot/internal/rules"
	"emberboot/internal/sessions"
)

type capturePacketConn struct {
	net.PacketConn
	destination net.Addr
}

func (c *capturePacketConn) WriteTo(b []byte, destination net.Addr) (int, error) {
	c.destination = destination
	return len(b), nil
}

func TestDeniedClientRevokesPreviousIPIdentity(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := sessions.Open(filepath.Join(t.TempDir(), "sessions.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	unknown := false
	cfg := &config.Config{Site: "test", Security: config.Security{AllowUnknownMACs: &unknown},
		Overrides: []config.Override{{MAC: "aa:bb:cc:dd:ee:01", Menu: []string{"private.iso"}}}}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	store.Touch("aa:bb:cc:dd:ee:01", "10.0.0.20", "dhcp", "previous client")
	s := &Server{d: Deps{Log: log, Cfg: func() *config.Config { return cfg }, Metrics: metrics.New(), Sessions: store},
		handlerSlots: make(chan struct{}, maxConcurrentHandlers)}
	req, err := dhcpv4.New(dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptClassIdentifier("PXEClient")))
	if err != nil {
		t.Fatal(err)
	}
	req.ClientHWAddr, _ = net.ParseMAC("aa:bb:cc:dd:ee:02")
	req.ClientIPAddr = net.ParseIP("10.0.0.20")
	c := &capturePacketConn{}
	s.handlerFor(4011)(c, &net.UDPAddr{IP: req.ClientIPAddr, Port: 68}, req)
	if c.destination != nil {
		t.Fatal("denied client received a DHCP response")
	}
	mac, _ := net.ParseMAC(store.MACForIP("10.0.0.20"))
	if !rules.Evaluate(cfg, mac, req.ClientIPAddr).Deny {
		t.Fatal("denied client inherited the previous client's HTTP/iSCSI policy")
	}
	rows, err := store.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("identity observation created session telemetry: %d rows", len(rows))
	}
}

func TestSendResponseRoutesRelayBeforeBroadcastFlag(t *testing.T) {
	for _, broadcast := range []bool{false, true} {
		req, err := dhcpv4.New(dhcpv4.WithBroadcast(broadcast))
		if err != nil {
			t.Fatal(err)
		}
		req.GatewayIPAddr = net.ParseIP("10.20.0.1")
		resp, err := dhcpv4.NewReplyFromRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		c := &capturePacketConn{}
		if err := sendResponse(c, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 67}, req, resp); err != nil {
			t.Fatal(err)
		}
		if got := c.destination.String(); got != "10.20.0.1:67" {
			t.Errorf("broadcast=%v: destination=%s, want relay 10.20.0.1:67", broadcast, got)
		}
	}
}

func TestRelayAddressIsNeverRecordedAsClientIdentity(t *testing.T) {
	req, err := dhcpv4.New()
	if err != nil {
		t.Fatal(err)
	}
	req.GatewayIPAddr = net.ParseIP("10.20.0.1")
	peer := &net.UDPAddr{IP: req.GatewayIPAddr, Port: 67}
	if got := clientIP(req, peer); got != nil {
		t.Fatalf("relay was mistaken for client: %s", got)
	}
	req.ClientIPAddr = net.ParseIP("10.20.0.25")
	if got := clientIP(req, peer); !got.Equal(req.ClientIPAddr) {
		t.Fatalf("known client IP lost: %s", got)
	}
}
