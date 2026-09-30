package iscsisrv

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func policyInitiator(t *testing.T, deps Deps) *initiator {
	t.Helper()
	deps.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	deps.Provider = &fakeProvider{content: make([]byte, 8192)}
	srv := New(deps)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeListener(ln)
	t.Cleanup(srv.Close)
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { c.Close() })
	return &initiator{t: t, c: c, cmdSN: 1}
}

func TestConnectionIdentityIsCapturedOnceButPolicyIsRechecked(t *testing.T) {
	var identity, captures atomic.Int32
	var revoked atomic.Bool
	identity.Store(1)
	in := policyInitiator(t, Deps{NewTargetPolicy: func(ip net.IP) func(string) bool {
		captures.Add(1)
		captured := identity.Load()
		return func(target string) bool { return captured == 1 && target == "test-iso" && !revoked.Load() }
	}})
	if resp := in.login("Normal", IQNPrefix+":test-iso"); resp.hdr[36] != 0 {
		t.Fatal("login failed")
	}
	identity.Store(0) // the short-lived IP lookup has now expired
	data, status, _ := in.scsi([]byte{0x12, 0, 0, 0, 36, 0}, 36)
	if status != statusGood || len(data) != 36 || captures.Load() != 1 {
		t.Fatal("read lost its bound identity")
	}
	revoked.Store(true)
	hdr := make([]byte, bhsLen)
	hdr[0], hdr[1], hdr[32] = opSCSICommand, 0xc0, 0x12
	binary.BigEndian.PutUint32(hdr[20:24], 36)
	in.send(hdr, nil)
	if resp := in.recv(); resp.opcode() != opReject {
		t.Fatalf("revoked read returned opcode %#x", resp.opcode())
	}
}

func TestConnectionPolicyFiltersDiscovery(t *testing.T) {
	in := policyInitiator(t, Deps{NewTargetPolicy: func(net.IP) func(string) bool {
		return func(string) bool { return false }
	}})
	if resp := in.login("Discovery", ""); resp.hdr[36] != 0 {
		t.Fatal("discovery login failed")
	}
	hdr := make([]byte, bhsLen)
	hdr[0], hdr[1] = opTextReq, 0x80
	in.send(hdr, encodeKeys(map[string]string{"SendTargets": "All"}))
	if resp := in.recv(); len(resp.data) != 0 {
		t.Fatalf("discovery leaked denied targets: %q", resp.data)
	}
}

func TestBoundConnectionStillHonorsSourceRevocation(t *testing.T) {
	var revoked atomic.Bool
	in := policyInitiator(t, Deps{
		AllowSourceIP:   func(net.IP) bool { return !revoked.Load() },
		NewTargetPolicy: func(net.IP) func(string) bool { return func(string) bool { return true } },
	})
	if resp := in.login("Normal", IQNPrefix+":test-iso"); resp.hdr[36] != 0 {
		t.Fatal("login failed")
	}
	revoked.Store(true)
	hdr := make([]byte, bhsLen)
	hdr[0] = opNopOut
	in.send(hdr, nil)
	if _, err := readPDU(in.c, 1<<20); err == nil {
		t.Fatal("source-revoked connection remained usable")
	}
}
