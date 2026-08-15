package tftpsrv

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pin/tftp/v3"

	"emberboot/internal/bootfiles"
	"emberboot/internal/metrics"
)

func TestUnknownFilenamesHaveBoundedMetricsAndLogs(t *testing.T) {
	var logs bytes.Buffer
	m := metrics.New()
	s := New(Deps{
		Log:     slog.New(slog.NewTextHandler(&logs, nil)),
		Metrics: m,
	})

	const attempts = 1000
	for i := 0; i < attempts; i++ {
		name := fmt.Sprintf("attacker-controlled-%d-%s", i, strings.Repeat("x", 100))
		if err := s.readHandler(name, nil); err == nil {
			t.Fatalf("unknown file %q unexpectedly succeeded", name)
		}
	}

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body,
		`emberboot_tftp_transfers_total{file="other",result="not_found"} 1000`) {
		t.Fatalf("missing bounded unknown-file counter:\n%s", body)
	}
	series := 0
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "emberboot_tftp_transfers_total{") {
			series++
		}
	}
	if series != 1 {
		t.Fatalf("unknown requests created %d TFTP metric series, want 1", series)
	}
	if strings.Contains(body, "attacker-controlled") {
		t.Fatal("attacker-controlled filename leaked into Prometheus labels")
	}
	if got := strings.Count(logs.String(), "tftp: refused unknown file"); got != 1 {
		t.Fatalf("unknown-file log lines = %d, want rate-limited single line", got)
	}
	if strings.Contains(logs.String(), "attacker-controlled") {
		t.Fatal("attacker-controlled filename leaked into logs")
	}
}

func TestTransferAdmissionIsBoundedPerClient(t *testing.T) {
	s := New(Deps{})
	for i := 0; i < maxTransfersPerIP; i++ {
		if !s.acquireTransfer("192.0.2.10") {
			t.Fatalf("transfer %d rejected below per-IP limit", i+1)
		}
	}
	if s.acquireTransfer("192.0.2.10") {
		t.Fatal("transfer above per-IP limit was accepted")
	}
	for i := 0; i < maxTransfersPerIP; i++ {
		s.releaseTransfer("192.0.2.10")
	}
	if !s.acquireTransfer("192.0.2.10") {
		t.Fatal("capacity was not released")
	}
	s.releaseTransfer("192.0.2.10")
}

func TestFrontDoorRejectsWRQAndCapsRRQBeforeTransfer(t *testing.T) {
	s := New(Deps{})
	front := &admissionPacketConn{owner: s, active: make(map[string]tftpAdmission)}
	rrq := tftpRequest(1, bootfiles.FileBIOS)
	now := time.Now()
	for i := 0; i < maxTransfersPerIP; i++ {
		addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 20000 + i}
		if !front.admit(rrq, addr, now) {
			t.Fatalf("RRQ %d rejected below per-IP cap", i+1)
		}
	}
	if front.admit(rrq, &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 30000}, now) {
		t.Fatal("RRQ above per-IP cap reached the TFTP dependency")
	}
	if front.admit(tftpRequest(2, "upload.bin"), &net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 31000}, now) {
		t.Fatal("WRQ reached the read-only TFTP dependency")
	}
	front.mu.Lock()
	active := len(front.active)
	front.mu.Unlock()
	if active != maxTransfersPerIP {
		t.Fatalf("front-door active transfers = %d, want %d", active, maxTransfersPerIP)
	}
}

func TestSinglePortFrontDoorServesRealTFTPTransfer(t *testing.T) {
	s := New(Deps{HTTPBase: "http://192.0.2.5:8090"})
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- s.serve(conn) }()
	client, err := tftp.NewClient(conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	client.SetTimeout(time.Second)
	client.SetRetries(3)
	transfer, err := client.Receive(bootfiles.FileAutoexec, "octet")
	if err != nil {
		s.Shutdown()
		t.Fatal(err)
	}
	var received bytes.Buffer
	if _, err := transfer.WriteTo(&received); err != nil {
		s.Shutdown()
		t.Fatal(err)
	}
	if !bytes.Equal(received.Bytes(), s.autoexec()) {
		t.Fatalf("TFTP payload = %q, want %q", received.Bytes(), s.autoexec())
	}
	s.Shutdown()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TFTP server did not stop")
	}
}

func tftpRequest(opcode uint16, name string) []byte {
	var packet bytes.Buffer
	var op [2]byte
	binary.BigEndian.PutUint16(op[:], opcode)
	packet.Write(op[:])
	packet.WriteString(name)
	packet.WriteByte(0)
	packet.WriteString("octet")
	packet.WriteByte(0)
	return packet.Bytes()
}
