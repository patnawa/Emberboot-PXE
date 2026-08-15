package httpsrv

import (
	"net"
	"net/http"
	"testing"
)

func TestBootConnectionAdmissionIsBounded(t *testing.T) {
	s := &BootServer{
		d:           BootDeps{RuntimeHTTPMaxStreams: 1, RuntimeHTTPMaxStreamsPerIP: 1},
		connections: make(map[net.Conn]string),
		connsByIP:   make(map[string]int),
	}
	first, firstPeer := net.Pipe()
	defer firstPeer.Close()
	second, secondPeer := net.Pipe()
	defer secondPeer.Close()

	s.connectionState(first, http.StateNew)
	s.connectionState(second, http.StateNew)
	s.connMu.Lock()
	got := len(s.connections)
	s.connMu.Unlock()
	if got != 1 {
		t.Fatalf("admitted connections = %d, want 1", got)
	}
	if _, err := second.Write([]byte("must be closed")); err == nil {
		t.Fatal("over-limit connection remained open")
	}
	s.connectionState(first, http.StateClosed)
	_ = first.Close()
}
