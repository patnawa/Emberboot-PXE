// Package tftpsrv is Emberboot's deliberately dumb TFTP server (ADR-0001):
// it serves exactly the embedded iPXE bootloaders plus a generated
// autoexec.ipxe that chains stock iPXE into our HTTP boot script. Nothing is
// read from disk; nothing else is served.
package tftpsrv

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"path"
	"strings"
	"time"

	"github.com/pin/tftp/v3"

	"emberboot/internal/bootfiles"
	"emberboot/internal/metrics"
	"emberboot/internal/sessions"
)

// Deps wires the TFTP server into the daemon.
type Deps struct {
	Log      *slog.Logger
	Metrics  *metrics.M
	Sessions *sessions.Store
	// HTTPBase is where autoexec.ipxe chains to, e.g. "http://10.0.0.5:8090".
	HTTPBase string
}

// Server wraps the pin/tftp server.
type Server struct {
	d   Deps
	srv *tftp.Server
}

// New builds the server (call Serve to start).
func New(d Deps) *Server {
	s := &Server{d: d}
	s.srv = tftp.NewServer(s.readHandler, nil /* reject writes */)
	s.srv.SetTimeout(5 * time.Second)
	return s
}

// Serve listens on addr (e.g. ":69") until Shutdown.
func (s *Server) Serve(addr string) error {
	return s.srv.ListenAndServe(addr)
}

// Shutdown waits for in-flight transfers.
func (s *Server) Shutdown() { s.srv.Shutdown() }

// autoexec is fetched automatically by stock iPXE binaries after they load
// (ipxe.org/howto/chainloading) — the loop-breaker that works even in
// options66-67 mode, where we never see a second DHCP round-trip.
func (s *Server) autoexec() []byte {
	return []byte(fmt.Sprintf("#!ipxe\ndhcp\nchain %s/boot.ipxe\n", s.d.HTTPBase))
}

// readHandler serves one file. Firmware TFTP stacks send odd paths
// (backslashes, leading directories); everything is normalized to a bare
// file name before lookup.
func (s *Server) readHandler(filename string, rf io.ReaderFrom) error {
	name := path.Base(strings.ReplaceAll(filename, `\`, "/"))

	var data []byte
	switch name {
	case bootfiles.FileAutoexec:
		data = s.autoexec()
	default:
		var ok bool
		data, ok = bootfiles.Get(name)
		if !ok {
			s.d.Metrics.TFTPTransfers.WithLabelValues(name, "unknown").Inc()
			s.d.Log.Info("tftp: refused unknown file", "file", filename, "client", s.clientIP(rf))
			return fmt.Errorf("file not found: %s", name)
		}
	}

	ip := s.clientIP(rf)
	if _, err := rf.ReadFrom(bytes.NewReader(data)); err != nil {
		s.d.Metrics.TFTPTransfers.WithLabelValues(name, "error").Inc()
		s.d.Sessions.TouchByIP(ip, "tftp", fmt.Sprintf("transfer of %s failed: %v", name, err))
		s.d.Log.Warn("tftp transfer failed", "file", name, "client", ip, "error", err)
		return err
	}
	s.d.Metrics.TFTPTransfers.WithLabelValues(name, "ok").Inc()
	s.d.Sessions.TouchByIP(ip, "tftp", "served "+name)
	s.d.Log.Debug("tftp served", "file", name, "client", ip, "bytes", len(data))
	return nil
}

func (s *Server) clientIP(rf io.ReaderFrom) string {
	if ot, ok := rf.(tftp.OutgoingTransfer); ok {
		addr := ot.RemoteAddr()
		return addr.IP.String()
	}
	return ""
}
