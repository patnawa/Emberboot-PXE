// Package tftpsrv is Emberboot's deliberately dumb TFTP server (ADR-0001):
// it serves exactly the embedded iPXE bootloaders plus a generated
// autoexec.ipxe that chains stock iPXE into our HTTP boot script. Nothing is
// read from disk; nothing else is served.
package tftpsrv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path"
	"strconv"
	"strings"
	"sync"
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

	// Unknown filenames are supplied by the network. Keep them out of metric
	// labels entirely and rate-limit the corresponding log line so a scanner
	// cannot create unbounded Prometheus series or flood the service log.
	unknownLogMu      sync.Mutex
	unknownLogAfter   time.Time
	unknownSuppressed uint64
	transferMu        sync.Mutex
	activeTransfers   int
	transfersByIP     map[string]int
	limitLogAfter     time.Time
	limitSuppressed   uint64
	front             *admissionPacketConn
}

const (
	maxActiveTransfers = 256
	maxTransfersPerIP  = 8
	maxAdmissionAge    = 15 * time.Minute
)

// New builds the server (call Serve to start).
func New(d Deps) *Server {
	s := &Server{d: d, transfersByIP: make(map[string]int)}
	s.srv = tftp.NewServer(s.readHandler, nil /* reject writes */)
	s.srv.SetTimeout(5 * time.Second)
	// Single-port mode avoids allocating one UDP socket per transfer. A
	// front-door PacketConn below admits requests before the dependency creates
	// its transfer goroutine and also drops WRQ outright.
	s.srv.EnableSinglePort()
	s.srv.SetHook(s)
	return s
}

// Serve listens on addr (e.g. ":69") until Shutdown.
func (s *Server) Serve(addr string) error {
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return err
	}
	return s.serve(conn)
}

func (s *Server) serve(conn net.PacketConn) error {
	front := &admissionPacketConn{
		PacketConn: conn,
		owner:      s,
		active:     make(map[string]tftpAdmission),
	}
	s.front = front
	return s.srv.Serve(front)
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
	ip := s.clientIP(rf)

	var data []byte
	switch name {
	case bootfiles.FileAutoexec:
		data = s.autoexec()
	default:
		var ok bool
		data, ok = bootfiles.Get(name)
		if !ok {
			s.countTransfer("other", "not_found")
			s.logUnknown(s.clientIP(rf))
			// Do not reflect an attacker-controlled filename into a TFTP error.
			return errors.New("file not found")
		}
	}

	if _, err := rf.ReadFrom(bytes.NewReader(data)); err != nil {
		s.countTransfer(name, "error")
		if s.d.Sessions != nil {
			s.d.Sessions.TouchByIP(ip, "tftp", fmt.Sprintf("transfer of %s failed", name))
		}
		if s.d.Log != nil {
			s.d.Log.Warn("tftp transfer failed", "file", name, "client", ip, "error", err)
		}
		return err
	}
	s.countTransfer(name, "ok")
	if s.d.Sessions != nil {
		s.d.Sessions.TouchByIP(ip, "tftp", "served "+name)
	}
	if s.d.Log != nil {
		s.d.Log.Debug("tftp served", "file", name, "client", ip, "bytes", len(data))
	}
	return nil
}

type tftpAdmission struct {
	ip      string
	started time.Time
}

// admissionPacketConn filters the shared TFTP socket before pin/tftp creates
// per-transfer state. Only a bounded number of valid RRQs reach the library;
// WRQs and stray packets from unknown endpoints are discarded in-place.
type admissionPacketConn struct {
	net.PacketConn
	owner  *Server
	mu     sync.Mutex
	active map[string]tftpAdmission
}

func (c *admissionPacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if c.admit(buf[:n], addr, time.Now()) {
			return n, addr, nil
		}
	}
}

func (c *admissionPacketConn) admit(packet []byte, addr net.Addr, now time.Time) bool {
	udp, ok := addr.(*net.UDPAddr)
	if !ok || len(packet) < 2 {
		return false
	}
	opcode := binary.BigEndian.Uint16(packet[:2])
	if opcode == 2 { // WRQ: Emberboot is strictly read-only.
		c.owner.countTransfer("other", "write_rejected")
		return false
	}
	endpoint := udp.String()
	c.mu.Lock()
	for key, entry := range c.active {
		if now.Sub(entry.started) > maxAdmissionAge {
			delete(c.active, key)
			c.owner.releaseTransfer(entry.ip)
		}
	}
	_, active := c.active[endpoint]
	c.mu.Unlock()
	if active {
		return true // ACK/retransmission for an admitted transfer.
	}
	if opcode != 1 { // Unknown endpoint may only start with RRQ.
		return false
	}
	filename, ok := validRRQ(packet)
	if !ok {
		return false
	}
	ip := udp.IP.String()
	if !c.owner.acquireTransfer(ip) {
		c.owner.countTransfer(tftpMetricFile(filename), "busy")
		return false
	}
	c.mu.Lock()
	// A duplicate may have raced between admission and this insert.
	if _, exists := c.active[endpoint]; exists {
		c.mu.Unlock()
		c.owner.releaseTransfer(ip)
		return true
	}
	c.active[endpoint] = tftpAdmission{ip: ip, started: now}
	c.mu.Unlock()
	return true
}

func validRRQ(packet []byte) (string, bool) {
	if len(packet) < 6 || binary.BigEndian.Uint16(packet[:2]) != 1 || packet[len(packet)-1] != 0 {
		return "", false
	}
	fields := bytes.Split(packet[2:len(packet)-1], []byte{0})
	if len(fields) < 2 || len(fields)%2 != 0 || len(fields[0]) == 0 || len(fields[1]) == 0 {
		return "", false
	}
	for _, field := range fields[2:] {
		if len(field) == 0 {
			return "", false
		}
	}
	return path.Base(strings.ReplaceAll(string(fields[0]), `\`, "/")), true
}

func tftpMetricFile(name string) string {
	switch name {
	case bootfiles.FileAutoexec, bootfiles.FileBIOS, bootfiles.FileUEFI64,
		bootfiles.FileUEFI64F, bootfiles.FileUEFI32, bootfiles.FileShim,
		bootfiles.FileUEFI64SB, bootfiles.FileWimboot:
		return name
	default:
		return "other"
	}
}

func (c *admissionPacketConn) release(stats tftp.TransferStats) {
	if stats.RemoteAddr == nil || stats.Tid == 0 {
		return
	}
	endpoint := net.JoinHostPort(stats.RemoteAddr.String(), strconv.Itoa(stats.Tid))
	c.mu.Lock()
	entry, ok := c.active[endpoint]
	if ok {
		delete(c.active, endpoint)
	}
	c.mu.Unlock()
	if ok {
		c.owner.releaseTransfer(entry.ip)
	}
}

// OnSuccess and OnFailure implement tftp.Hook and release the admission slot
// at the protocol's actual terminal event.
func (s *Server) OnSuccess(stats tftp.TransferStats) {
	if s.front != nil {
		s.front.release(stats)
	}
}

func (s *Server) OnFailure(stats tftp.TransferStats, _ error) {
	if s.front != nil {
		s.front.release(stats)
	}
}

func (s *Server) acquireTransfer(ip string) bool {
	if ip == "" {
		ip = "unknown"
	}
	s.transferMu.Lock()
	if s.activeTransfers >= maxActiveTransfers || s.transfersByIP[ip] >= maxTransfersPerIP {
		now := time.Now()
		if now.Before(s.limitLogAfter) {
			s.limitSuppressed++
			s.transferMu.Unlock()
			return false
		}
		hidden := s.limitSuppressed
		s.limitSuppressed = 0
		s.limitLogAfter = now.Add(30 * time.Second)
		s.transferMu.Unlock()
		if s.d.Log != nil {
			s.d.Log.Warn("TFTP transfer capacity limit reached", "suppressed_since_last", hidden)
		}
		return false
	}
	s.activeTransfers++
	s.transfersByIP[ip]++
	s.transferMu.Unlock()
	return true
}

func (s *Server) releaseTransfer(ip string) {
	if ip == "" {
		ip = "unknown"
	}
	s.transferMu.Lock()
	s.activeTransfers--
	s.transfersByIP[ip]--
	if s.transfersByIP[ip] == 0 {
		delete(s.transfersByIP, ip)
	}
	s.transferMu.Unlock()
}

func (s *Server) countTransfer(file, result string) {
	if s.d.Metrics != nil {
		s.d.Metrics.TFTPTransfers.WithLabelValues(file, result).Inc()
	}
}

func (s *Server) logUnknown(client string) {
	if s.d.Log == nil {
		return
	}
	now := time.Now()
	s.unknownLogMu.Lock()
	if now.Before(s.unknownLogAfter) {
		s.unknownSuppressed++
		s.unknownLogMu.Unlock()
		return
	}
	suppressed := s.unknownSuppressed
	s.unknownSuppressed = 0
	s.unknownLogAfter = now.Add(30 * time.Second)
	s.unknownLogMu.Unlock()
	s.d.Log.Info("tftp: refused unknown file", "client", client, "suppressed_since_last", suppressed)
}

func (s *Server) clientIP(rf io.ReaderFrom) string {
	if ot, ok := rf.(tftp.OutgoingTransfer); ok {
		addr := ot.RemoteAddr()
		return addr.IP.String()
	}
	return ""
}
