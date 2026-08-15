package dhcpsrv

import (
	"net"
	"strings"
	"sync"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"emberboot/internal/alerts"
)

// rogueMonitor passively listens for DHCP server responses on the wire and
// alerts when a PXE-shaped OFFER/ACK comes from a server that is not us —
// the forgotten-WDS-server failure mode. Best effort: on hosts where UDP 68
// is taken (a DHCP client daemon), monitoring is disabled with a warning,
// never an error.
type rogueMonitor struct {
	d  Deps
	mu sync.RWMutex
	// conn is protected because diagnostics and shutdown can run while the
	// Serve goroutine is still starting the best-effort monitor.
	conn net.PacketConn
}

func newRogueMonitor(d Deps) *rogueMonitor {
	return &rogueMonitor{d: d}
}

func (r *rogueMonitor) start() {
	conn, err := net.ListenPacket("udp4", ":68")
	if err != nil {
		r.d.Log.Warn("rogue PXE detection disabled: cannot listen on udp/68 "+
			"(a DHCP client is probably running on this host)", "error", err)
		return
	}
	r.mu.Lock()
	r.conn = conn
	r.mu.Unlock()
	go r.loop(conn)
	r.d.Log.Info("rogue PXE detection active on udp/68")
}

func (r *rogueMonitor) stop() {
	r.mu.Lock()
	conn := r.conn
	r.conn = nil
	r.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (r *rogueMonitor) active() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conn != nil
}

func (r *rogueMonitor) loop(conn net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			return // closed
		}
		m, err := dhcpv4.FromBytes(buf[:n])
		if err != nil || m.OpCode != dhcpv4.OpcodeBootReply {
			continue
		}
		if !r.looksPXE(m) {
			continue
		}
		srcIP := ""
		if udp, ok := src.(*net.UDPAddr); ok {
			srcIP = udp.IP.String()
		}
		serverID := m.ServerIdentifier()
		if r.isSelf(srcIP) || (serverID != nil && r.isSelf(serverID.String())) {
			continue
		}
		r.d.Metrics.RogueDetected.Inc()
		r.d.Alerts.Fire(alerts.RoguePXEServer, srcIP,
			"another PXE server is answering on this network",
			map[string]string{
				"server_ip": srcIP,
				"bootfile":  m.BootFileName,
				"client":    m.ClientHWAddr.String(),
			})
	}
}

// looksPXE: a reply is PXE-shaped if it advertises a bootfile or carries the
// PXEClient vendor class / PXE vendor options.
func (r *rogueMonitor) looksPXE(m *dhcpv4.DHCPv4) bool {
	if strings.HasPrefix(m.ClassIdentifier(), "PXEClient") {
		return true
	}
	if m.BootFileName != "" {
		return true
	}
	return m.Options.Get(dhcpv4.OptionVendorSpecificInformation) != nil
}

func (r *rogueMonitor) isSelf(ip string) bool {
	return ip == r.d.AdvertiseIP.String()
}
