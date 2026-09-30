// Package dhcpsrv implements Emberboot's PXE-side DHCP behavior: a proxyDHCP
// responder (port 67) plus the PXE boot server (port 4011), following the
// battle-tested pixiecore dual-path design:
//
//   - BIOS clients get a full proxyDHCP OFFER on port 67 with option 43
//     (discovery control: use bootfile directly).
//   - UEFI clients get a minimal OFFER without option 43, which pushes the
//     firmware to DHCPREQUEST on port 4011, where the ACK carries
//     siaddr/bootfile — the path that works on the buggy firmware actually
//     found in the wild.
//   - Requests from an already-chainloaded iPXE (user class "iPXE") get the
//     HTTP boot-script URL instead of a bootloader, breaking the chain loop.
//
// Emberboot is never the address-assigning DHCP server (CONTEXT.md): offers carry
// no yiaddr/lease information at all.
package dhcpsrv

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"

	"emberboot/internal/alerts"
	"emberboot/internal/bootfiles"
	"emberboot/internal/config"
	"emberboot/internal/metrics"
	"emberboot/internal/rules"
	"emberboot/internal/sessions"
)

// Deps wires the responder to the rest of the daemon. Cfg is called per
// packet so config hot-reloads apply immediately.
type Deps struct {
	Log         *slog.Logger
	Cfg         func() *config.Config
	Metrics     *metrics.M
	Alerts      *alerts.Notifier
	Sessions    *sessions.Store
	AdvertiseIP net.IP
	// HTTPBase is e.g. "http://10.0.0.5:8090" — where iPXE fetches scripts.
	HTTPBase string
}

// Server owns the DHCP listeners.
type Server struct {
	d               Deps
	proxy           *server4.Server // port 67 (proxy mode only)
	pxePort         *server4.Server // port 4011 (both modes)
	rogue           *rogueMonitor
	handlerSlots    chan struct{}
	admissionMu     sync.Mutex
	windowStart     time.Time
	windowCount     int
	limitLogAfter   time.Time
	limitSuppressed uint64
	denyLogAfter    time.Time
	denySuppressed  uint64
}

const (
	maxConcurrentHandlers = 256
	maxPacketsPerSecond   = 2000
)

// New creates the listeners appropriate for the configured mode.
func New(d Deps) (*Server, error) {
	s := &Server{d: d, handlerSlots: make(chan struct{}, maxConcurrentHandlers)}
	iface := d.Cfg().Network.Interface

	if d.Cfg().Network.DHCPMode == config.ModeProxy {
		proxy, err := server4.NewServer(iface, &net.UDPAddr{IP: net.IPv4zero, Port: 67},
			s.handlerFor(67))
		if err != nil {
			return nil, fmt.Errorf("proxyDHCP listener (port 67): %w", err)
		}
		s.proxy = proxy
	}

	pxe, err := server4.NewServer(iface, &net.UDPAddr{IP: net.IPv4zero, Port: 4011},
		s.handlerFor(4011))
	if err != nil {
		return nil, fmt.Errorf("PXE listener (port 4011): %w", err)
	}
	s.pxePort = pxe

	s.rogue = newRogueMonitor(d)
	return s, nil
}

// Serve runs the listeners until Close. Errors from a closed listener are
// swallowed; anything else is returned.
func (s *Server) Serve() error {
	errc := make(chan error, 3)
	if s.proxy != nil {
		go func() { errc <- s.proxy.Serve() }()
	}
	go func() { errc <- s.pxePort.Serve() }()
	s.rogue.start()
	return <-errc
}

// RogueDetectionActive reports whether the passive udp/68 monitor is running
// (diagnostics; it is disabled when a DHCP client daemon owns the port).
func (s *Server) RogueDetectionActive() bool {
	return s.rogue != nil && s.rogue.active()
}

// Close stops all listeners.
func (s *Server) Close() {
	if s.proxy != nil {
		s.proxy.Close()
	}
	s.pxePort.Close()
	s.rogue.stop()
}

// handlerFor builds the packet handler for one listening port.
func (s *Server) handlerFor(port int) server4.Handler {
	return func(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
		select {
		case s.handlerSlots <- struct{}{}:
			defer func() { <-s.handlerSlots }()
		default:
			s.rejectOverload("concurrency")
			return
		}
		if !s.admitPacket(time.Now()) {
			s.rejectOverload("rate")
			return
		}
		if m == nil || m.OpCode != dhcpv4.OpcodeBootRequest || !isPXERequest(m) {
			s.d.Metrics.DHCPIgnored.Inc()
			return
		}
		cfg := s.d.Cfg()
		mac := m.ClientHWAddr
		fw := classifyArch(m)
		ipxe := isIPXE(m)
		ip := clientIP(m, peer)
		if ip != nil && s.d.Sessions != nil {
			s.d.Sessions.ObserveIdentity(mac.String(), ip.String())
		}

		// Deny rules and lockdown apply before any response.
		dec := rules.Evaluate(cfg, mac, ip)
		if dec.Deny {
			s.logDenied(mac.String(), dec.RuleName)
			s.d.Metrics.DHCPIgnored.Inc()
			return
		}

		var resp *dhcpv4.DHCPv4
		var err error
		switch {
		case port == 67 && m.MessageType() == dhcpv4.MessageTypeDiscover:
			s.d.Metrics.DHCPRequests.WithLabelValues("discover").Inc()
			resp, err = s.buildOffer(m, fw, ipxe)
		case port == 4011 && m.MessageType() == dhcpv4.MessageTypeRequest:
			s.d.Metrics.DHCPRequests.WithLabelValues("pxe_request").Inc()
			resp, err = s.buildAck(m, fw, ipxe)
		default:
			s.d.Metrics.DHCPIgnored.Inc()
			return
		}
		if err != nil {
			s.d.Log.Warn("dhcp response build failed", "mac", mac.String(), "error", err)
			return
		}
		if resp == nil {
			return // unsupported firmware, already logged
		}

		s.track(m, peer, fw, ipxe, port)
		if err := sendResponse(conn, peer, m, resp); err != nil {
			s.d.Log.Warn("dhcp send failed", "mac", mac.String(), "peer", peer.String(), "error", err)
		}
	}
}

func (s *Server) admitPacket(now time.Time) bool {
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	if s.windowStart.IsZero() || now.Sub(s.windowStart) >= time.Second {
		s.windowStart = now
		s.windowCount = 0
	}
	if s.windowCount >= maxPacketsPerSecond {
		return false
	}
	s.windowCount++
	return true
}

func (s *Server) rejectOverload(reason string) {
	if s.d.Metrics != nil {
		s.d.Metrics.DHCPIgnored.Inc()
	}
	if s.d.Log == nil {
		return
	}
	now := time.Now()
	s.admissionMu.Lock()
	if now.Before(s.limitLogAfter) {
		s.limitSuppressed++
		s.admissionMu.Unlock()
		return
	}
	hidden := s.limitSuppressed
	s.limitSuppressed = 0
	s.limitLogAfter = now.Add(30 * time.Second)
	s.admissionMu.Unlock()
	s.d.Log.Warn("DHCP handler capacity limit reached", "reason", reason, "suppressed_since_last", hidden)
}

func (s *Server) logDenied(mac, rule string) {
	if s.d.Log == nil {
		return
	}
	now := time.Now()
	s.admissionMu.Lock()
	if now.Before(s.denyLogAfter) {
		s.denySuppressed++
		s.admissionMu.Unlock()
		return
	}
	hidden := s.denySuppressed
	s.denySuppressed = 0
	s.denyLogAfter = now.Add(30 * time.Second)
	s.admissionMu.Unlock()
	s.d.Log.Info("boot service denied", "mac", mac, "rule", rule, "suppressed_since_last", hidden)
}

// buildOffer answers a port-67 PXE DISCOVER in proxy mode.
func (s *Server) buildOffer(m *dhcpv4.DHCPv4, fw Firmware, ipxe bool) (*dhcpv4.DHCPv4, error) {
	resp, err := dhcpv4.NewReplyFromRequest(m,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer))
	if err != nil {
		return nil, err
	}
	s.stampCommon(resp, m)

	switch {
	case ipxe:
		// Chainloaded iPXE re-DHCPs: hand it the script URL directly.
		resp.BootFileName = s.scriptURL()
		s.d.Metrics.DHCPRequests.WithLabelValues("ipxe_script").Inc()
	case isHTTPBoot(m):
		// Native UEFI HTTP Boot: filename must be a full URL and option 60
		// must echo HTTPClient or the firmware ignores the offer.
		resp.UpdateOption(dhcpv4.OptClassIdentifier("HTTPClient"))
		resp.BootFileName = s.d.HTTPBase + "/boot/" + bootfiles.FileUEFI64
	case fw == FirmwareBIOS:
		// Full proxyDHCP offer: bootfile + discovery control "direct".
		resp.BootFileName = bootfiles.FileBIOS
		resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionVendorSpecificInformation, pxeVendorOpts()))
	default:
		// UEFI: minimal offer, no option 43 — firmware follows up on 4011.
		if bootfileFor(fw) == "" {
			s.d.Log.Info("unsupported client architecture", "mac", m.ClientHWAddr.String(), "firmware", fw.String())
			return nil, nil
		}
	}
	return resp, nil
}

// buildAck answers a port-4011 PXE REQUEST (both modes).
func (s *Server) buildAck(m *dhcpv4.DHCPv4, fw Firmware, ipxe bool) (*dhcpv4.DHCPv4, error) {
	resp, err := dhcpv4.NewReplyFromRequest(m,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck))
	if err != nil {
		return nil, err
	}
	s.stampCommon(resp, m)

	switch {
	case ipxe:
		resp.BootFileName = s.scriptURL()
		s.d.Metrics.DHCPRequests.WithLabelValues("ipxe_script").Inc()
	default:
		file := bootfileFor(fw)
		if file == "" {
			s.d.Log.Info("unsupported client architecture", "mac", m.ClientHWAddr.String(), "firmware", fw.String())
			return nil, nil
		}
		resp.BootFileName = file
		resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionVendorSpecificInformation, pxeVendorOpts()))
	}
	return resp, nil
}

// stampCommon sets the fields every PXE response needs: our server IP
// (siaddr — where TFTP lives), the PXEClient vendor class, and option 66.
func (s *Server) stampCommon(resp, req *dhcpv4.DHCPv4) {
	resp.ServerIPAddr = s.d.AdvertiseIP
	resp.UpdateOption(dhcpv4.OptServerIdentifier(s.d.AdvertiseIP))
	if !isHTTPBoot(req) {
		resp.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient"))
	}
	resp.UpdateOption(dhcpv4.OptTFTPServerName(s.d.AdvertiseIP.String()))
}

func (s *Server) scriptURL() string { return s.d.HTTPBase + "/boot.ipxe" }

// track records the DHCP stage on the Client's Boot Session.
func (s *Server) track(m *dhcpv4.DHCPv4, peer net.Addr, fw Firmware, ipxe bool, port int) {
	mac := m.ClientHWAddr.String()
	ip := ""
	if v := clientIP(m, peer); v != nil {
		ip = v.String()
	}
	detail := fmt.Sprintf("PXE %s on port %d (%s)", m.MessageType(), port, fw)
	if ipxe {
		detail = "iPXE handoff to HTTP boot script"
	}
	s.d.Sessions.TouchObserved(mac, ip, "dhcp", detail)
	s.d.Sessions.SetMeta(mac, fw.String(), "", "")
}

// clientIP extracts the best-known client IP from the packet or peer addr.
func clientIP(m *dhcpv4.DHCPv4, peer net.Addr) net.IP {
	if m.ClientIPAddr != nil && !m.ClientIPAddr.IsUnspecified() {
		return m.ClientIPAddr
	}
	// The UDP source of a relayed request identifies the relay, not a Client.
	if m.GatewayIPAddr != nil && !m.GatewayIPAddr.IsUnspecified() {
		return nil
	}
	if udp, ok := peer.(*net.UDPAddr); ok && udp.IP != nil && !udp.IP.IsUnspecified() {
		return udp.IP
	}
	return nil
}

// sendResponse unicasts when the client has an address, broadcasts when it
// does not (proxyDHCP offers to clients still acquiring a lease).
func sendResponse(conn net.PacketConn, peer net.Addr, req, resp *dhcpv4.DHCPv4) error {
	dest := peer
	if req.GatewayIPAddr != nil && !req.GatewayIPAddr.IsUnspecified() {
		// RFC 2131 section 4.1: giaddr takes precedence over the broadcast bit.
		dest = &net.UDPAddr{IP: req.GatewayIPAddr, Port: 67}
	} else if udp, ok := peer.(*net.UDPAddr); ok {
		if udp.IP == nil || udp.IP.IsUnspecified() || req.IsBroadcast() {
			dest = &net.UDPAddr{IP: net.IPv4bcast, Port: udp.Port}
			if udp.Port == 0 {
				dest = &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
			}
		}
	}
	_, err := conn.WriteTo(resp.ToBytes(), dest)
	return err
}
