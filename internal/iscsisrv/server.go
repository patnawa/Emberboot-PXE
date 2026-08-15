package iscsisrv

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// IQNPrefix is Emberboot's target naming authority; a target's full IQN is
// IQNPrefix + ":" + a provider-defined, IQN-safe suffix.
const IQNPrefix = "iqn.2026-08.local.emberboot"

// Provider supplies backing images for targets. Implemented by the image
// manager.
type Provider interface {
	// OpenTarget resolves an IQN suffix to a read-only backing image.
	// The returned closer releases per-session resources (may be nil).
	OpenTarget(suffix string) (ra io.ReaderAt, size int64, closer func(), err error)
	// TargetSuffixes lists offerable targets for discovery.
	TargetSuffixes() []string
}

// Deps wires the target server.
type Deps struct {
	Log         *slog.Logger
	Provider    Provider
	AdvertiseIP string
	Port        int
	// AllowSourceIP is an optional network admission control. When set, a
	// connection is closed immediately after accept unless its source IP is
	// allowed. A nil callback preserves the library's allow-all behavior.
	AllowSourceIP func(net.IP) bool
	// AllowTarget enforces current per-client policy for discovery and login.
	// It is evaluated after the coarse source-network admission check.
	AllowTarget func(clientIP net.IP, targetSuffix string) bool
	// Connection limits bound descriptors and per-connection buffers. Zero
	// applies production defaults sized for at least 300 concurrent clients.
	MaxConnections      int
	MaxConnectionsPerIP int
	// OnAttach is called when an initiator reaches full feature phase
	// (session tracking hook; may be nil).
	OnAttach func(clientIP, targetSuffix string)
}

// Server is the iSCSI target listener.
type Server struct {
	d  Deps
	ln net.Listener

	mu      sync.Mutex
	tsihC   uint16
	closing bool
	conns   map[net.Conn]struct{}
	byIP    map[string]int
	connWG  sync.WaitGroup

	refusalMu          sync.Mutex
	lastRefusalLog     time.Time
	refusalsSuppressed uint64
}

// Keep enough headroom above the stated 300-client design target without
// allowing an admitted subnet to exhaust memory/file descriptors by opening
// unbounded sessions.
const (
	defaultMaxISCSIConnections      = 768
	defaultMaxISCSIConnectionsPerIP = 8
	refusalLogInterval              = 30 * time.Second
)

// New creates the server (call Serve).
func New(d Deps) *Server {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.MaxConnections <= 0 {
		d.MaxConnections = defaultMaxISCSIConnections
	}
	if d.MaxConnectionsPerIP <= 0 {
		d.MaxConnectionsPerIP = defaultMaxISCSIConnectionsPerIP
	}
	return &Server{
		d: d, conns: make(map[net.Conn]struct{}), byIP: make(map[string]int),
	}
}

// Serve listens until Close.
func (s *Server) Serve() error {
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", s.d.Port))
	if err != nil {
		return err
	}
	return s.ServeListener(ln)
}

// ServeListener runs the accept loop on a caller-provided listener (tests).
func (s *Server) ServeListener(ln net.Listener) error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		_ = ln.Close()
		return nil
	}
	s.ln = ln
	s.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if closing {
				return nil
			}
			return err
		}
		ip := sourceIP(c.RemoteAddr())
		if s.d.AllowSourceIP != nil {
			if ip == nil || !s.d.AllowSourceIP(ip) {
				s.logRefusal("source policy", c.RemoteAddr())
				c.Close()
				continue
			}
		}
		ipKey := "unknown"
		if ip != nil {
			ipKey = ip.String()
		}
		s.mu.Lock()
		reason := ""
		switch {
		case s.closing:
			reason = "server closing"
		case len(s.conns) >= s.d.MaxConnections:
			reason = "global connection limit"
		case s.byIP[ipKey] >= s.d.MaxConnectionsPerIP:
			reason = "per-IP connection limit"
		}
		if reason != "" {
			s.mu.Unlock()
			if reason != "server closing" {
				s.logRefusal(reason, c.RemoteAddr())
			}
			_ = c.Close()
			continue
		}
		s.conns[c] = struct{}{}
		s.byIP[ipKey]++
		s.connWG.Add(1)
		s.mu.Unlock()
		go func() {
			defer func() {
				s.mu.Lock()
				delete(s.conns, c)
				s.byIP[ipKey]--
				if s.byIP[ipKey] <= 0 {
					delete(s.byIP, ipKey)
				}
				s.mu.Unlock()
				s.connWG.Done()
			}()
			s.handleConn(c)
		}()
	}
}

func (s *Server) logRefusal(reason string, remote net.Addr) {
	now := time.Now()
	s.refusalMu.Lock()
	if now.Sub(s.lastRefusalLog) < refusalLogInterval {
		s.refusalsSuppressed++
		s.refusalMu.Unlock()
		return
	}
	suppressed := s.refusalsSuppressed
	s.refusalsSuppressed = 0
	s.lastRefusalLog = now
	s.refusalMu.Unlock()
	s.d.Log.Warn("iSCSI connection refused", "reason", reason,
		"remote", remote.String(), "suppressed_since_last", suppressed)
}

func sourceIP(addr net.Addr) net.IP {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// Close stops the listener and every active session, then waits for their
// backing-image handles to be released.
func (s *Server) Close() {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		s.connWG.Wait()
		return
	}
	s.closing = true
	if s.ln != nil {
		_ = s.ln.Close()
	}
	connections := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		connections = append(connections, c)
	}
	s.mu.Unlock()
	for _, c := range connections {
		_ = c.Close()
	}
	s.connWG.Wait()
}

func (s *Server) nextTSIH() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tsihC++
	if s.tsihC == 0 {
		s.tsihC = 1
	}
	return s.tsihC
}

// SanitizeSuffix maps an image file name to its IQN suffix: lowercase,
// iqn-safe charset ('-' and '.' allowed).
func SanitizeSuffix(name string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.ToLower(name), ".iso"))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// conn is one initiator connection's state.
type conn struct {
	s        *Server
	c        net.Conn
	log      *slog.Logger
	lun      *lun
	closeLUN func()

	discovery      bool
	sessionTypeSet bool
	loggedIn       bool
	target         string

	statSN   uint32
	expCmdSN uint32
	// initiator's MaxRecvDataSegmentLength: our Data-In chunk bound.
	peerMaxDSL        int
	lastAuthorization time.Time
}

const ourMaxDSL = 262144

func (s *Server) handleConn(nc net.Conn) {
	defer nc.Close()
	cn := &conn{s: s, c: nc, log: s.d.Log.With("iscsi_client", nc.RemoteAddr().String()), peerMaxDSL: 8192}
	defer func() {
		if cn.closeLUN != nil {
			cn.closeLUN()
		}
	}()
	_ = nc.SetDeadline(time.Now().Add(30 * time.Second))
	for {
		p, err := readPDU(nc, 1<<20)
		if err != nil {
			if err != io.EOF {
				cn.log.Debug("iscsi connection ended", "error", err)
			}
			return
		}
		if err := cn.dispatch(p); err != nil {
			cn.log.Debug("iscsi session error", "error", err)
			return
		}
		// Login negotiation retains the short admission deadline. Only a
		// successfully authenticated full-feature session gets the longer
		// idle window.
		if cn.loggedIn {
			_ = nc.SetDeadline(time.Now().Add(10 * time.Minute))
		} else {
			_ = nc.SetDeadline(time.Now().Add(30 * time.Second))
		}
	}
}

func (cn *conn) dispatch(p *pdu) error {
	ip := sourceIP(cn.c.RemoteAddr())
	// Recheck the source ACL on every PDU, including discovery/NOP traffic
	// before login. Otherwise a socket admitted before a hot ACL edit could
	// stay alive and log in after its subnet was revoked.
	if ip == nil || cn.s.d.AllowSourceIP != nil && !cn.s.d.AllowSourceIP(ip) {
		return fmt.Errorf("iSCSI source authorization revoked")
	}
	if cn.loggedIn && time.Since(cn.lastAuthorization) >= 2*time.Second {
		if !cn.discovery && cn.target != "" && cn.s.d.AllowTarget != nil && !cn.s.d.AllowTarget(ip, cn.target) {
			return fmt.Errorf("iSCSI session authorization revoked")
		}
		cn.lastAuthorization = time.Now()
	}
	if !p.immediate() {
		cn.expCmdSN = p.cmdSN() + 1
	}
	if !cn.loggedIn && p.opcode() != opLoginReq {
		return cn.reject(p)
	}
	switch p.opcode() {
	case opLoginReq:
		return cn.handleLogin(p)
	case opTextReq:
		return cn.handleText(p)
	case opSCSICommand:
		return cn.handleSCSI(p)
	case opNopOut:
		return cn.handleNop(p)
	case opLogoutReq:
		return cn.handleLogout(p)
	case opSCSIDataOut:
		return cn.reject(p) // read-only target never accepts initiator data
	default:
		return cn.reject(p)
	}
}

// stamp fills the sequence-number block common to most responses.
func (cn *conn) stamp(hdr []byte, withStatSN bool) {
	if withStatSN {
		binary.BigEndian.PutUint32(hdr[24:28], cn.statSN)
		cn.statSN++
	}
	binary.BigEndian.PutUint32(hdr[28:32], cn.expCmdSN)
	binary.BigEndian.PutUint32(hdr[32:36], cn.expCmdSN+15)
}

func (cn *conn) handleLogin(p *pdu) error {
	keys := parseKeys(p.data)
	csg := (p.flags() >> 2) & 0x3
	nsg := p.flags() & 0x3
	transit := p.flags()&0x80 != 0

	resp := make([]byte, bhsLen)
	resp[0] = opLoginResp
	copy(resp[8:14], p.hdr[8:14]) // ISID echo
	copy(resp[16:20], p.hdr[16:20])
	clientIP := sourceIP(cn.c.RemoteAddr())
	if cn.target != "" && cn.s.d.AllowTarget != nil && !cn.s.d.AllowTarget(clientIP, cn.target) {
		return cn.loginError(resp, 0x02, 0x03)
	}

	if v, ok := keys["MaxRecvDataSegmentLength"]; ok {
		var n int
		fmt.Sscanf(v, "%d", &n)
		if n >= 512 {
			cn.peerMaxDSL = min(n, ourMaxDSL)
		}
	}

	replyKeys := negotiate(keys)
	replyKeys["MaxRecvDataSegmentLength"] = fmt.Sprintf("%d", ourMaxDSL)
	replyKeys["TargetPortalGroupTag"] = "1"

	if st, ok := keys["SessionType"]; ok {
		if st != "Discovery" && st != "Normal" {
			return cn.loginError(resp, 0x02, 0x00)
		}
		requestedDiscovery := st == "Discovery"
		if cn.sessionTypeSet && requestedDiscovery != cn.discovery || requestedDiscovery && cn.lun != nil {
			return cn.loginError(resp, 0x02, 0x00)
		}
		cn.discovery = requestedDiscovery
		cn.sessionTypeSet = true
	}
	if !cn.discovery {
		if tn, ok := keys["TargetName"]; ok {
			suffix, found := strings.CutPrefix(tn, IQNPrefix+":")
			if !found {
				return cn.loginError(resp, 0x02, 0x03) // not found
			}
			if cn.s.d.AllowTarget != nil && !cn.s.d.AllowTarget(clientIP, suffix) {
				return cn.loginError(resp, 0x02, 0x03)
			}
			ra, size, closer, err := cn.s.d.Provider.OpenTarget(suffix)
			if err != nil {
				cn.log.Info("iscsi target not available", "target", tn, "error", err)
				return cn.loginError(resp, 0x02, 0x03)
			}
			l, err := newLUN(ra, size, suffix)
			if err != nil {
				if closer != nil {
					closer()
				}
				return cn.loginError(resp, 0x03, 0x00)
			}
			if cn.closeLUN != nil {
				cn.closeLUN()
			}
			cn.lun, cn.closeLUN, cn.target = l, closer, suffix
		}
		if cn.lun == nil && (transit && nsg == 3) {
			// Normal session must name a target before full feature phase.
			return cn.loginError(resp, 0x02, 0x07) // missing parameter
		}
	}

	// Security stage: we require nothing; answer AuthMethod=None and follow
	// the initiator's transit request.
	if csg == 0 {
		replyKeys["AuthMethod"] = "None"
	}

	flags := byte(csg << 2)
	if transit {
		attached := false
		flags = 0x80 | byte(csg<<2) | nsg
		if nsg == 3 {
			if cn.target != "" && cn.s.d.AllowTarget != nil && !cn.s.d.AllowTarget(clientIP, cn.target) {
				return cn.loginError(resp, 0x02, 0x03)
			}
			binary.BigEndian.PutUint16(resp[14:16], cn.s.nextTSIH())
			cn.loggedIn = true
			cn.lastAuthorization = time.Now()
			cn.expCmdSN = p.cmdSN() + 1
			attached = !cn.discovery && cn.s.d.OnAttach != nil
		}
		resp[1] = flags
		cn.stamp(resp, true)
		if err := writePDU(cn.c, resp, encodeKeys(replyKeys)); err != nil {
			return err
		}
		if attached {
			host, _, _ := net.SplitHostPort(cn.c.RemoteAddr().String())
			cn.s.d.OnAttach(host, cn.target)
		}
		return nil
	}
	resp[1] = flags
	cn.stamp(resp, true)
	return writePDU(cn.c, resp, encodeKeys(replyKeys))
}

func (cn *conn) loginError(resp []byte, class, detail byte) error {
	resp[1] = 0
	resp[36], resp[37] = class, detail
	cn.stamp(resp, true)
	if err := writePDU(cn.c, resp, nil); err != nil {
		return err
	}
	return fmt.Errorf("login failed %d/%d", class, detail)
}

func (cn *conn) handleText(p *pdu) error {
	keys := parseKeys(p.data)
	resp := make([]byte, bhsLen)
	resp[0] = opTextResp
	resp[1] = 0x80 // final
	copy(resp[16:20], p.hdr[16:20])
	binary.BigEndian.PutUint32(resp[20:24], 0xffffffff)
	cn.stamp(resp, true)

	if _, ok := keys["SendTargets"]; ok {
		var b strings.Builder
		for _, suffix := range cn.s.d.Provider.TargetSuffixes() {
			if cn.s.d.AllowTarget != nil && !cn.s.d.AllowTarget(sourceIP(cn.c.RemoteAddr()), suffix) {
				continue
			}
			b.WriteString("TargetName=" + IQNPrefix + ":" + suffix)
			b.WriteByte(0)
			b.WriteString(fmt.Sprintf("TargetAddress=%s:%d,1", cn.s.d.AdvertiseIP, cn.s.d.Port))
			b.WriteByte(0)
		}
		return writePDU(cn.c, resp, []byte(b.String()))
	}
	return writePDU(cn.c, resp, nil)
}

func (cn *conn) handleNop(p *pdu) error {
	if p.itt() == 0xffffffff {
		return nil // unsolicited ping-reply from initiator: nothing to do
	}
	resp := make([]byte, bhsLen)
	resp[0] = opNopIn
	resp[1] = 0x80
	copy(resp[8:16], p.hdr[8:16])
	copy(resp[16:20], p.hdr[16:20])
	binary.BigEndian.PutUint32(resp[20:24], 0xffffffff)
	cn.stamp(resp, true)
	return writePDU(cn.c, resp, p.data)
}

func (cn *conn) handleLogout(p *pdu) error {
	resp := make([]byte, bhsLen)
	resp[0] = opLogoutResp
	resp[1] = 0x80
	copy(resp[16:20], p.hdr[16:20])
	cn.stamp(resp, true)
	if err := writePDU(cn.c, resp, nil); err != nil {
		return err
	}
	return io.EOF
}

func (cn *conn) reject(p *pdu) error {
	resp := make([]byte, bhsLen)
	resp[0] = opReject
	resp[1] = 0x80
	resp[2] = 0x04 // protocol error
	binary.BigEndian.PutUint32(resp[16:20], 0xffffffff)
	cn.stamp(resp, true)
	return writePDU(cn.c, resp, p.hdr[:])
}

func (cn *conn) handleSCSI(p *pdu) error {
	if !cn.loggedIn || cn.discovery || cn.lun == nil {
		return cn.reject(p)
	}
	for _, b := range p.hdr[8:16] {
		if b != 0 {
			return cn.reject(p)
		}
	}
	if cn.s.d.AllowTarget != nil && !cn.s.d.AllowTarget(sourceIP(cn.c.RemoteAddr()), cn.target) {
		return cn.reject(p)
	}
	edtl := binary.BigEndian.Uint32(p.hdr[20:24])
	res := cn.lun.handleCDB(p.hdr[32:48])

	// Trim to the initiator's expected transfer length.
	data := res.data
	dataLen := len(data)
	if res.readLength > 0 {
		dataLen = res.readLength
	}
	if uint32(dataLen) > edtl {
		dataLen = int(edtl)
	}
	residual := uint32(0)
	if res.status == statusGood && uint32(dataLen) < edtl {
		residual = edtl - uint32(dataLen)
	}

	// Data-In PDUs (no phase collapse: a plain SCSI Response always follows,
	// which every initiator accepts).
	dataSN := uint32(0)
	for off := 0; off < dataLen; {
		chunk := dataLen - off
		if chunk > cn.peerMaxDSL {
			chunk = cn.peerMaxDSL
		}
		var chunkData []byte
		if res.readLength > 0 {
			chunkData = make([]byte, chunk)
			n, err := cn.lun.ra.ReadAt(chunkData, res.readOffset+int64(off))
			if err != nil && err != io.EOF {
				return fmt.Errorf("read backing image: %w", err)
			}
			// ReaderAt may return a short final sector with io.EOF. The slice was
			// zero-initialized, as a CD's rounded final sector must be.
			_ = n
		} else {
			chunkData = data[off : off+chunk]
		}
		hdr := make([]byte, bhsLen)
		hdr[0] = opSCSIDataIn
		if off+chunk == dataLen {
			hdr[1] = 0x80 // F
		}
		copy(hdr[16:20], p.hdr[16:20])
		binary.BigEndian.PutUint32(hdr[20:24], 0xffffffff)
		cn.stamp(hdr, false)
		binary.BigEndian.PutUint32(hdr[36:40], dataSN)
		binary.BigEndian.PutUint32(hdr[40:44], uint32(off))
		if err := writePDU(cn.c, hdr, chunkData); err != nil {
			return err
		}
		dataSN++
		off += chunk
	}

	// SCSI Response.
	hdr := make([]byte, bhsLen)
	hdr[0] = opSCSIResponse
	hdr[1] = 0x80
	if residual > 0 {
		hdr[1] |= 0x02 // underflow
		binary.BigEndian.PutUint32(hdr[44:48], residual)
	}
	hdr[2] = 0 // command completed at target
	hdr[3] = res.status
	copy(hdr[16:20], p.hdr[16:20])
	cn.stamp(hdr, true)
	binary.BigEndian.PutUint32(hdr[36:40], dataSN) // ExpDataSN
	var body []byte
	if res.status == statusCheckCondition && len(res.sense) > 0 {
		body = make([]byte, 2+len(res.sense))
		binary.BigEndian.PutUint16(body[0:2], uint16(len(res.sense)))
		copy(body[2:], res.sense)
	}
	return writePDU(cn.c, hdr, body)
}
