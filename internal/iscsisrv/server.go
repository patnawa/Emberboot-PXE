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
// IQNPrefix + ":" + <sanitized image name>.
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
	// OnAttach is called when an initiator reaches full feature phase
	// (session tracking hook; may be nil).
	OnAttach func(clientIP, targetSuffix string)
}

// Server is the iSCSI target listener.
type Server struct {
	d  Deps
	ln net.Listener

	mu    sync.Mutex
	tsihC uint16
}

// New creates the server (call Serve).
func New(d Deps) *Server { return &Server{d: d} }

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
	s.ln = ln
	s.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			return nil // closed
		}
		go s.handleConn(c)
	}
}

// Close stops the listener.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		s.ln.Close()
	}
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
	s    *Server
	c    net.Conn
	log  *slog.Logger
	lun  *lun
	closeLUN func()

	discovery bool
	loggedIn  bool
	target    string

	statSN    uint32
	expCmdSN  uint32
	// initiator's MaxRecvDataSegmentLength: our Data-In chunk bound.
	peerMaxDSL int
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
		// Sessions idle-out rather than live forever half-open.
		_ = nc.SetDeadline(time.Now().Add(10 * time.Minute))
		if err := cn.dispatch(p); err != nil {
			cn.log.Debug("iscsi session error", "error", err)
			return
		}
	}
}

func (cn *conn) dispatch(p *pdu) error {
	if !p.immediate() {
		cn.expCmdSN = p.cmdSN() + 1
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
		return nil // read-only target: absorb and ignore
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

	if v, ok := keys["MaxRecvDataSegmentLength"]; ok {
		var n int
		fmt.Sscanf(v, "%d", &n)
		if n >= 512 {
			cn.peerMaxDSL = n
		}
	}

	replyKeys := negotiate(keys)
	replyKeys["MaxRecvDataSegmentLength"] = fmt.Sprintf("%d", ourMaxDSL)
	replyKeys["TargetPortalGroupTag"] = "1"

	if st, ok := keys["SessionType"]; ok {
		cn.discovery = st == "Discovery"
	}
	if !cn.discovery {
		if tn, ok := keys["TargetName"]; ok {
			suffix, found := strings.CutPrefix(tn, IQNPrefix+":")
			if !found {
				return cn.loginError(resp, 0x02, 0x03) // not found
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
		flags = 0x80 | byte(csg<<2) | nsg
		if nsg == 3 {
			binary.BigEndian.PutUint16(resp[14:16], cn.s.nextTSIH())
			cn.loggedIn = true
			cn.expCmdSN = p.cmdSN() + 1
			if !cn.discovery && cn.s.d.OnAttach != nil {
				host, _, _ := net.SplitHostPort(cn.c.RemoteAddr().String())
				cn.s.d.OnAttach(host, cn.target)
			}
		}
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
	if !cn.loggedIn || cn.lun == nil {
		return cn.reject(p)
	}
	edtl := binary.BigEndian.Uint32(p.hdr[20:24])
	res := cn.lun.handleCDB(p.hdr[32:48])

	// Trim to the initiator's expected transfer length.
	data := res.data
	if uint32(len(data)) > edtl {
		data = data[:edtl]
	}
	residual := uint32(0)
	if res.status == statusGood && uint32(len(data)) < edtl {
		residual = edtl - uint32(len(data))
	}

	// Data-In PDUs (no phase collapse: a plain SCSI Response always follows,
	// which every initiator accepts).
	dataSN := uint32(0)
	for off := 0; off < len(data); {
		chunk := len(data) - off
		if chunk > cn.peerMaxDSL {
			chunk = cn.peerMaxDSL
		}
		hdr := make([]byte, bhsLen)
		hdr[0] = opSCSIDataIn
		if off+chunk == len(data) {
			hdr[1] = 0x80 // F
		}
		copy(hdr[16:20], p.hdr[16:20])
		binary.BigEndian.PutUint32(hdr[20:24], 0xffffffff)
		cn.stamp(hdr, false)
		binary.BigEndian.PutUint32(hdr[36:40], dataSN)
		binary.BigEndian.PutUint32(hdr[40:44], uint32(off))
		if err := writePDU(cn.c, hdr, data[off:off+chunk]); err != nil {
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
