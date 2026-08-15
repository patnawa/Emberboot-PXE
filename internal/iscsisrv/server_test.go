package iscsisrv

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// fakeProvider serves one in-memory "ISO".
type fakeProvider struct{ content []byte }

func (f *fakeProvider) OpenTarget(suffix string) (io.ReaderAt, int64, func(), error) {
	if suffix != "test-iso" {
		return nil, 0, nil, fmt.Errorf("no such target")
	}
	return bytes.NewReader(f.content), int64(len(f.content)), nil, nil
}
func (f *fakeProvider) TargetSuffixes() []string { return []string{"test-iso"} }

// initiator is a minimal test-side iSCSI client.
type initiator struct {
	t     *testing.T
	c     net.Conn
	cmdSN uint32
}

func startServer(t *testing.T) (*initiator, []byte) {
	t.Helper()
	content := make([]byte, 5000)
	for i := range content {
		content[i] = byte(i * 7)
	}
	srv := New(Deps{
		Log:         slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Provider:    &fakeProvider{content},
		AdvertiseIP: "127.0.0.1",
		Port:        0,
	})
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
	t.Cleanup(func() { c.Close() })
	return &initiator{t: t, c: c, cmdSN: 1}, content
}

func (in *initiator) send(hdr []byte, data []byte) {
	in.t.Helper()
	if err := writePDU(in.c, hdr, data); err != nil {
		in.t.Fatal(err)
	}
}

func (in *initiator) recv() *pdu {
	in.t.Helper()
	p, err := readPDU(in.c, 1<<20)
	if err != nil {
		in.t.Fatal(err)
	}
	return p
}

// login runs a single-PDU login straight to full feature phase.
func (in *initiator) login(sessionType, targetName string) *pdu {
	in.t.Helper()
	hdr := make([]byte, bhsLen)
	hdr[0] = 0x40 | opLoginReq  // immediate
	hdr[1] = 0x80 | 0x04 | 0x03 // T, CSG=opneg, NSG=FFP
	copy(hdr[8:14], []byte{0, 1, 2, 3, 4, 5})
	binary.BigEndian.PutUint32(hdr[16:20], 0x1000)
	binary.BigEndian.PutUint32(hdr[24:28], in.cmdSN)
	keys := map[string]string{
		"InitiatorName":            "iqn.2026-08.test:client",
		"SessionType":              sessionType,
		"HeaderDigest":             "None",
		"DataDigest":               "None",
		"MaxRecvDataSegmentLength": "8192",
	}
	if targetName != "" {
		keys["TargetName"] = targetName
	}
	in.send(hdr, encodeKeys(keys))
	return in.recv()
}

// scsi issues one CDB and collects Data-In payload until the SCSI Response.
func (in *initiator) scsi(cdb []byte, edtl uint32) (data []byte, status byte, sense []byte) {
	in.t.Helper()
	hdr := make([]byte, bhsLen)
	hdr[0] = opSCSICommand
	hdr[1] = 0x80 | 0x40 // F, Read
	binary.BigEndian.PutUint32(hdr[16:20], 0x2000+in.cmdSN)
	binary.BigEndian.PutUint32(hdr[20:24], edtl)
	binary.BigEndian.PutUint32(hdr[24:28], in.cmdSN)
	in.cmdSN++
	copy(hdr[32:48], cdb)
	in.send(hdr, nil)
	for {
		p := in.recv()
		switch p.opcode() {
		case opSCSIDataIn:
			off := binary.BigEndian.Uint32(p.hdr[40:44])
			if int(off) != len(data) {
				in.t.Fatalf("out-of-order Data-In: offset %d, have %d", off, len(data))
			}
			data = append(data, p.data...)
		case opSCSIResponse:
			status = p.hdr[3]
			if len(p.data) > 2 {
				sense = p.data[2:]
			}
			return data, status, sense
		default:
			in.t.Fatalf("unexpected opcode %#x", p.opcode())
		}
	}
}

func TestLoginAndInquiry(t *testing.T) {
	in, _ := startServer(t)
	resp := in.login("Normal", IQNPrefix+":test-iso")
	if resp.opcode() != opLoginResp || resp.hdr[36] != 0 {
		t.Fatalf("login failed: opcode %#x status %d/%d", resp.opcode(), resp.hdr[36], resp.hdr[37])
	}
	if binary.BigEndian.Uint16(resp.hdr[14:16]) == 0 {
		t.Error("full-feature login must assign a TSIH")
	}
	data, status, _ := in.scsi([]byte{0x12, 0, 0, 0, 36, 0}, 36)
	if status != statusGood || len(data) != 36 {
		t.Fatalf("INQUIRY: status %d len %d", status, len(data))
	}
	if data[0] != 0x05 || data[1] != 0x80 {
		t.Errorf("must identify as removable CD-ROM: % x", data[:2])
	}
}

func TestReadCapacityAndRead(t *testing.T) {
	in, content := startServer(t)
	if resp := in.login("Normal", IQNPrefix+":test-iso"); resp.hdr[36] != 0 {
		t.Fatal("login failed")
	}
	cap10, status, _ := in.scsi([]byte{0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 8)
	if status != statusGood {
		t.Fatal("READ CAPACITY failed")
	}
	lastLBA := binary.BigEndian.Uint32(cap10[0:4])
	blockSize := binary.BigEndian.Uint32(cap10[4:8])
	if blockSize != 2048 || lastLBA != 2 { // 5000 bytes -> 3 blocks
		t.Fatalf("capacity: lastLBA=%d blockSize=%d", lastLBA, blockSize)
	}

	cdb := []byte{0x28, 0, 0, 0, 0, 1, 0, 0, 2, 0} // READ(10) lba=1 count=2
	data, status, _ := in.scsi(cdb, 4096)
	if status != statusGood || len(data) != 4096 {
		t.Fatalf("READ(10): status %d len %d", status, len(data))
	}
	if !bytes.Equal(data[:len(content)-2048], content[2048:]) {
		t.Error("read data does not match backing content")
	}
	for _, b := range data[len(content)-2048:] {
		if b != 0 {
			t.Error("tail past EOF must be zero-padded")
			break
		}
	}

	// Beyond capacity: CHECK CONDITION, LBA out of range.
	oob := []byte{0x28, 0, 0, 0, 0, 9, 0, 0, 1, 0}
	_, status, sense := in.scsi(oob, 2048)
	if status != statusCheckCondition || len(sense) < 14 || sense[12] != ascLBAOutOfRange {
		t.Errorf("OOB read: status %d sense % x", status, sense)
	}
}

func TestReadTOC(t *testing.T) {
	in, _ := startServer(t)
	if resp := in.login("Normal", IQNPrefix+":test-iso"); resp.hdr[36] != 0 {
		t.Fatal("login failed")
	}
	data, status, _ := in.scsi([]byte{0x43, 0, 0, 0, 0, 0, 0, 0, 32, 0}, 32)
	if status != statusGood {
		t.Fatal("READ TOC failed")
	}
	if data[2] != 1 || data[3] != 1 {
		t.Errorf("single-track TOC expected: % x", data[:4])
	}
	if data[6] != 1 {
		t.Errorf("first descriptor should be track 1: % x", data[4:12])
	}
}

func TestOSInitiatorCommands(t *testing.T) {
	in, _ := startServer(t)
	if resp := in.login("Normal", IQNPrefix+":test-iso"); resp.hdr[36] != 0 {
		t.Fatal("login failed")
	}
	// GET CONFIGURATION must report DVD-ROM (0x0010) as the current profile.
	data, status, _ := in.scsi([]byte{0x46, 0, 0, 0, 0, 0, 0, 0, 32, 0}, 32)
	if status != statusGood || binary.BigEndian.Uint16(data[6:8]) != 0x0010 {
		t.Errorf("GET CONFIGURATION current profile: status %d data % x", status, data[:8])
	}
	// MODE SENSE(10) for page 0x2A: MM capabilities with no write bits.
	ms, status, _ := in.scsi([]byte{0x5a, 0, 0x2a, 0, 0, 0, 0, 0, 64, 0}, 64)
	if status != statusGood || len(ms) < 10 || ms[8]&0x3f != 0x2a {
		t.Fatalf("MODE SENSE 2A: status %d data % x", status, ms)
	}
	if ms[8+3] != 0 {
		t.Error("write-capability bits must be clear on a read-only unit")
	}
	// Writes are refused as DATA PROTECT, not invalid-opcode.
	_, status, sense := in.scsi([]byte{0x2a, 0, 0, 0, 0, 0, 0, 0, 1, 0}, 0)
	if status != statusCheckCondition || len(sense) < 14 || sense[2]&0x0f != 0x07 || sense[12] != 0x27 {
		t.Errorf("WRITE(10) must fail write-protected: status %d sense % x", status, sense)
	}
	// GET EVENT STATUS: polite "no event" instead of an error.
	if _, status, _ = in.scsi([]byte{0x4a, 1, 0, 0, 0x10, 0, 0, 0, 8, 0}, 8); status != statusGood {
		t.Errorf("GET EVENT STATUS should succeed, got %d", status)
	}
}

func TestUnknownTargetRefused(t *testing.T) {
	in, _ := startServer(t)
	resp := in.login("Normal", IQNPrefix+":nope")
	if resp.hdr[36] != 0x02 {
		t.Fatalf("unknown target must fail with initiator error class, got %d/%d", resp.hdr[36], resp.hdr[37])
	}
}

func TestDiscovery(t *testing.T) {
	in, _ := startServer(t)
	if resp := in.login("Discovery", ""); resp.hdr[36] != 0 {
		t.Fatal("discovery login failed")
	}
	hdr := make([]byte, bhsLen)
	hdr[0] = opTextReq
	hdr[1] = 0x80
	binary.BigEndian.PutUint32(hdr[16:20], 0x3000)
	binary.BigEndian.PutUint32(hdr[20:24], 0xffffffff)
	binary.BigEndian.PutUint32(hdr[24:28], in.cmdSN)
	in.send(hdr, encodeKeys(map[string]string{"SendTargets": "All"}))
	resp := in.recv()
	if resp.opcode() != opTextResp {
		t.Fatalf("expected Text Response, got %#x", resp.opcode())
	}
	txt := string(resp.data)
	if !bytes.Contains(resp.data, []byte(IQNPrefix+":test-iso")) {
		t.Errorf("discovery must list the target: %q", txt)
	}
	if !bytes.Contains(resp.data, []byte("TargetAddress=127.0.0.1:")) {
		t.Errorf("discovery must carry the portal address: %q", txt)
	}
}

func TestSanitizeSuffix(t *testing.T) {
	cases := map[string]string{
		"Win11_24H2 English x64.ISO": "win11-24h2-english-x64",
		"debian-12.5.0-amd64.iso":    "debian-12.5.0-amd64",
	}
	for in, want := range cases {
		if got := SanitizeSuffix(in); got != want {
			t.Errorf("SanitizeSuffix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSourceIPAdmissionRunsBeforeProtocol(t *testing.T) {
	called := make(chan net.IP, 1)
	srv := New(Deps{
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Provider: &fakeProvider{content: []byte("unused")},
		AllowSourceIP: func(ip net.IP) bool {
			called <- append(net.IP(nil), ip...)
			return false
		},
	})
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
	defer c.Close()
	select {
	case ip := <-called:
		if !ip.IsLoopback() {
			t.Fatalf("admission callback got %v, want loopback", ip)
		}
	case <-time.After(time.Second):
		t.Fatal("source admission callback was not called")
	}
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := c.Read(one[:]); err == nil {
		t.Fatal("denied connection remained open")
	}
}

func TestPreLoginRejectsNonLoginPDU(t *testing.T) {
	in, _ := startServer(t)
	hdr := make([]byte, bhsLen)
	hdr[0] = opNopOut
	hdr[1] = 0x80
	binary.BigEndian.PutUint32(hdr[16:20], 1)
	in.send(hdr, nil)
	resp := in.recv()
	if resp.opcode() != opReject {
		t.Fatalf("pre-login opcode response = %#x, want Reject", resp.opcode())
	}
}

func TestReadPDUAppliesOpcodeSpecificBodyLimits(t *testing.T) {
	var hdr [bhsLen]byte
	hdr[0] = opSCSIDataOut
	hdr[7] = 1
	if _, err := readPDU(bytes.NewReader(hdr[:]), 1<<20); err == nil || !strings.Contains(err.Error(), "exceeds limit 0") {
		t.Fatalf("Data-Out limit error = %v", err)
	}

	hdr = [bhsLen]byte{}
	hdr[0] = opLoginReq
	length := maxLoginTextData + 1
	hdr[5] = byte(length >> 16)
	hdr[6] = byte(length >> 8)
	hdr[7] = byte(length)
	if _, err := readPDU(bytes.NewReader(hdr[:]), 1<<20); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("Login body limit error = %v", err)
	}
}
