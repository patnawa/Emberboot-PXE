package iscsisrv

import (
	"encoding/binary"
	"fmt"
	"io"
)

// cdBlockSize: ISOs are addressed in 2048-byte CD sectors.
const cdBlockSize = 2048

// SCSI status codes.
const (
	statusGood           = 0x00
	statusCheckCondition = 0x02
)

// Sense keys / additional sense codes used here.
const (
	senseIllegalRequest = 0x05
	ascInvalidOpcode    = 0x20
	ascLBAOutOfRange    = 0x21
	ascInvalidFieldCDB  = 0x24
)

// lun is one read-only CD-ROM logical unit backed by an ISO.
type lun struct {
	ra     io.ReaderAt
	blocks uint32 // capacity in 2048-byte sectors
	serial string
}

// scsiResult is the outcome of one CDB.
type scsiResult struct {
	data   []byte
	status byte
	sense  []byte
}

func good(data []byte) scsiResult { return scsiResult{data: data, status: statusGood} }

func check(key, asc, ascq byte) scsiResult {
	s := make([]byte, 18)
	s[0] = 0x70 // fixed format, current error
	s[2] = key
	s[7] = 10 // additional length
	s[12] = asc
	s[13] = ascq
	return scsiResult{status: statusCheckCondition, sense: s}
}

// maxReadBytes bounds one READ command's payload (initiators negotiate far
// smaller bursts; this is a defensive cap).
const maxReadBytes = 4 << 20

// handleCDB executes one SCSI command against the LUN.
func (l *lun) handleCDB(cdb []byte) scsiResult {
	if len(cdb) == 0 {
		return check(senseIllegalRequest, ascInvalidOpcode, 0)
	}
	switch cdb[0] {
	case 0x00: // TEST UNIT READY
		return good(nil)
	case 0x03: // REQUEST SENSE: nothing pending
		s := make([]byte, 18)
		s[0] = 0x70
		s[7] = 10
		return good(s)
	case 0x12: // INQUIRY
		return l.inquiry(cdb)
	case 0x1a: // MODE SENSE(6)
		return l.modeSense(cdb[2], false)
	case 0x5a: // MODE SENSE(10)
		return l.modeSense(cdb[2], true)
	case 0x1b, 0x1e, 0x35, 0xbb: // START STOP / PREVENT ALLOW / SYNC CACHE / SET CD SPEED
		return good(nil)
	case 0x4a: // GET EVENT STATUS NOTIFICATION: "no event available"
		return good([]byte{0, 2, 0x80, 0})
	case 0x0a, 0x2a, 0x8a, 0xaa: // WRITE(6/10/16/12): read-only medium
		return check(0x07 /* DATA PROTECT */, 0x27 /* write protected */, 0)
	case 0x25: // READ CAPACITY(10)
		out := make([]byte, 8)
		binary.BigEndian.PutUint32(out[0:4], l.blocks-1)
		binary.BigEndian.PutUint32(out[4:8], cdBlockSize)
		return good(out)
	case 0x9e: // READ CAPACITY(16) (service action 0x10)
		if cdb[1]&0x1f != 0x10 {
			return check(senseIllegalRequest, ascInvalidFieldCDB, 0)
		}
		out := make([]byte, 32)
		binary.BigEndian.PutUint64(out[0:8], uint64(l.blocks-1))
		binary.BigEndian.PutUint32(out[8:12], cdBlockSize)
		return good(out)
	case 0xa0: // REPORT LUNS: just LUN 0
		out := make([]byte, 16)
		binary.BigEndian.PutUint32(out[0:4], 8)
		return good(out)
	case 0x08: // READ(6)
		lba := uint64(cdb[1]&0x1f)<<16 | uint64(cdb[2])<<8 | uint64(cdb[3])
		n := uint32(cdb[4])
		if n == 0 {
			n = 256
		}
		return l.read(lba, n)
	case 0x28: // READ(10)
		return l.read(uint64(binary.BigEndian.Uint32(cdb[2:6])), uint32(binary.BigEndian.Uint16(cdb[7:9])))
	case 0xa8: // READ(12)
		return l.read(uint64(binary.BigEndian.Uint32(cdb[2:6])), binary.BigEndian.Uint32(cdb[6:10]))
	case 0x88: // READ(16)
		return l.read(binary.BigEndian.Uint64(cdb[2:10]), binary.BigEndian.Uint32(cdb[10:14]))
	case 0x43: // READ TOC/PMA/ATIP
		return l.readTOC(cdb)
	case 0x46: // GET CONFIGURATION: DVD-ROM current profile (what tgt serves
		// and what Windows/Linux initiators expect for an ISO-backed unit),
		// plus a Profile List feature naming DVD-ROM (current) and CD-ROM.
		feat := []byte{
			0x00, 0x00, 0x03, 8, // feature 0000 Profile List, current, 8 bytes
			0x00, 0x10, 0x01, 0, // profile 0x0010 DVD-ROM, currentP
			0x00, 0x08, 0x00, 0, // profile 0x0008 CD-ROM
		}
		out := make([]byte, 8, 8+len(feat))
		binary.BigEndian.PutUint32(out[0:4], uint32(4+len(feat)))
		binary.BigEndian.PutUint16(out[6:8], 0x0010)
		return good(append(out, feat...))
	case 0x51: // READ DISC INFORMATION: complete single-session disc
		out := make([]byte, 34)
		out[1] = 32   // length
		out[2] = 0x0e // last session complete, disc complete, non-erasable
		out[3] = 1    // first track
		out[4] = 1    // sessions (LSB)
		out[5] = 1    // first track in last session
		out[6] = 1    // last track in last session
		return good(out)
	default:
		return check(senseIllegalRequest, ascInvalidOpcode, 0)
	}
}

func (l *lun) read(lba uint64, count uint32) scsiResult {
	if count == 0 {
		return good(nil)
	}
	if lba+uint64(count) > uint64(l.blocks) {
		return check(senseIllegalRequest, ascLBAOutOfRange, 0)
	}
	byteLen := int64(count) * cdBlockSize
	if byteLen > maxReadBytes {
		return check(senseIllegalRequest, ascInvalidFieldCDB, 0)
	}
	buf := make([]byte, byteLen)
	if _, err := l.ra.ReadAt(buf, int64(lba)*cdBlockSize); err != nil && err != io.EOF {
		return check(0x03 /* MEDIUM ERROR */, 0x11, 0)
	}
	return good(buf)
}

// mmPage2A is the MM capabilities mode page: every read bit set, every
// write bit clear — Windows' cdrom.sys asks for this page while classifying
// the unit.
func mmPage2A() []byte {
	p := make([]byte, 2+26)
	p[0] = 0x2a
	p[1] = 26
	p[2] = 0x3f // reads: CD-R/CD-RW/Method2/DVD-ROM/DVD-R/DVD-RAM
	p[3] = 0x00 // writes: none
	p[4] = 0x71 // multisession, mode2 form1/2, audio play
	p[5] = 0xff
	p[6] = 0x2f // eject, tray loader, lock
	return p
}

// modeSense answers MODE SENSE(6/10). Page 0x2A and the all-pages request
// return the MM capabilities page; anything else gets a bare header, which
// initiators tolerate (proven by tgt's gaps).
func (l *lun) modeSense(pageAndPC byte, ten bool) scsiResult {
	var pages []byte
	switch pageAndPC & 0x3f {
	case 0x2a, 0x3f:
		pages = mmPage2A()
	}
	if ten {
		out := make([]byte, 8, 8+len(pages))
		binary.BigEndian.PutUint16(out[0:2], uint16(6+len(pages)))
		return good(append(out, pages...))
	}
	out := make([]byte, 4, 4+len(pages))
	out[0] = byte(3 + len(pages))
	return good(append(out, pages...))
}

// readTOC answers formats 0 (TOC) and 1 (session info) for a single-track
// data disc; MSF addressing is honored.
func (l *lun) readTOC(cdb []byte) scsiResult {
	msf := cdb[1]&0x02 != 0
	addr := func(lba uint32) []byte {
		if !msf {
			out := make([]byte, 4)
			binary.BigEndian.PutUint32(out, lba)
			return out
		}
		lba += 150 // MSF includes the 2-second lead-in offset
		return []byte{0, byte(lba / 4500), byte(lba / 75 % 60), byte(lba % 75)}
	}
	switch cdb[2] & 0x0f {
	case 0: // full TOC: track 1 + lead-out
		body := []byte{0, 0x14, 1, 0}
		body = append(body, addr(0)...)
		body = append(body, 0, 0x14, 0xaa, 0)
		body = append(body, addr(l.blocks)...)
		out := make([]byte, 4, 4+len(body))
		binary.BigEndian.PutUint16(out[0:2], uint16(len(body)+2))
		out[2], out[3] = 1, 1 // first, last track
		return good(append(out, body...))
	case 1: // multi-session info: single session
		body := []byte{0, 0x14, 1, 0}
		body = append(body, addr(0)...)
		out := make([]byte, 4, 4+len(body))
		binary.BigEndian.PutUint16(out[0:2], uint16(len(body)+2))
		out[2], out[3] = 1, 1 // first, last session
		return good(append(out, body...))
	default:
		return check(senseIllegalRequest, ascInvalidFieldCDB, 0)
	}
}

// inquiry answers standard and VPD inquiries.
func (l *lun) inquiry(cdb []byte) scsiResult {
	evpd := cdb[1]&0x01 != 0
	page := cdb[2]
	if !evpd {
		if page != 0 {
			return check(senseIllegalRequest, ascInvalidFieldCDB, 0)
		}
		out := make([]byte, 36)
		out[0] = 0x05 // CD/DVD device
		out[1] = 0x80 // removable
		out[2] = 0x05 // SPC-3
		out[3] = 0x02 // response format
		out[4] = 31   // additional length
		copy(out[8:16], "EMBERBT ")
		copy(out[16:32], "VIRTUAL CDROM   ")
		copy(out[32:36], "0.5 ")
		return good(out)
	}
	switch page {
	case 0x00: // supported VPD pages
		return good([]byte{0x05, 0x00, 0, 3, 0x00, 0x80, 0x83})
	case 0x80: // unit serial number
		s := l.serial
		if s == "" {
			s = "EMBERBOOT0"
		}
		out := append([]byte{0x05, 0x80, 0, byte(len(s))}, s...)
		return good(out)
	case 0x83: // device identification: T10 vendor id designator
		id := "EMBERBT " + l.serial
		des := append([]byte{0x02 /* codeset ASCII */, 0x01 /* T10 */, 0, byte(len(id))}, id...)
		out := append([]byte{0x05, 0x83, 0, byte(len(des))}, des...)
		return good(out)
	default:
		return check(senseIllegalRequest, ascInvalidFieldCDB, 0)
	}
}

func newLUN(ra io.ReaderAt, sizeBytes int64, serial string) (*lun, error) {
	if sizeBytes <= 0 {
		return nil, fmt.Errorf("empty backing image")
	}
	blocks := (sizeBytes + cdBlockSize - 1) / cdBlockSize
	return &lun{ra: ra, blocks: uint32(blocks), serial: serial}, nil
}
