// Package iscsisrv implements the minimal read-only iSCSI target (an RFC
// 7143 subset) that Emberboot uses to serve ISOs as bootable media — the
// honest route to the "any ISO" long tail (ADR-0003 tier iii without kernel
// drivers): iPXE sanboot attaches the LUN and registers it in the iBFT so
// the booted OS can reattach.
//
// Scope, deliberately narrow: one connection per session, LUN 0 only,
// read-only, no CHAP (LAN service, same trust level as TFTP/HTTP boot), no
// digests, ErrorRecoveryLevel 0.
package iscsisrv

import (
	"encoding/binary"
	"fmt"
	"io"
)

// iSCSI opcodes (initiator → target).
const (
	opNopOut      = 0x00
	opSCSICommand = 0x01
	opLoginReq    = 0x03
	opTextReq     = 0x04
	opSCSIDataOut = 0x05
	opLogoutReq   = 0x06
)

// iSCSI opcodes (target → initiator).
const (
	opNopIn        = 0x20
	opSCSIResponse = 0x21
	opLoginResp    = 0x23
	opTextResp     = 0x24
	opSCSIDataIn   = 0x25
	opLogoutResp   = 0x26
	opReject       = 0x3f
)

// bhsLen is the fixed Basic Header Segment size.
const bhsLen = 48

const (
	maxLoginTextData = 64 << 10
	maxNopData       = 64 << 10
)

// pdu is one received PDU: the 48-byte header plus its data segment.
type pdu struct {
	hdr  [bhsLen]byte
	data []byte
}

func (p *pdu) opcode() byte    { return p.hdr[0] & 0x3f }
func (p *pdu) immediate() bool { return p.hdr[0]&0x40 != 0 }
func (p *pdu) flags() byte     { return p.hdr[1] }
func (p *pdu) itt() uint32     { return binary.BigEndian.Uint32(p.hdr[16:20]) }
func (p *pdu) cmdSN() uint32   { return binary.BigEndian.Uint32(p.hdr[24:28]) }

// readPDU reads one PDU. maxData bounds the data segment (defensive).
func readPDU(r io.Reader, maxData int) (*pdu, error) {
	var p pdu
	if _, err := io.ReadFull(r, p.hdr[:]); err != nil {
		return nil, err
	}
	ahsLen := int(p.hdr[4]) * 4
	dataLen := int(binary.BigEndian.Uint32(p.hdr[4:8]) & 0x00ffffff)
	opLimit := opcodeDataLimit(p.opcode(), maxData)
	if dataLen > opLimit {
		return nil, fmt.Errorf("opcode %#x data segment %d exceeds limit %d", p.opcode(), dataLen, opLimit)
	}
	// Additional header segments are not used by any command we accept, but
	// must be consumed to stay in sync.
	if ahsLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(ahsLen)); err != nil {
			return nil, err
		}
	}
	if dataLen > 0 {
		p.data = make([]byte, dataLen)
		if _, err := io.ReadFull(r, p.data); err != nil {
			return nil, err
		}
		// Data segments are padded to 4 bytes.
		if pad := (4 - dataLen%4) % 4; pad > 0 {
			if _, err := io.CopyN(io.Discard, r, int64(pad)); err != nil {
				return nil, err
			}
		}
	}
	return &p, nil
}

func opcodeDataLimit(opcode byte, ceiling int) int {
	limit := 0
	switch opcode {
	case opLoginReq, opLoginResp, opTextReq, opTextResp:
		limit = maxLoginTextData
	case opNopOut, opNopIn:
		limit = maxNopData
	case opSCSIDataIn:
		limit = ourMaxDSL
	case opSCSIResponse:
		limit = maxLoginTextData // sense data is small; keep a defensive ceiling.
	case opReject:
		limit = bhsLen
	case opSCSICommand, opSCSIDataOut, opLogoutReq, opLogoutResp:
		limit = 0
	default:
		limit = 0
	}
	if ceiling >= 0 && limit > ceiling {
		return ceiling
	}
	return limit
}

// writePDU sends a PDU: hdr must be 48 bytes with DataSegmentLength unset;
// it is filled from len(data), and data is padded to 4 bytes.
func writePDU(w io.Writer, hdr []byte, data []byte) error {
	if len(hdr) != bhsLen {
		return fmt.Errorf("bad header length %d", len(hdr))
	}
	hdr[4] = 0 // no AHS
	hdr[5] = byte(len(data) >> 16)
	hdr[6] = byte(len(data) >> 8)
	hdr[7] = byte(len(data))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := w.Write(data); err != nil {
			return err
		}
		if pad := (4 - len(data)%4) % 4; pad > 0 {
			if _, err := w.Write(make([]byte, pad)); err != nil {
				return err
			}
		}
	}
	return nil
}
