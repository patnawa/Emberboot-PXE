package dhcpsrv

import (
	"encoding/binary"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"emberboot/internal/bootfiles"
)

// Firmware classifies a PXE client by DHCP option 93 (RFC 4578 / RFC 5970).
type Firmware int

const (
	FirmwareUnknown Firmware = iota
	FirmwareBIOS             // arch 0
	FirmwareUEFI32           // arch 6
	FirmwareUEFI64           // arch 7, 9
	FirmwareARM64            // arch 11 (out of scope; identified for logging)
	FirmwareHTTP64           // arch 16 (native UEFI HTTP Boot, x64)
	FirmwareHTTP32           // arch 15
	FirmwareHTTPARM64        // arch 19
)

func (f Firmware) String() string {
	switch f {
	case FirmwareBIOS:
		return "bios"
	case FirmwareUEFI32:
		return "uefi-ia32"
	case FirmwareUEFI64:
		return "uefi-x64"
	case FirmwareARM64:
		return "uefi-arm64"
	case FirmwareHTTP64:
		return "http-x64"
	case FirmwareHTTP32:
		return "http-ia32"
	case FirmwareHTTPARM64:
		return "http-arm64"
	default:
		return "unknown"
	}
}

// Bootfile names come from the embedded binaries in bootfiles.

// classifyArch reads option 93. Absent option means an ancient BIOS client.
func classifyArch(m *dhcpv4.DHCPv4) Firmware {
	v := m.Options.Get(dhcpv4.OptionClientSystemArchitectureType)
	if len(v) < 2 {
		return FirmwareBIOS
	}
	// Some clients send multiple 16-bit values; the first is authoritative.
	switch binary.BigEndian.Uint16(v[:2]) {
	case 0:
		return FirmwareBIOS
	case 6:
		return FirmwareUEFI32
	case 7, 9:
		return FirmwareUEFI64
	case 11:
		return FirmwareARM64
	case 15:
		return FirmwareHTTP32
	case 16:
		return FirmwareHTTP64
	case 19:
		return FirmwareHTTPARM64
	default:
		return FirmwareUnknown
	}
}

// bootfileFor maps firmware to the TFTP filename, or "" if unsupported.
func bootfileFor(f Firmware) string {
	switch f {
	case FirmwareBIOS:
		return bootfiles.FileBIOS
	case FirmwareUEFI32:
		return bootfiles.FileUEFI32
	case FirmwareUEFI64:
		return bootfiles.FileUEFI64
	default:
		return ""
	}
}

// isPXERequest reports whether the packet is PXE- or HTTPBoot-shaped: it has
// the vendor class "PXEClient..." or "HTTPClient..." (option 60).
func isPXERequest(m *dhcpv4.DHCPv4) bool {
	cls := m.ClassIdentifier()
	return strings.HasPrefix(cls, "PXEClient") || strings.HasPrefix(cls, "HTTPClient")
}

// isHTTPBoot reports native UEFI HTTP Boot clients (vendor class HTTPClient).
func isHTTPBoot(m *dhcpv4.DHCPv4) bool {
	return strings.HasPrefix(m.ClassIdentifier(), "HTTPClient")
}

// isIPXE reports whether the request came from an already-chainloaded iPXE
// (user class option 77 == "iPXE") — the loop-breaking signal (ADR-0001).
func isIPXE(m *dhcpv4.DHCPv4) bool {
	for _, uc := range m.UserClass() {
		if uc == "iPXE" {
			return true
		}
	}
	return false
}

// pxeVendorOpts builds option 43 for proxyDHCP offers to BIOS clients:
// PXE_DISCOVERY_CONTROL (sub-option 6) = 0x08 "download bootfile directly,
// skip boot-server discovery", terminated by 0xFF per the PXE 2.1 spec.
func pxeVendorOpts() []byte {
	return []byte{6, 1, 0x08, 0xFF}
}
