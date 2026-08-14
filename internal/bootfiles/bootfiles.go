// Package bootfiles embeds the third-party boot binaries Emberboot serves:
// iPXE bootloaders (over TFTP) and wimboot (over HTTP, for the Wimboot
// strategy). See PROVENANCE.md in this directory for exact upstream versions,
// URLs, hashes, and license obligations.
package bootfiles

import "embed"

//go:embed blobs
var blobs embed.FS

// File names, as requested by clients (TFTP) or scripts (HTTP).
const (
	FileBIOS     = "undionly.kpxe" // BIOS chainload (keeps firmware UNDI driver)
	FileUEFI64   = "snponly.efi"   // UEFI x64, firmware SNP driver (default)
	FileUEFI64F  = "ipxe.efi"      // UEFI x64, native drivers (fallback)
	FileUEFI32   = "ipxe32.efi"    // UEFI IA32
	FileShim     = "shimx64.efi"   // Secure Boot shim (iPXE v2.0.0 build)
	FileUEFI64SB = "snponly-sb.efi" // UEFI x64 built for the Secure Boot shim
	FileWimboot  = "wimboot"       // Windows PE loader (served over HTTP)
	// FileAutoexec is not embedded: the TFTP server generates it (it embeds
	// the instance's HTTP URL).
	FileAutoexec = "autoexec.ipxe"
)

// Get returns an embedded boot file by bare name.
func Get(name string) ([]byte, bool) {
	switch name {
	case FileBIOS, FileUEFI64, FileUEFI64F, FileUEFI32, FileShim, FileUEFI64SB, FileWimboot:
		data, err := blobs.ReadFile("blobs/" + name)
		if err != nil {
			return nil, false
		}
		return data, true
	default:
		return nil, false
	}
}
