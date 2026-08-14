package dhcpsrv

import (
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"emberboot/internal/bootfiles"
)

func pxeRequest(t *testing.T, arch uint16, userClass string) *dhcpv4.DHCPv4 {
	t.Helper()
	m, err := dhcpv4.New()
	if err != nil {
		t.Fatal(err)
	}
	m.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient:Arch:00007:UNDI:003016"))
	m.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType,
		[]byte{byte(arch >> 8), byte(arch)}))
	if userClass != "" {
		m.UpdateOption(dhcpv4.OptUserClass(userClass))
	}
	return m
}

func TestClassifyArch(t *testing.T) {
	cases := []struct {
		arch uint16
		want Firmware
		file string
	}{
		{0, FirmwareBIOS, bootfiles.FileBIOS},
		{6, FirmwareUEFI32, bootfiles.FileUEFI32},
		{7, FirmwareUEFI64, bootfiles.FileUEFI64},
		{9, FirmwareUEFI64, bootfiles.FileUEFI64},
		{11, FirmwareARM64, ""},
		{16, FirmwareHTTP64, ""},
	}
	for _, c := range cases {
		m := pxeRequest(t, c.arch, "")
		if got := classifyArch(m); got != c.want {
			t.Errorf("arch %d classified %s, want %s", c.arch, got, c.want)
		}
		if got := bootfileFor(classifyArch(m)); got != c.file {
			t.Errorf("arch %d bootfile %q, want %q", c.arch, got, c.file)
		}
	}
}

func TestMissingArchOptionMeansBIOS(t *testing.T) {
	m, err := dhcpv4.New()
	if err != nil {
		t.Fatal(err)
	}
	m.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient"))
	if got := classifyArch(m); got != FirmwareBIOS {
		t.Errorf("no option 93 should classify as BIOS, got %s", got)
	}
}

func TestIsIPXE(t *testing.T) {
	if !isIPXE(pxeRequest(t, 7, "iPXE")) {
		t.Error("user class iPXE must be detected (the chainload loop-breaker)")
	}
	if isIPXE(pxeRequest(t, 7, "")) {
		t.Error("plain firmware request misdetected as iPXE")
	}
	if isIPXE(pxeRequest(t, 7, "MSFT 5.0")) {
		t.Error("non-iPXE user class misdetected")
	}
}

func TestIsPXERequest(t *testing.T) {
	if !isPXERequest(pxeRequest(t, 7, "")) {
		t.Error("PXEClient vendor class must be recognized")
	}
	m, _ := dhcpv4.New()
	m.UpdateOption(dhcpv4.OptClassIdentifier("HTTPClient:Arch:00016:UNDI:003001"))
	if !isPXERequest(m) || !isHTTPBoot(m) {
		t.Error("HTTPClient vendor class must be recognized as HTTP Boot")
	}
	plain, _ := dhcpv4.New()
	if isPXERequest(plain) {
		t.Error("ordinary DHCP traffic must be ignored")
	}
}

func TestPXEVendorOptsTerminated(t *testing.T) {
	opts := pxeVendorOpts()
	if opts[len(opts)-1] != 0xFF {
		t.Error("option 43 must end with the 0xFF terminator (PXE 2.1 spec)")
	}
	if opts[0] != 6 || opts[1] != 1 || opts[2] != 0x08 {
		t.Errorf("discovery control sub-option malformed: %v", opts)
	}
}
