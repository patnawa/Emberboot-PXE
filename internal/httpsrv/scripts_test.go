package httpsrv

import (
	"net"
	"strings"
	"testing"

	"emberboot/internal/config"
	"emberboot/internal/images"
)

const testBase = "http://10.0.0.5:8090"

func testCfg(t *testing.T) *config.Config {
	t.Helper()
	c := &config.Config{Site: "hq"}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

func readyImage(name string, strategy images.Strategy, plan images.BootPlan) images.Image {
	return images.Image{
		FileName: name, DisplayName: name, State: images.StateReady,
		Strategy: strategy, Plan: plan,
	}
}

func testMAC(t *testing.T) net.HardwareAddr {
	m, err := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMenuFiltersAndLabels(t *testing.T) {
	cfg := testCfg(t)
	cfg.Overrides = []config.Override{{Name: "lab", MAC: "aa:*", Menu: []string{"a.iso"}}}
	imgs := []images.Image{
		readyImage("a.iso", images.StrategyMemdisk, images.BootPlan{Family: "unknown"}),
		readyImage("b.iso", images.StrategyMemdisk, images.BootPlan{Family: "unknown"}),
		{FileName: "c.iso", State: images.StateInvalid},
	}
	script := menuScript(cfg, imgs, testMAC(t), nil)
	if !strings.Contains(script, "a.iso") {
		t.Error("allowed image missing from menu")
	}
	if strings.Contains(script, "b.iso") {
		t.Error("override menu filter not applied")
	}
	if strings.Contains(script, "c.iso") {
		t.Error("non-Ready image must never be offered")
	}
	if !strings.Contains(script, "#!ipxe") {
		t.Error("not an iPXE script")
	}
	if !strings.Contains(script, "sanboot --no-describe --drive 0x80") {
		t.Error("local boot fallback missing")
	}
}

func TestLinuxExtractScript(t *testing.T) {
	img := readyImage("ubuntu.iso", images.StrategyLinuxExtract, images.BootPlan{
		Family: "ubuntu-casper", Kernel: "casper/vmlinuz", Initrds: []string{"casper/initrd"},
		Args: "root=/dev/ram0 ip=dhcp url=${ISOURL}",
	})
	img.AnswerFile = "auto.yaml"
	s := imageScript(testCfg(t), img, testMAC(t), nil, testBase, 0)
	if !strings.Contains(s, "kernel "+testBase+"/img/ubuntu.iso/file/casper/vmlinuz") {
		t.Errorf("kernel line wrong:\n%s", s)
	}
	if !strings.Contains(s, "url="+testBase+"/iso/ubuntu.iso") {
		t.Errorf("ISOURL must expand to an absolute URL (the OS fetches it, not iPXE):\n%s", s)
	}
	if !strings.Contains(s, "autoinstall ds=nocloud-net;s="+testBase+"/seed/auto.yaml/") {
		t.Errorf("autoinstall seed wiring missing:\n%s", s)
	}
	if !strings.Contains(s, "initrd "+testBase+"/img/ubuntu.iso/file/casper/initrd") {
		t.Errorf("initrd line wrong:\n%s", s)
	}
}

func TestOverrideAnswerFileWins(t *testing.T) {
	cfg := testCfg(t)
	cfg.Overrides = []config.Override{{Name: "lab", MAC: "aa:*", AnswerFile: "wipe.yaml"}}
	img := readyImage("u.iso", images.StrategyLinuxExtract, images.BootPlan{
		Family: "ubuntu-casper", Kernel: "casper/vmlinuz", Initrds: []string{"casper/initrd"},
	})
	img.AnswerFile = "default.yaml"
	s := imageScript(cfg, img, testMAC(t), nil, testBase, 0)
	if !strings.Contains(s, "seed/wipe.yaml/") || strings.Contains(s, "default.yaml") {
		t.Errorf("Override answer file must win over the per-image one:\n%s", s)
	}
}

func TestWimbootScript(t *testing.T) {
	img := readyImage("win11.iso", images.StrategyWimboot, images.BootPlan{
		Family: "windows",
		Files: map[string]string{
			"boot.wim": "sources/boot.wim", "bcd": "boot/bcd",
			"boot.sdi": "boot/boot.sdi", "install": "sources/install.wim",
		},
	})
	s := imageScript(testCfg(t), img, testMAC(t), nil, testBase, 0)
	for _, want := range []string{
		"kernel " + testBase + "/boot/wimboot",
		"initrd -n winpeshl.ini",
		"initrd -n install.bat",
		"initrd -n bcd " + testBase + "/img/win11.iso/file/boot/bcd bcd",
		"initrd -n install.wim " + testBase + "/img/win11.iso/file/sources/install.wim install.wim",
		"initrd -n boot.wim " + testBase + "/img/win11.iso/file/sources/boot.wim boot.wim",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("wimboot script missing %q:\n%s", want, s)
		}
	}
	// boot.wim must come after install.wim injection lines don't matter for
	// wimboot, but boot must be last meaningful command before :failed.
	if strings.Index(s, "boot ||") < strings.Index(s, "initrd -n boot.wim") {
		t.Error("boot must follow all initrd lines")
	}
}

func TestMemdiskScript(t *testing.T) {
	img := readyImage("tool.iso", images.StrategyMemdisk, images.BootPlan{Family: "unknown"})
	s := imageScript(testCfg(t), img, testMAC(t), nil, testBase, 0)
	if !strings.Contains(s, "sanboot "+testBase+"/iso/tool.iso") {
		t.Errorf("memdisk strategy must sanboot the raw ISO:\n%s", s)
	}
}

func TestInstallBAT(t *testing.T) {
	full := installBAT("install.wim", true)
	if !strings.Contains(full, "/installfrom:X:\\Windows\\System32\\install.wim") ||
		!strings.Contains(full, "/unattend:X:\\Windows\\System32\\autounattend.xml") {
		t.Errorf("full install.bat wrong:\n%s", full)
	}
	if !strings.Contains(full, "wpeinit") {
		t.Error("wpeinit must run before setup")
	}
	esd := installBAT("install.esd", false)
	if !strings.Contains(esd, "/installfrom:X:\\Windows\\System32\\install.esd") {
		t.Errorf(".esd sources must keep their extension:\n%s", esd)
	}
}

func TestESDKeepsExtensionInScript(t *testing.T) {
	img := readyImage("win.iso", images.StrategyWimboot, images.BootPlan{
		Family: "windows",
		Files:  map[string]string{"boot.wim": "sources/boot.wim", "install": "sources/install.esd"},
	})
	s := imageScript(testCfg(t), img, testMAC(t), nil, testBase, 0)
	if !strings.Contains(s, "initrd -n install.esd "+testBase+"/img/win.iso/file/sources/install.esd install.esd") {
		t.Errorf(".esd must be injected as install.esd:\n%s", s)
	}
}

func TestRAMGateRefusesSmallClients(t *testing.T) {
	img := readyImage("big.iso", images.StrategyLinuxExtract, images.BootPlan{
		Family: "ubuntu-casper", Kernel: "casper/vmlinuz", Initrds: []string{"casper/initrd"},
		RAMLoadMB: 6000,
	})
	blocked := imageScript(testCfg(t), img, testMAC(t), nil, testBase, 4096)
	if strings.Contains(blocked, "kernel ") || !strings.Contains(blocked, "only 4096 MB") {
		t.Errorf("4GB client must be refused a 6GB RAM-load with a clear message:\n%s", blocked)
	}
	if !strings.Contains(blocked, "chain "+testBase+"/boot.ipxe") {
		t.Error("refusal must route back to the menu")
	}
	allowed := imageScript(testCfg(t), img, testMAC(t), nil, testBase, 8192)
	if !strings.Contains(allowed, "kernel ") {
		t.Errorf("8GB client must boot normally:\n%s", allowed)
	}
	unknown := imageScript(testCfg(t), img, testMAC(t), nil, testBase, 0)
	if !strings.Contains(unknown, "kernel ") {
		t.Error("unknown RAM must not block the boot")
	}
}

func TestMemdiskEFIChain(t *testing.T) {
	img := readyImage("memtest.iso", images.StrategyMemdisk, images.BootPlan{
		Family: "unknown", Files: map[string]string{"efi": "EFI/BOOT/BOOTX64.EFI"},
	})
	s := imageScript(testCfg(t), img, testMAC(t), nil, testBase, 0)
	if !strings.Contains(s, "iseq ${platform} efi && chain "+testBase+"/img/memtest.iso/file/EFI/BOOT/BOOTX64.EFI") {
		t.Errorf("UEFI clients must chain the standalone EFI app:\n%s", s)
	}
	if !strings.Contains(s, "sanboot ") {
		t.Error("BIOS clients still need the sanboot fallback")
	}
}

func TestAnswerSubstitution(t *testing.T) {
	in := []byte("host: pc-${mac}\nsite: ${site}\nip: ${ip}\n")
	out := string(substituteAnswer(in, "hq", "aa:bb:cc:dd:ee:ff", "10.1.2.3"))
	if !strings.Contains(out, "pc-aa:bb:cc:dd:ee:ff") || !strings.Contains(out, "site: hq") ||
		!strings.Contains(out, "ip: 10.1.2.3") {
		t.Errorf("substitution failed: %s", out)
	}
}
