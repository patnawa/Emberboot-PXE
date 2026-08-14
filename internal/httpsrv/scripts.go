package httpsrv

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"emberboot/internal/config"
	"emberboot/internal/images"
	"emberboot/internal/rules"
)

// Script generation: every .ipxe document Emberboot serves is produced here.
// Scripts use RELATIVE URLs throughout, so they work no matter which
// name/IP/port the client reached us on.

// bootStub is /boot.ipxe: the entry point every chainloaded iPXE fetches.
// It immediately re-chains to the menu with client identity attached.
func bootStub() string {
	return `#!ipxe
chain menu.ipxe?mac=${net0/mac}&ip=${net0/ip}&mem=${memsize}
`
}

// menuScript builds the personalized Boot Menu for one Client.
func menuScript(cfg *config.Config, imgs []images.Image, mac net.HardwareAddr, ip net.IP) string {
	dec := rules.Evaluate(cfg, mac, ip)

	var b strings.Builder
	b.WriteString("#!ipxe\n")
	fmt.Fprintf(&b, "set menu-timeout %d\n", cfg.Menu.TimeoutSeconds*1000)
	b.WriteString(":start\n")
	fmt.Fprintf(&b, "menu %s  [%s]\n", cfg.Menu.Title, cfg.Site)
	b.WriteString("item --key l local  Boot from local disk\n")

	// Filter: Ready, not disabled, allowed by the Override menu (if set).
	shown := make([]images.Image, 0, len(imgs))
	for _, img := range imgs {
		if img.State != images.StateReady || img.Disabled {
			continue
		}
		if dec.Menu != nil && !contains(dec.Menu, img.FileName) {
			continue
		}
		shown = append(shown, img)
	}
	for i, img := range shown {
		fmt.Fprintf(&b, "item img%d  %s  (%s)\n", i, img.DisplayName, img.Strategy)
	}
	b.WriteString("item --key s shell  iPXE shell\n")
	b.WriteString("item --key r reboot  Reboot\n")
	b.WriteString("choose --timeout ${menu-timeout} --default local target && goto ${target} || goto local\n")

	b.WriteString(":local\n")
	// exit falls back to the firmware's normal boot order; sanboot covers
	// BIOS setups where exit does not continue the boot sequence.
	b.WriteString("sanboot --no-describe --drive 0x80 || exit\n")
	b.WriteString(":shell\nshell\ngoto start\n")
	b.WriteString(":reboot\nreboot\n")

	for i, img := range shown {
		fmt.Fprintf(&b, ":img%d\nchain img/%s/boot.ipxe?mac=${net0/mac}&ip=${net0/ip}&mem=${memsize} || goto failed\n",
			i, url.PathEscape(img.FileName))
	}
	b.WriteString(":failed\necho Boot failed - returning to menu in 5s\nsleep 5\ngoto start\n")
	return b.String()
}

// imageScript builds the per-Image boot script for one Client, by strategy.
// base is the absolute URL prefix the client reached us on (from the request
// Host) — kernel arguments like url=/fetch=/inst.repo= are resolved by the
// booted OS, not by iPXE, so they must be absolute. memMB is the client's
// reported RAM (0 = unknown), used to refuse RAM-loading images with a clear
// message instead of a mysterious mid-transfer death.
func imageScript(cfg *config.Config, img images.Image, mac net.HardwareAddr, ip net.IP, base string, memMB int) string {
	dec := rules.Evaluate(cfg, mac, ip)
	answer := img.AnswerFile
	if dec.AnswerFile != "" {
		answer = dec.AnswerFile // Override wins over per-image setting
	}

	enc := url.PathEscape(img.FileName)
	isoURL := base + "/iso/" + enc
	content := base + "/img/" + enc + "/file" // in-ISO tree

	// RAM gate: iPXE cannot compare numbers, so the check runs server-side
	// on the memsize the menu forwarded.
	if img.Plan.RAMLoadMB > 0 && memMB > 0 && memMB < img.Plan.RAMLoadMB {
		return fmt.Sprintf(`#!ipxe
echo
echo %s loads about %d MB into RAM, but this machine reports only %d MB.
echo Booting it here would fail partway through the transfer.
prompt Press any key to return to the menu
chain %s/boot.ipxe
`, img.DisplayName, img.Plan.RAMLoadMB, memMB, base)
	}

	var b strings.Builder
	b.WriteString("#!ipxe\n")
	fmt.Fprintf(&b, "echo Booting %s via %s\n", img.DisplayName, img.Strategy)

	switch img.Strategy {
	case images.StrategyLinuxExtract:
		args := strings.NewReplacer("${ISOURL}", isoURL, "${CONTENT}", content).Replace(img.Plan.Args)
		if img.ExtraKernelArgs != "" {
			args += " " + img.ExtraKernelArgs
		}
		args += answerArgs(img.Plan.Family, answer, mac, base)
		fmt.Fprintf(&b, "kernel %s/%s %s\n", content, img.Plan.Kernel, args)
		for _, ird := range img.Plan.Initrds {
			fmt.Fprintf(&b, "initrd %s/%s\n", content, ird)
		}
		b.WriteString("boot || goto failed\n")

	case images.StrategyWimboot:
		// The Windows flow injects install.wim into client RAM (stock WinPE
		// has no HTTP downloader; wimboot file-injection is the SMB-free
		// path). install.wim is 4-6GB, so warn about RAM up front.
		if _, ok := img.Plan.Files["install"]; ok {
			b.WriteString("echo NOTE: Windows install loads sources into RAM - client needs RAM > ISO size\n")
		}
		imgBase := base + "/img/" + enc
		fmt.Fprintf(&b, "kernel %s/boot/wimboot\n", base)
		fmt.Fprintf(&b, "initrd -n winpeshl.ini %s/winpeshl.ini winpeshl.ini\n", imgBase)
		fmt.Fprintf(&b, "initrd -n install.bat %s/install.bat?answer=%v install.bat\n", imgBase, answer != "")
		if answer != "" {
			fmt.Fprintf(&b, "initrd -n autounattend.xml %s/answers/%s?mac=${net0/mac} autounattend.xml\n",
				base, url.PathEscape(answer))
		}
		if p, ok := img.Plan.Files["bcd"]; ok {
			fmt.Fprintf(&b, "initrd -n bcd %s/%s bcd\n", content, p)
		}
		if p, ok := img.Plan.Files["boot.sdi"]; ok {
			fmt.Fprintf(&b, "initrd -n boot.sdi %s/%s boot.sdi\n", content, p)
		}
		if p, ok := img.Plan.Files["install"]; ok {
			name := installName(p)
			fmt.Fprintf(&b, "initrd -n %s %s/%s %s\n", name, content, p, name)
		}
		if p, ok := img.Plan.Files["boot.wim"]; ok {
			fmt.Fprintf(&b, "initrd -n boot.wim %s/%s boot.wim\n", content, p)
		}
		b.WriteString("boot || goto failed\n")

	case images.StrategyMemdisk:
		// A standalone EFI application (memtest-style ISOs) chains directly
		// on UEFI — no RAM limit and none of sanboot's UEFI flakiness.
		if efi, ok := img.Plan.Files["efi"]; ok {
			fmt.Fprintf(&b, "iseq ${platform} efi && chain %s/%s ||\n", content, efi)
		}
		b.WriteString("echo Loading whole ISO into RAM (needs RAM larger than the ISO)...\n")
		fmt.Fprintf(&b, "sanboot %s || goto failed\n", isoURL)

	default:
		b.WriteString("echo No boot strategy for this image\ngoto failed\n")
	}

	fmt.Fprintf(&b, ":failed\necho Boot of this image failed.\nprompt Press any key to return to the menu\nchain %s/boot.ipxe\n", base)
	return b.String()
}

// answerArgs wires an Answer File into the kernel command line, per family.
// URLs must be absolute: they are fetched by the OS installer, not iPXE.
func answerArgs(family, answer string, mac net.HardwareAddr, base string) string {
	if answer == "" {
		return ""
	}
	enc := url.PathEscape(answer)
	switch family {
	case "ubuntu-casper":
		// Subiquity autoinstall via a NoCloud seed directory we synthesize.
		return fmt.Sprintf(" autoinstall ds=nocloud-net;s=%s/seed/%s/", base, enc)
	case "anaconda":
		return fmt.Sprintf(" inst.ks=%s/answers/%s?mac=%s", base, enc, mac.String())
	case "suse":
		return fmt.Sprintf(" autoyast=%s/answers/%s?mac=%s", base, enc, mac.String())
	default:
		return ""
	}
}

// winpeshlINI is injected into WinPE (wimboot places it in
// X:\Windows\System32, where it overrides the default shell startup).
const winpeshlINI = "[LaunchApps]\r\n\"install.bat\"\r\n"

// installName preserves the source extension: setup.exe treats .wim and
// .esd differently, so an .esd must stay an .esd.
func installName(sourcePath string) string {
	if strings.HasSuffix(strings.ToLower(sourcePath), ".esd") {
		return "install.esd"
	}
	return "install.wim"
}

// installBAT runs inside WinPE: initialize, then hand over to Windows Setup
// with the injected install source (and answer file when present).
func installBAT(installFile string, hasAnswer bool) string {
	var b strings.Builder
	b.WriteString("@echo off\r\n")
	b.WriteString("wpeinit\r\n")
	switch {
	case installFile != "" && hasAnswer:
		fmt.Fprintf(&b, "X:\\sources\\setup.exe /installfrom:X:\\Windows\\System32\\%s /unattend:X:\\Windows\\System32\\autounattend.xml\r\n", installFile)
	case installFile != "":
		fmt.Fprintf(&b, "X:\\sources\\setup.exe /installfrom:X:\\Windows\\System32\\%s\r\n", installFile)
	default:
		b.WriteString("echo No install image was injected; starting plain WinPE setup.\r\n")
		b.WriteString("X:\\sources\\setup.exe\r\n")
	}
	// If setup exits, drop to a shell rather than a black screen.
	b.WriteString("cmd.exe\r\n")
	return b.String()
}

// substituteAnswer performs the trivial Answer File substitutions
// (CONTEXT.md): ${mac}, ${site}, ${ip}.
func substituteAnswer(content []byte, site, mac, ip string) []byte {
	r := strings.NewReplacer("${mac}", mac, "${site}", site, "${ip}", ip)
	return []byte(r.Replace(string(content)))
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
