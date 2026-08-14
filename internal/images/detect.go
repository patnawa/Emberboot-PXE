package images

import (
	"fmt"
	"strings"
)

// Strategy is the Boot Strategy (CONTEXT.md): how Emberboot delivers an
// Image to a Client.
type Strategy string

const (
	StrategyLinuxExtract Strategy = "linux-extract"
	StrategyWimboot      Strategy = "wimboot"
	StrategyMemdisk      Strategy = "memdisk" // iPXE sanboot: whole ISO into RAM
)

// BootPlan holds everything the HTTP boot-script generator needs, resolved
// against the actual ISO contents at validation time. Paths are in-ISO paths
// with their detected canonical casing. Args may contain the placeholders
// ${ISOURL} (URL of the raw ISO) and ${CONTENT} (URL prefix serving the ISO's
// internal tree), expanded at script-generation time.
type BootPlan struct {
	Family  string            `json:"family"`
	Kernel  string            `json:"kernel,omitempty"`
	Initrds []string          `json:"initrds,omitempty"`
	Args    string            `json:"args,omitempty"`
	// Files maps wimboot initrd labels to in-ISO paths (Windows only).
	Files map[string]string `json:"files,omitempty"`
}

// detect inspects an open ISO and picks the Boot Strategy per family
// (ADR-0003). It returns a human-readable reason with the outcome — shown in
// the dashboard so "why did this ISO get strategy X" is never a mystery.
func detect(h *isoHandle, sizeBytes int64) (Strategy, BootPlan, string, error) {
	// Windows installer: /sources/boot.wim is the definitive marker.
	if bootWim, ok := h.firstExisting("sources/boot.wim"); ok {
		plan := BootPlan{
			Family: "windows",
			Files:  map[string]string{"boot.wim": bootWim},
		}
		// Optional but recommended companions (case varies between ISOs).
		if p, ok := h.firstExisting("boot/bcd", "Boot/BCD", "boot/BCD"); ok {
			plan.Files["bcd"] = p
		}
		if p, ok := h.firstExisting("boot/boot.sdi", "Boot/boot.sdi"); ok {
			plan.Files["boot.sdi"] = p
		}
		if p, ok := h.firstExisting("bootmgr"); ok {
			plan.Files["bootmgr"] = p
		}
		if p, ok := h.firstExisting("sources/install.wim", "sources/install.esd"); ok {
			plan.Files["install"] = p
		}
		return StrategyWimboot, plan, "Windows installer detected (sources/boot.wim); wimboot with HTTP sources", nil
	}

	// Ubuntu / casper live: fetches the whole ISO into RAM via url=.
	if kernel, ok := h.firstExisting("casper/vmlinuz", "casper/hwe-vmlinuz"); ok {
		initrd, ok2 := h.firstExisting("casper/initrd", "casper/initrd.lz", "casper/hwe-initrd")
		if !ok2 {
			return "", BootPlan{}, "", fmt.Errorf("casper layout but no initrd found under /casper")
		}
		// ramdisk must hold the whole ISO: size in KB plus working margin.
		ramdiskKB := sizeBytes/1024 + 512*1024
		return StrategyLinuxExtract, BootPlan{
			Family:  "ubuntu-casper",
			Kernel:  kernel,
			Initrds: []string{initrd},
			Args: fmt.Sprintf("root=/dev/ram0 ramdisk_size=%d ip=dhcp url=${ISOURL} cloud-config-url=/dev/null",
				ramdiskKB),
		}, "Ubuntu casper live detected; kernel/initrd extracted, ISO fetched over HTTP (needs client RAM > ISO size)", nil
	}

	// Debian-live family (Clonezilla, GParted, generic live-build).
	if kernel, ok := h.firstExisting("live/vmlinuz"); ok {
		initrd, ok2 := h.firstExisting("live/initrd.img")
		if !ok2 || !h.exists("live/filesystem.squashfs") {
			return "", BootPlan{}, "", fmt.Errorf("debian-live layout but initrd.img or filesystem.squashfs missing")
		}
		return StrategyLinuxExtract, BootPlan{
			Family:  "debian-live",
			Kernel:  kernel,
			Initrds: []string{initrd},
			Args:    "boot=live union=overlay components noswap noprompt ip=dhcp fetch=${CONTENT}/live/filesystem.squashfs",
		}, "Debian-live detected (Clonezilla/GParted family); squashfs fetched over HTTP into RAM", nil
	}

	// archiso (Arch Linux) and SystemRescue (archiso-based, different basedir).
	for _, base := range []string{"arch", "sysresccd"} {
		kernelCandidates := []string{
			base + "/boot/x86_64/vmlinuz-linux", // Arch
			base + "/boot/x86_64/vmlinuz",       // SystemRescue
		}
		if kernel, ok := h.firstExisting(kernelCandidates...); ok {
			initrd, ok2 := h.firstExisting(
				base+"/boot/x86_64/initramfs-linux.img",
				base+"/boot/x86_64/sysresccd.img",
			)
			if !ok2 {
				return "", BootPlan{}, "", fmt.Errorf("archiso layout (%s) but no initramfs found", base)
			}
			initrds := []string{}
			for _, ucode := range []string{base + "/boot/intel-ucode.img", base + "/boot/amd-ucode.img"} {
				if h.exists(ucode) {
					initrds = append(initrds, ucode)
				}
			}
			initrds = append(initrds, initrd)
			return StrategyLinuxExtract, BootPlan{
				Family:  "archiso",
				Kernel:  kernel,
				Initrds: initrds,
				Args:    fmt.Sprintf("archisobasedir=%s archiso_http_srv=${CONTENT}/ ip=dhcp checksum", base),
			}, "archiso detected (" + base + "); rootfs squashfs fetched over HTTP", nil
		}
	}

	// Anaconda (Fedora/RHEL/Rocky/Alma): needs a served tree, never a raw ISO.
	if kernel, ok := h.firstExisting("images/pxeboot/vmlinuz"); ok {
		initrd, ok2 := h.firstExisting("images/pxeboot/initrd.img")
		if !ok2 {
			return "", BootPlan{}, "", fmt.Errorf("anaconda layout but images/pxeboot/initrd.img missing")
		}
		return StrategyLinuxExtract, BootPlan{
			Family:  "anaconda",
			Kernel:  kernel,
			Initrds: []string{initrd},
			Args:    "inst.repo=${CONTENT} ip=dhcp",
		}, "Anaconda installer detected (Fedora/RHEL family); ISO tree served over HTTP as inst.repo", nil
	}

	// openSUSE/SLES linuxrc: install= accepts a raw ISO URL directly.
	if kernel, ok := h.firstExisting("boot/x86_64/loader/linux"); ok {
		initrd, ok2 := h.firstExisting("boot/x86_64/loader/initrd")
		if !ok2 {
			return "", BootPlan{}, "", fmt.Errorf("suse layout but boot/x86_64/loader/initrd missing")
		}
		return StrategyLinuxExtract, BootPlan{
			Family:  "suse",
			Kernel:  kernel,
			Initrds: []string{initrd},
			Args:    "install=${ISOURL} netsetup=dhcp",
		}, "openSUSE/SLES linuxrc detected; installer fetches the ISO over HTTP", nil
	}

	// Debian installer ISOs are explicitly not netbootable from the ISO's own
	// initrd (cdrom-flavored d-i). Detect and explain rather than misboot.
	if h.exists("install.amd/vmlinuz") || h.exists("install.386/vmlinuz") {
		return StrategyMemdisk, BootPlan{Family: "debian-installer"},
			"Debian installer ISO: its initrd only mounts local media, so falling back to Memdisk " +
				"(needs client RAM > ISO size); consider Debian netboot images or a preseed mirror instead", nil
	}

	// Fallback: Memdisk (iPXE sanboot, whole ISO into RAM). Works for many
	// utility ISOs; requires client RAM > ISO size and, on UEFI, an ISO with
	// an EFI El Torito entry.
	return StrategyMemdisk, BootPlan{Family: "unknown"},
		"unrecognized layout; falling back to Memdisk (whole ISO into client RAM via iPXE sanboot)", nil
}

// friendlyName derives a menu label from an ISO file name:
// "ubuntu-24.04-live-server-amd64.iso" -> "ubuntu 24.04 live server amd64".
func friendlyName(fileName string) string {
	name := strings.TrimSuffix(fileName, ".iso")
	name = strings.TrimSuffix(name, ".ISO")
	name = strings.NewReplacer("_", " ", "-", " ").Replace(name)
	return name
}
