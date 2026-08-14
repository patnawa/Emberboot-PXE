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
	StrategyMemdisk      Strategy = "memdisk" // iPXE sanboot http: whole ISO into RAM
	// StrategyISCSI serves the ISO as a virtual CD over the embedded iSCSI
	// target: full media emulation, no RAM limit — the honest tier-iii
	// (ADR-0003) for ISOs that cannot netboot any other way.
	StrategyISCSI Strategy = "iscsi"
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
	// Files maps auxiliary labels to in-ISO paths: wimboot pieces for
	// Windows, "efi" for a chainable standalone EFI application.
	Files map[string]string `json:"files,omitempty"`
	// RAMLoadMB estimates client RAM (MB) this image loads into memory
	// (ISO/squashfs/install.wim plus working margin). 0 = no RAM loading.
	// The boot script generator refuses clients below this with a clear
	// message instead of a mysterious mid-boot failure.
	RAMLoadMB int `json:"ram_load_mb,omitempty"`
}

// mb converts bytes to MB, rounding up.
func mb(bytes int64) int { return int((bytes + 1<<20 - 1) >> 20) }

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
			// boot.wim + install sources are injected into client RAM.
			plan.RAMLoadMB = mb(h.sizeOf(p)+h.sizeOf(bootWim)) + 1536
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
			RAMLoadMB: mb(sizeBytes) + 1536,
		}, "Ubuntu casper live detected; kernel/initrd extracted, ISO fetched over HTTP (needs client RAM > ISO size)", nil
	}

	// Debian-live family (Clonezilla, GParted, generic live-build).
	if kernel, ok := h.firstExisting("live/vmlinuz"); ok {
		initrd, ok2 := h.firstExisting("live/initrd.img")
		if !ok2 || !h.exists("live/filesystem.squashfs") {
			return "", BootPlan{}, "", fmt.Errorf("debian-live layout but initrd.img or filesystem.squashfs missing")
		}
		return StrategyLinuxExtract, BootPlan{
			Family:    "debian-live",
			Kernel:    kernel,
			Initrds:   []string{initrd},
			Args:      "boot=live union=overlay components noswap noprompt ip=dhcp fetch=${CONTENT}/live/filesystem.squashfs",
			RAMLoadMB: mb(h.sizeOf("live/filesystem.squashfs")) + 1024,
		}, "Debian-live detected (Clonezilla/GParted family); squashfs fetched over HTTP into RAM", nil
	}

	// Fedora/RHEL-family *live* ISOs (Workstation, KDE spins, Rescue):
	// dracut's livenet can fetch the whole ISO over HTTP via root=live:URL.
	// Must be checked before the Anaconda installer rule — live ISOs also
	// carry images/pxeboot/.
	if h.exists("LiveOS/squashfs.img") {
		kernel, ok := h.firstExisting("images/pxeboot/vmlinuz", "isolinux/vmlinuz")
		initrd, ok2 := h.firstExisting("images/pxeboot/initrd.img", "isolinux/initrd.img")
		if !ok || !ok2 {
			return "", BootPlan{}, "", fmt.Errorf("LiveOS layout but no pxeboot kernel/initrd found")
		}
		return StrategyLinuxExtract, BootPlan{
			Family:    "dracut-live",
			Kernel:    kernel,
			Initrds:   []string{initrd},
			Args:      "root=live:${ISOURL} rd.live.image ip=dhcp",
			RAMLoadMB: mb(sizeBytes) + 1024,
		}, "Fedora/RHEL-family live image detected (LiveOS); dracut fetches the ISO over HTTP into RAM", nil
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
				Family:    "archiso",
				Kernel:    kernel,
				Initrds:   initrds,
				Args:      fmt.Sprintf("archisobasedir=%s archiso_http_srv=${CONTENT}/ ip=dhcp checksum", base),
				RAMLoadMB: mb(h.sizeOf(base+"/x86_64/airootfs.sfs")) + 1024,
			}, "archiso detected (" + base + "); rootfs squashfs fetched over HTTP", nil
		}
	}

	// Alpine Linux standard ISO: extracted kernel/initramfs plus the modloop
	// served out of the ISO; packages come from the online mirror.
	if kernel, ok := h.firstExisting("boot/vmlinuz-lts", "boot/vmlinuz-virt"); ok {
		flavor := "lts"
		if strings.HasSuffix(kernel, "virt") {
			flavor = "virt"
		}
		initrd, ok2 := h.firstExisting("boot/initramfs-" + flavor)
		if ok2 {
			return StrategyLinuxExtract, BootPlan{
				Family:  "alpine",
				Kernel:  kernel,
				Initrds: []string{initrd},
				Args: fmt.Sprintf("modloop=${CONTENT}/boot/modloop-%s alpine_repo=https://dl-cdn.alpinelinux.org/alpine/latest-stable/main ip=dhcp",
					flavor),
			}, "Alpine Linux detected; modloop served from the ISO, packages from the online mirror (needs internet)", nil
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

	// Debian installer ISOs cannot netboot from their own initrd (it only
	// mounts local media) — exactly what the iSCSI virtual CD provides.
	if h.exists("install.amd/vmlinuz") || h.exists("install.386/vmlinuz") {
		return StrategyISCSI, BootPlan{Family: "debian-installer"},
			"Debian installer ISO: served as a virtual CD over iSCSI. The bootloader stage works; " +
				"d-i itself may still fail to find its CD (its media detection runs before iSCSI login) — " +
				"Debian netboot images with a mirror are the reliable route", nil
	}

	// Proxmox VE: no netboot support in the ISO; iSCSI media emulation is
	// the only in-place chance, and its installer initrd has no iSCSI
	// support to reattach with.
	if h.exists("boot/linux26") {
		return StrategyISCSI, BootPlan{Family: "proxmox"},
			"Proxmox VE ISO: served as a virtual CD over iSCSI. The loader boots, but the Proxmox " +
				"installer cannot reattach to iSCSI media — expect it to stall; USB install remains the " +
				"supported route", nil
	}

	// Fallback for everything unrecognized (BSDs, appliances, old tools):
	// virtual CD over iSCSI — full media emulation, no RAM limit. A
	// standalone EFI application (memtest-style) is still chained directly
	// on UEFI, and sanboot-into-RAM remains the last resort in the script.
	plan := BootPlan{Family: "unknown", RAMLoadMB: mb(sizeBytes) + 512}
	reason := "unrecognized layout; served as a virtual CD over iSCSI (Memdisk as last resort)"
	if sizeBytes < 128<<20 {
		if efi, ok := h.firstExisting("EFI/BOOT/BOOTX64.EFI", "efi/boot/bootx64.efi"); ok {
			plan.Files = map[string]string{"efi": efi}
			reason += "; UEFI clients chain the ISO's standalone EFI application directly"
		}
	}
	return StrategyISCSI, plan, reason, nil
}

// friendlyName derives a menu label from an ISO file name:
// "ubuntu-24.04-live-server-amd64.iso" -> "ubuntu 24.04 live server amd64".
func friendlyName(fileName string) string {
	name := strings.TrimSuffix(fileName, ".iso")
	name = strings.TrimSuffix(name, ".ISO")
	name = strings.NewReplacer("_", " ", "-", " ").Replace(name)
	return name
}
