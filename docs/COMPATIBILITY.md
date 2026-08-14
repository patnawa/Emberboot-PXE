# OS / image compatibility

What happens when you drop an ISO into the images folder. The chosen Boot
Strategy and the reason for it are always shown in the console (Images →
click the image), so this table is the reference, not a guessing game.

Every RAM-loading image is guarded: a client that reports less RAM than the
image needs gets a clear on-screen message and returns to the menu instead
of dying mid-transfer.

| Family (detected by content) | Examples | How it boots | Needs |
|---|---|---|---|
| **windows** | Windows 10/11, Server 2016–2025 installers | wimboot → WinPE with injected `winpeshl.ini`/`install.bat`; `install.wim`/`.esd` delivered over HTTP into RAM; `setup.exe /installfrom` (+ `/unattend` when an answer file is assigned) | Client RAM > ISO size (typically 8 GB+) |
| **ubuntu-casper** | Ubuntu desktop/server 20.04+, Mint, most Ubuntu derivatives | kernel/initrd extracted; casper fetches the whole ISO over HTTP (`url=`); autoinstall via assigned answer file (NoCloud seed) | Client RAM > ISO size |
| **debian-live** | Clonezilla Live, GParted Live, Kali Live, live-build images | kernel/initrd extracted; squashfs fetched over HTTP (`fetch=`) | Client RAM > squashfs size |
| **dracut-live** | Fedora Workstation/KDE live, RHEL-family live/rescue images | kernel/initrd extracted; dracut livenet fetches the ISO over HTTP (`root=live:`) | Client RAM > ISO size |
| **anaconda** | Fedora Server, RHEL, Rocky, Alma, CentOS Stream DVD installers | kernel/initrd extracted; the ISO's package tree served over HTTP as `inst.repo=`; kickstart via assigned answer file | Low RAM (tree is streamed, not RAM-loaded). DVD ISOs install fully offline; boot/netinstall ISOs need a reachable repo |
| **suse** | openSUSE Leap, SLES (15 and older) | kernel/initrd extracted; linuxrc fetches the raw ISO (`install=`); AutoYaST via assigned answer file | Moderate RAM. SLES 16 / Leap 16 (Agama) not yet auto-detected |
| **archiso** | Arch Linux, SystemRescue, EndeavourOS | kernel/initrd (+ microcode) extracted; `airootfs.sfs` fetched over HTTP with checksum verification | Client RAM > rootfs size |
| **alpine** | Alpine standard/virt ISOs | kernel/initrd extracted; modloop served from the ISO; packages from the official mirror | Internet access from the client |
| **debian-installer** | Debian netinst/DVD | **Virtual CD over the embedded iSCSI target**: iPXE attaches the LUN (`sanboot --keep`), boots the installer, and the iBFT lets the OS reattach to its media. No RAM limit | Reachable TCP 3260 from the client VLAN |
| **proxmox** | Proxmox VE | Virtual CD over iSCSI (Proxmox has no direct netboot support) | Reachable TCP 3260 |
| **unknown (iSCSI virtual CD)** | BSDs (pfSense/OPNsense/FreeBSD), appliances, DOS/firmware utilities, anything unrecognized | Virtual CD over iSCSI, full media emulation. Small ISOs carrying a standalone EFI app (memtest86+ style) chain it directly on UEFI. Whole-ISO-into-RAM (`sanboot` http) remains the scripted last resort | Reachable TCP 3260; OS-side reattach support varies (see note) |

**iSCSI reattach note**: iPXE's `--keep` registers the session in the iBFT.
Bootloaders and kernels always read the virtual CD fine; whether the *OS
installer* can keep using it after taking over the NIC varies (Debian d-i
loads iSCSI support, BSD loaders read the whole kernel before takeover).
When an installer loses its media mid-way, the fallback is the RAM-load
path or a family-specific strategy. The dashboard's session timeline shows
exactly how far each attempt got.

## Firmware

- **Legacy BIOS** and **UEFI x64**: fully supported (auto-detected per client, correct iPXE served).
- **UEFI IA32**: bootloader served; same strategies apply.
- **Secure Boot**: enroll the embedded shim pair (`shimx64.efi` + `snponly-sb.efi`) per your firmware's procedure, or disable Secure Boot. No signature tricks.
- **Native UEFI HTTP Boot**: supported where firmware offers it (no TFTP involved).
- **ARM64**: out of scope in v1.

## Forcing a strategy

Detection can be overridden per image in the console (Images → Boot
strategy) or in `emberboot.yaml` (`images.attach.<file>.strategy`) — useful
for exotic remixes that structure-match the wrong family.
