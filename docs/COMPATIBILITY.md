# OS / image compatibility

What happens when you drop an ISO into the images folder. The chosen Boot
Strategy and the reason for it are always shown in the console (Images →
click the image), so this table is the reference, not a guessing game.

Detection proves that Emberboot can parse the media and construct a boot
plan. It does not prove every ISO release, firmware, NIC, or installer second
stage. Qualify the exact combinations used at a Site and record them in the
production release checklist. Emberboot calculates and records a full local
SHA-256 for generation pinning and signed transport grants. That proves which
local bytes a Boot Session selected; it does not establish vendor authenticity
because Emberboot does not have a trusted publisher digest to compare. Publish
with a temporary non-`.iso` name, verify the publisher's signed/published value
yourself, then atomically rename on the same filesystem.

RAM-loading strategies show an estimated requirement before boot. The stock
embedded iPXE binaries do not expose `MEMMAP_SETTINGS`, so Emberboot cannot
reliably discover Client RAM and does not automatically reject an undersized
machine. Treat the message as an operator check and qualify representative
hardware; a transfer can still fail if the Client lacks memory.

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
| **debian-installer** | Debian netinst/DVD | **Virtual CD over the embedded iSCSI target**: iPXE attaches the LUN (`sanboot --keep`), boots the installer, and the iBFT lets a capable OS reattach to its media. No RAM limit | Client subnet listed in `security.iscsi_allowed_subnets`; TCP 3260 allowed only from that boot VLAN |
| **proxmox** | Proxmox VE | Virtual CD over iSCSI (Proxmox has no direct netboot support) | Client subnet allowlisted; TCP 3260 restricted at the firewall |
| **unknown (virtual CD)** | BSDs (pfSense/OPNsense/FreeBSD), appliances, DOS/firmware utilities, anything unrecognized | Virtual CD over iSCSI, with an HTTP SAN virtual-CD fallback backed by HTTP Range reads. Small ISOs carrying a standalone EFI app (memtest86+ style) chain it directly on UEFI. The legacy `memdisk` strategy identifier selects HTTP SAN; it is not MEMDISK and does not copy the whole ISO into RAM | iSCSI must be enabled and the Client subnet allowlisted; OS-side reattach support varies (see note) |

**iSCSI reattach — what actually survives the OS taking over the NIC**
(iPXE's `--keep` registers the session in the iBFT; the OS must re-login
from that):

- **Windows Setup: supported path; qualify each NIC/ISO combination.** WinPE's `wpeinit` reads the iBFT,
  re-logs into the target, and the virtual DVD appears as a drive letter —
  the full Setup GUI runs from it. Requirement: `boot.wim` must contain a
  driver for the machine's NIC (slipstream with DISM if not). This makes
  `iscsi` a deliberate **low-RAM alternative for Windows installs** — force
  it per-image when clients lack the RAM for the wimboot injection path.
- **Debian d-i: bootloader yes, installer usually no** — d-i's media
  detection runs before iSCSI login. Its iBFT support targets *destination
  disks*, not the install CD. Use Debian netboot images + mirror instead.
- **Proxmox, FreeBSD/pfSense/OPNsense installers: no** — their install
  initrds/loaders have no iBFT reattach. The loader and kernel still boot
  from the virtual CD; the installer then stalls looking for media.

When the second stage loses its virtual media, use a family-specific netboot
strategy or media designed for that installer's network path. The HTTP SAN
fallback does not create an OS driver and therefore cannot guarantee reattach.
The dashboard's session timeline shows exactly how far each attempt got.

The target deliberately implements no CHAP. `security.iscsi_allowed_subnets`
is therefore mandatory for forced iSCSI strategies. iSCSI is disabled in the
secure default example; production configurations should set
`network.iscsi_enabled: true` explicitly, and an upstream or host firewall
must restrict TCP 3260 to the same boot VLANs. Treat targeting rules as menu
policy, not as a security boundary.

## Firmware

- **Legacy BIOS** and **UEFI x64**: implemented (auto-detected per client,
  correct iPXE served); qualify the Site's actual firmware/NIC matrix.
- **UEFI IA32**: bootloader served; same qualification requirement applies.
- **Secure Boot**: **not currently wired into the DHCP boot path.** The
  embedded `shimx64.efi` + `snponly-sb.efi` pair is reserved for a future,
  explicitly tested chain. Disable Secure Boot on Emberboot Clients for now.
- **Native UEFI HTTP Boot**: supported where firmware offers it (no TFTP involved).
- **ARM64**: out of scope in v1.

## Forcing a strategy

Detection can be overridden per image in the console (Images → Boot
strategy) or in `emberboot.yaml` (`images.attach.<file>.strategy`) — useful
for exotic remixes that structure-match the wrong family. The accepted legacy
value `memdisk` means an HTTP SAN virtual CD using Range requests; it does not
load the complete ISO into RAM. A forced `iscsi` strategy requires the listener
and Client subnet allowlist described above.
