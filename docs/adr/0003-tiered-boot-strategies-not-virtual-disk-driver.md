# Tiered Boot Strategies instead of a universal virtual-disk driver

iVentoy's "literally any ISO boots" magic is a signed Windows kernel driver that presents the remote ISO as local media — months of driver development, a code-signing certificate, and the exact closed-source moat (and Secure Boot controversy) we are escaping. We decided on tiered Boot Strategies chosen per-Image at validation time: **LinuxExtract** (kernel/initrd extraction + the distro's own HTTP-fetch mechanism), **Wimboot** (WinPE via wimboot + injected startup script pulling sources over HTTP), **Memdisk** (the legacy identifier for an iPXE HTTP SAN virtual CD backed by Range requests), and **iSCSI** (a read-only virtual CD exposed by the server). The chosen strategy and its reason are visible validation results in the dashboard.

**Considered options**: a universal client-side virtual-disk driver is
explicitly out of scope for v1 — not rejected forever, but it must never be a
prerequisite for core value. The iSCSI target is not equivalent: the installer
OS must support iBFT/media reattachment, it has no CHAP, and its TCP listener
must be limited by Emberboot's subnet allowlist and upstream firewall.

**Consequences**: some exotic ISOs genuinely will not boot (for example, an
HTTP-SAN-incompatible firmware/OS or an installer that cannot reattach its
iSCSI media). The `memdisk` name does not invoke MEMDISK or copy the ISO into
RAM. Detection constructs a plausible plan; the Site hardware/ISO matrix and
capacity target still require release qualification.
