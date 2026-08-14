# CONTEXT

Project name: **Emberboot** — a PXE boot server built for unattended 24x7 operation on large multi-VLAN networks.

Glossary of domain terms for this project. Terms are canonical: use them exactly as defined here in code, docs, and discussion.

## Glossary

### Client
A physical or virtual machine on the network that PXE-boots against this server. Identified primarily by MAC address. A Client is *not* a user or an admin.

### Site
A physical location (office/campus) with its own LAN and its own running server instance. The org has 1–3 Sites. Clients at a Site boot from that Site's instance.

### Image
A bootable payload an admin provides — in v1, an arbitrary ISO file (Windows installer, Linux installer, rescue tool). Dropped into a folder, it becomes bootable with no conversion step. "Image" never means a disk backup or a container image here.

### Ready (Image state)
An Image is Ready only after it has been fully copied and validated (checksum/structure). Only Ready Images appear on a Boot Menu — a half-copied ISO is never offered to a Client.

### Override
A targeting rule that changes what a Client sees: by MAC or by subnet/VLAN, an Override replaces or restricts the global default Boot Menu. There is no auto-boot-without-menu; a human at the console always confirms.

### Boot Menu
The list of Images (and tools) presented to a Client at boot time.

### ProxyDHCP Mode
The default network posture: the server answers *only* the PXE portion of DHCP alongside the org's existing DHCP server, which remains untouched. The server is never the address-assigning DHCP owner.

### Options-66/67 Mode
The alternate posture: the org's existing DHCP server is configured with options 66/67 pointing Clients at this server. Required to work across DHCP relay / IP helpers on multi-VLAN networks.

### Concurrent Boot
Multiple Clients booting at the same time. Design target: 300 Concurrent Boots per Site (e.g. a lab powering on after an outage). The scale number that drives architecture.

### Boot Session
One Client's journey from first DHCP request to a fully loaded Image (or failure). The unit of observability: logs and status are grouped per Boot Session.

### Boot Strategy
The per-Image method Emberboot selects for delivering that Image to a Client, decided during validation and visible in the dashboard. One of: **LinuxExtract** (kernel/initrd extraction + the distro's own HTTP fetch), **Wimboot** (WinPE via wimboot + injected startup script pulling sources over HTTP), or **Memdisk** (whole ISO into Client RAM — the fallback for unrecognized ISOs). "This ISO won't work" is a validation result, never a mystery at the crash cart.

### Answer File
An unattended-install file (autounattend.xml, preseed, kickstart, autoinstall) attachable to an Image and overridable per-Override. Supports only trivial substitution: `${mac}`, `${hostname}`, `${site}`.

### Last-Known-Good
The config-reload contract: a new config that fails schema validation is rejected — the previous valid config keeps serving, and the rejection is logged, alerted, and shown in the dashboard. Invalid config never interrupts booting Clients.

### Rogue PXE Server
Any other machine on the network answering PXE/proxyDHCP requests (e.g. a forgotten WDS server). Emberboot detects these from the DHCP traffic it already listens to, and alerts.

## Settled scope boundaries

- Internal tool for one org (small IT team), not multi-tenant, not SaaS.
- Scale target: ~2,000 known Clients, 300 Concurrent Boots, 20+ VLANs, 1–3 Sites.
- Firmware matrix: UEFI x64 + legacy BIOS. Secure Boot supported honestly (documented cert/MOK enrollment or disabling SB) — no shim tricks. ARM64 out of scope.
- Diskless operation (Clients that *run* from the network 24x7) is explicitly out of scope; "24x7" refers to server availability.
- Core differentiators vs iVentoy: unattended reliability and observability. "Drop an ISO in a folder and it boots" is table stakes, not the differentiator.
- Ships as a single static cross-platform binary (Linux + Windows), Linux-first in production, container-shippable. Written in Go.
- Availability model: one hardened, supervised, crash-only instance per Site. No clustering/VIP in v1; no state that can't be rebuilt from files.
- Transport: TFTP serves only the tiny iPXE bootloader; everything after is HTTP (native UEFI HTTP Boot as a bonus path). Raw-TFTP payload delivery is out.
- Management: declarative config files + image folder are the source of truth, hot-reloaded. Web UI is a read-mostly ops dashboard; REST API for automation. No UI-as-editor, no opaque internal DB of config.
- Image distribution to Sites is the admin's job (rsync/robocopy/DFS-R); the server watches its local folder and validates.
- Observability: structured JSON logs, Prometheus /metrics, per-Boot-Session timelines, webhook alerts (LINE-Notify-friendly).
- Config: YAML with strict schema validation and Last-Known-Good reload semantics.
- ISO support: tiered Boot Strategies (LinuxExtract / Wimboot / Memdisk). An iVentoy-style universal virtual-disk driver is explicitly out of scope for v1.
- Auth: single admin credential + bearer tokens for the API; dashboard bindable to a management VLAN. No multi-user/RBAC/AD in v1 (seam left for later).
- Alert catalog (fixed, v1): crash-restart detected, Image failed validation, Boot Session failure-rate spike, image-volume disk space low, config rejected, Rogue PXE Server detected.
- Boot Session history: embedded SQLite as a disposable cache (90-day retention, size-capped). Deleting it loses history, never breaks booting.
