# iPXE chainload transport instead of raw TFTP

Emberboot must survive 300 Concurrent Boots per Site, and raw TFTP (small block sizes, lock-step ACKs, UDP retransmit storms) collapses long before that. We decided TFTP serves exactly one thing — the ~100KB iPXE bootloader matched to the client's firmware — and iPXE immediately chainloads to HTTP for everything else: menus, kernels, WinPE, ISO content, answer files. Native UEFI HTTP Boot is a bonus path on firmware that supports it, since the HTTP side exists anyway.

**Consequences**: every boot is a two-stage handshake (firmware→TFTP→iPXE→HTTP), so DHCP must distinguish a first-stage firmware request from an iPXE re-request (user-class/option 77) or clients loop forever fetching iPXE. All payload-serving features (range requests, concurrency limits, session tracking) are built on the HTTP server only; TFTP stays deliberately dumb.
