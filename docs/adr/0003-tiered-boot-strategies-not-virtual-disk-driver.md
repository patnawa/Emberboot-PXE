# Tiered Boot Strategies instead of a universal virtual-disk driver

iVentoy's "literally any ISO boots" magic is a signed Windows kernel driver that presents the remote ISO as local media — months of driver development, a code-signing certificate, and the exact closed-source moat (and Secure Boot controversy) we are escaping. We decided on tiered Boot Strategies chosen per-Image at validation time: **LinuxExtract** (kernel/initrd extraction + the distro's own HTTP-fetch mechanism), **Wimboot** (WinPE via wimboot + injected startup script pulling install sources over HTTP), and **Memdisk** (whole ISO into client RAM) as the fallback for unrecognized ISOs. This covers the ~95% an IT team actually boots, and the chosen strategy — or "this ISO won't work, here's why" — is a visible validation result in the dashboard.

**Considered options**: tier (iii), the universal virtual-disk driver, is explicitly out of scope for v1 — not rejected forever, but it must never be a prerequisite for core value.

**Consequences**: some exotic ISOs genuinely won't boot (RAM smaller than ISO under Memdisk); this is a documented, visible limitation rather than a silent failure.
