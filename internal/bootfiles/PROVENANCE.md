# Boot binary provenance

All third-party binaries embedded in Emberboot, with exact upstream sources.
Emberboot itself never modifies these files.

## iPXE v2.0.0 (released 2026-03-06)

Source: `https://github.com/ipxe/ipxe/releases/download/v2.0.0/ipxeboot.tar.gz`
Corresponding source code: `https://github.com/ipxe/ipxe/archive/refs/tags/v2.0.0.tar.gz`
License: GPLv2 (some files BSD/UBDL). Embedding is aggregation, not linking;
if Emberboot binaries are distributed outside the org, ship this notice and a
copy of / link to the corresponding source above.

| Embedded name | Archive path | SHA-256 |
|---|---|---|
| undionly.kpxe | ipxeboot/x86_64/undionly.kpxe | 4186562D21FF54E970D905751C9F36D628E73A51A94AFE4A6A42F925B0DF448C |
| snponly.efi | ipxeboot/x86_64/snponly.efi | F61C2CE34E05D7D857633DF2E512D547DF75B6AA18B2DA152A7C9AF222CFE28F |
| ipxe.efi | ipxeboot/x86_64/ipxe.efi | 868AA34057FF416EBF2FDFB5781DE035E2C540477C04039198A9F8A9C6130034 |
| ipxe32.efi | ipxeboot/i386/ipxe.efi | EA63C6D3745E751E8DB4F9C8D4C97EFA883FB6D0FC57C697B3D13AD98C1BFE0C |
| shimx64.efi | ipxeboot/x86_64-sb/shimx64.efi | 83AD71C7D4F2CF328B75B653D09BF3BEA5F29BEE2E67CA058F37D83C07133885 |
| snponly-sb.efi | ipxeboot/x86_64-sb/snponly.efi | B1E67C3E4A1E8708DDFD0079AD4505E3A02245ACB55EE9A95437AB3C507BE82A |

The `-sb` pair is embedded for the future Secure Boot path (shim + matching
iPXE). Not wired into DHCP responses in v1; see docs for the honest Secure
Boot stance (enroll or disable).

## wimboot v2.9.0 (released 2025-11-17)

Source: `https://github.com/ipxe/wimboot/releases/download/v2.9.0/wimboot`
Corresponding source code: `https://github.com/ipxe/wimboot/archive/refs/tags/v2.9.0.tar.gz`
License: GPL-2.0.

| Embedded name | SHA-256 |
|---|---|
| wimboot | 5F067CCDC4D084D5BF77B6C853BD0F8402DFC2B4CD1B103D358993AE97FAE8E3 |
