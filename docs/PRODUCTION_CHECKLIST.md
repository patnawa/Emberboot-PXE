# Production hardening and release checklist

Emberboot is a network-infrastructure service. Complete this checklist for
each Site and release; a successful build or an Image reaching `Ready` is not
by itself production approval.

## Release evidence

- [ ] The deployment comes from a reviewed, immutable commit and the daemon's
  `-version` output matches the intended release.
- [ ] GitHub Actions format, vet, unit, race, Linux/Windows build, production
  Dockerfile build, and `govulncheck` jobs are green. Any vulnerability finding
  is documented and dispositioned before release.
- [ ] Release binaries have published SHA-256 digests. The digest of the
  installed binary matches the release manifest.
- [ ] Embedded iPXE/wimboot hashes and licenses match
  [`internal/bootfiles/PROVENANCE.md`](../internal/bootfiles/PROVENANCE.md).
- [ ] A rollback binary and its compatible config backup are available at the
  Site before upgrading.

## Host and service

- [ ] Use a dedicated, patched Linux host or VM with a static IPv4 address,
  synchronized time, reliable storage, and enough disk/network headroom for
  the Site's boot storm.
- [ ] Install the systemd unit from [`deploy/emberboot.service`](../deploy/emberboot.service).
  It runs as a dynamic unprivileged user with only `CAP_NET_BIND_SERVICE` and
  `CAP_NET_RAW`, uses `LimitNOFILE=8192`, and keeps its writable source of truth
  under `/var/lib/emberboot`.
- [ ] Keep the state directory and config owner-only. The config and answer
  files can contain API tokens, unattended-install passwords, and other
  secrets; do not put them in world-readable backups or logs.
- [ ] `systemd-analyze security emberboot.service` has been reviewed on the
  target distribution, and `systemctl status emberboot` shows no sandbox or
  restart-loop failures.
- [ ] Storage monitoring covers both free bytes and inodes on the Image and
  state volumes. The configured low-space threshold leaves time to respond.

For a container deployment:

- [ ] Build with an immutable version, for example
  `docker build --build-arg VERSION=v0.6.0 -f deploy/Dockerfile .`, and verify
  the running daemon reports that value. Never publish a production image left
  at the default `VERSION=dev`.
- [ ] The runtime is the distroless `nonroot` image and runs as UID/GID 65532.
  Use host networking, `--cap-drop ALL`, then add only
  `NET_BIND_SERVICE` and `NET_RAW`; also use a read-only root filesystem and
  `no-new-privileges`. Do not run it privileged or as root.
- [ ] Persist the complete `/data` directory on owner-only storage writable by
  UID/GID 65532. It contains the config, Images, answers, boot-grant signing
  key, and session cache required across container replacements.
- [ ] The repository-root `.dockerignore` remains deny-by-default. Confirm that
  local ISOs, configs, databases, credentials, logs, and `.git` are absent from
  the build context and final image.

## Management-plane security

- [ ] First-run administration is done locally through
  `http://127.0.0.1:8443` or an SSH tunnel.
- [ ] Any non-loopback `dashboard_bind` has a valid TLS certificate/key and at
  least one admin password hash. Plaintext, anonymous, and token-only remote
  browser management are configuration errors; API tokens are adjunct
  credentials for automation.
- [ ] TCP 8443 is reachable only from the management VLAN or VPN. Boot Clients
  do not have a route or firewall permission to the management console.
- [ ] API tokens are unique per automation consumer, stored in a secret
  manager, and rotated on staff/tool changes. Removed tokens have been tested.
- [ ] Config/answer-file backups are encrypted and their restore permissions
  are verified.

## PXE and firewall policy

- [ ] `network.advertise_ip` is the server's reachable static IPv4 address,
  present on the intended interface and routable from every boot VLAN.
- [ ] Choose one tested DHCP posture. ProxyDHCP is for the local broadcast
  domain alongside the existing DHCP owner; relayed VLANs use the documented
  option 66/67/IP-helper design. Emberboot never allocates client addresses.
- [ ] Firewalls permit only the required paths: UDP 67/69/4011 for PXE/TFTP,
  TCP 8090 for boot HTTP, and TCP 8443 from management networks.
- [ ] The embedded iSCSI target has **no CHAP**. Every required boot VLAN is
  explicitly listed in `security.iscsi_allowed_subnets`, every other source is
  denied, and TCP 3260 is restricted to the same subnets upstream. Keep
  `network.iscsi_enabled: false` when unused; set it explicitly to `true` only
  after the allowlist and firewall are ready.
- [ ] Targeting/deny rules are treated as menu policy, not identity or network
  authorization. Firewall and management-plane controls remain authoritative.
- [ ] Rogue-PXE alerts have a monitored destination and the expected DHCP/PXE
  servers are documented.

## Image publication and compatibility

- [ ] Download media from the publisher and verify its signed or published
  digest before exposure. Emberboot records a full local SHA-256 for generation
  pinning and signed transport grants, but cannot establish publisher
  authenticity without comparing it to that trusted external value.
- [ ] Copy large media using a name that does not end in `.iso` (for example
  `.iso.partial`), verify the completed local digest, then atomically rename
  it to the final `.iso` name on the same filesystem.
- [ ] Each approved ISO/version has a recorded strategy, publisher digest,
  answer-file revision, firmware mode, NIC model, and successful end-to-end
  result. A structurally `Ready` Image is not automatically compatible.
- [ ] RAM estimates shown in the boot script are treated as advisory. The
  stock embedded iPXE build lacks `MEMMAP_SETTINGS`, so there is no automatic
  RAM gate; test RAM-loading strategies on the lowest-memory approved Client.
- [ ] Legacy BIOS and UEFI x64 paths are tested on representative Site
  hardware. Secure Boot is disabled: the embedded shim pair is not currently
  wired into the DHCP boot path.
- [ ] iSCSI Images are tested through installer handoff, not only until their
  bootloader/kernel starts. Many installers cannot reattach virtual media
  after taking over the NIC.
- [ ] Destructive answer files and rescue tools are restricted operationally,
  peer reviewed, and tested on sacrificial hardware before general exposure.

## Capacity and failure testing

- [ ] Define the Site SLO and test at or above its planned simultaneous-client
  count with representative payload sizes. The architectural target of 300
  Concurrent Boots is not a guarantee until this test passes on the actual
  storage, switching, relay, and firewall path.
- [ ] Start with `network.http_max_streams: 600` and
  `network.iscsi_max_connections: 768`, with their per-IP limits at 8. Tune
  only from measured demand, keep the combined ceiling comfortably below the
  process's 8,192 open-file limit, and leave capacity for listeners, database
  files, logs, and management requests.
- [ ] Record boot success rate, HTTP throughput/range behavior, disk latency,
  CPU, memory, open files, packet loss, and switch/uplink utilization during
  the test. Retain enough headroom for retries and non-PXE traffic.
- [ ] Exercise mixed BIOS/UEFI and mixed Image strategies concurrently, not
  just repeated downloads of one small ISO.
- [ ] Verify Last-Known-Good behavior with a deliberately invalid config,
  supervised restart after process failure, low-disk alerting, webhook failure
  behavior, retention/size cleanup, and recovery from a restored config plus
  Image folder.
- [ ] Confirm that a change reported by `/healthz` or Diagnostics as
  `restart_required` is scheduled and does not interrupt an active boot wave.
  Restart-bound settings are DHCP mode/interface/advertise IP; TFTP, boot-HTTP,
  dashboard, and iSCSI ports/binds/TLS; HTTP/iSCSI global and per-IP limits;
  iSCSI enablement; Image/answer directories; and session DB path, retention,
  and size. Hot reload does not move existing listeners or stores.

## Upgrade and rollback

- [ ] Drain or defer new boots, back up config/answers and the Image manifest,
  replace the binary atomically, then restart the service.
- [ ] Run `/healthz`, the console Diagnostics checks, a BIOS smoke boot, a UEFI
  smoke boot, and one boot for every production strategy after the upgrade.
- [ ] Watch logs, metrics, Boot Sessions, and alerts through the agreed
  observation window. Roll back the binary/config together if exit criteria
  fail; the disposable session database is not required to restore booting.
