# secubox-netboot

Network boot and provisioning for GlobalScale MOCHAbin (Armada 7040) and
ESPRESSObin v7/Ultra (Armada 3720) appliances running SecuBox-Deb.

The **server** (gk2) stays at B0 — it only serves artifacts. Boot overlays
and flashing happen on the device under test (DUT) only, with explicit
operator confirmation.

---

## Boot Levels

| Level | Source | Integrity | When |
|-------|--------|-----------|------|
| **B0 — Local** | eMMC/SD (factory) | — | Server (gk2) default; untouched |
| **B1 — TFTP raw** | TFTP | none (trusted LAN) | Chain-proof / bench test |
| **B2 — HTTP signed** | HTTP `boot.fit` | **FIT signature** (verified by `bootm`) | Production: integrity from signature, not transport |
| **B3 — Installer** | B2 + release image | FIT + detached image sig | Provisioning: download → verify → write eMMC → reboot |

B0 is the default. A board opts into a network level through its profile.
B2 is the production target: plain HTTP is acceptable because integrity is
guaranteed by the FIT signature, not the transport.

---

## Enhanced Tow-Boot (#748)

Factory U-Boot (2020.10 on MOCHAbin) lacks `wget`, making HTTP netboot
impossible without a bootloader upgrade.

The solution is a **chainloaded overlay**: a second U-Boot built from
[Tow-Boot](https://tow-boot.org) (SecuBox fork) with `CONFIG_CMD_WGET`,
`CONFIG_FIT_SIGNATURE`, DHCP, and `booti` enabled, packaged as a signed FIT
and loaded **into RAM only** — the SPI firmware is never touched in this phase.

### Chainload flow

```
BootROM → TF-A (SPI mtd0) → U-Boot FACTORY (SPI mtd0)
                                  │  bootcmd redirected (overlay active)
                                  ▼
                     load /boot/sbx-uboot.fit  [signed, RAM only]
                                  │  bootm → go
                                  ▼
                         U-Boot OVERLAY (RAM)  — wget / FIT-sig / menu
                                  │  executes /boot/sbx-boot.scr
                                  ▼
                DHCP → HTTP boot.fit (B2) | TFTP Image (B1 fallback)
                     → bootm verifies FIT signature → booti
```

### Anti-brick safeguard

`bootcmd` is wrapped with `bootcount`/`altbootcmd`:

- If the overlay fails to load or the FIT signature check fails, execution
  falls through to `factory_bootcmd` immediately.
- If the OS fails to confirm health (`bootcount=0`) within 3 attempts,
  `altbootcmd` restores the factory boot automatically — no serial
  intervention required.
- Manual rollback: `secubox-netboot-overlay revert --commit`.

### Building the Tow-Boot overlay (#748)

Requires a host with [Nix](https://nixos.org/nix/):

```bash
cd tools/Tow-Boot
sg nix-users -c "nix-build -A globalscale-mochabin-8gb"
# outputs: result/Tow-Boot.spi.bin  result/u-boot.bin
```

Wrap the output into a signed chainload FIT:

```bash
packages/secubox-netboot/scripts/build-uboot-overlay.sh \
  --board mochabin \
  --tow-boot result/ \
  --key-dir /etc/secubox/netboot/keys \
  --out /var/lib/secubox/netboot/staging/overlay
```

Overlay load address: `OVERLAY_LOAD=0x06000000` (mochabin, validated).
Outputs: `sbx-uboot.fit` (signed), `sbx-boot.scr` (chainload script).

`Tow-Boot.spi.bin` is also produced for optional SPI flashing (opt-in,
operator-confirmed — see serial flasher below).

---

## Serial Flasher (#748, planned)

For boards where the factory bootloader cannot chainload at all, SecuBox
netboot will include a **UART push** path using the Marvell BootROM:

- Armada 7040/8040 (MOCHAbin): `mvebu64boot`
- Armada 3720 (ESPRESSObin v7/Ultra): `kwboot`

This bootstraps the enhanced Tow-Boot over serial before any network boot is
possible. Implementation is gated on HW validation (Phase 2 serial flasher
CLI in `sbin/`).

---

## Artifact Paths

```
/srv/secubox/netboot/
├── tftp/<id>/          TFTP root per board (by MAC): Image, board.dtb, initrd.img
├── http/<id>/          HTTP root per board: boot.fit (signed)
└── http/overlay-<board>/  overlay sbx-uboot.fit + sbx-boot.scr
```

`<id>` is the board MAC address (e.g. `00504384fb2f` for c3q).

HTTP boot vhost listens on **`:8099` only** — never `:80`.

Config: `/etc/secubox/netboot.toml`

---

## Commands

```bash
# Activate server role (TFTP + nginx boot vhost)
secubox-netboot-serve up
secubox-netboot-serve status

# Probe local board: U-Boot version, capabilities, env layout, boot media
secubox-netboot-probe

# Publish signed artifacts for a DUT
secubox-netboot-publish --id <MAC> --sign \
    --kernel /boot/Image --dtb /boot/armada-7040-mochabin.dtb \
    --initrd <installer.initrd> --addrs board/mochabin/addrs.env

# Publish an overlay (Tow-Boot chainload)
secubox-netboot-publish --id overlay-mochabin \
    --overlay-fit staging/sbx-uboot.fit --scr staging/sbx-boot.scr

# Apply overlay (dry-run by default; --confirm=true to commit)
secubox-netboot-overlay apply [--commit]
secubox-netboot-overlay status
secubox-netboot-overlay confirm-healthy   # reset bootcount after healthy boot
secubox-netboot-overlay revert --commit   # restore factory bootcmd

# Lifecycle hooks
secubox-netboot-triggers <event>
```

---

## REST API

Socket: `/run/secubox/netboot.sock` (standalone, never in-process aggregator).
All endpoints require JWT (`Authorization: Bearer <token>`).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/netboot/health` | Public health check |
| GET | `/api/v1/netboot/probe` | Board capabilities (read-only) |
| GET | `/api/v1/netboot/status` | Overlay state, bootcount, backup |
| GET | `/api/v1/netboot/inventory` | Board + overlay combined view |
| GET | `/api/v1/netboot/images` | Signed release image catalog |
| GET | `/api/v1/netboot/audit` | Append-only audit log |
| POST | `/api/v1/netboot/overlay/apply` | Apply overlay (`confirm=true` to commit) |
| POST | `/api/v1/netboot/overlay/revert` | Revert to factory bootcmd |
| POST | `/api/v1/netboot/overlay/persist` | Lock overlay as permanent boot |
| POST | `/api/v1/netboot/overlay/confirm-healthy` | Mark boot healthy (bootcount=0) |

---

## Key Configuration (`/etc/secubox/netboot.toml`)

```toml
[server]
http_base = "http://boot.gk2.secubox.in:8099"
tftp_root = "/srv/secubox/netboot/tftp"

[overlay]
max_tries = 3           # bootcount before auto-rollback to factory
key_hint  = "secubox-netboot"

[security]
require_signed_fit = true   # refuse unsigned overlay
confirm_required   = true   # all overlay/flash actions need confirm=true
```

---

## Security Constraints

- Boot vhost on `:8099` only — not routed through WAF (FIT signature is the
  integrity mechanism, not transport).
- FIT signature mandatory for B2/B3 profiles; `secubox-netboot-publish`
  refuses unsigned artifacts for those levels.
- SPI flashing AUTOMATION (the serial-flash CLI) is Phase 2; the
  `Tow-Boot.spi.bin` artifact itself is produced in Phase 1 for
  operator-initiated manual flash (opt-in, requires operator confirmation).
- Audit log: `/var/log/secubox/netboot/audit.log` (append-only, CSPN).
- Daemon runs as `secubox-netboot` (dedicated user/group, created in
  `debian/postinst`); `fw_setenv` calls use `sudo` with a tight sudoers rule.

---

## References

- Boot levels: `docs/BOOT-LEVELS.md`
- Overlay spec (Phase 2): `docs/PHASE2-uboot-overlay.md`
- Test topology (2× MOCHAbin): `docs/TEST-TOPOLOGY.md`
- Board addresses: `board/mochabin/addrs.env`, `board/espressobin-v7/`
- Issue tracker: #737 (netboot core), #748 (enhanced Tow-Boot + serial flasher)
