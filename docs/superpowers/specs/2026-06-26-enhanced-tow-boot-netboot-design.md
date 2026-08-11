# Enhanced Tow-Boot HTTP netboot + serial flasher + custom kernel modules

**Issue:** #748 · follow-on to #737 (secubox-netboot)
**Date:** 2026-06-26
**Status:** Design — approved, pending spec review

---

## 1. Problem

The factory U-Boot on the GlobalScale MOCHAbin (Marvell/GlobalScale **U-Boot 2020.10**, Sep 2023) has **no `wget` command** (`Unknown command 'wget'`). It supports only `tftpboot` + `booti` + `dhcp`. Therefore the #737 **B2 (signed HTTP `boot.fit`)** netboot path is impossible from the factory bootloader — HTTP needs a second-stage U-Boot built with networking + TLS-free HTTP (`wget`) + FIT signature verification.

We already own the two pieces needed and a third asset to wire in:

| Asset | Location | State |
|-------|----------|-------|
| **Tow-Boot** (our U-Boot, Nix build, U-Boot 2022.07, MOCHAbin board support, eMMC-boot mods) | `tools/Tow-Boot/` | Builds `Tow-Boot.spi.bin` / `.mmcboot.bin`; **zero networking compiled in** |
| **Serial flasher** (Marvell BootROM UART push) | `remote-ui/round/agent/recovery/protocols/{xmodem,kwboot,mvebu64boot}.py` | Pure-stdlib protocol modules; MOCHAbin → `mvebu64boot`, ESPRESSObin → `kwboot` |
| **Custom kernel** (6.12.85, specific built modules) | `kernel-build/linux-6.12.85/` | Source of the netboot `Image` + installer-initrd |

**Goal:** Enhance Tow-Boot to do **HTTP (signed `boot.fit`) netboot**, deliver it both as a **chainload FIT** (factory U-Boot `bootm`-loads it, RAM-run, no brick) **and** a **SPI-flashable** image, bootstrap/recover it with the **serial flasher**, and serve a kernel + installer-initrd built from the **custom kernel modules** — all integrated into the `secubox-netboot` package.

### Board naming
- **gk2** = MOCHAbin #1 — netboot server, stays **B0/untouched** (TFTP + nginx `boot.gk2.secubox.in:8099` + netboot API). Verified working.
- **c3q** = MOCHAbin #2 — DUT, being reinstalled OpenWrt → Debian. eMMC `mmc0` = 14.7 GiB (`/dev/mmcblk0`). Usable netboot port = `mvpp2-2` (single 1G copper RJ45, 88E1512 / PHY 0x01).

---

## 2. Decisions (from brainstorm)

1. **Delivery = chainload FIT *and* SPI-flashable.** The build emits both a signed `sbx-uboot.fit` (loaded by the factory U-Boot at `OVERLAY_LOAD`, RAM-run) and a persistent `Tow-Boot.spi.bin` (for `sf write`).
2. **Scope = all three components, one spec, phased.** Phases 1→3 are designed together, built and reviewed incrementally.
3. **HTTP port = 8099, unchanged.** The boot-vhost stays `192.168.1.200:8099` only — **no `listen 80`**, no HAProxy change, no WAF bypass. The enhanced U-Boot's `wget` is made to target `:8099`.

---

## 3. Architecture

### 3.1 Boot flow (target)

```
factory U-Boot (c3q, no wget)
  └─ chainload: load <sbx-uboot.fit> @ OVERLAY_LOAD ; bootm   (FIT signature verified)
       └─ ENHANCED TOW-BOOT runs in RAM  (has dhcp + wget + booti + FIT-verify)
            ├─ dhcp  (or static ip/serverip)
            ├─ wget ${loadaddr} http://gk2:8099/<MAC>/boot.fit   → bootm (sig-verify)   [B2]
            │     └─ fallback: tftpboot Image/board.dtb/initrd.img → booti                [B1]
            └─ SecuBox kernel (6.12.85) + installer-initrd
                 └─ B3 installer: dhcp → wget image+.sig → verify → dd → /dev/mmcblk0 → reboot
```

Bootstrap / recovery (no factory cooperation needed):
```
secubox-netboot-serialboot --board mochabin --image Tow-Boot.spi.bin --port /dev/ttyUSB0 [--persist-spi]
  └─ mvebu64boot BootROM push → ENHANCED TOW-BOOT in RAM → same flow as above
       └─ --persist-spi: at U-Boot prompt → sf probe/erase + loady(xmodem) + sf write   (opt-in)
```

### 3.2 Why this shape
- **Chainload = RAM-only ⇒ anti-brick by construction.** The factory bootloader is never overwritten; a bad overlay just falls back via `bootcount`/`altbootcmd`.
- **SPI flash is opt-in** (`--persist-spi`) for boards we want permanently HTTP-netbootable.
- **Serial flasher = the universal bootstrap** — works even with a wiped/bricked SPI, since it talks to the immutable Marvell BootROM.
- Integrity always comes from the **FIT signature**, never the transport — so plain HTTP on `:8099` is acceptable (BOOT-LEVELS.md doctrine).

---

## 4. Components

### Phase 1 — Enhanced Tow-Boot (`sbx-uboot`)

**4.1 Networking Kconfig (currently entirely absent).** Add a SecuBox config module under `tools/Tow-Boot/` (expressed as Tow-Boot `config = [(helpers: …)]` Kconfig, applied for the Marvell/armada-7040 hardware), enabling:

```
CMD_DHCP, CMD_TFTPBOOT, CMD_PING        # net basics
CMD_WGET, WGET, PROT_TCP                # HTTP GET over TCP
CMD_BOOTI                              # arm64 Image boot
FIT, FIT_SIGNATURE, RSA, SHA256        # signed boot.fit verification (CSPN)
CMD_BOOTMENU, BOOTCOUNT_LIMIT, BOOTCOUNT_ENV   # anti-brick menu + counter
```

This mirrors the already-authored `board/mochabin/uboot.fragment` (#737), but as Tow-Boot Nix Kconfig so it composes with the existing eMMC/SPI config.

**4.2 Boot script + key.** Embed the SecuBox boot logic (`boot/sbx-boot.cmd`, already in #737) as the default boot command, and embed the **FIT-verify public key** (`/etc/secubox/netboot/keys/secubox-netboot.crt`, the existing RSA-2048 key that signs `boot.fit`) into the U-Boot control DTB so `bootm` verifies signatures.

**4.3 wget port.** `sbx-boot.cmd` targets `http://${sbx_srv}:8099/${sbx_id}/boot.fit`. **Verify** U-Boot 2022.07 `wget` parses `host:port` in the URL; if it only honors port 80, **backport the upstream wget URI/port-parse patch** via Tow-Boot's patch mechanism (Tow-Boot already patches U-Boot). No server-side port change. (Plan-time verification item.)

**4.4 Artifacts.** Produce, per board:
- `sbx-uboot.fit` — signed FIT wrapping the enhanced Tow-Boot proper, loadable at `OVERLAY_LOAD` (`0x06000000` on mochabin) and `bootm`-chainloadable by the factory U-Boot. Built via the existing `boot/overlay-uboot.its.tmpl` + `mkimage -F -k`.
- `Tow-Boot.spi.bin` — the BootROM-format (BLE + doimage) image for `sf write` / serial push.

**4.5 secubox-netboot integration.** Add a `--tow-boot <artifact-dir>` mode to `scripts/build-uboot-overlay.sh` that consumes the nix-build output instead of cross-compiling mainline. `secubox-netboot-publish --overlay-fit … --scr …` already deposits the overlay; no change to publish/serve.

### Phase 2 — Serial flasher CLI (`secubox-netboot-serialboot`)

**4.6 Shared protocol package.** Lift the three **pure-stdlib** modules (`xmodem.py`, `kwboot.py`, `mvebu64boot.py` — no round-agent imports) into a shared location importable by both the `secubox-netboot` CLI and the round recovery agent. The round agent's `recovery_controller.py` glue stays where it is and imports the shared modules (no code duplication).

**4.7 CLI.** `secubox-netboot-serialboot`:
- `--board {mochabin|espressobin-v7|espressobin-ultra}` → selects `mvebu64boot` (Armada 7040/8040) or `kwboot` (Armada 3720).
- `--image <Tow-Boot.spi.bin>` → BootROM-pushed into RAM (mvebu64 validates the `0xB105B002` header).
- `--port /dev/ttyUSB0` (bench/gk2) — replaces the round agent's hardcoded `/dev/ttyGS0`.
- `--persist-spi` (opt-in) → after reaching the U-Boot prompt, drive `sf probe 0; sf erase 0 <size>; loady <addr>` + XMODEM upload + `sf write` + `reset`. This **completes the existing `flash_uboot()` TODO** (XMODEM-on-`loady` is currently unimplemented).
- Progress to stdout; exit non-zero on failure.

### Phase 3 — Custom kernel modules in served Image/initrd

**4.8 Module set.** Build the netboot `Image` and the installer-initrd from `kernel-build/linux-6.12.85` including the modules the installer path needs:
- Net: `mvpp2`, Marvell MDIO (`mvmdio`), Marvell PHY (`marvell` / 88E1512) — so DHCP + HTTP work in the installer.
- Storage: `sdhci`, `sdhci-xenon` (Armada eMMC), `mmc_block`, `ext4`.
- Misc as required by `installer/init` (`udhcpc` is busybox userspace; needs the NIC + MMC drivers in-kernel or in-initrd).

**4.9 Wiring.** `scripts/build-installer-initrd.sh` includes the module tree + runs `depmod`; the publish flow ships the matching `Image`/`board.dtb`. Document the exact module list in `packages/secubox-netboot/docs/`.

---

## 5. Components & interfaces (isolation view)

| Unit | Purpose | Input | Output | Depends on |
|------|---------|-------|--------|------------|
| Tow-Boot SecuBox net module | add HTTP-netboot Kconfig + key + boot script | nix build | enhanced `u-boot.bin` | Tow-Boot nix, signing key |
| overlay packager (`build-uboot-overlay.sh --tow-boot`) | wrap enhanced U-Boot into signed FIT + SPI bin | `u-boot.bin`/`.spi.bin`, key | `sbx-uboot.fit`, `Tow-Boot.spi.bin` | mkimage |
| `serialboot` protocol pkg | XMODEM/kwboot/mvebu64 framing | bytes + serial r/w cbs | bool | pyserial (I/O only) |
| `secubox-netboot-serialboot` CLI | push/flash over BootROM | image, port, board | RAM-run / SPI-persist | protocol pkg |
| installer-initrd builder | initrd with custom modules | kernel modules, `init` | `initrd.img` | depmod, cpio |

Each unit is independently testable: Kconfig presence (`grep`/`help`), FIT signature (`mkimage -l`), protocol framing (fixture unit tests), initrd contents (`zcat | cpio -t`).

---

## 6. Error handling & anti-brick

- **Chainload failure** (bad/forged FIT) → `bootm` refuses → factory `bootcount`/`altbootcmd` returns to local boot. No persistent change.
- **SPI flash** only on explicit `--persist-spi`; the serial flasher can always re-push via BootROM if SPI is corrupted (BootROM is immutable).
- **wget/tftp failure** in enhanced Tow-Boot → TFTP fallback → halt/return (no unverified boot).
- **Installer** (`init`) already halts safely on bad signature / missing image (#737).

---

## 7. Testing

1. **Kconfig:** after nix-build, confirm `help wget`, `help booti`, `help dhcp` present on serial; `grep` the `.config`.
2. **FIT:** `mkimage -l sbx-uboot.fit` shows `Sign algo: sha256,rsa2048:secubox-netboot` + verifies against the embedded key.
3. **Protocols:** unit tests with byte fixtures — XMODEM CRC/checksum framing, mvebu64 header validate/align (`0xB105B002`), kwboot pattern.
4. **Serial push (integration):** `secubox-netboot-serialboot` pushes enhanced Tow-Boot to c3q → reach `Tow-Boot>` prompt over `/dev/ttyUSB0`.
5. **End-to-end (once L2 fixed):** enhanced Tow-Boot → `wget gk2:8099/<MAC>/boot.fit` → boot SecuBox kernel + installer-initrd → rescue shell. Then B3 install once the release image is published.
6. **initrd:** `zcat initrd.img | cpio -t` lists the custom modules + `init` + `udhcpc` + `openssl`.

---

## 8. Constraints honored

- boot-vhost **8099-only**; no `:80`, no HAProxy change, **no WAF bypass** (integrity via FIT signature; vhost is "hors WAF" per BOOT-LEVELS.md).
- **FIT signature mandatory** (CSPN doctrine) for both `sbx-uboot.fit` and `boot.fit`.
- **Anti-brick**: chainload RAM-only, SPI flash opt-in, `bootcount`/`altbootcmd` retained, gk2 stays B0.
- Source-first: changes land in the #748 worktree; round-agent keeps using the shared protocol modules.

---

## 9. Out of scope (tracked separately)

- **Live L2 cabling fix** — c3q's copper RJ45 (`mvpp2-2`) must physically reach gk2's `.200` LAN segment; proven blocker (gk2 captured 0 frames from c3q). Physical, not code.
- **B3 release-image publish** — `secubox-mochabin-bookworm` artifact (from `build-image.yml`, run `27426515472`) must be downloaded, named `<image>.img`, **detached-signed** with the key matching the initrd's `netboot-image.pub`, and published under the DUT MAC. Needs the image-signing private key.

---

## 10. Phasing / deliverables

- **Phase 1** → enhanced Tow-Boot building both artifacts + `build-uboot-overlay.sh --tow-boot`; verified via `help wget` on a serial-pushed build.
- **Phase 2** → shared protocol pkg + `secubox-netboot-serialboot` CLI (+ `--persist-spi`); round-agent refactored to import it.
- **Phase 3** → custom-kernel Image/installer-initrd module wiring + docs.

Each phase is a reviewable increment under #748.
