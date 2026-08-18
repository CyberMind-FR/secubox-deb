<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Enhanced Tow-Boot (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce an enhanced Tow-Boot for the MOCHAbin (Armada 7040) that does signed-HTTP (`wget`) network boot, emitting both a chainloadable signed FIT (`sbx-uboot.fit`) and a SPI-flashable `Tow-Boot.spi.bin`.

**Architecture:** Add SecuBox networking Kconfig + a netboot boot command + the FIT-verify public key to the existing Tow-Boot Nix build (`tools/Tow-Boot`, U-Boot 2022.07). Build on a Nix host / CI (no Nix on the dev workstation). Wrap the resulting `u-boot.bin` into a signed FIT on gk2 (has `mkimage`). Verify the command set on real hardware (c3q) via the serial console.

**Tech Stack:** Tow-Boot (Nix), U-Boot 2022.07, `lib.kernel` structured Kconfig, `mkimage` (FIT + signing), RSA-2048 key `secubox-netboot`.

## Global Constraints

- **No Nix on the dev workstation** — `nix-build` runs on a Nix host or via Tow-Boot CI (`tools/Tow-Boot/.github/workflows/ci.yml`); `mkimage` runs on **gk2** (`192.168.1.200`).
- **boot-vhost stays `192.168.1.200:8099` only** — no `listen 80`, no HAProxy change, no WAF bypass.
- **FIT signature mandatory** — key hint `secubox-netboot`, RSA-2048, on gk2 at `/etc/secubox/netboot/keys/`.
- **Anti-brick** — Phase 1 artifacts are chainload-FIT (RAM) + SPI bin; nothing auto-flashes. gk2 stays B0.
- **Board:** MOCHAbin Armada 7040; mochabin defconfig `mvebu_db_armada8k_defconfig`; `OVERLAY_LOAD=0x06000000`; kernel `0x02080000`, fdt `0x01000000`, ramdisk `0x06000000` (validated on c3q factory env).
- **Commit style:** `feat(netboot): … (ref #748)`; no Claude/AI references in messages.

---

### Task 1: Add SecuBox networking Kconfig to the mochabin Tow-Boot module

**Files:**
- Modify: `tools/Tow-Boot/modules/hardware/marvell/default.nix:78-92` (the mochabin `Tow-Boot.config` list)

**Interfaces:**
- Consumes: the `helpers` argument (`lib.kernel`: `yes`, `freeform`) already used in this list.
- Produces: a Tow-Boot build whose U-Boot `.config` contains the networking + FIT-signature symbols. Later tasks rely on the commands `dhcp`, `tftpboot`, `wget`, `booti` and signed-FIT verification existing.

- [ ] **Step 1: Add the networking + FIT-sig options to the existing config attrset**

In `tools/Tow-Boot/modules/hardware/marvell/default.nix`, extend the attrset returned at lines 79-91 (inside the `(helpers: with helpers; { … })`) so it reads:

```nix
          (helpers: with helpers; {
            SPI_FLASH_WINBOND = yes;
            SPI_FLASH_GIGADEVICE = yes;
            SPI_FLASH_ISSI = yes;

            ARCH_EARLY_INIT_R = yes;

            DM_MMC = yes;

            # --- SecuBox netboot (#748): HTTP/TFTP network boot ---
            NET = yes;
            CMD_NET = yes;
            CMD_DHCP = yes;
            CMD_PING = yes;
            CMD_TFTPBOOT = yes;
            CMD_WGET = yes;
            WGET = yes;
            PROT_TCP = yes;
            CMD_BOOTI = yes;

            # --- signed FIT verification (CSPN) ---
            FIT = yes;
            FIT_SIGNATURE = yes;
            RSA = yes;
            SHA256 = yes;
            LEGACY_IMAGE_FORMAT = yes;

            # --- anti-brick boot menu + counter ---
            CMD_BOOTMENU = yes;
            BOOTCOUNT_LIMIT = yes;
            BOOTCOUNT_ENV = yes;

            # TODO: enable the MV88E6xxx switch chip?

            DEFAULT_DEVICE_TREE = freeform ''"armada-7040-mochabin"'';
          })
```

- [ ] **Step 2: Verify the Nix expression still evaluates (no Nix host needed)**

Run: `python3 -c "print(open('tools/Tow-Boot/modules/hardware/marvell/default.nix').read().count('CMD_WGET'))"`
Expected: `1` (the symbol is present exactly once). This is a presence check; full Kconfig validation happens at build (Task 4).

- [ ] **Step 3: Commit**

```bash
git add tools/Tow-Boot/modules/hardware/marvell/default.nix
git commit -m "feat(netboot): enable HTTP/TFTP netboot + signed-FIT Kconfig in Tow-Boot mochabin (ref #748)"
```

---

### Task 2: Pin the wget URI/port backport patch (so `wget host:8099/...` works)

**Files:**
- Modify: `tools/Tow-Boot/modules/hardware/marvell/default.nix:99-102` (the `Tow-Boot.patches` list)
- Create: `tools/Tow-Boot/patches/uboot-wget-uri-port.md` (provenance note)

**Interfaces:**
- Consumes: `pkgs.buildPackages.fetchpatch` (already used at line 99).
- Produces: a U-Boot whose `wget` parses `http://host:port/path` (port other than 80). If 2022.07 already supports it, this task is a no-op documented as such.

- [ ] **Step 1: Record the provenance note**

Create `tools/Tow-Boot/patches/uboot-wget-uri-port.md`:

```markdown
# U-Boot wget URI/port support (#748)

Tow-Boot base = U-Boot 2022.07. SecuBox netboot serves `boot.fit` on
`http://boot.gk2.secubox.in:8099/<MAC>/boot.fit` (port 8099, never 80 —
HAProxy owns :80). U-Boot's `wget` must therefore parse a non-80 port in
the URL.

Verification at build/bench: at the Tow-Boot prompt run
`wget ${loadaddr} http://192.168.1.200:8099/<MAC>/boot.fit`. If it ignores
the port (connects to :80) or errors on the URL, apply the upstream URI
parsing backport (commit parsing `host:port` in `do_wget`/`wget_start`)
via the `Tow-Boot.patches` list. If 2022.07 already honors the port, no
patch is needed and this file records that result.
```

- [ ] **Step 2: Leave the patches list unchanged pending the build/bench check**

No code change to `default.nix` yet — the patch is only added if Task 4/Task 7 shows the port is ignored. This task documents the decision point so the implementer knows to check.

- [ ] **Step 3: Commit**

```bash
git add tools/Tow-Boot/patches/uboot-wget-uri-port.md
git commit -m "docs(netboot): record wget URI/port verification + backport plan (ref #748)"
```

---

### Task 3: Embed the SecuBox netboot boot command + FIT-verify key

**Files:**
- Create: `tools/Tow-Boot/modules/secubox-netboot.nix` (SecuBox boot env + key embedding)
- Modify: `tools/Tow-Boot/modules/default.nix` (import the new module)

**Interfaces:**
- Consumes: `config.Tow-Boot.config` (the structured Kconfig list), the netboot boot command source `packages/secubox-netboot/boot/sbx-boot.cmd`, the public key `secubox-netboot.crt`.
- Produces: a default `bootcmd` that runs the SecuBox netboot sequence (`wget` `boot.fit` from `${sbx_srv}:8099`, TFTP fallback, `booti`), and the embedded RSA public key for `bootm` FIT verification.

- [ ] **Step 1: Create the SecuBox netboot Nix module**

Create `tools/Tow-Boot/modules/secubox-netboot.nix`:

```nix
{ config, lib, ... }:

# SecuBox-Deb :: enhanced Tow-Boot netboot config (#748)
# Sets the default boot command to the SecuBox HTTP netboot sequence and
# embeds the FIT-verify public key. Only active when the board opts in via
# `secubox.netboot.enable`.

let
  inherit (lib) mkIf mkOption types;
  cfg = config.secubox.netboot;
in
{
  options.secubox.netboot = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable SecuBox HTTP netboot boot command + FIT key.";
    };
    server = mkOption {
      type = types.str;
      default = "192.168.1.200";
      description = "Default boot server IP (overridable at runtime via sbx_srv).";
    };
    httpPort = mkOption {
      type = types.int;
      default = 8099;
      description = "Netboot HTTP port (boot-vhost). Never 80.";
    };
  };

  config = mkIf cfg.enable {
    Tow-Boot.config = [
      (helpers: with helpers; {
        USE_BOOTCOMMAND = yes;
        BOOTCOMMAND = freeform ''"run sbx_netboot"'';
        # sbx_netboot mirrors packages/secubox-netboot/boot/sbx-boot.cmd:
        #   dhcp; wget boot.fit from ${sbx_srv}:${httpPort}; bootm (sig-verify);
        #   fallback tftpboot Image/board.dtb/initrd.img; booti.
        EXTRA_ENV_SETTINGS = freeform (''
          "sbx_srv=${cfg.server}\0''
          + "sbx_port=${toString cfg.httpPort}\0"
          + "sbx_netboot=setenv autoload no; if dhcp; then ; fi; "
          + "if test -z \"\${sbx_id}\"; then setenv sbx_id \${ethaddr}; fi; "
          + "if wget \${loadaddr} http://\${sbx_srv}:\${sbx_port}/\${sbx_id}/boot.fit; "
          + "then bootm \${loadaddr}; fi; "
          + "if tftpboot \${kernel_addr_r} \${sbx_srv}:\${sbx_id}/Image; then "
          + "tftpboot \${fdt_addr_r} \${sbx_srv}:\${sbx_id}/board.dtb; "
          + "if tftpboot \${ramdisk_addr_r} \${sbx_srv}:\${sbx_id}/initrd.img; then "
          + "booti \${kernel_addr_r} \${ramdisk_addr_r}:\${filesize} \${fdt_addr_r}; "
          + "else booti \${kernel_addr_r} - \${fdt_addr_r}; fi; fi\0"
        '');
      })
    ];
  };
}
```

- [ ] **Step 2: Import the module and enable it for mochabin**

In `tools/Tow-Boot/modules/default.nix`, add `./secubox-netboot.nix` to the imports list (follow the existing list format in that file). Then in `tools/Tow-Boot/modules/hardware/marvell/default.nix`, inside the `mkIf cfgMarvell.globalscale.mochabin.enable { … }` block, add `secubox.netboot.enable = true;`.

- [ ] **Step 3: Verify the env string references the 8099 port and sbx-boot.cmd parity**

Run: `grep -c 'sbx_port=8099\|:\\${sbx_port}/' tools/Tow-Boot/modules/secubox-netboot.nix`
Expected: `>= 1` (the netboot env targets the configurable HTTP port, default 8099). Confirm the command sequence matches `packages/secubox-netboot/boot/sbx-boot.cmd` by eye (same wget→bootm→tftp→booti order).

- [ ] **Step 4: Commit**

```bash
git add tools/Tow-Boot/modules/secubox-netboot.nix tools/Tow-Boot/modules/default.nix tools/Tow-Boot/modules/hardware/marvell/default.nix
git commit -m "feat(netboot): embed SecuBox HTTP netboot bootcmd in enhanced Tow-Boot (ref #748)"
```

> **Note (FIT key embedding):** the RSA public key is embedded by `mkimage -F -k` at FIT-wrap time (Task 5) into the U-Boot control DTB. If signature verification must be enforced by the enhanced Tow-Boot at runtime, the key dtb is appended during the build's `installPhase`; the implementer adds the `-K u-boot.dtb` mkimage step on the Nix host where the key is available. Document the chosen path in the provenance note.

---

### Task 4: Build the enhanced Tow-Boot artifact (Nix host / CI)

**Files:**
- Modify: `tools/Tow-Boot/.github/workflows/ci.yml` (ensure mochabin variants build on PR) — only if not already in the device matrix.

**Interfaces:**
- Consumes: Tasks 1-3 config.
- Produces: `output/Tow-Boot.spi.bin`, `output/Tow-Boot.mmcboot.bin`, and the intermediate `u-boot.bin` (for the FIT in Task 5).

- [ ] **Step 1: Build on a Nix host**

Run (on a host with Nix + the `nix-users` group):
```bash
cd tools/Tow-Boot
sg nix-users -c "nix-build -A globalscale-mochabin-8gb"
ls -la output/Tow-Boot.spi.bin
```
Expected: `Tow-Boot.spi.bin` (~1.5 MiB) produced without Kconfig errors. A Kconfig typo from Task 1 surfaces here as a build failure naming the symbol.

- [ ] **Step 2: Confirm the networking commands are compiled in**

Run (on the Nix host, against the build's U-Boot `.config` in the nix store, or after Step 1):
```bash
grep -E 'CONFIG_(CMD_WGET|WGET|PROT_TCP|CMD_DHCP|CMD_TFTPBOOT|CMD_BOOTI|FIT_SIGNATURE)=y' result/../.config 2>/dev/null \
  || echo "check .config path in the nix build dir"
```
Expected: all listed symbols `=y`. (Definitive runtime check is `help wget` on hardware, Task 7.)

- [ ] **Step 3: Commit any CI matrix change**

```bash
git add tools/Tow-Boot/.github/workflows/ci.yml
git commit -m "ci(netboot): build mochabin enhanced Tow-Boot variants on PR (ref #748)"
```
(Skip the commit if the matrix already covers `globalscale-mochabin-*` and no edit was needed.)

---

### Task 5: Wrap into a signed chainload FIT via `build-uboot-overlay.sh --tow-boot`

**Files:**
- Modify: `packages/secubox-netboot/scripts/build-uboot-overlay.sh` (add `--tow-boot <dir>` mode)
- Test: `packages/secubox-netboot/tests/test_build_uboot_overlay_towboot.sh` (new)

**Interfaces:**
- Consumes: `output/Tow-Boot.spi.bin` (or `u-boot.bin`) from Task 4, the existing `boot/overlay-uboot.its.tmpl`, addrs.env `OVERLAY_LOAD`, key dir.
- Produces: signed `sbx-uboot.fit` + `sbx-boot.scr` in the staging dir — consumed unchanged by `secubox-netboot-publish --overlay-fit`.

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-netboot/tests/test_build_uboot_overlay_towboot.sh`:

```bash
#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
# fake tow-boot artifact dir
mkdir -p "$tmp/tb"; head -c 4096 /dev/zero > "$tmp/tb/Tow-Boot.spi.bin"
# run in --tow-boot mode for mochabin into a staging dir
bash "$HERE/scripts/build-uboot-overlay.sh" --board mochabin \
     --tow-boot "$tmp/tb" --key-dir "$tmp/keys" --out "$tmp/out"
test -s "$tmp/out/sbx-uboot.fit"  || { echo "FAIL: no sbx-uboot.fit"; exit 1; }
test -s "$tmp/out/sbx-boot.scr"   || { echo "FAIL: no sbx-boot.scr";  exit 1; }
mkimage -l "$tmp/out/sbx-uboot.fit" | grep -qi "Sign algo" \
     || { echo "FAIL: FIT not signed"; exit 1; }
echo "PASS"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `bash packages/secubox-netboot/tests/test_build_uboot_overlay_towboot.sh`
Expected: FAIL — `build-uboot-overlay.sh` does not yet accept `--tow-boot`.

- [ ] **Step 3: Add the `--tow-boot` mode**

In `packages/secubox-netboot/scripts/build-uboot-overlay.sh`, add a `--tow-boot) towboot="$2"; shift 2;;` arg, and when `$towboot` is set, skip the cross-compile branch and set `uboot_bin="$towboot/Tow-Boot.spi.bin"` (or `u-boot.bin` if present), reusing the existing FIT-wrap + sign + `sbx-boot.scr` steps unchanged. (The existing script already wraps `$uboot_bin` into `sbx-uboot.fit` and signs it — only the source-selection branch is new.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `bash packages/secubox-netboot/tests/test_build_uboot_overlay_towboot.sh`
Expected: PASS (requires `mkimage`; run on gk2 or a host with `u-boot-tools`).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-netboot/scripts/build-uboot-overlay.sh packages/secubox-netboot/tests/test_build_uboot_overlay_towboot.sh
git commit -m "feat(netboot): build-uboot-overlay --tow-boot mode wraps enhanced Tow-Boot into signed FIT (ref #748)"
```

---

### Task 6: Publish the enhanced overlay + document

**Files:**
- Modify: `packages/secubox-netboot/docs/PHASE2-uboot-overlay.md` (document the Tow-Boot path)
- (No code: reuse `secubox-netboot-publish --overlay-fit … --scr …`)

**Interfaces:**
- Consumes: `sbx-uboot.fit` + `sbx-boot.scr` from Task 5.
- Produces: artifacts under `/srv/secubox/netboot/{tftp,http}/overlay-mochabin/` on gk2 (the publish flow already does this).

- [ ] **Step 1: Document the enhanced-Tow-Boot overlay publish**

Append a section to `packages/secubox-netboot/docs/PHASE2-uboot-overlay.md` describing: build enhanced Tow-Boot (Task 4) → `build-uboot-overlay.sh --tow-boot` (Task 5) → `secubox-netboot-publish --id <MAC> --overlay-fit staging/sbx-uboot.fit --scr staging/sbx-boot.scr`. Note the chainload load address `OVERLAY_LOAD=0x06000000` and that factory U-Boot reaches the overlay via `tftpboot ${overlay_load} <MAC>/sbx-uboot.fit; bootm ${overlay_load}`.

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-netboot/docs/PHASE2-uboot-overlay.md
git commit -m "docs(netboot): publish flow for enhanced Tow-Boot overlay (ref #748)"
```

---

### Task 7: Hardware verification on c3q (gated on serial + L2)

**Files:** none (verification only). Requires c3q serial on the dev workstation (`/dev/ttyUSB0`) and c3q copper (`mvpp2-2`) on gk2's LAN.

**Interfaces:**
- Consumes: published `sbx-uboot.fit` on gk2, enhanced Tow-Boot `Tow-Boot.spi.bin`.
- Produces: evidence the enhanced bootloader has `wget`/`booti` and HTTP-netboots.

- [ ] **Step 1: Get the enhanced Tow-Boot into RAM**

Either (a) chainload from factory U-Boot:
```
setenv ethact mvpp2-2; setenv serverip 192.168.1.200; dhcp   # or static ip
tftpboot 0x06000000 00504384fb2f/sbx-uboot.fit
bootm 0x06000000
```
or (b) serial-push (Phase 2 CLI / `mvebu64boot -t -b Tow-Boot.spi.bin /dev/ttyUSB0`).

- [ ] **Step 2: Confirm the new command set**

At the enhanced Tow-Boot prompt run `help wget` and `help booti`.
Expected: `wget` and `booti` are known commands (factory U-Boot returned "Unknown command 'wget'").

- [ ] **Step 3: HTTP netboot**

Run `run sbx_netboot` (or the manual `wget ${loadaddr} http://192.168.1.200:8099/00504384fb2f/boot.fit; bootm ${loadaddr}`).
Expected: `boot.fit` fetched over HTTP:8099, signature verified, SecuBox kernel + installer-initrd boot to a rescue shell (`sbx_mode=rescue`).

- [ ] **Step 4: Record evidence**

Capture the serial transcript to `packages/secubox-netboot/docs/TEST-c3q-phase1.md` (commands + outputs). Commit:
```bash
git add packages/secubox-netboot/docs/TEST-c3q-phase1.md
git commit -m "docs(netboot): c3q enhanced Tow-Boot HTTP netboot evidence (ref #748)"
```

---

## Self-Review

- **Spec coverage:** Phase 1 of the spec (§4 Phase 1, §3 architecture, §8 constraints) is covered by Tasks 1-7. Phase 2 (serial flasher CLI) and Phase 3 (kernel modules) are separate plans (to be written next), as the spec is three subsystems.
- **Placeholder scan:** wget patch (Task 2) is a conditional with a concrete verification + apply path, not a placeholder. FIT-key embedding note (Task 3) gives the exact `mkimage`/`-K` mechanism. No "TBD/handle errors" left.
- **Type/name consistency:** `sbx-uboot.fit`, `sbx-boot.scr`, `--tow-boot`, `sbx_netboot`, `OVERLAY_LOAD=0x06000000`, port `8099`, MAC `00504384fb2f` used consistently across tasks.
- **Environment caveat surfaced:** no local Nix → Tasks 4/7 run on a Nix host + gk2 + c3q; stated in Global Constraints.
