# c3box Kernel Migration → SecuBox 6.12.85 — Design

**Date:** 2026-07-08
**Target node:** c3box (Globalscale **MOCHAbin**, Armada 7040, mesh `10.10.0.2`, LAN `192.168.1.94`)
**Status:** Design — pending user review

---

## Goal

Migrate c3box from the stock Debian kernel **6.1.0-47-arm64** to the SecuBox
custom kernel **6.12.85-5secubox** (the exact build gk2 runs), so the
`IS31FL3199` LED driver + DTS are present and the already-built
`secubox-led-heartbeat` package works — **without bricking a live mesh node's
boot**. A hung new-kernel boot must auto-revert to the known-good stock kernel
with no physical intervention.

---

## Key facts established on the live boards

| Fact | Value | Source |
|------|-------|--------|
| c3box board | **identical to gk2** (MOCHAbin Armada 7040) | `/proc/device-tree/model` |
| Proven-good kernel | `6.12.85` **#5secubox** (SMP Jun 2) | gk2 `/proc/version` |
| Kernel artifact | `gk2:/root/linux-image-6.12.85_6.12.85-5secubox_arm64.deb` | matches gk2 live `vmlinuz-6.12.85` (Jun 2 22:37) |
| LED driver | `CONFIG_LEDS_IS31FL319X=m` → `/lib/modules/6.12.85/kernel/drivers/leds/leds-is31fl319x.ko` (loaded on gk2) | `modinfo`, `lsmod` |
| Active boot path | **`boot.scr`** (compiled from `/boot/boot.cmd`), **not** extlinux | gk2 cmdline `console=ttyS0 root=/dev/mmcblk0p2` == boot.cmd bootargs |
| c3box boot.cmd | **already** tries `Image-secubox-led` first, falls back to `Image` (stock) | `/boot/boot.cmd` |
| c3box DTB | `dtbs/marvell/armada-7040-mochabin.dtb` | boot.cmd |
| Boot partition | `mmcblk0p1` 256 MB **vfat**, mounted `rw` on `/boot`, 132 MB free | `lsblk`, `mount` |
| Root partition | `mmcblk0p2` 5.4 GB ext4, **96 % full (230 MB free)** | `df` |
| Reclaimable | apt archives 264 MB + `/var/log` 252 MB | `du` |
| U-Boot env tools | `fw_setenv`/`fw_printenv` present; **no `/etc/fw_env.config`** | c3box |
| `mkimage` | present (`u-boot-tools`) — can recompile `boot.cmd`→`boot.scr` | c3box |
| Access | `ssh -J root@192.168.1.200 root@10.10.0.2` (my key, ProxyJump) | verified |

**Critical inversion vs. the original assumption:** there is **no U-Boot
`bootcount`/`altbootcmd`** on either board, and gk2's boot.scr fallback is
*load-time* (file-exists) only — not hang-time. Genuine remote auto-revert must
be built into `boot.cmd` as a **trial counter**.

---

## Approach: one-shot trial via U-Boot env counter, stock-default always

The invariant that makes this safe: **the default boot path always loads the
known-good stock kernel.** The new kernel boots *only* when a trial is armed,
the trial is *consumed before* the new kernel runs, and success is *confirmed
from userspace* before the new kernel becomes permanent.

### The counter channel — U-Boot env (with a hard verification gate)

`fw_setenv`/`fw_printenv` are installed but unconfigured. Step 0 of execution
**creates and verifies** `/etc/fw_env.config` for c3box's eMMC U-Boot env
(offset taken from gk2's working `/etc/fw_env.config` if present, else the
board's `CONFIG_ENV_OFFSET`), then proves a **round-trip**:
`fw_setenv sbx_probe 1 && [ "$(fw_printenv -n sbx_probe)" = 1 ]`. It also
confirms U-Boot's own `saveenv` writes to the same location by rebooting once
into the **unchanged** stock kernel with a trial-arm test (see Task order).

**If the env round-trip cannot be proven reliable, execution ABORTS and falls
back to the serial-select method** (documented below) — we never rely on an
unverified write channel for the guard.

### boot.cmd trial logic (compiled to boot.scr with `mkimage`)

```
# --- one-shot trial guard (new) ---
if test "${kernel_trial}" = "1"; then
    # consume the trial immediately, persist, THEN attempt new kernel.
    # a hang after this point leaves kernel_trial=0 → next boot is stock.
    setenv kernel_trial 0
    saveenv
    echo "TRIAL: attempting 6.12.85 (one-shot)"
    if load ${bootpart} ${kernel_addr_r} Image-secubox-led; then
        setenv initrd_file "initrd.img-6.12.85"
        setenv trial_ok 1
    fi
fi
# --- default / fallback: known-good stock kernel ---
if test "${trial_ok}" != "1"; then
    load ${bootpart} ${kernel_addr_r} Image        # stock 6.1.0-47
    setenv initrd_file "initrd.img"
fi
# DTB, initrd, bootargs, booti  — unchanged from current boot.cmd
```

- **Arm a trial (userspace):** `fw_setenv kernel_trial 1 && reboot`.
- **Confirm success (userspace, on the new kernel):** a systemd oneshot
  `sbx-kernel-promote.service` (WantedBy multi-user, after network) runs on the
  6.12.85 boot; when it sees `uname -r = 6.12.85` **and** the mesh interface is
  up, it makes 6.12.85 **permanent** by rewriting `boot.cmd` so the default
  `load` targets `Image-secubox-led` (stock kept as the file-exists fallback),
  recompiles `boot.scr`, and disables itself. Until that runs, every unarmed
  boot is stock.
- **Hang case:** new kernel never reaches userspace → `kernel_trial` already
  `0` (saved by U-Boot before booting it) → next power-cycle boots stock.
  Zero-touch revert.

### Serial-select fallback (only if the env channel is unprovable)

Keep stock as default; stage `Image-secubox-led`; whoever is at c3box's serial
console selects the 6.12.85 entry once. Slower (needs presence at
Notre-Dame-du-Cruet) but needs no writable guard channel.

---

## Kernel artifact staging

The `.deb` ships a **gzipped** `vmlinuz-6.12.85`; `boot.cmd` boots an
**uncompressed** `Image` via `booti`. Staging therefore:

1. `apt clean` + `journalctl --vacuum-size=50M` on c3box → ~500 MB free (guard:
   assert ≥ 400 MB free on `/` before proceeding).
2. `scp` the `-5secubox` `.deb` from gk2 → c3box; `dpkg -i`. This installs
   `/lib/modules/6.12.85/` (incl. `leds-is31fl319x.ko`), `vmlinuz-6.12.85`, and
   the 6.12.85 `dtbs/`.
3. Produce the uncompressed boot Image: `zcat /boot/vmlinuz-6.12.85 >
   /boot/Image-secubox-led` (verify gzip magic first; fall back to extracting
   the raw `Image` from the `.deb` if not gzip).
4. `update-initramfs -c -k 6.12.85` → `/boot/initrd.img-6.12.85`.
5. Copy the 6.12.85 `armada-7040-mochabin.dtb` into `/boot/dtbs/marvell/`
   (keep the 6.1 one under a `.stock` name; boot.cmd's DTB load is version-
   agnostic by path, so verify the new DTB boots the new kernel).
6. **Space check on vfat `/boot`:** Image (~32 MB) + initrd (~30 MB) fits in the
   132 MB free, but assert ≥ 20 MB headroom remains after staging.

Bootargs stay **c3box's** (`root=/dev/mmcblk0p2 rootfstype=ext4 rw rootwait
console=ttyS0,115200 net.ifnames=0`) — unchanged from current boot.cmd.

---

## LED heartbeat enablement (after the kernel is permanent)

Only once 6.12.85 is the confirmed permanent kernel:

- Install `secubox-led-heartbeat` on c3box (its `postinst` compiles the DTS
  overlay + `modprobe leds-is31fl319x`). The driver module is now present.
- Verify the IS31FL3199 appears on I²C and the heartbeat LED pulses.
- This is a **separate, low-risk phase** gated on a healthy 6.12.85 boot; it
  does not touch the bootloader.

---

## Recovery ladder (defence in depth)

1. **Auto (zero-touch):** hung trial → `kernel_trial=0` already saved → next
   boot is stock. Primary safety net.
2. **Menu (serial):** U-Boot/extlinux prompt (`PROMPT 1 TIMEOUT 30`) lets a
   console operator pick stock.
3. **Netboot:** c3box was originally installed via gk2 netboot; the gk2 netboot
   rig (`.77`, signed `sbx.img.gz` on `/data:8099`) is the last-resort
   re-image. **Confirm it is armed before the first trial reboot.**

No step in the plan makes the stock kernel unbootable at any point until
6.12.85 is *confirmed booting from userspace*.

---

## Testing / verification gates

- **Pre-flight:** board is MOCHAbin; ≥ 400 MB free on `/`; env round-trip
  proven; stock kernel still default; netboot recovery armed.
- **Dry boot (no new kernel):** arm `kernel_trial=1` with `boot.cmd` modified
  but **`Image-secubox-led` absent** → assert the board still boots stock and
  `kernel_trial` is `0` afterward. Proves the consume-then-fallback path
  *before* a real new-kernel attempt.
- **Trial boot:** stage the kernel, arm trial, reboot; assert `uname -r =
  6.12.85`, mesh up (`10.10.0.2` reachable), aggregator/p2p services green.
- **Promotion:** `sbx-kernel-promote` ran; a plain `reboot` (unarmed) now comes
  up on 6.12.85. Assert stock is still selectable as fallback.
- **LEDs:** IS31FL3199 on I²C; heartbeat visible.
- **Rollback rehearsal:** document (and, if safe, exercise once) arming a trial
  that intentionally fails-to-load → confirm auto-revert to stock.

---

## Files / artifacts

- `docs/superpowers/specs/2026-07-08-c3box-kernel-migration-design.md` — this.
- `board/mochabin/boot/boot.cmd` — versioned boot.cmd with the trial guard
  (source of truth; deployed + `mkimage`-compiled on the board).
- `packages/secubox-led-heartbeat/…/sbx-kernel-promote.service` (+ helper
  script) — the userspace promotion oneshot. (Placement TBD in plan: may live
  in a small `secubox-kernel-guard` helper rather than led-heartbeat.)
- `scripts/c3box-kernel-migrate.sh` — the staged, guarded migration runner
  (idempotent, abort-on-failed-gate), OR the plan executes the steps directly
  under SDD. Decided in writing-plans.

---

## Out of scope

- Changing c3box's rootfs layout, partition sizes, or root device.
- Migrating any other mesh node (gk2 already on 6.12.85; amd64 is x86).
- Rebuilding the kernel itself — we deploy the proven `-5secubox` artifact.
- U-Boot binary replacement (we only edit the boot script + env).

---

## Open decisions for the plan

1. **Guard helper home:** fold `sbx-kernel-promote` into `secubox-led-heartbeat`
   vs. a tiny new `secubox-kernel-guard` package. (Leaning: standalone helper —
   the guard is kernel-lifecycle, not LED-specific.)
2. **Runner vs. SDD-direct:** one idempotent `c3box-kernel-migrate.sh` with
   gate asserts, vs. executing each guarded step live under review. (Leaning:
   idempotent script — a live board migration wants replayable, abortable
   steps.)
