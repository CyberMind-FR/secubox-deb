<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Build Scripts Refactor — Common Module Plan

> **Status:** STUB / TODO for later. Not ready to execute. Flesh out
> with full task decomposition (DRY, TDD, frequent commits) before
> attempting via superpowers:executing-plans.

**Goal:** Eliminate the ~60% code duplication across `image/build-*.sh`
scripts so a single edit (DHCP firewall rule, MOTD format, kiosk
launcher, secubox-status tool, …) lands on every platform at once.

## Background — current pain

Four siblings each carry their own copy of common logic:

| Script | Lines | Platform | Uses firstboot.sh ? | secubox-* tools created |
|---|---|---|---|---|
| `build-live-usb.sh` | ~3870 | amd64 live USB | yes | ~30 |
| `build-rpi-usb.sh` | ~1050 | rpi400 live USB | no | 3 (bootmenu, splash) |
| `build-mochabin-live-usb.sh` | ~1080 | mochabin live USB | no | ? |
| `build-image.sh` | ~1100 | mochabin install eMMC | yes | (via firstboot.sh) |

Observed drift symptoms:

* rpi400 image ships old DEC-PDP splash + lacks `secubox-status`,
  `secubox-help`, `secubox-kiosk-setup`, etc.
* DHCP firewall fix (v2.12.12 nft `udp dport 68 accept`) only landed
  in firstboot.sh — mochabin live + rpi400 live missed it.
* MOTD live-IP via update-motd.d only on amd64 live.
* INCLUDE_PKGS lists differ (python3-jose missing on amd64, present
  on rpi400 — see v2.12.x debug session).

## Target architecture

```
image/
├── lib/                            ← NEW shared helpers
│   ├── partition-layout.sh         (mkpart GPT + bios_grub + ESP + LIVE)
│   ├── grub-install-dual.sh        (mkimage EFI + grub-install i386-pc)
│   ├── nftables-default.sh         (the secubox_filter table with DHCP allow)
│   ├── motd-dynamic.sh             (update-motd.d/10-secubox setup)
│   ├── secubox-cli-tools.sh        (creates secubox-{status,help,logs,…})
│   ├── kiosk-setup.sh              (X11/Wayland prep + .kiosk-enabled sentinel)
│   └── include-pkgs.sh             (canonical INCLUDE_PKGS list, with arch
│                                    conditionals)
├── build-live-usb.sh               ← shrinks ~70%: source lib/*.sh + glue
├── build-rpi-usb.sh                ← shrinks ~50%
├── build-mochabin-live-usb.sh      ← shrinks ~50%
└── build-image.sh                  ← shrinks ~40%
```

## Implementation phases

1. **Extract verbatim** — move identical-or-near-identical blocks into
   lib/*.sh without behaviour change. Verify each platform still
   builds (CI pipeline diff: bit-for-bit identical artefacts).
2. **Resolve drift** — for each near-identical block, pick the
   correct/latest variant (often amd64's) and apply uniformly. Note
   incompatibilities (rpi400 has no UEFI ESP) via clean
   conditionals.
3. **Add board-aware hooks** — `lib/board-detect.sh` returns
   `{amd64-live, rpi400-live, mochabin-live, mochabin-install}` so
   the shared helpers know when to skip steps (e.g. no GRUB EFI on
   rpi400, no kiosk packages on mochabin headless install).
4. **CI harness** — single workflow matrix builds all 4 from same
   lib/. Per-platform test step boots the image in QEMU (where
   possible) and checks `/etc/secubox/build-info.json` + a sanity
   set of services.

## Open questions

* Should `firstboot.sh` itself be refactored into lib/firstboot/*.sh
  modules sourced at install time, or kept as a monolithic
  oneshot ?
* Does rpi400 need its own boot menu (no GRUB) handler in lib/, or
  can we adopt extlinux/syslinux as the shared bootloader path ?
* secubox-net-detect.service: gated by `.net-configured` marker but
  has been the source of multiple regressions (br-lan phantom,
  netplan overwrite) — keep, demote to opt-in, or absorb into
  firstboot.sh ?

## Estimate

* Phase 1 (extract verbatim): 2-3 days for a careful operator.
* Phase 2 (drift resolution): 1 week — touches every script, needs
  per-platform smoke test.
* Phase 3 (board hooks): 2-3 days.
* Phase 4 (CI harness): 2 days.

**Total: ~2 weeks dedicated focus.** Not a side-project.

## Pre-requisites before kicking this off

* All v2.12.x bugs cleared from the issue tracker — refactor on top
  of a known-working state.
* Snapshot tag of pre-refactor build artefacts so we can byte-diff
  the post-refactor output as a regression gate.
