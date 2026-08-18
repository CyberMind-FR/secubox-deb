<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MOCHAbin mPCIe Slot J5 — EP06 Investigation Runbook

**Status:** parked. Runbook ready to execute when an mPCIe modem is
reseated in J5 (the original EP06-E on hand; no spare on order).
**Related issues:** #255 (DTS UTMI PHY landed) · #345 (this runbook).

## Symptom

After the DTS patch in #255 wired the UTMI PHY to `cp0_usb3_1`, the
mPCIe slot J5 USB pipe is fully alive — kernel reports the controller
binds cleanly and `lsusb -t` shows 4 USB buses (vs 2 before the patch).

But plugging a Quectel EP06-E modem into J5 still doesn't produce any
`new high-speed USB device` event in dmesg, no `2c7c:0306` in `lsusb`,
and `lspci -vvv` reports the PCIe side as `DLActive-` (no link
partner). The modem is electrically dark on both interfaces of the
slot.

## Hypothesis

mPCIe defines several control pins per slot that the host must drive
for the device to wake:

| Pin           | Direction   | Meaning                 | Default                          |
| ------------- | ----------- | ----------------------- | -------------------------------- |
| PERST#        | host→device | reset (active low)      | must transition low→high at boot |
| W_DISABLE#    | host→device | radio kill (active low) | must be HIGH for radio           |
| WAKE#         | device→host | wake event (active low) | input only                       |
| PWR_EN / 3.3V | rail        | power                   | must be ON                       |

In `armada-7040-mochabin.dts`:

- `cp0_pcie2` has `reset-gpios = <&cp0_gpio1 9 GPIO_ACTIVE_LOW>` —
  PERST# is declared.
- `cp0_usb3_1` has UTMI PHY but **no W_DISABLE# / PWR_EN / WAKE#
  GPIOs** declared.

The schematic for the MOCHAbin J5 slot is not in this repo, and
Globalscale only publishes a partial. So we don't know which CP0 GPIO
(if any) is wired to W_DISABLE#. The other option is that it's
hard-tied (HIGH or LOW) on the PCB.

Reference: `cn9132-clearfog.dts` declares `rfkill-gpio` nodes for each
of its mPCIe / M.2 slots (lines 69–122). That's the pattern to copy.

## Investigation procedure

`scripts/probe-mpcie-gpios.sh` (v0.2.0) is a one-line-at-a-time probe.
v0.1.0 of this script ran a blanket sweep across all "unused input"
CP0 GPIOs and took gk2 hard-down on 2026-05-22 — `gpioinfo`'s
`[used]` tag only reflects what the kernel *requested*, and several
unrequested lines are physically wired to critical functions (eth
switch reset, PCIe2 PERST#, pca9554 IRQ). v0.2.0 therefore:

- skips a hardcoded `DANGER_LINES` list (those three + future
  additions);
- refuses to touch `gpiochip2` (CP0 GPIO1) entirely without
  `--allow-chip2` (no per-line schematic mapping for that bank yet);
- defaults to dry-run — listing candidates without driving anything;
- requires `--commit` + `--line CHIP N` to actually drive a line HIGH.

There is no longer a blanket-sweep mode.

Prerequisites:

- Run **on the MOCHAbin**, as root.
- A known-good mPCIe device seated in J5 (preferably the EP06 modem;
  failing that, any mPCIe-USB device).
- Screw tightened — the slot has spring-contact retention only.

### Step 1 — baseline (safe, no GPIO writes)

```bash
# from the dev host
scp scripts/probe-mpcie-gpios.sh root@<mochabin>:/tmp/
ssh root@<mochabin> 'bash /tmp/probe-mpcie-gpios.sh --baseline'
```

Output goes to `/var/log/secubox/mpcie-probe-<timestamp>.log`. Check
the gpioinfo table to confirm the lines you expect are `[used]` (PHY
reset on cp0_gpio0 line 12, etc.) — the script will refuse to touch
those.

### Step 2 — list candidates (dry-run, default mode)

```bash
ssh root@<mochabin> 'bash /tmp/probe-mpcie-gpios.sh'
```

Prints the candidate list on `gpiochip1` (CP0 GPIO0). Each entry is
of the form `gpiochip1:N` — an unrequested input that is NOT in
`DANGER_LINES`. No GPIO is driven in this mode.

If you want candidates on `gpiochip2` too (entire bank held off by
default), add `--allow-chip2` — only do this if you can physically
power-cycle the board if something locks up.

### Step 3 — commit a single line

Pick one candidate from step 2, then drive it for `SETTLE_SEC=3` s
(longer with the env var if the EP06 needs more time to boot its
radio):

```bash
ssh root@<mochabin> \
  'SETTLE_SEC=10 bash /tmp/probe-mpcie-gpios.sh --line gpiochip1 14 --commit'
```

The script:

1. Snapshots `lsusb` + last `dmesg` line.
2. Drives the line output-HIGH for `SETTLE_SEC` seconds.
3. Re-snapshots.
4. Releases the line (libgpiod restores input direction on close).
5. If `lsusb` differs or new "new high-speed USB device" /
   "Quectel" / `2c7c` appears in dmesg, logs `*** CHANGE DETECTED ***`.

A successful probe gives you the GPIO number to wire into the DTS.
Iterate over candidates one at a time; if a probe locks up the board,
add the line to `DANGER_LINES` in the script before retrying.

## Translating findings to DTS

Once a line is confirmed, add an `rfkill-gpio` block to
`armada-7040-mochabin.dts` next to the existing `&cp0_usb3_1` /
`&cp0_pcie2` declarations. Template (replace `<chip>` and `<line>`):

```dts
/ {
    /* J5 W_DISABLE# (mPCIe modem radio enable) */
    rfkill-mpcie-modem {
        compatible = "rfkill-gpio";
        label = "mpcie modem (J5)";
        radio-type = "wwan";
        /* rfkill-gpio inverts internally; ACTIVE_HIGH = pin HIGH when
         * radio is OFF, LOW when ON. Check polarity against the
         * schematic before merging. */
        shutdown-gpios = <&<chip> <line> GPIO_ACTIVE_HIGH>;
    };
};
```

If the modem still doesn't enumerate after asserting W_DISABLE# HIGH,
the next suspect is a missing 3.3V rail enable. Look for an unused
GPIO that toggles `/sys/class/regulator/regulator-N/state` from
`disabled` → `enabled` when driven HIGH.

## Disambiguating "dead modem" vs "slot not powering it"

There's no spare EP06 coming, so we can't simply swap units. If the
GPIO sweep finds no candidate line, the remaining signal that the
modem is alive at all is:

- **3.3V on J5 pin 2 / 24 / 39 / 41 / 52** — multimeter on the
  connector with the modem unseated tells you if the slot's power rail
  is live. If 3.3V is missing, the modem can't possibly enumerate
  regardless of W_DISABLE#.
- **Modem LED** — the EP06-E lights an onboard status LED when it has
  power. Visible through the chassis cutout near J5.

Multimeter scoping is outside the runbook's automated scope but is the
next escalation if the sweep is inconclusive.

## Outcome we want

A single small DTS patch (rfkill-gpio block, maybe a regulator) that
makes EP06 enumerate at boot without any post-boot intervention. That
unblocks #236 (secubox-rbs-sensor v0.2) and the v0.4 SMS-via-EP06
notification channel for secubox-sentinelle-gsm.
