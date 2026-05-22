# MOCHAbin mPCIe Slot J5 — EP06 Investigation Runbook

**Status:** in progress, blocked on spare EP06 hardware.
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

| Pin           | Direction   | Meaning                | Default                          |
| ------------- | ----------- | ---------------------- | -------------------------------- |
| PERST#        | host→device | reset (active low)     | must transition low→high at boot |
| W_DISABLE#    | host→device | radio kill (active low) | must be HIGH for radio          |
| WAKE#         | device→host | wake event (active low) | input only                      |
| PWR_EN / 3.3V | rail        | power                  | must be ON                       |

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

`scripts/probe-mpcie-gpios.sh` automates an empirical sweep. It probes
each *unrequested* CP0 GPIO line one at a time, driving it HIGH for a
few seconds while watching `dmesg` and `lsusb` for any change. Lines
that the kernel has already requested (PHY reset, switch reset, LED
shutdown, etc.) are skipped — never touched.

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

### Step 2 — sweep all unused lines

```bash
/usr/local/sbin/probe-mpcie-gpios
```

For each unused CP0 GPIO, the script:

1. Snapshots `lsusb` + last `dmesg` line.
2. Drives the line output-HIGH for `SETTLE_SEC` seconds (default 3).
3. Re-snapshots.
4. Releases the line (libgpiod restores input direction on close).
5. If `lsusb` differs or new "new high-speed USB device" /
   "Quectel" / `2c7c` appears in dmesg, logs `*** CHANGE DETECTED ***`.

A successful probe gives you the GPIO number to wire into the DTS.

### Step 3 — narrow to a single line

If the sweep flags a candidate, re-run with `--line` for confirmation:

```bash
SETTLE_SEC=10 /usr/local/sbin/probe-mpcie-gpios --line gpiochip2 14
```

Longer settle helps if the modem's boot sequence is slow (EP06 takes
~6–8s to enumerate after radio enable).

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

## Decisions deferred to hardware availability

- We can't tell whether the current EP06 in our lab is bad or just
  not getting power. The spare hardware order (from
  `.claude/WIP.md`) will let us swap and disambiguate.
- If the spare also fails to enumerate with the GPIO sweep returning
  no candidates, the next step is to scope the J5 connector with a
  multimeter on pins 20 (W_DISABLE#) and 2/24/39/41/52 (3V3) — but
  that's outside the scope of this runbook.

## Outcome we want

A single small DTS patch (rfkill-gpio block, maybe a regulator) that
makes EP06 enumerate at boot without any post-boot intervention. That
unblocks #236 (secubox-rbs-sensor v0.2) and the v0.4 SMS-via-EP06
notification channel for secubox-sentinelle-gsm.
