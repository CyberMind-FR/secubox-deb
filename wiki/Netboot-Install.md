# Netboot Install — MOCHAbin from gk2

Network-boot a second MOCHAbin (c3box) from gk2's netboot rig and perform a
fully automated, cryptographically verified SecuBox Debian install to eMMC.

Validated 2026-06-27 (factory U-Boot 2020.10, custom kernel 6.12.85 #5secubox,
image `secubox-mochabin-bookworm` CI run 27426515472).

---

## Prerequisites

| Item | Detail |
|------|--------|
| Cable | Straight copper RJ45 from gk2 **lan1** to c3box **mvpp2-2** (the single copper port, not the 4-port switch) |
| Signing key | `secubox-netboot.key` on gk2 (matches `netboot-image.pub` embedded in the installer FIT) |
| Image | `secubox-mochabin-bookworm` artifact from CI (latest successful build-packages + build-image run) |
| gk2 services | dnsmasq DHCP on `192.168.77.0/24`, TFTP root `/srv/tftp`, nginx `:8099` serving signed image |
| Serial console | USB-UART to c3box debug header (115200 8N1) to catch factory U-Boot |

> **Port note**: Only `mvpp2-2` (the single copper RJ45) is reachable by the factory U-Boot.
> The 4 switch ports require the MV88E6XXX DSA driver which is absent at early boot.

---

## Step 1 — Publish the signed image on gk2

```bash
# Sign the image
openssl dgst -sha256 -sign /etc/secubox/netboot/secubox-netboot.key \
  -out /srv/netboot/sbx.img.gz.sig /data/sbx.img.gz

# Publish (symlink or copy into the nginx root)
ln -sf /data/sbx.img.gz /srv/netboot/sbx.img.gz
ln -sf /data/sbx.img.gz.sig /srv/netboot/sbx.img.gz.sig

# Verify the public key matches what the installer FIT embeds
openssl rsa -in /etc/secubox/netboot/secubox-netboot.key -pubout \
  | diff - /etc/secubox/netboot/netboot-image.pub
```

---

## Step 2 — Catch the factory U-Boot on c3box

Power-cycle c3box. On the serial console you have **2 seconds** (`bootdelay=2`).

> **Important**: press **Enter** to interrupt autoboot — NOT Ctrl-C.

```
Hit any key to stop autoboot:  2
Marvell>> 
```

---

## Step 3 — Configure TFTP environment

```
# Set TFTP block size for fast transfer
setenv tftpblocksize 1468

# Set the TFTP server (gk2 lan1 address)
setenv serverip 192.168.77.1
setenv ipaddr 192.168.77.100

# Save (optional — env is NOT in SPI mtd2 on this board, lost on power cycle)
# saveenv
```

> **U-Boot env note**: `fw_setenv` from Linux has no effect on this board — the factory
> U-Boot does not store its env in SPI mtd2 (a stale foreign env sits there). All env
> changes must be made interactively in the U-Boot shell.

---

## Step 4 — Load installer via TFTP and boot

```
# Load kernel, DTB, initrd into free RAM addresses (NOT 0x02080000 — reserved)
tftpboot 0x0a000000 Image
tftpboot 0x09000000 armada-7040-mochabin.dtb
tftpboot 0x10000000 initrd.img

# Boot
booti 0x0a000000 0x10000000 0x09000000
```

The installer rescue shell appears. The 49 MB signed FIT is fetched automatically
from `http://192.168.77.1:8099/` during installer init.

---

## Step 5 — Automated verified install from the rescue shell

```bash
# Download image to RAM (c3box has 8 GB — fits comfortably)
wget http://192.168.77.1:8099/sbx.img.gz -O /tmp/sbx.img.gz
wget http://192.168.77.1:8099/sbx.img.gz.sig -O /tmp/sbx.img.gz.sig

# Verify signature against the embedded public key
openssl dgst -sha256 -verify /etc/secubox/installer/netboot-image.pub \
  -signature /tmp/sbx.img.gz.sig /tmp/sbx.img.gz
# Expected output: Verified OK

# Stream to eMMC (progress tracked via status=progress)
gunzip -c /tmp/sbx.img.gz | dd of=/dev/mmcblk0 bs=4M conv=fsync status=progress
sync
```

---

## Step 6 — Fix auto-boot persistence (boot.scr)

The image ships `extlinux.conf` pointing to `0x02080000` (reserved on factory U-Boot —
causes an immediate reset). It also ships no compiled `boot.scr`. Build one before rebooting:

```bash
# From the rescue shell, after dd completes, mount the boot partition
mount /dev/mmcblk0p1 /mnt

cat > /tmp/boot.cmd << 'EOF'
setenv bootargs "console=ttyS0,115200 earlycon root=LABEL=rootfs rw"
load mmc 0:1 0x0a000000 Image
load mmc 0:1 0x10000000 initrd.img
load mmc 0:1 0x09000000 armada-7040-mochabin.dtb
booti 0x0a000000 0x10000000:${filesize} 0x09000000
EOF

mkimage -C none -A arm64 -T script -d /tmp/boot.cmd /mnt/boot.scr
sync
umount /mnt
```

Reboot. The factory U-Boot picks up `boot.scr` from mmc and boots Debian unattended.

---

## Gotchas

| Symptom | Root cause | Fix |
|---------|-----------|-----|
| Board resets immediately after kernel load | Kernel loaded at `0x02080000` (reserved memory region) | Use `0x0a000000` for kernel, `0x10000000` for initrd |
| TFTP very slow | Default block size too small | `setenv tftpblocksize 1468` |
| `fw_setenv` from Linux has no effect | Factory U-Boot env is NOT in SPI mtd2 (stale foreign env there) | Reconfigure U-Boot env interactively each time, or use boot.scr |
| Autoboot not interrupted | Interrupt key is **Enter**, not Ctrl-C | Press Enter within 2 seconds of power-on |
| Switch ports (4-port block) unreachable at boot | MV88E6XXX DSA driver absent in factory U-Boot | Cable must go to `mvpp2-2` (single copper RJ45) |
| Image boots but SecuBox stack not starting | First boot — wait ~90 s for systemd units to settle | Check `journalctl -u secubox-aggregator` |

---

## eMMC layout after install

| Partition | Type | Mount | Purpose |
|-----------|------|-------|---------|
| mmcblk0p1 | FAT32 | `/boot` | Kernel, DTB, initrd, boot.scr, extlinux.conf |
| mmcblk0p2 | ext4 | `/` | Root filesystem |
| mmcblk0p3 | ext4 | `/data` | Persistent data |

---

## Related

- [[ARM-Installation]] — general ARM installation guide
- [[Hardware-Matrix]] — board support matrix
- `feature/748-enhanced-tow-boot-http-netboot-serial-fl` — enhanced Tow-Boot with native HTTP/wget (blocked, see #748)
- GitHub: [#748](https://github.com/CyberMind-FR/secubox-deb/issues/748) · [#737](https://github.com/CyberMind-FR/secubox-deb/issues/737)
