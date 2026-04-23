# ESPRESSObin U-Boot Boot Commands — Eye Remote

## Overview

This guide covers configuring ESPRESSObin U-Boot to boot from **Eye Remote mass storage** (active slot) or **TFTP** (shadow slot). The Eye Remote Pi Zero W provides USB OTG connectivity and network access for dual-boot management.

**Key network setup:**
- Eye Remote IP: `10.55.0.2`
- ESPRESSObin IP: `10.55.0.1`
- Network: `10.55.0.0/30` (routable via USB OTG ECM)

---

## Prerequisites

1. **Eye Remote Pi Zero W**
   - Running v2.1.0 or later
   - USB OTG ECM mode enabled
   - DHCP server active on `10.55.0.2`

2. **ESPRESSObin**
   - U-Boot installed in SPI NOR flash or eMMC
   - Serial console access (TTL UART 115200 baud)
   - USB OTG micro-AB port (supports OTG mode)

3. **Connectivity**
   - USB OTG cable (Pi Zero ↔ ESPRESSObin USB OTG port)
   - Serial console cable (UART3, pins TXD/RXD/GND)
   - Optional: Ethernet for TFTP boot (fallback)

4. **Host Files**
   - Kernel: `Image` (Linux ARM64 binary)
   - DTB: `armada-3720-espressobin.dtb` (device tree)
   - Present on Eye Remote mass storage or TFTP server

---

## Power Ordering — Two Approaches

### Option A: Independent Power (Recommended)

Safest method — power devices independently:

1. **Connect USB OTG cable** (Pi Zero ↔ ESPRESSObin OTG port)
   - Pi Zero: micro-AB port
   - ESPRESSObin: OTG micro-B port
   - Cable acts as **data link only**

2. **Power Pi Zero separately** (5V via micro-USB)
   - Pi Zero boots → enables USB host (via g_ether overlay)
   - Exports mass storage LUN

3. **Power ESPRESSObin independently** (external 5V)
   - Detects USB device (mass storage LUN) after U-Boot starts
   - No risk of back-power or brown-out

### Option B: Retry Loop in U-Boot

For scenarios where ESPRESSObin must power from USB OTG:

```
# In U-Boot console (press Enter during boot)
setenv bootcmd 'usb start; if usb storage; then fatload usb 0 ${kernel_addr_r} Image && fatload usb 0 ${fdt_addr_r} armada-3720-espressobin.dtb && booti ${kernel_addr_r} - ${fdt_addr_r}; fi; false'
saveenv
reset
```

U-Boot will:
1. Power on via USB OTG
2. Wait ~2s for Pi Zero to stabilize
3. Attempt `usb start` → `usb storage`
4. If USB device appears → load kernel/DTB → boot
5. If timeout → retry or fall back to TFTP

---

## Mass Storage Boot (Active Slot)

### Quick Check: USB Enumeration

Enter U-Boot console and verify USB device is detected:

```
ESPRESSObin=> usb start
Starting USB Controller
USB XHCI 1.00

ESPRESSObin=> usb storage
  Device 0: Vendor: QEMU     Rev: 2.5+ Type: Removable Hard Disk
            Capacity: 1024 MB = 1 GB (2097152 x 512)

ESPRESSObin=> usb tree
USB device tree:
  1  XHCI 1.00
     | 1 Hub: QEMU QEMU USB Storage Controller (product id 0x0070)
     | | 1 Mass Storage: QEMU USB Storage (000010000000000000000000)
```

### Boot Command: Active Slot

Set boot command to load kernel and DTB from mass storage:

```
ESPRESSObin=> setenv bootcmd 'usb start; usb storage; fatload usb 0 ${kernel_addr_r} Image; fatload usb 0 ${fdt_addr_r} armada-3720-espressobin.dtb; booti ${kernel_addr_r} - ${fdt_addr_r}'

ESPRESSObin=> setenv bootargs 'root=/dev/mmcblk0p2 rw rootwait console=ttyMV0,115200'

ESPRESSObin=> saveenv
Saving Environment to SPI Flash... OK
```

**Explanation:**
- `usb start` — Initialize USB controller
- `usb storage` — Detect USB storage device
- `fatload usb 0 ${kernel_addr_r} Image` — Load kernel from USB LUN 0
- `fatload usb 0 ${fdt_addr_r} armada-3720-espressobin.dtb` — Load DTB
- `booti ${kernel_addr_r} - ${fdt_addr_r}` — Boot with kernel at `kernel_addr_r`, no ramdisk, DTB at `fdt_addr_r`
- `saveenv` — Persist to SPI NOR flash

### Verify Boot Environment

List current environment variables:

```
ESPRESSObin=> printenv bootcmd
bootcmd=usb start; usb storage; fatload usb 0 ${kernel_addr_r} Image; fatload usb 0 ${fdt_addr_r} armada-3720-espressobin.dtb; booti ${kernel_addr_r} - ${fdt_addr_r}

ESPRESSObin=> printenv kernel_addr_r
kernel_addr_r=0x2000000

ESPRESSObin=> printenv fdt_addr_r
fdt_addr_r=0x1f00000

ESPRESSObin=> printenv bootargs
bootargs=root=/dev/mmcblk0p2 rw rootwait console=ttyMV0,115200
```

---

## TFTP Boot (Shadow Slot)

### Prerequisite: TFTP Server

Set up TFTP on Eye Remote or a separate machine:

```bash
# Eye Remote (10.55.0.2) or host on 10.55.0.0/30 network
mkdir -p /srv/tftp
cp Image /srv/tftp/
cp armada-3720-espressobin.dtb /srv/tftp/

# Start dnsmasq or in.tftpd listening on 10.55.0.2:69
systemctl restart dnsmasq
# or
systemctl restart tftpd-hpa
```

### Boot Command: Shadow Slot

Configure TFTP boot for failover scenarios:

```
ESPRESSObin=> setenv serverip 10.55.0.2

ESPRESSObin=> setenv bootcmd 'usb start; if usb storage; then fatload usb 0 ${kernel_addr_r} Image && fatload usb 0 ${fdt_addr_r} armada-3720-espressobin.dtb && booti ${kernel_addr_r} - ${fdt_addr_r}; else tftp ${kernel_addr_r} Image && tftp ${fdt_addr_r} armada-3720-espressobin.dtb && booti ${kernel_addr_r} - ${fdt_addr_r}; fi'

ESPRESSObin=> saveenv
```

**Logic:**
1. Try USB mass storage boot (active slot)
2. If USB fails or times out → TFTP boot (shadow slot)
3. Either way, boot the kernel + DTB combination

### Direct TFTP Boot (No Fallback)

For testing the TFTP shadow channel in isolation:

```
ESPRESSObin=> setenv serverip 10.55.0.2

ESPRESSObin=> tftp ${kernel_addr_r} Image
Using usb_ether device
TFTP from server 10.55.0.2; our IP address is 10.55.0.1
Filename 'Image'.
Load address: 0x2000000
Loading: #################################################################
         1234 Bytes/s
done
Bytes transferred = 16384000 (fa80000 in hex)

ESPRESSObin=> tftp ${fdt_addr_r} armada-3720-espressobin.dtb
Using usb_ether device
TFTP from server 10.55.0.2; our IP address is 10.55.0.1
Filename 'armada-3720-espressobin.dtb'.
Load address: 0x1f00000
Loading: #
done
Bytes transferred = 32768 (8000 in hex)

ESPRESSObin=> booti ${kernel_addr_r} - ${fdt_addr_r}
```

---

## Workflow: Test Then Promote

### Phase 1: Upload to TFTP (Shadow)

1. Build new kernel and DTB on development machine
2. Copy to TFTP server at `/srv/tftp/`
   ```bash
   scp Image root@10.55.0.2:/srv/tftp/
   scp armada-3720-espressobin.dtb root@10.55.0.2:/srv/tftp/
   ```

### Phase 2: Test via TFTP (Shadow Boot)

1. Interrupt U-Boot at prompt
2. Clear USB first (in case old device present):
   ```
   ESPRESSObin=> usb reset
   ```
3. Boot via TFTP:
   ```
   ESPRESSObin=> setenv serverip 10.55.0.2
   ESPRESSObin=> tftp ${kernel_addr_r} Image
   ESPRESSObin=> tftp ${fdt_addr_r} armada-3720-espressobin.dtb
   ESPRESSObin=> booti ${kernel_addr_r} - ${fdt_addr_r}
   ```

### Phase 3: Verify Boot Success

Once kernel boots, verify via SSH:

```bash
ssh root@10.55.0.1
# Verify kernel version, modules, etc.
uname -a
```

### Phase 4: Promote to Active Slot (USB Mass Storage)

Once TFTP boot is verified:

1. Copy files to Eye Remote mass storage
   ```bash
   scp Image root@10.55.0.2:/mnt/usb/boot/
   scp armada-3720-espressobin.dtb root@10.55.0.2:/mnt/usb/boot/
   ```

2. Update U-Boot bootcmd to use USB:
   ```
   ESPRESSObin=> setenv bootcmd 'usb start; usb storage; fatload usb 0 ${kernel_addr_r} Image; fatload usb 0 ${fdt_addr_r} armada-3720-espressobin.dtb; booti ${kernel_addr_r} - ${fdt_addr_r}'
   ESPRESSObin=> saveenv
   ```

3. Reset and verify USB boot:
   ```
   ESPRESSObin=> reset
   ```

---

## Troubleshooting

### Issue: "No USB storage device(s) found"

**Cause:** Pi Zero not detected or not in host mode.

**Diagnosis:**
```
ESPRESSObin=> usb start
Starting USB Controller
USB XHCI 1.00

ESPRESSObin=> usb tree
USB device tree:
  1  XHCI 1.00
     1 Hub: QEMU QEMU USB Storage Controller (product id 0x0070)
     (nothing under hub — no device)
```

**Solutions:**
1. **Check Pi Zero power:** Verify 5V applied to Pi Zero micro-USB port
   ```bash
   # On Pi Zero:
   vcgencmd get_throttled  # Should be 0x0 (no throttle)
   ```

2. **Check USB cable:** Swap cable, verify all connections
   ```bash
   # On Pi Zero:
   lsusb
   # Should show usb_ethernet module loaded
   lsmod | grep g_ether
   ```

3. **Restart U-Boot retry loop:** Reset both devices
   ```
   ESPRESSObin=> reset
   ```

4. **Check Eye Remote ECM driver:** On Pi Zero, verify interface is up
   ```bash
   ip link show usb0
   # Should be "UP"
   ```

### Issue: "Unable to read file Image"

**Cause:** File not found on mass storage, or incorrect filename.

**Diagnosis:**
```
ESPRESSObin=> usb storage
ESPRESSObin=> fatls usb 0
(no files listed, or different names)
```

**Solutions:**
1. **Verify file exists on Eye Remote:**
   ```bash
   ls -lh /mnt/usb/boot/Image
   ```

2. **Check FAT filesystem:**
   ```bash
   mount | grep usb0
   fsck.vfat -v /dev/sda1
   ```

3. **Verify filename case:** U-Boot FAT driver is case-sensitive
   ```
   ESPRESSObin=> fatls usb 0
   # Should show "Image" (capital I)
   ```

4. **Recreate boot partition if corrupted:**
   ```bash
   mkfs.vfat -F 32 /dev/sda1
   mkdir -p /mnt/usb/boot
   mount /dev/sda1 /mnt/usb/boot
   cp Image armada-3720-espressobin.dtb /mnt/usb/boot/
   umount /mnt/usb/boot
   ```

### Issue: TFTP Timeout

**Cause:** Network unreachable, TFTP server down, or firewall blocking.

**Diagnosis:**
```
ESPRESSObin=> setenv serverip 10.55.0.2
ESPRESSObin=> tftp ${kernel_addr_r} Image
Using usb_ether device
TFTP from server 10.55.0.2; our IP address is 10.55.0.1
Filename 'Image'.
Load address: 0x2000000
Waiting for ethernet device... timeout!
```

**Solutions:**
1. **Verify network connectivity:**
   ```bash
   # On Pi Zero or test host
   ping 10.55.0.1
   # Should succeed
   ```

2. **Check TFTP server is running:**
   ```bash
   systemctl status dnsmasq  # or tftpd-hpa
   netstat -uln | grep :69   # TFTP port
   ```

3. **Verify firewall allows TFTP:**
   ```bash
   ufw allow 69/udp
   # or nftables
   nft add rule inet filter input udp dport 69 accept
   ```

4. **Test TFTP connectivity manually:**
   ```bash
   # On test host on 10.55.0.0/30 network
   echo "test" > /srv/tftp/test.txt
   tftp 10.55.0.2
   > get test.txt
   ```

5. **Set TFTP timeout in U-Boot:**
   ```
   ESPRESSObin=> setenv netretry 5
   ESPRESSObin=> saveenv
   ```

### Issue: Kernel Loads but Won't Boot

**Symptoms:** Files load successfully, but kernel crashes or hangs.

**Diagnosis:**
```
ESPRESSObin=> booti ${kernel_addr_r} - ${fdt_addr_r}
## Flattened Device Tree blob at 1f00000
## Kernel loaded from 0x02000000
## Loading Device Tree to 27f00000, end 27f08000 ... OK
## Booting using the fdt blob at 0x27f00000
(hangs here)
```

**Solutions:**
1. **Verify DTB matches kernel version:**
   ```bash
   file armada-3720-espressobin.dtb
   # Should show "Device Tree Blob"
   ```

2. **Check kernel bootargs:**
   ```
   ESPRESSObin=> printenv bootargs
   # Verify root= device exists
   ```

3. **Enable serial console on kernel side:**
   ```
   ESPRESSObin=> setenv bootargs 'root=/dev/mmcblk0p2 rw rootwait console=ttyMV0,115200 earlyprintk'
   ESPRESSObin=> saveenv
   ```

4. **Rebuild kernel with proper config:**
   ```bash
   # Ensure CONFIG_SERIAL_MVEBU_UART=y in kernel .config
   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
        mvebu_v7_defconfig
   ```

---

## Environment Variable Reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `bootcmd` | varies | Command executed at boot |
| `bootargs` | varies | Kernel boot arguments (root, console, etc.) |
| `kernel_addr_r` | 0x2000000 | DRAM address for kernel load |
| `fdt_addr_r` | 0x1f00000 | DRAM address for DTB load |
| `ramdisk_addr_r` | varies | DRAM address for ramdisk (if used) |
| `serverip` | 10.55.0.2 | TFTP server IP |
| `ipaddr` | 10.55.0.1 | ESPRESSObin IP (USB OTG) |
| `netmask` | 255.255.255.252 | Network mask for USB OTG link |
| `netretry` | 1 | TFTP retry count |

**To view all:**
```
ESPRESSObin=> printenv
```

**To save any change:**
```
ESPRESSObin=> saveenv
```

---

## See Also

- `docs/eye-remote/usb-otg-ecm-mode.md` — USB OTG ECM setup on Pi Zero
- `docs/eye-remote/mass-storage-lun.md` — Exposing mass storage LUN
- `docs/eye-remote/network-setup.md` — 10.55.0.0/30 network config
- U-Boot Armada 3720 documentation: https://u-boot.readthedocs.io/
- ESPRESSObin Quick Start: https://espressobin.docs.globalscale.com/

---

## Examples

### Full Bootcmd with Fallback

Active slot (USB) with fallback to shadow slot (TFTP):

```
setenv bootcmd 'usb start; if usb storage; then echo "Booting from USB..."; fatload usb 0 ${kernel_addr_r} Image && fatload usb 0 ${fdt_addr_r} armada-3720-espressobin.dtb && booti ${kernel_addr_r} - ${fdt_addr_r}; else echo "USB boot failed, trying TFTP..."; tftp ${kernel_addr_r} Image && tftp ${fdt_addr_r} armada-3720-espressobin.dtb && booti ${kernel_addr_r} - ${fdt_addr_r}; fi'

setenv bootargs 'root=/dev/mmcblk0p2 rw rootwait console=ttyMV0,115200'

saveenv
reset
```

### Development Iteration (TFTP Only)

For rapid kernel development, stay on TFTP:

```
setenv bootcmd 'usb reset; setenv serverip 10.55.0.2; tftp ${kernel_addr_r} Image && tftp ${fdt_addr_r} armada-3720-espressobin.dtb && booti ${kernel_addr_r} - ${fdt_addr_r}'

setenv bootargs 'root=/dev/mmcblk0p2 rw rootwait console=ttyMV0,115200 earlyprintk'

saveenv
reset
```

---

**Author:** CyberMind — Gérald Kerma
**License:** Proprietary / ANSSI CSPN candidate
**Last Updated:** 2024
