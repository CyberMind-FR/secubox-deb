# Eye Remote Bootstrap Media Management

**Version:** 2.1.0
**Last Updated:** 2026-04-23
**Status:** Production
**Author:** CyberMind — Gerald Kerma

---

## Overview

The Eye Remote Bootstrap system extends the Pi Zero W USB OTG gadget to provide a managed boot media channel for ESPRESSObin boards. Via a single USB OTG cable, the Eye Remote simultaneously provides:

1. **Metrics Transport** (ECM) — Ethernet-over-USB network on `10.55.0.0/30`
2. **Serial Console** (ACM) — Debug console on `/dev/ttyACM0` (host) / `/dev/ttyGS0` (gadget)
3. **Boot Media** (Mass Storage) — USB LUN serving kernel, DTB, initrd, and rootfs images

This enables a recovery workflow without requiring physical intervention: flash a new kernel from the Eye Remote web dashboard, test it on the target board, then promote it to the active slot with atomic swap semantics.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Eye Remote Pi Zero W                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┐    ┌──────────────────┐    ┌───────────────┐  │
│  │ FastAPI Router  │───▶│ core/boot_media  │───▶│ gadget-setup  │  │
│  │ /boot-media/*   │    │ (Python)         │    │ (Bash)        │  │
│  └────────┬────────┘    └────────┬─────────┘    └───────┬───────┘  │
│           │                      │                      │          │
│           ▼                      ▼                      ▼          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              /var/lib/secubox/eye-remote/boot-media/        │   │
│  │  ┌─────────┐  ┌─────────┐  ┌──────────────────────────────┐  │   │
│  │  │ active  │  │ shadow  │  │ images/<sha256>.img          │  │   │
│  │  │ (link)  │  │ (link)  │  │ images/<sha256>.img.tmp (UP) │  │   │
│  │  └────┬────┘  └────┬────┘  └──────────────────────────────┘  │   │
│  │       │            │                                         │   │
│  │       ▼            ▼                                         │   │
│  │  ┌─────────────────────────────┐    ┌────────────────────┐  │   │
│  │  │ LUN 0 (mass_storage.usb0)   │    │ tftp/ (symlinks)   │  │   │
│  │  │ points to active slot       │    │ serves shadow slot │  │   │
│  │  └─────────────────────────────┘    └────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                    libcomposite configfs                       │ │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────────────┐           │ │
│  │  │ ecm.usb0 │  │ acm.usb0 │  │ mass_storage.usb0  │           │ │
│  │  │ 10.55.0.2│  │ ttyGS0   │  │ LUN 0 (removable)  │           │ │
│  │  └──────────┘  └──────────┘  └────────────────────┘           │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ USB OTG cable
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     ESPRESSObin U-Boot                              │
│  Option 1: usb start → fatload usb 0 Image                          │
│  Option 2: dhcp → tftpboot $kernel_addr_r Image (shadow channel)    │
└─────────────────────────────────────────────────────────────────────┘
```

### Boot Media Directory Structure

The Eye Remote maintains a double-buffer 4R storage layout:

```
/var/lib/secubox/eye-remote/boot-media/
├── state.json                    ← Boot media metadata & state
├── active                        ← Symlink → images/<sha256>.img
├── shadow                        ← Symlink → images/<sha256>.img (or NULL)
├── images/
│   ├── a1b2c3d4e5f6.img         ← FAT32 or ext4 image (read-only, deduplicated)
│   ├── f0e1d2c3b4a5.img.tmp     ← Upload in progress (temporary)
│   ├── rollback-r1/             ← Previous active (4R #1)
│   │   └── a1b2c3d4e5f6.img
│   ├── rollback-r2/             ← Previous active (4R #2)
│   ├── rollback-r3/             ← Previous active (4R #3)
│   └── rollback-r4/             ← Previous active (4R #4)
└── tftp/                        ← TFTP service root (symlinks to shadow)
    ├── Image → ../images/f0e1d2c3b4a5.img
    ├── device-tree.dtb
    └── initrd.img
```

### State Machine

```
Initial State: Empty (no active, no shadow)
                    │
                    ▼
    ┌─────────────────────────────────┐
    │   UPLOAD SHADOW                 │
    │ (via /api/v1/eye-remote/        │
    │  boot-media/upload)             │
    └────────────┬────────────────────┘
                 │
                 ▼
    ┌─────────────────────────────────┐
    │   SHADOW READY                  │
    │ (image valid, extractable)      │
    │                                 │
    │ [Branch A] Test via TFTP ──┐   │
    │            (Optional)       │   │
    │                             ▼   │
    │                      Testing...  │
    │                             │   │
    │ [Branch B] ◄───────────────┘   │
    │ Promote Shadow to Active        │
    │ (via /api/v1/eye-remote/        │
    │  boot-media/swap)               │
    └────────────┬────────────────────┘
                 │
                 ▼
    ┌─────────────────────────────────┐
    │   ACTIVE ONLY                   │
    │ (shadow cleared, active set)    │
    │ (LUN ejected & reattached)      │
    └────────────┬────────────────────┘
                 │
    [Optional]   │ Upload new shadow
                 ▼
    ┌─────────────────────────────────┐
    │   READY TO SWAP                 │
    │ (active + shadow both set)      │
    │ Can test shadow or rollback     │
    └────────────┬────────────────────┘
                 │
    ┌────────────┴───────────┐
    │                        │
    │ Swap (promote shadow)  │  Rollback (restore R1)
    │                        │
    └────────────┬───────────┘
                 │
                 ▼
    ┌─────────────────────────────────┐
    │   SWAPPED                       │
    │ (shadow → active, active → R1)  │
    └─────────────────────────────────┘
```

---

## Features

### 1. USB Mass Storage LUN

- **Function:** `mass_storage.usb0` via libcomposite configfs
- **LUN 0:** Points to the **active** boot slot
- **Removable Media:** Yes (allows eject without unmount)
- **Size:** 16 MiB–4 GiB (filesystem-agnostic)
- **Formats Supported:** FAT16, FAT32, ext2, ext3, ext4
- **Access:** Read+Write (flashing U-Boot environment, logs, etc.)

### 2. Double-Buffer with 4R Rollback

The Eye Remote maintains **4 rollback snapshots (4R)**:

- **Active:** Currently served via USB LUN to ESPRESSObin
- **Shadow:** Pending validation (uploaded but not promoted)
- **R1–R4:** Previous active states, available for rollback

Each state change (swap, rollback) is atomically linked and logged.

### 3. TFTP Shadow Channel

In parallel with the USB LUN, the Eye Remote runs **dnsmasq TFTP** on `10.55.0.2` port 69:

- **Root:** `/var/lib/secubox/eye-remote/boot-media/tftp/`
- **Content:** Symlinks to shadow slot (`Image`, `device-tree.dtb`, `initrd.img`)
- **Use Case:** Test new kernel without swapping active slot
- **Boot Command (ESPRESSObin U-Boot):**
  ```
  => setenv serverip 10.55.0.2
  => setenv ipaddr 10.55.0.1
  => tftpboot $kernel_addr_r Image
  => booti $kernel_addr_r - $fdt_addr_r
  ```

### 4. Crash-Safe Atomic Swap

When promoting shadow to active:

1. **Eject LUN** from gadget (force disconnect)
2. **Swap symlinks atomically** (rename, not unlink-then-link)
3. **Update metadata** (state.json)
4. **Re-attach LUN** to gadget
5. **Verify** LUN file matches expected path

All operations protected by **file lock + process lock** (PARAMETERS module style).

### 5. API Management

**Base Path:** `/api/v1/eye-remote/boot-media/`

All endpoints require **JWT authentication** with scope `boot:write` (for POST) or `boot:read` (for GET).

---

## API Endpoints

| Method | Path | Authentication | Description |
|--------|------|------|---|
| **GET** | `/state` | `boot:read` | Fetch current boot media state (slots, metadata) |
| **POST** | `/upload` | `boot:write` | Stream image to shadow slot (chunked multipart) |
| **POST** | `/swap` | `boot:write` | Promote shadow to active, rotate active → R1 |
| **POST** | `/rollback` | `boot:write` | Restore previous active from R1–R4 |
| **GET** | `/tftp/status` | `boot:read` | TFTP service status & shadow contents |
| **GET** | `/images` | `boot:read` | List available images with metadata |

### Detailed Endpoint Specifications

#### GET `/api/v1/eye-remote/boot-media/state`

**Request:**
```bash
curl -H "Authorization: Bearer $JWT" \
     http://10.55.0.1:8000/api/v1/eye-remote/boot-media/state
```

**Response (200 OK):**
```json
{
  "active": {
    "path": "images/a1b2c3d4e5f6.img",
    "sha256": "a1b2c3d4e5f6...",
    "size_bytes": 268435456,
    "created_at": "2026-04-23T10:30:00Z",
    "label": "debian-bookworm-arm64-espressobin"
  },
  "shadow": {
    "path": "images/f0e1d2c3b4a5.img",
    "sha256": "f0e1d2c3b4a5...",
    "size_bytes": 268435456,
    "created_at": "2026-04-23T11:45:00Z",
    "label": "debian-bookworm-arm64-espressobin-rc1"
  },
  "lun_attached": true,
  "last_swap_at": "2026-04-23T10:00:00Z",
  "tftp_armed": true,
  "rollback_available": ["r1", "r2", "r3"]
}
```

#### POST `/api/v1/eye-remote/boot-media/upload`

**Request (multipart/form-data):**
```bash
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  -F "image=@debian-bookworm-arm64.img" \
  -F "label=debian-bookworm-arm64-espressobin-rc1" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/upload
```

**Parameters:**
- `image` (file, required): Boot image (FAT32/ext4)
- `label` (string, optional): Human-readable label

**Processing:**
1. Stream to temp file with `.tmp` suffix
2. Calculate SHA256 during streaming
3. Validate filesystem magic & size (16 MiB–4 GiB)
4. Extract boot files to `tftp/` (if extractable: Image, dtb, initrd)
5. Atomic rename to `images/<sha256>.img`
6. Update shadow symlink

**Response (201 Created):**
```json
{
  "path": "images/f0e1d2c3b4a5.img",
  "sha256": "f0e1d2c3b4a5...",
  "size_bytes": 268435456,
  "created_at": "2026-04-23T11:45:00Z",
  "label": "debian-bookworm-arm64-espressobin-rc1",
  "tftp_ready": true
}
```

**Response (400 Bad Request) — Invalid image:**
```json
{
  "error": "Invalid filesystem",
  "detail": "Image size must be 16 MiB–4 GiB"
}
```

#### POST `/api/v1/eye-remote/boot-media/swap`

**Request:**
```bash
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/swap
```

**Optional parameters:**
- `verify=true` (default): Verify LUN re-attached successfully

**Processing:**
1. Check shadow exists and is valid
2. Eject LUN from gadget
3. Swap symlinks: `active` ← `shadow`, `r1` ← old `active`
4. Shift rollback chain: `r2` ← `r1`, `r3` ← `r2`, `r4` ← `r3`
5. Clear shadow slot
6. Re-attach LUN
7. Update state.json

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Boot slot swapped successfully",
  "active": {
    "path": "images/f0e1d2c3b4a5.img",
    "sha256": "f0e1d2c3b4a5...",
    "size_bytes": 268435456,
    "created_at": "2026-04-23T11:45:00Z"
  },
  "rollback_available": ["r1", "r2", "r3", "r4"]
}
```

**Response (409 Conflict) — Shadow not ready:**
```json
{
  "error": "No shadow to swap",
  "detail": "Upload an image to shadow before promoting"
}
```

#### POST `/api/v1/eye-remote/boot-media/rollback`

**Request:**
```bash
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/rollback?target=r1
```

**Parameters:**
- `target` (string): Rollback slot to restore (`r1`, `r2`, `r3`, or `r4`)

**Processing:**
1. Check target exists
2. Eject LUN
3. Promote target to active, rotate chain
4. Re-attach LUN

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Restored from r1",
  "active": {
    "path": "images/a1b2c3d4e5f6.img",
    "sha256": "a1b2c3d4e5f6...",
    "size_bytes": 268435456,
    "created_at": "2026-04-23T10:30:00Z"
  }
}
```

#### GET `/api/v1/eye-remote/boot-media/tftp/status`

**Request:**
```bash
curl -H "Authorization: Bearer $JWT" \
     http://10.55.0.1:8000/api/v1/eye-remote/boot-media/tftp/status
```

**Response (200 OK):**
```json
{
  "enabled": true,
  "dnsmasq_running": true,
  "port": 69,
  "root": "/var/lib/secubox/eye-remote/boot-media/tftp",
  "shadow": {
    "path": "images/f0e1d2c3b4a5.img",
    "label": "debian-bookworm-arm64-espressobin-rc1"
  },
  "files": [
    {
      "name": "Image",
      "size": 12582912,
      "type": "kernel"
    },
    {
      "name": "device-tree.dtb",
      "size": 65536,
      "type": "devicetree"
    },
    {
      "name": "initrd.img",
      "size": 8388608,
      "type": "initramfs"
    }
  ]
}
```

---

## Workflow Examples

### Workflow 1: Upload New Image

```bash
#!/bin/bash

# 1. Generate JWT token (login as boot:write user)
JWT=$(curl -s -X POST http://10.55.0.1:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"boot-admin","password":"secubox-bootstrap"}' | jq -r .access_token)

# 2. Upload new image to shadow
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  -F "image=@debian-bookworm-arm64-espressobin-rc1.img" \
  -F "label=RC1 Build $(date +%Y%m%d)" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/upload

# 3. Check current state
curl -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/state | jq .

# Output:
# {
#   "active": { ... old image ... },
#   "shadow": { ... new image just uploaded ... },
#   "tftp_armed": true,
#   ...
# }
```

### Workflow 2: Test via TFTP (Optional)

No API call needed! The shadow is immediately available via TFTP.

```bash
# On ESPRESSObin U-Boot console:
=> setenv serverip 10.55.0.2
=> setenv ipaddr 10.55.0.1
=> tftpboot $kernel_addr_r Image
=> booti $kernel_addr_r - $fdt_addr_r

# Boot logs appear on serial console via Eye Remote
```

If the test kernel panics or fails, just reboot: U-Boot will load the **active** slot from the USB LUN (unchanged).

### Workflow 3: Promote Shadow to Active

Once shadow is tested and stable:

```bash
# 1. Get JWT (already have from upload)
JWT=$(...)

# 2. Promote shadow to active
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/swap

# Response shows active now contains the RC1 image,
# old active is saved in r1, and shadow is cleared.

# 3. Reboot ESPRESSObin (or power cycle)
# U-Boot will now load the new kernel from LUN
```

### Workflow 4: Boot from LUN

On ESPRESSObin U-Boot console:

```bash
=> usb start
=> usb tree

# Output:
# USB device tree:
#   1  Hub (480 Mb/s, 0mA)
#   |  ├─ 1.1 Mass Storage (active boot media)
#   └─ ...

=> fatload usb 0 $kernel_addr_r Image
=> fatload usb 0 $fdt_addr_r device-tree.dtb
=> fatload usb 0 $initrd_addr_r initrd.img
=> booti $kernel_addr_r $initrd_addr_r:$initrd_size $fdt_addr_r
```

### Workflow 5: Rollback to Previous

If the active image becomes corrupted or unstable:

```bash
# 1. Check available rollback points
curl -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/state | \
  jq .rollback_available

# Output: ["r1", "r2", "r3", "r4"]

# 2. Rollback to r1 (most recent previous)
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/rollback?target=r1

# Response confirms active is now restored from r1
# r1 contents moved to r2, r2→r3, r3→r4, r4 cleared

# 3. Reboot ESPRESSObin — boots old kernel again
```

---

## Image Requirements

### Format

- **Supported:** FAT16, FAT32, ext2, ext3, ext4
- **Recommended:** FAT32 (maximum U-Boot compatibility)

### Size

- **Minimum:** 16 MiB (allows room for kernel + DTB + initrd)
- **Maximum:** 4 GiB (USB mass storage practical limit)
- **Typical:** 256 MiB–1 GiB

### Contents

**Required (for USB LUN boot):**
- Kernel image (`Image` for arm64, `zImage` for arm32)
- Device tree binary (`device-tree.dtb` or `<board>.dtb`)

**Optional:**
- Initial ramdisk (`initrd.img`)
- U-Boot environment variables
- Boot script

**Example FAT32 structure:**
```
/Image                   ← Kernel (required)
/device-tree.dtb        ← Device tree (required)
/initrd.img             ← Initramfs (optional)
/uEnv.txt               ← U-Boot environment (optional)
/boot.scr               ← Boot script (optional)
```

### Validation

The Eye Remote validates images on upload:

1. **Filesystem magic:** Check magic bytes for FAT or ext
2. **Size check:** Enforce 16 MiB–4 GiB bounds
3. **Extractability:** For TFTP, attempt to extract Image, dtb, initrd
4. **SHA256 digest:** Compute and store for integrity tracking

If validation fails, upload rejects with 400 Bad Request.

---

## Configuration

### secubox.conf

The Eye Remote bootstrap respects the following settings in `/etc/secubox/secubox.conf`:

```toml
[eye_remote]
enabled = true
bootstrap_enabled = true
bootstrap_root = "/var/lib/secubox/eye-remote/boot-media"
max_image_size_gb = 4
min_image_size_mb = 16

[eye_remote.tftp]
enabled = true
dnsmasq_config = "/etc/dnsmasq.d/secubox-eye-remote-tftp.conf"
port = 69

[eye_remote.gadget]
ecm_enabled = true
acm_enabled = true
mass_storage_enabled = true
```

### TFTP DHCP Configuration (dnsmasq)

**File:** `/etc/dnsmasq.d/secubox-eye-remote-tftp.conf`

```ini
# TFTP service for Eye Remote bootstrap
enable-tftp
tftp-root=/var/lib/secubox/eye-remote/boot-media/tftp
tftp-port=69
listen-address=10.55.0.2
# Allow read from tftp root only (security)
tftp-secure
# Increase timeout for large initrd
tftp-max-block-size=1024
```

### Power Ordering

**Note:** The Eye Remote gadget attaches the LUN immediately on startup. ESPRESSObin U-Boot is responsible for detecting the LUN and initiating `usb start`.

**Recommended sequence:**
1. Power on ESPRESSObin (U-Boot starts, waits for user input)
2. Plug in USB OTG cable to Eye Remote
3. Wait 2 seconds for USB enumeration
4. Press Enter on U-Boot to interrupt autoboot
5. Issue `usb start` command
6. Issue `fatload usb 0 ...` to load kernel

---

## Troubleshooting

### Issue: "LUN not visible on ESPRESSObin"

**Symptoms:**
- `usb start` shows no Mass Storage device
- `usb tree` lists only hub, no LUN

**Diagnosis:**
```bash
# On Eye Remote (host):
ssh pi@eye-remote.local
systemctl status secubox-eye-remote-gadget

# Check if gadget tree exists:
ls -la /sys/kernel/config/usb_gadget/secubox/functions/mass_storage.usb0/
```

**Solutions:**
1. **Restart gadget:**
   ```bash
   systemctl restart secubox-eye-remote-gadget
   ```

2. **Check active symlink exists:**
   ```bash
   ls -la /var/lib/secubox/eye-remote/boot-media/active
   # Should point to a real image file
   ```

3. **Verify file is readable:**
   ```bash
   ls -lah /var/lib/secubox/eye-remote/boot-media/images/
   # Files should have read permissions
   ```

4. **Check USB connection physically:**
   - Use DATA port (middle), not PWR port
   - Try a different USB cable or port
   - Verify no USB hub between Eye Remote and ESPRESSObin

### Issue: "TFTP timeout / Image not found"

**Symptoms:**
- `tftpboot` hangs or reports "not found"
- TFTP root path incorrect

**Diagnosis:**
```bash
# Check TFTP service:
curl http://10.55.0.1:8000/api/v1/eye-remote/boot-media/tftp/status | jq .

# Check shadow symlink:
ls -la /var/lib/secubox/eye-remote/boot-media/tftp/

# Verify dnsmasq TFTP is running:
ps aux | grep dnsmasq
netstat -tlnup | grep :69
```

**Solutions:**
1. **Upload image to shadow first:**
   ```bash
   curl -X POST \
     -H "Authorization: Bearer $JWT" \
     -F "image=@debian-bookworm.img" \
     http://10.55.0.1:8000/api/v1/eye-remote/boot-media/upload
   ```

2. **Verify network connectivity:**
   ```bash
   # On ESPRESSObin U-Boot:
   => ping 10.55.0.2
   # Should respond with host IP
   ```

3. **Check file extraction succeeded:**
   - TFTP status should show `files` array non-empty
   - If image is raw (no filesystem), extract must fail gracefully
   - Fall back to using LUN boot instead

### Issue: "Swap failed / LUN ejection timeout"

**Symptoms:**
- `POST /swap` returns 500 error
- LUN remains stuck in gadget

**Diagnosis:**
```bash
# Check gadget lock:
lsof | grep /var/lib/secubox/eye-remote/boot-media/

# Check gadget-setup.sh log:
journalctl -u secubox-eye-remote-gadget -n 50

# Verify file lock isn't held:
ps aux | grep eye-remote
```

**Solutions:**
1. **Force-eject via shell (careful!):**
   ```bash
   sudo /usr/sbin/gadget-setup.sh swap-lun ""
   sleep 0.5
   sudo /usr/sbin/gadget-setup.sh swap-lun \
     "/var/lib/secubox/eye-remote/boot-media/active"
   ```

2. **Restart gadget service:**
   ```bash
   systemctl stop secubox-eye-remote-gadget
   sleep 2
   systemctl start secubox-eye-remote-gadget
   ```

3. **Check for stale processes:**
   ```bash
   systemctl status secubox-eye-remote-api
   # If API process holds lock, restart it
   systemctl restart secubox-eye-remote-api
   ```

### Issue: "Invalid filesystem on upload"

**Symptoms:**
- `POST /upload` returns 400 Bad Request
- Error: "Invalid filesystem" or "Size out of range"

**Solutions:**
1. **Verify image format:**
   ```bash
   file debian-bookworm.img
   # Should output: FAT boot sector, x86 or x64 boot loader binary
   # or: Linux rev 1.0 ext4 filesystem
   ```

2. **Check image size:**
   ```bash
   ls -lh debian-bookworm.img
   # Should be between 16 MiB and 4 GiB
   ```

3. **Create valid FAT32 image if needed:**
   ```bash
   # Create 256 MiB FAT32 image
   fallocate -l 256M debian-bookworm.img
   mkfs.vfat -F32 debian-bookworm.img

   # Mount and copy kernel files
   sudo mount debian-bookworm.img /mnt/boot
   sudo cp Image /mnt/boot/
   sudo cp device-tree.dtb /mnt/boot/
   sudo umount /mnt/boot
   ```

---

## See Also

- **[Eye Remote Hardware](Eye-Remote-Hardware.md)** — Physical connections, pin assignments
- **[Eye Remote Gateway](Eye-Remote-Gateway.md)** — Network configuration, DHCP/DNS
- **[Eye Remote Implementation](Eye-Remote-Implementation.md)** — Python/Bash internals, codebase structure
- **[Architecture Boot](Architecture-Boot.md)** — Overall boot architecture for SecuBox-Deb
- **[U-Boot Documentation](../eye-remote/uboot-bootcmd.md)** — ESPRESSObin U-Boot commands

---

**CyberMind · SecuBox-Deb · Eye Remote Bootstrap v2.1.0**

*Last reviewed: 2026-04-23 · Maintainer: Gerald Kerma <gandalf@cybermind.fr>*
