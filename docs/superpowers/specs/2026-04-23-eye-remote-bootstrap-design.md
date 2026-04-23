# Eye Remote Bootstrap v2.1.0 — Design Specification

**Author:** GK² · CyberMind
**Date:** 2026-04-23
**Version:** 2.1.0
**Status:** Approved

---

## 1. Overview

Extend the Eye Remote so the same USB-OTG cable carries three concurrent roles on one `libcomposite` gadget:

| Function | Role | v2.0.0 | v2.1.0 |
|----------|------|--------|--------|
| `ecm.usb0` | Metrics transport (10.55.0.2 ↔ 10.55.0.1) | ✅ | ✅ |
| `acm.usb0` | Serial console capture | ✅ | ✅ |
| `mass_storage.usb0` | Bootstrap LUN for ESPRESSObin U-Boot | ❌ | ✅ |

Add a FastAPI sub-router `/api/v1/eye-remote/boot-media/` for upload/swap/rollback of the LUN backing file, plus a dnsmasq-served TFTP path on `10.55.0.2` as the shadow slot of a 4R double-buffer.

**Non-goal:** Replacing the BootROM path. The Armada 3720 BootROM cannot USB-boot. First-stage (TIM+WTP+U-Boot) stays in SPI/eMMC/SD. This feature targets kernel, DTB, initrd, rootfs, live-boot, recovery — everything U-Boot loads after it is itself running.

---

## 2. Architecture

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
│  │  ┌─────────┐  ┌─────────┐  ┌─────────────────────────────┐  │   │
│  │  │ active  │  │ shadow  │  │ images/<sha256>.img ...     │  │   │
│  │  │ (link)  │  │ (link)  │  │                             │  │   │
│  │  └────┬────┘  └────┬────┘  └─────────────────────────────┘  │   │
│  │       │            │                                         │   │
│  │       ▼            ▼                                         │   │
│  │  ┌─────────────────────────┐    ┌────────────────────────┐  │   │
│  │  │ LUN (mass_storage.usb0)│    │ tftp/ (symlinks)       │  │   │
│  │  │ points to active       │    │ serves shadow          │  │   │
│  │  └─────────────────────────┘    └────────────────────────┘  │   │
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
                              │ USB OTG
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     ESPRESSObin (U-Boot)                            │
│  usb start → sees mass_storage LUN → fatload usb 0 Image           │
│  OR: dhcp → tftp $kernel_addr_r Image (shadow channel)             │
└─────────────────────────────────────────────────────────────────────┘
```

**Key flows:**
- **Normal boot:** U-Boot loads from LUN (active slot)
- **Shadow test:** U-Boot loads via TFTP (shadow slot, no swap needed)
- **Promotion:** `POST /swap` → eject LUN → atomic symlink swap → reattach LUN

---

## 3. Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Script replacement | New `gadget-setup.sh` replaces `secubox-otg-gadget.sh` | Clean architecture, consolidate all modes |
| LUN path | Clean break to `/var/lib/secubox/eye-remote/boot-media/` | Old `debug.img` was placeholder only |
| LUN attach timing | Immediate on `up` | Power ordering is U-Boot concern, not gadget concern |
| TFTP content | Symlinks to shadow | Follows 4R pattern, minimal disk duplication |
| Language split | Shell for configfs, Python for file ops | Each language doing what it excels at |

---

## 4. Component Specifications

### 4.1 USB Gadget Layer (`gadget-setup.sh`)

**Path:** `remote-ui/round/files/etc/secubox/eye-remote/gadget-setup.sh`

**Subcommands:**

| Command | Action |
|---------|--------|
| `up` | Create configfs tree, attach all 3 functions, bind UDC |
| `down` | Unbind UDC, tear down tree cleanly |
| `swap-lun <path>` | Force-eject → update `lun.0/file` → re-attach |
| `status` | JSON output: UDC state, functions, LUN file |

**configfs tree:**
```
/sys/kernel/config/usb_gadget/secubox/
├── idVendor          = 0x1d6b
├── idProduct         = 0x0104
├── bcdDevice         = 0x0210
├── strings/0x409/
│   ├── manufacturer  = "CyberMind SecuBox"
│   ├── product       = "Eye Remote Bootstrap"
│   └── serialnumber  = <from /proc/cpuinfo>
├── functions/
│   ├── ecm.usb0/
│   ├── acm.usb0/
│   └── mass_storage.usb0/
│       └── lun.0/
│           ├── file        → /var/lib/.../boot-media/active
│           ├── removable   = 1
│           ├── ro          = 0
│           ├── cdrom       = 0
│           ├── nofua       = 0
│           └── stall       = 1
├── configs/c.1/
│   ├── ecm.usb0 → ../../functions/ecm.usb0
│   ├── acm.usb0 → ../../functions/acm.usb0
│   └── mass_storage.usb0 → ../../functions/mass_storage.usb0
└── UDC               = <bound controller>
```

**Requirements:**
- Idempotent: `up` checks if running, `down` handles partial teardown
- Non-zero exit with clear diagnostic on failure
- LUN eject sequence: `echo "" > file; sleep 0.1; echo "$path" > file`

### 4.2 Boot Media Core (`core/boot_media.py`)

**Thread-safety:** File lock + in-process lock (same pattern as `core/device_registry.py`)

**State file:** `/var/lib/secubox/eye-remote/boot-media/state.json`
```json
{
  "active": {
    "path": "images/a1b2c3d4...img",
    "sha256": "a1b2c3d4...",
    "size_bytes": 134217728,
    "created_at": "2026-04-23T10:30:00Z",
    "label": "debian-bookworm-arm64"
  },
  "shadow": null,
  "last_swap_at": null,
  "tftp_armed": false
}
```

**Functions:**

| Function | Description |
|----------|-------------|
| `get_state() -> BootMediaState` | Read state.json, verify symlinks exist |
| `upload_to_shadow(fileobj, label) -> BootImage` | Stream to temp, sha256, validate, atomic rename, extract boot files to tftp/ |
| `swap() -> BootMediaState` | Lock → eject → swap symlinks atomically → reattach → update state |
| `rollback() -> BootMediaState` | Swap back (no-op if shadow empty) |
| `validate_image(path) -> bool` | FAT16/32 or ext magic, size 16 MiB–4 GiB |

**Atomic swap implementation:**
```python
def swap():
    with file_lock, process_lock:
        subprocess.run(["gadget-setup.sh", "swap-lun", ""], check=True)
        tmp_link = active_path.with_suffix('.tmp')
        tmp_link.symlink_to(shadow_target)
        tmp_link.rename(active_path)  # Atomic!
        # ... update shadow similarly
        subprocess.run(["gadget-setup.sh", "swap-lun", str(active_path)], check=True)
        save_state()
```

### 4.3 Pydantic Models (`models/boot_media.py`)

```python
class BootSlot(str, Enum):
    ACTIVE = "active"
    SHADOW = "shadow"

class BootImage(BaseModel):
    path: str
    sha256: str
    size_bytes: int
    created_at: datetime
    label: Optional[str]

class BootMediaState(BaseModel):
    active: Optional[BootImage]
    shadow: Optional[BootImage]
    lun_attached: bool
    last_swap_at: Optional[datetime]
    tftp_armed: bool
```

### 4.4 FastAPI Router (`api/routers/boot_media.py`)

**Mount:** `/api/v1/eye-remote/boot-media/`

| Method | Path | Auth | Request | Response |
|--------|------|------|---------|----------|
| `GET` | `/state` | JWT | — | `BootMediaState` |
| `POST` | `/upload` | JWT | multipart `file` + `label` | `BootImage` |
| `POST` | `/swap` | JWT | — | `BootMediaState` |
| `POST` | `/rollback` | JWT | — | `BootMediaState` |
| `GET` | `/tftp/status` | JWT | — | `{"alive": bool, "root": str}` |

**Error responses:** 400 (invalid image), 409 (swap in progress), 500 (gadget failure)

### 4.5 TFTP / dnsmasq

**Config:** `files/etc/dnsmasq.d/secubox-eye-tftp.conf`
```ini
interface=usb0
bind-interfaces
enable-tftp
tftp-root=/var/lib/secubox/eye-remote/boot-media/tftp
tftp-no-fail
```

**TFTP directory:** Extracted boot files from shadow image

When `upload_to_shadow()` completes, it:
1. Loop-mounts the shadow image (FAT or ext)
2. Copies boot files (Image, *.dtb, initrd*) to tftp/
3. Unmounts the image

```
tftp/
├── Image           # Copied from shadow image /boot/Image
├── armada-3720-espressobin.dtb
└── initrd.img
```

On `swap()`, tftp/ is cleared and repopulated from the new shadow (old active).

This ensures TFTP always serves testable boot files from shadow slot without requiring persistent loop mounts.

**Systemd drop-in:** `dnsmasq.service.d/secubox-eye.conf`
```ini
[Unit]
After=secubox-eye-gadget.service
Wants=secubox-eye-gadget.service
```

---

## 5. State Machine

```
    ┌──────────┐         POST /upload          ┌──────────┐
    │  EMPTY   │ ─────────────────────────────▶│  SHADOW  │
    │ active:∅ │                               │  READY   │
    │ shadow:∅ │                               │ shadow:A │
    └──────────┘                               └────┬─────┘
                                                    │ POST /swap
                                                    ▼
    ┌──────────┐         POST /upload          ┌──────────┐
    │  ACTIVE  │ ─────────────────────────────▶│  READY   │
    │  ONLY    │◀───────POST /rollback─────────│ TO SWAP  │
    │ active:A │                               │ active:A │
    │ shadow:∅ │                               │ shadow:B │
    └──────────┘                               └────┬─────┘
         ▲                                          │ POST /swap
         │              POST /rollback              ▼
         └─────────────────────────────────────┬──────────┐
                                               │  SWAPPED │
                                               │ active:B │
                                               │ shadow:A │
                                               └──────────┘
```

**Invariants:**
- `active` symlink always exists (or placeholder)
- LUN bound to `active` target
- TFTP serves `shadow` target

**Crash recovery:**
| Failure point | Recovery |
|---------------|----------|
| After eject, before symlink | Next `up` reattaches old active |
| After symlink, before reattach | Symlinks consistent, next access reattaches |

---

## 6. File Structure

```
remote-ui/round/
├── files/
│   └── etc/
│       ├── secubox/eye-remote/
│       │   ├── gadget-setup.sh
│       │   └── tftp.env
│       ├── systemd/system/
│       │   ├── secubox-eye-gadget.service
│       │   └── dnsmasq.service.d/secubox-eye.conf
│       └── dnsmasq.d/secubox-eye-tftp.conf
├── build-eye-remote-image.sh

models/boot_media.py
core/boot_media.py
api/routers/boot_media.py

debian/secubox-eye-remote/
├── install
├── postinst
├── postrm
└── changelog

tests/integration/test_boot_media.py

docs/
├── eye-remote/uboot-bootcmd.md
└── wiki/
    ├── Eye-Remote-Bootstrap.md
    ├── Eye-Remote-Bootstrap-FR.md
    └── Eye-Remote-Bootstrap-ZH.md
```

---

## 7. Debian Packaging

**Package:** `secubox-eye-remote` 2.1.0-1

**postinst:**
- `systemctl daemon-reload`
- Enable `secubox-eye-gadget.service` on fresh install only
- Create `/var/lib/secubox/eye-remote/boot-media/{images,tftp}`
- Create placeholder.img if no active image
- Initialize state.json if missing

**postrm purge:**
- Remove state.json, symlinks, tftp/
- Preserve `images/` directory (user data)

**Dependencies:** Add `dnsmasq-base`

---

## 8. Testing

**Path:** `tests/integration/test_boot_media.py`

**Key tests:**
- Upload + sha256 roundtrip
- Swap atomicity: fail after eject → recoverable
- Swap atomicity: fail after symlink → LUN reattached
- Rollback restores previous active
- `validate_image` rejects truncated/wrong-magic
- Concurrent upload blocked (409)

**Mock:** Fake configfs tree under `tmp_path`

---

## 9. Constraints

Per task specification §2:

1. **Backward compatibility:** ECM+ACM behavior unchanged
2. **Ordering:** Document Pi power and U-Boot `usb reset` solutions
3. **Atomic swap:** `kill -9` mid-swap leaves consistent state
4. **configfs only:** No `modprobe g_ether` or `g_serial`
5. **Pi Zero W quirks:** Legacy DPI, ST7701S init via pigpio, QEMU build

---

## 10. Acceptance Criteria

- `apt upgrade` from 2.0.0 to 2.1.0 succeeds cleanly
- Existing integration tests pass (ECM+ACM unchanged)
- `usb start; usb tree` on ESPRESSObin shows Pi Zero LUN
- `fatload usb 0 $kernel_addr_r Image` succeeds
- `POST /swap` + `POST /rollback` returns to pre-swap state
- Atomic swap test passes under simulated SIGKILL

---

## 11. Task Breakdown

| ID | Task | Type |
|----|------|------|
| T1 | `gadget-setup.sh` | Code |
| T2 | `secubox-eye-gadget.service` | Code |
| T3 | `models/boot_media.py` | Code |
| T4 | `core/boot_media.py` | Code |
| T5 | `api/routers/boot_media.py` | Code |
| T6 | dnsmasq/TFTP config | Code |
| T7 | U-Boot documentation | Doc |
| T8 | Debian packaging | Code |
| T9 | Build script update | Code |
| T10 | Integration tests | Code |
| T11 | Wiki: Eye-Remote-Bootstrap | Doc |
| T12 | Update existing wiki pages | Doc |
| T13 | i18n (FR, ZH) | Doc |
| T14 | CLAUDE.md update | Doc |

---

*GK² · CyberMind · SecuBox-Deb · April 2026*
